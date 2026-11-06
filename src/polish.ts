import fs from "fs/promises";
import path from "path";
import { createHash } from "crypto";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { logger } from "./logger.js";
import {
  VAULT_PATH_NOTE,
  createUnifiedDiff,
  readFileContent,
  toVaultPath,
  validatePath,
  withVaultErrors,
  writeFileContent,
} from "./lib.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export type PolishConfig = {
  apiKey: string;
  serviceTier: ServiceTier | undefined;
  model: string;
  templateDir: string;
  defaultTemperature: number;
  timeoutMs: number;
  maxChunkChars: number;
};

type Result<T> = { ok: true; value: T } | { ok: false; error: string };

// OpenRouter service tiers (https://openrouter.ai/docs/guides/features/service-tiers).
// "flex" routes to cheaper, lower-priority endpoints and may return capacity errors.
const SERVICE_TIERS = [
  "auto",
  "default",
  "flex",
  "priority",
  "fast",
  "scale",
  "ultrafast",
] as const;
type ServiceTier = (typeof SERVICE_TIERS)[number];

function parseServiceTier(raw: string | undefined): Result<ServiceTier | undefined> {
  const value = raw?.trim().toLowerCase();
  if (!value) return { ok: true, value: undefined };
  const tier = SERVICE_TIERS.find((candidate) => candidate === value);
  if (!tier) {
    return {
      ok: false,
      error: `OPENROUTER_SERVICE_TIER must be one of: ${SERVICE_TIERS.join(", ")}`,
    };
  }
  return { ok: true, value: tier };
}

const OPENROUTER_CHAT_URL = "https://openrouter.ai/api/v1/chat/completions";
const DEFAULT_TEMPLATE_DIR = "/_polish";
const DEFAULT_TEMPERATURE = 0.3;
const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_CHUNK_CHARS = 6000;
const PREVIEW_TTL_MS = 30 * 60 * 1000;
const PREVIEW_CACHE_LIMIT = 50;

function parseNumber(raw: string | undefined, fallback: number, min: number, max: number) {
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < min || value > max) return fallback;
  return value;
}

/**
 * Reads polishing settings from the environment. Returns null (tools disabled)
 * when OPENROUTER_API_KEY or OPENROUTER_MODEL is missing.
 */
export function loadPolishConfig(env: NodeJS.ProcessEnv): PolishConfig | null {
  const apiKey = env.OPENROUTER_API_KEY?.trim();
  const model = env.OPENROUTER_MODEL?.trim();
  if (!apiKey) {
    logger.info("OPENROUTER_API_KEY not set - polishing tools disabled");
    return null;
  }
  if (!model) {
    logger.warn(
      "OPENROUTER_API_KEY is set but OPENROUTER_MODEL is missing - polishing tools disabled"
    );
    return null;
  }
  if (!/^[A-Za-z0-9._:/-]+$/.test(model)) {
    logger.warn("OPENROUTER_MODEL contains invalid characters - polishing tools disabled");
    return null;
  }
  const serviceTier = parseServiceTier(env.OPENROUTER_SERVICE_TIER);
  if (!serviceTier.ok) {
    logger.warn(`${serviceTier.error} - polishing tools disabled`);
    return null;
  }
  const config: PolishConfig = {
    apiKey,
    serviceTier: serviceTier.value,
    model,
    templateDir: env.POLISH_TEMPLATE_DIR?.trim() || DEFAULT_TEMPLATE_DIR,
    defaultTemperature: parseNumber(env.POLISH_TEMPERATURE, DEFAULT_TEMPERATURE, 0, 2),
    timeoutMs: parseNumber(env.POLISH_TIMEOUT_MS, DEFAULT_TIMEOUT_MS, 1000, 600_000),
    maxChunkChars: parseNumber(env.POLISH_MAX_CHUNK_CHARS, DEFAULT_MAX_CHUNK_CHARS, 500, 100_000),
  };
  logger.info(
    `Polishing tools enabled (model: ${model}, service tier: ${config.serviceTier ?? "provider default"}, templates: ${config.templateDir})`
  );
  return config;
}

// ---------------------------------------------------------------------------
// Prompt construction
// ---------------------------------------------------------------------------

const BASE_SYSTEM_PROMPT = [
  "You are a professional copy editor. Polish the text the user provides.",
  "",
  "Hard rules (they override any style guide or instruction below):",
  "- Preserve meaning, facts, claims, numbers, and proper nouns. Do not add, remove, or summarize content.",
  "- Keep the original language of the text. Never translate it.",
  "- Fix awkward phrasing, translationese, redundancy, grammar, spelling, punctuation, and spacing.",
  "- Keep the tone and register (for example honorific or casual speech) unless the style guide asks for a change.",
  "- Preserve Markdown structure exactly: headings, lists, tables, block quotes, links, wikilinks ([[...]]), embeds (![[...]]), tags, footnotes, callouts, and HTML.",
  "- Never change anything inside code blocks or inline code.",
  "- Output only the polished text. No preface, explanation, notes, or surrounding code fences.",
].join("\n");

function buildSystemPrompt(template: PolishTemplate | null, instructions: string | undefined) {
  const parts = [BASE_SYSTEM_PROMPT];
  if (template && template.instructions.trim()) {
    parts.push(`Style guide (${template.name}):\n${template.instructions.trim()}`);
  }
  if (instructions && instructions.trim()) {
    parts.push(`Additional instructions for this request:\n${instructions.trim()}`);
  }
  return parts.join("\n\n");
}

// ---------------------------------------------------------------------------
// OpenRouter client (OpenAI-compatible chat completions)
// ---------------------------------------------------------------------------

const openRouterErrorSchema = z.object({
  error: z.object({
    message: z.string().optional(),
    code: z.union([z.string(), z.number()]).optional(),
  }),
});

const openRouterResponseSchema = z.object({
  service_tier: z.string().nullable().optional(),
  choices: z
    .array(
      z.object({
        message: z.object({ content: z.string().nullable().optional() }).optional(),
        finish_reason: z.string().nullable().optional(),
      })
    )
    .optional(),
});

function describeOpenRouterError(body: unknown): string | undefined {
  const parsed = openRouterErrorSchema.safeParse(body);
  if (!parsed.success) return undefined;
  const { code, message } = parsed.data.error;
  return [code === undefined ? undefined : String(code), message].filter(Boolean).join(": ");
}

async function callModel(
  config: PolishConfig,
  systemPrompt: string,
  text: string,
  temperature: number
): Promise<Result<string>> {
  let response: globalThis.Response;
  try {
    response = await fetch(OPENROUTER_CHAT_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${config.apiKey}`,
        "X-Title": "mcpfs",
      },
      body: JSON.stringify({
        model: config.model,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: text },
        ],
        temperature,
        ...(config.serviceTier === undefined ? {} : { service_tier: config.serviceTier }),
      }),
      signal: AbortSignal.timeout(config.timeoutMs),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { ok: false, error: `OpenRouter request failed: ${message}` };
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return {
      ok: false,
      error: `OpenRouter returned a non-JSON response (HTTP ${response.status})`,
    };
  }

  const apiError = describeOpenRouterError(body);
  if (!response.ok || apiError !== undefined) {
    return {
      ok: false,
      error:
        `OpenRouter API error (HTTP ${response.status}): ${apiError || "unknown error"}` +
        (config.serviceTier === "flex" && (response.status === 429 || response.status === 503)
          ? " (flex capacity may be unavailable; retry later or unset OPENROUTER_SERVICE_TIER)"
          : ""),
    };
  }

  const parsed = openRouterResponseSchema.safeParse(body);
  if (!parsed.success) {
    return { ok: false, error: "OpenRouter returned an unexpected response shape" };
  }
  const choice = parsed.data.choices?.[0];
  const finishReason = choice?.finish_reason ?? undefined;
  const output = choice?.message?.content ?? "";
  if (!output.trim()) {
    return {
      ok: false,
      error: `Model returned no text (finish reason: ${finishReason ?? "unknown"})`,
    };
  }
  if (finishReason !== undefined && finishReason !== "stop") {
    return {
      ok: false,
      error: `Model stopped early (finish reason: ${finishReason}); try a smaller POLISH_MAX_CHUNK_CHARS`,
    };
  }
  if (config.serviceTier !== undefined) {
    logger.debug(
      `OpenRouter served polish request on tier ${parsed.data.service_tier ?? "unreported"}`
    );
  }
  return { ok: true, value: output };
}

// ---------------------------------------------------------------------------
// Text chunking
// ---------------------------------------------------------------------------

type SplitDocument = { frontmatter: string; body: string };

// YAML frontmatter is metadata, not prose, so it is never sent for polishing.
function splitFrontmatter(text: string): SplitDocument {
  const match = /^---\r?\n[\s\S]*?\r?\n---[ \t]*(?:\r?\n|$)/.exec(text);
  if (!match) return { frontmatter: "", body: text };
  return { frontmatter: match[0], body: text.slice(match[0].length) };
}

/**
 * Splits text into contiguous line ranges of at most maxChars, cutting only
 * at blank lines outside fenced code blocks. Joining the chunks with "\n"
 * reproduces the input exactly.
 */
function chunkText(text: string, maxChars: number): string[] {
  const lines = text.split("\n");
  const chunks: string[] = [];
  let current: string[] = [];
  let currentLength = 0;
  let inFence = false;

  for (const line of lines) {
    const canCut = !inFence && line.trim() === "";
    if (canCut && currentLength >= maxChars && current.length > 0) {
      chunks.push(current.join("\n"));
      current = [];
      currentLength = 0;
    }
    current.push(line);
    currentLength += line.length + 1;
    if (/^\s*(```|~~~)/.test(line)) inFence = !inFence;
  }
  chunks.push(current.join("\n"));
  return chunks;
}

// Removes a code fence the model wrapped around its whole answer.
function stripWrappingFence(output: string, input: string): string {
  const trimmed = output.trim();
  if (/^\s*(```|~~~)/.test(input)) return trimmed;
  const match = /^(```|~~~)[^\n]*\n([\s\S]*?)\n\1\s*$/.exec(trimmed);
  return match?.[2] ?? trimmed;
}

async function polishBody(
  config: PolishConfig,
  body: string,
  systemPrompt: string,
  temperature: number
): Promise<string> {
  const chunks = chunkText(body, config.maxChunkChars);
  const polished: string[] = [];
  for (const chunk of chunks) {
    const leading = /^\s*/.exec(chunk)?.[0] ?? "";
    const core = chunk.slice(leading.length).trimEnd();
    const trailing = chunk.slice(leading.length + core.length);
    if (!core) {
      polished.push(chunk);
      continue;
    }
    const result = await callModel(config, systemPrompt, core, temperature);
    if (!result.ok) throw new Error(result.error);
    polished.push(leading + stripWrappingFence(result.value, core) + trailing);
  }
  return polished.join("\n");
}

async function polishDocument(
  config: PolishConfig,
  text: string,
  template: PolishTemplate | null,
  instructions: string | undefined
): Promise<string> {
  const { frontmatter, body } = splitFrontmatter(text);
  const systemPrompt = buildSystemPrompt(template, instructions);
  const temperature = template?.temperature ?? config.defaultTemperature;
  return frontmatter + (await polishBody(config, body, systemPrompt, temperature));
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

type PolishTemplate = {
  name: string;
  description: string;
  temperature: number | undefined;
  instructions: string;
};

const TEMPLATE_NAME_PATTERN = /^[A-Za-z0-9가-힣_-]{1,64}$/;

function parseTemplate(name: string, raw: string): PolishTemplate {
  const { frontmatter, body } = splitFrontmatter(raw);
  let description = "";
  let temperature: number | undefined;
  for (const line of frontmatter.split(/\r?\n/)) {
    const match = /^(description|temperature):\s*(.*)$/.exec(line);
    if (!match) continue;
    const value = (match[2] ?? "").trim().replace(/^["']|["']$/g, "");
    if (match[1] === "description") {
      description = value;
    } else {
      const parsed = Number(value);
      if (value !== "" && Number.isFinite(parsed) && parsed >= 0 && parsed <= 2) {
        temperature = parsed;
      }
    }
  }
  return { name, description, temperature, instructions: body.trim() };
}

function serializeTemplate(
  description: string,
  temperature: number | undefined,
  instructions: string
): string {
  const header = [
    "---",
    `description: ${JSON.stringify(description)}`,
    ...(temperature === undefined ? [] : [`temperature: ${temperature}`]),
    "---",
  ];
  return `${header.join("\n")}\n${instructions.trim()}\n`;
}

function templateVaultPath(config: PolishConfig, name: string): string {
  return path.posix.join(config.templateDir, `${name}.md`);
}

function assertTemplateName(name: string): void {
  if (!TEMPLATE_NAME_PATTERN.test(name)) {
    throw new Error(
      "Invalid template name: use 1-64 letters, digits, Hangul, '-' or '_' (no extension)"
    );
  }
}

async function listTemplates(config: PolishConfig): Promise<PolishTemplate[]> {
  const dir = await validatePath(config.templateDir);
  let entries: string[];
  try {
    entries = await fs.readdir(dir);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
  const templates: PolishTemplate[] = [];
  for (const entry of entries.sort()) {
    if (!entry.endsWith(".md")) continue;
    const name = entry.slice(0, -3);
    if (!TEMPLATE_NAME_PATTERN.test(name)) continue;
    try {
      const filePath = await validatePath(templateVaultPath(config, name));
      templates.push(parseTemplate(name, await readFileContent(filePath)));
    } catch (error) {
      logger.warn(`Skipping unreadable polish template ${name}: ${String(error)}`);
    }
  }
  return templates;
}

async function loadTemplate(
  config: PolishConfig,
  name: string | undefined
): Promise<PolishTemplate | null> {
  if (name === undefined || name.trim() === "") return null;
  assertTemplateName(name);
  try {
    const dirPath = await validatePath(config.templateDir);
    await fs.access(dirPath);
    const filePath = await validatePath(templateVaultPath(config, name));
    return parseTemplate(name, await readFileContent(filePath));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(
        `Polish template not found: ${name}. Use list_polish_templates to see available templates.`
      );
    }
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Preview cache: applying a previewed polish reuses the exact previewed text
// instead of calling the model again and getting a different result.
// ---------------------------------------------------------------------------

type PreviewEntry = { polished: string; expiresAt: number };

const previewCache = new Map<string, PreviewEntry>();

function previewKey(parts: readonly string[]): string {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(`${part.length}:${part}`);
  return hash.digest("hex");
}

function getPreview(key: string): string | undefined {
  const entry = previewCache.get(key);
  if (!entry) return undefined;
  if (entry.expiresAt < Date.now()) {
    previewCache.delete(key);
    return undefined;
  }
  return entry.polished;
}

function setPreview(key: string, polished: string): void {
  const now = Date.now();
  for (const [cachedKey, entry] of previewCache) {
    if (entry.expiresAt < now) previewCache.delete(cachedKey);
  }
  while (previewCache.size >= PREVIEW_CACHE_LIMIT) {
    const oldest = previewCache.keys().next().value;
    if (oldest === undefined) break;
    previewCache.delete(oldest);
  }
  previewCache.set(key, { polished, expiresAt: now + PREVIEW_TTL_MS });
}

function formatDiff(original: string, modified: string, vaultPath: string): string {
  if (original === modified) return "No changes.";
  const diff = createUnifiedDiff(original, modified, vaultPath);
  let fence = "```";
  while (diff.includes(fence)) fence += "`";
  return `${fence}diff\n${diff}${fence}`;
}

// ---------------------------------------------------------------------------
// Tool registration
// ---------------------------------------------------------------------------

type PolishFileArgs = {
  path: string;
  template?: string | undefined;
  instructions?: string | undefined;
  dryRun?: boolean | undefined;
};

type PolishTextArgs = {
  text: string;
  template?: string | undefined;
  instructions?: string | undefined;
};

type SavePolishTemplateArgs = {
  name: string;
  description: string;
  instructions: string;
  temperature?: number | undefined;
  overwrite?: boolean | undefined;
};

const ENGLISH_PROMPT_NOTE =
  "Write prompt text (template instructions and the 'instructions' argument) in English " +
  "unless the user explicitly asks for another language. The text being polished keeps " +
  "its own language either way.";

function textResult(text: string) {
  return {
    content: [{ type: "text" as const, text }],
    structuredContent: { content: text },
  };
}

export function registerPolishTools(server: McpServer, config: PolishConfig): void {
  const templateArg = z
    .string()
    .optional()
    .describe("Template name from list_polish_templates. Omit to use only the built-in rules.");
  const instructionsArg = z
    .string()
    .optional()
    .describe("Extra one-off instructions for this request, in English unless asked otherwise.");

  server.registerTool(
    "polish_file",
    {
      title: "Polish File",
      description:
        "Polish (copy-edit) the prose of a text or Markdown file with a dedicated " +
        "editing model (via OpenRouter). Use this when the user asks to polish, proofread, copy-edit, or " +
        "improve the writing of a note (for example '윤문', '교정', '다듬어줘'). The server reads " +
        "the file itself, so do not pass the content. Meaning, Markdown structure, links, " +
        "code, and YAML frontmatter are preserved. By default (dryRun: true) it returns a " +
        "diff without writing; call again with dryRun: false and the same arguments to " +
        "apply exactly the previewed result. Call list_polish_templates first to pick a " +
        "matching style template. " +
        ENGLISH_PROMPT_NOTE +
        " " +
        VAULT_PATH_NOTE,
      inputSchema: {
        path: z.string(),
        template: templateArg,
        instructions: instructionsArg,
        dryRun: z
          .boolean()
          .default(true)
          .describe("true: return a diff only. false: write the polished text to the file."),
      },
      outputSchema: { content: z.string() },
      annotations: {
        readOnlyHint: false,
        idempotentHint: false,
        destructiveHint: true,
        openWorldHint: true,
      },
    },
    withVaultErrors(async (args: PolishFileArgs) => {
      const filePath = await validatePath(args.path);
      const vaultPath = toVaultPath(filePath);
      const original = await readFileContent(filePath);
      const template = await loadTemplate(config, args.template);
      const key = previewKey([
        vaultPath,
        original,
        template ? JSON.stringify(template) : "",
        args.instructions ?? "",
      ]);

      let polished = getPreview(key);
      const reused = polished !== undefined;
      if (polished === undefined) {
        polished = await polishDocument(config, original, template, args.instructions);
      }

      const diff = formatDiff(original, polished, vaultPath);
      if (args.dryRun !== false) {
        setPreview(key, polished);
        return textResult(
          `Preview for ${vaultPath} (not written). Call polish_file again with dryRun: false ` +
            `and the same arguments to apply it.\n\n${diff}`
        );
      }

      if (original === polished) {
        return textResult(`No changes needed for ${vaultPath}.`);
      }
      // Guard against overwriting edits made (e.g. by sync) while the model ran.
      const current = await readFileContent(filePath);
      if (current !== original) {
        throw new Error(`${vaultPath} changed while polishing; nothing was written. Try again.`);
      }
      await writeFileContent(filePath, polished);
      previewCache.delete(key);
      return textResult(
        `Polished ${vaultPath}${reused ? " (applied the previewed result)" : ""}.\n\n${diff}`
      );
    })
  );

  server.registerTool(
    "polish_text",
    {
      title: "Polish Text",
      description:
        "Polish (copy-edit) a piece of text with a dedicated editing model (via OpenRouter) and return " +
        "the polished text. Use this for text that is not stored in a vault file; for files " +
        "use polish_file instead so the content does not need to be sent. Meaning, Markdown " +
        "structure, links, and code are preserved. " +
        ENGLISH_PROMPT_NOTE,
      inputSchema: {
        text: z.string().min(1),
        template: templateArg,
        instructions: instructionsArg,
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    withVaultErrors(async (args: PolishTextArgs) => {
      const template = await loadTemplate(config, args.template);
      const polished = await polishDocument(config, args.text, template, args.instructions);
      return textResult(polished);
    })
  );

  server.registerTool(
    "list_polish_templates",
    {
      title: "List Polish Templates",
      description:
        "List the style templates available to polish_file and polish_text, with each " +
        "template's description. Use it to choose the template that fits the text and the " +
        "user's request. If none fits, ask the user about the desired style or create one " +
        `with save_polish_template. Templates are Markdown notes in ${config.templateDir}.`,
      inputSchema: {},
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true },
    },
    withVaultErrors(async () => {
      const templates = await listTemplates(config);
      if (templates.length === 0) {
        return textResult(
          "No polish templates yet. polish_file and polish_text work without one; " +
            "create one with save_polish_template."
        );
      }
      const lines = templates.map((template) => {
        const temperature =
          template.temperature === undefined ? "" : ` (temperature ${template.temperature})`;
        return `- ${template.name}: ${template.description || "(no description)"}${temperature}`;
      });
      return textResult(lines.join("\n"));
    })
  );

  server.registerTool(
    "save_polish_template",
    {
      title: "Save Polish Template",
      description:
        "Create or update a style template for polish_file and polish_text. A template is a " +
        "style guide appended to the built-in editing rules (it cannot override them: meaning " +
        "and Markdown structure are always preserved). Good templates state concrete rules " +
        "(tone, sentence length, terminology, punctuation) and may include short " +
        "'Original:' / 'Polished:' example pairs. Write the description and instructions in " +
        "English unless the user explicitly asks for another language; examples may stay in " +
        "the language of the text they illustrate. Saved as a Markdown note in " +
        `${config.templateDir}, which the user can also edit in Obsidian.`,
      inputSchema: {
        name: z
          .string()
          .describe("Template name: 1-64 letters, digits, Hangul, '-' or '_' (no extension)."),
        description: z
          .string()
          .min(1)
          .describe("One line saying when to use this template, in English by default."),
        instructions: z
          .string()
          .min(1)
          .describe("The style guide body (Markdown), in English by default."),
        temperature: z
          .number()
          .min(0)
          .max(2)
          .optional()
          .describe("Sampling temperature for this template. Lower is more conservative."),
        overwrite: z
          .boolean()
          .default(false)
          .describe("Must be true to replace an existing template with the same name."),
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: false, idempotentHint: true, destructiveHint: true },
    },
    withVaultErrors(async (args: SavePolishTemplateArgs) => {
      assertTemplateName(args.name);
      const dirPath = await validatePath(config.templateDir);
      await fs.mkdir(dirPath, { recursive: true });
      const vaultPath = templateVaultPath(config, args.name);
      const filePath = await validatePath(vaultPath);

      let exists = true;
      try {
        await fs.access(filePath);
      } catch {
        exists = false;
      }
      if (exists && !args.overwrite) {
        throw new Error(
          `Template ${args.name} already exists. Pass overwrite: true to replace it.`
        );
      }

      const description = args.description.replace(/\s+/g, " ").trim();
      await writeFileContent(
        filePath,
        serializeTemplate(description, args.temperature, args.instructions)
      );
      return textResult(`${exists ? "Updated" : "Created"} polish template ${vaultPath}.`);
    })
  );
}
