import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { logger } from "./logger.js";
import { VAULT_PATH_NOTE, toVaultPath, validatePath, withVaultErrors } from "./lib.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

export type SyncthingConfig = {
  baseUrl: string;
  apiKey: string;
  folderId: string;
  debounceMs: number;
  timeoutMs: number;
};

type Result<T> = { ok: true; value: T } | { ok: false; error: string };

const DEFAULT_DEBOUNCE_MS = 1000;
const DEFAULT_TIMEOUT_MS = 30_000;
// Above this many pending paths a single full-folder scan is cheaper.
const MAX_SUBS_PER_SCAN = 100;

function parseNumber(raw: string | undefined, fallback: number, min: number, max: number) {
  if (raw === undefined || raw.trim() === "") return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < min || value > max) return fallback;
  return value;
}

function parseBaseUrl(raw: string): Result<string> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, error: "SYNCTHING_URL is not a valid URL" };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, error: "SYNCTHING_URL must use http:// or https://" };
  }
  if (url.username || url.password || url.search || url.hash) {
    return {
      ok: false,
      error: "SYNCTHING_URL must not contain credentials, a query string or a fragment",
    };
  }
  return { ok: true, value: url.toString().replace(/\/+$/, "") };
}

/**
 * Reads Syncthing settings from the environment. Returns null (rescans
 * disabled) unless SYNCTHING_URL, SYNCTHING_API_KEY and SYNCTHING_FOLDER_ID
 * are all set.
 */
export function loadSyncthingConfig(env: NodeJS.ProcessEnv): SyncthingConfig | null {
  const rawUrl = env.SYNCTHING_URL?.trim();
  const apiKey = env.SYNCTHING_API_KEY?.trim();
  const folderId = env.SYNCTHING_FOLDER_ID?.trim();

  if (!rawUrl && !apiKey && !folderId) {
    logger.info("SYNCTHING_URL not set - Syncthing rescans disabled");
    return null;
  }
  const missing = [
    ["SYNCTHING_URL", rawUrl],
    ["SYNCTHING_API_KEY", apiKey],
    ["SYNCTHING_FOLDER_ID", folderId],
  ]
    .filter(([, value]) => !value)
    .map(([name]) => name);
  if (!rawUrl || !apiKey || !folderId) {
    logger.warn(`Missing ${missing.join(", ")} - Syncthing rescans disabled`);
    return null;
  }

  const baseUrl = parseBaseUrl(rawUrl);
  if (!baseUrl.ok) {
    logger.warn(`${baseUrl.error} - Syncthing rescans disabled`);
    return null;
  }

  const config: SyncthingConfig = {
    baseUrl: baseUrl.value,
    apiKey,
    folderId,
    debounceMs: parseNumber(env.SYNCTHING_DEBOUNCE_MS, DEFAULT_DEBOUNCE_MS, 0, 60_000),
    timeoutMs: parseNumber(env.SYNCTHING_TIMEOUT_MS, DEFAULT_TIMEOUT_MS, 1000, 600_000),
  };
  logger.info(
    `Syncthing rescans enabled (url: ${config.baseUrl}, folder: ${folderId}, debounce: ${config.debounceMs}ms)`
  );
  return config;
}

// ---------------------------------------------------------------------------
// REST client
// ---------------------------------------------------------------------------

/**
 * Converts an absolute vault path to a Syncthing `sub` value (relative to the
 * folder root). Returns null for the vault root, which means a full scan.
 */
function toScanSub(absolutePath: string): string | null {
  const vaultPath = toVaultPath(absolutePath);
  if (!vaultPath.startsWith("/")) {
    throw new Error("Path is outside the vault");
  }
  const sub = vaultPath.replace(/^\/+/, "");
  return sub === "" ? null : sub;
}

/**
 * POST /rest/db/scan. An empty `subs` list scans the whole folder.
 * Syncthing answers once the scan has finished.
 */
async function requestScan(config: SyncthingConfig, subs: string[]): Promise<Result<void>> {
  const params = new URLSearchParams({ folder: config.folderId });
  for (const sub of subs) params.append("sub", sub);
  const url = `${config.baseUrl}/rest/db/scan?${params.toString()}`;

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "X-API-Key": config.apiKey },
      signal: AbortSignal.timeout(config.timeoutMs),
    });
    if (!response.ok) {
      const body = (await response.text()).trim().slice(0, 300);
      return {
        ok: false,
        error: `Syncthing returned HTTP ${response.status}${body ? `: ${body}` : ""}`,
      };
    }
    return { ok: true, value: undefined };
  } catch (error) {
    if (error instanceof Error && error.name === "TimeoutError") {
      return { ok: false, error: `Syncthing scan timed out after ${config.timeoutMs}ms` };
    }
    const message = error instanceof Error ? error.message : String(error);
    const cause = error instanceof Error && error.cause instanceof Error ? error.cause.message : "";
    return {
      ok: false,
      error: `Syncthing request failed: ${message}${cause ? ` (${cause})` : ""}`,
    };
  }
}

// ---------------------------------------------------------------------------
// Automatic, debounced rescans after vault writes
// ---------------------------------------------------------------------------

let activeConfig: SyncthingConfig | null = null;
const pendingSubs = new Set<string>();
let pendingFullScan = false;
let flushTimer: NodeJS.Timeout | null = null;

export function setSyncthingConfig(config: SyncthingConfig | null): void {
  activeConfig = config;
}

async function flushPendingScans(): Promise<void> {
  flushTimer = null;
  const config = activeConfig;
  if (!config) return;

  const fullScan = pendingFullScan || pendingSubs.size > MAX_SUBS_PER_SCAN;
  const subs = fullScan ? [] : [...pendingSubs];
  pendingSubs.clear();
  pendingFullScan = false;

  const result = await requestScan(config, subs);
  const target = fullScan ? "full folder" : `${subs.length} path(s)`;
  if (result.ok) {
    logger.debug(`Syncthing rescan requested (${target})`);
  } else {
    logger.warn(`Syncthing rescan (${target}) failed: ${result.error}`);
  }
}

/**
 * Queues a rescan of the given absolute vault paths. No-op when Syncthing is
 * not configured. Never throws, so a failed rescan never fails a write.
 */
export function notifyVaultChange(...absolutePaths: string[]): void {
  if (!activeConfig) return;
  for (const absolutePath of absolutePaths) {
    try {
      const sub = toScanSub(absolutePath);
      if (sub === null) pendingFullScan = true;
      else pendingSubs.add(sub);
    } catch {
      logger.warn("Skipping Syncthing rescan for a path outside the vault");
    }
  }
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    void flushPendingScans();
  }, activeConfig.debounceMs);
  flushTimer.unref();
}

// ---------------------------------------------------------------------------
// MCP tool
// ---------------------------------------------------------------------------

type SyncthingRescanArgs = {
  path?: string | undefined;
};

export function registerSyncthingTools(server: McpServer, config: SyncthingConfig): void {
  server.registerTool(
    "syncthing_rescan",
    {
      title: "Syncthing Rescan",
      description:
        "Ask the host's Syncthing to rescan the vault immediately so changes propagate " +
        "to other devices without waiting for its file watcher. Writes made through this " +
        "server are already rescanned automatically; use this after external changes or " +
        "when sync seems stuck. Omit 'path' (or pass '/') to scan the whole vault. " +
        VAULT_PATH_NOTE,
      inputSchema: {
        path: z
          .string()
          .optional()
          .describe("Vault path of a file or directory to rescan. Defaults to the whole vault."),
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: false, idempotentHint: true, destructiveHint: false },
    },
    withVaultErrors(async (args: SyncthingRescanArgs) => {
      const requested = args.path?.trim() || "/";
      const validPath = await validatePath(requested);
      const sub = toScanSub(validPath);
      const result = await requestScan(config, sub === null ? [] : [sub]);
      if (!result.ok) throw new Error(result.error);
      const text = `Syncthing rescanned ${toVaultPath(validPath)}.`;
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: { content: text },
      };
    })
  );
}
