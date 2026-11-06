#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { InMemoryEventStore } from "@modelcontextprotocol/sdk/examples/shared/inMemoryEventStore.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { Request, Response, NextFunction } from "express";
import express from "express";
import cors from "cors";
import { randomUUID, createHash, randomBytes, timingSafeEqual } from "node:crypto";
import fs from "fs/promises";
import { createReadStream, existsSync } from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { z } from "zod";
import { minimatch } from "minimatch";
import { normalizePath, expandHome } from "./path-utils.js";
import { logger } from "./logger.js";
import {
  // Function imports
  formatSize,
  validatePath,
  getFileStats,
  readFileContent,
  writeFileContent,
  searchFilesWithValidation,
  applyFileEdits,
  tailFile,
  headFile,
  setVaultRoot,
  toVaultPath,
  withVaultErrors,
  VAULT_PATH_NOTE,
} from "./lib.js";
import { loadPolishConfig, registerPolishTools } from "./polish.js";

// Get the directory where this script is located
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, "..");
const envPath = path.join(projectRoot, ".env");

// Generate the owner-only authorization secret.
function generateRandomCredentials(): { authSecret: string } {
  return { authSecret: randomBytes(32).toString("hex") };
}

// Create .env file with the owner-only authorization secret.
async function createEnvFile(): Promise<{ authSecret: string }> {
  const credentials = generateRandomCredentials();
  const envContent = `# Owner-only secret required on the OAuth consent page.
MCP_AUTH_SECRET=${credentials.authSecret}

# Server configuration (optional)
PORT=24024
`;
  await fs.writeFile(envPath, envContent, { encoding: "utf8", mode: 0o600 });
  await fs.chmod(envPath, 0o600);
  return credentials;
}

// Load .env file manually
async function loadEnvFile(): Promise<void> {
  try {
    const content = await fs.readFile(envPath, "utf-8");
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (trimmed && !trimmed.startsWith("#")) {
        const eqIndex = trimmed.indexOf("=");
        if (eqIndex > 0) {
          const key = trimmed.substring(0, eqIndex);
          const value = trimmed.substring(eqIndex + 1);
          if (!process.env[key]) {
            process.env[key] = value;
          }
        }
      }
    }
  } catch {
    // .env doesn't exist, that's fine
  }
}

// Handle --init flag
const rawArgs = process.argv.slice(2);
const hasInit = rawArgs.includes("--init");
const hasForce = rawArgs.includes("--force");

if (hasInit) {
  if (existsSync(envPath) && !hasForce) {
    logger.info(`.env file already exists at: ${envPath}`);
    logger.info("Use --force to overwrite.");
    process.exit(1);
  }

  const credentials = await createEnvFile();
  logger.info("Created .env file with the owner authorization secret:");
  logger.info(`  MCP_AUTH_SECRET=${credentials.authSecret}`);
  logger.info(`File location: ${envPath}`);
  logger.info("You can now start the server with:");
  logger.info("  node dist/index.js /path/to/allowed/directory");
  process.exit(0);
}

// Load .env file if it exists
await loadEnvFile();

const MCP_AUTH_SECRET = process.env.MCP_AUTH_SECRET;

if (!MCP_AUTH_SECRET) {
  logger.error("Missing required environment variable: MCP_AUTH_SECRET");
  process.exit(1);
}

// Token storage (in production, use Redis or similar)
const accessTokens: Map<string, { expiresAt: number }> = new Map();
const refreshTokens: Map<string, { clientId: string; expiresAt: number }> = new Map();

// Authorization code storage for PKCE flow
type AuthorizationCode = {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  expiresAt: number;
};
const authorizationCodes: Map<string, AuthorizationCode> = new Map();

// Pending authorization requests - CSRF protection
// Only requests that were shown the consent screen can be approved
type PendingAuthorization = {
  clientId: string;
  redirectUri: string;
  state: string | undefined;
  codeChallenge: string;
  codeChallengeMethod: string;
  expiresAt: number;
};
const pendingAuthorizations: Map<string, PendingAuthorization> = new Map();
const PENDING_AUTH_EXPIRATION_MS = 10 * 60 * 1000; // 10 minutes

// Dynamic client registration storage
type RegisteredClient = {
  clientId: string;
  clientSecret?: string | undefined;
  tokenEndpointAuthMethod: "none" | "client_secret_post" | "client_secret_basic";
  redirectUris: string[];
  clientName?: string | undefined;
  createdAt: number;
};
const registeredClients: Map<string, RegisteredClient> = new Map();

// Token expiration times
const TOKEN_EXPIRATION_MS = 60 * 60 * 1000; // 1 hour
const REFRESH_TOKEN_EXPIRATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const AUTH_CODE_EXPIRATION_MS = 10 * 60 * 1000; // 10 minutes

const oauthStatePathValue = process.env.OAUTH_STATE_PATH?.trim();
if (oauthStatePathValue && !path.isAbsolute(oauthStatePathValue)) {
  throw new Error("OAUTH_STATE_PATH must be an absolute path when set");
}
const oauthStatePath = oauthStatePathValue ? path.resolve(oauthStatePathValue) : undefined;
let oauthStateWriteQueue: Promise<void> = Promise.resolve();

const expiringTokenSchema = z.object({ expiresAt: z.number().finite() });
const refreshTokenSchema = z.object({
  clientId: z.string(),
  expiresAt: z.number().finite(),
});
const authorizationCodeSchema = z.object({
  clientId: z.string(),
  redirectUri: z.string(),
  codeChallenge: z.string(),
  codeChallengeMethod: z.string(),
  expiresAt: z.number().finite(),
});
const pendingAuthorizationSchema = z.object({
  clientId: z.string(),
  redirectUri: z.string(),
  state: z.string().optional(),
  codeChallenge: z.string(),
  codeChallengeMethod: z.string(),
  expiresAt: z.number().finite(),
});
const registeredClientSchema = z.object({
  clientId: z.string(),
  clientSecret: z.string().optional(),
  tokenEndpointAuthMethod: z.enum(["none", "client_secret_post", "client_secret_basic"]),
  redirectUris: z.array(z.string()),
  clientName: z.string().optional(),
  createdAt: z.number().finite(),
});
const oauthStateSchema = z.object({
  version: z.literal(1),
  accessTokens: z.array(z.tuple([z.string(), expiringTokenSchema])),
  refreshTokens: z.array(z.tuple([z.string(), refreshTokenSchema])),
  authorizationCodes: z.array(z.tuple([z.string(), authorizationCodeSchema])),
  pendingAuthorizations: z.array(z.tuple([z.string(), pendingAuthorizationSchema])),
  registeredClients: z.array(z.tuple([z.string(), registeredClientSchema])),
});

function getOAuthStateSnapshot() {
  return {
    version: 1 as const,
    accessTokens: [...accessTokens.entries()],
    refreshTokens: [...refreshTokens.entries()],
    authorizationCodes: [...authorizationCodes.entries()],
    pendingAuthorizations: [...pendingAuthorizations.entries()],
    registeredClients: [...registeredClients.entries()],
  };
}

async function writeOAuthState(): Promise<void> {
  if (!oauthStatePath) return;

  const snapshot = getOAuthStateSnapshot();
  const stateDirectory = path.dirname(oauthStatePath);
  await fs.mkdir(stateDirectory, { recursive: true, mode: 0o700 });
  await fs.chmod(stateDirectory, 0o700);
  const temporaryPath = `${oauthStatePath}.${randomBytes(16).toString("hex")}.tmp`;

  try {
    await fs.writeFile(temporaryPath, `${JSON.stringify(snapshot, null, 2)}\n`, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600,
    });
    await fs.rename(temporaryPath, oauthStatePath);
  } catch (error) {
    try {
      await fs.unlink(temporaryPath);
    } catch {
      // Ignore cleanup errors and preserve the original write failure.
    }
    throw error;
  }
}

function persistOAuthState(): Promise<void> {
  const write = oauthStateWriteQueue.then(writeOAuthState, writeOAuthState);
  oauthStateWriteQueue = write.catch(() => undefined);
  return write;
}

async function loadOAuthState(): Promise<void> {
  if (!oauthStatePath) {
    logger.warn("OAUTH_STATE_PATH is not set; OAuth state will not survive a restart");
    return;
  }

  let content: string;
  try {
    content = await fs.readFile(oauthStatePath, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      logger.info(`OAuth state file will be created at ${oauthStatePath}`);
      return;
    }
    throw error;
  }

  const state = oauthStateSchema.parse(JSON.parse(content) as unknown);
  const now = Date.now();

  for (const [token, value] of state.accessTokens) {
    if (value.expiresAt > now) accessTokens.set(token, value);
  }
  for (const [token, value] of state.refreshTokens) {
    if (value.expiresAt > now) refreshTokens.set(token, value);
  }
  for (const [code, value] of state.authorizationCodes) {
    if (value.expiresAt > now) authorizationCodes.set(code, value);
  }
  for (const [csrfToken, value] of state.pendingAuthorizations) {
    if (value.expiresAt > now) {
      pendingAuthorizations.set(csrfToken, { ...value, state: value.state });
    }
  }
  for (const [clientId, value] of state.registeredClients) {
    registeredClients.set(clientId, {
      ...value,
      clientSecret: value.clientSecret,
      clientName: value.clientName,
    });
  }

  logger.info(
    `Loaded OAuth state: ${registeredClients.size} clients, ${accessTokens.size} access tokens, ${refreshTokens.size} refresh tokens`
  );

  await persistOAuthState();
}

await loadOAuthState();

async function persistOAuthStateForResponse(res: Response): Promise<boolean> {
  try {
    await persistOAuthState();
    return true;
  } catch (error) {
    logger.error("Failed to persist OAuth state", error);
    if (!res.headersSent) {
      res.status(500).json({
        error: "server_error",
        error_description: "Failed to persist OAuth state",
      });
    }
    return false;
  }
}

// Generate access token
function generateAccessToken(): string {
  return createHash("sha256")
    .update(randomUUID() + Date.now().toString())
    .digest("hex");
}

// Generate refresh token
function generateRefreshToken(): string {
  return randomBytes(32).toString("hex");
}

// Base64URL encode for PKCE
function base64UrlEncode(buffer: Buffer): string {
  return buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

// Verify PKCE code challenge
function verifyCodeChallenge(codeVerifier: string, codeChallenge: string, method: string): boolean {
  if (method === "S256") {
    const hash = createHash("sha256").update(codeVerifier).digest();
    const computed = base64UrlEncode(hash);
    return computed === codeChallenge;
  }
  // plain method (not recommended but supported)
  return codeVerifier === codeChallenge;
}

function verifyMcpAuthSecret(candidate: unknown): boolean {
  if (typeof candidate !== "string" || !MCP_AUTH_SECRET) return false;
  const expected = Buffer.from(MCP_AUTH_SECRET, "utf8");
  const received = Buffer.from(candidate, "utf8");
  return expected.length === received.length && timingSafeEqual(expected, received);
}

type TokenClientCredentials = {
  clientId?: string;
  clientSecret?: string;
};

function readTokenClientCredentials(req: Request): TokenClientCredentials {
  const credentials: TokenClientCredentials = {};
  if (typeof req.body.client_id === "string") credentials.clientId = req.body.client_id;
  if (typeof req.body.client_secret === "string") {
    credentials.clientSecret = req.body.client_secret;
  }

  const authorization = req.headers.authorization;
  if (!credentials.clientId && authorization?.startsWith("Basic ")) {
    try {
      const decoded = Buffer.from(authorization.slice("Basic ".length), "base64").toString("utf8");
      const separator = decoded.indexOf(":");
      if (separator > 0) {
        credentials.clientId = decodeURIComponent(decoded.slice(0, separator));
        credentials.clientSecret = decodeURIComponent(decoded.slice(separator + 1));
      }
    } catch {
      // The token endpoint will return invalid_client below.
    }
  }

  return credentials;
}

function isAllowedRedirectUri(value: unknown): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > 2048) return false;
  try {
    const uri = new URL(value);
    if (uri.username || uri.password || uri.hash) return false;
    if (uri.protocol === "https:") return uri.hostname.length > 0;
    return uri.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(uri.hostname);
  } catch {
    return false;
  }
}

function isAllowedRedirectUriList(value: unknown): value is string[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.length <= 20 &&
    value.every((uri) => isAllowedRedirectUri(uri))
  );
}

function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[character] ?? character
  );
}

function verifyRegisteredClient(clientId: string, clientSecret?: string): boolean {
  const client = registeredClients.get(clientId);
  if (!client) return false;
  if (client.tokenEndpointAuthMethod === "none") return true;
  if (!client.clientSecret || typeof clientSecret !== "string") return false;
  const expected = Buffer.from(client.clientSecret, "utf8");
  const received = Buffer.from(clientSecret, "utf8");
  return expected.length === received.length && timingSafeEqual(expected, received);
}

// Get server URL from request
function getServerUrl(req: Request): string {
  const configured = process.env.MCP_PUBLIC_URL?.replace(/\/+$/, "");
  if (configured) return configured;
  const protocol = req.headers["x-forwarded-proto"] || req.protocol || "http";
  const host = req.headers["x-forwarded-host"] || req.headers.host || "localhost";
  return `${protocol}://${host}`;
}

function getMcpResourceUrl(req: Request): string {
  return `${getServerUrl(req)}/mcp`;
}

function getProtectedResourceMetadataUrl(req: Request): string {
  return `${getServerUrl(req)}/.well-known/oauth-protected-resource`;
}

function setBearerChallenge(req: Request, res: Response, error?: string): void {
  const parameters = [`resource_metadata="${getProtectedResourceMetadataUrl(req)}"`];
  if (error) parameters.unshift(`error="${error}"`);
  res.setHeader("WWW-Authenticate", `Bearer ${parameters.join(", ")}`);
}

// Validate access token
function validateAccessToken(token: string): boolean {
  const tokenData = accessTokens.get(token);
  if (!tokenData) return false;
  if (Date.now() > tokenData.expiresAt) {
    accessTokens.delete(token);
    return false;
  }
  return true;
}

// Auth middleware
function authMiddleware(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    setBearerChallenge(req, res);
    res.status(401).json({
      error: "unauthorized",
      error_description: "Missing or invalid Authorization header. Use Bearer token.",
    });
    return;
  }

  const token = authHeader.substring(7);
  if (!validateAccessToken(token)) {
    setBearerChallenge(req, res, "invalid_token");
    res.status(401).json({
      error: "invalid_token",
      error_description: "Access token is invalid or expired.",
    });
    return;
  }

  next();
}

// Check if a path is unsafe to serve (root, home directory, or system paths)
function isUnsafePath(dirPath: string): boolean {
  const normalized = path.resolve(dirPath);

  // Root directory
  if (normalized === "/") return true;

  // Home directory (Linux/Mac)
  const homeDir = process.env.HOME || process.env.USERPROFILE || "";
  if (homeDir && normalized === path.resolve(homeDir)) return true;

  // System directories (Linux/Mac)
  const unsafePaths = [
    "/bin",
    "/sbin",
    "/usr",
    "/etc",
    "/var",
    "/lib",
    "/lib64",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/root",
    // Mac specific
    "/System",
    "/Library",
    "/Applications",
    "/Users",
    // Windows
    "C:\\",
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
  ];

  for (const unsafe of unsafePaths) {
    if (normalized === path.resolve(unsafe)) return true;
  }

  return false;
}

// Command line argument parsing - filter out flags
const args = process.argv.slice(2).filter((arg) => !arg.startsWith("--"));

if (args.length > 1) {
  logger.error("Only a single vault directory can be served.");
  logger.info("Usage: mcpfs [vault-directory]");
  process.exit(1);
}

// If no directory provided, try to use current directory if safe
const requestedVault = args[0] ?? process.cwd();
if (args.length === 0) {
  if (isUnsafePath(requestedVault)) {
    logger.error("No vault directory specified and current directory is unsafe to serve.");
    logger.error(`Current directory: ${requestedVault}`);
    logger.info("Usage: mcpfs [vault-directory]");
    logger.info("For safety, the server won't automatically serve:");
    logger.info("  - Root directory (/)");
    logger.info("  - Home directory (~)");
    logger.info("  - System directories (/usr, /etc, /var, etc.)");
    logger.info("Please specify the vault directory explicitly, or run from inside it.");
    process.exit(1);
  }
  logger.info(`No vault directory specified. Serving current directory: ${requestedVault}`);
}

// Security: Resolve symlinks in the vault path during startup so later
// validation compares against the real location.
const vaultRoot = await (async () => {
  const absolute = path.resolve(expandHome(requestedVault));
  try {
    const resolved = normalizePath(await fs.realpath(absolute));
    const stats = await fs.stat(resolved);
    if (!stats.isDirectory()) {
      logger.error(`Error: ${resolved} is not a directory`);
      process.exit(1);
    }
    return resolved;
  } catch (err) {
    logger.error(`Error accessing vault directory ${absolute}`, err);
    process.exit(1);
  }
})();

// Initialize the vault root in lib.ts
setVaultRoot(vaultRoot);

// Optional OpenRouter-backed polishing tools (enabled when OPENROUTER_API_KEY is set)
const polishConfig = loadPolishConfig(process.env);

// Type definitions for tool arguments (with undefined to satisfy exactOptionalPropertyTypes)
type ReadTextFileArgs = {
  path: string;
  tail?: number | undefined;
  head?: number | undefined;
};

type ReadMediaFileArgs = {
  path: string;
};

type ReadMultipleFilesArgs = {
  paths: string[];
};

type WriteFileArgs = {
  path: string;
  content: string;
};

type EditFileArgs = {
  path: string;
  edits: Array<{ oldText: string; newText: string }>;
  dryRun?: boolean | undefined;
};

type CreateDirectoryArgs = {
  path: string;
};

type ListDirectoryArgs = {
  path: string;
};

type ListDirectoryWithSizesArgs = {
  path: string;
  sortBy?: "name" | "size" | undefined;
};

type DirectoryTreeArgs = {
  path: string;
  excludePatterns?: string[] | undefined;
};

type MoveFileArgs = {
  source: string;
  destination: string;
};

type SearchFilesArgs = {
  path: string;
  pattern: string;
  excludePatterns?: string[] | undefined;
};

type GetFileInfoArgs = {
  path: string;
};

// Reads a file as a stream of buffers, concatenates them, and then encodes
// the result to a Base64 string. This is a memory-efficient way to handle
// binary data from a stream before the final encoding.
async function readFileAsBase64Stream(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const stream = createReadStream(filePath);
    const chunks: Buffer[] = [];
    stream.on("data", (chunk) => {
      chunks.push(chunk as Buffer);
    });
    stream.on("end", () => {
      const finalBuffer = Buffer.concat(chunks);
      resolve(finalBuffer.toString("base64"));
    });
    stream.on("error", (err) => reject(err));
  });
}

// Factory function to create a new MCP server instance
function createServer() {
  const server = new McpServer({
    name: "secure-filesystem-server",
    version: "0.2.0",
  });

  // Tool registrations

  const readTextFileHandler = withVaultErrors(async (args: ReadTextFileArgs) => {
    const validPath = await validatePath(args.path);

    if (args.head && args.tail) {
      throw new Error("Cannot specify both head and tail parameters simultaneously");
    }

    let content: string;
    if (args.tail) {
      content = await tailFile(validPath, args.tail);
    } else if (args.head) {
      content = await headFile(validPath, args.head);
    } else {
      content = await readFileContent(validPath);
    }

    return {
      content: [{ type: "text" as const, text: content }],
      structuredContent: { content },
    };
  });

  // read_file is retained as a compatibility alias for older MCP clients.
  server.registerTool(
    "read_file",
    {
      title: "Read File (Deprecated)",
      description:
        "Read the complete contents of a file as text. DEPRECATED: Use read_text_file instead.",
      inputSchema: {
        path: z.string(),
        tail: z
          .number()
          .optional()
          .describe("If provided, returns only the last N lines of the file"),
        head: z
          .number()
          .optional()
          .describe("If provided, returns only the first N lines of the file"),
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true },
    },
    readTextFileHandler
  );

  server.registerTool(
    "read_text_file",
    {
      title: "Read Text File",
      description:
        "Read the complete contents of a file from the file system as text. " +
        "Handles various text encodings and provides detailed error messages " +
        "if the file cannot be read. Use this tool when you need to examine " +
        "the contents of a single file. Use the 'head' parameter to read only " +
        "the first N lines of a file, or the 'tail' parameter to read only " +
        "the last N lines of a file. Operates on the file as text regardless of extension. " +
        VAULT_PATH_NOTE,
      inputSchema: {
        path: z.string(),
        tail: z
          .number()
          .optional()
          .describe("If provided, returns only the last N lines of the file"),
        head: z
          .number()
          .optional()
          .describe("If provided, returns only the first N lines of the file"),
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true },
    },
    readTextFileHandler
  );

  server.registerTool(
    "read_media_file",
    {
      title: "Read Media File",
      description:
        "Read an image or audio file. Returns the base64 encoded data and MIME type. " +
        VAULT_PATH_NOTE,
      inputSchema: {
        path: z.string(),
      },
      outputSchema: {
        content: z.array(
          z.object({
            type: z.enum(["image", "audio", "blob"]),
            data: z.string(),
            mimeType: z.string(),
          })
        ),
      },
      annotations: { readOnlyHint: true },
    },
    withVaultErrors(async (args: ReadMediaFileArgs) => {
      const validPath = await validatePath(args.path);
      const extension = path.extname(validPath).toLowerCase();
      const mimeTypes: Record<string, string> = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".bmp": "image/bmp",
        ".svg": "image/svg+xml",
        ".mp3": "audio/mpeg",
        ".wav": "audio/wav",
        ".ogg": "audio/ogg",
        ".flac": "audio/flac",
      };
      const mimeType = mimeTypes[extension] || "application/octet-stream";
      const data = await readFileAsBase64Stream(validPath);

      const type = mimeType.startsWith("image/")
        ? "image"
        : mimeType.startsWith("audio/")
          ? "audio"
          : // Fallback for other binary types, not officially supported by the spec but has been used for some time
            "blob";
      const contentItem = { type: type as "image" | "audio" | "blob", data, mimeType };
      return {
        content: [contentItem],
        structuredContent: { content: [contentItem] },
      } as unknown as CallToolResult;
    })
  );

  server.registerTool(
    "read_multiple_files",
    {
      title: "Read Multiple Files",
      description:
        "Read the contents of multiple files simultaneously. This is more " +
        "efficient than reading files one by one when you need to analyze " +
        "or compare multiple files. Each file's content is returned with its " +
        "path as a reference. Failed reads for individual files won't stop " +
        "the entire operation. " +
        VAULT_PATH_NOTE,
      inputSchema: {
        paths: z
          .array(z.string())
          .min(1)
          .describe("Array of vault paths to read, relative to the vault root '/'."),
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true },
    },
    withVaultErrors(async (args: ReadMultipleFilesArgs) => {
      const results = await Promise.all(
        args.paths.map(async (filePath: string) => {
          try {
            const validPath = await validatePath(filePath);
            const content = await readFileContent(validPath);
            return `${filePath}:\n${content}\n`;
          } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            return `${filePath}: Error - ${errorMessage}`;
          }
        })
      );
      const text = results.join("\n---\n");
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: { content: text },
      };
    })
  );

  server.registerTool(
    "write_file",
    {
      title: "Write File",
      description:
        "Create a new file or completely overwrite an existing file with new content. " +
        "Use with caution as it will overwrite existing files without warning. " +
        "Handles text content with proper encoding. " +
        VAULT_PATH_NOTE,
      inputSchema: {
        path: z.string(),
        content: z.string(),
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: false, idempotentHint: true, destructiveHint: true },
    },
    withVaultErrors(async (args: WriteFileArgs) => {
      const validPath = await validatePath(args.path);
      await writeFileContent(validPath, args.content);
      const text = `Successfully wrote to ${args.path}`;
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: { content: text },
      };
    })
  );

  server.registerTool(
    "edit_file",
    {
      title: "Edit File",
      description:
        "Make line-based edits to a text file. Each edit replaces exact line sequences " +
        "with new content. Returns a git-style diff showing the changes made. " +
        VAULT_PATH_NOTE,
      inputSchema: {
        path: z.string(),
        edits: z.array(
          z.object({
            oldText: z.string().describe("Text to search for - must match exactly"),
            newText: z.string().describe("Text to replace with"),
          })
        ),
        dryRun: z.boolean().default(false).describe("Preview changes using git-style diff format"),
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: false, idempotentHint: false, destructiveHint: true },
    },
    withVaultErrors(async (args: EditFileArgs) => {
      const validPath = await validatePath(args.path);
      if (args.dryRun) {
        const result = await applyFileEdits(validPath, args.edits, true);
        return {
          content: [{ type: "text" as const, text: result }],
          structuredContent: { content: result },
        };
      }
      const result = await applyFileEdits(validPath, args.edits, false);
      return {
        content: [{ type: "text" as const, text: result }],
        structuredContent: { content: result },
      };
    })
  );

  server.registerTool(
    "create_directory",
    {
      title: "Create Directory",
      description:
        "Create a new directory or ensure a directory exists. Can create multiple " +
        "nested directories in one operation. If the directory already exists, " +
        "this operation will succeed silently. Perfect for setting up directory " +
        "structures for projects or ensuring required paths exist. " +
        VAULT_PATH_NOTE,
      inputSchema: {
        path: z.string(),
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: false, idempotentHint: true, destructiveHint: false },
    },
    withVaultErrors(async (args: CreateDirectoryArgs) => {
      const validPath = await validatePath(args.path);
      await fs.mkdir(validPath, { recursive: true });
      const text = `Successfully created directory ${args.path}`;
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: { content: text },
      };
    })
  );

  server.registerTool(
    "list_directory",
    {
      title: "List Directory",
      description:
        "Get a detailed listing of all files and directories in a specified path. " +
        "Results clearly distinguish between files and directories with [FILE] and [DIR] " +
        "prefixes. This tool is essential for understanding directory structure and " +
        "finding specific files within a directory. " +
        VAULT_PATH_NOTE,
      inputSchema: {
        path: z.string(),
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true },
    },
    withVaultErrors(async (args: ListDirectoryArgs) => {
      const validPath = await validatePath(args.path);
      const entries = await fs.readdir(validPath, { withFileTypes: true });
      const formatted = entries
        .map((entry) => `${entry.isDirectory() ? "[DIR]" : "[FILE]"} ${entry.name}`)
        .join("\n");
      return {
        content: [{ type: "text" as const, text: formatted }],
        structuredContent: { content: formatted },
      };
    })
  );

  server.registerTool(
    "list_directory_with_sizes",
    {
      title: "List Directory with Sizes",
      description:
        "Get a detailed listing of all files and directories in a specified path, including sizes. " +
        "Results clearly distinguish between files and directories with [FILE] and [DIR] " +
        "prefixes. This tool is useful for understanding directory structure and " +
        "finding specific files within a directory. " +
        VAULT_PATH_NOTE,
      inputSchema: {
        path: z.string(),
        sortBy: z
          .enum(["name", "size"])
          .optional()
          .default("name")
          .describe("Sort entries by name or size"),
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true },
    },
    withVaultErrors(async (args: ListDirectoryWithSizesArgs) => {
      const validPath = await validatePath(args.path);
      const entries = await fs.readdir(validPath, { withFileTypes: true });

      // Get detailed information for each entry
      const detailedEntries = await Promise.all(
        entries.map(async (entry) => {
          const entryPath = path.join(validPath, entry.name);
          try {
            const stats = await fs.stat(entryPath);
            return {
              name: entry.name,
              isDirectory: entry.isDirectory(),
              size: stats.size,
              mtime: stats.mtime,
            };
          } catch {
            return {
              name: entry.name,
              isDirectory: entry.isDirectory(),
              size: 0,
              mtime: new Date(0),
            };
          }
        })
      );

      // Sort entries based on sortBy parameter
      const sortedEntries = [...detailedEntries].sort((a, b) => {
        if (args.sortBy === "size") {
          return b.size - a.size; // Descending by size
        }
        // Default sort by name
        return a.name.localeCompare(b.name);
      });

      // Format the output
      const formattedEntries = sortedEntries.map(
        (entry) =>
          `${entry.isDirectory ? "[DIR]" : "[FILE]"} ${entry.name.padEnd(30)} ${
            entry.isDirectory ? "" : formatSize(entry.size).padStart(10)
          }`
      );

      // Add summary
      const totalFiles = detailedEntries.filter((e) => !e.isDirectory).length;
      const totalDirs = detailedEntries.filter((e) => e.isDirectory).length;
      const totalSize = detailedEntries.reduce(
        (sum, entry) => sum + (entry.isDirectory ? 0 : entry.size),
        0
      );

      const summary = [
        "",
        `Total: ${totalFiles} files, ${totalDirs} directories`,
        `Combined size: ${formatSize(totalSize)}`,
      ];

      const text = [...formattedEntries, ...summary].join("\n");
      const contentBlock = { type: "text" as const, text };
      return {
        content: [contentBlock],
        structuredContent: { content: text },
      };
    })
  );

  server.registerTool(
    "directory_tree",
    {
      title: "Directory Tree",
      description:
        "Get a recursive tree view of files and directories as a JSON structure. " +
        "Each entry includes 'name', 'type' (file/directory), and 'children' for directories. " +
        "Files have no children array, while directories always have a children array (which may be empty). " +
        "The output is formatted with 2-space indentation for readability. " +
        VAULT_PATH_NOTE,
      inputSchema: {
        path: z.string(),
        excludePatterns: z.array(z.string()).optional().default([]),
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true },
    },
    withVaultErrors(async (args: DirectoryTreeArgs) => {
      type TreeEntry = {
        name: string;
        type: "file" | "directory";
        children?: TreeEntry[];
      };
      const rootPath = args.path;

      async function buildTree(
        currentPath: string,
        excludePatterns: string[] = []
      ): Promise<TreeEntry[]> {
        const validPath = await validatePath(currentPath);
        const entries = await fs.readdir(validPath, { withFileTypes: true });
        const result: TreeEntry[] = [];

        for (const entry of entries) {
          const relativePath = path.relative(rootPath, path.join(currentPath, entry.name));
          const shouldExclude = excludePatterns.some((pattern) => {
            if (pattern.includes("*")) {
              return minimatch(relativePath, pattern, { dot: true });
            }
            // For files: match exact name or as part of path
            // For directories: match as directory path
            return (
              minimatch(relativePath, pattern, { dot: true }) ||
              minimatch(relativePath, `**/${pattern}`, { dot: true }) ||
              minimatch(relativePath, `**/${pattern}/**`, { dot: true })
            );
          });
          if (shouldExclude) continue;

          const entryData: TreeEntry = {
            name: entry.name,
            type: entry.isDirectory() ? "directory" : "file",
          };

          if (entry.isDirectory()) {
            const subPath = path.join(currentPath, entry.name);
            entryData.children = await buildTree(subPath, excludePatterns);
          }

          result.push(entryData);
        }

        return result;
      }

      const treeData = await buildTree(rootPath, args.excludePatterns);
      const text = JSON.stringify(treeData, null, 2);
      const contentBlock = { type: "text" as const, text };
      return {
        content: [contentBlock],
        structuredContent: { content: text },
      };
    })
  );

  server.registerTool(
    "move_file",
    {
      title: "Move File",
      description:
        "Move or rename files and directories. Both source and destination must be within the vault. " +
        VAULT_PATH_NOTE,
      inputSchema: {
        source: z.string(),
        destination: z.string(),
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: false, idempotentHint: false, destructiveHint: false },
    },
    withVaultErrors(async (args: MoveFileArgs) => {
      const validSourcePath = await validatePath(args.source);
      const validDestPath = await validatePath(args.destination);
      await fs.rename(validSourcePath, validDestPath);
      const text = `Successfully moved ${args.source} to ${args.destination}`;
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: { content: text },
      };
    })
  );

  server.registerTool(
    "search_files",
    {
      title: "Search Files",
      description:
        "Recursively search for files and directories matching a pattern. " +
        "The patterns should be glob-style patterns that match paths relative to the search path. " +
        "Use pattern like '*.ext' to match files in current directory, and '**/*.ext' to match files in all subdirectories. " +
        "Returns vault paths of all matching items. Great for finding files when you don't know their exact location. " +
        VAULT_PATH_NOTE,
      inputSchema: {
        path: z.string(),
        pattern: z.string(),
        excludePatterns: z.array(z.string()).optional().default([]),
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true },
    },
    withVaultErrors(async (args: SearchFilesArgs) => {
      const validPath = await validatePath(args.path);
      const results = await searchFilesWithValidation(validPath, args.pattern, {
        excludePatterns: args.excludePatterns,
      });
      const text = results.length > 0 ? results.map(toVaultPath).join("\n") : "No matches found";
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: { content: text },
      };
    })
  );

  server.registerTool(
    "get_file_info",
    {
      title: "Get File Info",
      description:
        "Retrieve detailed metadata about a file or directory. Returns comprehensive " +
        "information including size, creation time, last modified time, permissions, " +
        "and type. This tool is perfect for understanding file characteristics " +
        "without reading the actual content. " +
        VAULT_PATH_NOTE,
      inputSchema: {
        path: z.string(),
      },
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true },
    },
    withVaultErrors(async (args: GetFileInfoArgs) => {
      const validPath = await validatePath(args.path);
      const info = await getFileStats(validPath);
      const text = Object.entries(info)
        .map(([key, value]) => `${key}: ${value}`)
        .join("\n");
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: { content: text },
      };
    })
  );

  server.registerTool(
    "list_allowed_directories",
    {
      title: "List Allowed Directories",
      description:
        "Returns the directory this server can access. The server exposes a single " +
        "vault whose root is '/'; every file and subdirectory in it is accessible. " +
        VAULT_PATH_NOTE,
      inputSchema: {},
      outputSchema: { content: z.string() },
      annotations: { readOnlyHint: true },
    },
    withVaultErrors(async () => {
      const text = "Allowed directories:\n/";
      return {
        content: [{ type: "text" as const, text }],
        structuredContent: { content: text },
      };
    })
  );

  // MCP Roots are intentionally ignored. The server exposes only the
  // operator-selected vault directory passed at startup.

  if (polishConfig) {
    registerPolishTools(server, polishConfig);
  }

  return server;
}

// Express app setup
const app = express();
app.use(
  cors({
    origin: "*",
    methods: "GET,POST,DELETE",
    preflightContinue: false,
    optionsSuccessStatus: 204,
    exposedHeaders: ["mcp-session-id", "last-event-id", "mcp-protocol-version"],
  })
);

// OAuth 2.1 Discovery Endpoints (RFC 9728, RFC 8414)

// Protected Resource Metadata (RFC 9728)
const protectedResourceMetadataHandler = (req: Request, res: Response): void => {
  const serverUrl = getServerUrl(req);
  res.json({
    resource: getMcpResourceUrl(req),
    authorization_servers: [serverUrl],
    bearer_methods_supported: ["header"],
  });
};
app.get("/.well-known/oauth-protected-resource", protectedResourceMetadataHandler);
app.get("/.well-known/oauth-protected-resource/mcp", protectedResourceMetadataHandler);

// Authorization Server Metadata (RFC 8414)
app.get("/.well-known/oauth-authorization-server", (req: Request, res: Response) => {
  const serverUrl = getServerUrl(req);
  res.json({
    issuer: serverUrl,
    authorization_endpoint: `${serverUrl}/authorize`,
    token_endpoint: `${serverUrl}/token`,
    registration_endpoint: `${serverUrl}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    scopes_supported: ["offline_access"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
    code_challenge_methods_supported: ["S256"],
    service_documentation: "https://github.com/jeswin/mcpfs",
  });
});

// Dynamic Client Registration (RFC 7591)
app.post("/register", express.json(), async (req: Request, res: Response) => {
  const { redirect_uris, client_name } = req.body;

  if (!isAllowedRedirectUriList(redirect_uris)) {
    res.status(400).json({
      error: "invalid_redirect_uri",
      error_description: "redirect_uris must contain one to twenty valid HTTP(S) URIs",
    });
    return;
  }

  if (client_name !== undefined && (typeof client_name !== "string" || client_name.length > 200)) {
    res.status(400).json({
      error: "invalid_client_metadata",
      error_description: "client_name must be a string of at most 200 characters",
    });
    return;
  }

  const requestedAuthMethod = req.body.token_endpoint_auth_method;
  const tokenEndpointAuthMethod =
    requestedAuthMethod === "none" ||
    requestedAuthMethod === "client_secret_post" ||
    requestedAuthMethod === "client_secret_basic"
      ? requestedAuthMethod
      : "client_secret_post";
  const clientId = randomBytes(16).toString("hex");
  const clientSecret =
    tokenEndpointAuthMethod === "none" ? undefined : randomBytes(32).toString("hex");

  registeredClients.set(clientId, {
    clientId,
    clientSecret,
    tokenEndpointAuthMethod,
    redirectUris: redirect_uris,
    clientName: client_name,
    createdAt: Date.now(),
  });

  if (!(await persistOAuthStateForResponse(res))) {
    registeredClients.delete(clientId);
    return;
  }

  logger.info(
    `Registered new client: ${clientId} (${client_name || "unnamed"}), token_auth=${tokenEndpointAuthMethod}, redirects=${redirect_uris.length}`
  );

  const response: Record<string, unknown> = {
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris,
    client_name,
    token_endpoint_auth_method: tokenEndpointAuthMethod,
  };
  if (clientSecret) response.client_secret = clientSecret;
  res.status(201).json(response);
});

// Authorization Endpoint with PKCE - Shows consent screen
app.get("/authorize", async (req: Request, res: Response) => {
  const { response_type, client_id, redirect_uri, state, code_challenge, code_challenge_method } =
    req.query as Record<string, string>;

  // Validate required parameters
  if (response_type !== "code") {
    res.status(400).send("Invalid response_type. Only 'code' is supported.");
    return;
  }

  if (!client_id) {
    res.status(400).send("Missing client_id");
    return;
  }

  // Check if client is registered
  const client = registeredClients.get(client_id);
  if (!client) {
    res.status(400).send(`Unknown client_id: ${client_id}`);
    return;
  }

  if (!redirect_uri) {
    res.status(400).send("Missing redirect_uri");
    return;
  }

  // Redirect URIs are compared exactly with the values registered by the client.
  const isValidRedirect = client.redirectUris.includes(redirect_uri);

  if (!isValidRedirect) {
    res.status(400).send(`Invalid redirect_uri: ${redirect_uri}`);
    return;
  }

  if (!code_challenge || !code_challenge_method) {
    res.status(400).send("PKCE required: missing code_challenge or code_challenge_method");
    return;
  }

  if (code_challenge_method !== "S256") {
    res.status(400).send("Only S256 code_challenge_method is supported");
    return;
  }

  // Generate CSRF token and store pending authorization
  const csrfToken = randomBytes(32).toString("hex");
  pendingAuthorizations.set(csrfToken, {
    clientId: client_id,
    redirectUri: redirect_uri,
    state: state || undefined,
    codeChallenge: code_challenge,
    codeChallengeMethod: code_challenge_method,
    expiresAt: Date.now() + PENDING_AUTH_EXPIRATION_MS,
  });
  if (!(await persistOAuthStateForResponse(res))) {
    pendingAuthorizations.delete(csrfToken);
    return;
  }
  logger.info(`Authorization requested for client: ${client_id}`);

  // Show consent screen
  const clientName = escapeHtml(client.clientName || client_id);
  const escapedDirectories = escapeHtml(vaultRoot);
  const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize Access - mcpfs</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: white;
      border-radius: 16px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
      padding: 40px;
      max-width: 420px;
      width: 100%;
    }
    h1 {
      color: #1a202c;
      font-size: 24px;
      margin-bottom: 8px;
    }
    .subtitle {
      color: #718096;
      font-size: 14px;
      margin-bottom: 24px;
    }
    .client-info {
      background: #f7fafc;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
    }
    .client-name {
      font-weight: 600;
      color: #2d3748;
      font-size: 16px;
    }
    .permissions {
      margin-bottom: 24px;
    }
    .permissions h3 {
      color: #4a5568;
      font-size: 14px;
      margin-bottom: 12px;
    }
    .permission-item {
      display: flex;
      align-items: center;
      padding: 8px 0;
      color: #4a5568;
      font-size: 14px;
    }
    .permission-item::before {
      content: "✓";
      color: #48bb78;
      font-weight: bold;
      margin-right: 10px;
    }
    .buttons {
      display: flex;
      gap: 12px;
    }
    button {
      flex: 1;
      padding: 12px 24px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
    }
    .allow {
      background: #667eea;
      color: white;
      border: none;
    }
    .allow:hover { background: #5a67d8; }
    .deny {
      background: white;
      color: #4a5568;
      border: 1px solid #e2e8f0;
    }
    .deny:hover { background: #f7fafc; }
    .directories {
      margin-top: 16px;
      padding: 12px;
      background: #fffaf0;
      border: 1px solid #fbd38d;
      border-radius: 8px;
      font-size: 12px;
      color: #744210;
    }
    .directories strong { display: block; margin-bottom: 4px; }
    .dir-list { font-family: monospace; word-break: break-all; }
    .secret-field { margin-top: 16px; }
    .secret-field label { display: block; color: #4a5568; font-size: 14px; font-weight: 600; margin-bottom: 6px; }
    .secret-field input { width: 100%; padding: 10px; border: 1px solid #cbd5e0; border-radius: 6px; }
    .secret-field small { display: block; color: #718096; font-size: 12px; margin-top: 6px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Authorize Access</h1>
    <p class="subtitle">An application is requesting access to your files</p>

    <div class="client-info">
      <div class="client-name">${clientName}</div>
    </div>

      <div class="permissions">
      <h3>This application will be able to:</h3>
      <div class="permission-item">Read files and directories</div>
      <div class="permission-item">Modify files in the synchronized directory</div>
      <div class="permission-item">Create directories in the synchronized directory</div>
        <div class="permission-item">Search and list files</div>
      </div>

    <div class="directories">
      <strong>Allowed directories:</strong>
      <div class="dir-list">${escapedDirectories}</div>
    </div>

    <form method="POST" action="/authorize" style="margin-top: 24px;">
      <input type="hidden" name="csrf_token" value="${csrfToken}">
      <div class="secret-field">
        <label for="access_secret">Private access secret</label>
        <input id="access_secret" name="access_secret" type="password" autocomplete="off" required>
        <small>This server's private secret is required to approve access.</small>
      </div>
      <div class="buttons">
        <button type="submit" name="action" value="allow" class="allow">Allow</button>
        <button type="submit" name="action" value="deny" class="deny" formnovalidate>Deny</button>
      </div>
    </form>
  </div>
</body>
</html>`;

  res.setHeader(
    "Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
  );
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.type("html").send(html);
});

// Handle authorization form submission
app.post(
  "/authorize",
  express.urlencoded({ extended: true }),
  async (req: Request, res: Response) => {
    const { csrf_token, action } = req.body;

    // Verify CSRF token - this proves the user saw our consent screen
    if (!csrf_token || typeof csrf_token !== "string") {
      res.status(400).send("Invalid request: missing CSRF token");
      return;
    }

    const pendingAuth = pendingAuthorizations.get(csrf_token);
    if (!pendingAuth) {
      res.status(400).send("Invalid or expired authorization request. Please try again.");
      return;
    }

    // Check expiration
    if (Date.now() > pendingAuth.expiresAt) {
      pendingAuthorizations.delete(csrf_token);
      logger.warn(`Expired authorization request for client: ${pendingAuth.clientId}`);
      if (!(await persistOAuthStateForResponse(res))) return;
      res.status(400).send("Authorization request expired. Please try again.");
      return;
    }

    // Build redirect URL
    const redirectUrl = new URL(pendingAuth.redirectUri);

    if (action !== "allow") {
      pendingAuthorizations.delete(csrf_token);
      logger.info(`Authorization denied for client: ${pendingAuth.clientId}`);
      // User denied access
      redirectUrl.searchParams.set("error", "access_denied");
      redirectUrl.searchParams.set("error_description", "User denied the authorization request");
      if (pendingAuth.state) redirectUrl.searchParams.set("state", pendingAuth.state);
      if (!(await persistOAuthStateForResponse(res))) return;
      res.redirect(redirectUrl.toString());
      return;
    }

    if (!verifyMcpAuthSecret(req.body.access_secret)) {
      logger.warn(`Invalid owner secret for client: ${pendingAuth.clientId}`);
      res.status(403).send("Access denied: invalid private access secret.");
      return;
    }

    // Consume the pending request only after a valid approval.
    pendingAuthorizations.delete(csrf_token);

    // User approved - generate authorization code
    const code = randomBytes(32).toString("hex");

    authorizationCodes.set(code, {
      clientId: pendingAuth.clientId,
      redirectUri: pendingAuth.redirectUri,
      codeChallenge: pendingAuth.codeChallenge,
      codeChallengeMethod: pendingAuth.codeChallengeMethod,
      expiresAt: Date.now() + AUTH_CODE_EXPIRATION_MS,
    });

    if (!(await persistOAuthStateForResponse(res))) {
      authorizationCodes.delete(code);
      pendingAuthorizations.set(csrf_token, pendingAuth);
      return;
    }

    logger.info(`Authorization code issued for client: ${pendingAuth.clientId}`);

    redirectUrl.searchParams.set("code", code);
    if (pendingAuth.state) redirectUrl.searchParams.set("state", pendingAuth.state);

    // Do not log the redirect URL: it contains a one-time authorization code
    // and may also contain the client's state value.
    res.redirect(redirectUrl.toString());
  }
);

// Token Endpoint - Supports authorization_code and refresh_token
app.post(
  "/token",
  express.json(),
  express.urlencoded({ extended: true }),
  async (req: Request, res: Response) => {
    const clientCredentials = readTokenClientCredentials(req);
    const grantType = req.body.grant_type;
    const clientId = clientCredentials.clientId;
    const clientSecret = clientCredentials.clientSecret;
    logger.info(
      `Token request received: grant_type=${grantType}, client_id=${clientId || "omitted"}`
    );

    // Handle authorization_code grant (OAuth 2.1 with PKCE)
    if (grantType === "authorization_code") {
      const code = req.body.code;
      const codeVerifier = req.body.code_verifier;
      const redirectUri = req.body.redirect_uri;

      if (!code || !codeVerifier) {
        logger.debug(`Token error: Missing code or code_verifier`);
        res.status(400).json({
          error: "invalid_request",
          error_description: "Missing code or code_verifier",
        });
        return;
      }

      const authCode = authorizationCodes.get(code);
      if (!authCode) {
        logger.debug(`Token error: Invalid or expired authorization code`);
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Invalid or expired authorization code",
        });
        return;
      }

      // Verify code hasn't expired
      if (Date.now() > authCode.expiresAt) {
        authorizationCodes.delete(code);
        logger.debug(`Token error: Authorization code has expired`);
        if (!(await persistOAuthStateForResponse(res))) return;
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Authorization code has expired",
        });
        return;
      }

      // Verify client_id matches (if provided)
      // OAuth 2.1 allows client_id to be omitted if the code is already bound to the client
      if (clientId && authCode.clientId !== clientId) {
        logger.debug(
          `Token error: Client ID mismatch - expected ${authCode.clientId}, got ${clientId}`
        );
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Client ID mismatch",
        });
        return;
      }

      const effectiveClientId = authCode.clientId;
      if (!verifyRegisteredClient(effectiveClientId, clientSecret)) {
        logger.warn(`Token error: invalid client credentials for ${effectiveClientId}`);
        res.status(401).json({
          error: "invalid_client",
          error_description: "Invalid or missing OAuth client credentials",
        });
        return;
      }

      // Verify redirect_uri matches
      if (authCode.redirectUri !== redirectUri) {
        logger.debug(
          `Token error: Redirect URI mismatch - expected ${authCode.redirectUri}, got ${redirectUri}`
        );
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Redirect URI mismatch",
        });
        return;
      }

      // Verify PKCE code_verifier
      if (
        !verifyCodeChallenge(codeVerifier, authCode.codeChallenge, authCode.codeChallengeMethod)
      ) {
        logger.debug(`Token error: Invalid code_verifier`);
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Invalid code_verifier",
        });
        return;
      }

      // Delete the used authorization code (one-time use)
      authorizationCodes.delete(code);

      // Generate tokens
      const accessToken = generateAccessToken();
      const refreshToken = generateRefreshToken();
      const expiresIn = TOKEN_EXPIRATION_MS / 1000;

      accessTokens.set(accessToken, {
        expiresAt: Date.now() + TOKEN_EXPIRATION_MS,
      });

      refreshTokens.set(refreshToken, {
        clientId: effectiveClientId,
        expiresAt: Date.now() + REFRESH_TOKEN_EXPIRATION_MS,
      });

      if (!(await persistOAuthStateForResponse(res))) return;

      logger.info(`Access token issued for client: ${effectiveClientId} (authorization_code)`);

      res.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: expiresIn,
        refresh_token: refreshToken,
      });
      return;
    }

    // Handle refresh_token grant
    if (grantType === "refresh_token") {
      const refreshToken = req.body.refresh_token;

      if (!refreshToken) {
        res.status(400).json({
          error: "invalid_request",
          error_description: "Missing refresh_token",
        });
        return;
      }

      const storedRefresh = refreshTokens.get(refreshToken);
      if (!storedRefresh) {
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Invalid refresh token",
        });
        return;
      }

      if (Date.now() > storedRefresh.expiresAt) {
        refreshTokens.delete(refreshToken);
        if (!(await persistOAuthStateForResponse(res))) return;
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Refresh token has expired",
        });
        return;
      }

      const effectiveClientId = clientId || storedRefresh.clientId;
      if (effectiveClientId !== storedRefresh.clientId) {
        res.status(400).json({
          error: "invalid_grant",
          error_description: "Client ID mismatch",
        });
        return;
      }
      if (!verifyRegisteredClient(effectiveClientId, clientSecret)) {
        res.status(401).json({
          error: "invalid_client",
          error_description: "Invalid or missing OAuth client credentials",
        });
        return;
      }

      // Rotate refresh token (OAuth 2.1 requirement)
      refreshTokens.delete(refreshToken);
      const newRefreshToken = generateRefreshToken();
      const accessToken = generateAccessToken();
      const expiresIn = TOKEN_EXPIRATION_MS / 1000;

      accessTokens.set(accessToken, {
        expiresAt: Date.now() + TOKEN_EXPIRATION_MS,
      });

      refreshTokens.set(newRefreshToken, {
        clientId: storedRefresh.clientId,
        expiresAt: Date.now() + REFRESH_TOKEN_EXPIRATION_MS,
      });

      if (!(await persistOAuthStateForResponse(res))) return;

      logger.info(`Access token refreshed for client: ${storedRefresh.clientId}`);

      res.json({
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: expiresIn,
        refresh_token: newRefreshToken,
      });
      return;
    }

    res.status(400).json({
      error: "unsupported_grant_type",
      error_description: "Supported grant types: authorization_code, refresh_token",
    });
  }
);

// Map sessionId to server transport for each client
const transports: Map<string, StreamableHTTPServerTransport> = new Map();

// Handle POST requests for client messages (protected)
app.post("/mcp", authMiddleware, async (req: Request, res: Response) => {
  logger.debug("Received MCP POST request");
  try {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;

    let transport: StreamableHTTPServerTransport;

    if (sessionId && transports.has(sessionId)) {
      const existingTransport = transports.get(sessionId);
      if (!existingTransport) {
        res.status(400).json({
          jsonrpc: "2.0",
          error: { code: -32000, message: "Session not found" },
          id: req?.body?.id,
        });
        return;
      }
      transport = existingTransport;
    } else if (!sessionId) {
      const server = createServer();

      const eventStore = new InMemoryEventStore();
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        eventStore,
        onsessioninitialized: (sid: string) => {
          logger.debug(`Session initialized with ID: ${sid}`);
          transports.set(sid, transport);
        },
      });

      server.server.onclose = async () => {
        const sid = transport.sessionId;
        if (sid && transports.has(sid)) {
          logger.debug(`Transport closed for session ${sid}, removing from transports map`);
          transports.delete(sid);
        }
      };

      await server.connect(transport as Parameters<typeof server.connect>[0]);
      await transport.handleRequest(req, res);
      return;
    } else {
      res.status(400).json({
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "Bad Request: No valid session ID provided",
        },
        id: req?.body?.id,
      });
      return;
    }

    await transport.handleRequest(req, res);
  } catch (err) {
    logger.error("Error handling MCP request", err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: {
          code: -32603,
          message: "Internal server error",
        },
        id: req?.body?.id,
      });
    }
  }
});

// Handle GET requests for SSE streams (protected)
app.get("/mcp", authMiddleware, async (req: Request, res: Response) => {
  logger.debug("Received MCP GET request");
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (!sessionId || !transports.has(sessionId)) {
    res.status(400).json({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Bad Request: No valid session ID provided",
      },
      id: req?.body?.id,
    });
    return;
  }

  const transport = transports.get(sessionId);
  if (!transport) {
    res.status(400).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Session not found" },
      id: req?.body?.id,
    });
    return;
  }
  await transport.handleRequest(req, res);
});

// Handle DELETE requests for session termination (protected)
app.delete("/mcp", authMiddleware, async (req: Request, res: Response) => {
  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  if (!sessionId || !transports.has(sessionId)) {
    res.status(400).json({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Bad Request: No valid session ID provided",
      },
      id: req?.body?.id,
    });
    return;
  }

  logger.debug(`Session termination request for session ${sessionId}`);

  const transport = transports.get(sessionId);
  if (!transport) {
    res.status(400).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Session not found" },
      id: req?.body?.id,
    });
    return;
  }

  try {
    await transport.handleRequest(req, res);
  } catch (err) {
    logger.error("Error handling session termination", err);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: {
          code: -32603,
          message: "Error handling session termination",
        },
        id: req?.body?.id,
      });
    }
  }
});

// Start the server
const PORT = process.env.PORT || 24024;
const httpServer = app.listen(PORT, () => {
  logger.info(`MCP Filesystem Server (HTTP Streaming) listening on port ${PORT}`);
  logger.info(`Vault root: ${vaultRoot}`);
});

// Handle server errors
httpServer.on("error", (err: unknown) => {
  const code =
    typeof err === "object" && err !== null && "code" in err
      ? (err as { code?: unknown }).code
      : undefined;
  if (code === "EADDRINUSE") {
    logger.error(`Failed to start: Port ${PORT} is already in use.`);
  } else {
    logger.error("HTTP server encountered an error", err);
  }
  process.exit(1);
});

// Handle server shutdown
process.on("SIGINT", async () => {
  logger.info("Shutting down server...");

  for (const [sessionId, transport] of transports) {
    try {
      logger.debug(`Closing transport for session ${sessionId}`);
      await transport.close();
      transports.delete(sessionId);
    } catch (err) {
      logger.error(`Error closing transport for session ${sessionId}`, err);
    }
  }

  httpServer.close(() => {
    logger.info("Server shutdown complete");
    process.exit(0);
  });
});
