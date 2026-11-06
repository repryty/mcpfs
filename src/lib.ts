import fs from "fs/promises";
import path from "path";
import { randomBytes } from "crypto";
import { createTwoFilesPatch } from "diff";
import { minimatch } from "minimatch";
import { normalizePath } from "./path-utils.js";
import { isPathWithinAllowedDirectories } from "./path-validation.js";

// The single vault directory exposed by this server. Every tool path is
// interpreted relative to this directory, which clients see as "/".
let vaultRoot = "";

// Set the vault root (an absolute, symlink-resolved directory path)
export function setVaultRoot(directory: string): void {
  vaultRoot = directory;
}

// Get the absolute vault root
export function getVaultRoot(): string {
  return vaultRoot;
}

/**
 * Maps a client-supplied vault path to an absolute filesystem path.
 *
 * "/", "", "." are the vault root. "notes/a.md", "/notes/a.md" and
 * "./notes/a.md" all address the same file. For backward compatibility, an
 * absolute path that already points inside the vault is accepted as-is.
 * The result is not yet access-checked; use validatePath for that.
 */
export function resolveVaultPath(requestedPath: string): string {
  if (!vaultRoot) {
    throw new Error("Vault root is not configured");
  }
  const trimmed = requestedPath.trim();
  if (path.isAbsolute(trimmed)) {
    const legacyAbsolute = normalizePath(path.resolve(trimmed));
    if (isPathWithinAllowedDirectories(legacyAbsolute, [vaultRoot])) {
      return legacyAbsolute;
    }
  }
  const relative = trimmed.replace(/^[/\\]+/, "");
  return path.resolve(vaultRoot, relative);
}

/**
 * Converts an absolute filesystem path inside the vault to its vault path
 * ("/" for the root, "/notes/a.md" for a file). Paths outside the vault are
 * returned unchanged.
 */
export function toVaultPath(absolutePath: string): string {
  if (!vaultRoot) return absolutePath;
  const relative = path.relative(vaultRoot, absolutePath);
  if (relative === "") return "/";
  if (relative.startsWith("..") || path.isAbsolute(relative)) return absolutePath;
  return "/" + relative.split(path.sep).join("/");
}

/**
 * Replaces absolute vault-root prefixes in a message (e.g. fs error text)
 * with vault paths so the host filesystem layout is not exposed.
 */
export function maskVaultRoot(message: string): string {
  if (!vaultRoot) return message;
  return message
    .split(vaultRoot + path.sep)
    .join("/")
    .split(vaultRoot)
    .join("/");
}

// All tool paths are relative to the vault root, which clients see as "/".
export const VAULT_PATH_NOTE =
  "Paths are relative to the vault root, which is '/'. " +
  "For example 'notes/today.md' and '/notes/today.md' are the same file.";

// Wraps a tool handler so that error messages never expose the absolute
// location of the vault on the host.
export function withVaultErrors<A extends unknown[], R>(
  handler: (...handlerArgs: A) => Promise<R>
): (...handlerArgs: A) => Promise<R> {
  return async (...handlerArgs: A) => {
    try {
      return await handler(...handlerArgs);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(maskVaultRoot(message));
    }
  };
}

// Type definitions
type FileInfo = {
  size: number;
  created: Date;
  modified: Date;
  accessed: Date;
  isDirectory: boolean;
  isFile: boolean;
  permissions: string;
};

export type SearchOptions = {
  excludePatterns?: string[] | undefined;
};

export type SearchResult = {
  path: string;
  isDirectory: boolean;
};

// Pure Utility Functions
export function formatSize(bytes: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  if (bytes === 0) return "0 B";

  const i = Math.floor(Math.log(bytes) / Math.log(1024));

  if (i < 0 || i === 0) return `${bytes} ${units[0]}`;

  const unitIndex = Math.min(i, units.length - 1);
  return `${(bytes / Math.pow(1024, unitIndex)).toFixed(2)} ${units[unitIndex]}`;
}

export function normalizeLineEndings(text: string): string {
  return text.replace(/\r\n/g, "\n");
}

export function createUnifiedDiff(
  originalContent: string,
  newContent: string,
  filepath: string = "file"
): string {
  // Ensure consistent line endings for diff
  const normalizedOriginal = normalizeLineEndings(originalContent);
  const normalizedNew = normalizeLineEndings(newContent);

  return createTwoFilesPatch(
    filepath,
    filepath,
    normalizedOriginal,
    normalizedNew,
    "original",
    "modified"
  );
}

// Security & Validation Functions
export async function validatePath(requestedPath: string): Promise<string> {
  if (requestedPath.includes("\x00")) {
    throw new Error("Access denied - path contains a null byte");
  }
  const absolute = resolveVaultPath(requestedPath);
  const allowed = [vaultRoot];

  // Security: Check if path is within the vault before any file operations
  if (!isPathWithinAllowedDirectories(normalizePath(absolute), allowed)) {
    throw new Error(`Access denied - path outside the vault: ${requestedPath}`);
  }

  // Security: Handle symlinks by checking their real path to prevent symlink attacks
  // This prevents attackers from creating symlinks that point outside the vault
  try {
    const realPath = await fs.realpath(absolute);
    if (!isPathWithinAllowedDirectories(normalizePath(realPath), allowed)) {
      throw new Error(`Access denied - symlink target outside the vault: ${requestedPath}`);
    }
    return realPath;
  } catch (error) {
    // Security: For new files that don't exist yet, verify parent directory
    // This ensures we can't create files in unauthorized locations
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      const parentDir = path.dirname(absolute);
      try {
        const realParentPath = await fs.realpath(parentDir);
        if (!isPathWithinAllowedDirectories(normalizePath(realParentPath), allowed)) {
          throw new Error(
            `Access denied - parent directory outside the vault: ${toVaultPath(parentDir)}`
          );
        }
        return absolute;
      } catch {
        throw new Error(`Parent directory does not exist: ${toVaultPath(parentDir)}`);
      }
    }
    throw error;
  }
}

// File Operations
export async function getFileStats(filePath: string): Promise<FileInfo> {
  const stats = await fs.stat(filePath);
  return {
    size: stats.size,
    created: stats.birthtime,
    modified: stats.mtime,
    accessed: stats.atime,
    isDirectory: stats.isDirectory(),
    isFile: stats.isFile(),
    permissions: stats.mode.toString(8).slice(-3),
  };
}

export async function readFileContent(
  filePath: string,
  encoding: string = "utf-8"
): Promise<string> {
  return await fs.readFile(filePath, encoding as BufferEncoding);
}

export async function writeFileContent(filePath: string, content: string): Promise<void> {
  try {
    // Security: 'wx' flag ensures exclusive creation - fails if file/symlink exists,
    // preventing writes through pre-existing symlinks
    await fs.writeFile(filePath, content, { encoding: "utf-8", flag: "wx" });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      // Security: Use atomic rename to prevent race conditions where symlinks
      // could be created between validation and write. Rename operations
      // replace the target file atomically and don't follow symlinks.
      const tempPath = `${filePath}.${randomBytes(16).toString("hex")}.tmp`;
      try {
        await fs.writeFile(tempPath, content, "utf-8");
        await fs.rename(tempPath, filePath);
      } catch (renameError) {
        try {
          await fs.unlink(tempPath);
        } catch {
          /* ignore cleanup error */
        }
        throw renameError;
      }
    } else {
      throw error;
    }
  }
}

// File Editing Functions
type FileEdit = {
  oldText: string;
  newText: string;
};

export async function applyFileEdits(
  filePath: string,
  edits: FileEdit[],
  dryRun: boolean = false
): Promise<string> {
  // Read file content and normalize line endings
  const content = normalizeLineEndings(await fs.readFile(filePath, "utf-8"));

  // Apply edits sequentially
  let modifiedContent = content;
  for (const edit of edits) {
    const normalizedOld = normalizeLineEndings(edit.oldText);
    const normalizedNew = normalizeLineEndings(edit.newText);

    // If exact match exists, use it
    if (modifiedContent.includes(normalizedOld)) {
      modifiedContent = modifiedContent.replace(normalizedOld, normalizedNew);
      continue;
    }

    // Otherwise, try line-by-line matching with flexibility for whitespace
    const oldLines = normalizedOld.split("\n");
    const contentLines = modifiedContent.split("\n");
    let matchFound = false;

    for (let i = 0; i <= contentLines.length - oldLines.length; i++) {
      const potentialMatch = contentLines.slice(i, i + oldLines.length);

      // Compare lines with normalized whitespace
      const isMatch = oldLines.every((oldLine, j) => {
        const contentLine = potentialMatch[j];
        return contentLine !== undefined && oldLine.trim() === contentLine.trim();
      });

      if (isMatch) {
        // Preserve original indentation of first line
        const firstLine = contentLines[i];
        const originalIndent = firstLine !== undefined ? (firstLine.match(/^\s*/)?.[0] ?? "") : "";
        const newLines = normalizedNew.split("\n").map((line, j) => {
          if (j === 0) return originalIndent + line.trimStart();
          // For subsequent lines, try to preserve relative indentation
          const oldLine = oldLines[j];
          const oldIndent = oldLine !== undefined ? (oldLine.match(/^\s*/)?.[0] ?? "") : "";
          const newIndent = line.match(/^\s*/)?.[0] ?? "";
          if (oldIndent && newIndent) {
            const relativeIndent = newIndent.length - oldIndent.length;
            return originalIndent + " ".repeat(Math.max(0, relativeIndent)) + line.trimStart();
          }
          return line;
        });

        contentLines.splice(i, oldLines.length, ...newLines);
        modifiedContent = contentLines.join("\n");
        matchFound = true;
        break;
      }
    }

    if (!matchFound) {
      throw new Error(`Could not find exact match for edit:\n${edit.oldText}`);
    }
  }

  // Create unified diff
  const diff = createUnifiedDiff(content, modifiedContent, toVaultPath(filePath));

  // Format diff with appropriate number of backticks
  let numBackticks = 3;
  while (diff.includes("`".repeat(numBackticks))) {
    numBackticks++;
  }
  const formattedDiff = `${"`".repeat(numBackticks)}diff\n${diff}${"`".repeat(numBackticks)}\n\n`;

  if (!dryRun) {
    // Security: Use atomic rename to prevent race conditions where symlinks
    // could be created between validation and write. Rename operations
    // replace the target file atomically and don't follow symlinks.
    const tempPath = `${filePath}.${randomBytes(16).toString("hex")}.tmp`;
    try {
      await fs.writeFile(tempPath, modifiedContent, "utf-8");
      await fs.rename(tempPath, filePath);
    } catch (err) {
      try {
        await fs.unlink(tempPath);
      } catch {
        /* ignore cleanup error */
      }
      throw err;
    }
  }

  return formattedDiff;
}

// Memory-efficient implementation to get the last N lines of a file
export async function tailFile(filePath: string, numLines: number): Promise<string> {
  const CHUNK_SIZE = 1024; // Read 1KB at a time
  const stats = await fs.stat(filePath);
  const fileSize = stats.size;

  if (fileSize === 0) return "";

  // Open file for reading
  const fileHandle = await fs.open(filePath, "r");
  try {
    const lines: string[] = [];
    let position = fileSize;
    const chunk = Buffer.alloc(CHUNK_SIZE);
    let linesFound = 0;
    let remainingText = "";

    // Read chunks from the end of the file until we have enough lines
    while (position > 0 && linesFound < numLines) {
      const size = Math.min(CHUNK_SIZE, position);
      position -= size;

      const { bytesRead } = await fileHandle.read(chunk, 0, size, position);
      if (!bytesRead) break;

      // Get the chunk as a string and prepend any remaining text from previous iteration
      const readData = chunk.slice(0, bytesRead).toString("utf-8");
      const chunkText = readData + remainingText;

      // Split by newlines and count
      const chunkLines = normalizeLineEndings(chunkText).split("\n");

      // If this isn't the end of the file, the first line is likely incomplete
      // Save it to prepend to the next chunk
      if (position > 0) {
        remainingText = chunkLines[0] ?? "";
        chunkLines.shift(); // Remove the first (incomplete) line
      }

      // Add lines to our result (up to the number we need)
      for (let i = chunkLines.length - 1; i >= 0 && linesFound < numLines; i--) {
        const line = chunkLines[i];
        if (line !== undefined) {
          lines.unshift(line);
          linesFound++;
        }
      }
    }

    return lines.join("\n");
  } finally {
    await fileHandle.close();
  }
}

// New function to get the first N lines of a file
export async function headFile(filePath: string, numLines: number): Promise<string> {
  const fileHandle = await fs.open(filePath, "r");
  try {
    const lines: string[] = [];
    let buffer = "";
    let bytesRead = 0;
    const chunk = Buffer.alloc(1024); // 1KB buffer

    // Read chunks and count lines until we have enough or reach EOF
    while (lines.length < numLines) {
      const result = await fileHandle.read(chunk, 0, chunk.length, bytesRead);
      if (result.bytesRead === 0) break; // End of file
      bytesRead += result.bytesRead;
      buffer += chunk.slice(0, result.bytesRead).toString("utf-8");

      const newLineIndex = buffer.lastIndexOf("\n");
      if (newLineIndex !== -1) {
        const completeLines = buffer.slice(0, newLineIndex).split("\n");
        buffer = buffer.slice(newLineIndex + 1);
        for (const line of completeLines) {
          lines.push(line);
          if (lines.length >= numLines) break;
        }
      }
    }

    // If there is leftover content and we still need lines, add it
    if (buffer.length > 0 && lines.length < numLines) {
      lines.push(buffer);
    }

    return lines.join("\n");
  } finally {
    await fileHandle.close();
  }
}

export async function searchFilesWithValidation(
  rootPath: string,
  pattern: string,
  options: SearchOptions = {}
): Promise<string[]> {
  const { excludePatterns = [] } = options;
  const results: string[] = [];

  async function search(currentPath: string) {
    const entries = await fs.readdir(currentPath, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);

      try {
        await validatePath(fullPath);

        const relativePath = path.relative(rootPath, fullPath);
        const shouldExclude = excludePatterns.some((excludePattern) =>
          minimatch(relativePath, excludePattern, { dot: true })
        );

        if (shouldExclude) continue;

        // Use glob matching for the search pattern
        if (minimatch(relativePath, pattern, { dot: true })) {
          results.push(fullPath);
        }

        if (entry.isDirectory()) {
          await search(fullPath);
        }
      } catch {
        continue;
      }
    }
  }

  await search(rootPath);
  return results;
}
