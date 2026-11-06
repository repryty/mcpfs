# CLAUDE.md

This file provides guidance to Claude Code when working with the mcpfs codebase.

## Critical Guidelines

### NEVER ACT WITHOUT EXPLICIT USER APPROVAL

**YOU MUST ALWAYS ASK FOR PERMISSION BEFORE:**

- Making architectural decisions or changes
- Implementing new features or functionality
- Modifying APIs, interfaces, or data structures
- Changing expected behavior or test expectations
- Adding new dependencies or patterns

**ONLY make changes AFTER the user explicitly approves.** When you identify issues or potential improvements, explain them clearly and wait for the user's decision. Do NOT assume what the user wants or make "helpful" changes without permission.

### FINISH DISCUSSIONS BEFORE WRITING CODE

**IMPORTANT**: When the user asks a question or you're in the middle of a discussion, DO NOT jump to writing code. Always:

1. **Complete the discussion first** - Understand the problem fully
2. **Analyze and explain** - Work through the issue verbally
3. **Get confirmation** - Ensure the user agrees with the approach
4. **Only then write code** - After the user explicitly asks you to implement

## Project Overview

mcpfs is an HTTP streaming port of the official MCP Filesystem Server. It replaces stdio transport with HTTP Streaming (Streamable HTTP transport) for remote access and web client compatibility.

### Key Features

- Read/write files
- Create/list/delete directories
- Move files/directories
- Search files
- Get file metadata
- Single vault root: clients address the served directory as `/`
- OAuth 2.1 authentication with PKCE support
- Persistent, hashed OAuth token state with atomic file writes
- ChatGPT integration via MCP connectors
- Optional OpenRouter-backed polishing tools with vault-stored style templates

## Code Principles

- **NO CLASSES** - Use functional style with strict types
- **PREFER `type` over `interface`**
- **USE RESULT TYPES** - For error handling where appropriate
- **ESM MODULES** - All imports must include `.js` extension

## Linting and Code Quality Standards

**CRITICAL**: NEVER weaken linting, testing, or type-checking rules:

- **NO eslint-disable comments** - Fix the actual issues instead of suppressing warnings
- **NO @ts-expect-error or @ts-ignore** - Fix type errors properly
- **NO relaxing TypeScript strict mode** - Maintain full type safety
- **NO weakening any quality gates** - Standards exist for a reason

When you encounter linting, type, or test errors, the solution is ALWAYS to fix the underlying issue properly, never to suppress or bypass the error.

## Security: Never Use npx

**CRITICAL SECURITY REQUIREMENT**: NEVER use `npx` for any commands.

- **ALWAYS use exact dependency versions** in package.json
- **ALWAYS use local node_modules binaries**

## Essential Commands

```bash
# Build
npm run build

# Start server
npm start

# Development (watch mode)
npm run dev

# Lint
npm run lint

# Lint with auto-fix
npm run lint:fix
```

## Project Structure

```
mcpfs/
├── src/
│   ├── index.ts          # Main entry point, Express server, OAuth endpoints
│   ├── oauth-store.ts    # Persistent hashed OAuth state store
│   ├── lib.ts            # Filesystem operations, vault path mapping
│   ├── polish.ts         # Optional OpenRouter polishing tools and templates
│   ├── path-utils.ts     # Path normalization utilities
│   ├── roots-utils.ts    # MCP roots handling
│   └── logger.ts         # Logging utilities
├── dist/                 # Compiled output
├── eslint.config.js      # ESLint configuration
├── tsconfig.json         # TypeScript configuration
└── package.json
```

## Environment Variables

| Variable                  | Required | Default                   | Description                              |
| ------------------------- | -------- | ------------------------- | ---------------------------------------- |
| `CLIENT_ID`               | Yes      | -                         | OAuth client ID                          |
| `CLIENT_SECRET`           | Yes      | -                         | OAuth client secret                      |
| `PORT`                    | No       | 24024                     | Server port                              |
| `LOG_LEVEL`               | No       | info                      | Logging level (debug, info, warn, error) |
| `OAUTH_STATE_PATH`        | No       | `.mcpfs/oauth-state.json` | Persistent OAuth state file              |
| `PUBLIC_URL`              | No       | Derived from request      | Public URL used in OAuth metadata        |
| `TRUST_PROXY`             | No       | false                     | Trust reverse-proxy forwarded headers    |
| `OPENROUTER_API_KEY`      | No       | -                         | Enables polishing tools                  |
| `OPENROUTER_MODEL`        | With key | -                         | OpenRouter model ID for polishing        |
| `OPENROUTER_SERVICE_TIER` | No       | -                         | OpenRouter service tier (e.g. `flex`)    |
| `POLISH_TEMPLATE_DIR`     | No       | `/_polish`                | Vault folder for polish templates        |

## Git Workflow

**CRITICAL GIT SAFETY RULES**:

1. **NEVER use `git push --force`**
2. **ALL git push commands require EXPLICIT user authorization**
3. **Use revert commits instead of force push**

## Logging

Use the logger module instead of console.log:

```typescript
import { logger } from "./logger.js";

logger.debug("Detailed debugging info");
logger.info("General information");
logger.warn("Warning message");
logger.error("Error message", error);
```
