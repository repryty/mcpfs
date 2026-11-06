# Filesystem MCP Server (HTTP Streaming)

An HTTP streaming port of the official [MCP Filesystem Server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) by Anthropic.

## About This Port

This is a port of [@modelcontextprotocol/server-filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) that replaces the **stdio** transport with **HTTP Streaming** (Streamable HTTP transport).

### Why HTTP Streaming?

The original MCP filesystem server uses stdio transport, which works well for local CLI integrations but has limitations:

- Requires spawning a subprocess for each connection
- Not suitable for remote/networked deployments
- Can't be accessed by web-based MCP clients

This port uses HTTP Streaming, enabling:

- **Remote access** - Connect over HTTP from anywhere
- **Multiple concurrent sessions** - Handle many clients simultaneously
- **Web client compatibility** - Works with browser-based MCP clients
- **Standalone deployment** - Run as a service without subprocess management

This fork keeps the file-based interface and OAuth transport, and is designed
to expose a directory that is synchronized by an external filesystem tool
such as Syncthing. mcpfs reads and writes that directory directly; it does not
call a synchronization API or require a particular synchronization backend.

---

## Features

- Read/write files
- Backward-compatible `read_file` alias
- Create/list directories
- Move files and directories
- Search files
- Get file metadata
- Single vault root: only the configured vault is exposed, and clients address it as `/`
- **OAuth 2.1 authentication** with PKCE support
- **ChatGPT integration** via MCP connectors
- Works with native Syncthing services and other filesystem synchronizers

## Installation

```bash
npm install -g mcpfs
```

Or for local development:

```bash
npm install
npm run build
```

## Quick Start

```bash
# Initialize credentials (creates .env with a random owner secret)
mcpfs --init

# Start the server against the locally synchronized vault
mcpfs /srv/obsidian/mcp-vault
```

## Using with ChatGPT

ChatGPT requires a publicly accessible HTTPS URL. Use Cloudflare Tunnel (free) to expose your local server:

### Step 1: Install Cloudflare Tunnel

```bash
# Linux
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared
chmod +x cloudflared
sudo mv cloudflared /usr/local/bin/

# Mac
brew install cloudflared

# Windows - download from:
# https://github.com/cloudflare/cloudflared/releases
```

### Step 2: Start mcpfs

```bash
mcpfs --init  # First time only - creates credentials
mcpfs /path/to/your/project
```

### Step 3: Start the Tunnel

In a separate terminal:

```bash
cloudflared tunnel --url http://localhost:24024
```

You'll get a URL like `https://random-words.trycloudflare.com`

### Step 4: Connect in ChatGPT

1. Go to **ChatGPT → Settings → Apps → Create** (developer mode/custom MCP app)
2. **Name**: `mcpfs` (or any name you prefer)
3. **URL**: `https://random-words.trycloudflare.com/mcp` (use your tunnel URL + `/mcp`)
4. **Authentication**: OAuth
5. Click **Create**

ChatGPT dynamically registers its OAuth client and starts the authorization
flow. On the mcpfs consent page, enter `MCP_AUTH_SECRET`; this is the only
owner-controlled secret required to approve access. The server then redirects
back to ChatGPT and completes the code/token exchange automatically.

ChatGPT will redirect you to authorize. Once complete, you can use filesystem tools in ChatGPT!

### Note on Tunnel URLs

Quick tunnels generate a new URL each time. For a permanent URL:

- Create a free Cloudflare account
- Set up a named tunnel with your own domain

---

## Usage

### Synchronized vault mode

The server serves the directory passed on the command line. When using
Syncthing, this should be the same local directory configured as the
Syncthing folder on the Linux host. mcpfs treats it as a normal local
filesystem: Syncthing runs independently and no Syncthing credentials or REST
endpoint are needed by mcpfs.

Client-provided MCP Roots are ignored so the exposed directory cannot be
expanded by the MCP client. When no directories are specified, the server
will serve the **current working directory** if it's considered safe. The
server will refuse to auto-serve:

- Root directory (`/`)
- Home directory (`~`)
- System directories (`/usr`, `/etc`, `/var`, `/System`, etc.)

To serve these directories, you must specify them explicitly as the command-line argument.

### Command Line Options

| Option    | Description                                                   |
| --------- | ------------------------------------------------------------- |
| `--init`  | Generate the owner authorization secret and save it to `.env` |
| `--force` | Used with `--init` to overwrite existing `.env`               |

### Environment Variables

```bash
MCP_AUTH_SECRET=my-owner-secret mcpfs /path/to/dir

# With custom port
PORT=8080 MCP_AUTH_SECRET=my-owner-secret mcpfs /path/to/dir
```

| Variable                  | Required          | Default    | Description                                                    |
| ------------------------- | ----------------- | ---------- | -------------------------------------------------------------- |
| `MCP_AUTH_SECRET`         | Yes               | -          | Private secret required on the OAuth consent page              |
| `PORT`                    | No                | 24024      | Server port                                                    |
| `MCP_PUBLIC_URL`          | Proxy deployments | -          | Canonical public origin used in OAuth metadata                 |
| `OAUTH_STATE_PATH`        | No                | -          | JSON file used to persist OAuth clients and tokens             |
| `OPENROUTER_API_KEY`      | No                | -          | Enables the polishing tools (OpenRouter API key)               |
| `OPENROUTER_SERVICE_TIER` | No                | -          | OpenRouter service tier, e.g. `flex` (cheaper, lower priority) |
| `OPENROUTER_MODEL`        | With API key      | -          | OpenRouter model ID, e.g. `google/<model>`                     |
| `POLISH_TEMPLATE_DIR`     | No                | `/_polish` | Vault folder that holds polish templates                       |
| `POLISH_TEMPERATURE`      | No                | 0.3        | Default sampling temperature for polishing                     |
| `POLISH_MAX_CHUNK_CHARS`  | No                | 6000       | Approximate characters sent per model request                  |
| `POLISH_TIMEOUT_MS`       | No                | 120000     | Timeout per model request                                      |

Back up the synchronized directory independently of mcpfs (for example with
Restic or filesystem snapshots). A backup job must cover changes received by
Syncthing as well as changes made through MCP, because neither mcpfs nor
Syncthing is a complete backup system.

### Linux: native Syncthing service

The recommended deployment runs Syncthing on the Linux host as the `repryty`
user. Keep its configuration and database in that user's home directory, and
share only the vault directory with the MCPFS container.

1. Install Syncthing using your distribution's package or the official
   repository. Enable lingering so the user service continues without an
   interactive login:

   ```bash
   sudo loginctl enable-linger repryty
   sudo -u repryty XDG_RUNTIME_DIR=/run/user/$(id -u repryty) \
     systemctl --user enable --now syncthing.service
   ```

2. Open the Syncthing GUI on the host (normally `http://127.0.0.1:8384`),
   add the Obsidian devices, and create a folder such as `obsidian-vault`
   with path `/srv/obsidian/mcp-vault`. Set the folder type to **Send &
   Receive** only after the initial migration has been checked.

3. Ensure `repryty` can read and write the vault and that the container's
   runtime UID can write it as well. Do not put Syncthing's `.stfolder` or
   configuration directory inside the MCPFS OAuth directory.

4. On every Obsidian device, disable the old Self-hosted LiveSync plugin
   before enabling Syncthing for this vault. Never run both synchronizers on
   the same files.

For the first migration, stop writes, finish the last LiveSync pull, make a
backup, and use the server copy as the initial Syncthing folder. Connect one
device at a time and verify the file count and representative file contents
before enabling additional writers. Syncthing can create `sync-conflict-*`
files when two devices edit the same file; resolve those in Obsidian and keep
the backup job enabled.

### Docker Compose (MCPFS only)

Syncthing remains a native Linux user service; the Compose service below only
bind-mounts its host-synchronized directory into MCPFS. Copy it to
`docker-compose.yml` and set the referenced variables in the deployment
environment (do not commit the deployment `.env`).

```yaml
services:
  mcpfs:
    build: .
    container_name: obsidian-mcpfs
    restart: unless-stopped
    init: true
    environment:
      MCP_AUTH_SECRET: ${MCPFS_AUTH_SECRET:?Set MCPFS_AUTH_SECRET externally}
      MCP_PUBLIC_URL: ${MCPFS_PUBLIC_URL:?Set MCPFS_PUBLIC_URL externally}
      OAUTH_STATE_PATH: /var/lib/mcpfs/oauth-state.json
      PORT: "24024"
      # Optional: enables polish_file / polish_text
      OPENROUTER_API_KEY: ${OPENROUTER_API_KEY:-}
      OPENROUTER_MODEL: ${OPENROUTER_MODEL:-}
      OPENROUTER_SERVICE_TIER: ${OPENROUTER_SERVICE_TIER:-}
    volumes:
      - ./mcpfs/oauth:/var/lib/mcpfs:rw
      - ${OBSIDIAN_VAULT_PATH:?Set OBSIDIAN_VAULT_PATH}:/srv/obsidian/vault:rw
    command: ["/srv/obsidian/vault"]
    networks:
      - risu_net

networks:
  risu_net:
    external: true
```

The reverse proxy or tunnel should forward to port `24024` and use the same
origin as `MCP_PUBLIC_URL`. The `MCP_AUTH_SECRET` is used only on the OAuth
consent page; it is not a Syncthing credential.

---

## HTTP Endpoints

### OAuth 2.1 Discovery (RFC 9728, RFC 8414)

| Method | Path                                      | Description                   |
| ------ | ----------------------------------------- | ----------------------------- |
| GET    | `/.well-known/oauth-protected-resource`   | Protected resource metadata   |
| GET    | `/.well-known/oauth-authorization-server` | Authorization server metadata |

### OAuth 2.1 Endpoints

| Method | Path         | Description                            |
| ------ | ------------ | -------------------------------------- |
| POST   | `/register`  | Dynamic client registration (RFC 7591) |
| GET    | `/authorize` | Authorization endpoint with PKCE       |
| POST   | `/token`     | Token endpoint                         |

### MCP Endpoints

| Method | Path   | Auth   | Description                                      |
| ------ | ------ | ------ | ------------------------------------------------ |
| POST   | `/mcp` | Bearer | Send MCP messages (initialize, tool calls, etc.) |
| GET    | `/mcp` | Bearer | SSE stream for server-to-client notifications    |
| DELETE | `/mcp` | Bearer | Terminate session                                |

---

## Authentication

This server supports OAuth 2.1 with multiple authentication flows:

### Authorization Code Flow with PKCE (Recommended)

Used by ChatGPT and other MCP clients. The flow is:

1. Client discovers OAuth endpoints via `/.well-known/oauth-authorization-server`
2. Client registers dynamically via `/register` (or uses static credentials)
3. Client redirects to `/authorize` with PKCE challenge
4. Server redirects back with authorization code
5. Client exchanges code for tokens at `/token`

### Using the Token

```bash
curl -X POST http://localhost:24024/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
      "protocolVersion": "2024-11-05",
      "capabilities": {},
      "clientInfo": { "name": "my-client", "version": "1.0.0" }
    }
  }'
```

---

## Directory Access Control

The server uses a fixed directory access control system for the synchronized
vault.

### Single Vault Root

```bash
mcpfs /srv/obsidian/mcp-vault
```

Exactly one directory (the vault) is served. Passing more than one directory
is an error.

Clients see the vault as `/`, so tool paths are short vault-relative paths
instead of absolute host paths:

| Client path                       | Resolves to                            |
| --------------------------------- | -------------------------------------- |
| `/`, `.` or empty string          | vault root                             |
| `notes/today.md`                  | `<vault>/notes/today.md`               |
| `/notes/today.md`                 | `<vault>/notes/today.md`               |
| `/srv/obsidian/mcp-vault/x.md`    | `<vault>/x.md` (legacy absolute paths) |
| `../other`, symlinks out of vault | rejected                               |

Tool output (search results, diffs, error messages) also uses vault paths
such as `/notes/today.md`, so the host location of the vault is never exposed.

### How It Works

1. **Server Startup** - Server starts with the configured vault directory
2. **Client Connection** - Client connects and sends `initialize` request
3. **Filesystem access** - Reads and writes use the local directory directly
4. **Synchronization** - Syncthing independently propagates filesystem changes
5. **Access Control** - All filesystem operations are restricted to the vault

---

## API

### Tools

- **read_file** (deprecated)
  - Compatibility alias for `read_text_file`
  - Inputs: `path`, `head` (optional), `tail` (optional)

- **read_text_file**
  - Read complete contents of a file as text
  - Inputs:
    - `path` (string)
    - `head` (number, optional): First N lines
    - `tail` (number, optional): Last N lines

- **read_media_file**
  - Read an image or audio file as base64
  - Input: `path` (string)

- **read_multiple_files**
  - Read multiple files simultaneously
  - Input: `paths` (string[])

- **write_file**
  - Create new file or overwrite existing
  - Inputs: `path` (string), `content` (string)

- **edit_file**
  - Make selective edits with pattern matching
  - Inputs: `path`, `edits` (array of oldText/newText), `dryRun` (boolean)

- **create_directory**
  - Create new directory or ensure it exists
  - Input: `path` (string)

- **list_directory**
  - List directory contents with [FILE] or [DIR] prefixes
  - Input: `path` (string)

- **list_directory_with_sizes**
  - List directory with file sizes
  - Inputs: `path` (string), `sortBy` ("name" | "size")

- **search_files**
  - Recursively search for files matching patterns
  - Inputs: `path`, `pattern`, `excludePatterns`

- **directory_tree**
  - Get recursive JSON tree structure
  - Inputs: `path`, `excludePatterns`

- **move_file**
  - Move or rename files and directories
  - Inputs: `source`, `destination`

- **get_file_info**
  - Get detailed file/directory metadata
  - Input: `path` (string)

### Polishing Tools (optional, OpenRouter)

Registered only when `OPENROUTER_API_KEY` and `OPENROUTER_MODEL` are set. Any
OpenRouter model works, including Google models such as `google/<model>`.
Set `OPENROUTER_SERVICE_TIER=flex` to use OpenRouter's cheaper, lower-priority
flex endpoints. Flex requests can fail with capacity errors (for example HTTP 429) instead of falling back to the default tier, and they may be slower, so
consider raising `POLISH_TIMEOUT_MS`. The MCP
client decides on its own when to call them, for example when the user asks
to polish or proofread a note.

- **polish_file**
  - Copy-edits a vault file with the configured model. The server reads the file itself, so
    the client does not send the content.
  - Inputs: `path`, `template` (optional), `instructions` (optional),
    `dryRun` (default `true`)
  - `dryRun: true` returns a diff. Calling again with `dryRun: false` and the
    same arguments writes exactly the previewed result (cached for 30
    minutes) without another model call. If the file changed in the meantime,
    nothing is written.
- **polish_text**
  - Copy-edits text passed directly and returns the result
  - Inputs: `text`, `template` (optional), `instructions` (optional)
- **list_polish_templates**
  - Lists templates with their descriptions so the client can pick one
- **save_polish_template**
  - Inputs: `name`, `description`, `instructions`, `temperature` (optional),
    `overwrite` (default `false`)

Built-in rules always apply and cannot be overridden by a template: meaning,
language, Markdown structure, wikilinks and code are preserved, and YAML
frontmatter is never sent to the model. Long files are split at blank lines
outside code blocks.

Templates are Markdown notes in `POLISH_TEMPLATE_DIR` and can also be edited
in Obsidian:

```md
---
description: "Blog posts: keep casual tone, short sentences"
temperature: 0.2
---

- Keep each sentence under about 40 characters.
- Prefer active voice.
```

Tool descriptions instruct clients to write template and instruction prompts
in English unless the user asks for another language. The polished text
always keeps its own language.

### Tool Annotations

| Tool                        | readOnlyHint | idempotentHint | destructiveHint |
| --------------------------- | ------------ | -------------- | --------------- |
| `read_text_file`            | `true`       | –              | –               |
| `read_media_file`           | `true`       | –              | –               |
| `read_multiple_files`       | `true`       | –              | –               |
| `list_directory`            | `true`       | –              | –               |
| `list_directory_with_sizes` | `true`       | –              | –               |
| `directory_tree`            | `true`       | –              | –               |
| `search_files`              | `true`       | –              | –               |
| `get_file_info`             | `true`       | –              | –               |
| `create_directory`          | `false`      | `true`         | `false`         |
| `write_file`                | `false`      | `true`         | `true`          |
| `edit_file`                 | `false`      | `false`        | `true`          |
| `move_file`                 | `false`      | `false`        | `false`         |
| `polish_text`               | `true`       | –              | –               |
| `list_polish_templates`     | `true`       | –              | –               |
| `polish_file`               | `false`      | `false`        | `true`          |
| `save_polish_template`      | `false`      | `true`         | `true`          |

---

## Security

- **OAuth 2.1 authentication** with PKCE for authorization code flow
- **Refresh token rotation** - tokens are rotated on each refresh (OAuth 2.1 requirement)
- `MCP_AUTH_SECRET` is required on the consent form before an authorization code is issued
- Only the configured synchronized vault is accessible; client Roots cannot expand it
- Symlinks are resolved to prevent directory escape attacks

## License

MIT License. See LICENSE file for details.

## Credits

Based on the [MCP Filesystem Server](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) by Anthropic, PBC.
