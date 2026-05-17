# NVD MCP Server

[![NVD API Integration Tests](https://github.com/Alig1493/nvd-mcp-server/actions/workflows/test-nvd-api.yml/badge.svg)](https://github.com/Alig1493/nvd-mcp-server/actions/workflows/test-nvd-api.yml)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that lets AI assistants like Claude, Cursor, and Gemini search the [National Vulnerability Database (NVD)](https://nvd.nist.gov/) for security vulnerabilities — in plain English, no API knowledge required.

Ask your AI assistant things like:
- *"Find critical CVEs published this month"*
- *"What vulnerabilities affect OpenSSL 3.0.0?"*
- *"Look up Log4Shell"*
- *"Show me high-severity Linux kernel buffer overflow CVEs"*

---

## How it works

```mermaid
sequenceDiagram
    actor User
    participant Agent as AI Assistant<br/>(Claude / Cursor / Gemini)
    participant MCP as NVD MCP Server
    participant NVD as NVD API<br/>(nvd.nist.gov)

    User->>Agent: "Find critical CVEs in Apache Log4j"
    Agent->>MCP: search_cves(keyword_search="Apache Log4j",<br/>cvss_v3_severity="CRITICAL")
    MCP->>NVD: GET /rest/json/cves/2.0<br/>?keywordSearch=Apache+Log4j<br/>&cvssV3Severity=CRITICAL<br/>&apiKey=...
    NVD-->>MCP: Raw vulnerability JSON
    MCP->>MCP: Validate & condense response
    MCP-->>Agent: id, description, CVSS score,<br/>CWEs, references, KEV status
    Agent-->>User: Formatted summary of matching CVEs
```

The server sits between your AI assistant and the NVD API. It:
1. Receives natural-language-driven tool calls from the AI
2. Translates them into authenticated NVD API requests
3. Validates the raw response against strict data models
4. Returns a clean, condensed result the AI can reason about

---

## Prerequisites

- **Python 3.13+**
- **[uv](https://docs.astral.sh/uv/getting-started/installation/)** — fast Python package manager
- An **NVD API key** (free, takes ~1 hour to receive)

---

## Step 1 — Get an NVD API key

The NVD API is free and open, but an API key increases your rate limit from **5 requests/30 seconds** to **50 requests/30 seconds**.

1. Go to **https://nvd.nist.gov/developers/request-an-api-key**
2. Enter your email address and submit the form
3. Check your email — you'll receive your key within an hour
4. Copy the key, you'll need it in the next step

---

## Step 2 — Install the server

```bash
git clone https://github.com/Alig1493/nvd-mcp-server.git
cd nvd-mcp-server
uv sync
```

---

## Step 3 — Configure your API key

Create a `.env` file in the project root:

```bash
NVD_API_KEY=your-api-key-here
```

That's the only required setting. The NVD API URLs are pre-configured.

---

## Step 4 — Connect to your AI assistant

Pick your assistant below and follow the instructions.

### Claude Desktop

Open your Claude Desktop config file:

| OS | Path |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

Add the following inside the `"mcpServers"` object (create the object if it doesn't exist):

```json
{
  "mcpServers": {
    "nvd-mcp-server": {
      "type": "stdio",
      "command": "uv",
      "args": [
        "--directory", "/absolute/path/to/nvd-mcp-server",
        "run", "python", "-m", "nvd_mcp_server.server"
      ],
      "env": {
        "NVD_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

Replace `/absolute/path/to/nvd-mcp-server` with the full path to where you cloned the repo.

Restart Claude Desktop and look for the 🔌 icon — the tool is ready.

---

### Claude Code (CLI)

Run this once from your terminal:

```bash
claude mcp add nvd-mcp-server \
  --command uv \
  --args "--directory /absolute/path/to/nvd-mcp-server run python -m nvd_mcp_server.server" \
  --env NVD_API_KEY=your-api-key-here
```

Or manually add to `~/.claude.json` under `"mcpServers"` (same JSON block as Claude Desktop above).

---

### Cursor

Open Cursor → Settings → MCP, then add a new server with:

```json
{
  "nvd-mcp-server": {
    "type": "stdio",
    "command": "uv",
    "args": [
      "--directory", "/absolute/path/to/nvd-mcp-server",
      "run", "python", "-m", "nvd_mcp_server.server"
    ],
    "env": {
      "NVD_API_KEY": "your-api-key-here"
    }
  }
}
```

---

### Any other MCP-compatible client

Any client that supports the MCP stdio transport (Gemini, Windsurf, Continue, etc.) can use the same configuration pattern:

| Field | Value |
|-------|-------|
| Type | `stdio` |
| Command | `uv` |
| Args | `--directory /path/to/nvd-mcp-server run python -m nvd_mcp_server.server` |
| Env | `NVD_API_KEY=your-key` |

---

## Example prompts

### Look up a specific CVE

> *"What is CVE-2021-44228?"*

```
CVE-2021-44228 — Log4Shell
Published: 2021-12-10 | Status: Analyzed
CVSS: 10.0 CRITICAL (CVSSv3.1) | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features do not protect against
attacker-controlled LDAP endpoints. An attacker who can control log messages
can execute arbitrary code loaded from a remote server.

CWEs: CWE-20, CWE-400, CWE-502, CWE-917
CISA KEV: Added 2021-12-10 · Due 2021-12-24
```

---

### Find vulnerabilities for a product

> *"What are the critical vulnerabilities affecting OpenSSL 3.0.0?"*

The assistant searches by CPE name and CVSS severity, returning a table of matching CVEs with scores and descriptions.

---

### Search by keyword

> *"Find recent CVEs related to remote code execution in Windows"*

> *"Show me SQL injection vulnerabilities from the last 6 months"*

---

### Filter by severity

> *"List high and critical CVEs published in January 2025"*

> *"Find all CVEs in CISA's Known Exploited Vulnerabilities catalog from Q1 2023"*

---

### Paginate through results

> *"Show me the next page of results"*

Every response includes a `pagination_hint` telling the assistant exactly how many results remain and how to fetch the next page — you never need to think about offsets.

---

## Available filters (reference)

| Filter | What it does | Example value |
|--------|-------------|---------------|
| `cve_id` | Look up a specific CVE | `CVE-2021-44228` |
| `keyword_search` | Search descriptions | `"buffer overflow"` |
| `keyword_exact_match` | Exact phrase match | `true` |
| `cvss_v3_severity` | Filter by CVSSv3 severity | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `cvss_v2_severity` | Filter by CVSSv2 severity | `HIGH`, `MEDIUM`, `LOW` |
| `cvss_v3_metrics` | Match a CVSSv3 vector string | `AV:N/AC:L/PR:N/UI:N` |
| `cwe_id` | Filter by weakness type | `CWE-79`, `CWE-89` |
| `cpe_name` | Filter by affected product | `cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*` |
| `is_vulnerable` | Only confirmed vulnerable configs | `true` (requires `cpe_name`) |
| `virtual_match_string` | Broad product match | `cpe:2.3:o:linux:linux_kernel` |
| `pub_start_date` / `pub_end_date` | Published date range | `2024-01-01T00:00:00.000` |
| `last_mod_start_date` / `last_mod_end_date` | Last modified date range | `2025-01-01T00:00:00.000` |
| `kev_start_date` / `kev_end_date` | CISA KEV addition date range | `2023-01-01T00:00:00.000` |
| `has_kev` | Only KEV catalog CVEs | `true` |
| `no_rejected` | Exclude rejected CVEs | `true` |
| `cve_tag` | Filter by tag | `disputed`, `unsupported-when-assigned` |
| `start_index` | Pagination offset | `10`, `20`, ... |

> **Note:** CVSSv2 data was last generated by NVD on 2022-07-13. Filtering by `cvss_v2_severity` or `cvss_v2_metrics` only matches CVEs published before that date.

---

## Configuration options

These can be set as environment variables or in your `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `NVD_API_KEY` | *(required)* | Your NVD API key |
| `NVD_CVE_URL` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | NVD CVE endpoint |
| `NVD_CVE_HISTORY_URL` | `https://services.nvd.nist.gov/rest/json/cvehistory/2.0` | NVD history endpoint |
| `TOTAL_TIMEOUT` | `60.0` | Per-request timeout in seconds |
| `RETRY_MAX_DURATION` | `120` | Total retry budget in seconds |

---

## Running the test suite

The test suite makes real calls to the NVD API and covers all supported parameters:

```bash
uv run scripts/test_cve_api.py
```

The tests run in parallel and print results as they arrive. All 31 tests should pass in under 60 seconds.

To run the tests in CI, add `NVD_API_KEY` as a repository secret in GitHub → Settings → Secrets → Actions.

---

## Troubleshooting

**The tool doesn't appear in my AI assistant**
Restart the application after editing the config file. Check that the path to the repo is absolute (not `~` or relative).

**`NVD_API_KEY` validation error on startup**
The server requires an API key. Make sure `NVD_API_KEY` is set either in `.env` or in the `"env"` block of your MCP config.

**Requests timing out**
The NVD API can be slow for broad queries (e.g. searching all CVEs for a very common product). Try narrowing your search with additional filters. You can also increase the timeout by setting `TOTAL_TIMEOUT=120` in your environment.

**Rate limit errors (HTTP 403)**
Without an API key you are limited to 5 requests per 30 seconds. Get a free key at https://nvd.nist.gov/developers/request-an-api-key.
