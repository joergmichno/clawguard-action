# ClawGuard AI Security Scanner

[![Scanned by ClawGuard](https://img.shields.io/badge/scanned%20by-ClawGuard-blue?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjIiPjxwYXRoIGQ9Ik0xMiAyMnMtOC00LjUtOC0xMS44QTQgNCAwIDAgMSA4IDJjMS43NCAwIDMuNDEuODEgNC41IDIuMDlDMTMuMDkgMi44MSAxNC43NiAyIDE2LjUgMmE0IDQgMCAwIDEgNCA4LjJjMCA3LjMtOCAxMS44LTggMTEuOHoiLz48L3N2Zz4=)](https://github.com/joergmichno/clawguard)

A GitHub Action that scans AI prompt files, MCP configurations, and LLM-related content in pull requests for security vulnerabilities including prompt injection, jailbreaks, and data exfiltration attempts.

Powered by [ClawGuard](https://github.com/joergmichno/clawguard) -- 182 detection patterns, 15 languages, F1 score 97.4%.

## Quick Start

Add this to `.github/workflows/clawguard.yml`:

```yaml
name: ClawGuard Scan
on:
  pull_request:
    branches: [main]
permissions:
  contents: read
  pull-requests: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: joergmichno/clawguard-action@v1
        with:
          api_key: ${{ secrets.CLAWGUARD_API_KEY }}
```

Get your free API key at [prompttools.co](https://prompttools.co).

## What It Detects

| Category | Examples |
|----------|----------|
| Prompt Injection | "Ignore all previous instructions", role override, system prompt extraction |
| Jailbreaks | DAN, developer mode, character roleplay escapes |
| Data Exfiltration | Encoded data in URLs, hidden markdown image callbacks |
| Tool Abuse | Unauthorized file access, command injection via MCP tools |
| Social Engineering | Authority impersonation, urgency manipulation |
| Obfuscation | Base64-encoded payloads, Unicode homoglyphs, ROT13 |

Full coverage: [OWASP LLM Top 10](https://genai.owasp.org/) (100%) and [OWASP Agentic Security Top 10](https://genai.owasp.org/) (100%).

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `api_key` | Yes | - | ClawGuard Shield API key |
| `file_patterns` | No | `*.prompt,*.md,*.txt` | Comma-separated glob patterns for files to scan |
| `fail_on_critical` | No | `false` | Fail the workflow if HIGH or CRITICAL findings are detected |
| `scan_all_files` | No | `false` | Scan all matching files instead of only PR-changed files |
| `api_url` | No | `https://prompttools.co/api/v1/scan` | API endpoint (for self-hosted instances) |
| `github_token` | No | `${{ github.token }}` | Token for posting PR comments |

## Outputs

| Output | Description |
|--------|-------------|
| `findings_count` | Total number of security findings |
| `risk_level` | Overall risk level: `CLEAN`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `max_risk_score` | Highest risk score across all files (0-10) |
| `files_scanned` | Number of files scanned |

## Configuration Examples

### Scan AI prompt files only (minimal)

```yaml
- uses: joergmichno/clawguard-action@v1
  with:
    api_key: ${{ secrets.CLAWGUARD_API_KEY }}
    file_patterns: "*.prompt"
```

### Block PRs with critical threats

```yaml
- uses: joergmichno/clawguard-action@v1
  with:
    api_key: ${{ secrets.CLAWGUARD_API_KEY }}
    file_patterns: "*.prompt,*.md,*.txt,*.json,*.yaml,*.yml"
    fail_on_critical: "true"
```

### Scan all files in repository

```yaml
- uses: joergmichno/clawguard-action@v1
  with:
    api_key: ${{ secrets.CLAWGUARD_API_KEY }}
    scan_all_files: "true"
```

### Use scan results in subsequent steps

```yaml
- uses: joergmichno/clawguard-action@v1
  id: clawguard
  with:
    api_key: ${{ secrets.CLAWGUARD_API_KEY }}

- name: Check results
  if: steps.clawguard.outputs.risk_level == 'CRITICAL'
  run: |
    echo "CRITICAL threats found: ${{ steps.clawguard.outputs.findings_count }}"
    # Send Slack notification, block deploy, etc.
```

## PR Comment Example

When findings are detected, ClawGuard posts a comment on the PR:

> ## :shield: ClawGuard AI Security Scan
>
> :red_circle: **3 finding(s)** across 2 file(s) | Risk: **HIGH** (8/10)
>
> | File | Risk | Findings |
> |------|------|----------|
> | `prompts/system.md` | HIGH | 2 |
> | `config/mcp.json` | MEDIUM | 1 |
>
> **`prompts/system.md`**
> - **CRITICAL** [Prompt Injection] Direct Override: `ignore all previous instructions`
> - **HIGH** [Data Exfiltration] Hidden Callback: `![](https://evil.com/steal?d=`
>
> ---
> <sub>Scanned by ClawGuard</sub>

The comment is updated on subsequent pushes (no comment spam).

## Requirements

- **GitHub runner:** Any GitHub-hosted runner (Ubuntu, macOS, Windows). No Docker needed.
- **Dependencies:** `curl` and `jq` (pre-installed on all GitHub runners).
- **API key:** Free tier includes 100 scans/day. [Get yours here](https://prompttools.co).

## Self-Hosted API

Running ClawGuard Shield on your own infrastructure:

```yaml
- uses: joergmichno/clawguard-action@v1
  with:
    api_key: ${{ secrets.CLAWGUARD_API_KEY }}
    api_url: "https://shield.yourcompany.com/api/v1/scan"
```

## Badge

Add this badge to your README to show your project is scanned:

```markdown
[![Scanned by ClawGuard](https://img.shields.io/badge/scanned%20by-ClawGuard-blue)](https://github.com/joergmichno/clawguard)
```

## License

MIT -- see [ClawGuard](https://github.com/joergmichno/clawguard) for the scanner engine.
