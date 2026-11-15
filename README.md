# agentscope

AI agent / MCP permission auditor — self-hosted and fully offline.

AgentScope scans your Model Context Protocol (MCP) config files and
reports what each configured server can actually do: execute shell
commands, read your filesystem (and *which* paths), reach the network,
touch a database, and receive secrets. It flags the risky patterns —
wildcard permissions, unpinned packages, hardcoded secrets, dangerous
flags, destructive tools, and root-wide filesystem access — and scores
every server with a documented formula.

It reads config files only. It never starts an MCP server, never runs
the commands it finds, and never makes a network call.

## Features

- **Config discovery** — point it at a single file (any filename) or a
  directory; directories are walked recursively and known MCP config
  filenames are auto-discovered:
  `claude_desktop_config.json` (Claude Desktop), `.cursor/mcp.json`
  (Cursor), `mcp.json` (Windsurf / VS Code), `settings.json`
  (Claude Code, including top-level `permissions.allow`).
- **Config shapes** — both `{"mcpServers": {...}}` (Claude Desktop /
  Cursor) and `{"servers": {...}}` (VS Code) are parsed, plus a
  list-form server array and a bare single-server file.
- **Capability classification** — per server: shell execution,
  filesystem scope (the exact path arguments), network access,
  database access, and env vars that look like secrets.
- **Secret names only** — secret values are inspected in memory to
  detect hardcoding, but are **never** written to any output: reports
  show env var *names* with values masked as `***`, and arguments that
  match a known secret pattern are masked too. A dedicated test plants
  a fake secret in a fixture and asserts the value appears nowhere in
  `report.md`, `report.json`, or stdout.
- **Seven documented checks** — see the rules table below.
- **Documented risk scoring** — every finding carries a severity and
  points; per-server and overall scores use the formula below.
- **Reports** — `report.md` (human-readable) + `report.json`
  (machine-readable) in the output directory.
- **CI-friendly exit code** — non-zero when any finding is at or above
  the `--fail-on` severity threshold (default `high`).

## Checks (rules)

| Rule | Title | Severity | Points | What triggers it |
|---|---|---:|---:|---|
| R001 | Wildcard permission granted | high | 25 | A permission/arg is `*`, `*:*`, ends with `:*`, or contains `(*)`, e.g. `Bash(*)` |
| R002 | Unpinned package execution | medium | 10 | `npx`/`uvx` (also `pnpx`/`bunx`) runs a package with no `@version`, or `@latest` |
| R003 | Hardcoded secret | high | 25 | An env value matches a known secret pattern (`sk-…`, `ghp_…`, `AKIA…`, a credentialed DB URL, …) or a secret-named env var holds a literal value ≥ 8 chars. Values that are references (`${VAR}`, `$VAR`) or placeholders are not flagged |
| R004 | Dangerous flag disables safety checks | critical | 40 | Args contain `--dangerously-skip-permissions`, `--dangerously-allow-all`, `--allow-all`, `--skip-permissions`, `--no-sandbox`, `--disable-sandbox`, `--allow-root`, `--privileged`, `--unsafe`, or `--insecure` |
| R005 | Destructive operation exposed | high | 25 | Server name, command, args, or tool names contain DROP / TRUNCATE / DESTROY / WIPE / PURGE, `DELETE FROM`, a bare `delete`/`drop`-style tool name, `rm -rf`, or `mkfs` |
| R006 | Broad filesystem access | high | 25 | Filesystem scope includes `/`, `/*`, `~`, `/home`, `/Users`, `/root`, `/etc`, `C:\`, `*`, or `.*` |
| R007 | Shell execution capability | medium | 10 | The server's command is a shell (`bash`, `sh`, `zsh`, `cmd`, `powershell`, …) or its name is shell/terminal/exec-like |

## Scoring

Severity points:

| Severity | Points |
|---|---:|
| critical | 40 |
| high | 25 |
| medium | 10 |
| low | 5 |
| info | 0 |

- **Per-server score** = sum of that server's finding points, capped at 100.
- **Overall score** = the highest per-server score (0 when there are no
  servers or no findings). The riskiest server drives the overall
  score — averaging would hide one dangerous server behind safe ones.
- **Risk level** from a score: `0` clean, `1–9` low, `10–24` medium,
  `25–49` high, `50–100` critical.

Worked example: a server with a dangerous flag (40) + a hardcoded
secret (25) + an unpinned package (10) scores 75 → **critical**.

## Install

Python 3.11+ only. No third-party runtime dependencies — standard
library only (pytest is used for the tests).

```bash
git clone https://github.com/tahiryounas604/agentscope.git
cd agentscope
# optional: install as a command
pip install --break-system-packages .
```

## Usage

```bash
# Scan a directory (auto-discovers known MCP config filenames)
python3 agentscope.py scan ~/.config/Claude

# Scan a single config file (any filename works)
python3 agentscope.py scan ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Custom output directory, stricter failure threshold
python3 agentscope.py scan . --out ./out --fail-on medium

# Installed form
agentscope scan path/to/mcp.json --out ./out
```

Output (default directory `agentscope-report/`):

```
agentscope-report/
├── report.md      # human-readable report
└── report.json    # machine-readable results
```

Exit codes: `0` = no finding at/above `--fail-on`, `1` = threshold
met, `2` = usage / IO error (e.g. path does not exist, no known
config files in the directory, invalid JSON in the only file).

Example run (against `examples/vulnerable-claude_desktop_config.json`):

```
scanned 1 file(s), 4 server(s)
overall risk score: 100/100 (critical)
findings: 11
  100  critical  dangerous-db (4 finding(s))
   85  critical  everything (4 finding(s))
   35  high      filesystem-broad (2 finding(s))
   10  medium    shell-runner (1 finding(s))
wrote agentscope-report/report.md
wrote agentscope-report/report.json
FAIL: findings at or above 'high' severity
```

(The exact per-server lines come from the real fixture; run it
yourself to see the full finding details.)

## Architecture

```
agentscope.py            top-level entry point shim
agentscope/
├── __init__.py          version
├── __main__.py          python -m agentscope
├── models.py            Finding / Capabilities / Server / ScanResult
│                        (secret values are never stored on any model)
├── scoring.py           the documented points, bands and thresholds
├── scanner.py           discovery, parsing, classification, checks R001–R007
├── report.py            report.md + report.json writers (masked output)
└── cli.py               `agentscope scan` subcommand and exit codes
tests/                   offline pytest suite + vulnerable/safe fixtures
examples/                the same vulnerable/safe configs, for a quick try
```

Data flow: `discover → parse → classify capabilities → run checks →
score → write reports`. Parsing is shape-tolerant (see Features);
classification and checks work off the normalised server entries.

## Tests

```bash
python3 -m pytest -q
```

The suite covers: every scoring rule and level boundary, each check
(wildcard, unpinned incl. scoped/`@latest` cases, dangerous flags,
destructive names, broad vs scoped filesystem, shell, hardcoded
secrets vs `${VAR}` references), vulnerable-vs-safe fixtures,
directory auto-discovery, the Claude Code `permissions` shape, the
VS Code `servers` shape, error paths, CLI end-to-end (exit codes,
`--fail-on` thresholds, report files), and masking — a planted fake
secret is asserted absent from every output surface.

## HONEST LIMITS

- **Static config analysis only.** AgentScope reads config files; it
  does not start MCP servers, call their tools, or observe runtime
  behaviour. A server that is safe in config can still misbehave at
  runtime, and vice versa.
- **Heuristic classification.** Shell/filesystem/network/database
  detection is keyword- and shape-based (command names, known server
  names, path-like and URL-like arguments). An unusually named server
  can be misclassified, and filesystem scope is taken from path
  arguments — a server that ignores its arguments is not detected.
- **Secret detection is pattern + name based.** Known token formats
  and secret-named env vars with literal values are caught; a secret
  stored under an innocuous name in an unrecognised format may be
  missed. Conversely, a long literal in a secret-named var that is
  not actually sensitive will be flagged — that is deliberate
  (fail towards visibility), and the fix is a `${VAR}` reference.
- **Not every config dialect is parsed.** The known Claude Desktop /
  Cursor / Windsurf / VS Code / Claude Code shapes are covered;
  vendor-specific extensions beyond `command`/`args`/`env`/`url` and
  `permissions.allow` are treated generically (all strings are scanned
  for wildcards/flags/destructive names, env values excluded).
- **Scoring is a triage aid, not a verdict.** The points are a simple
  documented heuristic for prioritising review, not a CVSS score and
  not a measure of exploitability in your specific setup.
- **No remediation is performed.** AgentScope reports; it never edits
  your configs.

## Author

Tahir Younas — Tytechlabs — https://www.linkedin.com/in/tahiryounas604

## License

GPL-3.0 — see `LICENSE`.
