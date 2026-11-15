"""Scanner: discovery, parsing, capability classification and checks.

Offline and stdlib-only. Secret *values* are inspected in memory to
detect hardcoded secrets, but are never stored on a Finding, Server or
report — only secret *names* survive, and any output copy of an
argument that matched a secret pattern is masked.
"""
from __future__ import annotations

import json
import os
import re

from .models import Capabilities, Finding, ScanResult, Server
from .scoring import level_for_score, points_for, server_score

# ---------------------------------------------------------------- discovery

KNOWN_FILENAMES = {
    "claude_desktop_config.json",
    "mcp.json",
    "settings.json",
    ".mcp.json",
}


def discover_configs(path: str) -> list[str]:
    """Return config files for a file or directory path.

    A file path is used as-is (any filename). A directory is walked
    recursively and every file whose name is a known MCP config
    filename is returned, sorted for deterministic output.
    """
    if os.path.isfile(path):
        return [path]
    if os.path.isdir(path):
        found = []
        for root, dirs, files in os.walk(path):
            dirs.sort()
            for name in sorted(files):
                if name in KNOWN_FILENAMES:
                    found.append(os.path.join(root, name))
        return found
    return []


# ---------------------------------------------------------------- secrets

SECRET_KEY_RE = re.compile(
    r"(SECRET|TOKEN|API[_-]?KEY|PASSWORD|PASSWD|PRIVATE[_-]?KEY|"
    r"ACCESS[_-]?KEY|CREDENTIAL|DATABASE_URL|\bDSN\b|AUTH[_-]?KEY)",
    re.IGNORECASE,
)

SECRET_VALUE_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9\-_]{10,}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(postgres|mysql|mongodb(?:\+srv)?|redis)://[^\s:@/]+:[^\s@/]+@"),
]

PLACEHOLDER_EXACT = {
    "", "changeme", "change-me", "example", "xxx", "xxxx", "...",
    "your-key-here", "your_api_key", "placeholder", "redacted", "***",
    "todo", "none", "null",
}


def is_secret_key(name: str) -> bool:
    return bool(SECRET_KEY_RE.search(name or ""))


def is_placeholder(value: str) -> bool:
    if value is None:
        return True
    v = str(value).strip()
    if v.lower() in PLACEHOLDER_EXACT:
        return True
    if v.startswith("${") or v.startswith("$(") or v.startswith("{{"):
        return True
    if v.startswith("$") and len(v) < 60 and re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", v):
        return True
    if v.startswith("<") and v.endswith(">"):
        return True
    return False


def value_matches_secret_pattern(value: str) -> bool:
    v = str(value or "")
    return any(p.search(v) for p in SECRET_VALUE_PATTERNS)


def looks_like_hardcoded_secret(key: str, value) -> bool:
    """True when an env value appears to be a literal secret.

    A value that is an environment reference (``${VAR}`` / ``$VAR``)
    or a placeholder is not hardcoded.
    """
    if value is None:
        return False
    v = str(value)
    if not v.strip() or is_placeholder(v):
        return False
    if value_matches_secret_pattern(v):
        return True
    if is_secret_key(key) and len(v.strip()) >= 8:
        return True
    return False


def mask_text(text: str) -> str:
    """Replace anything matching a secret pattern with ``***``."""
    out = str(text or "")
    for pat in SECRET_VALUE_PATTERNS:
        out = pat.sub("***", out)
    return out


def mask_arg(arg) -> str:
    return mask_text(str(arg))


# ---------------------------------------------------------------- parsing

def _as_str_list(value) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if value is None:
        return []
    return [str(value)]


def _collect_strings(obj, out: list[str]) -> None:
    """Collect string keys/values from a server dict, except env values.

    Env values are deliberately excluded so a secret value can never
    flow into a finding detail via this helper.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            if str(k).lower() == "env" and isinstance(v, dict):
                # keys only — never env values
                for ek in v.keys():
                    out.append(str(ek))
                continue
            _collect_strings(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _collect_strings(item, out)
    elif isinstance(obj, str):
        out.append(obj)


def _extract_servers(data: dict, source_file: str) -> list[dict]:
    """Normalise the known config shapes into raw server dicts.

    Returns a list of {"name", "raw"} entries. Handles:
      - {"mcpServers": {name: {...}}}   (Claude Desktop / Cursor)
      - {"servers": {name: {...}}}      (VS Code)
      - {"mcpServers": [...]}           (list form, name inside)
      - top-level {"permissions": {"allow": [...]}} (Claude Code
        settings.json) -> synthetic "global-permissions" server
    """
    entries: list[dict] = []
    if not isinstance(data, dict):
        return entries
    for key in ("mcpServers", "servers", "mcp_servers"):
        block = data.get(key)
        if isinstance(block, dict):
            for name, raw in block.items():
                if isinstance(raw, dict):
                    entries.append({"name": str(name), "raw": raw})
                else:
                    entries.append({"name": str(name), "raw": {"command": str(raw)}})
        elif isinstance(block, list):
            for i, raw in enumerate(block):
                if isinstance(raw, dict):
                    name = raw.get("name") or raw.get("id") or f"server-{i}"
                    entries.append({"name": str(name), "raw": raw})
    perms = data.get("permissions")
    if isinstance(perms, dict):
        allow = perms.get("allow") or perms.get("allowed") or []
        deny = perms.get("deny") or []
        if allow or deny:
            entries.append({
                "name": "global-permissions",
                "raw": {
                    "command": "",
                    "args": [],
                    "permissions_allow": _as_str_list(allow),
                    "permissions_deny": _as_str_list(deny),
                },
            })
    # A bare single-server file: {"command": ..., "args": [...]}
    if not entries and ("command" in data or "args" in data):
        entries.append({"name": data.get("name") or "default", "raw": data})
    return entries


def load_config_file(path: str):
    """Return (data, error). ``data`` is None on error."""
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh), None
    except FileNotFoundError:
        return None, f"{path}: file not found"
    except json.JSONDecodeError as exc:
        return None, f"{path}: invalid JSON ({exc.msg} at line {exc.lineno})"
    except OSError as exc:
        return None, f"{path}: cannot read ({exc})"


# ---------------------------------------------------------------- classify

SHELL_COMMANDS = {"bash", "sh", "zsh", "fish", "cmd", "cmd.exe",
                  "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
FILESYSTEM_HINTS = ("filesystem", "file-system", "file_system", "server-filesystem")
NETWORK_HINTS = ("fetch", "http", "browser", "puppeteer", "playwright",
                 "web-search", "websearch", "search", "scrape", "crawl")
DATABASE_HINTS = ("postgres", "mysql", "sqlite", "mongo", "redis",
                  "database", "db-", "-db", "sql-server", "mssql")
DB_URL_PREFIXES = ("postgres://", "postgresql://", "mysql://",
                   "mongodb://", "mongodb+srv://", "redis://", "sqlite:")


def _basename(command: str) -> str:
    return os.path.basename(str(command or "").strip()).lower()


def _looks_like_path(text: str) -> bool:
    t = str(text)
    if t.startswith(("/", "~/", "./", "../", "~\\")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", t):
        return True
    return False


def classify_server(name: str, raw: dict) -> Capabilities:
    command = str(raw.get("command") or "")
    args = _as_str_list(raw.get("args"))
    env = raw.get("env") if isinstance(raw.get("env"), dict) else {}
    url = str(raw.get("url") or raw.get("endpoint") or "")
    haystack = " ".join([name, command] + args).lower()

    caps = Capabilities()
    # shell execution
    if _basename(command) in SHELL_COMMANDS:
        caps.shell_execution = True
    if any(h in name.lower() for h in ("shell", "terminal", "bash", "exec")):
        caps.shell_execution = True
    # filesystem: explicit path arguments
    for a in args:
        if _looks_like_path(a):
            caps.filesystem_paths.append(a)
    if any(h in haystack for h in FILESYSTEM_HINTS) and not caps.filesystem_paths:
        caps.filesystem_paths.append("(server default scope)")
    # network
    if url.startswith(("http://", "https://", "ws://", "wss://")):
        caps.network_access = True
    if any(h in haystack for h in NETWORK_HINTS):
        caps.network_access = True
    if any(a.startswith(("http://", "https://")) for a in args):
        caps.network_access = True
    # database
    if any(h in haystack for h in DATABASE_HINTS):
        caps.database_access = True
    if any(a.lower().startswith(DB_URL_PREFIXES) for a in args):
        caps.database_access = True
    for k in env.keys():
        if str(k).upper() in ("DATABASE_URL", "DATABASE_URI", "DB_URL", "DSN"):
            caps.database_access = True
    # env secrets — names only
    caps.env_secret_names = sorted(k for k in env.keys() if is_secret_key(str(k)))
    return caps


# ---------------------------------------------------------------- checks

DANGEROUS_FLAGS = [
    "--dangerously-skip-permissions",
    "--dangerously-allow-all",
    "--allow-all",
    "--skip-permissions",
    "--no-sandbox",
    "--disable-sandbox",
    "--allow-root",
    "--privileged",
    "--unsafe",
    "--insecure",
]

DESTRUCTIVE_RE = re.compile(
    r"(\bDROP\b|\bTRUNCATE\b|DESTROY|\bWIPE\b|DELETE\s+FROM|"
    r"\bDELETE_ALL\b|\brm\s+-(?:rf|fr|r)\b|\bmkfs\b|\bPURGE\b)",
    re.IGNORECASE,
)
# Tool/server names that are a bare destructive verb, e.g. a tool
# literally called "delete" or "drop_table".
DESTRUCTIVE_NAME_RE = re.compile(
    r"(^|[\s_\-./])(drop|delete|truncate|destroy|wipe|purge)([\s_\-./]|$)",
    re.IGNORECASE,
)

BROAD_PATHS = {"/", "/*", "~", "~/", "/home", "/home/", "/Users", "/Users/",
               "C:\\", "C:/", "C:\\*", "*", ".*", "/root", "/etc"}


def _finding(rule_id, title, severity, server_name, detail, source_file):
    return Finding(
        rule_id=rule_id, title=title, severity=severity,
        points=points_for(severity), server_name=server_name,
        detail=detail, source_file=source_file,
    )


def _is_unpinned(command: str, args: list[str]) -> tuple[bool, str]:
    """Return (unpinned, package_token) for npx/uvx-style invocations."""
    base = _basename(command)
    if base not in ("npx", "uvx", "pnpx", "bunx"):
        return False, ""
    skip_with_value = {"--package", "-p", "--from", "--index-url", "--extra-index-url"}
    i = 0
    package = ""
    while i < len(args):
        tok = args[i]
        if tok in skip_with_value:
            # the package may be the value of --package/-p/--from
            if i + 1 < len(args):
                package = args[i + 1]
            break
        if tok.startswith("-"):
            i += 1
            continue
        package = tok
        break
    if not package:
        return False, ""
    # Split a pinned version suffix. Scoped: @scope/name[@version]
    if package.startswith("@"):
        rest = package[1:]
        if "/" in rest:
            _, _, tail = rest.partition("/")
            if "@" not in tail:
                return True, package
            version = tail.rsplit("@", 1)[-1]
            return (version in ("", "latest")), package
        return True, package
    if "@" not in package:
        return True, package
    version = package.rsplit("@", 1)[-1]
    return (version in ("", "latest")), package


def check_server(name: str, raw: dict, source_file: str,
                 caps: Capabilities) -> list[Finding]:
    findings: list[Finding] = []
    command = str(raw.get("command") or "")
    args = _as_str_list(raw.get("args"))
    env = raw.get("env") if isinstance(raw.get("env"), dict) else {}

    strings: list[str] = []
    _collect_strings(raw, strings)
    joined = "\n".join(strings)
    allow_list = _as_str_list(raw.get("permissions_allow")) + \
        _as_str_list(raw.get("permissions")) + \
        _as_str_list((raw.get("permissions") or {}).get("allow")
                     if isinstance(raw.get("permissions"), dict) else [])

    # R001 wildcard permissions
    wildcard_hits = []
    for s in strings + allow_list:
        t = s.strip()
        if t == "*" or "(*)" in t or t.endswith(":*") or t == "*:*":
            wildcard_hits.append(t)
    if wildcard_hits:
        findings.append(_finding(
            "R001", "Wildcard permission granted", "high", name,
            f"Wildcard permission(s): {', '.join(sorted(set(wildcard_hits))[:5])} "
            "grant unrestricted access instead of a scoped allowlist.",
            source_file))

    # R002 unpinned package
    unpinned, pkg = _is_unpinned(command, args)
    if unpinned:
        findings.append(_finding(
            "R002", "Unpinned package execution", "medium", name,
            f"'{_basename(command)}' runs package '{mask_arg(pkg)}' without a "
            "pinned @version — the code executed can change at any time "
            "(supply-chain risk). Pin an exact version.",
            source_file))

    # R003 hardcoded secrets in env values (values never copied out)
    for key in sorted(env.keys()):
        if looks_like_hardcoded_secret(str(key), env[key]):
            findings.append(_finding(
                "R003", "Hardcoded secret in env", "high", name,
                f"Env var '{key}' contains a hardcoded secret value "
                "(value masked: ***). Use an environment reference "
                "such as ${VAR} or a secret manager instead.",
                source_file))
    # secrets embedded in args — masked in the detail
    for a in args:
        if value_matches_secret_pattern(a):
            findings.append(_finding(
                "R003", "Hardcoded secret in arguments", "high", name,
                f"An argument matches a known secret pattern "
                f"(masked: {mask_arg(a)[:40]}). Secrets in args are "
                "visible in process listings and logs.",
                source_file))
            break

    # R004 dangerous flags
    flag_hits = [f for f in DANGEROUS_FLAGS
                 if any(f == a.strip() or a.strip().startswith(f + "=")
                        for a in args + [command])]
    if flag_hits:
        findings.append(_finding(
            "R004", "Dangerous flag disables safety checks", "critical", name,
            f"Dangerous flag(s): {', '.join(sorted(set(flag_hits)))} "
            "disable permission/sandbox checks for this server.",
            source_file))

    # R005 destructive tool / command names
    destructive_targets = [name, command] + args + \
        _as_str_list(raw.get("tools")) + \
        _as_str_list(raw.get("allowedTools")) + \
        _as_str_list(raw.get("allowed_tools"))
    destructive_hit = None
    for t in destructive_targets:
        if DESTRUCTIVE_RE.search(str(t)) or DESTRUCTIVE_NAME_RE.search(str(t)):
            destructive_hit = str(t)
            break
    if destructive_hit:
        findings.append(_finding(
            "R005", "Destructive operation exposed", "high", name,
            f"'{mask_arg(destructive_hit)[:60]}' exposes a destructive "
            "operation (DROP/DELETE/TRUNCATE-like). An agent that can "
            "invoke it can irreversibly destroy data.",
            source_file))

    # R006 broad filesystem access
    broad = [p for p in caps.filesystem_paths if p.strip() in BROAD_PATHS]
    if broad:
        findings.append(_finding(
            "R006", "Broad filesystem access", "high", name,
            f"Filesystem scope includes broad path(s): "
            f"{', '.join(sorted(set(broad)))}. Scope the server to the "
            "specific project directory it needs.",
            source_file))

    # R007 shell execution capability
    if caps.shell_execution:
        findings.append(_finding(
            "R007", "Shell execution capability", "medium", name,
            f"Server '{name}' can execute shell commands "
            f"(command: {_basename(command) or 'shell-like name'}). "
            "Shell access lets an agent run arbitrary commands with "
            "your user's permissions.",
            source_file))

    return findings


# ---------------------------------------------------------------- scan

def scan_file(path: str, result: ScanResult) -> None:
    data, error = load_config_file(path)
    if error:
        result.errors.append(error)
        return
    result.scanned_files.append(path)
    if not isinstance(data, dict):
        result.errors.append(f"{path}: top-level JSON is not an object")
        return
    for entry in _extract_servers(data, path):
        name, raw = entry["name"], entry["raw"]
        caps = classify_server(name, raw)
        server = Server(
            name=name,
            source_file=path,
            command=mask_text(str(raw.get("command") or "")),
            args_masked=[mask_arg(a) for a in _as_str_list(raw.get("args"))],
            url=mask_text(str(raw.get("url") or raw.get("endpoint") or "")),
            env_names=sorted(str(k) for k in (raw.get("env") or {}).keys())
            if isinstance(raw.get("env"), dict) else [],
            capabilities=caps,
        )
        server.findings = check_server(name, raw, path, caps)
        server.score = server_score(server.findings)
        server.risk_level = level_for_score(server.score)
        result.servers.append(server)


def scan_path(path: str) -> ScanResult:
    result = ScanResult()
    files = discover_configs(path)
    if not files:
        if not os.path.exists(path):
            result.errors.append(f"{path}: no such file or directory")
        else:
            result.errors.append(
                f"{path}: no known MCP config files found "
                f"(looked for: {', '.join(sorted(KNOWN_FILENAMES))})")
        return result
    for f in files:
        scan_file(f, result)
    result.servers.sort(key=lambda s: (-s.score, s.name))
    return result
