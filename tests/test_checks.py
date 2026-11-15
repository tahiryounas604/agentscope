"""Individual check detection: wildcard, unpinned, dangerous flag,
destructive name, broad filesystem, shell, hardcoded secret."""
from agentscope.scanner import _is_unpinned, check_server, classify_server


def _rules(name, raw):
    caps = classify_server(name, raw)
    return {f.rule_id for f in check_server(name, raw, "test.json", caps)}


# --- wildcard (R001) -------------------------------------------------------

def test_wildcard_bash_star_in_args():
    rules = _rules("s", {"command": "npx", "args": ["--allowed-tools", "Bash(*)"]})
    assert "R001" in rules


def test_wildcard_plain_star():
    rules = _rules("s", {"command": "tool", "args": ["*"]})
    assert "R001" in rules


def test_wildcard_in_permissions_allow():
    rules = _rules("global-permissions",
                   {"command": "", "args": [], "permissions_allow": ["Bash(*)"]})
    assert "R001" in rules


def test_no_wildcard_for_scoped_permission():
    rules = _rules("s", {"command": "tool", "args": ["Bash(git status)"]})
    assert "R001" not in rules


# --- unpinned packages (R002) ----------------------------------------------

def test_unpinned_npx_unscoped():
    assert _is_unpinned("npx", ["-y", "mcp-shell"]) == (True, "mcp-shell")


def test_unpinned_npx_scoped_without_version():
    unpinned, pkg = _is_unpinned("npx", ["-y", "@modelcontextprotocol/server-everything"])
    assert unpinned is True
    assert pkg == "@modelcontextprotocol/server-everything"


def test_unpinned_latest_counts_as_unpinned():
    assert _is_unpinned("npx", ["pkg@latest"])[0] is True
    assert _is_unpinned("uvx", ["pkg@latest"])[0] is True


def test_pinned_packages_are_not_unpinned():
    assert _is_unpinned("npx", ["-y", "@scope/pkg@1.2.3"])[0] is False
    assert _is_unpinned("npx", ["pkg@0.5.0"])[0] is False
    assert _is_unpinned("uvx", ["mcp-server-sqlite@0.5.0"])[0] is False


def test_unpinned_not_applied_to_other_commands():
    assert _is_unpinned("bash", ["something"])[0] is False
    assert _is_unpinned("node", ["server.js"])[0] is False


def test_unpinned_finding_emitted():
    assert "R002" in _rules("s", {"command": "npx", "args": ["-y", "some-pkg"]})
    assert "R002" not in _rules("s", {"command": "npx", "args": ["-y", "some-pkg@2.0.0"]})


# --- dangerous flags (R004) --------------------------------------------------

def test_dangerous_flag_detection():
    rules = _rules("s", {"command": "uvx",
                         "args": ["tool@1.0.0", "--dangerously-skip-permissions"]})
    assert "R004" in rules


def test_dangerous_flag_variants():
    for flag in ("--allow-all", "--no-sandbox", "--skip-permissions"):
        rules = _rules("s", {"command": "tool", "args": [flag]})
        assert "R004" in rules, flag


def test_no_dangerous_flag_on_clean_args():
    rules = _rules("s", {"command": "tool", "args": ["--port", "8080"]})
    assert "R004" not in rules


# --- destructive names (R005) ------------------------------------------------

def test_destructive_drop_in_args():
    rules = _rules("s", {"command": "uvx",
                         "args": ["tool@1.0.0", "--tool", "DROP_TABLE"]})
    assert "R005" in rules


def test_destructive_server_name():
    rules = _rules("db-destroyer", {"command": "tool", "args": []})
    assert "R005" in rules


def test_destructive_delete_tool_name():
    rules = _rules("s", {"command": "tool", "args": [], "tools": ["delete"]})
    assert "R005" in rules


def test_no_destructive_on_reader():
    rules = _rules("sqlite-reader",
                   {"command": "uvx", "args": ["mcp-server-sqlite@0.5.0"]})
    assert "R005" not in rules


# --- broad filesystem (R006) + shell (R007) ----------------------------------

def test_broad_filesystem_root():
    rules = _rules("fs", {"command": "npx",
                          "args": ["@modelcontextprotocol/server-filesystem@1.0.0", "/"]})
    assert "R006" in rules


def test_scoped_filesystem_is_not_broad():
    rules = _rules("fs", {"command": "npx",
                          "args": ["@modelcontextprotocol/server-filesystem@1.0.0",
                                   "/home/user/projects/demo"]})
    assert "R006" not in rules


def test_shell_execution_finding():
    assert "R007" in _rules("shell-runner", {"command": "bash", "args": ["-c", "ls"]})
    assert "R007" not in _rules("fs", {"command": "npx", "args": ["pkg@1.0.0"]})


# --- hardcoded secrets (R003) --------------------------------------------------

def test_hardcoded_secret_by_key_and_value():
    rules = _rules("s", {"command": "tool", "args": [],
                         "env": {"API_KEY": "a-real-looking-value-123456"}})
    assert "R003" in rules


def test_hardcoded_secret_by_pattern():
    rules = _rules("s", {"command": "tool", "args": [],
                         "env": {"SOMETHING": "sk-abcdefghij1234567890"}})
    assert "R003" in rules


def test_env_reference_is_not_hardcoded():
    rules = _rules("s", {"command": "tool", "args": [],
                         "env": {"API_KEY": "${API_KEY}"}})
    assert "R003" not in rules


def test_empty_env_value_is_not_hardcoded():
    rules = _rules("s", {"command": "tool", "args": [], "env": {"API_KEY": ""}})
    assert "R003" not in rules
