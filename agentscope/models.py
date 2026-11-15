"""Data models for AgentScope. Secret values are never stored here."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str  # critical | high | medium | low | info
    points: int
    server_name: str
    detail: str  # must never contain a secret value
    source_file: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "points": self.points,
            "server": self.server_name,
            "detail": self.detail,
            "source_file": self.source_file,
        }


@dataclass
class Capabilities:
    shell_execution: bool = False
    filesystem_paths: list = field(default_factory=list)  # paths only, never secrets
    network_access: bool = False
    database_access: bool = False
    env_secret_names: list = field(default_factory=list)  # NAMES only

    @property
    def filesystem_access(self) -> bool:
        return bool(self.filesystem_paths)

    def to_dict(self) -> dict:
        return {
            "shell_execution": self.shell_execution,
            "filesystem_access": self.filesystem_access,
            "filesystem_paths": list(self.filesystem_paths),
            "network_access": self.network_access,
            "database_access": self.database_access,
            "env_secret_names": list(self.env_secret_names),
        }


@dataclass
class Server:
    name: str
    source_file: str
    command: str = ""
    args_masked: list = field(default_factory=list)  # args with secrets masked
    url: str = ""
    env_names: list = field(default_factory=list)  # all env keys (names only)
    capabilities: Capabilities = field(default_factory=Capabilities)
    findings: list = field(default_factory=list)  # list[Finding]
    score: int = 0
    risk_level: str = "clean"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "source_file": self.source_file,
            "command": self.command,
            "args": list(self.args_masked),
            "url": self.url,
            "env": {name: "***" for name in self.env_names},
            "env_secret_names": list(self.capabilities.env_secret_names),
            "capabilities": self.capabilities.to_dict(),
            "score": self.score,
            "risk_level": self.risk_level,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanResult:
    scanned_files: list = field(default_factory=list)
    servers: list = field(default_factory=list)  # list[Server]
    errors: list = field(default_factory=list)

    @property
    def all_findings(self) -> list:
        out = []
        for s in self.servers:
            out.extend(s.findings)
        return out

    @property
    def overall_score(self) -> int:
        from .scoring import overall_score as _overall
        return _overall([s.score for s in self.servers])

    @property
    def risk_level(self) -> str:
        from .scoring import level_for_score
        return level_for_score(self.overall_score)
