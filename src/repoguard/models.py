"""Contrato do relatório. O CLI e uma interface futura leem o mesmo objeto."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Literal

Severity = Literal["info", "low", "medium", "high", "critical"]
Verdict = Literal["apto", "revisar", "nao_clonar"]

SEVERITIES: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class TreeEntry:
    path: str
    kind: str
    size: int | None = None


@dataclass(frozen=True)
class RawFinding:
    """Achado antes da reputação ajustar a severidade."""

    rule_id: str
    severity: Severity
    title: str
    detail: str
    path: str | None = None
    evidence: str | None = None
    dampable: bool = False
    escalate_when_young: bool = False
    escalate_when_untrusted: bool = False


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    detail: str
    path: str | None = None
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Snapshot:
    """O que a API devolveu e as regras podem ler. Nenhum arquivo é executado."""

    owner: str
    repo: str
    html_url: str
    ref: str
    created_at: datetime | None
    stars: int
    forks: int
    is_fork: bool
    archived: bool
    license_spdx: str | None
    owner_created_at: datetime | None
    commit_count: int | None
    tree_truncated: bool
    entries: tuple[TreeEntry, ...]
    files: dict[str, str]
    skipped_large: tuple[str, ...]
    release_assets: tuple[str, ...]
    now: datetime


@dataclass(frozen=True)
class ScanReport:
    repo: str
    html_url: str
    ref: str
    verdict: Verdict
    risk_score: int
    findings: tuple[Finding, ...]
    stats: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "html_url": self.html_url,
            "ref": self.ref,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "findings": [finding.to_dict() for finding in self.findings],
            "stats": self.stats,
        }
