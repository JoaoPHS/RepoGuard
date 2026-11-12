"""Nota de risco e veredito. A reputação só atenua sinais sociais e de conta nova."""

from __future__ import annotations

from repoguard.models import Finding, RawFinding, Severity, Snapshot, Verdict
from repoguard.rules.common import clean_snippet
from repoguard.timeutil import age_days

WEIGHTS: dict[Severity, int] = {
    "info": 0,
    "low": 4,
    "medium": 10,
    "high": 25,
    "critical": 40,
}
_ORDER: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")
_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

YOUNG_DAYS = 30
YOUNG_STARS = 10
REPUTABLE_DAYS = 180
REPUTABLE_STARS = 50
REVIEW_SCORE = 30
BLOCK_SCORE = 70


def is_young_unknown(snapshot: Snapshot) -> bool:
    age = age_days(snapshot.created_at, snapshot.now)
    if age is None:
        return False
    return age < YOUNG_DAYS and snapshot.stars < YOUNG_STARS


def is_reputable(snapshot: Snapshot) -> bool:
    age = age_days(snapshot.created_at, snapshot.now)
    if age is None:
        return False
    return age >= REPUTABLE_DAYS and snapshot.stars >= REPUTABLE_STARS


def step_severity(severity: Severity, steps: int) -> Severity:
    index = _ORDER.index(severity)
    return _ORDER[min(len(_ORDER) - 1, max(0, index + steps))]


def adjust(raw: RawFinding, snapshot: Snapshot) -> Finding:
    severity = raw.severity
    if raw.escalate_when_young and is_young_unknown(snapshot):
        severity = step_severity(severity, 1)
    elif raw.escalate_when_untrusted and not is_reputable(snapshot):
        severity = step_severity(severity, 1)
    elif raw.dampable and is_reputable(snapshot):
        severity = step_severity(severity, -1)
    return Finding(
        rule_id=raw.rule_id,
        severity=severity,
        title=raw.title,
        detail=raw.detail,
        path=raw.path,
        evidence=_safe_evidence(raw.evidence),
    )


def _safe_evidence(evidence: str | None) -> str | None:
    if not evidence:
        return None
    cleaned = clean_snippet(evidence, 0, len(evidence))
    return cleaned or None


def verdict_for(findings: list[Finding]) -> tuple[int, Verdict]:
    score = min(100, sum(WEIGHTS[finding.severity] for finding in findings))
    severities = {finding.severity for finding in findings}
    if "critical" in severities or score >= BLOCK_SCORE:
        verdict: Verdict = "nao_clonar"
    elif "high" in severities or score >= REVIEW_SCORE:
        verdict = "revisar"
    else:
        verdict = "apto"
    return score, verdict


def finalize(raw_findings: list[RawFinding], snapshot: Snapshot) -> tuple[tuple[Finding, ...], int, Verdict]:
    findings = [adjust(raw, snapshot) for raw in raw_findings]
    findings.sort(key=lambda finding: (_RANK[finding.severity], finding.rule_id, finding.path or ""))
    score, verdict = verdict_for(findings)
    return tuple(findings), score, verdict
