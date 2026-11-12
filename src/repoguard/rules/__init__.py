"""Famílias de regras do veredito."""

from __future__ import annotations

from collections.abc import Callable

from repoguard.models import RawFinding, Snapshot
from repoguard.rules import install, metadata, name, readme, releases, secrets, tree, workflows

Rule = Callable[[Snapshot], list[RawFinding]]

RULES: tuple[Rule, ...] = (
    metadata.check,
    name.check,
    tree.check,
    workflows.check,
    install.check,
    secrets.check,
    readme.check,
    releases.check,
)


def collect(snapshot: Snapshot) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for rule in RULES:
        findings.extend(rule(snapshot))
    return findings
