"""Workflows e actions publicados no repositório."""

from __future__ import annotations

import re

from repoguard.models import RawFinding, Snapshot
from repoguard.rules.common import CURL_PIPE, evidence_for, human_join

_EVENT_IN_RUN = re.compile(r"\$\{\{\s*github\.event\.")
_PR_HEAD = (
    "github.event.pull_request.head",
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.repo",
)
_USES = re.compile(r"uses:\s*([^\s#]+)", re.IGNORECASE)
_SHA = re.compile(r"^[0-9a-fA-F]{40}$")


def check(snapshot: Snapshot) -> list[RawFinding]:
    findings: list[RawFinding] = []
    unpinned: list[str] = []
    unpinned_path: str | None = None
    for path, content in _workflows(snapshot):
        if CURL_PIPE.search(content):
            findings.append(
                RawFinding(
                    rule_id="workflow.curl_pipe_shell",
                    severity="high",
                    title="Download encadeado em shell",
                    detail="O workflow baixa conteúdo remoto e o encaminha para um shell.",
                    path=path,
                    evidence=evidence_for(content, CURL_PIPE),
                )
            )
        pr_severity = _pr_target_severity(content)
        if pr_severity is not None:
            privileged = pr_severity == "critical"
            findings.append(
                RawFinding(
                    rule_id="workflow.pr_target_checkout",
                    severity=pr_severity,
                    title="pull_request_target com checkout do PR",
                    detail=(
                        "O workflow usa pull_request_target e faz checkout do código do pull request. "
                        + (
                            "Ele também usa segredo ou permissão de escrita."
                            if privileged
                            else "Esse código roda num workflow privilegiado, mesmo sem um segredo escrito no arquivo."
                        )
                    ),
                    path=path,
                    evidence=evidence_for(content, re.compile(r"pull_request_target")),
                )
            )
        if _run_interpolates_event(content):
            findings.append(
                RawFinding(
                    rule_id="workflow.interpolacao_evento",
                    severity="high",
                    title="Dado do evento interpolado no shell",
                    detail=(
                        "Um passo run interpola github.event no script. "
                        "O texto do issue ou do pull request pode virar comando."
                    ),
                    path=path,
                    evidence=evidence_for(content, _EVENT_IN_RUN),
                )
            )
        if re.search(r"permissions:\s*write-all", content):
            findings.append(
                RawFinding(
                    rule_id="workflow.permissoes_amplas",
                    severity="medium",
                    title="Permissões amplas no workflow",
                    detail="O workflow declara permissions: write-all.",
                    path=path,
                    evidence=evidence_for(content, re.compile(r"permissions:\s*write-all")),
                )
            )
        specs = _unpinned_actions(content)
        if specs and unpinned_path is None:
            unpinned_path = path
        for spec in specs:
            if spec not in unpinned:
                unpinned.append(spec)

    if unpinned:
        findings.append(
            RawFinding(
                rule_id="workflow.action_sem_sha",
                severity="low",
                title="Action sem commit fixo",
                detail=(
                    "Há actions referenciadas por tag ou branch, não por um SHA de 40 caracteres: "
                    f"{human_join(unpinned[:5])}."
                ),
                path=unpinned_path,
                evidence=unpinned[0],
                dampable=True,
            )
        )
    return findings


def _workflows(snapshot: Snapshot) -> list[tuple[str, str]]:
    selected: list[tuple[str, str]] = []
    for path, content in snapshot.files.items():
        lowered = path.lower()
        name = lowered.rsplit("/", 1)[-1]
        if lowered.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
            selected.append((path, content))
        elif name in {"action.yml", "action.yaml"}:
            selected.append((path, content))
    return selected


def _pr_target_severity(content: str) -> str | None:
    if re.search(r"pull_request_target\b", content) is None:
        return None
    if not any(token in content for token in _PR_HEAD):
        return None
    if re.search(r"\bsecrets\.", content):
        return "critical"
    if re.search(r"permissions:\s*write-all", content):
        return "critical"
    if re.search(r"(?:contents|id-token|packages):\s*write", content):
        return "critical"
    return "high"


def _run_interpolates_event(content: str) -> bool:
    return any(_EVENT_IN_RUN.search(script) for script in _run_scripts(content))


def _run_scripts(content: str) -> list[str]:
    lines = content.expandtabs(2).splitlines()
    scripts: list[str] = []
    index = 0
    while index < len(lines):
        match = re.match(r"^([ ]*)(?:-\s*)?run:(.*)$", lines[index])
        if match is None:
            index += 1
            continue
        indent = len(match.group(1))
        rest = match.group(2).strip()
        if rest[:1] in {"|", ">"}:
            block: list[str] = []
            index += 1
            while index < len(lines):
                line = lines[index]
                if not line.strip():
                    block.append(line)
                    index += 1
                    continue
                line_indent = len(line) - len(line.lstrip(" "))
                if line_indent <= indent:
                    break
                block.append(line)
                index += 1
            scripts.append("\n".join(block))
        else:
            scripts.append(rest)
            index += 1
    return scripts


def _unpinned_actions(content: str) -> list[str]:
    found: list[str] = []
    for match in _USES.finditer(content):
        spec = match.group(1).strip().strip("'\"")
        if spec.startswith(("./", "docker://")):
            continue
        if "@" not in spec:
            found.append(spec)
            continue
        ref = spec.rsplit("@", 1)[1]
        if _SHA.fullmatch(ref):
            continue
        found.append(spec)
    return found
