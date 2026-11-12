"""Manifestos de instalação, hooks e scripts que o repositório pede para rodar."""

from __future__ import annotations

import json
import re

from repoguard.models import RawFinding, Snapshot
from repoguard.rules.common import (
    BASE64_EXEC,
    CURL_PIPE,
    EXFIL,
    HOOK_NET,
    MINER,
    OBFUSCATED,
    SHELL_CHANNEL,
    evidence_for,
    human_join,
)

_LIFECYCLE = ("preinstall", "install", "postinstall", "prepare")
_GIT_HTTP = re.compile(r"git\+http://", re.IGNORECASE)
_GIT_URL = re.compile(
    r"git\+https?://|git\+ssh://|\bgithub:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
    re.IGNORECASE,
)
_LOOSE_URL = re.compile(r"(?m)^\s*(?:-e\s+)?https?://\S+")
_SETUP_CMD = re.compile(
    r"\bos\.system\s*\(|\bsubprocess\.(?:run|call|Popen|check_output|check_call)\s*\(|"
    r"\bexec\s*\(|\beval\s*\("
)
_SCRIPT_NAMES = (".sh", ".ps1", ".bat", ".cmd")
_JS_NAMES = (".js", ".mjs", ".cjs")
_INSTALL_JS = {"install.js", "preinstall.js", "postinstall.js", "setup.js"}
_SCRIPT_FILES = {"makefile", "dockerfile", "justfile"}


def check(snapshot: Snapshot) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for path, content in snapshot.files.items():
        name = path.rsplit("/", 1)[-1].lower()
        if name == "package.json":
            findings.extend(_package(path, content))
            joined = "\n".join(_lifecycle_scripts(content).values())
            if joined:
                findings.extend(_active_script(path, joined, exfil=False))
        if name in {"setup.py", "pyproject.toml", "setup.cfg", "pipfile"} or _is_requirements(name):
            findings.extend(_python_deps(path, content))
        if name == "setup.py" and _SETUP_CMD.search(content):
            findings.append(
                RawFinding(
                    rule_id="install.setup_comando",
                    severity="high",
                    title="setup.py executa comando na instalação",
                    detail=(
                        "O setup.py chama o sistema, subprocess, exec ou eval. "
                        "Isso roda quando o pacote é instalado."
                    ),
                    path=path,
                    evidence=evidence_for(content, _SETUP_CMD),
                )
            )
        if _is_script(path) and CURL_PIPE.search(content):
            findings.append(
                RawFinding(
                    rule_id="script.curl_pipe_shell",
                    severity="high",
                    title="Script baixa e executa código remoto",
                    detail="O arquivo encaminha um download para um shell.",
                    path=path,
                    evidence=evidence_for(content, CURL_PIPE),
                )
            )
        if _is_script(path) and name != "package.json":
            findings.extend(_active_script(path, content))
        if _install_text(path) and BASE64_EXEC.search(content):
            findings.append(
                RawFinding(
                    rule_id="install.base64_exec",
                    severity="critical",
                    title="Código ofuscado em base64 com execução",
                    detail="O arquivo decodifica base64 e encaminha o resultado para execução.",
                    path=path,
                    evidence=evidence_for(content, BASE64_EXEC),
                )
            )
    return findings


def _package(path: str, content: str) -> list[RawFinding]:
    scripts = _lifecycle_scripts(content)
    findings: list[RawFinding] = []
    if scripts:
        networked = [
            key
            for key, value in scripts.items()
            if HOOK_NET.search(value) or CURL_PIPE.search(value) or EXFIL.search(value)
        ]
        if networked:
            sample = "\n".join(scripts[key] for key in networked)
            findings.append(
                RawFinding(
                    rule_id="install.hook_rede",
                    severity="critical",
                    title="Instalação baixa ou executa código remoto",
                    detail=(
                        f"O script {human_join(networked)} do package.json acessa a rede "
                        "ou encaminha um download para o shell."
                    ),
                    path=path,
                    evidence=evidence_for(sample, HOOK_NET) or evidence_for(sample, CURL_PIPE),
                )
            )
        else:
            findings.append(
                RawFinding(
                    rule_id="install.hook",
                    severity="medium",
                    title="Script de ciclo de instalação",
                    detail=(
                        f"O package.json define {human_join(list(scripts))}, "
                        "que o npm executa durante a instalação."
                    ),
                    path=path,
                    evidence=clean_script(next(iter(scripts.values()))),
                    dampable=True,
                    escalate_when_untrusted=True,
                )
            )
    for spec in _package_dep_specs(content):
        if _GIT_HTTP.search(spec):
            findings.append(
                RawFinding(
                    rule_id="install.dependencia_git_http",
                    severity="high",
                    title="Dependência por git sem criptografia",
                    detail="Há dependência apontando para git+http, que trafega sem criptografia.",
                    path=path,
                    evidence=clean_script(spec),
                )
            )
        elif _GIT_URL.search(spec) or re.search(r"https?://", spec):
            findings.append(
                RawFinding(
                    rule_id="install.dependencia_url",
                    severity="medium",
                    title="Dependência por URL ou git",
                    detail=(
                        "Há dependência apontando para um repositório git ou uma URL, "
                        "fora do registro padrão do ecossistema."
                    ),
                    path=path,
                    evidence=clean_script(spec),
                )
            )
    return _one_per_rule(findings)


def _python_deps(path: str, content: str) -> list[RawFinding]:
    findings: list[RawFinding] = []
    if _GIT_HTTP.search(content):
        findings.append(
            RawFinding(
                rule_id="install.dependencia_git_http",
                severity="high",
                title="Dependência por git sem criptografia",
                detail="Há dependência apontando para git+http, que trafega sem criptografia.",
                path=path,
                evidence=evidence_for(content, _GIT_HTTP),
            )
        )
    elif _GIT_URL.search(content) or _LOOSE_URL.search(content):
        pattern = _GIT_URL if _GIT_URL.search(content) else _LOOSE_URL
        findings.append(
            RawFinding(
                rule_id="install.dependencia_url",
                severity="medium",
                title="Dependência por URL ou git",
                detail=(
                    "Há dependência apontando para um repositório git ou uma URL, "
                    "fora do registro padrão do ecossistema."
                ),
                path=path,
                evidence=evidence_for(content, pattern),
            )
        )
    return findings


def _is_requirements(name: str) -> bool:
    return name.startswith("requirements") and name.endswith(".txt")


def _lifecycle_scripts(content: str) -> dict[str, str]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return {}
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return {}
    found: dict[str, str] = {}
    for key in _LIFECYCLE:
        value = scripts.get(key)
        if isinstance(value, str) and value.strip():
            found[key] = value
    return found


def _package_dep_specs(content: str) -> list[str]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    specs: list[str] = []
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(key)
        if not isinstance(block, dict):
            continue
        for name, value in block.items():
            if isinstance(value, str):
                specs.append(f"{name} {value}")
    return specs


def _install_text(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    if name in {"package.json", "setup.py", "pyproject.toml", "setup.cfg"}:
        return True
    if name.startswith("requirements") and name.endswith(".txt"):
        return True
    return _is_script(path)


def _active_script(path: str, content: str, *, exfil: bool = True) -> list[RawFinding]:
    findings: list[RawFinding] = []
    if exfil and EXFIL.search(content):
        findings.append(
            RawFinding(
                rule_id="install.exfil",
                severity="critical",
                title="Destino usado para vazamento",
                detail="O arquivo aponta para um endereço típico de coleta de dados ou de callback.",
                path=path,
                evidence=evidence_for(content, EXFIL),
            )
        )
    if OBFUSCATED.search(content):
        findings.append(
            RawFinding(
                rule_id="install.ofuscacao",
                severity="critical",
                title="Execução ofuscada",
                detail="O arquivo monta ou executa código escondido em codificação.",
                path=path,
                evidence=evidence_for(content, OBFUSCATED),
            )
        )
    if SHELL_CHANNEL.search(content):
        findings.append(
            RawFinding(
                rule_id="script.canal_shell",
                severity="critical",
                title="Canal de shell pela rede",
                detail="O script referencia um canal de rede usado por shell remoto.",
                path=path,
                evidence=evidence_for(content, SHELL_CHANNEL),
            )
        )
    if MINER.search(content):
        findings.append(
            RawFinding(
                rule_id="script.minerador",
                severity="critical",
                title="Indicador de minerador",
                detail="O arquivo cita um minerador ou um endereço de pool de mineração.",
                path=path,
                evidence=evidence_for(content, MINER),
            )
        )
    return findings


def _is_script(path: str) -> bool:
    lowered = path.lower()
    name = lowered.rsplit("/", 1)[-1]
    if name in _SCRIPT_FILES or name in _INSTALL_JS:
        return True
    parts = lowered.split("/")
    in_scope = len(parts) == 1 or parts[0] == "scripts"
    return in_scope and name.endswith(_SCRIPT_NAMES + _JS_NAMES)


def _one_per_rule(findings: list[RawFinding]) -> list[RawFinding]:
    seen: set[str] = set()
    unique: list[RawFinding] = []
    for finding in findings:
        if finding.rule_id in seen:
            continue
        seen.add(finding.rule_id)
        unique.append(finding)
    return unique


def clean_script(text: str) -> str:
    from repoguard.rules.common import clean_snippet

    return clean_snippet(text, 0, min(len(text), 120))
