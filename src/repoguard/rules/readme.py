"""O que o README pede para a pessoa fazer antes mesmo de clonar."""

from __future__ import annotations

import re

from repoguard.models import RawFinding, Snapshot
from repoguard.rules.common import CURL_PIPE, evidence_for

_DISABLE = re.compile(
    r"(?:deslig\w*|desativ\w*|disable|turn\s+off|desative)[^\n]{0,80}"
    r"(?:antiv[ií]rus|antivirus|windows\s+defender|defender|smartscreen|gatekeeper)"
    r"|(?:antiv[ií]rus|antivirus|windows\s+defender|smartscreen|gatekeeper)[^\n]{0,60}"
    r"(?:deslig\w*|desativ\w*|disable|turn\s+off)",
    re.IGNORECASE,
)
_PASTE = re.compile(
    r"(?:cole|colar|paste|insira)[^\n]{0,80}(?:token|segredo|secret|personal access)"
    r"|(?:token|segredo|personal access token)[^\n]{0,60}(?:cole|colar|paste)",
    re.IGNORECASE,
)


def check(snapshot: Snapshot) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for path, content in snapshot.files.items():
        if not path.rsplit("/", 1)[-1].lower().startswith("readme"):
            continue
        if CURL_PIPE.search(content):
            findings.append(
                RawFinding(
                    rule_id="readme.curl_pipe_shell",
                    severity="medium",
                    title="Instalação por curl encaminhado ao shell",
                    detail="O README pede para baixar um script remoto e executá-lo no shell.",
                    path=path,
                    evidence=evidence_for(content, CURL_PIPE),
                    dampable=True,
                    escalate_when_young=True,
                )
            )
        if _DISABLE.search(content):
            findings.append(
                RawFinding(
                    rule_id="readme.desligar_protecao",
                    severity="high",
                    title="Pedido para desligar proteção",
                    detail="O README pede para desativar antivírus, Defender, SmartScreen ou Gatekeeper.",
                    path=path,
                    evidence=evidence_for(content, _DISABLE),
                )
            )
        if _PASTE.search(content):
            findings.append(
                RawFinding(
                    rule_id="readme.pedido_token",
                    severity="high",
                    title="Pedido para colar um token",
                    detail="O README pede para colar um token ou segredo.",
                    path=path,
                    evidence=evidence_for(content, _PASTE),
                )
            )
    return findings
