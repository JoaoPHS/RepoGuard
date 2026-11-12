"""Referências a caminhos de credencial em script ou manifesto de instalação."""

from __future__ import annotations

import re

from repoguard.models import RawFinding, Snapshot
from repoguard.rules.common import PRIVATE_KEY, evidence_for
from repoguard.rules.install import _is_script, _lifecycle_scripts

_SECRET = re.compile(
    r"\.ssh/id_rsa|\.ssh/id_ed25519|\.ssh/authorized_keys|"
    r"\.aws/credentials|AWS_SECRET_ACCESS_KEY|AZURE_CLIENT_SECRET|"
    r"(?:cat|type|open|read|Get-Content|readFile|readFileSync)[^\n]{0,80}\.npmrc|"
    r"NPM_TOKEN|npm_token|Login Data|wallet\.dat",
    re.IGNORECASE,
)
_COMMITTED = re.compile(r"_authToken=|_auth\s*=", re.IGNORECASE)


def check(snapshot: Snapshot) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for path, content in snapshot.files.items():
        name = path.rsplit("/", 1)[-1].lower()
        if name.startswith("readme"):
            continue
        if _is_env_file(name) and content.strip():
            findings.append(
                RawFinding(
                    rule_id="segredo.arquivo_env",
                    severity="high",
                    title="Arquivo de ambiente versionado",
                    detail="Um .env com conteúdo foi publicado no repositório.",
                    path=path,
                )
            )
        if PRIVATE_KEY.search(content):
            findings.append(
                RawFinding(
                    rule_id="segredo.chave_privada",
                    severity="critical",
                    title="Chave privada no repositório",
                    detail="O arquivo contém o cabeçalho de uma chave privada.",
                    path=path,
                    evidence=evidence_for(content, PRIVATE_KEY),
                )
            )
        inspected = content
        if name == "package.json":
            inspected = "\n".join(_lifecycle_scripts(content).values())
            if not inspected:
                continue
        elif name in {".npmrc", ".yarnrc"} and _COMMITTED.search(content):
            findings.append(
                RawFinding(
                    rule_id="segredo.credencial_no_arquivo",
                    severity="high",
                    title="Credencial gravada no repositório",
                    detail="Um arquivo de configuração de pacote contém token de autenticação.",
                    path=path,
                    evidence=evidence_for(content, _COMMITTED),
                )
            )
            continue
        elif not (_is_script(path) or name == "setup.py"):
            continue
        if inspected and _SECRET.search(inspected):
            findings.append(
                RawFinding(
                    rule_id="segredo.leitura_caminho",
                    severity="critical",
                    title="Leitura de caminho de credencial",
                    detail=(
                        "O arquivo referencia caminho ou variável típicos de chave SSH, "
                        "credencial de nuvem, token do npm, carteira ou perfil de navegador."
                    ),
                    path=path,
                    evidence=evidence_for(inspected, _SECRET),
                )
            )
    return findings


def _is_env_file(name: str) -> bool:
    if "example" in name or "sample" in name:
        return False
    return name == ".env" or name.startswith(".env.")
