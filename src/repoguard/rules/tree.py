"""Sinais que aparecem só pelo nome e pelo tamanho dos arquivos."""

from __future__ import annotations

import re

from repoguard.models import RawFinding, Snapshot
from repoguard.rules.common import listed

_BINARY = (".exe", ".scr", ".msi", ".dll", ".hta", ".vbs", ".iso")
_DOUBLE = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|txt|jpg|jpeg|png|gif|mp4|mp3)\.(exe|scr|js|vbs|bat|cmd|ps1)$",
    re.IGNORECASE,
)


def check(snapshot: Snapshot) -> list[RawFinding]:
    findings: list[RawFinding] = []
    if snapshot.tree_truncated:
        findings.append(
            RawFinding(
                rule_id="tree.truncada",
                severity="medium",
                title="Árvore de arquivos incompleta",
                detail=(
                    "A API do GitHub não devolveu a árvore inteira. "
                    "Arquivos fora dessa resposta não foram analisados."
                ),
            )
        )

    binaries: list[str] = []
    doubles: list[str] = []
    disguised: list[str] = []
    for entry in snapshot.entries:
        if entry.kind != "blob":
            continue
        name = entry.path.rsplit("/", 1)[-1]
        lowered = name.lower()
        if lowered.endswith(_BINARY) or lowered.endswith(".apk"):
            binaries.append(entry.path)
        if _DOUBLE.search(name):
            doubles.append(entry.path)
        if any(char in entry.path for char in ("\u202e", "\u200b", "\u200c", "\u200d", "\u2060")):
            disguised.append(entry.path)

    if binaries:
        findings.append(
            RawFinding(
                rule_id="tree.binario_executavel",
                severity="high",
                title="Executável ou imagem versionados",
                detail=f"Há arquivo executável ou imagem de disco no código versionado: {listed(binaries)}.",
                path=binaries[0],
            )
        )
    if doubles:
        findings.append(
            RawFinding(
                rule_id="tree.extensao_dupla",
                severity="high",
                title="Extensão dupla",
                detail=(
                    "Há arquivo cujo nome imita um documento e termina em executável ou script: "
                    f"{listed(doubles)}."
                ),
                path=doubles[0],
            )
        )
    if disguised:
        findings.append(
            RawFinding(
                rule_id="tree.nome_disfarcado",
                severity="high",
                title="Nome de arquivo disfarçado",
                detail=(
                    "Há arquivo com caractere invisível ou inversão de texto no caminho: "
                    f"{listed(disguised)}."
                ),
                path=disguised[0],
            )
        )
    if snapshot.skipped_large:
        paths = list(snapshot.skipped_large)
        findings.append(
            RawFinding(
                rule_id="tree.arquivo_grande_nao_lido",
                severity="low",
                title="Arquivo grande não inspecionado",
                detail=(
                    "Arquivos de risco acima de 100 mil bytes não tiveram o conteúdo lido: "
                    f"{listed(paths)}."
                ),
                path=paths[0],
            )
        )
    return findings
