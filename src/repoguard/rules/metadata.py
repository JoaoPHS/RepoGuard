"""Sinais de idade, histórico, fork, licença e arquivo morto."""

from __future__ import annotations

from repoguard.models import RawFinding, Snapshot
from repoguard.timeutil import age_days, days_phrase

REPO_YOUNG_DAYS = 14
OWNER_YOUNG_DAYS = 30


def check(snapshot: Snapshot) -> list[RawFinding]:
    findings: list[RawFinding] = []
    repo_age = age_days(snapshot.created_at, snapshot.now)
    if repo_age is not None and repo_age < REPO_YOUNG_DAYS:
        findings.append(
            RawFinding(
                rule_id="meta.repo_muito_novo",
                severity="low",
                title="Repositório muito recente",
                detail=(
                    f"O repositório foi criado há {days_phrase(repo_age)}. "
                    "Isso, sozinho, não indica intenção maliciosa."
                ),
            )
        )

    owner_age = age_days(snapshot.owner_created_at, snapshot.now)
    if owner_age is not None and owner_age < OWNER_YOUNG_DAYS:
        findings.append(
            RawFinding(
                rule_id="meta.owner_muito_novo",
                severity="medium",
                title="Conta do dono muito recente",
                detail=f"A conta que publica o repositório foi criada há {days_phrase(owner_age)}.",
                dampable=True,
            )
        )

    if snapshot.commit_count == 0:
        findings.append(
            RawFinding(
                rule_id="meta.repositorio_vazio",
                severity="info",
                title="Repositório sem commits",
                detail="Não há commits no branch consultado.",
            )
        )
    elif snapshot.commit_count == 1:
        findings.append(
            RawFinding(
                rule_id="meta.um_unico_commit",
                severity="low",
                title="Um único commit",
                detail="O histórico consultado tem um único commit.",
            )
        )

    if snapshot.is_fork:
        findings.append(
            RawFinding(
                rule_id="meta.fork",
                severity="info",
                title="O repositório é um fork",
                detail="O conteúdo pode ter sido alterado em relação à origem.",
            )
        )
    if not snapshot.license_spdx:
        findings.append(
            RawFinding(
                rule_id="meta.sem_licenca",
                severity="info",
                title="Sem licença declarada",
                detail="A API do GitHub não informa uma licença SPDX.",
            )
        )
    if snapshot.archived:
        findings.append(
            RawFinding(
                rule_id="meta.arquivado",
                severity="info",
                title="Repositório arquivado",
                detail="O repositório está arquivado. Isso não elimina sinais de risco no conteúdo.",
            )
        )
    return findings
