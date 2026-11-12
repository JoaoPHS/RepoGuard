"""Nomes de anexos das releases. O arquivo em si não é baixado."""

from __future__ import annotations

import re

from repoguard.models import RawFinding, Snapshot
from repoguard.rules.common import human_join
from repoguard.timeutil import age_days

_ASSET = re.compile(r"\.(exe|scr|msi|iso|img|dmg)$", re.IGNORECASE)
_YOUNG_RELEASE_DAYS = 90


def check(snapshot: Snapshot) -> list[RawFinding]:
    flagged = [name for name in snapshot.release_assets if _ASSET.search(name)]
    if not flagged:
        return []
    age = age_days(snapshot.created_at, snapshot.now)
    severity = "high" if age is not None and age < _YOUNG_RELEASE_DAYS else "medium"
    shown = flagged[:8]
    return [
        RawFinding(
            rule_id="release.binario_anexo",
            severity=severity,
            title="Anexo executável na release",
            detail=(
                "A release lista executável ou imagem de disco. O arquivo não foi baixado: "
                f"{human_join(shown)}."
            ),
            evidence=flagged[0],
        )
    ]
