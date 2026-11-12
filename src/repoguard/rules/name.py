"""Nomes que misturam alfabetos, escondem caracteres ou imitam projetos conhecidos."""

from __future__ import annotations

import json

from repoguard.models import RawFinding, Snapshot
from repoguard.rules.common import clean_snippet

_POPULAR = frozenset(
    {
        "lodash",
        "express",
        "webpack",
        "axios",
        "requests",
        "django",
        "flask",
        "numpy",
        "pandas",
        "pillow",
        "electron",
        "typescript",
        "angular",
        "colors",
        "mongodb",
        "postgres",
        "redis",
        "kubernetes",
        "terraform",
        "ansible",
        "nodejs",
        "reactjs",
        "nextjs",
        "vitejs",
        "fakerjs",
    }
)

_INVISIBLE = frozenset(
    {
        "\u200b",
        "\u200c",
        "\u200d",
        "\u2060",
        "\ufeff",
        "\u202a",
        "\u202b",
        "\u202c",
        "\u202d",
        "\u202e",
        "\u2066",
        "\u2067",
        "\u2068",
        "\u2069",
    }
)


def check(snapshot: Snapshot) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for label, value in (("dono", snapshot.owner), ("repositório", snapshot.repo)):
        if any(char in _INVISIBLE for char in value):
            findings.append(
                RawFinding(
                    rule_id="nome.caractere_invisivel",
                    severity="high",
                    title="Caractere invisível no nome",
                    detail=(
                        f"O nome do {label} contém um caractere invisível ou de controle de direção."
                    ),
                    evidence=clean_snippet(value),
                )
            )
        if _mixed_scripts(value):
            findings.append(
                RawFinding(
                    rule_id="nome.homoglifo",
                    severity="high",
                    title="Mistura de alfabetos no nome",
                    detail=(
                        f"O nome do {label} mistura letras latinas com letras de outro alfabeto, "
                        "um truque comum para imitar nomes conhecidos."
                    ),
                    evidence=clean_snippet(value),
                )
            )
    seen: set[str] = set()
    for label, value in (("repositório", snapshot.repo), ("pacote", _package_name(snapshot))):
        if not value:
            continue
        popular = _typosquat_of(value)
        if popular is None or popular in seen:
            continue
        seen.add(popular)
        findings.append(
            RawFinding(
                rule_id="nome.typosquat",
                severity="high",
                title="Nome parecido com um projeto conhecido",
                detail=(
                    f"O nome do {label} difere pouco de {popular}, "
                    "um nome muito copiado por pacotes falsos."
                ),
                evidence=clean_snippet(value),
            )
        )
    return findings


def _package_name(snapshot: Snapshot) -> str:
    content = snapshot.files.get("package.json")
    if not content:
        return ""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return ""
    if not isinstance(data, dict) or not isinstance(data.get("name"), str):
        return ""
    return data["name"].rsplit("/", 1)[-1]


def _typosquat_of(name: str) -> str | None:
    folded = "".join(char for char in name.lower() if char.isalnum())
    if len(folded) < 6 or folded in _POPULAR:
        return None
    for popular in _POPULAR:
        same_length = len(folded) == len(popular)
        if same_length and (_hamming(folded, popular) == 1 or _adjacent_swap(folded, popular)):
            return popular
        if _extra_duplicate(folded, popular):
            return popular
    return None


def _hamming(left: str, right: str) -> int:
    return sum(char_left != char_right for char_left, char_right in zip(left, right, strict=True))


def _adjacent_swap(name: str, popular: str) -> bool:
    chars = list(name)
    for index in range(len(chars) - 1):
        chars[index], chars[index + 1] = chars[index + 1], chars[index]
        if "".join(chars) == popular:
            return True
        chars[index], chars[index + 1] = chars[index + 1], chars[index]
    return False


def _extra_duplicate(name: str, popular: str) -> bool:
    if len(name) != len(popular) + 1:
        return False
    for index, char in enumerate(name):
        neighbor = ""
        if index > 0:
            neighbor = name[index - 1]
        elif index + 1 < len(name):
            neighbor = name[index + 1]
        if char != neighbor:
            continue
        if name[:index] + name[index + 1 :] == popular:
            return True
    return False


def _mixed_scripts(text: str) -> bool:
    latin = False
    other = False
    for char in text:
        if char.isascii() and char.isalpha():
            latin = True
        code = ord(char)
        if 0x0400 <= code <= 0x052F or 0x0370 <= code <= 0x03FF:
            other = True
    return latin and other
