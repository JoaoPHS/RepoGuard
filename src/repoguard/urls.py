"""Interpreta URL do GitHub ou o atalho owner/repo."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from repoguard.errors import RepoGuardError

_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_GITHUB_HOSTS = {"github.com", "www.github.com"}
_REF_KINDS = {"tree", "blob", "commit"}


@dataclass(frozen=True)
class RepoTarget:
    owner: str
    repo: str
    ref: str | None = None

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"


def parse_target(value: str) -> RepoTarget:
    text = value.strip()
    if not text:
        raise RepoGuardError("Informe a URL ou o nome owner/repo do GitHub.")

    ref: str | None = None
    if text.startswith("git@"):
        if not text.startswith("git@github.com:"):
            raise RepoGuardError(
                "Só repositórios do GitHub são aceitos. A URL precisa ser github.com/owner/repo."
            )
        parts = [part for part in text.removeprefix("git@github.com:").split("/") if part]
    else:
        if "://" not in text and not _looks_like_host(text):
            parts = [part for part in text.split("/") if part]
            return _finish(parts, None, text)
        if "://" not in text:
            text = "https://" + text
        parsed = urlparse(text)
        if parsed.username or parsed.password:
            raise RepoGuardError("A URL não pode conter usuário ou senha.")
        host = (parsed.hostname or "").lower()
        if host not in _GITHUB_HOSTS:
            raise RepoGuardError(
                "Só repositórios do GitHub são aceitos. A URL precisa ser github.com/owner/repo."
            )
        parts = [part for part in parsed.path.split("/") if part]

    if parts and parts[-1].endswith(".git"):
        parts[-1] = parts[-1][: -len(".git")]

    if len(parts) >= 4 and parts[2] in _REF_KINDS:
        ref = parts[3]
        parts = parts[:2]
    elif len(parts) > 2:
        parts = parts[:2]

    return _finish(parts, ref, value.strip())


def _looks_like_host(text: str) -> bool:
    lowered = text.lower()
    return lowered.startswith("github.com/") or lowered.startswith("www.github.com/")


def _finish(parts: list[str], ref: str | None, original: str) -> RepoTarget:
    if len(parts) != 2:
        raise RepoGuardError(f"URL inválida: {original}")
    owner, repo = parts
    if not _valid_name(owner) or not _valid_name(repo):
        raise RepoGuardError(f"URL inválida: {original}")
    if ref is not None and (not ref or any(char.isspace() for char in ref) or len(ref) > 255):
        raise RepoGuardError(f"URL inválida: {original}")
    return RepoTarget(owner=owner, repo=repo, ref=ref)


def _valid_name(name: str) -> bool:
    if not 1 <= len(name) <= 100:
        return False
    if ".." in name or name.startswith("-") or name.endswith("."):
        return False
    return _NAME.fullmatch(name) is not None
