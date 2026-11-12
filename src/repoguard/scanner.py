"""Orquestra a leitura remota e devolve o relatório."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Protocol

from repoguard.errors import RepoGuardError
from repoguard.github_client import GitHubClient
from repoguard.limits import MAX_FILE_BYTES, MAX_FILES, MAX_TREE_ENTRIES
from repoguard.models import ScanReport, Snapshot, TreeEntry
from repoguard.rules import collect
from repoguard.scoring import finalize
from repoguard.timeutil import age_days, parse_github_time
from repoguard.urls import parse_target

_EXACT_NAMES = {
    "package.json",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "pipfile",
    "makefile",
    "justfile",
    "dockerfile",
    "action.yml",
    "action.yaml",
    ".npmrc",
    ".yarnrc",
    "docker-compose.yml",
    "docker-compose.yaml",
}
_SCRIPT_SUFFIXES = (".sh", ".ps1", ".bat", ".cmd")
_JS_SUFFIXES = (".js", ".mjs", ".cjs")
_INSTALL_JS = {"install.js", "preinstall.js", "postinstall.js", "setup.js"}
_KEY_NAMES = {"id_rsa", "id_ed25519", "id_dsa"}
_KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx")


class RepoSource(Protocol):
    def get_repo(self, owner: str, repo: str) -> dict[str, Any]: ...

    def get_owner(self, login: str, kind: str) -> dict[str, Any] | None: ...

    def get_commits(self, owner: str, repo: str, ref: str) -> list[Any]: ...

    def get_releases(self, owner: str, repo: str) -> list[Any]: ...

    def get_tree(self, owner: str, repo: str, ref: str) -> tuple[list[Any], bool]: ...

    def get_text_file(self, owner: str, repo: str, path: str, ref: str) -> str | None: ...


def scan(
    target: str,
    *,
    ref: str | None = None,
    token: str | None = None,
    client: RepoSource | None = None,
    now: datetime | None = None,
) -> ScanReport:
    """Avalia um repositório do GitHub sem clonar e sem executar código."""

    moment = _clock(now)
    parsed = parse_target(target)
    source = client if client is not None else GitHubClient(token=_token(token))
    repo = source.get_repo(parsed.owner, parsed.repo)
    chosen = _choose_ref(ref, parsed.ref, repo, parsed.full_name)
    owner_doc = _owner_doc(source, repo, parsed.owner)
    commits = source.get_commits(parsed.owner, parsed.repo, chosen)
    releases = source.get_releases(parsed.owner, parsed.repo)
    raw_tree, truncated = source.get_tree(parsed.owner, parsed.repo, chosen)
    entries, truncated = _entries(raw_tree, truncated)
    to_fetch, skipped = select_risk_files(entries)
    files: dict[str, str] = {}
    for path in to_fetch:
        text = source.get_text_file(parsed.owner, parsed.repo, path, chosen)
        if text is not None:
            files[path] = text

    snapshot = Snapshot(
        owner=parsed.owner,
        repo=parsed.repo,
        html_url=_html_url(repo, parsed.owner, parsed.repo),
        ref=chosen,
        created_at=parse_github_time(repo.get("created_at")),
        stars=_as_int(repo.get("stargazers_count")),
        forks=_as_int(repo.get("forks_count")),
        is_fork=bool(repo.get("fork")),
        archived=bool(repo.get("archived")),
        license_spdx=_license(repo),
        owner_created_at=parse_github_time(owner_doc.get("created_at")) if owner_doc else None,
        commit_count=None if len(commits) >= 5 else len(commits),
        tree_truncated=truncated,
        entries=tuple(entries),
        files=files,
        skipped_large=tuple(skipped),
        release_assets=tuple(_asset_names(releases)),
        now=moment,
    )
    findings, score, verdict = finalize(collect(snapshot), snapshot)
    return ScanReport(
        repo=parsed.full_name,
        html_url=snapshot.html_url,
        ref=chosen,
        verdict=verdict,
        risk_score=score,
        findings=findings,
        stats=_stats(snapshot),
    )


def select_risk_files(
    entries: list[TreeEntry] | tuple[TreeEntry, ...],
    limit: int = MAX_FILES,
) -> tuple[list[str], list[str]]:
    """Escolhe até `limit` conteúdos e separa os arquivos grandes demais."""

    chosen = [entry for entry in entries if entry.kind == "blob" and is_risk_file(entry.path)]
    chosen.sort(key=lambda entry: _priority(entry.path))
    to_fetch: list[str] = []
    skipped: list[str] = []
    for entry in chosen:
        if entry.size is not None and entry.size > MAX_FILE_BYTES:
            skipped.append(entry.path)
            continue
        if len(to_fetch) >= limit:
            continue
        to_fetch.append(entry.path)
    return to_fetch, skipped


def is_risk_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    lowered = path.lower()
    if lowered.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
        return True
    if name in _EXACT_NAMES or name.startswith("readme"):
        return True
    if name.startswith("requirements") and name.endswith(".txt"):
        return True
    if name in _INSTALL_JS or name in _KEY_NAMES or name.endswith(_KEY_SUFFIXES):
        return True
    if name == ".env" or (name.startswith(".env.") and "example" not in name and "sample" not in name):
        return True
    parts = lowered.split("/")
    in_scope = len(parts) == 1 or parts[0] == "scripts"
    return in_scope and name.endswith(_SCRIPT_SUFFIXES + _JS_SUFFIXES)


def _priority(path: str) -> tuple[int, str]:
    name = path.rsplit("/", 1)[-1].lower()
    lowered = path.lower()
    if lowered.startswith(".github/workflows/"):
        rank = 0
    elif name in {"package.json", "setup.py", "pyproject.toml"} or name in _INSTALL_JS | _KEY_NAMES:
        rank = 1
    elif name.endswith(_KEY_SUFFIXES) or name == ".env" or name.startswith(".env."):
        rank = 1
    elif name.endswith(_SCRIPT_SUFFIXES):
        rank = 2
    elif name.startswith("requirements") or name in {
        "dockerfile",
        "makefile",
        "pipfile",
        "setup.cfg",
        "justfile",
    }:
        rank = 3
    elif name.startswith("readme"):
        rank = 4
    else:
        rank = 5
    return (rank, lowered)


def _entries(raw_tree: list[Any], truncated: bool) -> tuple[list[TreeEntry], bool]:
    entries: list[TreeEntry] = []
    for item in raw_tree:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            continue
        if len(entries) >= MAX_TREE_ENTRIES:
            return entries, True
        size = item.get("size")
        entries.append(
            TreeEntry(
                path=item["path"],
                kind=str(item.get("type") or ""),
                size=size if isinstance(size, int) and size >= 0 else None,
            )
        )
    return entries, truncated


def _asset_names(releases: list[Any]) -> list[str]:
    names: list[str] = []
    for release in releases:
        if not isinstance(release, dict) or not isinstance(release.get("assets"), list):
            continue
        for asset in release["assets"]:
            if isinstance(asset, dict) and isinstance(asset.get("name"), str):
                names.append(asset["name"])
    return names


def _owner_doc(source: RepoSource, repo: dict[str, Any], login: str) -> dict[str, Any] | None:
    owner = repo.get("owner") if isinstance(repo.get("owner"), dict) else {}
    kind = owner.get("type") if isinstance(owner.get("type"), str) else "User"
    return source.get_owner(login, kind)


def _choose_ref(explicit: str | None, from_url: str | None, repo: dict[str, Any], full_name: str) -> str:
    if explicit is not None:
        chosen = explicit.strip()
        if not chosen:
            raise RepoGuardError("A referência informada em --ref está vazia.")
    elif from_url:
        chosen = from_url
    else:
        default = repo.get("default_branch")
        if not isinstance(default, str) or not default.strip():
            raise RepoGuardError(f"O repositório {full_name} não tem branch padrão. Informe --ref.")
        chosen = default.strip()
    if any(char.isspace() for char in chosen) or len(chosen) > 255:
        raise RepoGuardError("A referência do Git não pode conter espaço.")
    return chosen


def _html_url(repo: dict[str, Any], owner: str, name: str) -> str:
    html = repo.get("html_url")
    if isinstance(html, str) and html.startswith("https://github.com/"):
        return html
    return f"https://github.com/{owner}/{name}"


def _license(repo: dict[str, Any]) -> str | None:
    info = repo.get("license")
    if not isinstance(info, dict):
        return None
    spdx = info.get("spdx_id")
    if isinstance(spdx, str) and spdx and spdx != "NOASSERTION":
        return spdx
    return None


def _stats(snapshot: Snapshot) -> dict[str, Any]:
    return {
        "stars": snapshot.stars,
        "forks": snapshot.forks,
        "age_days": age_days(snapshot.created_at, snapshot.now),
        "owner_age_days": age_days(snapshot.owner_created_at, snapshot.now),
        "commit_count": snapshot.commit_count,
        "archived": snapshot.archived,
        "fork": snapshot.is_fork,
        "license": snapshot.license_spdx,
        "tree_entries": len(snapshot.entries),
        "tree_truncated": snapshot.tree_truncated,
        "files_read": len(snapshot.files),
        "files_skipped_large": list(snapshot.skipped_large),
        "release_assets": len(snapshot.release_assets),
    }


def _token(token: str | None) -> str | None:
    if token is not None:
        cleaned = token.strip()
        return cleaned or None
    env = os.environ.get("GITHUB_TOKEN")
    if isinstance(env, str) and env.strip():
        return env.strip()
    return None


def _clock(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now


def _as_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)
