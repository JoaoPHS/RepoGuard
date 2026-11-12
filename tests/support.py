"""Apoio dos testes. Nenhum teste fala com a rede."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from repoguard.models import Snapshot, TreeEntry

FIXTURES = Path(__file__).parent / "fixtures"
NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)


def load_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def load_json(name: str) -> Any:
    return json.loads(load_fixture(name))


def make_snapshot(**overrides: Any) -> Snapshot:
    base: dict[str, Any] = {
        "owner": "acme",
        "repo": "widget",
        "html_url": "https://github.com/acme/widget",
        "ref": "main",
        "created_at": datetime(2020, 1, 1, tzinfo=timezone.utc),
        "stars": 100,
        "forks": 2,
        "is_fork": False,
        "archived": False,
        "license_spdx": "MIT",
        "owner_created_at": datetime(2018, 5, 1, tzinfo=timezone.utc),
        "commit_count": 12,
        "tree_truncated": False,
        "entries": (),
        "files": {},
        "skipped_large": (),
        "release_assets": (),
        "now": NOW,
    }
    base.update(overrides)
    if isinstance(base["entries"], list):
        base["entries"] = tuple(base["entries"])
    if isinstance(base["skipped_large"], list):
        base["skipped_large"] = tuple(base["skipped_large"])
    if isinstance(base["release_assets"], list):
        base["release_assets"] = tuple(base["release_assets"])
    return Snapshot(**base)


def blob(path: str, size: int = 20) -> TreeEntry:
    return TreeEntry(path=path, kind="blob", size=size)


def scripted(routes: dict[str, tuple[int, Any]], calls: list[str] | None = None):
    def transport(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
        path = urlparse(url).path
        if calls is not None:
            calls.append(path)
        if path not in routes:
            body = b'{"message":"Not Found"}'
            return 404, {"content-type": "application/json"}, body
        status, payload = routes[path]
        if isinstance(payload, bytes):
            body = payload
        else:
            body = json.dumps(payload).encode("utf-8")
        return status, {"content-type": "application/json"}, body

    return transport
