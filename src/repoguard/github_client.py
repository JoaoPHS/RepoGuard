"""Cliente da API REST do GitHub. Não segue host fora de api.github.com."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

from repoguard.errors import RepoGuardError
from repoguard.limits import MAX_FILE_BYTES

API_VERSION = "2022-11-28"
USER_AGENT = "RepoGuard"
Transport = Callable[[str, dict[str, str]], tuple[int, dict[str, str], bytes]]


class GitHubClient:
    def __init__(
        self,
        token: str | None = None,
        transport: Transport | None = None,
        base_url: str = "https://api.github.com",
    ) -> None:
        cleaned = token.strip() if isinstance(token, str) else ""
        self._token = cleaned or None
        self._transport = transport or urllib_transport
        self._base = base_url.rstrip("/")

    def get_repo(self, owner: str, repo: str) -> dict[str, Any]:
        status, headers, data = self._exchange(f"/repos/{_seg(owner)}/{_seg(repo)}")
        if status == 404:
            raise RepoGuardError(f"Repositório não encontrado ou sem acesso: {owner}/{repo}.")
        self._ensure_ok(status, headers, data)
        if not isinstance(data, dict):
            raise RepoGuardError("A API do GitHub devolveu um repositório inválido.")
        return data

    def get_owner(self, login: str, kind: str) -> dict[str, Any] | None:
        prefix = "/orgs/" if kind == "Organization" else "/users/"
        status, headers, data = self._exchange(prefix + _seg(login))
        if status == 404:
            return None
        self._ensure_ok(status, headers, data)
        return data if isinstance(data, dict) else None

    def get_commits(self, owner: str, repo: str, ref: str) -> list[Any]:
        status, headers, data = self._exchange(
            f"/repos/{_seg(owner)}/{_seg(repo)}/commits",
            {"per_page": "5", "sha": ref},
        )
        if status == 409:
            return []
        if status == 404:
            raise RepoGuardError(f"A referência {ref} não existe em {owner}/{repo}.")
        self._ensure_ok(status, headers, data)
        return data if isinstance(data, list) else []

    def get_releases(self, owner: str, repo: str) -> list[Any]:
        status, headers, data = self._exchange(
            f"/repos/{_seg(owner)}/{_seg(repo)}/releases",
            {"per_page": "5"},
        )
        if status in {404, 409}:
            return []
        self._ensure_ok(status, headers, data)
        return data if isinstance(data, list) else []

    def get_tree(self, owner: str, repo: str, ref: str) -> tuple[list[Any], bool]:
        status, headers, data = self._exchange(
            f"/repos/{_seg(owner)}/{_seg(repo)}/git/trees/{_seg(ref)}",
            {"recursive": "1"},
        )
        if status == 409:
            return [], False
        if status == 404:
            raise RepoGuardError(f"A referência {ref} não existe em {owner}/{repo}.")
        self._ensure_ok(status, headers, data)
        if not isinstance(data, dict):
            return [], False
        tree = data.get("tree")
        if not isinstance(tree, list):
            tree = []
        return tree, bool(data.get("truncated"))

    def get_text_file(self, owner: str, repo: str, path: str, ref: str) -> str | None:
        status, headers, data = self._exchange(
            f"/repos/{_seg(owner)}/{_seg(repo)}/contents/{urllib.parse.quote(path, safe='/')}",
            {"ref": ref},
        )
        if status in {404, 409}:
            return None
        if status == 403 and not _is_rate_limit(status, headers, data):
            return None
        self._ensure_ok(status, headers, data)
        return _decode_file(data)

    def _exchange(
        self,
        path: str,
        query: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], Any]:
        url = self._base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": API_VERSION,
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            status, raw_headers, body = self._transport(url, headers)
        except RepoGuardError:
            raise
        except Exception as exc:
            raise RepoGuardError("Não foi possível falar com a API do GitHub.") from exc
        normalized = {str(key).lower(): str(value) for key, value in raw_headers.items()}
        parsed: Any = None
        if body.strip():
            try:
                parsed = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                if status < 400:
                    raise RepoGuardError("A API do GitHub devolveu uma resposta que não é JSON.")
        return status, normalized, parsed

    def _ensure_ok(self, status: int, headers: dict[str, str], data: Any) -> None:
        if status < 400:
            return
        message = ""
        if isinstance(data, dict) and isinstance(data.get("message"), str):
            message = data["message"]
        if _is_rate_limit(status, headers, data):
            raise RepoGuardError(
                "Limite de requisições da API do GitHub atingido. Defina GITHUB_TOKEN ou aguarde."
            )
        if status == 401:
            raise RepoGuardError("Token do GitHub rejeitado. Verifique a variável GITHUB_TOKEN.")
        if status == 404:
            raise RepoGuardError("Recurso não encontrado ou sem acesso.")
        if message and len(message) < 180 and "token" not in message.lower():
            raise RepoGuardError(f"A API do GitHub respondeu HTTP {status}: {message}")
        raise RepoGuardError(f"A API do GitHub respondeu HTTP {status}.")


def urllib_transport(url: str, headers: dict[str, str]) -> tuple[int, dict[str, str], bytes]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "api.github.com":
        raise RepoGuardError("A consulta foi bloqueada porque o destino não é a API do GitHub.")
    request = urllib.request.Request(url, headers=headers, method="GET")
    opener = urllib.request.build_opener(_GitHubRedirect)
    try:
        with opener.open(request, timeout=30) as response:
            payload = response.read()
            response_headers = {key.lower(): value for key, value in response.headers.items()}
            return response.status, response_headers, payload
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        response_headers = {}
        if exc.headers is not None:
            response_headers = {key.lower(): value for key, value in exc.headers.items()}
        return exc.code, response_headers, payload
    except urllib.error.URLError as exc:
        raise RepoGuardError("Não foi possível falar com a API do GitHub.") from exc


class _GitHubRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname != "api.github.com":
            raise RepoGuardError("A API do GitHub redirecionou para um host inesperado.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _seg(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def _is_rate_limit(status: int, headers: dict[str, str], data: Any) -> bool:
    if status not in {403, 429}:
        return False
    remaining = headers.get("x-ratelimit-remaining")
    message = ""
    if isinstance(data, dict) and isinstance(data.get("message"), str):
        message = data["message"].lower()
    return str(remaining) == "0" or "rate limit" in message or "too many requests" in message


def _decode_file(data: Any) -> str | None:
    if not isinstance(data, dict) or data.get("type") not in {None, "file"}:
        return None
    size = data.get("size")
    if isinstance(size, int) and size > MAX_FILE_BYTES:
        return None
    if data.get("encoding") != "base64" or not isinstance(data.get("content"), str):
        return None
    try:
        raw = _b64decode(data["content"])
    except ValueError:
        return None
    if len(raw) > MAX_FILE_BYTES or b"\x00" in raw:
        return None
    return raw.decode("utf-8", errors="replace")


def _b64decode(value: str) -> bytes:
    import base64

    return base64.b64decode(value, validate=False)
