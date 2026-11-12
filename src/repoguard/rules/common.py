"""Trechos curtos e padrões compartilhados. O texto do repositório não vira comando de terminal."""

from __future__ import annotations

import re

from repoguard.limits import EVIDENCE_LIMIT

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
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

CURL_PIPE = re.compile(
    r"(?:curl|wget|Invoke-WebRequest|\biwr\b)"
    r"[^\n|]{0,400}\|\s*(?:sudo\s+)?(?:(?:ba)?sh|zsh|dash|powershell|pwsh|iex|Invoke-Expression)\b",
    re.IGNORECASE,
)

BASE64_EXEC = re.compile(
    r"base64(?:\s+-d|\s+--decode)[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:(?:ba)?sh|zsh|dash|powershell|pwsh)\b"
    r"|FromBase64String[\s\S]{0,240}Invoke-Expression"
    r"|Buffer\.from\s*\([^)]{0,160}base64[^)]{0,40}\)[\s\S]{0,200}\b(?:eval|exec|Function)\s*\("
    r"|\batob\s*\([^)]{0,200}\)[\s\S]{0,200}\b(?:eval|Function)\s*\(",
    re.IGNORECASE,
)

EXFIL = re.compile(
    r"webhook\.site|transfer\.sh|ngrok(?:-free)?\.(?:io|app)|"
    r"interact\.sh|oast\.fun|oastify\.com|burpcollaborator\.net|"
    r"pipedream\.net|requestbin\.com|canarytokens\.com",
    re.IGNORECASE,
)
OBFUSCATED = re.compile(
    r"fromCharCode[\s\S]{0,200}\b(?:eval|Function)\s*\("
    r"|\b(?:eval|Function)\s*\([\s\S]{0,200}fromCharCode"
    r"|(?:-enc(?:odedcommand)?)\s+[A-Za-z0-9+/=]{24,}",
    re.IGNORECASE,
)
SHELL_CHANNEL = re.compile(r"/dev/tcp/", re.IGNORECASE)
MINER = re.compile(r"\bxmrig\b|stratum\+tcp://", re.IGNORECASE)
PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----",
    re.IGNORECASE,
)

HOOK_NET = re.compile(
    r"\bcurl\b|\bwget\b|Invoke-WebRequest|\biwr\b|\bfetch\s*\(|\baxios\b|"
    r"\bXMLHttpRequest\b|\burllib\b|\bWebClient\b|DownloadString|https?://",
    re.IGNORECASE,
)


def clean_snippet(text: str, start: int = 0, end: int | None = None, limit: int = EVIDENCE_LIMIT) -> str:
    if end is None:
        end = min(len(text), start + 80)
    window_start = max(0, start - 40)
    window_end = min(len(text), max(end, start) + 40)
    raw = _neutralize(text[window_start:window_end])
    raw = re.sub(r"\s+", " ", raw).strip()
    if len(raw) > limit:
        return raw[: limit - 3] + "..."
    return raw


def _neutralize(text: str) -> str:
    text = ANSI.sub("", text)
    chars: list[str] = []
    for char in text:
        code = ord(char)
        if char in "\n\r\t":
            chars.append(" ")
        elif code < 32 or code == 127 or char in _INVISIBLE:
            chars.append(f"\\u{code:04x}")
        else:
            chars.append(char)
    return "".join(chars)


def evidence_for(text: str, pattern: re.Pattern[str]) -> str | None:
    match = pattern.search(text)
    if match is None:
        return None
    snippet = clean_snippet(text, match.start(), match.end())
    return snippet or None


def human_join(items: list[str]) -> str:
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " e " + items[-1]


def listed(items: list[str], limit: int = 8) -> str:
    shown = items[:limit]
    text = ", ".join(shown)
    extra = len(items) - len(shown)
    if extra:
        text += f" e mais {extra}"
    return text
