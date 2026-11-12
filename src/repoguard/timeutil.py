"""Idades usadas na reputação e nos textos do relatório."""

from __future__ import annotations

from datetime import datetime, timezone


def parse_github_time(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def age_days(moment: datetime | None, now: datetime) -> int | None:
    if moment is None:
        return None
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return max(0, (now - moment).days)


def days_phrase(age: int) -> str:
    if age == 1:
        return "1 dia"
    return f"{age} dias"
