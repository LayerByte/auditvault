from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any

from .models import EVENT_STATUSES, SEVERITY_LEVELS, EventRecord, QueryFilters


class ValidationError(ValueError):
    """Raised when user-provided data cannot be safely accepted."""


def normalize_text(value: Any, field_name: str, *, required: bool = False) -> str:
    """Return a trimmed string and enforce required fields."""

    if value is None:
        if required:
            raise ValidationError(f"{field_name} is required.")
        return ""

    text = str(value).strip()
    if required and not text:
        raise ValidationError(f"{field_name} is required.")
    return text


def normalize_optional_text(value: Any) -> str | None:
    """Normalize optional text fields to either a string or None."""

    text = normalize_text(value, "value")
    return text or None


def validate_severity(value: Any) -> str:
    severity = normalize_text(value, "severity", required=True).upper()
    if severity not in SEVERITY_LEVELS:
        allowed = ", ".join(SEVERITY_LEVELS)
        raise ValidationError(f"severity must be one of: {allowed}.")
    return severity


def validate_status(value: Any) -> str:
    status = normalize_text(value, "status", required=True).upper()
    if status not in EVENT_STATUSES:
        allowed = ", ".join(EVENT_STATUSES)
        raise ValidationError(f"status must be one of: {allowed}.")
    return status


def validate_date_or_datetime(value: Any, field_name: str) -> str:
    """Accept YYYY-MM-DD or ISO-like datetime input and return a normalized value."""

    text = normalize_text(value, field_name, required=True)
    formats = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d")

    for fmt in formats:
        try:
            parsed = datetime.strptime(text, fmt)
            if fmt == "%Y-%m-%d":
                return parsed.strftime("%Y-%m-%d")
            return parsed.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue

    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValidationError(
            f"{field_name} must be a date or datetime such as 2026-09-14 "
            "or 2026-09-14 10:30:00."
        ) from exc

    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def normalize_range_start(value: Any, field_name: str) -> str:
    """Normalize a date range start to the beginning of a day when needed."""

    text = validate_date_or_datetime(value, field_name)
    if len(text) == 10:
        return f"{text} 00:00:00"
    return text


def normalize_range_end(value: Any, field_name: str) -> str:
    """Normalize a date range end to the end of a day when needed."""

    text = validate_date_or_datetime(value, field_name)
    if len(text) == 10:
        return f"{text} 23:59:59"
    return text


def validate_ip_address(value: Any) -> str | None:
    text = normalize_optional_text(value)
    if text is None:
        return None

    try:
        ipaddress.ip_address(text)
    except ValueError as exc:
        raise ValidationError(f"ip_address is not valid: {text}") from exc

    return text


def validate_tag(value: Any) -> str:
    tag = normalize_text(value, "tag", required=True).lower()
    if len(tag) > 64:
        raise ValidationError("tag must be 64 characters or fewer.")
    if not all(char.isalnum() or char in {"-", "_", "."} for char in tag):
        raise ValidationError("tag may contain only letters, numbers, hyphen, underscore, or dot.")
    return tag


def parse_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        raw_tags = value
    else:
        raw_tags = str(value).replace(";", ",").split(",")

    tags: list[str] = []
    seen: set[str] = set()
    for raw_tag in raw_tags:
        if str(raw_tag).strip() == "":
            continue
        tag = validate_tag(raw_tag)
        if tag not in seen:
            tags.append(tag)
            seen.add(tag)
    return tags


def validate_event_payload(data: dict[str, Any]) -> EventRecord:
    """Validate one imported or CLI-created event record."""

    timestamp_value = data.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    source_name = normalize_text(
        data.get("source") or data.get("source_name") or "Manual Entry",
        "source",
        required=True,
    )

    return EventRecord(
        timestamp=validate_date_or_datetime(timestamp_value, "timestamp"),
        severity=validate_severity(data.get("severity") or "INFO"),
        category=normalize_text(data.get("category"), "category", required=True).lower(),
        source_name=source_name,
        source_type=normalize_text(data.get("source_type") or source_name, "source_type"),
        source_description=normalize_text(data.get("source_description") or "", "source_description"),
        title=normalize_text(data.get("title"), "title", required=True),
        description=normalize_text(data.get("description") or "", "description"),
        ip_address=validate_ip_address(data.get("ip_address") or data.get("ip")),
        hostname=normalize_optional_text(data.get("hostname")),
        username=normalize_optional_text(data.get("username")),
        status=validate_status(data.get("status") or "OPEN"),
        tags=parse_tags(data.get("tags")),
    )


def validate_query_filters(
    *,
    text: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    category: str | None = None,
    ip_address: str | None = None,
    hostname: str | None = None,
    username: str | None = None,
    tag: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> QueryFilters:
    """Validate search/filter arguments before they are used in parameterized SQL."""

    if limit < 1 or limit > 1000:
        raise ValidationError("limit must be between 1 and 1000.")
    if offset < 0:
        raise ValidationError("offset cannot be negative.")

    return QueryFilters(
        text=normalize_optional_text(text),
        severity=validate_severity(severity) if severity else None,
        status=validate_status(status) if status else None,
        category=normalize_optional_text(category.lower() if category else None),
        ip_address=validate_ip_address(ip_address),
        hostname=normalize_optional_text(hostname),
        username=normalize_optional_text(username),
        tag=validate_tag(tag) if tag else None,
        from_date=normalize_range_start(from_date, "from_date") if from_date else None,
        to_date=normalize_range_end(to_date, "to_date") if to_date else None,
        limit=limit,
        offset=offset,
    )
