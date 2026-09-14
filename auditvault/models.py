from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


APP_NAME = "AuditVault"
DEFAULT_DB_PATH = Path("auditvault.db")

SEVERITY_LEVELS = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
EVENT_STATUSES = ("OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE")

DEFAULT_SOURCES = (
    ("Windows Event Log", "Windows Event Log", "Operating system audit and event records."),
    ("Firewall", "Firewall", "Network firewall events and connection decisions."),
    ("Web Server", "Web Server", "HTTP access, application gateway, or reverse proxy events."),
    ("Application", "Application", "Application-level operational and security events."),
    ("IDS", "IDS", "Intrusion detection system alerts for defensive review."),
    ("Manual Entry", "Manual Entry", "User-entered security event records."),
)


@dataclass(frozen=True)
class EventRecord:
    """Validated event data ready for database insertion."""

    timestamp: str
    severity: str
    category: str
    source_name: str
    source_type: str
    source_description: str
    title: str
    description: str = ""
    ip_address: str | None = None
    hostname: str | None = None
    username: str | None = None
    status: str = "OPEN"
    tags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class QueryFilters:
    """Optional filters for list, export, and search commands."""

    text: str | None = None
    severity: str | None = None
    status: str | None = None
    category: str | None = None
    ip_address: str | None = None
    hostname: str | None = None
    username: str | None = None
    tag: str | None = None
    from_date: str | None = None
    to_date: str | None = None
    limit: int = 50
    offset: int = 0
