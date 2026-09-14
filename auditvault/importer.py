from __future__ import annotations

import csv
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .database import connect, ensure_database, insert_event
from .models import DEFAULT_DB_PATH
from .validators import ValidationError, validate_event_payload


def _load_records(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open("r", encoding="utf-8", newline="") as file:
            return list(csv.DictReader(file))
    if suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "events" in data:
            data = data["events"]
        if not isinstance(data, list):
            raise ValidationError("JSON import must contain a list of event objects.")
        return [dict(record) for record in data]
    raise ValidationError("import supports only .csv and .json files.")


def import_events(db_path: Path, input_path: Path) -> dict[str, int | list[str]]:
    ensure_database(db_path)
    if not input_path.exists():
        raise ValidationError(f"input file not found: {input_path}")

    records = _load_records(input_path)
    result: dict[str, int | list[str]] = {
        "read": len(records),
        "inserted": 0,
        "duplicates": 0,
        "invalid": 0,
        "errors": [],
    }

    with connect(db_path) as connection:
        for line_number, raw_record in enumerate(records, start=2):
            try:
                event = validate_event_payload(raw_record)
                with connection:
                    inserted, _event_id = insert_event(connection, event)
                if inserted:
                    result["inserted"] += 1
                else:
                    result["duplicates"] += 1
            except (ValidationError, sqlite3.DatabaseError) as exc:
                connection.rollback()
                result["invalid"] += 1
                result["errors"].append(f"record {line_number}: {exc}")

    return result


def seed_events(db_path: Path = DEFAULT_DB_PATH) -> dict[str, int | list[str]]:
    """Generate fictional defensive sample events."""

    now = datetime.now().replace(microsecond=0)
    samples = [
        {
            "timestamp": (now - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "HIGH",
            "category": "authentication",
            "source": "Windows Event Log",
            "title": "Multiple Failed Logins",
            "description": "Several failed authentication attempts were recorded for a local workstation.",
            "ip_address": "192.168.1.20",
            "hostname": "WS-04",
            "username": "student.user",
            "status": "OPEN",
            "tags": "authentication,windows",
        },
        {
            "timestamp": (now - timedelta(hours=5)).strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "MEDIUM",
            "category": "account",
            "source": "Windows Event Log",
            "title": "Account Lockout",
            "description": "A fictional local account was locked after repeated failed sign-in attempts.",
            "ip_address": "192.168.1.21",
            "hostname": "WS-05",
            "username": "demo.account",
            "status": "INVESTIGATING",
            "tags": "account,authentication",
        },
        {
            "timestamp": (now - timedelta(days=1, hours=2)).strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "LOW",
            "category": "network",
            "source": "Firewall",
            "title": "Firewall Connection Blocked",
            "description": "A denied inbound connection was logged by the firewall.",
            "ip_address": "10.10.0.15",
            "hostname": "FW-EDGE",
            "status": "RESOLVED",
            "tags": "firewall,network",
        },
        {
            "timestamp": (now - timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "CRITICAL",
            "category": "malware-detection",
            "source": "IDS",
            "title": "Suspicious File Detected",
            "description": "A fictional suspicious file indicator was detected in a lab directory.",
            "ip_address": "192.168.1.32",
            "hostname": "SRV-02",
            "username": "service.demo",
            "status": "OPEN",
            "tags": "ids,file-integrity",
        },
        {
            "timestamp": (now - timedelta(days=8)).strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "INFO",
            "category": "configuration",
            "source": "Application",
            "title": "Configuration Changed",
            "description": "Application configuration was changed during an approved maintenance window.",
            "hostname": "APP-01",
            "username": "admin.demo",
            "status": "RESOLVED",
            "tags": "configuration,change-management",
        },
        {
            "timestamp": (now - timedelta(days=12)).strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "INFO",
            "category": "operations",
            "source": "Application",
            "title": "Service Restarted",
            "description": "A monitored service restarted successfully after a scheduled update.",
            "hostname": "APP-02",
            "status": "RESOLVED",
            "tags": "operations,service",
        },
        {
            "timestamp": (now - timedelta(days=20)).strftime("%Y-%m-%d %H:%M:%S"),
            "severity": "MEDIUM",
            "category": "certificate",
            "source": "Web Server",
            "title": "Certificate Nearing Expiration",
            "description": "A fictional TLS certificate is nearing expiration and should be reviewed.",
            "hostname": "WEB-01",
            "status": "OPEN",
            "tags": "tls,certificate",
        },
    ]

    result: dict[str, int | list[str]] = {
        "read": len(samples),
        "inserted": 0,
        "duplicates": 0,
        "invalid": 0,
        "errors": [],
    }

    ensure_database(db_path)
    with connect(db_path) as connection:
        for record in samples:
            try:
                event = validate_event_payload(record)
                with connection:
                    inserted, _event_id = insert_event(connection, event)
                if inserted:
                    result["inserted"] += 1
                else:
                    result["duplicates"] += 1
            except (ValidationError, sqlite3.DatabaseError) as exc:
                connection.rollback()
                result["invalid"] += 1
                result["errors"].append(str(exc))

    return result
