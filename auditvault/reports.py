from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .database import connect, ensure_database
from .models import DEFAULT_DB_PATH


def print_rows(rows: Iterable, columns: list[str]) -> None:
    rows = list(rows)
    if not rows:
        print("No records found.")
        return

    widths = {
        column: max(len(column), *(len(str(row[column] or "")) for row in rows))
        for column in columns
    }
    header = "  ".join(column.upper().ljust(widths[column]) for column in columns)
    print(header)
    print("-" * len(header))
    for row in rows:
        print("  ".join(str(row[column] or "").ljust(widths[column]) for column in columns))


def print_event_table(rows: Iterable) -> None:
    print_rows(
        rows,
        ["id", "timestamp", "severity", "status", "hostname", "ip_address", "title"],
    )


def statistics(db_path: Path = DEFAULT_DB_PATH) -> dict[str, object]:
    ensure_database(db_path)
    with connect(db_path) as connection:
        total = connection.execute("SELECT COUNT(*) AS count FROM events").fetchone()["count"]
        open_count = connection.execute(
            "SELECT COUNT(*) AS count FROM events WHERE status = ?",
            ("OPEN",),
        ).fetchone()["count"]
        critical_count = connection.execute(
            "SELECT COUNT(*) AS count FROM events WHERE severity = ?",
            ("CRITICAL",),
        ).fetchone()["count"]

        grouped_queries = {
            "severity": """
                SELECT severity AS label, COUNT(*) AS count
                FROM events
                GROUP BY severity
                ORDER BY count DESC
            """,
            "category": """
                SELECT category AS label, COUNT(*) AS count
                FROM events
                GROUP BY category
                HAVING COUNT(*) > 0
                ORDER BY count DESC
                LIMIT 10
            """,
            "status": """
                SELECT status AS label, COUNT(*) AS count
                FROM events
                GROUP BY status
                ORDER BY count DESC
            """,
            "source": """
                SELECT s.name AS label, COUNT(e.id) AS count
                FROM sources AS s
                LEFT JOIN events AS e ON e.source_id = s.id
                GROUP BY s.id
                HAVING COUNT(e.id) > 0
                ORDER BY count DESC
            """,
            "top_ips": """
                SELECT ip_address AS label, COUNT(*) AS count
                FROM events
                WHERE ip_address IS NOT NULL
                GROUP BY ip_address
                ORDER BY count DESC
                LIMIT 10
            """,
            "top_hostnames": """
                SELECT hostname AS label, COUNT(*) AS count
                FROM events
                WHERE hostname IS NOT NULL
                GROUP BY hostname
                ORDER BY count DESC
                LIMIT 10
            """,
            "tags": """
                SELECT t.name AS label, COUNT(et.event_id) AS count
                FROM tags AS t
                JOIN event_tags AS et ON et.tag_id = t.id
                GROUP BY t.id
                ORDER BY count DESC, t.name
                LIMIT 10
            """,
            "avg_description_length": """
                SELECT severity AS label, ROUND(AVG(LENGTH(description)), 1) AS count
                FROM events
                GROUP BY severity
                ORDER BY severity
            """,
        }

        groups = {
            key: list(connection.execute(sql).fetchall())
            for key, sql in grouped_queries.items()
        }

        windows = {}
        for label, modifier in (
            ("last_24_hours", "-1 day"),
            ("last_7_days", "-7 days"),
            ("last_30_days", "-30 days"),
        ):
            windows[label] = connection.execute(
                """
                SELECT COUNT(*) AS count
                FROM events
                WHERE datetime(timestamp) BETWEEN datetime('now', ?) AND datetime('now')
                """,
                (modifier,),
            ).fetchone()["count"]

        recent_critical = list(
            connection.execute(
                """
                SELECT e.id, e.timestamp, e.hostname, e.title
                FROM events AS e
                WHERE e.severity = ?
                ORDER BY e.timestamp DESC
                LIMIT 5
                """,
                ("CRITICAL",),
            ).fetchall()
        )

    return {
        "total": total,
        "open": open_count,
        "critical": critical_count,
        "groups": groups,
        "windows": windows,
        "recent_critical": recent_critical,
    }


def print_statistics(db_path: Path = DEFAULT_DB_PATH) -> None:
    data = statistics(db_path)
    print("AUDITVAULT SECURITY DATABASE")
    print()
    print(f"Total Events: {data['total']}")
    print(f"Open: {data['open']}")
    print(f"Critical: {data['critical']}")

    labels = (
        ("severity", "Severity"),
        ("category", "Top Categories"),
        ("status", "Status"),
        ("source", "Sources"),
        ("top_ips", "Top IP Addresses"),
        ("top_hostnames", "Top Hostnames"),
        ("tags", "Most Common Tags"),
        ("avg_description_length", "Average Description Length by Severity"),
    )

    for key, title in labels:
        print(f"\n## {title}")
        rows = data["groups"][key]
        if not rows:
            print("No data.")
            continue
        for row in rows:
            print(f"{str(row['label']):<24} {row['count']}")

    print("\n## Time Windows")
    for label, count in data["windows"].items():
        print(f"{label.replace('_', ' ').title():<24} {count}")

    print("\n## Recent Critical Events")
    if not data["recent_critical"]:
        print("No critical events found.")
    else:
        print_rows(data["recent_critical"], ["id", "timestamp", "hostname", "title"])
