from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any

from .models import DEFAULT_DB_PATH, DEFAULT_SOURCES, EventRecord, QueryFilters


SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema.sql"


def connect(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open a SQLite connection with foreign keys and Row access enabled."""

    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(db_path: Path = DEFAULT_DB_PATH) -> None:
    """Create tables, indexes, constraints, and default sources."""

    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    with connect(db_path) as connection:
        connection.executescript(schema)
        connection.executemany(
            """
            INSERT OR IGNORE INTO sources (name, type, description)
            VALUES (?, ?, ?)
            """,
            DEFAULT_SOURCES,
        )
        connection.commit()


def ensure_database(db_path: Path = DEFAULT_DB_PATH) -> None:
    if not db_path.exists():
        initialize_database(db_path)


def compute_event_hash(event: EventRecord) -> str:
    """Create a deterministic fingerprint for duplicate detection."""

    parts = (
        event.timestamp,
        event.severity,
        event.category,
        event.source_name,
        event.title,
        event.description,
        event.ip_address or "",
        event.hostname or "",
        event.username or "",
    )
    joined = "\u241f".join(parts)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def get_or_create_source(connection: sqlite3.Connection, event: EventRecord) -> int:
    connection.execute(
        """
        INSERT OR IGNORE INTO sources (name, type, description)
        VALUES (?, ?, ?)
        """,
        (event.source_name, event.source_type or event.source_name, event.source_description),
    )
    row = connection.execute(
        "SELECT id FROM sources WHERE name = ?",
        (event.source_name,),
    ).fetchone()
    if row is None:
        raise sqlite3.DatabaseError("source lookup failed after insert.")
    return int(row["id"])


def get_or_create_tag(connection: sqlite3.Connection, tag_name: str) -> int:
    connection.execute(
        "INSERT OR IGNORE INTO tags (name) VALUES (?)",
        (tag_name,),
    )
    row = connection.execute(
        "SELECT id FROM tags WHERE name = ?",
        (tag_name,),
    ).fetchone()
    if row is None:
        raise sqlite3.DatabaseError("tag lookup failed after insert.")
    return int(row["id"])


def insert_event(connection: sqlite3.Connection, event: EventRecord) -> tuple[bool, int | None]:
    """Insert an event and its tags. Returns (inserted, event_id)."""

    source_id = get_or_create_source(connection, event)
    event_hash = compute_event_hash(event)

    try:
        cursor = connection.execute(
            """
            INSERT INTO events (
                timestamp, severity, category, source_id, title, description,
                ip_address, hostname, username, status, hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.timestamp,
                event.severity,
                event.category,
                source_id,
                event.title,
                event.description,
                event.ip_address,
                event.hostname,
                event.username,
                event.status,
                event_hash,
            ),
        )
    except sqlite3.IntegrityError as exc:
        if "UNIQUE constraint failed: events.hash" in str(exc):
            existing = connection.execute(
                "SELECT id FROM events WHERE hash = ?",
                (event_hash,),
            ).fetchone()
            return False, int(existing["id"]) if existing else None
        raise

    event_id = int(cursor.lastrowid)
    for tag in event.tags:
        tag_id = get_or_create_tag(connection, tag)
        connection.execute(
            """
            INSERT OR IGNORE INTO event_tags (event_id, tag_id)
            VALUES (?, ?)
            """,
            (event_id, tag_id),
        )

    return True, event_id


def add_event(db_path: Path, event: EventRecord) -> tuple[bool, int | None]:
    ensure_database(db_path)
    with connect(db_path) as connection:
        try:
            with connection:
                return insert_event(connection, event)
        except sqlite3.DatabaseError:
            connection.rollback()
            raise


def build_event_query(filters: QueryFilters) -> tuple[str, list[Any]]:
    """Build a safe SQL query from whitelisted filters and parameter values."""

    where: list[str] = []
    params: list[Any] = []

    if filters.text:
        like = f"%{filters.text}%"
        where.append(
            """
            (
                e.title LIKE ?
                OR e.description LIKE ?
                OR e.hostname LIKE ?
                OR e.username LIKE ?
                OR e.ip_address LIKE ?
                OR e.category LIKE ?
            )
            """
        )
        params.extend([like, like, like, like, like, like])

    if filters.severity:
        where.append("e.severity = ?")
        params.append(filters.severity)
    if filters.status:
        where.append("e.status = ?")
        params.append(filters.status)
    if filters.category:
        where.append("e.category = ?")
        params.append(filters.category)
    if filters.ip_address:
        where.append("e.ip_address = ?")
        params.append(filters.ip_address)
    if filters.hostname:
        where.append("e.hostname = ?")
        params.append(filters.hostname)
    if filters.username:
        where.append("e.username = ?")
        params.append(filters.username)
    if filters.tag:
        where.append(
            """
            e.id IN (
                SELECT et.event_id
                FROM event_tags AS et
                JOIN tags AS t ON t.id = et.tag_id
                WHERE t.name = ?
            )
            """
        )
        params.append(filters.tag)
    if filters.from_date and filters.to_date:
        where.append("e.timestamp BETWEEN ? AND ?")
        params.extend([filters.from_date, filters.to_date])
    elif filters.from_date:
        where.append("e.timestamp >= ?")
        params.append(filters.from_date)
    elif filters.to_date:
        where.append("e.timestamp <= ?")
        params.append(filters.to_date)

    where_clause = f"WHERE {' AND '.join(where)}" if where else ""
    params.extend([filters.limit, filters.offset])

    query = f"""
        SELECT
            e.id,
            e.timestamp,
            e.severity,
            e.category,
            s.name AS source,
            e.title,
            e.description,
            e.ip_address,
            e.hostname,
            e.username,
            e.status,
            e.created_at,
            COALESCE(GROUP_CONCAT(t.name, ', '), '') AS tags
        FROM events AS e
        JOIN sources AS s ON s.id = e.source_id
        LEFT JOIN event_tags AS et ON et.event_id = e.id
        LEFT JOIN tags AS t ON t.id = et.tag_id
        {where_clause}
        GROUP BY e.id
        ORDER BY e.timestamp DESC, e.id DESC
        LIMIT ? OFFSET ?
    """
    return query, params


def query_events(db_path: Path, filters: QueryFilters) -> list[sqlite3.Row]:
    ensure_database(db_path)
    query, params = build_event_query(filters)
    with connect(db_path) as connection:
        return list(connection.execute(query, params).fetchall())


def get_event(db_path: Path, event_id: int) -> sqlite3.Row | None:
    ensure_database(db_path)
    with connect(db_path) as connection:
        return connection.execute(
            """
            SELECT
                e.*,
                s.name AS source,
                s.type AS source_type,
                COALESCE(GROUP_CONCAT(t.name, ', '), '') AS tags
            FROM events AS e
            JOIN sources AS s ON s.id = e.source_id
            LEFT JOIN event_tags AS et ON et.event_id = e.id
            LEFT JOIN tags AS t ON t.id = et.tag_id
            WHERE e.id = ?
            GROUP BY e.id
            """,
            (event_id,),
        ).fetchone()


def update_event_status(db_path: Path, event_id: int, status: str) -> bool:
    ensure_database(db_path)
    with connect(db_path) as connection:
        with connection:
            cursor = connection.execute(
                "UPDATE events SET status = ? WHERE id = ?",
                (status, event_id),
            )
            return cursor.rowcount > 0


def delete_event(db_path: Path, event_id: int) -> bool:
    """Delete one local event record and its tag links through ON DELETE CASCADE."""

    ensure_database(db_path)
    with connect(db_path) as connection:
        with connection:
            cursor = connection.execute(
                "DELETE FROM events WHERE id = ?",
                (event_id,),
            )
            return cursor.rowcount > 0


def list_sources(db_path: Path) -> list[sqlite3.Row]:
    ensure_database(db_path)
    with connect(db_path) as connection:
        return list(
            connection.execute(
                """
                SELECT s.id, s.name, s.type, s.description, COUNT(e.id) AS event_count
                FROM sources AS s
                LEFT JOIN events AS e ON e.source_id = s.id
                GROUP BY s.id
                ORDER BY s.name
                """
            ).fetchall()
        )


def list_tags(db_path: Path) -> list[sqlite3.Row]:
    ensure_database(db_path)
    with connect(db_path) as connection:
        return list(
            connection.execute(
                """
                SELECT t.id, t.name, COUNT(et.event_id) AS event_count
                FROM tags AS t
                LEFT JOIN event_tags AS et ON et.tag_id = t.id
                GROUP BY t.id
                HAVING COUNT(et.event_id) >= 0
                ORDER BY event_count DESC, t.name
                """
            ).fetchall()
        )


def inspect_database(db_path: Path) -> dict[str, Any]:
    ensure_database(db_path)
    with connect(db_path) as connection:
        tables = list(
            connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                  AND name NOT LIKE 'sqlite_%'
                ORDER BY name
                """
            ).fetchall()
        )
        indexes = list(
            connection.execute(
                """
                SELECT name, tbl_name
                FROM sqlite_master
                WHERE type = 'index'
                  AND name NOT LIKE 'sqlite_%'
                ORDER BY tbl_name, name
                """
            ).fetchall()
        )
        tagged_events = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM events
            WHERE id IN (SELECT DISTINCT event_id FROM event_tags)
            """
        ).fetchone()["count"]

        return {
            "tables": tables,
            "indexes": indexes,
            "tagged_events": tagged_events,
        }
