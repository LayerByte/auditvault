from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

from . import database
from .exporter import export_events
from .importer import import_events, seed_events
from .models import DEFAULT_DB_PATH, EVENT_STATUSES, SEVERITY_LEVELS
from .reports import print_event_table, print_rows, print_statistics
from .validators import (
    ValidationError,
    validate_event_payload,
    validate_query_filters,
    validate_status,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditvault",
        description="AuditVault security event database CLI.",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help="Path to the SQLite database file. Default: auditvault.db",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init", help="Create or update the SQLite database schema.")
    subparsers.add_parser("seed", help="Insert safe fictional sample events.")
    subparsers.add_parser("stats", help="Show dashboard statistics.")
    subparsers.add_parser("sources", help="List event sources.")
    subparsers.add_parser("tags", help="List tags.")
    subparsers.add_parser("inspect", help="Inspect tables, indexes, and database metadata.")

    add_parser = subparsers.add_parser("add", help="Add one security event.")
    add_parser.add_argument("--timestamp", help="Event time, e.g. 2026-09-14 10:30:00")
    add_parser.add_argument("--severity", choices=SEVERITY_LEVELS, required=True)
    add_parser.add_argument("--category", required=True)
    add_parser.add_argument("--source", default="Manual Entry")
    add_parser.add_argument("--source-type", default="Manual Entry")
    add_parser.add_argument("--source-description", default="")
    add_parser.add_argument("--title", required=True)
    add_parser.add_argument("--description", default="")
    add_parser.add_argument("--ip-address", "--ip")
    add_parser.add_argument("--hostname")
    add_parser.add_argument("--username")
    add_parser.add_argument("--status", choices=EVENT_STATUSES, default="OPEN")
    add_parser.add_argument("--tags", default="", help="Comma-separated tags.")

    list_parser = subparsers.add_parser("list", help="List recent events.")
    add_filter_arguments(list_parser)

    search_parser = subparsers.add_parser("search", help="Search text fields with SQL LIKE.")
    search_parser.add_argument("--text", required=True)
    add_filter_arguments(search_parser, include_text=False)

    filter_parser = subparsers.add_parser("filter", help="Filter events by structured fields.")
    add_filter_arguments(filter_parser)

    import_parser = subparsers.add_parser("import", help="Import events from CSV or JSON.")
    import_parser.add_argument("path", type=Path)

    export_parser = subparsers.add_parser("export", help="Export query results to CSV or JSON.")
    export_parser.add_argument("path", type=Path)
    add_filter_arguments(export_parser)

    event_parser = subparsers.add_parser("event", help="Show one event by ID.")
    event_parser.add_argument("id", type=int)

    status_parser = subparsers.add_parser("status", help="Update event status.")
    status_parser.add_argument("id", type=int)
    status_parser.add_argument("status", choices=EVENT_STATUSES)

    delete_parser = subparsers.add_parser("delete", help="Delete one local event record.")
    delete_parser.add_argument("id", type=int)
    delete_parser.add_argument("--yes", action="store_true", help="Confirm deletion.")

    return parser


def add_filter_arguments(parser: argparse.ArgumentParser, *, include_text: bool = True) -> None:
    if include_text:
        parser.add_argument("--text")
    parser.add_argument("--severity", choices=SEVERITY_LEVELS)
    parser.add_argument("--status", choices=EVENT_STATUSES)
    parser.add_argument("--category")
    parser.add_argument("--ip", dest="ip_address")
    parser.add_argument("--hostname")
    parser.add_argument("--username")
    parser.add_argument("--tag")
    parser.add_argument("--from-date")
    parser.add_argument("--to-date")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--offset", type=int, default=0)


def filters_from_args(args: argparse.Namespace, *, text: str | None = None):
    return validate_query_filters(
        text=text if text is not None else getattr(args, "text", None),
        severity=getattr(args, "severity", None),
        status=getattr(args, "status", None),
        category=getattr(args, "category", None),
        ip_address=getattr(args, "ip_address", None),
        hostname=getattr(args, "hostname", None),
        username=getattr(args, "username", None),
        tag=getattr(args, "tag", None),
        from_date=getattr(args, "from_date", None),
        to_date=getattr(args, "to_date", None),
        limit=getattr(args, "limit", 50),
        offset=getattr(args, "offset", 0),
    )


def handle_import_result(result: dict[str, int | list[str]]) -> None:
    print(f"Records read: {result['read']}")
    print(f"Inserted: {result['inserted']}")
    print(f"Duplicates skipped: {result['duplicates']}")
    print(f"Invalid records: {result['invalid']}")
    for error in result["errors"]:
        print(f"- {error}")


def show_event(db_path: Path, event_id: int) -> int:
    row = database.get_event(db_path, event_id)
    if row is None:
        print(f"Event {event_id} was not found.")
        return 1
    for key in row.keys():
        print(f"{key}: {row[key]}")
    return 0


def inspect_database(db_path: Path) -> None:
    metadata = database.inspect_database(db_path)
    print("Tables")
    print_rows(metadata["tables"], ["name"])
    print("\nIndexes")
    print_rows(metadata["indexes"], ["tbl_name", "name"])
    print(f"\nTagged events via subquery: {metadata['tagged_events']}")


def run(args: argparse.Namespace) -> int:
    db_path = args.db

    if args.command == "init":
        database.initialize_database(db_path)
        print(f"Initialized database: {db_path}")
        return 0

    if args.command == "seed":
        result = seed_events(db_path)
        handle_import_result(result)
        return 0

    database.ensure_database(db_path)

    if args.command == "add":
        event = validate_event_payload(vars(args))
        inserted, event_id = database.add_event(db_path, event)
        if inserted:
            print(f"Added event {event_id}.")
        else:
            print(f"Duplicate event skipped; existing event id: {event_id}.")
        return 0

    if args.command == "list":
        rows = database.query_events(db_path, filters_from_args(args))
        print_event_table(rows)
        return 0

    if args.command == "search":
        rows = database.query_events(db_path, filters_from_args(args, text=args.text))
        print_event_table(rows)
        return 0

    if args.command == "filter":
        rows = database.query_events(db_path, filters_from_args(args))
        print_event_table(rows)
        return 0

    if args.command == "stats":
        print_statistics(db_path)
        return 0

    if args.command == "sources":
        print_rows(database.list_sources(db_path), ["id", "name", "type", "event_count"])
        return 0

    if args.command == "tags":
        print_rows(database.list_tags(db_path), ["id", "name", "event_count"])
        return 0

    if args.command == "inspect":
        inspect_database(db_path)
        return 0

    if args.command == "import":
        result = import_events(db_path, args.path)
        handle_import_result(result)
        return 0

    if args.command == "export":
        count = export_events(db_path, args.path, filters_from_args(args))
        print(f"Exported {count} event(s) to {args.path}.")
        return 0

    if args.command == "event":
        return show_event(db_path, args.id)

    if args.command == "status":
        status = validate_status(args.status)
        if database.update_event_status(db_path, args.id, status):
            print(f"Event {args.id} status updated to {status}.")
            return 0
        print(f"Event {args.id} was not found.")
        return 1

    if args.command == "delete":
        if not args.yes:
            print("Deletion requires --yes to avoid accidental record removal.")
            return 1
        if database.delete_event(db_path, args.id):
            print(f"Deleted event {args.id}.")
            return 0
        print(f"Event {args.id} was not found.")
        return 1

    raise ValidationError(f"Unknown command: {args.command}")


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return run(args)
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        return 130
    except ValidationError as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    except sqlite3.DatabaseError as exc:
        print(f"Database error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
