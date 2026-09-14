# AuditVault

AuditVault is a clean Python and SQLite project for storing, searching, filtering, and reporting fictional security audit events.

School Purpose Only.

## Overview

AuditVault is built as an educational defensive security database project. It gives students a practical way to work with SQLite tables, relationships, constraints, safe queries, imports, exports, and command-line workflows.

The project is local-first. It does not scan networks, attack systems, collect credentials, brute force accounts, install persistence, or modify external services.

## Features

- Local SQLite database initialization
- Manual event creation from the command line
- CSV and JSON import support
- CSV and JSON export support
- Event search across common text fields
- Structured filtering by severity, status, category, IP address, hostname, username, tag, and date range
- Event status updates
- Duplicate detection with SHA-256 event fingerprints
- Dashboard-style statistics using SQL aggregation
- Database inspection for tables, indexes, and tagged-event metadata
- Input validation and readable error messages
- Explicit confirmation before deleting a local record

## Technologies

- Python 3
- SQLite
- Python standard library only
- `argparse`
- `sqlite3`
- `csv`
- `json`
- `pathlib`
- `hashlib`

## Database Schema

AuditVault creates a local `auditvault.db` file when the database is initialized.

Main tables:

- `events` stores audit events, severity, category, status, source, host, user, IP address, and event hash data.
- `sources` stores event source information.
- `tags` stores normalized tag names.
- `event_tags` connects events and tags with a many-to-many relationship.

The schema demonstrates primary keys, foreign keys, unique constraints, check constraints, default values, indexes, and join tables.

## SQL Concepts Demonstrated

- `CREATE TABLE`
- `INSERT`
- `SELECT`
- `UPDATE`
- `DELETE`
- `WHERE`
- `JOIN`
- `LEFT JOIN`
- `GROUP BY`
- `HAVING`
- `ORDER BY`
- `LIKE`
- `IN`
- `BETWEEN`
- `LIMIT`
- `OFFSET`
- Subqueries
- Transactions
- Parameterized queries
- Indexes

## Installation

Clone the repository:

```bash
git clone https://github.com/LayerByte/auditvault.git
cd auditvault
```

Check Python:

```bash
python --version
```

AuditVault does not require third-party packages.

## Usage

Initialize the database:

```bash
python main.py init
```

Import the included sample events:

```bash
python main.py import sample_data/events.csv
```

List recent events:

```bash
python main.py list
```

Show statistics:

```bash
python main.py stats
```

## CLI Commands

```text
init       Create or update the SQLite database schema
seed       Insert safe fictional sample events
add        Add one audit event
list       List recent events
search     Search text fields
filter     Filter events by structured fields
stats      Show summary statistics
sources    List event sources
tags       List event tags
inspect    Inspect database tables and indexes
import     Import events from CSV or JSON
export     Export events to CSV or JSON
event      Show one event by ID
status     Update an event status
delete     Delete one local event record
```

## Example Commands

Add an event:

```bash
python main.py add --severity HIGH --category authentication --title "Multiple Failed Logins" --hostname WS-04 --ip 192.168.1.20 --tags authentication,windows
```

Search events:

```bash
python main.py search --text "failed login"
```

Filter events:

```bash
python main.py filter --severity CRITICAL --status OPEN
python main.py filter --from-date 2026-01-01 --to-date 2026-12-31
python main.py filter --tag firewall
```

Update event status:

```bash
python main.py status 1 RESOLVED
```

Export a report:

```bash
python main.py export report.json --status OPEN
python main.py export high-events.csv --severity HIGH
```

Delete a local event record:

```bash
python main.py delete 1 --yes
```

## Importing Events

CSV and JSON imports support these fields:

- `timestamp`
- `severity`
- `category`
- `source`
- `source_type`
- `source_description`
- `title`
- `description`
- `ip_address`
- `hostname`
- `username`
- `status`
- `tags`

Each record is validated before it is saved. Invalid rows are reported, duplicates are skipped, and database writes use transactions.

## Searching and Filtering

Search uses safe parameterized SQL:

```bash
python main.py search --text "certificate"
```

Structured filters can be combined:

```bash
python main.py filter --severity HIGH --status OPEN --category authentication
```

Date filters accept dates or datetimes:

```bash
python main.py filter --from-date 2026-09-01 --to-date 2026-09-30
```

## Security

AuditVault is designed for defensive education and local analysis. User-controlled values are passed into SQL statements through parameters instead of direct string concatenation.

Example:

```python
connection.execute(
    "UPDATE events SET status = ? WHERE id = ?",
    (status, event_id),
)
```

The project validates severity values, status values, dates, IP addresses, tags, and imported event records before database operations.

## Limitations

- Not a SIEM, EDR, scanner, or monitoring agent.
- No remote collection or live event streaming.
- No authentication or multi-user access control.
- Designed for local educational datasets.
- Timestamps are stored as normalized text for simple SQLite analysis.

## Disclaimer

AuditVault is for school assignments, defensive learning, and authorized local analysis only. It does not include exploitation, password cracking, credential theft, malware, persistence, brute forcing, destructive behavior, or unauthorized access functionality.

## License

Released under the MIT License.
