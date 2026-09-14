from __future__ import annotations

import csv
import json
from pathlib import Path

from .database import query_events
from .models import QueryFilters
from .validators import ValidationError


def export_events(db_path: Path, output_path: Path, filters: QueryFilters) -> int:
    rows = query_events(db_path, filters)
    suffix = output_path.suffix.lower()

    if suffix == ".csv":
        with output_path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "id",
                    "timestamp",
                    "severity",
                    "category",
                    "source",
                    "title",
                    "description",
                    "ip_address",
                    "hostname",
                    "username",
                    "status",
                    "created_at",
                    "tags",
                ],
            )
            writer.writeheader()
            for row in rows:
                writer.writerow(dict(row))
        return len(rows)

    if suffix == ".json":
        output_path.write_text(
            json.dumps([dict(row) for row in rows], indent=2),
            encoding="utf-8",
        )
        return len(rows)

    raise ValidationError("export supports only .csv and .json files.")
