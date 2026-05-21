"""
database/connection.py
----------------------
Manages the SQLite connection for the red-team pipeline.
Provides a context-manager wrapper and a one-shot migration runner
that applies schema.sql if the database is freshly created.
"""

import sqlite3
import os
from pathlib import Path
from typing import Optional, List, Union


# Default DB path sits at the project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = _PROJECT_ROOT / "redteam.db"
SCHEMA_PATH = _PROJECT_ROOT / "schema.sql"


class DatabaseConnection:
    """
    Lightweight SQLite connection wrapper.

    Usage (context manager):
        with DatabaseConnection() as db:
            db.execute("SELECT 1")

    Usage (manual):
        db = DatabaseConnection()
        db.connect()
        db.execute("SELECT 1")
        db.close()
    """

    def __init__(self, db_path: "Union[str, Path]" = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = None

    # ── Public interface ──────────────────────────────────────────────────────

    def connect(self):  # -> DatabaseConnection
        """Open connection and apply schema migrations if needed."""
        is_new = not self.db_path.exists()
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row          # rows behave like dicts
        self._conn.execute("PRAGMA foreign_keys = ON")
        if is_new:
            self._apply_schema()
        return self

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        self._ensure_connected()
        return self._conn.execute(sql, params)

    def executemany(self, sql: str, params_seq) -> sqlite3.Cursor:
        self._ensure_connected()
        return self._conn.executemany(sql, params_seq)

    def commit(self) -> None:
        self._ensure_connected()
        self._conn.commit()

    def fetchall(self, sql: str, params: tuple = ()) -> list:
        return self.execute(sql, params).fetchall()

    def fetchone(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        return self.execute(sql, params).fetchone()

    # ── Context manager ───────────────────────────────────────────────────────

    def __enter__(self):  # -> DatabaseConnection
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is None:
            self.commit()
        self.close()
        return False   # don't suppress exceptions

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _ensure_connected(self) -> None:
        if self._conn is None:
            raise RuntimeError(
                "DatabaseConnection is not open. "
                "Call connect() or use it as a context manager."
            )

    def _apply_schema(self) -> None:
        """Run schema.sql against a freshly created database."""
        if not SCHEMA_PATH.exists():
            raise FileNotFoundError(f"Schema file not found: {SCHEMA_PATH}")
        sql = SCHEMA_PATH.read_text()
        self._conn.executescript(sql)
        self._conn.commit()
        print(f"[db] Schema applied → {self.db_path}")
