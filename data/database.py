from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any


DB_PATH = Path(__file__).resolve().parent / "audit_history.db"


def _database_url() -> str | None:
    return os.environ.get("DATABASE_URL")


def _is_postgres() -> bool:
    url = _database_url()
    return bool(url) and url.startswith(("postgres://", "postgresql://"))


def _ph(sql: str) -> str:
    """Adapte les marqueurs de parametres SQLite (?) au format PostgreSQL (%s)."""
    return sql.replace("?", "%s") if _is_postgres() else sql


def get_connection() -> Any:
    if _is_postgres():
        import psycopg
        from psycopg.rows import dict_row

        return psycopg.connect(_database_url(), row_factory=dict_row)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _insert_returning_id(conn: Any, sql: str, params: tuple) -> int:
    if _is_postgres():
        cursor = conn.execute(_ph(sql) + " RETURNING id", params)
        return int(cursor.fetchone()["id"])
    cursor = conn.execute(sql, params)
    return int(cursor.lastrowid)


def init_db() -> None:
    if _is_postgres():
        _init_db_postgres()
    else:
        _init_db_sqlite()


def _init_db_sqlite() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                os_type TEXT NOT NULL,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,
                score INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                failed INTEGER NOT NULL,
                total INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                expected TEXT NOT NULL,
                actual TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                raw_output TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES audit_runs(id)
            )
            """
        )
        # Migration : les bases creees avant le regroupement par categorie
        # n'ont pas la colonne.
        columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_results)")}
        if "category" not in columns:
            conn.execute(
                "ALTER TABLE audit_results ADD COLUMN category TEXT NOT NULL DEFAULT ''"
            )

        run_columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_runs)")}
        if "manual" not in run_columns:
            conn.execute("ALTER TABLE audit_runs ADD COLUMN manual INTEGER NOT NULL DEFAULT 0")
        # NULL pour les audits anterieurs au chronometrage.
        if "duration_seconds" not in run_columns:
            conn.execute("ALTER TABLE audit_runs ADD COLUMN duration_seconds REAL")
        if "profile" not in run_columns:
            conn.execute("ALTER TABLE audit_runs ADD COLUMN profile TEXT")
        if "errors" not in run_columns:
            conn.execute("ALTER TABLE audit_runs ADD COLUMN errors INTEGER NOT NULL DEFAULT 0")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rule_status (
                rule_id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1
            )
            """
        )


def _init_db_postgres() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_runs (
                id SERIAL PRIMARY KEY,
                os_type TEXT NOT NULL,
                target TEXT NOT NULL,
                started_at TEXT NOT NULL,
                score INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                failed INTEGER NOT NULL,
                total INTEGER NOT NULL,
                manual INTEGER NOT NULL DEFAULT 0,
                duration_seconds REAL,
                profile TEXT,
                errors INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        # Migration : les bases creees avant l'ajout de ces colonnes les gagnent ici.
        conn.execute("ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS manual INTEGER NOT NULL DEFAULT 0")
        conn.execute("ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS duration_seconds REAL")
        conn.execute("ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS profile TEXT")
        conn.execute("ALTER TABLE audit_runs ADD COLUMN IF NOT EXISTS errors INTEGER NOT NULL DEFAULT 0")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_results (
                id SERIAL PRIMARY KEY,
                run_id INTEGER NOT NULL REFERENCES audit_runs(id),
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT '',
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                expected TEXT NOT NULL,
                actual TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                raw_output TEXT NOT NULL
            )
            """
        )
        conn.execute("ALTER TABLE audit_results ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT ''")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rule_status (
                rule_id TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1
            )
            """
        )


def save_audit_run(
    os_type: str,
    target: str,
    results: list[dict[str, Any]],
    started_at: datetime,
    duration_seconds: float,
    profile: str | None = None,
) -> int:
    total = len(results)
    passed = sum(1 for item in results if item["status"] == "PASS")
    manual = sum(1 for item in results if item["status"] == "MANUAL")
    errors = sum(1 for item in results if item["status"] == "ERROR")
    failed = total - passed - manual - errors
    # Controles manuels et en erreur n'ont pas de verdict : ni pour ni contre.
    evaluated = passed + failed
    score = round((passed / evaluated) * 100) if evaluated else 0

    with get_connection() as conn:
        run_id = _insert_returning_id(
            conn,
            """
            INSERT INTO audit_runs (
                os_type, target, started_at, score, passed, failed, total,
                manual, duration_seconds, profile, errors
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                os_type,
                target,
                started_at.isoformat(timespec="seconds"),
                score,
                passed,
                failed,
                total,
                manual,
                round(duration_seconds, 2),
                profile,
                errors,
            ),
        )

        cursor = conn.cursor()
        cursor.executemany(
            _ph(
                """
                INSERT INTO audit_results (
                    run_id, rule_id, title, category, severity, status, expected,
                    actual, recommendation, raw_output
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
            ),
            [
                (
                    run_id,
                    item["rule_id"],
                    item["title"],
                    item.get("category", ""),
                    item["severity"],
                    item["status"],
                    item["expected"],
                    item["actual"],
                    item["recommendation"],
                    item["raw_output"],
                )
                for item in results
            ],
        )

    return run_id


def list_runs() -> list[Any]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM audit_runs ORDER BY started_at DESC, id DESC"
        ).fetchall()


def get_run(run_id: int) -> Any | None:
    with get_connection() as conn:
        return conn.execute(
            _ph("SELECT * FROM audit_runs WHERE id = ?"),
            (run_id,),
        ).fetchone()


def get_results(run_id: int) -> list[Any]:
    with get_connection() as conn:
        return conn.execute(
            _ph("SELECT * FROM audit_results WHERE run_id = ? ORDER BY id"),
            (run_id,),
        ).fetchall()


def row_to_dict(row: Any) -> dict[str, Any]:
    return json.loads(json.dumps(dict(row), default=str))


def count_users() -> int:
    with get_connection() as conn:
        row = conn.execute("SELECT COUNT(*) AS total FROM users").fetchone()
        return int(row["total"])


def create_user(username: str, password_hash: str, role: str) -> int:
    with get_connection() as conn:
        return _insert_returning_id(
            conn,
            """
            INSERT INTO users (username, password_hash, role, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (username, password_hash, role, datetime.now().isoformat(timespec="seconds")),
        )


def get_user_by_username(username: str) -> Any | None:
    with get_connection() as conn:
        return conn.execute(
            _ph("SELECT * FROM users WHERE username = ?"),
            (username,),
        ).fetchone()


def get_user_by_id(user_id: int) -> Any | None:
    with get_connection() as conn:
        return conn.execute(
            _ph("SELECT * FROM users WHERE id = ?"),
            (user_id,),
        ).fetchone()


def list_users() -> list[Any]:
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM users ORDER BY created_at DESC, id DESC"
        ).fetchall()


def delete_user(user_id: int) -> None:
    with get_connection() as conn:
        conn.execute(_ph("DELETE FROM users WHERE id = ?"), (user_id,))


def get_disabled_rule_ids() -> set[str]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT rule_id FROM rule_status WHERE enabled = 0"
        ).fetchall()
        return {row["rule_id"] for row in rows}


def set_rule_enabled(rule_id: str, enabled: bool) -> None:
    with get_connection() as conn:
        conn.execute(
            _ph(
                """
                INSERT INTO rule_status (rule_id, enabled) VALUES (?, ?)
                ON CONFLICT(rule_id) DO UPDATE SET enabled = excluded.enabled
                """
            ),
            (rule_id, 1 if enabled else 0),
        )
