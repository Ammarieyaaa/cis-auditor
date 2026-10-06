import sqlite3
from datetime import datetime

from data import database


def result(rule_id, status):
    return {
        "rule_id": rule_id,
        "title": rule_id,
        "category": "Test",
        "severity": "medium",
        "status": status,
        "expected": "",
        "actual": "",
        "recommendation": "",
        "raw_output": "",
    }


def test_score_exclut_les_controles_manuels(db):
    results = [result("A", "PASS"), result("B", "PASS"), result("C", "FAIL"), result("D", "MANUAL")]
    run_id = db.save_audit_run("linux", "local", results, datetime.now(), 12.345, profile="Level 1")
    run = db.get_run(run_id)
    assert (run["passed"], run["failed"], run["manual"], run["total"]) == (2, 1, 1, 4)
    assert run["score"] == 67  # 2 conformes sur 3 controles evalues
    assert run["duration_seconds"] == 12.35
    assert run["profile"] == "Level 1"
    assert len(db.get_results(run_id)) == 4


def test_score_exclut_les_erreurs_d_execution(db):
    results = [result("A", "PASS"), result("B", "ERROR"), result("C", "ERROR")]
    run = db.get_run(db.save_audit_run("linux", "local", results, datetime.now(), 1.0))
    assert (run["passed"], run["failed"], run["errors"]) == (1, 0, 2)
    assert run["score"] == 100


def test_score_nul_si_uniquement_manuel(db):
    run_id = db.save_audit_run("linux", "local", [result("A", "MANUAL")], datetime.now(), 0.1)
    assert db.get_run(run_id)["score"] == 0


def test_migration_d_une_ancienne_base(tmp_path, monkeypatch):
    """Une base creee avant le chronometrage garde ses audits et gagne les colonnes."""
    path = tmp_path / "ancienne.db"
    with sqlite3.connect(path) as conn:
        conn.execute(
            "CREATE TABLE audit_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, os_type TEXT NOT NULL,"
            " target TEXT NOT NULL, started_at TEXT NOT NULL, score INTEGER NOT NULL,"
            " passed INTEGER NOT NULL, failed INTEGER NOT NULL, total INTEGER NOT NULL)"
        )
        conn.execute(
            "INSERT INTO audit_runs (os_type, target, started_at, score, passed, failed, total)"
            " VALUES ('linux', 'local', '2026-09-04T15:31:24', 41, 35, 50, 85)"
        )

    monkeypatch.setattr(database, "DB_PATH", path)
    database.init_db()

    run = database.get_run(1)
    assert run["score"] == 41
    assert run["manual"] == 0
    assert run["errors"] == 0
    assert run["duration_seconds"] is None
    assert run["profile"] is None


def test_perimetre_rssi(db):
    db.set_rule_enabled("CIS-X", False)
    assert "CIS-X" in db.get_disabled_rule_ids()
    db.set_rule_enabled("CIS-X", True)
    assert "CIS-X" not in db.get_disabled_rule_ids()
