"""Tests de la CLI (couche Presentation en ligne de commande)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from presentation import cli as cli_module


def invoke(*args):
    return CliRunner().invoke(cli_module.cli, list(args))


def test_rule_sets_liste_les_deux_referentiels(db):
    result = invoke("rule-sets")
    assert result.exit_code == 0
    assert "windows" in result.output
    assert "linux" in result.output


def test_categories_liste_le_referentiel_linux(db):
    result = invoke("categories", "--os", "linux")
    assert result.exit_code == 0
    assert "Comptes utilisateurs et umask" in result.output


def test_audit_puis_history_puis_report(db, fake_commands):
    result = invoke(
        "audit", "--os", "linux", "--level", "1", "--no-include-extra",
        "--category", "Comptes utilisateurs et umask",
    )
    assert result.exit_code == 0
    assert "score global" in result.output
    assert len(fake_commands) == 5  # 5 regles dans cette categorie

    history = invoke("history")
    assert history.exit_code == 0
    assert "linux" in history.output
    assert "local" in history.output

    run_id = db.list_runs()[0]["id"]
    report = invoke("report", str(run_id))
    assert report.exit_code == 0
    payload = json.loads(report.output)
    assert payload["audit"]["os_type"] == "linux"
    assert len(payload["resultats"]) == 5


def test_audit_sans_regle_dans_le_profil_choue(db):
    result = invoke("audit", "--os", "windows", "--level", "1", "--no-include-extra", "--category", "Introuvable")
    assert result.exit_code != 0
    assert "Aucune règle" in result.output or "Aucune regle" in result.output


def test_report_audit_inexistant_echoue(db):
    result = invoke("report", "999")
    assert result.exit_code != 0


def test_report_ecrit_dans_un_fichier(db, fake_commands, tmp_path):
    invoke("audit", "--os", "linux", "--level", "1", "--no-include-extra", "--category", "Comptes utilisateurs et umask")
    run_id = db.list_runs()[0]["id"]
    output_file = tmp_path / "rapport.json"

    result = invoke("report", str(run_id), "--output", str(output_file))
    assert result.exit_code == 0
    assert output_file.exists()
    payload = json.loads(output_file.read_text(encoding="utf-8"))
    assert payload["audit"]["id"] == run_id
