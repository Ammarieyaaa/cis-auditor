from datetime import datetime

import pytest

from core.comparison import category_deltas, compare_rules
from conftest import login


def row(rule_id, status, category="Comptes"):
    return {"rule_id": rule_id, "title": rule_id, "category": category, "severity": "medium",
            "status": status, "expected": "", "actual": "", "recommendation": "", "raw_output": ""}


def ids(entries):
    return [entry["rule_id"] for entry in entries]


# --- Classement des regles ---------------------------------------------------


def test_compare_rules_classe_chaque_evolution():
    before = [row("A", "FAIL"), row("B", "PASS"), row("C", "FAIL"), row("D", "PASS"),
              row("E", "ERROR"), row("F", "FAIL")]
    after = [row("A", "PASS"), row("B", "FAIL"), row("C", "FAIL"), row("D", "PASS"),
             row("E", "FAIL"), row("G", "PASS")]
    groups = compare_rules(before, after)
    assert ids(groups["corrigees"]) == ["A"]
    assert ids(groups["regressions"]) == ["B"]
    assert ids(groups["toujours_non_conformes"]) == ["C"]
    assert ids(groups["toujours_conformes"]) == ["D"]
    # Une erreur d'execution n'est ni un progres ni un recul.
    assert ids(groups["non_comparables"]) == ["E"]
    assert ids(groups["ajoutees"]) == ["G"]
    assert ids(groups["retirees"]) == ["F"]


def test_statuts_avant_apres_conserves():
    groups = compare_rules([row("A", "FAIL")], [row("A", "PASS")])
    entry = groups["corrigees"][0]
    assert (entry["status_before"], entry["status_after"]) == ("FAIL", "PASS")


# --- Scores par categorie ----------------------------------------------------


def group(name, score):
    return {"name": name, "score": score}


def test_category_deltas_ordre_regressions_puis_progres():
    before = [group("Stable", 50), group("Progres", 20), group("Recul", 80), group("GrosProgres", 0)]
    after = [group("Stable", 50), group("Progres", 40), group("Recul", 60), group("GrosProgres", 100)]
    rows = category_deltas(before, after)
    assert [r["name"] for r in rows] == ["Recul", "GrosProgres", "Progres", "Stable"]
    assert [r["delta"] for r in rows] == [-20, 100, 20, 0]


def test_category_deltas_categorie_absente_d_un_cote():
    rows = category_deltas([group("Ancienne", 30)], [group("Nouvelle", 70), group("Vide", None)])
    by_name = {r["name"]: r for r in rows}
    assert by_name["Nouvelle"] == {"name": "Nouvelle", "before": None, "after": 70, "delta": None}
    assert by_name["Ancienne"]["after"] is None
    assert by_name["Vide"]["delta"] is None
    # Sans delta calculable, en fin de liste.
    assert rows[-1]["delta"] is None


# --- Page de comparaison -----------------------------------------------------


@pytest.fixture
def two_runs(db):
    first = db.save_audit_run(
        "linux", "local",
        [row("A", "FAIL"), row("B", "PASS"), row("C", "FAIL", "Réseau")],
        datetime(2026, 9, 1, 10, 0), 30.0, "Level 1",
    )
    second = db.save_audit_run(
        "linux", "local",
        [row("A", "PASS"), row("B", "FAIL"), row("C", "PASS", "Réseau")],
        datetime(2026, 9, 4, 10, 0), 28.0, "Level 1",
    )
    return first, second


def test_page_comparaison(client, two_runs):
    first, second = two_runs
    login(client, "rssi")
    html = client.get(f"/compare?avant={first}&apres={second}").get_data(as_text=True)
    assert "Évolution de l'audit Linux/Unix" in html
    assert "▲" in html and "+34 pts" in html  # 33 % -> 67 %
    assert "Régressions" in html and "Corrigées" in html
    assert 'data-name="Réseau"' in html and "+100 pts" in html
    assert "ne portent pas exactement sur le même périmètre" not in html


def test_ordre_des_audits_remis_dans_le_temps(client, two_runs):
    first, second = two_runs
    login(client, "technicien")
    html = client.get(f"/compare?avant={second}&apres={first}").get_data(as_text=True)
    assert f"vs #{first}" in html


def test_avertissement_si_profil_different(client, db, two_runs):
    first, _ = two_runs
    other = db.save_audit_run("linux", "local", [row("A", "PASS")], datetime(2026, 9, 5), 1.0, "Level 2")
    login(client, "technicien")
    html = client.get(f"/compare?avant={first}&apres={other}").get_data(as_text=True)
    assert "ne portent pas exactement sur le même périmètre" in html


def test_refus_entre_deux_systemes(client, db, two_runs):
    first, _ = two_runs
    windows = db.save_audit_run("windows", "local", [row("A", "PASS")], datetime(2026, 9, 5), 1.0)
    login(client, "technicien")
    response = client.get(f"/compare?avant={first}&apres={windows}", follow_redirects=True)
    assert "même système" in response.get_data(as_text=True)


def test_audit_inexistant(client, two_runs):
    login(client, "technicien")
    assert client.get("/compare?avant=1&apres=999").status_code == 404
    assert client.get("/compare").status_code == 404


def test_page_resultats_propose_l_audit_precedent(client, two_runs):
    first, second = two_runs
    login(client, "technicien")
    html = client.get(f"/results/{second}").get_data(as_text=True)
    assert f'<option value="{first}" selected' in html


def test_audit_precedent_choisi_par_date_pas_par_id(client, db):
    # B s'enregistre en premier (id le plus bas) bien qu'il ait demarre apres
    # A : un audit local rapide qui termine avant un audit distant lent
    # demarre plus tot. Le "precedent" doit rester celui qui a demarre avant,
    # pas celui dont l'id est plus petit.
    b_id = db.save_audit_run("linux", "local", [row("A", "PASS")], datetime(2026, 9, 5, 12, 0), 1.0, "Level 1")
    a_id = db.save_audit_run("linux", "local", [row("A", "PASS")], datetime(2026, 9, 1, 12, 0), 1.0, "Level 1")

    login(client, "technicien")
    html = client.get(f"/results/{b_id}").get_data(as_text=True)
    assert f'<option value="{a_id}" selected' in html
