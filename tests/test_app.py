import json
from datetime import datetime

import pytest

from core.engine import load_rules
from conftest import login


def launch_audit(client, **form):
    data = {"os_type": "linux", "mode": "local", "level": "2", "include_extra": "1"}
    data.update(form)
    if "categories" not in data:
        data["categories"] = sorted({rule["category"] for rule in load_rules(data["os_type"])})
    return client.post("/audit", data=data)


def saved_run(db, response):
    run_id = int(response.headers["Location"].rstrip("/").split("/")[-1])
    return db.get_run(run_id)


# --- Controle d'acces --------------------------------------------------------


def test_visiteur_anonyme_redirige_vers_login(client):
    response = client.get("/history")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


@pytest.mark.parametrize("role, status", [("admin", 403), ("dsi", 403), ("technicien", 200), ("rssi", 200)])
def test_droit_de_lancer_un_audit(client, role, status):
    login(client, role)
    assert client.get("/audit").status_code == status


def test_perimetre_reserve_au_rssi(client):
    login(client, "technicien")
    assert client.get("/rssi/scope").status_code == 403
    login(client, "rssi")
    assert client.get("/rssi/scope").status_code == 200


# --- Lancement d'audit -------------------------------------------------------


def test_audit_level_1_complet(client, db, fake_commands):
    login(client, "technicien")
    response = launch_audit(client, level="1", include_extra="")
    assert response.status_code == 302
    run = saved_run(db, response)
    assert run["total"] == 70
    assert run["profile"] == "Level 1"
    assert run["duration_seconds"] is not None
    assert len(fake_commands) == 70


def test_audit_windows_level_2_avec_bitlocker(client, db, fake_commands):
    login(client, "technicien")
    run = saved_run(db, launch_audit(client, os_type="windows"))
    assert run["total"] == 80
    assert run["profile"] == "Level 2 + BitLocker (BL)"


def test_audit_sans_categorie_refuse(client, db, fake_commands):
    login(client, "technicien")
    response = launch_audit(client, categories=[])
    assert response.status_code == 200
    assert "Sélectionne au moins une catégorie" in response.get_data(as_text=True)
    assert db.list_runs() == []


def test_audit_sans_regle_dans_le_profil_refuse(client, db, fake_commands):
    login(client, "technicien")
    bitlocker = {rule["category"] for rule in load_rules("windows") if rule["profile"] == "BitLocker (BL)"}
    response = launch_audit(client, os_type="windows", level="1", include_extra="", categories=sorted(bitlocker))
    assert "Aucune règle ne correspond" in response.get_data(as_text=True)
    assert db.list_runs() == []
    assert fake_commands == []


def test_audit_ignore_les_regles_desactivees(client, db, fake_commands):
    login(client, "technicien")
    first = load_rules("linux")[0]["id"]
    db.set_rule_enabled(first, False)
    run = saved_run(db, launch_audit(client))
    assert run["total"] == 84


# --- Audit distant : SSH (Linux) et WinRM (Windows) --------------------------


class FakeSSHClient:
    """Remplace paramiko.SSHClient : aucune connexion reseau reelle."""

    connected_with: dict | None = None
    closed = False

    def set_missing_host_key_policy(self, policy):
        pass

    def connect(self, host, username, password, timeout=None):
        FakeSSHClient.connected_with = {"host": host, "username": username, "password": password}

    def close(self):
        FakeSSHClient.closed = True


def test_audit_distant_ssh_linux(client, db, fake_commands, monkeypatch):
    from presentation import app as app_module

    monkeypatch.setattr(app_module.paramiko, "SSHClient", FakeSSHClient)
    login(client, "technicien")
    run = saved_run(
        db,
        launch_audit(client, mode="remote", host="192.168.1.10", remote_user="ubuntu", remote_password="secret"),
    )
    assert run["target"] == "192.168.1.10"
    assert FakeSSHClient.connected_with == {"host": "192.168.1.10", "username": "ubuntu", "password": "secret"}
    assert FakeSSHClient.closed is True


def test_audit_distant_ssh_echec_connexion(client, db, monkeypatch):
    class RefusingSSHClient(FakeSSHClient):
        def connect(self, host, username, password, timeout=None):
            raise OSError("connexion refusee")

    from presentation import app as app_module

    monkeypatch.setattr(app_module.paramiko, "SSHClient", RefusingSSHClient)
    login(client, "technicien")
    response = launch_audit(client, mode="remote", host="10.0.0.1", remote_user="root", remote_password="x")
    assert "Connexion SSH impossible" in response.get_data(as_text=True)
    assert db.list_runs() == []


def test_audit_distant_winrm_windows(client, db, fake_commands, monkeypatch):
    from presentation import app as app_module

    connect_calls = []

    def fake_connect(host, username, password):
        connect_calls.append((host, username, password))
        return object()

    monkeypatch.setattr(app_module, "winrm_connect", fake_connect)
    login(client, "technicien")
    run = saved_run(
        db,
        launch_audit(
            client, os_type="windows", mode="remote",
            host="192.168.1.20", remote_user="Administrateur", remote_password="secret",
        ),
    )
    assert run["target"] == "192.168.1.20"
    assert connect_calls == [("192.168.1.20", "Administrateur", "secret")]


def test_audit_distant_winrm_echec_connexion(client, db, monkeypatch):
    from presentation import app as app_module

    def fake_connect(host, username, password):
        raise ConnectionError("Acces refuse")

    monkeypatch.setattr(app_module, "winrm_connect", fake_connect)
    login(client, "technicien")
    response = launch_audit(
        client, os_type="windows", mode="remote",
        host="192.168.1.20", remote_user="Administrateur", remote_password="mauvais",
    )
    assert "Connexion WinRM impossible" in response.get_data(as_text=True)
    assert db.list_runs() == []


def test_audit_distant_champs_manquants_refuse(client, db):
    login(client, "technicien")
    response = launch_audit(client, mode="remote", host="", remote_user="", remote_password="")
    assert "et le mot de passe SSH" in response.get_data(as_text=True)
    assert db.list_runs() == []


# --- Affichage et exports ----------------------------------------------------


@pytest.fixture
def run_id(db):
    results = [
        {"rule_id": rid, "title": rid, "category": "Réseau", "severity": "high", "status": status,
         "expected": "x", "actual": "y\nz", "recommendation": "Corriger", "raw_output": ""}
        for rid, status in [("R-1", "PASS"), ("R-2", "FAIL")]
    ]
    return db.save_audit_run("linux", "local", results, datetime(2026, 9, 4, 15, 31), 83.2, "Level 1")


def test_page_resultats_libelles_francais(client, run_id):
    login(client, "technicien")
    html = client.get(f"/results/{run_id}").get_data(as_text=True)
    assert "Conforme" in html and "Non conforme" in html
    assert "Manuel" not in html  # aucun controle manuel dans cet audit
    assert "1 min 23 s" in html
    assert "Profil : Level 1" in html


def test_export_html(client, run_id):
    login(client, "dsi")
    response = client.get(f"/report/{run_id}")
    assert response.status_code == 200
    assert "attachment" in response.headers["Content-Disposition"]
    assert "Non conforme" in response.get_data(as_text=True)


def test_export_pdf(client, run_id):
    login(client, "dsi")
    response = client.get(f"/report/{run_id}/pdf")
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/pdf"
    assert response.get_data().startswith(b"%PDF")


def test_export_json(client, run_id):
    login(client, "rssi")
    response = client.get(f"/report/{run_id}/json")
    payload = json.loads(response.get_data(as_text=True))
    assert payload["audit"]["score"] == 50
    assert payload["audit"]["profile"] == "Level 1"
    assert [r["statut"] for r in payload["resultats"]] == ["Conforme", "Non conforme"]


def test_score_par_categorie(client, db):
    def row(rid, category, status):
        return {"rule_id": rid, "title": rid, "category": category, "severity": "medium", "status": status,
                "expected": "", "actual": "", "recommendation": "", "raw_output": ""}

    results = [
        row("A-1", "Comptes", "PASS"), row("A-2", "Comptes", "PASS"),
        row("A-3", "Comptes", "PASS"), row("A-4", "Comptes", "FAIL"),
        row("A-5", "Comptes", "ERROR"),  # exclue : 3 conformes sur 4 evalues
        row("B-1", "Journalisation", "ERROR"),  # rien d'evalue : pas de score
    ]
    run_id = db.save_audit_run("windows", "local", results, datetime.now(), 1.0)
    login(client, "technicien")

    html = client.get(f"/results/{run_id}").get_data(as_text=True)
    assert "75 %" in html
    assert "Erreur" in html and "Erreurs d'exécution" in html

    report = client.get(f"/report/{run_id}").get_data(as_text=True)
    assert "Comptes — 75 %" in report
    assert "Journalisation — —" in report

    payload = json.loads(client.get(f"/report/{run_id}/json").get_data(as_text=True))
    assert payload["audit"]["errors"] == 2
    assert "Erreur" in [r["statut"] for r in payload["resultats"]]


def test_rapport_inexistant(client):
    login(client, "technicien")
    assert client.get("/report/999/pdf").status_code == 404
