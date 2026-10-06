"""Tests des connecteurs de la couche collecte (locaux et distants), sans cible reelle."""

from __future__ import annotations

import pytest

import requests

from collectors import filesystem, http, local, process, registry, ssh, winrm
from core.engine import collect


# --- Connecteur local : commandes systeme ------------------------------------


def test_local_erreur_inattendue_devient_execution_error(monkeypatch):
    def boom(*args, **kwargs):
        raise PermissionError("droits insuffisants")

    monkeypatch.setattr(local.subprocess, "run", boom)
    result = local.execute("linux", "whoami")
    assert result["execution_error"] is True
    assert "droits insuffisants" in result["error"]


# --- Connecteur local : processus (psutil) -----------------------------------


class FakeProcess:
    """Imite un psutil.Process : .info leve si le processus a disparu entre-temps."""

    def __init__(self, name=None, raises=None):
        self._name = name
        self._raises = raises

    @property
    def info(self):
        if self._raises:
            raise self._raises
        return {"name": self._name}


def test_process_detecte_un_processus_en_cours(monkeypatch):
    fake_processes = [FakeProcess("systemd"), FakeProcess("sshd"), FakeProcess("bash")]
    monkeypatch.setattr(process.psutil, "process_iter", lambda attrs=None: fake_processes)

    result = process.is_running("sshd")
    assert result == {"returncode": 0, "output": "RUNNING", "error": ""}


def test_process_absent_est_stopped(monkeypatch):
    monkeypatch.setattr(process.psutil, "process_iter", lambda attrs=None: [FakeProcess("bash")])
    result = process.is_running("telnetd")
    assert result == {"returncode": 0, "output": "STOPPED", "error": ""}


def test_process_ignore_les_processus_disparus(monkeypatch):
    gone = FakeProcess("x", raises=process.psutil.NoSuchProcess(pid=1))
    monkeypatch.setattr(process.psutil, "process_iter", lambda attrs=None: [gone, FakeProcess("cron")])
    result = process.is_running("cron")
    assert result["output"] == "RUNNING"


# --- Connecteur local : fichiers ---------------------------------------------


def test_filesystem_lit_un_fichier(tmp_path):
    target = tmp_path / "sshd_config"
    target.write_text("PermitRootLogin no\n", encoding="utf-8")
    result = filesystem.read_file(str(target))
    assert result == {"returncode": 0, "output": "PermitRootLogin no", "error": ""}


def test_filesystem_fichier_absent_est_un_constat_pas_une_panne(tmp_path):
    result = filesystem.read_file(str(tmp_path / "absent.conf"))
    assert result["returncode"] != 0
    assert "execution_error" not in result


# --- Connecteur local : registre Windows -------------------------------------


class FakeWinreg:
    HKEY_LOCAL_MACHINE = "HKLM_HANDLE"

    def __init__(self, values):
        self.values = values

    def OpenKey(self, hive, key):
        return _FakeKey(self.values, hive, key)

    def QueryValueEx(self, opened, name):
        try:
            return self.values[(opened.hive, opened.key, name)]
        except KeyError:
            raise FileNotFoundError(name)


class _FakeKey:
    def __init__(self, values, hive, key):
        self.values = values
        self.hive = hive
        self.key = key

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_registry_lit_une_valeur(monkeypatch):
    fake = FakeWinreg({("HKLM_HANDLE", "SYSTEM\\Policies", "PasswordComplexity"): (1, 4)})
    monkeypatch.setattr(registry, "winreg", fake)
    monkeypatch.setattr(registry, "_hive_constant", lambda hive: fake.HKEY_LOCAL_MACHINE)

    result = registry.read_value("HKLM", "SYSTEM\\Policies", "PasswordComplexity")
    assert result == {"returncode": 0, "output": "1", "error": ""}


def test_registry_valeur_absente_est_un_constat(monkeypatch):
    fake = FakeWinreg({})
    monkeypatch.setattr(registry, "winreg", fake)
    monkeypatch.setattr(registry, "_hive_constant", lambda hive: fake.HKEY_LOCAL_MACHINE)

    result = registry.read_value("HKLM", "SYSTEM\\Policies", "Absent")
    assert result["returncode"] != 0
    assert "execution_error" not in result


def test_registry_ruche_inconnue_est_une_erreur(monkeypatch):
    monkeypatch.setattr(registry, "winreg", FakeWinreg({}))
    result = registry.read_value("HKZZ", "x", "y")
    assert result["execution_error"] is True


# --- Connecteur distant : SSH (existant, verifie apres deplacement) ----------


def test_ssh_execute_ok():
    class Channel:
        def recv_exit_status(self):
            return 0

    class Stream:
        def __init__(self, text):
            self.channel = Channel()
            self._text = text

        def read(self):
            return self._text.encode()

    class FakeSSHClient:
        def exec_command(self, command, timeout=None):
            return None, Stream("PermitRootLogin no"), Stream("")

    result = ssh.execute(FakeSSHClient(), "grep PermitRootLogin /etc/ssh/sshd_config")
    assert result == {"returncode": 0, "output": "PermitRootLogin no", "error": ""}


def test_ssh_coupure_est_une_erreur():
    class BrokenSSH:
        def exec_command(self, *args, **kwargs):
            raise OSError("connexion perdue")

    result = ssh.execute(BrokenSSH(), "hostname")
    assert result["execution_error"] is True
    assert "connexion perdue" in result["error"]


# --- Connecteur distant : WinRM ----------------------------------------------


class FakeWinRMResult:
    def __init__(self, status_code, std_out=b"", std_err=b""):
        self.status_code = status_code
        self.std_out = std_out
        self.std_err = std_err


class FakeWinRMSession:
    def __init__(self, run_ps_result=None, run_cmd_result=None):
        self._run_ps_result = run_ps_result
        self._run_cmd_result = run_cmd_result or FakeWinRMResult(0, b"WIN-HOST")

    def run_cmd(self, command):
        return self._run_cmd_result

    def run_ps(self, command):
        return self._run_ps_result


def test_winrm_execute_ok():
    session = FakeWinRMSession(run_ps_result=FakeWinRMResult(0, b"Enabled"))
    result = winrm.execute(session, "Get-Something")
    assert result == {"returncode": 0, "output": "Enabled", "error": ""}


def test_winrm_erreur_devient_execution_error():
    class BrokenSession:
        def run_ps(self, command):
            raise TimeoutError("hote injoignable")

    result = winrm.execute(BrokenSession(), "Get-Something")
    assert result["execution_error"] is True
    assert "hote injoignable" in result["error"]


def test_winrm_connect_valide_la_session(monkeypatch):
    fake_module = type("m", (), {})()
    fake_module.Session = lambda endpoint, auth, transport, server_cert_validation: FakeWinRMSession()
    monkeypatch.setitem(__import__("sys").modules, "winrm", fake_module)

    session = winrm.connect("10.0.0.5", "admin", "secret")
    assert isinstance(session, FakeWinRMSession)


def test_winrm_connect_echoue_si_authentification_refusee(monkeypatch):
    fake_module = type("m", (), {})()
    fake_module.Session = lambda endpoint, auth, transport, server_cert_validation: FakeWinRMSession(
        run_cmd_result=FakeWinRMResult(1, b"", b"Acces refuse")
    )
    monkeypatch.setitem(__import__("sys").modules, "winrm", fake_module)

    with pytest.raises(ConnectionError):
        winrm.connect("10.0.0.5", "admin", "mauvais-mot-de-passe")


# --- Connecteur distant : HTTP / API ------------------------------------------


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self.ok = status_code < 400
        self._payload = payload
        self.text = text

    def json(self):
        return self._payload


def test_http_compare_un_champ_json(monkeypatch):
    monkeypatch.setattr(
        http.requests, "request",
        lambda method, url, headers=None, json=None, timeout=None: FakeResponse(200, {"status": {"enabled": True}}),
    )
    result = http.request({"url": "https://agent.local/status", "json_path": "status.enabled"})
    assert result == {"returncode": 0, "output": "True", "error": ""}


def test_http_erreur_reseau_devient_execution_error(monkeypatch):
    def boom(*args, **kwargs):
        raise requests.RequestException("connexion refusee")

    monkeypatch.setattr(http.requests, "request", boom)
    result = http.request({"url": "https://agent.local/status"})
    assert result["execution_error"] is True


# --- Dispatch de la couche metier vers le bon connecteur ---------------------


def test_collect_route_vers_le_fichier(monkeypatch, tmp_path):
    target = tmp_path / "f.txt"
    target.write_text("ok", encoding="utf-8")
    check = {"connector": "file", "type": "equals", "path": str(target), "expected": "ok"}
    assert collect("linux", check) == {"returncode": 0, "output": "ok", "error": ""}


def test_collect_route_vers_la_commande_par_defaut(monkeypatch):
    calls = []
    monkeypatch.setattr(
        "core.engine.execute_command",
        lambda os_type, command, ssh_client=None, winrm_session=None: calls.append(command) or {"returncode": 0, "output": "", "error": ""},
    )
    collect("linux", {"type": "command_success", "command": "true"})
    assert calls == ["true"]


@pytest.mark.parametrize("connector", ["file", "registry"])
@pytest.mark.parametrize("session_kwargs", [{"ssh_client": object()}, {"winrm_session": object()}])
def test_collect_refuse_file_et_registry_en_audit_distant(connector, session_kwargs):
    # Ces connecteurs lisent en local (winreg / Path) : sur une session
    # distante, ils liraient la machine qui fait tourner l'app, pas la cible.
    check = {"connector": connector, "type": "equals", "expected": "x"}
    result = collect("linux", check, **session_kwargs)
    assert result["execution_error"] is True
