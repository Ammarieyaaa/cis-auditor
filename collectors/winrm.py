"""Connecteur distant : execution d'une commande PowerShell sur une cible Windows via WinRM."""

from __future__ import annotations

from typing import Any


def connect(host: str, username: str, password: str, transport: str = "ntlm", use_ssl: bool = False) -> Any:
    """Ouvre une session WinRM et la valide tout de suite (comme ssh_client.connect())."""
    import winrm

    scheme = "https" if use_ssl else "http"
    port = 5986 if use_ssl else 5985
    endpoint = f"{scheme}://{host}:{port}/wsman"
    session = winrm.Session(endpoint, auth=(username, password), transport=transport, server_cert_validation="ignore")

    probe = session.run_cmd("hostname")
    if probe.status_code != 0:
        error = probe.std_err.decode(errors="replace").strip() if isinstance(probe.std_err, bytes) else str(probe.std_err)
        raise ConnectionError(error or "Connexion WinRM refusee.")

    return session


def execute(session: Any, command: str) -> dict[str, Any]:
    try:
        result = session.run_ps(command)
    except Exception as exc:
        return {
            "returncode": 1,
            "output": "",
            "error": f"Erreur WinRM: {exc}",
            "execution_error": True,
        }

    out = _decode(result.std_out).strip()
    err = _decode(result.std_err).strip()
    return {
        "returncode": result.status_code,
        "output": out if out else err,
        "error": err,
    }


def _decode(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)
