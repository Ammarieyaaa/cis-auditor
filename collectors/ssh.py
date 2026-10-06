"""Connecteur distant : execution d'une commande sur une cible via une session SSH deja ouverte."""

from __future__ import annotations

from typing import Any


def execute(ssh_client: Any, command: str) -> dict[str, Any]:
    try:
        _stdin, stdout, stderr = ssh_client.exec_command(command, timeout=15)
        returncode = stdout.channel.recv_exit_status()
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
    except Exception as exc:
        return {
            "returncode": 1,
            "output": "",
            "error": f"Erreur SSH: {exc}",
            "execution_error": True,
        }

    return {
        "returncode": returncode,
        "output": out if out else err,
        "error": err,
    }
