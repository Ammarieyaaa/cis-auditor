"""Connecteur local : execution d'une commande sur la machine qui fait tourner l'app."""

from __future__ import annotations

import subprocess
from typing import Any


def build_runner(os_type: str, command: str) -> list[str]:
    if os_type == "windows":
        return [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ]

    return ["bash", "-lc", command]


def execute(os_type: str, command: str) -> dict[str, Any]:
    runner = build_runner(os_type, command)
    try:
        completed = subprocess.run(
            runner,
            capture_output=True,
            check=False,
            text=True,
            timeout=15,
        )
    except FileNotFoundError as exc:
        return {
            "returncode": 127,
            "output": "",
            "error": f"Interpreteur introuvable: {exc}",
            "execution_error": True,
        }
    except subprocess.TimeoutExpired:
        return {
            "returncode": 124,
            "output": "",
            "error": "Delai d'execution depasse.",
            "execution_error": True,
        }
    except Exception as exc:
        # Meme politique que les connecteurs distants (ssh/winrm) : une panne
        # d'execution locale (droits, encodage, ...) est une ERROR de la
        # regle, pas un plantage de tout l'audit.
        return {
            "returncode": 1,
            "output": "",
            "error": f"Erreur d'execution locale: {exc}",
            "execution_error": True,
        }

    stdout = completed.stdout.strip()
    stderr = completed.stderr.strip()
    output = stdout if stdout else stderr

    return {
        "returncode": completed.returncode,
        "output": output,
        "error": stderr,
    }
