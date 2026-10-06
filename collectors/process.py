"""Connecteur local : etat des processus systeme, via psutil (Linux et Windows)."""

from __future__ import annotations

from typing import Any

import psutil


def is_running(name: str) -> dict[str, Any]:
    """Cherche un processus dont le nom correspond (sans la casse)."""
    name_lower = name.lower()
    for proc in psutil.process_iter(["name"]):
        try:
            if (proc.info.get("name") or "").lower() == name_lower:
                return {"returncode": 0, "output": "RUNNING", "error": ""}
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Le processus a disparu ou n'est pas consultable : on continue,
            # ce n'est pas une panne du controle.
            continue

    return {"returncode": 0, "output": "STOPPED", "error": ""}
