"""Connecteur local : lecture directe d'une valeur du registre Windows (sans passer par une commande)."""

from __future__ import annotations

from typing import Any

try:
    import winreg
except ImportError:  # pragma: no cover - module absent hors Windows
    winreg = None  # type: ignore[assignment]


_HIVES = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKEY_USERS": "HKEY_USERS",
}


def _hive_constant(hive: str) -> int | None:
    if winreg is None:
        return None
    name = _HIVES.get(hive.upper())
    if name is None:
        return None
    return getattr(winreg, name)


def read_value(hive: str, key: str, name: str) -> dict[str, Any]:
    """Lit une valeur de registre. Renvoie le meme format que les autres connecteurs."""
    if winreg is None:
        return {
            "returncode": 1,
            "output": "",
            "error": "Le registre Windows n'est accessible que depuis un audit local sous Windows.",
            "execution_error": True,
        }

    hive_key = _hive_constant(hive)
    if hive_key is None:
        return {
            "returncode": 1,
            "output": "",
            "error": f"Ruche de registre inconnue: {hive}",
            "execution_error": True,
        }

    try:
        with winreg.OpenKey(hive_key, key) as opened:
            value, _value_type = winreg.QueryValueEx(opened, name)
    except FileNotFoundError as exc:
        # La cle ou la valeur n'existe pas : c'est un constat, pas une panne.
        return {"returncode": 1, "output": "", "error": str(exc)}
    except OSError as exc:
        return {
            "returncode": 1,
            "output": "",
            "error": f"Erreur d'acces au registre: {exc}",
            "execution_error": True,
        }

    return {"returncode": 0, "output": str(value), "error": ""}
