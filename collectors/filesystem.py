"""Connecteur local : lecture directe d'un fichier (sans passer par une commande)."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def read_file(path: str) -> dict[str, Any]:
    """Lit un fichier texte. Renvoie le meme format que les autres connecteurs."""
    try:
        content = Path(path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        # Le fichier n'existe pas : c'est un constat, pas une panne d'execution.
        return {"returncode": 1, "output": "", "error": f"Fichier introuvable: {path}"}
    except OSError as exc:
        return {
            "returncode": 1,
            "output": "",
            "error": f"Erreur de lecture: {exc}",
            "execution_error": True,
        }

    return {"returncode": 0, "output": content.strip(), "error": ""}
