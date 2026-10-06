"""Construction des donnees de rapport (le rendu HTML/PDF reste dans les templates)."""

from __future__ import annotations

from typing import Any

from data.database import row_to_dict

# Vocabulaire partage entre les presentations (web et CLI).
STATUT_FR = {"PASS": "Conforme", "FAIL": "Non conforme", "MANUAL": "Manuel", "ERROR": "Erreur"}
STATUT_CLASSE = {"PASS": "pass", "FAIL": "fail", "MANUAL": "manual", "ERROR": "error"}
SEVERITE_FR = {"high": "Élevée", "medium": "Moyenne", "low": "Faible"}


def build_json_payload(
    run: Any, rows: list[Any], status_labels: dict[str, str] = STATUT_FR
) -> dict[str, Any]:
    return {
        "audit": row_to_dict(run),
        "resultats": [
            {**row_to_dict(row), "statut": status_labels.get(row["status"], row["status"])}
            for row in rows
        ],
    }
