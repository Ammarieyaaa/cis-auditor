"""Calcul du score de conformite, global et par categorie."""

from __future__ import annotations

from typing import Any

STATUS_ORDER = {"FAIL": 0, "ERROR": 1, "MANUAL": 2, "PASS": 3}


def group_by_category(rows: list[Any]) -> list[dict[str, Any]]:
    """Regroupe les resultats par categorie, les non-conformites d'abord."""
    groups: dict[str, list] = {}
    for row in rows:
        groups.setdefault(row["category"] or "Autres", []).append(row)

    grouped = []
    for name, items in groups.items():
        passed = sum(1 for item in items if item["status"] == "PASS")
        failed = sum(1 for item in items if item["status"] == "FAIL")
        evaluated = passed + failed
        grouped.append(
            {
                "name": name,
                "rules": sorted(
                    items,
                    key=lambda item: (STATUS_ORDER.get(item["status"], 0), item["rule_id"]),
                ),
                "total": len(items),
                "failed": failed,
                "manual": sum(1 for item in items if item["status"] == "MANUAL"),
                "errors": sum(1 for item in items if item["status"] == "ERROR"),
                "passed": passed,
                # Meme regle que le score global : manuels et erreurs exclus.
                "score": round(passed / evaluated * 100) if evaluated else None,
            }
        )

    grouped.sort(key=lambda group: (-group["failed"], group["name"]))
    return grouped
