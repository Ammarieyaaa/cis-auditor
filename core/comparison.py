"""Comparaison de deux audits du meme systeme, regle par regle."""

from __future__ import annotations

from typing import Any

TRANSITIONS = {
    ("FAIL", "PASS"): "corrigees",
    ("PASS", "FAIL"): "regressions",
    ("FAIL", "FAIL"): "toujours_non_conformes",
    ("PASS", "PASS"): "toujours_conformes",
}


def compare_rules(before: list[Any], after: list[Any]) -> dict[str, list[dict[str, Any]]]:
    """Classe chaque regle selon l'evolution de son statut entre les deux audits.

    Un statut manuel ou en erreur d'un cote n'est pas un constat : la regle
    tombe dans "non_comparables" plutot que d'etre comptee comme progres ou recul.
    """
    before_by_id = {row["rule_id"]: row for row in before}
    after_by_id = {row["rule_id"]: row for row in after}
    groups: dict[str, list[dict[str, Any]]] = {
        name: []
        for name in (
            "regressions",
            "corrigees",
            "toujours_non_conformes",
            "toujours_conformes",
            "non_comparables",
            "ajoutees",
            "retirees",
        )
    }

    for rule_id, new in after_by_id.items():
        old = before_by_id.get(rule_id)
        if old is None:
            groups["ajoutees"].append(_entry(new, None, new["status"]))
            continue
        key = TRANSITIONS.get((old["status"], new["status"]), "non_comparables")
        groups[key].append(_entry(new, old["status"], new["status"]))

    for rule_id, old in before_by_id.items():
        if rule_id not in after_by_id:
            groups["retirees"].append(_entry(old, old["status"], None))

    for entries in groups.values():
        entries.sort(key=lambda entry: entry["rule_id"])
    return groups


def _entry(row: Any, status_before: str | None, status_after: str | None) -> dict[str, Any]:
    return {
        "rule_id": row["rule_id"],
        "title": row["title"],
        "category": row["category"] or "Autres",
        "status_before": status_before,
        "status_after": status_after,
    }


def category_deltas(groups_before: list[dict], groups_after: list[dict]) -> list[dict[str, Any]]:
    """Score par categorie avant/apres, regressions en tete, puis plus forts progres."""
    before = {group["name"]: group["score"] for group in groups_before}
    after = {group["name"]: group["score"] for group in groups_after}
    names = list(after) + [name for name in before if name not in after]

    rows = []
    for name in names:
        score_before = before.get(name)
        score_after = after.get(name)
        delta = None
        if score_before is not None and score_after is not None:
            delta = score_after - score_before
        rows.append({"name": name, "before": score_before, "after": score_after, "delta": delta})

    rows.sort(key=_delta_order)
    return rows


def _delta_order(row: dict[str, Any]) -> tuple:
    delta = row["delta"]
    if delta is None:
        return (3, 0, row["name"])
    if delta < 0:
        return (0, delta, row["name"])
    if delta > 0:
        return (1, -delta, row["name"])
    return (2, 0, row["name"])
