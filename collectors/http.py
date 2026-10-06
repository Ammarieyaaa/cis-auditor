"""Connecteur distant : interroge un endpoint HTTP/REST et compare un champ de la reponse."""

from __future__ import annotations

from typing import Any

import requests


def _extract(data: Any, json_path: str) -> Any:
    """Chemin simple en points, ex. "status.enabled" -> data["status"]["enabled"]."""
    value = data
    for part in json_path.split("."):
        if not part:
            continue
        value = value[int(part)] if isinstance(value, list) else value[part]
    return value


def request(check: dict[str, Any]) -> dict[str, Any]:
    method = check.get("method", "GET").upper()
    try:
        response = requests.request(
            method,
            check["url"],
            headers=check.get("headers"),
            json=check.get("body"),
            timeout=check.get("timeout", 10),
        )
    except requests.RequestException as exc:
        return {
            "returncode": 1,
            "output": "",
            "error": f"Erreur HTTP: {exc}",
            "execution_error": True,
        }

    json_path = check.get("json_path")
    if json_path:
        try:
            output = str(_extract(response.json(), json_path))
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            return {
                "returncode": 1,
                "output": response.text,
                "error": f"Chemin JSON invalide '{json_path}': {exc}",
                "execution_error": True,
            }
    else:
        output = response.text.strip()

    return {
        "returncode": 0 if response.ok else response.status_code,
        "output": output,
        "error": "" if response.ok else response.text,
    }
