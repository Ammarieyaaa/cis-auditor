from __future__ import annotations

import json
import platform
import re
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from typing import Any

from collectors import filesystem as filesystem_collector
from collectors import http as http_collector
from collectors import local as local_collector
from collectors import process as process_collector
from collectors import registry as registry_collector
from collectors import ssh as ssh_collector
from collectors import winrm as winrm_collector


BASE_DIR = Path(__file__).resolve().parent.parent
RULES_DIR = BASE_DIR / "rules"


def available_rule_sets() -> list[dict[str, str]]:
    return [
        {"id": "windows", "label": "Windows"},
        {"id": "linux", "label": "Linux / Unix"},
    ]


EXPLANATIONS_PATH = RULES_DIR / "explanations.json"

_explanations_cache: dict[str, dict[str, str]] | None = None


def load_explanations() -> dict[str, dict[str, str]]:
    """Vulgarisation de chaque regle, indexee par identifiant.

    Tenue a part des referentiels : les fichiers de regles decrivent ce que
    l'outil execute, ce fichier-ci explique a un lecteur non expert ce que la
    regle protege. Melanger les deux rendrait les referentiels illisibles.
    """
    global _explanations_cache
    if _explanations_cache is not None:
        return _explanations_cache

    if EXPLANATIONS_PATH.exists():
        with EXPLANATIONS_PATH.open(encoding="utf-8") as file:
            _explanations_cache = json.load(file)
    else:
        _explanations_cache = {}
    return _explanations_cache


def load_rules(os_type: str) -> list[dict[str, Any]]:
    rule_path = RULES_DIR / f"{os_type}.json"
    if not rule_path.exists():
        raise FileNotFoundError(f"Aucun fichier de regles trouve pour {os_type}.")

    with rule_path.open(encoding="utf-8") as file:
        data = json.load(file)

    rules = data.get("rules", [])
    explanations = load_explanations()
    for rule in rules:
        explanation = explanations.get(rule["id"])
        if explanation:
            rule["explanation"] = explanation
    return rules


def rule_level(rule: dict[str, Any]) -> int | None:
    """Niveau CIS de la regle, ou None pour un profil complementaire (BitLocker).

    Une regle "Level 1/2" figure deja au niveau 1 : on retient le plus bas.
    """
    levels = [int(level) for level in re.findall(r"Level\s*(\d)", rule.get("profile", ""))]
    return min(levels) if levels else None


def extra_profiles(os_type: str) -> list[str]:
    """Profils hors niveau presents dans le referentiel (ex. "BitLocker (BL)")."""
    names = {rule.get("profile", "") for rule in load_rules(os_type) if rule_level(rule) is None}
    return sorted(name for name in names if name)


def matches_profile(rule: dict[str, Any], max_level: int, include_extra: bool) -> bool:
    level = rule_level(rule)
    if level is None:
        return include_extra
    # Le profil Level 2 du CIS inclut toutes les regles Level 1.
    return level <= max_level


def available_categories(os_type: str) -> list[dict[str, Any]]:
    """Categories du referentiel, dans l'ordre du fichier, avec leur effectif par niveau."""
    categories: dict[str, dict[str, int]] = {}
    for rule in load_rules(os_type):
        name = rule.get("category", "Autres")
        level = rule_level(rule)
        counts = categories.setdefault(name, {"1": 0, "2": 0, "extra": 0})
        counts["extra" if level is None else str(level)] += 1
    return [
        {"name": name, "count": sum(counts.values()), "levels": counts}
        for name, counts in categories.items()
    ]


def select_rules(
    os_type: str,
    disabled_rule_ids: set[str] | None = None,
    categories: set[str] | None = None,
    max_level: int = 2,
    include_extra: bool = True,
) -> list[dict[str, Any]]:
    disabled_rule_ids = disabled_rule_ids or set()
    return [
        rule
        for rule in load_rules(os_type)
        if rule["id"] not in disabled_rule_ids
        # categories vide ou None = tout le referentiel
        and (not categories or rule.get("category", "Autres") in categories)
        and matches_profile(rule, max_level, include_extra)
    ]


MAX_PARALLEL_RULES = 8


def run_audit(
    os_type: str,
    rules: list[dict[str, Any]],
    ssh_client: Any | None = None,
    winrm_session: Any | None = None,
) -> list[dict[str, Any]]:
    """Execute chaque regle, en parallele : chaque controle (commande locale,
    SSH, WinRM, HTTP) est un aller-retour independant, souvent domine par la
    latence reseau plutot que par du calcul.

    Sans objet a paralleliser (0 ou 1 regle) : on evite l'overhead du pool.
    """
    if len(rules) <= 1:
        return [run_rule(os_type, rule, ssh_client, winrm_session) for rule in rules]

    worker = partial(run_rule, os_type, ssh_client=ssh_client, winrm_session=winrm_session)
    with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_RULES, len(rules))) as executor:
        # executor.map conserve l'ordre d'entree, meme si les regles finissent dans le desordre.
        return list(executor.map(worker, rules))


def run_rule(
    os_type: str,
    rule: dict[str, Any],
    ssh_client: Any | None = None,
    winrm_session: Any | None = None,
) -> dict[str, Any]:
    base = {
        "rule_id": rule["id"],
        "title": rule["title"],
        "category": rule.get("category", "Autres"),
        "severity": rule.get("severity", "medium"),
        "recommendation": rule.get("recommendation", ""),
        "description": rule.get("description", ""),
    }

    if rule["check"].get("type") == "manual":
        return {
            **base,
            "status": "MANUAL",
            "expected": describe_expected(rule["check"]),
            "actual": "Non évalué automatiquement : à vérifier manuellement.",
            "raw_output": "",
        }

    result = collect(os_type, rule["check"], ssh_client, winrm_session)
    if result.get("execution_error"):
        # Le controle n'a pas pu tourner : ce n'est pas un constat de non-conformite.
        status = "ERROR"
    else:
        status = "PASS" if evaluate_result(rule["check"], result) else "FAIL"

    return {
        **base,
        "status": status,
        "expected": describe_expected(rule["check"]),
        "actual": extract_actual(result),
        "raw_output": result["output"],
    }


def collect(
    os_type: str,
    check: dict[str, Any],
    ssh_client: Any | None = None,
    winrm_session: Any | None = None,
) -> dict[str, Any]:
    """Route le controle vers son connecteur (couche collecte).

    "connector" par defaut a "command" pour rester compatible avec les
    referentiels existants, qui ne le precisent pas.
    """
    connector = check.get("connector", "command")

    if connector in ("file", "registry", "process") and (ssh_client is not None or winrm_session is not None):
        # "file", "registry" et "process" lisent en Python local (winreg /
        # Path / psutil) : sur un audit distant, ils liraient la machine qui
        # fait tourner l'app et pas la cible, en le faisant passer pour un
        # resultat de la cible.
        return {
            "returncode": 1,
            "output": "",
            "error": f"Le connecteur '{connector}' n'est disponible qu'en audit local.",
            "execution_error": True,
        }
    if connector == "file":
        return filesystem_collector.read_file(check["path"])
    if connector == "registry":
        return registry_collector.read_value(check["hive"], check["key"], check["name"])
    if connector == "process":
        return process_collector.is_running(check["name"])
    if connector == "http":
        return http_collector.request(check)

    return execute_command(os_type, check["command"], ssh_client, winrm_session)


def execute_command(
    os_type: str,
    command: str,
    ssh_client: Any | None = None,
    winrm_session: Any | None = None,
) -> dict[str, Any]:
    """Delegue a la couche collecte : WinRM ou SSH si une session est fournie, sinon local."""
    if winrm_session is not None:
        return winrm_collector.execute(winrm_session, command)
    if ssh_client is not None:
        return ssh_collector.execute(ssh_client, command)
    return local_collector.execute(os_type, command)


def evaluate_result(check: dict[str, Any], result: dict[str, Any]) -> bool:
    mode = check.get("type", "contains")
    output = result["output"].strip()

    if mode == "command_success":
        return result["returncode"] == 0

    if result["returncode"] not in (0,):
        return False

    expected = str(check.get("expected", "")).strip()

    if mode == "equals":
        return output.lower() == expected.lower()

    if mode == "not_equals":
        return output.lower() != expected.lower()

    if mode == "contains":
        return expected.lower() in output.lower()

    if mode == "regex":
        return re.search(expected, output, flags=re.IGNORECASE | re.MULTILINE) is not None

    if mode == "numeric_min":
        return extract_number(output) >= float(expected)

    if mode == "numeric_max":
        return extract_number(output) <= float(expected)

    return False


def extract_number(value: str) -> float:
    match = re.search(r"-?\d+(?:\.\d+)?", value)
    if not match:
        return float("nan")
    return float(match.group(0))


def describe_expected(check: dict[str, Any]) -> str:
    mode = check.get("type", "contains")
    expected = check.get("expected", "")

    if mode == "manual":
        return "Contrôle manuel (voir la procédure d'audit de la règle)."
    if mode == "command_success":
        return "La commande doit reussir."
    if mode == "regex":
        return f"Doit correspondre au motif: {expected}"
    if mode == "numeric_min":
        return f"Valeur superieure ou egale a {expected}"
    if mode == "numeric_max":
        return f"Valeur inferieure ou egale a {expected}"
    if mode == "equals":
        return f"Valeur egale a: {expected}"
    if mode == "not_equals":
        return f"Valeur differente de: {expected}"
    return f"Doit contenir: {expected}"


def extract_actual(result: dict[str, Any]) -> str:
    if result["output"]:
        return result["output"]
    if result["error"]:
        return result["error"]
    return f"Code retour: {result['returncode']}"


def current_platform_label() -> str:
    return f"{platform.system()} {platform.release()}"
