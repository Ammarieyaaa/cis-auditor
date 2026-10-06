import subprocess

import pytest

from core import engine as audit_engine
from core.engine import evaluate_result, load_rules, matches_profile, rule_level, run_rule, select_rules


def ok(output, returncode=0):
    return {"returncode": returncode, "output": output, "error": ""}


# --- Evaluation d'une sortie de commande -----------------------------------


@pytest.mark.parametrize(
    "check, result, expected",
    [
        ({"type": "equals", "expected": "Enabled"}, ok("enabled"), True),
        ({"type": "equals", "expected": "Enabled"}, ok("Disabled"), False),
        ({"type": "not_equals", "expected": "0"}, ok("1"), True),
        ({"type": "contains", "expected": "PermitRootLogin no"}, ok("x\nPermitRootLogin no\n"), True),
        ({"type": "contains", "expected": "absent"}, ok("autre chose"), False),
        ({"type": "regex", "expected": r"^maxretry\s*=\s*[1-5]$"}, ok("maxretry = 3"), True),
        ({"type": "numeric_min", "expected": "14"}, ok("MinimumPasswordLength : 14"), True),
        ({"type": "numeric_min", "expected": "14"}, ok("8"), False),
        ({"type": "numeric_max", "expected": "900"}, ok("600"), True),
        ({"type": "numeric_max", "expected": "900"}, ok("aucun nombre"), False),
        ({"type": "command_success"}, ok("", returncode=0), True),
        ({"type": "command_success"}, ok("", returncode=1), False),
    ],
)
def test_evaluate_result(check, result, expected):
    assert evaluate_result(check, result) is expected


def test_commande_en_erreur_jamais_conforme():
    # Meme si la sortie contient la valeur attendue, un code retour non nul = echec.
    assert evaluate_result({"type": "contains", "expected": "ok"}, ok("ok", returncode=1)) is False


# --- Profils CIS Level 1 / Level 2 -----------------------------------------


@pytest.mark.parametrize(
    "profile, level",
    [
        ("Level 1 - Server, Level 1 - Workstation", 1),
        ("Level 2 - Server, Level 2 - Workstation", 2),
        ("Level 1/2 - Server, Level 1/2 - Workstation", 1),
        ("Level 1 (L1)", 1),
        ("Level 2 (L2)", 2),
        ("BitLocker (BL)", None),
    ],
)
def test_rule_level(profile, level):
    assert rule_level({"profile": profile}) == level


def test_level_2_inclut_level_1():
    rule_l1 = {"profile": "Level 1 (L1)"}
    rule_l2 = {"profile": "Level 2 (L2)"}
    assert matches_profile(rule_l1, max_level=2, include_extra=False)
    assert matches_profile(rule_l2, max_level=2, include_extra=False)
    assert not matches_profile(rule_l2, max_level=1, include_extra=False)


def test_profil_bitlocker_optionnel():
    rule_bl = {"profile": "BitLocker (BL)"}
    assert matches_profile(rule_bl, max_level=1, include_extra=True)
    assert not matches_profile(rule_bl, max_level=2, include_extra=False)


@pytest.mark.parametrize(
    "os_type, max_level, include_extra, expected_count",
    [
        ("linux", 1, False, 70),
        ("linux", 2, False, 85),
        ("windows", 1, False, 64),
        ("windows", 2, False, 75),
        ("windows", 2, True, 80),
    ],
)
def test_select_rules_par_profil(os_type, max_level, include_extra, expected_count):
    rules = select_rules(os_type, max_level=max_level, include_extra=include_extra)
    assert len(rules) == expected_count


def test_select_rules_exclut_les_regles_desactivees_par_le_rssi():
    all_rules = select_rules("linux")
    disabled = {all_rules[0]["id"], all_rules[1]["id"]}
    remaining = select_rules("linux", disabled_rule_ids=disabled)
    assert len(remaining) == len(all_rules) - 2
    assert not disabled & {rule["id"] for rule in remaining}


def test_select_rules_filtre_par_categorie():
    category = load_rules("windows")[0]["category"]
    rules = select_rules("windows", categories={category})
    assert rules and all(rule["category"] == category for rule in rules)


# --- Execution d'une regle ---------------------------------------------------


def test_regle_manuelle_non_executee(monkeypatch):
    def must_not_run(*args, **kwargs):
        raise AssertionError("une regle manuelle ne doit lancer aucune commande")

    monkeypatch.setattr(audit_engine, "execute_command", must_not_run)
    rule = {"id": "T-1", "title": "Revue manuelle", "check": {"type": "manual"}}
    assert run_rule("linux", rule)["status"] == "MANUAL"


def test_regle_automatique_pass_et_fail(monkeypatch):
    rule = {"id": "T-2", "title": "Pare-feu", "check": {"type": "equals", "expected": "True", "command": "x"}}
    monkeypatch.setattr(audit_engine, "execute_command", lambda *a, **k: ok("True"))
    assert run_rule("windows", rule)["status"] == "PASS"
    monkeypatch.setattr(audit_engine, "execute_command", lambda *a, **k: ok("False"))
    assert run_rule("windows", rule)["status"] == "FAIL"


# --- Erreurs d'execution : ni conforme ni non conforme -----------------------

RULE = {"id": "T-3", "title": "t", "check": {"type": "equals", "expected": "1", "command": "x"}}


def test_delai_depasse_donne_erreur(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="x", timeout=15)

    monkeypatch.setattr(subprocess, "run", timeout)
    assert run_rule("linux", RULE)["status"] == "ERROR"


def test_interpreteur_introuvable_donne_erreur(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("powershell")

    monkeypatch.setattr(subprocess, "run", missing)
    assert run_rule("windows", RULE)["status"] == "ERROR"


def test_coupure_ssh_donne_erreur():
    class BrokenSSH:
        def exec_command(self, *args, **kwargs):
            raise OSError("connexion perdue")

    result = run_rule("linux", RULE, ssh_client=BrokenSSH())
    assert result["status"] == "ERROR"
    assert "connexion perdue" in result["actual"]


def test_code_retour_non_nul_reste_non_conforme(monkeypatch):
    # La commande a tourne : un composant absent est un constat, pas une panne.
    monkeypatch.setattr(audit_engine, "execute_command", lambda *a, **k: ok("", returncode=127))
    assert run_rule("linux", RULE)["status"] == "FAIL"


# --- Parallelisation de l'audit -----------------------------------------------


def test_run_audit_conserve_l_ordre_meme_avec_des_regles_plus_lentes(monkeypatch):
    import time

    delays = {"R-1": 0.05, "R-2": 0.0, "R-3": 0.03}

    def fake_execute(os_type, command, ssh_client=None, winrm_session=None):
        time.sleep(delays.get(command, 0))
        return {"returncode": 0, "output": command, "error": ""}

    monkeypatch.setattr(audit_engine, "execute_command", fake_execute)
    rules = [
        {"id": rid, "title": rid, "check": {"type": "equals", "command": rid, "expected": rid}}
        for rid in ["R-1", "R-2", "R-3"]
    ]
    results = audit_engine.run_audit("linux", rules)
    assert [r["rule_id"] for r in results] == ["R-1", "R-2", "R-3"]
    assert all(r["status"] == "PASS" for r in results)


# --- Integrite des referentiels ---------------------------------------------

KNOWN_TYPES = {"equals", "not_equals", "contains", "regex", "numeric_min", "numeric_max", "command_success", "manual"}


@pytest.mark.parametrize("os_type", ["linux", "windows"])
def test_referentiel_coherent(os_type):
    rules = load_rules(os_type)
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids)), "identifiants de regle en double"
    for rule in rules:
        check = rule["check"]
        assert check.get("type", "contains") in KNOWN_TYPES, rule["id"]
        if check.get("type") != "manual":
            assert check.get("command", "").strip(), f"{rule['id']} sans commande"
        assert rule.get("profile"), f"{rule['id']} sans profil CIS"
        assert rule.get("recommendation"), f"{rule['id']} sans recommandation"
