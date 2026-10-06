"""Interface en ligne de commande : couche Presentation, en complement du web.

Reutilise le meme moteur (core/), les memes connecteurs (collectors/) et le
meme stockage (data/database.py) que l'interface Flask, sans dependre d'elle.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime

import click

# La console Windows n'est pas UTF-8 par defaut : sans ca, les caracteres
# accentues des regles/categories (francais) s'affichent mal.
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

from config import env_file  # noqa: F401  charge .env avant toute lecture d'environnement

from core.engine import (
    available_categories,
    available_rule_sets,
    extra_profiles,
    run_audit,
    select_rules,
)
from core.reporting import STATUT_FR, build_json_payload
from core.scoring import group_by_category
from data import database
from security import auth


@click.group()
def cli() -> None:
    """RAM Security - audit de conformite CIS en ligne de commande."""
    database.init_db()
    auth.seed_default_admin()


@cli.command("rule-sets")
def rule_sets_cmd() -> None:
    """Liste les referentiels disponibles (Windows, Linux/Unix)."""
    for item in available_rule_sets():
        click.echo(f"{item['id']:<10} {item['label']}")


@cli.command("categories")
@click.option("--os", "os_type", type=click.Choice(["linux", "windows"]), default="linux", show_default=True)
def categories_cmd(os_type: str) -> None:
    """Liste les categories du referentiel CIS, avec leur effectif par niveau."""
    for category in available_categories(os_type):
        levels = category["levels"]
        click.echo(
            f"{category['name']:<32} total={category['count']:<4} "
            f"L1={levels['1']} L2={levels['2']} extra={levels['extra']}"
        )


@cli.command("audit")
@click.option("--os", "os_type", type=click.Choice(["linux", "windows"]), default="linux", show_default=True)
@click.option("--level", type=click.Choice(["1", "2"]), default="2", show_default=True)
@click.option(
    "--category", "categories", multiple=True,
    help="Categorie a auditer (repetable). Par defaut : tout le referentiel.",
)
@click.option("--include-extra/--no-include-extra", default=True, help="Inclure les profils hors niveau (ex. BitLocker).")
def audit_cmd(os_type: str, level: str, categories: tuple[str, ...], include_extra: bool) -> None:
    """Lance un audit local et l'enregistre dans l'historique."""
    max_level = int(level)
    selected = set(categories) or None

    rules_to_run = select_rules(
        os_type,
        disabled_rule_ids=database.get_disabled_rule_ids(),
        categories=selected,
        max_level=max_level,
        include_extra=include_extra,
    )
    if not rules_to_run:
        raise click.ClickException("Aucune regle ne correspond a ce profil/ces categories.")

    profile = f"Level {max_level}"
    extras = extra_profiles(os_type)
    if include_extra and extras:
        profile += " + " + ", ".join(extras)

    click.echo(f"Audit {os_type} - profil {profile} - {len(rules_to_run)} regle(s)...")

    started_at = datetime.now()
    chrono = time.perf_counter()
    results = run_audit(os_type, rules_to_run)
    duration = time.perf_counter() - chrono

    run_id = database.save_audit_run(
        os_type=os_type,
        target="local",
        results=results,
        started_at=started_at,
        duration_seconds=duration,
        profile=profile,
    )

    run = database.get_run(run_id)
    click.echo(f"\nAudit #{run_id} termine en {duration:.1f}s - score global : {run['score']} %")
    for group in group_by_category(results):
        score = f"{group['score']} %" if group["score"] is not None else "  - "
        click.echo(
            f"  {group['name']:<32} {score:>6}  "
            f"({group['passed']} conformes / {group['failed']} non conformes / "
            f"{group['manual']} manuels / {group['errors']} erreurs)"
        )


@cli.command("history")
@click.option("--limit", default=10, show_default=True)
def history_cmd(limit: int) -> None:
    """Affiche les derniers audits enregistres."""
    runs = database.list_runs()[:limit]
    if not runs:
        click.echo("Aucun audit enregistre.")
        return
    for run in runs:
        click.echo(
            f"#{run['id']:<4} {run['os_type']:<8} {run['target']:<14} "
            f"{run['started_at']}  score={run['score']} %"
        )


@cli.command("report")
@click.argument("run_id", type=int)
@click.option(
    "--format", "fmt", type=click.Choice(["json"]), default="json", show_default=True,
    help="Format d'export (HTML/PDF : utiliser l'interface web).",
)
@click.option("--output", "-o", type=click.Path(), default=None, help="Fichier de sortie (sinon, stdout).")
def report_cmd(run_id: int, fmt: str, output: str | None) -> None:
    """Exporte le rapport JSON d'un audit."""
    run = database.get_run(run_id)
    if run is None:
        raise click.ClickException(f"Audit #{run_id} introuvable.")
    rows = database.get_results(run_id)

    payload = build_json_payload(run, rows, STATUT_FR)
    body = json.dumps(payload, ensure_ascii=False, indent=2)

    if output:
        with open(output, "w", encoding="utf-8") as file:
            file.write(body)
        click.echo(f"Rapport ecrit dans {output}")
    else:
        click.echo(body)


if __name__ == "__main__":
    cli()
