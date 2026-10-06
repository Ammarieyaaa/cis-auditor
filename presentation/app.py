from __future__ import annotations

import io
import json
import os
import time
from datetime import datetime
from pathlib import Path

from config import env_file  # noqa: F401  charge .env avant toute lecture d'environnement

import paramiko
from flask import Flask, abort, flash, jsonify, make_response, redirect, render_template, request, session, url_for
from xhtml2pdf import pisa

from assistant import chatbot, document_store, knowledge
from collectors.winrm import connect as winrm_connect
from core import comparison, reporting
from core.reporting import SEVERITE_FR, STATUT_CLASSE, STATUT_FR
from core.engine import (
    available_categories,
    available_rule_sets,
    current_platform_label,
    extra_profiles,
    load_rules,
    run_audit,
    select_rules,
)
from core.scoring import group_by_category
from data import database
from data.database import get_results, get_run, init_db, list_runs, save_audit_run
from security import auth


BASE_DIR = Path(__file__).resolve().parent.parent

app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-a-changer-en-production")
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

# Une seule fois au chargement du module (pas a chaque requete : le schema ne
# change pas entre deux requetes, inutile de rejouer les CREATE/ALTER TABLE).
init_db()
auth.seed_default_admin()

MOIS_FR = [
    "janvier", "février", "mars", "avril", "mai", "juin",
    "juillet", "août", "septembre", "octobre", "novembre", "décembre",
]


@app.template_filter("fr_datetime")
def fr_datetime(value: str) -> str:
    if not value:
        return ""
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return str(value)
    return f"{dt.day} {MOIS_FR[dt.month - 1]} {dt.year} à {dt.strftime('%H:%M')}"


@app.template_filter("fr_severity")
def fr_severity(value: str) -> str:
    return SEVERITE_FR.get(value, value)


@app.template_filter("fr_status")
def fr_status(value: str) -> str:
    return STATUT_FR.get(value, value)


@app.template_filter("status_class")
def status_class(value: str) -> str:
    return STATUT_CLASSE.get(value, "fail")


@app.template_filter("fr_duration")
def fr_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    if seconds < 60:
        return f"{seconds:.1f} s".replace(".", ",")
    minutes, rest = divmod(round(seconds), 60)
    return f"{minutes} min {rest:02d} s"


@app.context_processor
def inject_current_user() -> dict:
    return {"current_user": auth.current_user(), "role_labels": auth.ROLE_LABELS}


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = database.get_user_by_username(username)

        if user is None or not auth.verify_password(password, user["password_hash"]):
            flash("Identifiants incorrects.", "error")
            return render_template("login.html")

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        next_url = request.args.get("next")
        default_url = url_for("admin_users") if user["role"] == "admin" else url_for("dashboard")
        return redirect(next_url or default_url)

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin", methods=["GET", "POST"])
@auth.role_required("admin")
def admin_users():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "technicien")

        if not username or not password or role not in auth.ROLES:
            flash("Formulaire invalide.", "error")
        elif database.get_user_by_username(username) is not None:
            flash("Ce nom d'utilisateur existe deja.", "error")
        else:
            database.create_user(username, auth.hash_password(password), role)
            flash(f"Compte '{username}' cree.", "success")

        return redirect(url_for("admin_users"))

    return render_template(
        "admin.html",
        users=database.list_users(),
        roles=auth.ROLES,
        role_labels=auth.ROLE_LABELS,
    )


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@auth.role_required("admin")
def admin_delete_user(user_id: int):
    if user_id == session.get("user_id"):
        flash("Impossible de supprimer votre propre compte.", "error")
    else:
        database.delete_user(user_id)
        flash("Compte supprime.", "success")
    return redirect(url_for("admin_users"))


@app.route("/")
@auth.role_required("technicien", "dsi", "rssi")
def dashboard():
    runs = list_runs()
    latest = runs[0] if runs else None
    return render_template(
        "index.html",
        runs=runs[:5],
        total_runs=len(runs),
        latest=latest,
        platform_label=current_platform_label(),
    )


@app.route("/audit", methods=["GET", "POST"])
@auth.role_required("technicien", "rssi")
def audit():
    rule_sets = available_rule_sets()
    # Les deux referentiels sont envoyes au navigateur : la liste des categories
    # se met a jour au changement de systeme sans aller-retour serveur.
    categories = {item["id"]: available_categories(item["id"]) for item in rule_sets}
    extras = {item["id"]: extra_profiles(item["id"]) for item in rule_sets}

    def render_form():
        return render_template(
            "audit.html",
            rule_sets=rule_sets,
            categories=categories,
            extras=extras,
            platform_label=current_platform_label(),
        )

    if request.method == "POST":
        os_type = request.form.get("os_type", "linux")
        mode = request.form.get("mode", "local")
        selected = set(request.form.getlist("categories"))
        max_level = 1 if request.form.get("level") == "1" else 2
        include_extra = request.form.get("include_extra") == "1"

        if not selected:
            flash("Sélectionne au moins une catégorie à auditer.", "error")
            return render_form()

        rules_to_run = select_rules(
            os_type,
            disabled_rule_ids=database.get_disabled_rule_ids(),
            categories=selected,
            max_level=max_level,
            include_extra=include_extra,
        )
        if not rules_to_run:
            flash("Aucune règle ne correspond à ce profil dans les catégories choisies.", "error")
            return render_form()

        profile = f"Level {max_level}"
        if include_extra and extras.get(os_type):
            profile += " + " + ", ".join(extras[os_type])

        if mode == "remote":
            host = request.form.get("host", "").strip()
            remote_user = request.form.get("remote_user", "").strip()
            remote_password = request.form.get("remote_password", "")
            transport_label = "SSH" if os_type == "linux" else "WinRM"

            if not host or not remote_user or not remote_password:
                flash(f"Renseigne l'adresse, l'utilisateur et le mot de passe {transport_label}.", "error")
                return render_form()

            started_at = datetime.now()

            if os_type == "windows":
                try:
                    winrm_session = winrm_connect(host, remote_user, remote_password)
                except Exception as exc:
                    flash(f"Connexion WinRM impossible : {exc}", "error")
                    return render_form()

                chrono = time.perf_counter()
                results = run_audit(os_type, rules_to_run, winrm_session=winrm_session)
                duration = time.perf_counter() - chrono
            else:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    client.connect(host, username=remote_user, password=remote_password, timeout=10)
                except Exception as exc:
                    flash(f"Connexion SSH impossible : {exc}", "error")
                    return render_form()

                chrono = time.perf_counter()
                try:
                    results = run_audit(os_type, rules_to_run, ssh_client=client)
                finally:
                    client.close()
                duration = time.perf_counter() - chrono

            target = host
        else:
            started_at = datetime.now()
            chrono = time.perf_counter()
            results = run_audit(os_type, rules_to_run)
            duration = time.perf_counter() - chrono
            target = "local"

        run_id = save_audit_run(
            os_type=os_type,
            target=target,
            results=results,
            started_at=started_at,
            duration_seconds=duration,
            profile=profile,
        )
        return redirect(url_for("results", run_id=run_id))

    return render_form()


@app.route("/results/<int:run_id>")
@auth.role_required("technicien", "dsi", "rssi")
def results(run_id: int):
    run = get_run(run_id)
    if run is None:
        abort(404)
    rows = get_results(run_id)
    others = [other for other in list_runs() if other["os_type"] == run["os_type"] and other["id"] != run_id]
    # Par defaut on propose l'audit precedent : c'est la question "qu'est-ce qui a change ?".
    # Comparaison par date, pas par id : deux audits concurrents (ex. un audit
    # distant lent demarre avant un audit local rapide) peuvent s'enregistrer
    # dans un ordre d'id different de leur ordre chronologique.
    previous = next((other for other in others if other["started_at"] < run["started_at"]), None)
    return render_template(
        "results.html",
        run=run,
        results=rows,
        groups=group_by_category(rows),
        comparable_runs=others,
        default_compare_id=previous["id"] if previous else None,
    )


@app.route("/compare")
@auth.role_required("technicien", "dsi", "rssi")
def compare():
    first = get_run(request.args.get("avant", type=int) or 0)
    second = get_run(request.args.get("apres", type=int) or 0)
    if first is None or second is None:
        abort(404)
    if first["id"] == second["id"]:
        flash("Choisis deux audits différents à comparer.", "error")
        return redirect(url_for("results", run_id=second["id"]))
    if first["os_type"] != second["os_type"]:
        flash("On ne compare que deux audits du même système.", "error")
        return redirect(url_for("results", run_id=second["id"]))

    before, after = sorted((first, second), key=lambda run: (run["started_at"], run["id"]))
    rows_before, rows_after = get_results(before["id"]), get_results(after["id"])
    return render_template(
        "compare.html",
        before=before,
        after=after,
        transitions=comparison.compare_rules(rows_before, rows_after),
        categories=comparison.category_deltas(
            group_by_category(rows_before), group_by_category(rows_after)
        ),
    )


@app.route("/history")
@auth.role_required("technicien", "dsi", "rssi")
def history():
    return render_template("history.html", runs=list_runs())


@app.route("/rules")
@auth.role_required("technicien", "dsi", "rssi")
def rules():
    os_type = request.args.get("os", "windows")
    rule_sets = available_rule_sets()
    loaded_rules = load_rules(os_type)
    return render_template(
        "rules.html",
        os_type=os_type,
        rule_sets=rule_sets,
        rules=loaded_rules,
        disabled_ids=database.get_disabled_rule_ids(),
    )


@app.route("/rssi/scope", methods=["GET", "POST"])
@auth.role_required("rssi")
def rssi_scope():
    os_type = request.args.get("os", request.form.get("os_type", "windows"))
    rule_sets = available_rule_sets()

    if request.method == "POST":
        rule_id = request.form.get("rule_id", "")
        enabled = request.form.get("enabled") == "1"
        database.set_rule_enabled(rule_id, enabled)
        flash(f"Règle '{rule_id}' {'activée' if enabled else 'désactivée'}.", "success")
        return redirect(url_for("rssi_scope", os=os_type))

    loaded_rules = load_rules(os_type)
    return render_template(
        "rssi_scope.html",
        os_type=os_type,
        rule_sets=rule_sets,
        rules=loaded_rules,
        disabled_ids=database.get_disabled_rule_ids(),
    )


def _load_run_or_404(run_id: int):
    run = get_run(run_id)
    if run is None:
        abort(404)
    return run, get_results(run_id)


def _download(body, content_type: str, filename: str):
    response = make_response(body)
    response.headers["Content-Type"] = content_type
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


@app.route("/report/<int:run_id>")
@auth.role_required("technicien", "dsi", "rssi")
def report(run_id: int):
    run, rows = _load_run_or_404(run_id)
    html = render_template("report.html", run=run, groups=group_by_category(rows), pdf=False)
    return _download(html, "text/html; charset=utf-8", f"rapport-audit-{run_id}.html")


@app.route("/report/<int:run_id>/pdf")
@auth.role_required("technicien", "dsi", "rssi")
def report_pdf(run_id: int):
    run, rows = _load_run_or_404(run_id)
    html = render_template("report.html", run=run, groups=group_by_category(rows), pdf=True)
    buffer = io.BytesIO()
    status = pisa.CreatePDF(html, dest=buffer, encoding="utf-8")
    if status.err:
        abort(500)
    return _download(buffer.getvalue(), "application/pdf", f"rapport-audit-{run_id}.pdf")


@app.route("/report/<int:run_id>/json")
@auth.role_required("technicien", "dsi", "rssi")
def report_json(run_id: int):
    run, rows = _load_run_or_404(run_id)
    payload = reporting.build_json_payload(run, rows, STATUT_FR)
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    return _download(body, "application/json; charset=utf-8", f"rapport-audit-{run_id}.json")


@app.route("/assistant/ask", methods=["POST"])
@auth.role_required("technicien", "dsi", "rssi")
def assistant_ask():
    """Agent unique : regles internes + tous les documents importes."""
    payload = request.get_json(silent=True) or {}
    message = payload.get("message", "").strip()

    if not message:
        return jsonify({"error": "Message vide."}), 400

    try:
        result = knowledge.ask(message)
    except chatbot.OllamaUnavailableError as exc:
        return jsonify({"error": str(exc)}), 503

    return jsonify(result)


@app.errorhandler(413)
def file_too_large(_exc):
    return jsonify({"error": "Fichier trop volumineux (20 Mo maximum)."}), 413


@app.route("/documents")
@auth.role_required("technicien", "dsi", "rssi")
def documents_page():
    return render_template("documents.html", documents=document_store.list_documents())


@app.route("/documents/upload", methods=["POST"])
@auth.role_required("technicien", "dsi", "rssi")
def documents_upload():
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return jsonify({"error": "Aucun fichier reçu."}), 400
    if not uploaded.filename.lower().endswith(".pdf"):
        return jsonify({"error": "Seuls les fichiers PDF sont acceptés."}), 400

    try:
        doc_id, cached = document_store.ingest_pdf(uploaded.read(), uploaded.filename)
    except document_store.DocumentTooLargeError as exc:
        return jsonify({"error": str(exc)}), 400
    except document_store.EmptyDocumentError as exc:
        return jsonify({"error": str(exc)}), 422
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    knowledge.invalidate()
    return jsonify(
        {
            "doc_id": doc_id,
            "cached": cached,
            "documents": document_store.list_documents(),
        }
    )


@app.route("/documents/<doc_id>/delete", methods=["POST"])
@auth.role_required("technicien", "dsi", "rssi")
def documents_delete(doc_id: str):
    try:
        document_store.forget_document(doc_id)
    except document_store.DocumentNotFoundError:
        return jsonify({"error": "Document introuvable."}), 404

    knowledge.invalidate()
    return jsonify({"documents": document_store.list_documents()})


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
