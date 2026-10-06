"""Agent unique interrogeant les regles internes ET les PDF importes.

Avant, deux RAG separes coexistaient avec deux zones de saisie distinctes : on
posait une question sur un benchmark AWS importe et le moteur des regles
Windows/Linux repondait. Une seule base interrogeable supprime le probleme, et
chaque passage retrouve porte sa provenance (identifiant de regle, ou nom de
fichier et page).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

from assistant import chatbot, document_store


# Nombre de passages preselectionnes lexicalement puis reclasses semantiquement.
CANDIDATE_K = 24
# Nombre de passages finalement envoyes au modele de redaction.
RETRIEVE_K = 5
# Poids du score semantique face au score lexical dans le classement final.
SEMANTIC_WEIGHT = 0.6

BM25_K1 = 1.5
BM25_B = 0.75


# ---------------------------------------------------------------------------
# Tokenisation
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[a-z0-9_.:-]{3,}")

# Mots vides FR/EN : sans ce filtre, une question comme "comment tester la
# securite dans AWS" pese surtout sur "comment"/"dans" et remonte n'importe
# quelle page du benchmark.
_STOPWORDS = frozenset(
    """
    comment quel quelle quels quelles est sont pour dans avec sans les des une
    que qui quoi cette ces mon son mes ses par sur plus tout tous toute toutes
    faire fait peut doit etre lors afin ainsi donc mais aussi leur elle ils
    the and for but with that this from what how which are you your can not
    should must does when where there their been have has was were will
    """.split()
)

# Les benchmarks CIS sont rediges en anglais alors que les questions arrivent en
# francais. Sans ce pont, "comment tester le chiffrement au repos" ne partage
# aucun mot avec la page qui dit "Ensure encryption at rest is enabled".
_GLOSSARY = {
    "chiffrement": ["encryption", "encrypted", "encrypt"],
    "chiffre": ["encrypted", "encryption"],
    "chiffree": ["encrypted", "encryption"],
    "repos": ["rest"],
    "passe": ["password", "passwords"],
    "authentification": ["authentication", "authenticate"],
    "identifiant": ["credential", "username"],
    "identifiants": ["credentials"],
    "utilisateur": ["user", "account"],
    "utilisateurs": ["users", "accounts"],
    "compte": ["account"],
    "comptes": ["accounts"],
    "administrateur": ["administrator", "admin", "root"],
    "droits": ["permissions", "privileges", "rights"],
    "permission": ["permission", "permissions"],
    "permissions": ["permissions", "privileges"],
    "privilege": ["privilege", "privileged"],
    "privileges": ["privileges", "privileged"],
    "acces": ["access"],
    "journalisation": ["logging", "audit"],
    "journal": ["log", "logging"],
    "journaux": ["logs", "logging"],
    "trace": ["trail", "log"],
    "traces": ["trails", "logs"],
    "surveillance": ["monitoring", "monitor"],
    "alerte": ["alarm", "alert"],
    "alertes": ["alarms", "alerts"],
    "sauvegarde": ["backup"],
    "sauvegardes": ["backups"],
    "pare-feu": ["firewall"],
    "parefeu": ["firewall"],
    "reseau": ["network"],
    "cle": ["key"],
    "cles": ["keys"],
    "certificat": ["certificate"],
    "certificats": ["certificates"],
    "correctif": ["patch", "update"],
    "correctifs": ["patches", "updates"],
    "verrouillage": ["lockout", "lock"],
    "strategie": ["policy"],
    "strategies": ["policies"],
    "politique": ["policy"],
    "regle": ["rule", "policy", "benchmark"],
    "regles": ["rules", "policies"],
    "registre": ["registry"],
    "service": ["service", "daemon"],
    "services": ["services"],
    "activee": ["enabled"],
    "active": ["enabled"],
    "desactive": ["disabled"],
    "desactivee": ["disabled"],
    "stockage": ["storage", "bucket"],
    "donnees": ["data", "database"],
    "publique": ["public", "publicly"],
    "securite": ["security", "secure"],
    "tester": ["audit", "check", "verify", "test"],
    "teste": ["audit", "check", "verify", "test"],
    "verifier": ["verify", "check", "audit"],
    "controler": ["check", "audit", "control"],
    "controle": ["control", "check"],
    "commande": ["command"],
    "resultat": ["result", "output", "expected"],
    "attendu": ["expected"],
    "recommandation": ["recommendation", "remediation"],
    "correction": ["remediation", "fix"],
    "facteur": ["factor", "mfa"],
    "rotation": ["rotation", "rotate"],
    "expiration": ["expiration", "expire", "maximum"],
    "duree": ["age", "duration", "lifetime"],
    "longueur": ["length"],
    "complexite": ["complexity"],
    "historique": ["history"],
    "racine": ["root"],
    "distant": ["remote"],
    "distante": ["remote"],
    "role": ["role"],
    "roles": ["roles"],
}


def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS]


def _expand_query_tokens(query: str) -> dict[str, float]:
    """Tokens de la question, avec le poids de chacun.

    Les traductions du glossaire comptent moitie moins que les mots reellement
    tapes : sinon "quelle commande pour auditer CIS-WIN-1.1.5" fait entrer
    command/result/output/expected, qui matchent partout et noient le seul
    terme discriminant de la question.
    """
    weights: dict[str, float] = {}
    for token in _tokens(query):
        weights[token] = 1.0
        for translation in _GLOSSARY.get(token, ()):
            weights.setdefault(translation, 0.5)
    return weights


# Un identifiant de regle tape par l'utilisateur designe une regle precise : il
# doit primer sur toute similarite statistique.
_RULE_ID_RE = re.compile(r"cis-[a-z]+-[\d.]+")


def _explicit_rule_ids(query: str) -> set[str]:
    return set(_RULE_ID_RE.findall(query.lower()))


# ---------------------------------------------------------------------------
# Index unifie
# ---------------------------------------------------------------------------

_index: dict[str, Any] | None = None


def _entry_label(entry: dict[str, Any]) -> str:
    if entry["source"] == "rule":
        return entry["rule_id"]
    return f"{entry['filename']} p.{entry['page']}"


def _build_entries() -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []

    # Les regles internes sont peu nombreuses et deja embeddees dans le cache
    # du corpus : on les reutilise telles quelles.
    for rule in chatbot.get_corpus_embeddings():
        entries.append(
            {
                "source": "rule",
                "rule_id": rule["rule_id"],
                "os": rule["os"],
                "title": rule["title"],
                "description": rule["description"],
                "audit_procedure": rule["audit_procedure"],
                "remediation_path": rule["remediation_path"],
                "command": rule["command"],
                "expected": rule["expected"],
                "text": rule["text"],
                "embedding": rule["embedding"],
            }
        )

    for doc_id, document in document_store.documents().items():
        for chunk in document["chunks"]:
            entry = {
                "source": "pdf",
                "doc_id": doc_id,
                "filename": document["filename"],
                "page": chunk["page"],
                "text": chunk["text"],
                "chunk": chunk,
            }
            if "embedding" in chunk:
                entry["embedding"] = chunk["embedding"]
            entries.append(entry)

    return entries


def _get_index() -> dict[str, Any]:
    global _index
    if _index is not None:
        return _index

    entries = _build_entries()
    document_frequency: Counter[str] = Counter()
    total_length = 0

    for entry in entries:
        term_frequency = Counter(_tokens(entry["text"]))
        entry["tf"] = term_frequency
        entry["length"] = sum(term_frequency.values())
        total_length += entry["length"]
        document_frequency.update(term_frequency.keys())

    count = len(entries) or 1
    _index = {
        "entries": entries,
        # Conserve pour savoir quelles plateformes sont reellement couvertes :
        # combien de passages parlent d'AWS, d'Azure, de Kubernetes...
        "df": document_frequency,
        "idf": {
            term: math.log(1 + (count - freq + 0.5) / (freq + 0.5))
            for term, freq in document_frequency.items()
        },
        "avg_length": total_length / count,
    }
    return _index


def invalidate() -> None:
    """A appeler apres tout ajout ou suppression de document."""
    global _index
    _index = None


# ---------------------------------------------------------------------------
# Recherche
# ---------------------------------------------------------------------------

def _bm25_candidates(
    query_weights: dict[str, float], rule_ids: set[str]
) -> list[tuple[float, dict[str, Any]]]:
    index = _get_index()
    idf = index["idf"]
    avg_length = index["avg_length"] or 1.0

    pinned: list[tuple[float, dict[str, Any]]] = []
    scored: list[tuple[float, dict[str, Any]]] = []

    for entry in index["entries"]:
        # Une regle nommee explicitement entre dans les candidats quoi qu'il
        # arrive, sans dependre de son score statistique.
        if rule_ids and entry["source"] == "rule" and entry["rule_id"].lower() in rule_ids:
            pinned.append((float("inf"), entry))
            continue

        term_frequency = entry["tf"]
        length = entry["length"]
        score = 0.0
        for token, weight in query_weights.items():
            frequency = term_frequency.get(token, 0)
            if not frequency:
                continue
            denominator = frequency + BM25_K1 * (
                1 - BM25_B + BM25_B * length / avg_length
            )
            score += weight * idf.get(token, 0.0) * frequency * (BM25_K1 + 1) / denominator
        if score > 0:
            scored.append((score, entry))

    scored.sort(key=lambda item: item[0], reverse=True)
    return (pinned + scored)[:CANDIDATE_K]


def _ensure_embeddings(entries: list[dict[str, Any]]) -> None:
    """Calcule les embeddings manquants, puis les persiste.

    Seuls les passages de PDF sont concernes : ils ne sont embeddes qu'a la
    premiere question qui les selectionne, sinon indexer un benchmark complet
    prendrait plusieurs minutes.
    """
    missing = [entry for entry in entries if "embedding" not in entry]
    if not missing:
        return

    embeddings = chatbot.embed_texts([e["text"] for e in missing], kind="passage")
    touched: set[str] = set()
    for entry, embedding in zip(missing, embeddings):
        entry["embedding"] = embedding
        if entry["source"] == "pdf":
            entry["chunk"]["embedding"] = embedding
            touched.add(entry["doc_id"])

    for doc_id in touched:
        document_store.persist_embeddings(doc_id)


def retrieve(query: str) -> list[dict[str, Any]]:
    candidates = _bm25_candidates(_expand_query_tokens(query), _explicit_rule_ids(query))
    if not candidates:
        return []

    _ensure_embeddings([entry for _score, entry in candidates])
    query_embedding = chatbot.embed_text(query, kind="query")

    finite = [score for score, _entry in candidates if score != float("inf")]
    best_lexical = max(finite, default=0.0) or 1.0

    reranked = []
    for score, entry in candidates:
        # Une regle nommee explicitement garde le score lexical maximal : le
        # reclassement semantique peut la reordonner, pas l'evincer.
        lexical = 1.0 if score == float("inf") else score / best_lexical
        semantic = chatbot.cosine_similarity(query_embedding, entry["embedding"])
        reranked.append(
            (SEMANTIC_WEIGHT * semantic + (1 - SEMANTIC_WEIGHT) * lexical, entry)
        )

    reranked.sort(key=lambda item: item[0], reverse=True)
    return [entry for _score, entry in reranked[:RETRIEVE_K]]


# ---------------------------------------------------------------------------
# Reponse
# ---------------------------------------------------------------------------

def _build_system_prompt(entries: list[dict[str, Any]]) -> str:
    blocks = []
    for entry in entries:
        if entry["source"] == "pdf":
            blocks.append(
                f"[Document {entry['filename']}, page {entry['page']}]\n{entry['text']}"
            )
            continue

        # Une regle interne porte deja sa commande d'audit et sa valeur
        # attendue : on les presente en clair plutot que noyees dans le texte,
        # sinon le modele repond "non precisee" alors qu'elles existent.
        lines = [f"[Regle {entry['rule_id']} - {entry['os']}] {entry['title']}"]
        for label, value in (
            ("Description", entry.get("description", "")),
            ("Procedure d'audit", entry.get("audit_procedure", "")),
            ("Chemin de configuration", entry.get("remediation_path", "")),
            ("Commande d'audit", entry.get("command", "")),
            ("Resultat attendu", entry.get("expected", "")),
        ):
            if value:
                lines.append(f"{label} : {value}")
        blocks.append("\n".join(lines))

    return (
        "Tu es l'assistant RAM Security, un outil d'audit de configuration de "
        "securite. Reponds en francais, UNIQUEMENT a partir des extraits fournis "
        "ci-dessous, sans jamais inventer de commande, de resultat ou de regle "
        "qui n'y figure pas explicitement.\n\n"
        "Les extraits viennent de deux sources : les regles internes de l'outil "
        "(identifiant du type CIS-WIN-1.1.4) et les documents PDF importes par "
        "l'utilisateur (nom de fichier et page). Cite systematiquement la source "
        "utilisee entre parentheses apres chaque information.\n\n"
        "Structure ta reponse ainsi :\n"
        "Explication : ce que dit la regle concernee.\n"
        "Commande : la commande d'audit telle qu'ecrite dans la source, ou "
        "\"non precisee\" si les extraits n'en contiennent aucune.\n"
        "Resultat attendu : tel qu'ecrit dans la source, ou \"non precise\".\n\n"
        "Si les extraits ne repondent pas a la question, dis-le clairement "
        "plutot que d'inventer une reponse.\n\n"
        f"Extraits disponibles :\n\n" + "\n\n".join(blocks)
    )


_CODE_SPAN_RE = re.compile(r"`([^`\n]{4,200})`")


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()


def _unverified_commands(answer: str, entries: list[dict[str, Any]]) -> list[str]:
    """Repere les commandes citees par le modele qui n'existent dans aucune source.

    Un petit modele invente des commandes plausibles malgre la consigne
    (`powercfg -showconfig` a ete produit pour un benchmark qui ne contient que
    des chemins d'interface). Dans un outil d'audit, une commande inventee est
    plus dangereuse qu'une absence de reponse, donc on verifie chaque extrait de
    code contre le texte reellement retrouve.
    """
    source = _normalise(" ".join(entry["text"] for entry in entries))
    unverified = [
        span.strip()
        for span in _CODE_SPAN_RE.findall(answer)
        if _normalise(span) not in source
    ]
    return list(dict.fromkeys(unverified))


# ---------------------------------------------------------------------------
# Couverture par plateforme
# ---------------------------------------------------------------------------

# Repondre "je n'ai pas de document sur AWS" demande de savoir ce qu'on couvre.
# Une question sur AWS trouve toujours des candidats BM25 (elle partage "regle"
# ou "benchmark" avec le referentiel Windows) : sans ce controle, on envoyait
# des extraits Windows au modele et on attendait qu'il constate lui-meme le
# hors-sujet, lentement et en le formulant mal.
_PLATFORMS = {
    "AWS": {
        "terms": ("aws", "s3", "ec2", "cloudtrail", "cloudwatch", "iam", "rds", "vpc"),
        "benchmark": "CIS Amazon Web Services Foundations Benchmark",
    },
    "Azure": {
        "terms": ("azure", "entra", "intune", "defender-for-cloud"),
        "benchmark": "CIS Microsoft Azure Foundations Benchmark",
    },
    "Google Cloud": {
        "terms": ("gcp", "google-cloud", "bigquery", "gke"),
        "benchmark": "CIS Google Cloud Platform Foundation Benchmark",
    },
    "Kubernetes": {
        "terms": ("kubernetes", "kubelet", "kubectl", "etcd"),
        "benchmark": "CIS Kubernetes Benchmark",
    },
    "Docker": {
        "terms": ("docker", "dockerd", "containerd"),
        "benchmark": "CIS Docker Benchmark",
    },
    "macOS": {
        "terms": ("macos", "mac", "osx"),
        "benchmark": "CIS Apple macOS Benchmark",
    },
    "Windows": {
        "terms": ("windows", "registry", "powershell", "bitlocker", "defender"),
        "benchmark": "CIS Microsoft Windows Benchmark",
    },
    "Linux": {
        "terms": ("linux", "ubuntu", "systemd", "sshd", "auditd", "apparmor"),
        "benchmark": "CIS Linux Benchmark",
    },
}

# Un seuil en nombre absolu ne marche pas : le referentiel Linux tient en 54
# passages alors que le benchmark Windows mentionne Azure 32 fois sans rien en
# dire d'utile. Ce qui distingue les deux, c'est la PART d'une source consacree
# a la plateforme : un tiers des regles pour Linux, 1,5 % du PDF pour Azure.
COVERAGE_MIN_RATIO = 0.05
COVERAGE_MIN_ENTRIES = 5


def _coverage() -> dict[str, int]:
    """Nombre de passages par plateforme, dans la source qui la couvre le mieux.

    Retourne 0 quand aucune source ne lui consacre une part significative : la
    plateforme n'est alors qu'evoquee au detour d'un autre referentiel.
    """
    index = _get_index()
    if "coverage" in index:
        return index["coverage"]

    sources: dict[str, list[dict[str, Any]]] = {}
    for entry in index["entries"]:
        key = "regles" if entry["source"] == "rule" else entry["doc_id"]
        sources.setdefault(key, []).append(entry)

    coverage: dict[str, int] = {}
    for platform, spec in _PLATFORMS.items():
        terms = set(spec["terms"])
        best = 0
        for entries in sources.values():
            hits = sum(1 for entry in entries if terms & entry["tf"].keys())
            if hits >= COVERAGE_MIN_ENTRIES and hits / len(entries) >= COVERAGE_MIN_RATIO:
                best = max(best, hits)
        coverage[platform] = best

    index["coverage"] = coverage
    return coverage


def _requested_platform(query: str) -> str | None:
    """Plateforme explicitement nommee dans la question, si elle l'est."""
    tokens = set(_tokens(query))
    for platform, spec in _PLATFORMS.items():
        if tokens & set(spec["terms"]):
            return platform
    return None


def _uncovered_answer(platform: str) -> str:
    return (
        f"Je n'ai aucun referentiel couvrant {platform}.\n"
        f"Ma base contient : {_covered_summary()}.\n"
        f"Pour repondre sur {platform}, importe le "
        f"\"{_PLATFORMS[platform]['benchmark']}\" au format PDF depuis la page "
        "Documents, puis repose ta question."
    )


def _covered_summary() -> str:
    coverage = _coverage()
    covered = [name for name, count in coverage.items() if count > 0]
    return ", ".join(covered) if covered else "aucune plateforme"


def _inventory() -> str:
    """Etat de la base de connaissance, en clair."""
    documents = document_store.list_documents()
    rules = len(chatbot.get_corpus_embeddings())

    coverage = _coverage()
    covered = [name for name, count in coverage.items() if count > 0]
    missing = [name for name, count in coverage.items() if count == 0]

    lines = [f"Plateformes que je couvre : {', '.join(covered) or 'aucune'}."]
    lines.append(f"Regles internes : {rules} (Windows et Linux).")

    if documents:
        lines.append(f"Documents PDF importes : {len(documents)}")
        lines.extend(
            f"- {document['filename']} ({document['pages']} pages)"
            for document in documents
        )
    else:
        lines.append("Documents PDF importes : aucun.")

    if missing:
        lines.append(
            f"Non couvert : {', '.join(missing)}. Importe le benchmark CIS "
            "correspondant depuis la page Documents pour que je puisse repondre "
            "dessus."
        )
    return "\n".join(lines)


# Une question sur la base elle-meme ("combien de documents as-tu ?") n'a aucune
# reponse dans les extraits : le RAG cherchait "documents" dans les regles CIS et
# repondait qu'il ne trouvait rien. On y repond directement.
_INVENTORY_RE = re.compile(
    r"(combien|quels?|quelles?|liste|inventaire|as-tu|avez-vous|tu as)"
    r"[^?]{0,60}"
    # "doc" abrege est au moins aussi frequent que "document" dans une question.
    r"(doc(?:ument)?s?|pdf|fichiers?|referentiels?|benchmarks?|base de connaissance)"
    r"|que (sais|connais)-?(tu|vous)",
    re.IGNORECASE,
)


def _no_match_answer() -> str:
    documents = document_store.list_documents()
    known = (
        "Documents importes : "
        + ", ".join(document["filename"] for document in documents)
        if documents
        else "Aucun document PDF n'est importe."
    )
    return (
        "Aucune regle interne ni aucun passage des documents importes ne "
        "correspond a cette question.\n"
        f"{known}\n"
        "Si la question porte sur une plateforme non couverte (AWS, Azure...), "
        "importe son benchmark CIS depuis la page Documents. Sinon, reformule "
        "avec les termes techniques du referentiel."
    )


def ask(query: str) -> dict[str, Any]:
    if _INVENTORY_RE.search(query):
        return {"answer": _inventory(), "sources": [], "warnings": []}

    # Court-circuit avant tout appel au modele : inutile de lui envoyer des
    # extraits Windows pour une question AWS et d'attendre qu'il constate le
    # hors-sujet.
    platform = _requested_platform(query)
    if platform and _coverage()[platform] == 0:
        return {"answer": _uncovered_answer(platform), "sources": [], "warnings": []}

    entries = retrieve(query)
    if not entries:
        return {"answer": _no_match_answer(), "sources": [], "warnings": []}

    answer = chatbot.chat_completion(_build_system_prompt(entries), query)

    return {
        "answer": answer,
        "sources": [
            {"kind": entry["source"], "label": _entry_label(entry)} for entry in entries
        ],
        "warnings": _unverified_commands(answer, entries),
    }
