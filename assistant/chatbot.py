from __future__ import annotations

import hashlib
import json
import math
import os
import time
from pathlib import Path
from typing import Any

import requests

from core.engine import load_rules

from config import env_file  # noqa: F401  charge .env avant toute lecture d'environnement


# ---------------------------------------------------------------------------
# Fournisseur de modeles
#
# "ollama"  : tout tourne en local, aucune donnee ne sort de la machine, mais
#             sur un CPU sans GPU une reponse coute ~60 a 95 s et un modele 3B
#             invente des commandes d'audit malgre la consigne.
# "nvidia"  : endpoints NVIDIA NIM (API compatible OpenAI). Bien plus rapide et
#             bien plus fiable sur le respect des extraits, mais les extraits du
#             document sont envoyes a un service externe.
# ---------------------------------------------------------------------------

LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "ollama").lower()

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_CHAT_MODEL = os.environ.get("OLLAMA_CHAT_MODEL", "llama3.2")
OLLAMA_EMBED_MODEL = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")

NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "")
NVIDIA_BASE_URL = os.environ.get(
    "NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"
)
NVIDIA_CHAT_MODEL = os.environ.get(
    "NVIDIA_CHAT_MODEL", "nvidia/nemotron-3-super-120b-a12b"
)
NVIDIA_EMBED_MODEL = os.environ.get(
    "NVIDIA_EMBED_MODEL", "nvidia/nemotron-3-embed-1b"
)
# Les endpoints d'embedding NIM plafonnent la taille de lot ; on decoupe.
NVIDIA_EMBED_BATCH = int(os.environ.get("NVIDIA_EMBED_BATCH", "32"))

# Sur un CPU sans GPU, une reponse demande facilement plus d'une minute, et le
# rechargement d'un modele evince ajoute encore plusieurs dizaines de secondes.
OLLAMA_TIMEOUT = int(os.environ.get("OLLAMA_TIMEOUT", "600"))
# Garde les deux modeles resident : sans ca, alterner embeddings et redaction
# force Ollama a recharger le modele a chaque question.
OLLAMA_KEEP_ALIVE = os.environ.get("OLLAMA_KEEP_ALIVE", "30m")

# L'offre gratuite met les requetes en file : le delai vient de l'attente, pas
# de la generation. 120 s ne suffisait pas sur un prompt de 5 extraits.
NVIDIA_TIMEOUT = int(os.environ.get("NVIDIA_TIMEOUT", "300"))
NVIDIA_RETRIES = int(os.environ.get("NVIDIA_RETRIES", "3"))

CORPUS_CACHE_PATH = Path(__file__).resolve().parent.parent / ".cache" / "corpus_embeddings.json"

_corpus_cache: list[dict[str, Any]] | None = None


class OllamaUnavailableError(Exception):
    """Erreur d'appel au fournisseur de modeles.

    Le nom est conserve car les routes Flask et les tests s'y referent deja.
    """


def chat_model_name() -> str:
    return NVIDIA_CHAT_MODEL if LLM_PROVIDER == "nvidia" else OLLAMA_CHAT_MODEL


def embed_model_name() -> str:
    return NVIDIA_EMBED_MODEL if LLM_PROVIDER == "nvidia" else OLLAMA_EMBED_MODEL


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

def _ollama_post(endpoint: str, payload: dict[str, Any], model: str) -> dict[str, Any]:
    """Appelle Ollama en distinguant "injoignable" de "trop lent".

    `requests` leve la meme famille d'exception dans les deux cas ; les confondre
    donne le message "Verifie qu'il est lance" alors qu'Ollama tourne
    parfaitement et n'a simplement pas fini de calculer.
    """
    payload = {**payload, "keep_alive": OLLAMA_KEEP_ALIVE}
    try:
        response = requests.post(
            f"{OLLAMA_HOST}/{endpoint}", json=payload, timeout=OLLAMA_TIMEOUT
        )
        response.raise_for_status()
    except requests.exceptions.Timeout as exc:
        raise OllamaUnavailableError(
            f"Ollama n'a pas repondu en moins de {OLLAMA_TIMEOUT} s. Le modele "
            f"'{model}' tourne sur processeur, ce qui est lent sur un gros "
            "document : reessaie, augmente OLLAMA_TIMEOUT, ou bascule sur les "
            "endpoints NVIDIA (LLM_PROVIDER=nvidia)."
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise OllamaUnavailableError(
            "Impossible de contacter Ollama. Verifie qu'il est lance "
            f"(ollama serve) et que le modele '{model}' est installe "
            f"(ollama pull {model})."
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise OllamaUnavailableError(
            f"Ollama a renvoye une erreur pour le modele '{model}' : {exc}"
        ) from exc

    return response.json()


def _nvidia_post(endpoint: str, payload: dict[str, Any], model: str) -> dict[str, Any]:
    if not NVIDIA_API_KEY:
        raise OllamaUnavailableError(
            "LLM_PROVIDER=nvidia mais NVIDIA_API_KEY n'est pas definie. Cree une "
            "cle sur https://build.nvidia.com puis exporte-la avant de lancer "
            "l'application."
        )

    # L'offre gratuite renvoie regulierement 503 "temporarily overloaded" ou 429
    # sur une surcharge passagere : reessayer coute quelques secondes et evite
    # de remonter une erreur a l'utilisateur pour rien.
    for attempt in range(NVIDIA_RETRIES):
        try:
            response = requests.post(
                f"{NVIDIA_BASE_URL}/{endpoint}",
                json=payload,
                headers={
                    "Authorization": f"Bearer {NVIDIA_API_KEY}",
                    "Accept": "application/json",
                },
                timeout=NVIDIA_TIMEOUT,
            )
        except requests.exceptions.RequestException:
            if attempt == NVIDIA_RETRIES - 1:
                raise
            time.sleep(2 * (attempt + 1))
            continue

        if response.status_code in (429, 503) and attempt < NVIDIA_RETRIES - 1:
            time.sleep(2 * (attempt + 1))
            continue
        break

    try:
        response.raise_for_status()
    except requests.exceptions.Timeout as exc:
        raise OllamaUnavailableError(
            f"L'endpoint NVIDIA n'a pas repondu en moins de {NVIDIA_TIMEOUT} s "
            f"pour le modele '{model}'."
        ) from exc
    except requests.exceptions.ConnectionError as exc:
        raise OllamaUnavailableError(
            "Impossible de joindre l'API NVIDIA. Verifie ta connexion reseau."
        ) from exc
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        detail = exc.response.text[:300] if exc.response is not None else ""
        if status == 401:
            raise OllamaUnavailableError(
                "Cle NVIDIA_API_KEY refusee (401). Regenere une cle sur "
                "https://build.nvidia.com."
            ) from exc
        if status == 404:
            raise OllamaUnavailableError(
                f"Le modele '{model}' n'existe pas sur l'API NVIDIA (404). "
                "Verifie son identifiant exact dans le catalogue."
            ) from exc
        if status in (429, 503):
            raise OllamaUnavailableError(
                f"L'endpoint gratuit de '{model}' est sature "
                f"({status}), meme apres {NVIDIA_RETRIES} tentatives. Reessaie "
                "dans un moment ou change de NVIDIA_CHAT_MODEL."
            ) from exc
        raise OllamaUnavailableError(
            f"L'API NVIDIA a renvoye une erreur {status} pour '{model}' : {detail}"
        ) from exc
    except requests.exceptions.RequestException as exc:
        raise OllamaUnavailableError(
            f"Appel a l'API NVIDIA impossible pour '{model}' : {exc}"
        ) from exc

    return response.json()


# ---------------------------------------------------------------------------
# Embeddings
# ---------------------------------------------------------------------------

# nomic-embed-text (Ollama) attend un prefixe textuel, les modeles NVIDIA
# embedqa attendent un champ input_type. Meme idee dans les deux cas : une
# question et un passage ne doivent pas etre encodes de la meme facon, sinon la
# recherche perd nettement en precision.
_OLLAMA_PREFIX = {"query": "search_query: ", "passage": "search_document: "}


def embed_texts(texts: list[str], kind: str = "passage") -> list[list[float]]:
    """Embed plusieurs textes en un seul appel.

    Le batch n'est pas un detail de confort : avec Ollama sur CPU, un appel par
    texte plafonne a ~0,8 texte/s alors qu'un appel groupe monte a ~2,8 texte/s.
    """
    if not texts:
        return []

    if LLM_PROVIDER == "nvidia":
        vectors: list[list[float]] = []
        for start in range(0, len(texts), NVIDIA_EMBED_BATCH):
            batch = texts[start : start + NVIDIA_EMBED_BATCH]
            data = _nvidia_post(
                "embeddings",
                {
                    "model": NVIDIA_EMBED_MODEL,
                    "input": batch,
                    "input_type": kind,
                    "truncate": "END",
                },
                NVIDIA_EMBED_MODEL,
            )
            vectors.extend(item["embedding"] for item in data["data"])
        return vectors

    prefix = _OLLAMA_PREFIX.get(kind, "")
    payload = {
        "model": OLLAMA_EMBED_MODEL,
        "input": [f"{prefix}{text}" for text in texts],
    }
    return _ollama_post("api/embed", payload, OLLAMA_EMBED_MODEL)["embeddings"]


def embed_text(text: str, kind: str = "passage") -> list[float]:
    return embed_texts([text], kind=kind)[0]


# ---------------------------------------------------------------------------
# Corpus des regles JSON (RAG interne, distinct du RAG sur PDF importe)
# ---------------------------------------------------------------------------

def load_corpus() -> list[dict[str, Any]]:
    """Aplatit les regles JSON en documents interrogeables.

    La commande d'audit et sa valeur attendue font partie du texte indexe : sans
    elles, l'assistant repondait "commande non precisee" alors que chaque regle
    en contient une, et les termes techniques de la commande (secedit, registry,
    Get-ItemProperty) ne pouvaient pas etre retrouves lexicalement.
    """
    corpus: list[dict[str, Any]] = []
    for os_type in ("windows", "linux"):
        for rule in load_rules(os_type):
            check = rule.get("check", {}) or {}
            command = str(check.get("command", "") or "")
            expected = str(check.get("expected", "") or "")

            text = " ".join(
                str(part)
                for part in (
                    # L'identifiant fait partie du texte indexe : les reponses
                    # citent "CIS-WIN-1.1.5", et l'utilisateur enchaine
                    # naturellement en demandant cette regle par son numero.
                    rule["id"],
                    rule.get("cis_rule", ""),
                    rule.get("title", ""),
                    rule.get("description", ""),
                    rule.get("rationale", ""),
                    rule.get("recommendation", ""),
                    rule.get("audit_procedure", ""),
                    rule.get("remediation_path", ""),
                    command,
                )
                if part
            )
            corpus.append(
                {
                    "rule_id": rule["id"],
                    "os": os_type,
                    "title": rule.get("title", ""),
                    "description": rule.get("description", ""),
                    "recommendation": rule.get("recommendation", ""),
                    "audit_procedure": rule.get("audit_procedure", ""),
                    "remediation_path": rule.get("remediation_path", ""),
                    "command": command,
                    "expected": expected,
                    "text": text,
                }
            )
    return corpus


def _corpus_hash(corpus: list[dict[str, Any]]) -> str:
    # Le modele fait partie de l'empreinte : deux modeles d'embedding ne
    # produisent ni les memes vecteurs ni forcement la meme dimension, donc un
    # cache calcule avec l'un est inutilisable avec l'autre.
    raw = "\x1f".join(
        [LLM_PROVIDER, embed_model_name()]
        + [f"{doc['rule_id']}|{doc['text']}" for doc in corpus]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _load_cached_embeddings(corpus: list[dict[str, Any]], digest: str) -> bool:
    if not CORPUS_CACHE_PATH.exists():
        return False
    try:
        cached = json.loads(CORPUS_CACHE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False

    if cached.get("hash") != digest:
        return False

    by_id = {item["rule_id"]: item["embedding"] for item in cached.get("corpus", [])}
    if not all(doc["rule_id"] in by_id for doc in corpus):
        return False

    for doc in corpus:
        doc["embedding"] = by_id[doc["rule_id"]]
    return True


def _save_cached_embeddings(corpus: list[dict[str, Any]], digest: str) -> None:
    try:
        CORPUS_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CORPUS_CACHE_PATH.write_text(
            json.dumps(
                {
                    "hash": digest,
                    "corpus": [
                        {"rule_id": doc["rule_id"], "embedding": doc["embedding"]}
                        for doc in corpus
                    ],
                }
            ),
            encoding="utf-8",
        )
    except OSError:
        pass


def get_corpus_embeddings() -> list[dict[str, Any]]:
    global _corpus_cache
    if _corpus_cache is not None:
        return _corpus_cache

    corpus = load_corpus()
    digest = _corpus_hash(corpus)

    if not _load_cached_embeddings(corpus, digest):
        embeddings = embed_texts([doc["text"] for doc in corpus], kind="passage")
        for doc, embedding in zip(corpus, embeddings):
            doc["embedding"] = embedding
        _save_cached_embeddings(corpus, digest)

    _corpus_cache = corpus
    return _corpus_cache


def cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def retrieve(query: str, k: int = 4) -> list[dict[str, Any]]:
    query_embedding = embed_text(query, kind="query")
    corpus = get_corpus_embeddings()

    scored = [
        (cosine_similarity(query_embedding, doc["embedding"]), doc)
        for doc in corpus
    ]
    scored.sort(key=lambda item: item[0], reverse=True)
    return [doc for _score, doc in scored[:k]]


def build_system_prompt(sources: list[dict[str, Any]]) -> str:
    rules_block = "\n\n".join(
        f"Regle {doc['rule_id']} ({doc['os']}) : {doc['title']}\n"
        f"Description : {doc['description']}\n"
        f"Recommandation : {doc['recommendation']}"
        for doc in sources
    )

    return (
        "Tu es l'assistant RAM Security, un outil d'audit de "
        "configuration base sur les CIS Benchmarks. Reponds en francais, de "
        "maniere concise, UNIQUEMENT a partir des regles CIS fournies "
        "ci-dessous. Si la question ne concerne aucune de ces regles, dis "
        "clairement que tu ne sais pas plutot que d'inventer une reponse. "
        "Cite l'identifiant de regle (ex: CIS-WIN-1.1.4) quand tu t'appuies "
        "dessus.\n\n"
        f"Regles disponibles :\n\n{rules_block}"
    )


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

def chat_completion(system_prompt: str, user_message: str) -> str:
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_message},
    ]

    # Temperature nulle : on ne veut aucune creativite ici. Le modele doit
    # recopier ce que disent les extraits, pas broder une commande d'audit
    # plausible mais inexistante.
    if LLM_PROVIDER == "nvidia":
        data = _nvidia_post(
            "chat/completions",
            {
                "model": NVIDIA_CHAT_MODEL,
                "messages": messages,
                "temperature": 0,
                "stream": False,
            },
            NVIDIA_CHAT_MODEL,
        )
        return data["choices"][0]["message"]["content"]

    payload = {
        "model": OLLAMA_CHAT_MODEL,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0},
    }
    return _ollama_post("api/chat", payload, OLLAMA_CHAT_MODEL)["message"]["content"]


def ask(query: str) -> dict[str, Any]:
    sources = retrieve(query)
    system_prompt = build_system_prompt(sources)
    answer = chat_completion(system_prompt, query)
    cited_sources = [] if _is_unknown_answer(answer) else sources

    return {
        "answer": answer,
        "sources": [{"rule_id": doc["rule_id"], "title": doc["title"]} for doc in cited_sources],
    }


_UNKNOWN_PHRASES = (
    "je ne sais pas",
    "je ne connais pas",
    "je n'ai pas d'information",
    "je n'ai pas cette information",
)


def _is_unknown_answer(answer: str) -> bool:
    lowered = answer.lower()
    return any(phrase in lowered for phrase in _UNKNOWN_PHRASES)
