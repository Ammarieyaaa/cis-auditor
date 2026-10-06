"""Stockage persistant des PDF importes.

L'extraction d'un benchmark CIS coute une trentaine de secondes ; la refaire a
chaque redemarrage du serveur, ou parce qu'on reimporte le meme fichier, n'a
aucun interet. Les documents sont donc indexes par empreinte de contenu et
conserves sur disque, embeddings compris au fur et a mesure qu'ils sont calcules.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, BinaryIO

from pypdf import PdfReader


MAX_PAGES = 2000
MAX_CHUNKS = 4000
MAX_DOCUMENTS = 8
CHUNK_MAX_CHARS = 1200
CHUNK_OVERLAP = 150

STORE_PATH = Path(__file__).resolve().parent.parent / ".cache" / "documents"

_loaded: dict[str, dict[str, Any]] | None = None


class DocumentTooLargeError(Exception):
    pass


class EmptyDocumentError(Exception):
    pass


class DocumentNotFoundError(Exception):
    pass


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

def _chunk_page_text(text: str, page_number: int) -> list[dict[str, Any]]:
    text = text.strip()
    if not text:
        return []
    if len(text) <= CHUNK_MAX_CHARS:
        return [{"page": page_number, "text": text}]

    chunks = []
    start = 0
    while start < len(text):
        end = min(start + CHUNK_MAX_CHARS, len(text))
        chunks.append({"page": page_number, "text": text[start:end].strip()})
        if end == len(text):
            break
        start = end - CHUNK_OVERLAP
    return chunks


def extract_pdf_chunks(file_obj: BinaryIO) -> list[dict[str, Any]]:
    try:
        reader = PdfReader(file_obj)
    except Exception as exc:
        raise ValueError("Fichier PDF illisible ou corrompu.") from exc

    if len(reader.pages) > MAX_PAGES:
        raise DocumentTooLargeError(
            f"Document trop volumineux ({len(reader.pages)} pages, maximum {MAX_PAGES})."
        )

    chunks: list[dict[str, Any]] = []
    for page_number, page in enumerate(reader.pages, start=1):
        page_text = (page.extract_text() or "").strip()
        chunks.extend(_chunk_page_text(page_text, page_number))

    if not chunks:
        raise EmptyDocumentError(
            "Aucun texte exploitable trouve dans ce PDF. S'il s'agit d'un document "
            "scanne (image), l'extraction OCR n'est pas encore prise en charge."
        )

    if len(chunks) > MAX_CHUNKS:
        raise DocumentTooLargeError(
            f"Document trop volumineux ({len(chunks)} sections de texte, maximum {MAX_CHUNKS})."
        )

    return chunks


# ---------------------------------------------------------------------------
# Persistance
# ---------------------------------------------------------------------------

def _path_for(doc_id: str) -> Path:
    return STORE_PATH / f"{doc_id}.json"


def _write(doc_id: str, document: dict[str, Any]) -> None:
    try:
        STORE_PATH.mkdir(parents=True, exist_ok=True)
        _path_for(doc_id).write_text(
            json.dumps(
                {
                    "filename": document["filename"],
                    "created_at": document["created_at"],
                    "chunks": [
                        {
                            "page": chunk["page"],
                            "text": chunk["text"],
                            **(
                                {"embedding": chunk["embedding"]}
                                if "embedding" in chunk
                                else {}
                            ),
                        }
                        for chunk in document["chunks"]
                    ],
                }
            ),
            encoding="utf-8",
        )
    except OSError:
        # Un cache non ecrit degrade la vitesse, il ne doit pas casser l'import.
        pass


def _load_all() -> dict[str, dict[str, Any]]:
    global _loaded
    if _loaded is not None:
        return _loaded

    documents: dict[str, dict[str, Any]] = {}
    if STORE_PATH.exists():
        for path in STORE_PATH.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                continue
            documents[path.stem] = {
                "filename": data["filename"],
                "created_at": data.get("created_at", 0),
                "chunks": data["chunks"],
            }

    _loaded = documents
    return _loaded


def documents() -> dict[str, dict[str, Any]]:
    return _load_all()


def list_documents() -> list[dict[str, Any]]:
    return sorted(
        (
            {
                "doc_id": doc_id,
                "filename": document["filename"],
                "chunks": len(document["chunks"]),
                "pages": max((c["page"] for c in document["chunks"]), default=0),
                "embedded": sum(1 for c in document["chunks"] if "embedding" in c),
            }
            for doc_id, document in _load_all().items()
        ),
        key=lambda item: item["filename"].lower(),
    )


def ingest_pdf(data: bytes, filename: str) -> tuple[str, bool]:
    """Indexe un PDF et le conserve. Retourne (doc_id, deja_en_cache).

    L'identifiant est l'empreinte du contenu : reimporter le meme fichier ne
    recalcule rien, meme s'il a ete renomme.
    """
    doc_id = hashlib.sha256(data).hexdigest()[:32]
    store = _load_all()

    if doc_id in store:
        return doc_id, True

    import io

    chunks = extract_pdf_chunks(io.BytesIO(data))
    document = {"filename": filename, "created_at": time.time(), "chunks": chunks}
    store[doc_id] = document
    _write(doc_id, document)

    while len(store) > MAX_DOCUMENTS:
        oldest = min(store, key=lambda key: store[key]["created_at"])
        forget_document(oldest)

    return doc_id, False


def persist_embeddings(doc_id: str) -> None:
    """Sauvegarde les embeddings calcules paresseusement pendant une question."""
    store = _load_all()
    if doc_id in store:
        _write(doc_id, store[doc_id])


def forget_document(doc_id: str) -> None:
    store = _load_all()
    if store.pop(doc_id, None) is None:
        raise DocumentNotFoundError(doc_id)
    try:
        _path_for(doc_id).unlink(missing_ok=True)
    except OSError:
        pass
