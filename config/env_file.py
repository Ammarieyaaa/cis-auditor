"""Charge RAM_SECURITY/.env dans os.environ au demarrage.

Evite d'avoir a exporter NVIDIA_API_KEY a la main dans chaque terminal, et .env
figure deja dans .gitignore : la cle ne part donc pas dans le depot.

A importer avant toute lecture de os.environ.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


def load() -> None:
    if not ENV_PATH.exists():
        return

    for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        # Une variable deja posee dans le shell reste prioritaire sur le fichier.
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load()
