import os

import pytest

from config import env_file  # noqa: F401  charge .env une bonne fois, puis on neutralise DATABASE_URL ci-dessous

from core import engine as audit_engine
from data import database

# La suite de tests tourne toujours sur SQLite. Sans cette ligne, un
# DATABASE_URL configure dans .env (pour tester la couche donnees contre un
# vrai Postgres) ferait ecrire tous les tests dans la base Postgres du
# developpeur des qu'un test importe app.py (qui charge .env a son tour).
os.environ.pop("DATABASE_URL", None)


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Base SQLite jetable : les tests ne touchent jamais audit_history.db."""
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    database.init_db()
    return database


@pytest.fixture
def fake_commands(monkeypatch):
    """Aucune commande systeme reelle : chaque controle recoit une sortie vide."""
    calls = []

    def fake_execute(os_type, command, ssh_client=None, winrm_session=None):
        calls.append(command)
        return {"returncode": 0, "output": "", "error": ""}

    monkeypatch.setattr(audit_engine, "execute_command", fake_execute)
    return calls


@pytest.fixture
def client(db):
    from presentation import app as app_module

    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


def login(client, role, user_id=1, username="testeur"):
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["username"] = username
        session["role"] = role
