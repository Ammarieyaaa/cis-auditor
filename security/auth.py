from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from flask import abort, redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from data import database


ROLES = ("admin", "technicien", "dsi", "rssi")
ROLE_LABELS = {
    "admin": "Administrateur",
    "technicien": "Technicien",
    "dsi": "DSI",
    "rssi": "RSSI",
}


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return check_password_hash(password_hash, password)


def seed_default_admin() -> None:
    if database.count_users() == 0:
        database.create_user("admin", hash_password("admin123"), "admin")
        print("Compte administrateur par defaut cree : admin / admin123 (a changer)")


def current_user() -> dict[str, Any] | None:
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return {"id": user_id, "username": session.get("username"), "role": session.get("role")}


def login_required(view: Callable) -> Callable:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if current_user() is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def role_required(*roles: str) -> Callable[[Callable], Callable]:
    def decorator(view: Callable) -> Callable:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            user = current_user()
            if user is None:
                return redirect(url_for("login", next=request.path))
            if user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator
