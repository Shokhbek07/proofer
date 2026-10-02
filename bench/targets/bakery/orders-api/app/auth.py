import functools
import hashlib

from flask import Blueprint, abort, g, jsonify, request
from itsdangerous import BadSignature, URLSafeTimedSerializer

from . import config
from .db import get_db

bp = Blueprint("auth", __name__)
_signer = URLSafeTimedSerializer(config.SECRET_KEY)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def issue_token(user):
    return _signer.dumps({"uid": user["id"], "role": user["role"]})


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            abort(401)
        try:
            g.user = _signer.loads(header[7:], max_age=config.TOKEN_MAX_AGE)
        except BadSignature:
            abort(401)
        return view(*args, **kwargs)

    return wrapped


def staff_required(view):
    @functools.wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "staff":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


@bp.post("/register")
def register():
    data = request.get_json(force=True)
    db = get_db()
    db.execute(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        (data["email"], hash_password(data["password"])),
    )
    db.commit()
    return jsonify({"ok": True}), 201


@bp.post("/login")
def login():
    data = request.get_json(force=True)
    row = get_db().execute(
        "SELECT id, role, password_hash FROM users WHERE email = ?", (data["email"],)
    ).fetchone()
    if row is None or row["password_hash"] != hash_password(data["password"]):
        abort(401)
    return jsonify({"token": issue_token(row)})
