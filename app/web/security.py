from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta


PBKDF2_ROUNDS = 240_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ROUNDS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        scheme, rounds_text, salt_text, digest_text = password_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        rounds = int(rounds_text)
        salt = base64.b64decode(salt_text.encode("ascii"))
        expected = base64.b64decode(digest_text.encode("ascii"))
    except Exception:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return hmac.compare_digest(actual, expected)


def sign_session(user_id: int, secret_key: str, *, max_age_hours: int = 12) -> str:
    expires = int((datetime.now(UTC) + timedelta(hours=max_age_hours)).timestamp())
    payload = f"{user_id}:{expires}"
    signature = hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{signature}".encode("utf-8")).decode("ascii")


def verify_session(token: str, secret_key: str) -> int | None:
    try:
        decoded = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        user_id_text, expires_text, signature = decoded.split(":", 2)
        payload = f"{user_id_text}:{expires_text}"
        expected = hmac.new(secret_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        if int(expires_text) < int(datetime.now(UTC).timestamp()):
            return None
        return int(user_id_text)
    except Exception:
        return None


def csrf_token(session_token: str, secret_key: str) -> str:
    return hmac.new(secret_key.encode("utf-8"), session_token.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_csrf_token(session_token: str, submitted_token: str, secret_key: str) -> bool:
    if not session_token or not submitted_token:
        return False
    expected = csrf_token(session_token, secret_key)
    return hmac.compare_digest(expected, submitted_token)
