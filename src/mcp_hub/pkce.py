"""PKCE (RFC 7636) and OAuth `state` helpers."""
from __future__ import annotations

import base64
import hashlib
import secrets

_UNRESERVED = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"


def new_verifier(length: int = 64) -> str:
    """43..128 unreserved characters (RFC 7636 §4.1)."""
    if not 43 <= length <= 128:
        raise ValueError("PKCE verifier length must be 43..128")
    return "".join(secrets.choice(_UNRESERVED) for _ in range(length))


def challenge_s256(verifier: str) -> str:
    """BASE64URL(SHA256(verifier)) without padding (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def new_state() -> str:
    return secrets.token_urlsafe(24)
