import base64
import hashlib
import re

from mcp_hub.pkce import challenge_s256, new_state, new_verifier


def test_verifier_shape():
    v = new_verifier()
    assert 43 <= len(v) <= 128
    assert re.fullmatch(r"[A-Za-z0-9\-._~]+", v)
    assert new_verifier() != v


def test_challenge_is_deterministic_for_known_verifier():
    # Fixed input -> fixed S256 challenge (unpadded base64url SHA-256).
    v = "dBjftJeZ4CVP-mB92K9uhvLbBv0zUjbUEVWTnbK6oqY"
    assert challenge_s256(v) == "HWuPrmQPw16o-bBaLlRhNU8sTvqw-4KRocmUlPnQHLg"


def test_challenge_is_unpadded_base64url_sha256():
    v = new_verifier()
    expected = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode()
    assert challenge_s256(v) == expected and "=" not in expected


def test_state_is_random():
    assert len({new_state() for _ in range(50)}) == 50
