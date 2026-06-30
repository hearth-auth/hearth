"""PKCE (RFC 7636) code verifier and challenge generation.

Use :func:`generate_pkce_pair` to create a ``(code_verifier, code_challenge)``
pair for the S256 method:

    pair = generate_pkce_pair()
    # 1. Store pair.code_verifier securely.
    # 2. Pass pair.code_challenge (and challenge_method="S256") in the
    #    authorization request.
    # 3. Pass pair.code_verifier in exchange_code().
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class PkcePair:
    """RFC 7636 PKCE pair — ``code_verifier`` is the secret, ``code_challenge`` is sent."""

    code_verifier: str
    code_challenge: str


def generate_pkce_pair() -> PkcePair:
    """Generate a fresh PKCE verifier/challenge pair using the S256 method.

    The verifier is 43 URL-safe base64 characters (32 random bytes, no padding),
    which satisfies the RFC 7636 §4.1 minimum of 43 characters.

    The challenge is ``BASE64URL(SHA256(ASCII(code_verifier)))`` with no padding.

    :returns: A :class:`PkcePair` with ``code_verifier`` and ``code_challenge``.
    """
    raw = os.urandom(32)
    code_verifier = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return PkcePair(code_verifier=code_verifier, code_challenge=code_challenge)
