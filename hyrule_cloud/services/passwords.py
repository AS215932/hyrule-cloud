"""Argon2id password and recovery-code hashing.

Used for BOTH `accounts.password_hash` and `accounts.recovery_code_hash`. A
recovery code is a password-reset primitive — even at 128 bits of entropy,
it gets the same Argon2id treatment as a password. Plain sha256/HMAC is
deliberately not offered here; cheap hashes for password-grade secrets is
a recurring footgun and the consistent guidance is "argon2id, always".
"""

from __future__ import annotations

import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

# Defaults are well-balanced for a typical API node. memory_cost=64 MiB,
# time_cost=3, parallelism=1 matches OWASP 2023 guidance.
_PH = PasswordHasher(
    memory_cost=65536,  # 64 MiB
    time_cost=3,
    parallelism=1,
)

# Recovery code: hyr-rec-<26-char base32>. 130 bits of entropy.
_RECOVERY_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"  # base32 lowercase, no 0/1/8/9


def hash_password(password: str) -> str:
    """Argon2id-hash a password. Returns the encoded PHC string."""
    return _PH.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Constant-time verify. Returns True iff the password matches."""
    try:
        return _PH.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True if argon2 params have moved past what the stored hash uses."""
    try:
        return _PH.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


def generate_recovery_code() -> str:
    """Returns a fresh recovery code in display form (cleartext, shown once)."""
    body = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(26))
    return f"hyr-rec-{body}"


def hash_recovery_code(code: str) -> str:
    """Argon2id-hash a recovery code. Same treatment as a password."""
    return _PH.hash(code)


def verify_recovery_code(stored_hash: str, code: str) -> bool:
    """Constant-time recovery code check."""
    try:
        return _PH.verify(stored_hash, code)
    except (VerifyMismatchError, InvalidHashError):
        return False
