"""Block A0: anon management token verification for ownerless VMs.

This module is intentionally minimal — it predates the A1 account/session
auth layer and exists solely to gate destructive VM operations on a
proof-of-token from the anon order flow. When A1 lands (Wave 2), session-
and bearer-API-key resolution moves into a sibling `middleware/auth.py`
module; this file remains the canonical anon-token extractor.

Two helpers:
  - can_view_public_status — always True. The sanitized status view at
    `GET /v1/vm/{id}/status` is intentionally public; the route handler
    enforces field-level sanitization, not access.
  - can_manage_vm — True iff the caller presented a token that hashes to
    the row's `anon_management_token_hash`. Constant-time compare.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING

from fastapi import Request

if TYPE_CHECKING:
    from hyrule_cloud.db import VMRow


_BEARER_PREFIX = "Bearer "
_ANON_TOKEN_PREFIX = "hyr_vm_"


def hash_anon_token(token: str) -> str:
    """sha256-hex the cleartext token. The hash is what lands in the DB."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def anon_management_token(request: Request) -> str | None:
    """Extract a presented anon management token, if any.

    Accepted in two places:
      - Authorization: Bearer hyr_vm_<...> (canonical, agent-friendly)
      - ?token=hyr_vm_<...> (UX-friendly, used by the post-order URL)

    Returns the raw token string (with `hyr_vm_` prefix) or None if absent
    or malformed. Does NOT verify against any row — that's `can_manage_vm`'s
    job.
    """
    auth = request.headers.get("authorization") or ""
    if auth.startswith(_BEARER_PREFIX):
        candidate = auth[len(_BEARER_PREFIX):].strip()
        if candidate.startswith(_ANON_TOKEN_PREFIX):
            return candidate

    query = request.query_params.get("token")
    if query and query.startswith(_ANON_TOKEN_PREFIX):
        return query

    return None


def can_view_public_status(vm: VMRow) -> bool:
    """Always True. The public status view is by design unauthenticated.

    This function exists for symmetry with `can_manage_vm` and to give
    future authorization extensions (admin-only views, owner-only fields)
    a single chokepoint to grow into.
    """
    del vm  # unused in v1; reserved for symmetry
    return True


def can_manage_vm(vm: VMRow, presented_token: str | None) -> bool:
    """True iff `presented_token` hashes to `vm.anon_management_token_hash`.

    Legacy pre-A0 rows have `anon_management_token_hash = NULL` — they
    deny by default until claimed (Wave 2's claim flow). Comparison is
    constant-time via hmac.compare_digest to avoid timing leaks of the
    hash bytes.
    """
    if not presented_token:
        return False
    if not vm.anon_management_token_hash:
        # Legacy ownerless VM with no token issued. Cannot be managed via
        # the anon flow; A1's claim flow will give it an owner_account_id.
        return False
    return hmac.compare_digest(
        vm.anon_management_token_hash,
        hash_anon_token(presented_token),
    )
