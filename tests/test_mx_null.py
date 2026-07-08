"""MX check handling of RFC 7505 null MX (``0 .``).

example.com publishes a null MX; the old code stripped it to an empty host and
built a DNSLookupRequest(name="") that raised a ValidationError, surfacing a
valid "no mail" configuration as status="error". A null MX must be a clean
finding instead.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import hyrule_cloud.services.mx.checks as mxc
from hyrule_cloud.models import DNSLookupRecordType, MXStatus


def _answers(*values: str) -> SimpleNamespace:
    return SimpleNamespace(answers=[SimpleNamespace(value=v) for v in values])


@pytest.mark.asyncio
async def test_null_mx_is_a_clean_finding(monkeypatch):
    async def fake_lookup(req):
        assert req.type == DNSLookupRecordType.MX  # never resolves an empty host
        return _answers("0 .")

    monkeypatch.setattr(mxc, "dns_lookup", fake_lookup)

    resp = await mxc._mx("example.com")

    assert resp.status == MXStatus.INFO
    codes = [f.code for f in resp.findings]
    assert codes == ["mx_null"]
    # The old bug reported this via the invalid-target error path.
    assert resp.status != MXStatus.ERROR


@pytest.mark.asyncio
async def test_root_exchange_with_nonzero_preference_is_malformed(monkeypatch):
    """A single ``10 .`` is NOT a null MX — RFC 7505 requires preference 0. It
    must warn as malformed, not report a clean "accepts no mail" INFO (and must
    not try to resolve the empty exchange host)."""
    async def fake_lookup(req):
        assert req.type == DNSLookupRecordType.MX  # never resolves an empty host
        return _answers("10 .")

    monkeypatch.setattr(mxc, "dns_lookup", fake_lookup)

    resp = await mxc._mx("example.com")

    codes = [f.code for f in resp.findings]
    assert codes == ["mx_null_bad_preference"]
    assert "mx_null" not in codes
    assert resp.status == MXStatus.WARNING


@pytest.mark.asyncio
async def test_null_mx_mixed_with_real_records_warns_without_crashing(monkeypatch):
    async def fake_lookup(req):
        if req.type == DNSLookupRecordType.MX:
            return _answers("0 .", "10 mail.example.com.")
        return _answers("192.0.2.1")  # the real host resolves

    monkeypatch.setattr(mxc, "dns_lookup", fake_lookup)

    resp = await mxc._mx("example.com")

    codes = [f.code for f in resp.findings]
    assert "mx_null_mixed" in codes
    assert "mx_host_no_address" not in codes  # real host resolved fine
    assert resp.status == MXStatus.WARNING
