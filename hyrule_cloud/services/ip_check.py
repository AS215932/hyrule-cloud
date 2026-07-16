"""Short-lived network observations for browsers and autonomous agents."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import secrets
import time
from datetime import UTC, datetime, timedelta

from eth_account import Account
from eth_account.messages import encode_defunct
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from hyrule_cloud.config import IPCheckConfig
from hyrule_cloud.db import IPCheckObservationRow, IPCheckSessionRow
from hyrule_cloud.models import (
    IPCheckAgentFingerprintReport,
    IPCheckAgentFingerprintRequest,
    IPCheckBrowserFingerprintReport,
    IPCheckBrowserFingerprintRequest,
    IPCheckBrowserObservationRequest,
    IPCheckDNSObservationRequest,
    IPCheckEvidenceProvenance,
    IPCheckHTTPSObservationResponse,
    IPCheckNetworkAdapter,
    IPCheckNetworkObservationRequest,
    IPCheckProbeDefinition,
    IPCheckProbeManifest,
    IPCheckSessionCreateRequest,
    IPCheckSessionCreateResponse,
    IPCheckSessionReport,
    IPCheckWebRTCStatus,
)


class IPCheckSessionError(RuntimeError):
    pass


class IPCheckSessionNotFoundError(IPCheckSessionError):
    pass


def ip_check_ready(config: IPCheckConfig) -> bool:
    return bool(
        config.enabled
        and config.dns_observer_secret
        and config.v4_probe_base_url
        and config.v6_probe_base_url
        and config.dns_zone
        and config.stun_urls
    )


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _new_session_id() -> str:
    return "ipc_" + secrets.token_urlsafe(16)


def _new_token() -> str:
    return "hyr_ipc_" + secrets.token_urlsafe(32)


def _new_dns_label() -> str:
    return secrets.token_hex(16)


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _agent_identity_challenge(session_id: str, expires_at: datetime) -> str:
    expiry = _utc(expires_at).isoformat().replace("+00:00", "Z")
    return f"hyrule.host network observation\nsession={session_id}\nexpires={expiry}"


def verify_agent_wallet_signature(
    *,
    session_id: str,
    expires_at: datetime,
    wallet_address: str,
    wallet_signature: str,
) -> bool:
    challenge = _agent_identity_challenge(session_id, expires_at)
    try:
        recovered = Account.recover_message(
            encode_defunct(text=challenge), signature=wallet_signature
        )
    except (TypeError, ValueError):
        return False
    return str(recovered).lower() == wallet_address.lower()


def _session_url(base_url: str, session_id: str) -> str:
    return f"{base_url.rstrip('/')}/v1/ip-check/sessions/{session_id}"


async def cleanup_expired_ip_checks(
    session: AsyncSession,
    *,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(UTC)
    expired_sessions = select(IPCheckSessionRow.session_id).where(
        IPCheckSessionRow.expires_at <= now
    )
    await session.execute(
        delete(IPCheckObservationRow).where(
            IPCheckObservationRow.session_id.in_(expired_sessions)
        )
    )
    await session.execute(
        delete(IPCheckSessionRow).where(IPCheckSessionRow.expires_at <= now)
    )
    # Defence in depth: no observation may outlive the documented maximum even
    # if a session row was malformed or a future migration changes its TTL.
    await session.execute(
        delete(IPCheckObservationRow).where(
            IPCheckObservationRow.observed_at < now - timedelta(minutes=15)
        )
    )


async def run_ip_check_cleanup(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    interval_seconds: int = 60,
) -> None:
    """Continuously enforce the 15-minute retention ceiling."""

    while True:
        try:
            async with session_factory() as session:
                await cleanup_expired_ip_checks(session)
                await session.commit()
        except asyncio.CancelledError:
            raise
        except Exception:
            # Cleanup is retried on the next bounded interval. API operations
            # also reject expired sessions even if a transient DB error delayed
            # physical deletion.
            pass
        await asyncio.sleep(interval_seconds)


async def create_ip_check_session(
    session_factory: async_sessionmaker[AsyncSession],
    config: IPCheckConfig,
    request: IPCheckSessionCreateRequest,
) -> IPCheckSessionCreateResponse:
    session_id = _new_session_id()
    token = _new_token()
    dns_label = _new_dns_label()
    expires_at = datetime.now(UTC) + timedelta(seconds=config.session_ttl_seconds)
    async with session_factory() as session:
        await cleanup_expired_ip_checks(session)
        session.add(
            IPCheckSessionRow(
                session_id=session_id,
                token_hash=_token_hash(token),
                dns_label=dns_label,
                expected_dns_resolvers=request.expected_dns_resolvers,
                expires_at=expires_at,
            )
        )
        await session.commit()
    path = f"/v1/ip-check/sessions/{session_id}/observe/http"
    report_url = _session_url(config.api_base_url, session_id)
    auth_headers = {"Authorization": f"Bearer {token}"}
    network_submission_url = f"{report_url}/observe/network"
    agent_fingerprint_url = f"{report_url}/fingerprints/agent"
    dns_hostname = f"{dns_label}.{config.dns_zone.rstrip('.').lower()}"
    probes = [
        IPCheckProbeDefinition(
            id="https_ipv4",
            protocol="https",
            target=config.v4_probe_base_url.rstrip("/") + path,
            method="POST",
            headers=auth_headers,
            provenance=IPCheckEvidenceProvenance.SERVER_OBSERVED,
            description="Record IPv4 egress from the environment executing this request.",
        ),
        IPCheckProbeDefinition(
            id="https_ipv6",
            protocol="https",
            target=config.v6_probe_base_url.rstrip("/") + path,
            method="POST",
            headers=auth_headers,
            provenance=IPCheckEvidenceProvenance.SERVER_OBSERVED,
            optional=True,
            description="Record IPv6 egress; inability to connect is a valid result.",
        ),
        IPCheckProbeDefinition(
            id="dns",
            protocol="dns",
            target=dns_hostname,
            record_types=["A", "AAAA"],
            provenance=IPCheckEvidenceProvenance.SERVER_OBSERVED,
            description="Resolve the unique name so Hyrule can observe the recursive resolver.",
        ),
    ]
    probes.extend(
        IPCheckProbeDefinition(
            id=f"stun_{index}",
            protocol="stun",
            target=url,
            result_submission_url=network_submission_url,
            headers=auth_headers,
            provenance=IPCheckEvidenceProvenance.CLIENT_DECLARED,
            optional=True,
            description=(
                "Run an RFC 5389 binding probe and submit only globally routable mapped "
                "addresses. The report labels this client-declared until a STUN observer "
                "attests it."
            ),
        )
        for index, url in enumerate(config.stun_urls, start=1)
    )
    probes.append(
        IPCheckProbeDefinition(
            id="agent_fingerprint",
            protocol="https",
            target=agent_fingerprint_url,
            method="POST",
            headers=auth_headers,
            provenance=IPCheckEvidenceProvenance.CLIENT_DECLARED,
            optional=True,
            description=(
                "Declare runtime and capabilities; optionally sign the manifest challenge "
                "with an EVM wallet to upgrade identity assurance to signed."
            ),
        )
    )
    return IPCheckSessionCreateResponse(
        session_id=session_id,
        token=token,
        expires_at=expires_at,
        retention_seconds=config.session_ttl_seconds,
        ipv4_probe_url=config.v4_probe_base_url.rstrip("/") + path,
        ipv6_probe_url=config.v6_probe_base_url.rstrip("/") + path,
        dns_probe_hostname=dns_hostname,
        stun_urls=config.stun_urls,
        probe_manifest=IPCheckProbeManifest(
            probes=probes,
            report_url=report_url,
            agent_identity_challenge=_agent_identity_challenge(session_id, expires_at),
        ),
    )


async def _authorized_session(
    session: AsyncSession,
    session_id: str,
    token: str,
) -> IPCheckSessionRow:
    row = await session.get(IPCheckSessionRow, session_id)
    now = datetime.now(UTC)
    if row is None or _utc(row.expires_at) <= now:
        raise IPCheckSessionNotFoundError("IP-check session not found")
    if not hmac.compare_digest(row.token_hash, _token_hash(token)):
        # Do not disclose whether the session id or bearer was wrong.
        raise IPCheckSessionNotFoundError("IP-check session not found")
    return row


async def observe_https_address(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    session_id: str,
    token: str,
    address: str,
) -> IPCheckHTTPSObservationResponse:
    parsed = ipaddress.ip_address(address)
    normalized = str(parsed)
    observed_at = datetime.now(UTC)
    async with session_factory() as session:
        row = await _authorized_session(session, session_id, token)
        existing = await session.scalar(
            select(IPCheckObservationRow.id).where(
                IPCheckObservationRow.session_id == row.session_id,
                IPCheckObservationRow.kind == "https",
                IPCheckObservationRow.address == normalized,
            )
        )
        if existing is None:
            session.add(
                IPCheckObservationRow(
                    session_id=row.session_id,
                    kind="https",
                    address=normalized,
                    family=parsed.version,
                    observed_at=observed_at,
                )
            )
            await session.commit()
    return IPCheckHTTPSObservationResponse(
        session_id=session_id,
        address=normalized,
        family=parsed.version,
        observed_at=observed_at,
    )


async def observe_browser_candidates(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    session_id: str,
    token: str,
    observation: IPCheckBrowserObservationRequest,
) -> None:
    await observe_network_addresses(
        session_factory,
        session_id=session_id,
        token=token,
        observation=IPCheckNetworkObservationRequest(
            adapter=IPCheckNetworkAdapter.WEBRTC,
            status=observation.status,
            public_addresses=observation.public_addresses,
        ),
    )


async def observe_network_addresses(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    session_id: str,
    token: str,
    observation: IPCheckNetworkObservationRequest,
) -> None:
    kind = observation.adapter.value
    async with session_factory() as session:
        row = await _authorized_session(session, session_id, token)
        await session.execute(
            delete(IPCheckObservationRow).where(
                IPCheckObservationRow.session_id == row.session_id,
                IPCheckObservationRow.kind.in_([kind, f"{kind}_status"]),
            )
        )
        session.add(
            IPCheckObservationRow(
                session_id=row.session_id,
                kind=f"{kind}_status",
                details={
                    "status": observation.status.value,
                    "provenance": IPCheckEvidenceProvenance.CLIENT_DECLARED.value,
                },
            )
        )
        for address in observation.public_addresses:
            parsed = ipaddress.ip_address(address)
            session.add(
                IPCheckObservationRow(
                    session_id=row.session_id,
                    kind=kind,
                    address=str(parsed),
                    family=parsed.version,
                    details={
                        "provenance": IPCheckEvidenceProvenance.CLIENT_DECLARED.value
                    },
                )
            )
        await session.commit()


def _session_fingerprint(token_hash: str, kind: str, details: dict[str, object]) -> str:
    canonical = json.dumps(details, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hmac.new(
        token_hash.encode(), f"{kind}.".encode() + canonical.encode(), hashlib.sha256
    ).hexdigest()
    prefix = "bf" if kind == "browser" else "af"
    return f"{prefix}_{digest[:32]}"


def _clean_headers(headers: dict[str, str | None]) -> dict[str, str]:
    limits = {
        "user_agent": 512,
        "accept_language": 256,
        "sec_ch_ua": 512,
        "sec_ch_ua_platform": 128,
        "tls_ja4": 128,
    }
    return {
        name: value.strip()[: limits[name]]
        for name, value in headers.items()
        if value and value.strip()
    }


async def observe_browser_fingerprint(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    session_id: str,
    token: str,
    observation: IPCheckBrowserFingerprintRequest,
    observed_headers: dict[str, str | None],
) -> IPCheckBrowserFingerprintReport:
    headers = _clean_headers(observed_headers)
    client_traits = observation.model_dump(
        exclude={"high_entropy_consent"}, exclude_none=True
    )
    high_entropy = any(
        client_traits.get(name) is not None
        for name in ("webgl_vendor", "webgl_renderer", "canvas_sha256", "audio_sha256")
    )
    consistency: dict[str, bool | None] = {
        "user_agent_matches_header": None,
        "language_matches_header": None,
        "platform_matches_client_hint": None,
    }
    if observation.user_agent is not None and "user_agent" in headers:
        consistency["user_agent_matches_header"] = (
            observation.user_agent == headers["user_agent"]
        )
    if observation.languages and "accept_language" in headers:
        header_language = headers["accept_language"].split(",", 1)[0].split(";", 1)[0]
        consistency["language_matches_header"] = (
            observation.languages[0].lower() == header_language.strip().lower()
        )
    if observation.platform is not None and "sec_ch_ua_platform" in headers:
        hinted = headers["sec_ch_ua_platform"].strip('"')
        consistency["platform_matches_client_hint"] = (
            observation.platform.lower() == hinted.lower()
        )

    async with session_factory() as session:
        row = await _authorized_session(session, session_id, token)
        details: dict[str, object] = {
            "header_traits": headers,
            "client_traits": client_traits,
            "consistency": consistency,
            "high_entropy_traits_used": high_entropy,
        }
        details["fingerprint_id"] = _session_fingerprint(
            row.token_hash, "browser", details
        )
        await session.execute(
            delete(IPCheckObservationRow).where(
                IPCheckObservationRow.session_id == row.session_id,
                IPCheckObservationRow.kind == "browser_fingerprint",
            )
        )
        session.add(
            IPCheckObservationRow(
                session_id=row.session_id,
                kind="browser_fingerprint",
                details=details,
            )
        )
        await session.commit()
        expires_at = _utc(row.expires_at)
    return IPCheckBrowserFingerprintReport(
        fingerprint_id=str(details["fingerprint_id"]),
        expires_at=expires_at,
        header_traits=headers,
        client_traits=client_traits,
        consistency=consistency,
        high_entropy_traits_used=high_entropy,
        provenance={
            "header_traits": IPCheckEvidenceProvenance.SERVER_OBSERVED,
            "client_traits": IPCheckEvidenceProvenance.CLIENT_DECLARED,
        },
    )


async def observe_agent_fingerprint(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    session_id: str,
    token: str,
    observation: IPCheckAgentFingerprintRequest,
) -> IPCheckAgentFingerprintReport:
    async with session_factory() as session:
        row = await _authorized_session(session, session_id, token)
        identity_verified = False
        identity_subject = observation.wallet_address
        if observation.wallet_address and observation.wallet_signature:
            identity_verified = verify_agent_wallet_signature(
                session_id=session_id,
                expires_at=row.expires_at,
                wallet_address=observation.wallet_address,
                wallet_signature=observation.wallet_signature,
            )
        runtime: dict[str, object] = {
            key: value
            for key, value in {
                "name": observation.runtime,
                "version": observation.runtime_version,
                "operating_system": observation.operating_system,
                "architecture": observation.architecture,
                "protocol": observation.protocol.value,
            }.items()
            if value is not None
        }
        model_claim = {
            key: value
            for key, value in {
                "vendor": observation.model_vendor_claim,
                "model": observation.model_name_claim,
            }.items()
            if value is not None
        }
        assurance = (
            IPCheckEvidenceProvenance.SIGNED
            if identity_verified
            else IPCheckEvidenceProvenance.CLIENT_DECLARED
        )
        details: dict[str, object] = {
            "runtime": runtime,
            "capabilities": observation.capabilities,
            "model_claim": model_claim,
            "identity_subject": identity_subject,
            "identity_verified": identity_verified,
            "identity_assurance": assurance.value,
        }
        # The proof itself is verified in memory and never persisted.
        details["fingerprint_id"] = _session_fingerprint(row.token_hash, "agent", details)
        await session.execute(
            delete(IPCheckObservationRow).where(
                IPCheckObservationRow.session_id == row.session_id,
                IPCheckObservationRow.kind == "agent_fingerprint",
            )
        )
        session.add(
            IPCheckObservationRow(
                session_id=row.session_id,
                kind="agent_fingerprint",
                details=details,
            )
        )
        await session.commit()
        expires_at = _utc(row.expires_at)
    return IPCheckAgentFingerprintReport(
        fingerprint_id=str(details["fingerprint_id"]),
        expires_at=expires_at,
        runtime=runtime,
        capabilities=observation.capabilities,
        model_claim=model_claim,
        identity_subject=identity_subject,
        identity_verified=identity_verified,
        identity_assurance=assurance,
        provenance={
            "runtime": IPCheckEvidenceProvenance.CLIENT_DECLARED,
            "capabilities": IPCheckEvidenceProvenance.CLIENT_DECLARED,
            "model_claim": IPCheckEvidenceProvenance.CLIENT_DECLARED,
            "identity": assurance,
        },
    )


def verify_dns_observer_signature(
    config: IPCheckConfig,
    *,
    timestamp: str,
    signature: str,
    body: bytes,
) -> bool:
    if not config.dns_observer_secret or not timestamp.isdigit():
        return False
    now = int(time.time())
    if abs(now - int(timestamp)) > config.dns_observer_clock_skew_seconds:
        return False
    signed = timestamp.encode() + b"." + body
    expected = hmac.new(
        config.dns_observer_secret.encode(), signed, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature.lower())


async def observe_dns_resolver(
    session_factory: async_sessionmaker[AsyncSession],
    observation: IPCheckDNSObservationRequest,
) -> bool:
    async with session_factory() as session:
        row = await session.scalar(
            select(IPCheckSessionRow).where(
                IPCheckSessionRow.dns_label == observation.dns_label,
                IPCheckSessionRow.expires_at > datetime.now(UTC),
            )
        )
        if row is None:
            return False
        parsed = ipaddress.ip_address(observation.resolver_address)
        existing = await session.scalar(
            select(IPCheckObservationRow.id).where(
                IPCheckObservationRow.session_id == row.session_id,
                IPCheckObservationRow.kind == "dns",
                IPCheckObservationRow.address == str(parsed),
            )
        )
        if existing is None:
            session.add(
                IPCheckObservationRow(
                    session_id=row.session_id,
                    kind="dns",
                    address=str(parsed),
                    family=parsed.version,
                    details={"query_name": observation.query_name}
                    if observation.query_name
                    else None,
                    observed_at=observation.observed_at or datetime.now(UTC),
                )
            )
            await session.commit()
        return True


def _dns_leak_status(resolvers: list[str], expected: list[str]) -> str:
    if not resolvers:
        return "inconclusive"
    if not expected:
        return "not_assessed"
    expected_networks = [ipaddress.ip_network(value) for value in expected]
    unexpected = [
        value
        for value in resolvers
        if not any(ipaddress.ip_address(value) in network for network in expected_networks)
    ]
    return "possible_leak" if unexpected else "no_leak"


def _webrtc_leak_status(
    status: IPCheckWebRTCStatus | None,
    candidates: list[str],
    https_addresses: list[str],
) -> str:
    if status != IPCheckWebRTCStatus.COLLECTED or not candidates or not https_addresses:
        return "inconclusive"
    return "possible_leak" if set(candidates) - set(https_addresses) else "no_leak"


def _adapter_status(
    observations: list[IPCheckObservationRow], kind: str
) -> IPCheckWebRTCStatus | None:
    for item in observations:
        if item.kind != f"{kind}_status" or not item.details:
            continue
        raw_status = item.details.get("status")
        try:
            return (
                IPCheckWebRTCStatus(raw_status)
                if isinstance(raw_status, str)
                else IPCheckWebRTCStatus.FAILED
            )
        except (TypeError, ValueError):
            return IPCheckWebRTCStatus.FAILED
    return None


def _browser_fingerprint_report(
    observations: list[IPCheckObservationRow], expires_at: datetime
) -> IPCheckBrowserFingerprintReport | None:
    item = next(
        (entry for entry in observations if entry.kind == "browser_fingerprint"), None
    )
    if item is None or not item.details:
        return None
    details = item.details
    return IPCheckBrowserFingerprintReport(
        fingerprint_id=str(details.get("fingerprint_id", "")),
        expires_at=expires_at,
        header_traits=dict(details.get("header_traits") or {}),
        client_traits=dict(details.get("client_traits") or {}),
        consistency=dict(details.get("consistency") or {}),
        high_entropy_traits_used=bool(details.get("high_entropy_traits_used")),
        provenance={
            "header_traits": IPCheckEvidenceProvenance.SERVER_OBSERVED,
            "client_traits": IPCheckEvidenceProvenance.CLIENT_DECLARED,
        },
    )


def _agent_fingerprint_report(
    observations: list[IPCheckObservationRow], expires_at: datetime
) -> IPCheckAgentFingerprintReport | None:
    item = next(
        (entry for entry in observations if entry.kind == "agent_fingerprint"), None
    )
    if item is None or not item.details:
        return None
    details = item.details
    assurance = IPCheckEvidenceProvenance(
        str(
            details.get(
                "identity_assurance", IPCheckEvidenceProvenance.CLIENT_DECLARED.value
            )
        )
    )
    return IPCheckAgentFingerprintReport(
        fingerprint_id=str(details.get("fingerprint_id", "")),
        expires_at=expires_at,
        runtime=dict(details.get("runtime") or {}),
        capabilities=list(details.get("capabilities") or []),
        model_claim=dict(details.get("model_claim") or {}),
        identity_subject=(
            str(details["identity_subject"])
            if details.get("identity_subject") is not None
            else None
        ),
        identity_verified=bool(details.get("identity_verified")),
        identity_assurance=assurance,
        provenance={
            "runtime": IPCheckEvidenceProvenance.CLIENT_DECLARED,
            "capabilities": IPCheckEvidenceProvenance.CLIENT_DECLARED,
            "model_claim": IPCheckEvidenceProvenance.CLIENT_DECLARED,
            "identity": assurance,
        },
    )


async def get_ip_check_report(
    session_factory: async_sessionmaker[AsyncSession],
    config: IPCheckConfig,
    *,
    session_id: str,
    token: str,
) -> IPCheckSessionReport:
    async with session_factory() as session:
        row = await _authorized_session(session, session_id, token)
        observations = list(
            (
                await session.scalars(
                    select(IPCheckObservationRow)
                    .where(IPCheckObservationRow.session_id == row.session_id)
                    .order_by(IPCheckObservationRow.observed_at)
                )
            ).all()
        )
    https_v4 = sorted(
        {item.address for item in observations if item.kind == "https" and item.family == 4 and item.address}
    )
    https_v6 = sorted(
        {item.address for item in observations if item.kind == "https" and item.family == 6 and item.address}
    )
    dns_resolvers = sorted(
        {item.address for item in observations if item.kind == "dns" and item.address}
    )
    webrtc_addresses = sorted(
        {item.address for item in observations if item.kind == "webrtc" and item.address}
    )
    stun_addresses = sorted(
        {item.address for item in observations if item.kind == "stun" and item.address}
    )
    webrtc_status = _adapter_status(observations, "webrtc")
    stun_status = _adapter_status(observations, "stun")
    all_https = https_v4 + https_v6
    expires_at = _utc(row.expires_at)
    return IPCheckSessionReport(
        session_id=session_id,
        expires_at=expires_at,
        https_ipv4_addresses=https_v4,
        https_ipv6_addresses=https_v6,
        dns_resolver_addresses=dns_resolvers,
        webrtc_public_addresses=webrtc_addresses,
        webrtc_status=webrtc_status,
        stun_public_addresses=stun_addresses,
        stun_status=stun_status,
        ipv4_status="observed" if https_v4 else "not_observed",
        ipv6_status="observed" if https_v6 else "not_observed",
        webrtc_leak_status=_webrtc_leak_status(
            webrtc_status, webrtc_addresses, all_https
        ),
        nat_egress_status=_webrtc_leak_status(stun_status, stun_addresses, all_https),
        dns_leak_status=_dns_leak_status(
            dns_resolvers, list(row.expected_dns_resolvers or [])
        ),
        dns_expectation_configured=bool(row.expected_dns_resolvers),
        browser_fingerprint=_browser_fingerprint_report(observations, expires_at),
        agent_fingerprint=_agent_fingerprint_report(observations, expires_at),
        retention_seconds=config.session_ttl_seconds,
    )
