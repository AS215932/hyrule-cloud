"""Mail deliverability helpers layered on top of /v1/mx diagnostics."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from hyrule_cloud.models import (
    DiagnosticStatus,
    DNSLookupRecordType,
    MailBounceClassification,
    MailBounceParseRequest,
    MailBounceParseResponse,
    MailRecordRecommendation,
    MailRecordRecommendationRequest,
    MailRecordRecommendationResponse,
)

_SMTP_RE = re.compile(r"\b([245][0-9]{2})(?:[ .-]([245]\.[0-9]\.[0-9]{1,3}))?\b")
_REMOTE_MTA_RE = re.compile(r"(?:remote mta|reporting-mta|diagnostic-code|mx):\s*([^\s;]+)", re.IGNORECASE)


def parse_bounce(body: MailBounceParseRequest) -> MailBounceParseResponse:
    text = body.message
    lower = text.lower()
    smtp = _smtp_status(text)
    classification = MailBounceClassification.UNKNOWN
    causes: list[str] = []
    actions: list[str] = []

    if any(token in lower for token in ["spf", "dkim", "dmarc", "5.7.26", "authentication failed", "unauthenticated"]):
        classification = MailBounceClassification.AUTH_FAILURE
        causes.append("Remote system rejected the message because sender authentication failed or aligned poorly.")
        actions.extend([
            "Run /v1/mx/reports/mail-delivery for the sender domain.",
            "Verify SPF, DKIM signing, and DMARC alignment for the sending domain.",
        ])
    elif any(token in lower for token in ["policy", "blocked", "rejected", "blacklist", "spam", "5.7."]):
        classification = MailBounceClassification.POLICY_REJECTION
        causes.append("Remote system applied policy, reputation, or content filtering.")
        actions.extend([
            "Check sender IP/domain reputation and DNS authentication.",
            "Ask the recipient provider for the exact policy reason if logs are available.",
        ])
    elif any(token in lower for token in ["mailbox full", "quota", "over quota", "insufficient storage"]):
        classification = MailBounceClassification.MAILBOX_FULL
        causes.append("Recipient mailbox or quota appears full.")
        actions.append("Ask recipient to free space or use an alternate recipient address.")
    elif any(token in lower for token in ["rate", "temporarily deferred", "try again later", "4.7.", "421", "451"]):
        classification = MailBounceClassification.RATE_LIMITED
        causes.append("Remote system temporarily deferred or rate-limited delivery.")
        actions.append("Retry with normal MTA backoff and check sender reputation if deferrals persist.")
    elif any(token in lower for token in ["dns", "host not found", "no mx", "servfail", "nxdomain"]):
        classification = MailBounceClassification.DNS_FAILURE
        causes.append("A DNS lookup needed for delivery failed.")
        actions.append("Check recipient MX, sender SPF includes, and DNSSEC if present.")
    elif any(token in lower for token in ["tls", "certificate", "starttls", "mta-sts"]):
        classification = MailBounceClassification.TLS_FAILURE
        causes.append("TLS, certificate, STARTTLS, or MTA-STS policy failure is indicated.")
        actions.append("Check SMTP TLS and MTA-STS/TLS-RPT records for both domains.")

    if not causes:
        causes.append("The bounce did not contain enough structured evidence for confident classification.")
        actions.append("Run MX, SMTP, SPF, DKIM, DMARC, DNS, blacklist, and WHOIS checks for the sender and recipient domains.")

    remote_mta = _remote_mta(text)
    status = DiagnosticStatus.WARNING if classification != MailBounceClassification.UNKNOWN else DiagnosticStatus.INFO
    return MailBounceParseResponse(
        status=status,
        classification=classification,
        smtp_status=smtp,
        remote_mta=remote_mta,
        probable_causes=causes,
        recommended_actions=actions,
        evidence={
            "sender_domain": body.context.sender_domain,
            "recipient_domain": body.context.recipient_domain,
            "message_excerpt": text[:2048],
        },
        generated_at=datetime.now(UTC),
    )


def recommend_records(body: MailRecordRecommendationRequest) -> MailRecordRecommendationResponse:
    domain = body.domain.rstrip(".").lower()
    warnings: list[str] = []
    mechanisms: list[str] = []
    for ip in body.sending_ips:
        if ":" in ip:
            mechanisms.append(f"ip6:{ip}")
        else:
            mechanisms.append(f"ip4:{ip}")
    for host in body.sending_hosts:
        mechanisms.append(f"a:{host.rstrip('.')}")
    provider = body.provider.lower()
    if provider in {"google_workspace", "google"}:
        mechanisms.append("include:_spf.google.com")
    elif provider in {"m365", "office365", "microsoft365"}:
        mechanisms.append("include:spf.protection.outlook.com")
    elif provider == "hyrule":
        mechanisms.append("include:_spf.hyrule.host")
    if not mechanisms:
        mechanisms.append("mx")
        warnings.append("No explicit sending IPs/hosts were supplied; SPF recommendation falls back to mx.")

    records = [
        MailRecordRecommendation(
            type=DNSLookupRecordType.TXT,
            name=domain,
            value=f"v=spf1 {' '.join(mechanisms)} -all",
            purpose="SPF sender authorization",
            notes="Keep total SPF DNS lookups at or below 10.",
        ),
        MailRecordRecommendation(
            type=DNSLookupRecordType.TXT,
            name=f"_dmarc.{domain}",
            value=f"v=DMARC1; p={body.policy.dmarc}; rua=mailto:dmarc@{domain}; ruf=mailto:dmarc@{domain}; adkim=s; aspf=s",
            purpose="DMARC alignment and reporting",
            notes="Start with p=none if you are not ready to enforce.",
        ),
        MailRecordRecommendation(
            type=DNSLookupRecordType.TXT,
            name=f"default._domainkey.{domain}",
            value="v=DKIM1; k=rsa; p=<publish-provider-public-key-here>",
            purpose="DKIM public key placeholder",
            notes="Replace with the exact selector and key from the sending platform.",
        ),
    ]
    if body.policy.tls_reporting:
        records.append(
            MailRecordRecommendation(
                type=DNSLookupRecordType.TXT,
                name=f"_smtp._tls.{domain}",
                value=f"v=TLSRPTv1; rua=mailto:tlsrpt@{domain}",
                purpose="SMTP TLS reporting",
            )
        )
    if body.policy.mta_sts:
        records.append(
            MailRecordRecommendation(
                type=DNSLookupRecordType.TXT,
                name=f"_mta-sts.{domain}",
                value="v=STSv1; id=2026061301",
                purpose="MTA-STS policy discovery",
                notes=f"Also serve https://mta-sts.{domain}/.well-known/mta-sts.txt.",
            )
        )
    if body.policy.bimi:
        records.append(
            MailRecordRecommendation(
                type=DNSLookupRecordType.TXT,
                name=f"default._bimi.{domain}",
                value="v=BIMI1; l=https://example.com/bimi.svg; a=https://example.com/vmc.pem",
                purpose="BIMI logo assertion",
                notes="Requires DMARC enforcement and provider-specific VMC support.",
            )
        )
    return MailRecordRecommendationResponse(
        domain=domain,
        provider=body.provider,
        records=records,
        warnings=warnings,
        generated_at=datetime.now(UTC),
    )


def _smtp_status(text: str) -> str | None:
    match = _SMTP_RE.search(text)
    if not match:
        return None
    return " ".join(part for part in match.groups() if part)


def _remote_mta(text: str) -> str | None:
    match = _REMOTE_MTA_RE.search(text)
    if match:
        return match.group(1).strip().strip(";,.<>")
    return None
