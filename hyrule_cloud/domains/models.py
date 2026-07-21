from __future__ import annotations

import enum
import secrets
import string
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Literal

from bip_utils import (
    P2PKHAddrDecoder,
    P2SHAddrDecoder,
    SegwitBech32Decoder,
    XmrAddrDecoder,
)
from pydantic import BaseModel, Field, StringConstraints, field_validator, model_validator

_ALPHABET = string.ascii_letters + string.digits


def _valid_btc_mainnet_address(address: str) -> bool:
    """Accept checksummed legacy and SegWit Bitcoin mainnet addresses."""
    try:
        SegwitBech32Decoder.Decode("bc", address)
        return True
    except (TypeError, ValueError):
        pass
    for decoder, network_version in (
        (P2PKHAddrDecoder, b"\x00"),
        (P2SHAddrDecoder, b"\x05"),
    ):
        try:
            decoder.DecodeAddr(address, net_ver=network_version)
            return True
        except (TypeError, ValueError):
            continue
    return False


def _valid_xmr_mainnet_address(address: str) -> bool:
    """Accept checksummed standard and subaddress Monero mainnet addresses."""
    for decoder, network_version in (
        (XmrAddrDecoder, b"\x12"),
        (XmrAddrDecoder, b"\x2a"),
    ):
        try:
            decoder.DecodeAddr(address, net_ver=network_version)
            return True
        except (TypeError, ValueError):
            continue
    return False


def _id(prefix: str) -> str:
    return prefix + "".join(secrets.choice(_ALPHABET) for _ in range(22))


def generate_domain_quote_id() -> str:
    return _id("dq_")


def generate_domain_order_id() -> str:
    return _id("do_")


def generate_domain_registration_id() -> str:
    return _id("dr_")


def generate_domain_status_id() -> str:
    return _id("ds_")


def generate_domain_operation_id() -> str:
    return _id("dop_")


def generate_domain_job_id() -> str:
    return _id("djob_")


class DomainAction(enum.StrEnum):
    REGISTER = "register"
    RENEW = "renew"


class DomainOrderStatus(enum.StrEnum):
    AWAITING_PAYMENT = "awaiting_payment"
    PAID = "paid"
    QUEUED = "queued"
    CHECKING = "checking"
    SUBMITTING = "submitting"
    PROVIDER_PENDING = "provider_pending"
    ACTIVE = "active"
    FAILED = "failed"
    REFUND_DUE = "refund_due"
    REFUNDED = "refunded"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class DomainOperationStatus(enum.StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_PROVIDER = "waiting_provider"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class NameserverMode(enum.StrEnum):
    MANAGED = "managed"
    EXTERNAL = "external"


class DNSSECMode(enum.StrEnum):
    MANAGED = "managed"
    EXTERNAL = "external"
    OFF = "off"


class DomainPaymentMethod(enum.StrEnum):
    USDC = "usdc"
    BTC = "btc"
    XMR = "xmr"


class DomainFailurePolicy(enum.StrEnum):
    KEEP_VM = "keep_vm"
    CANCEL_BUNDLE = "cancel_bundle"


class DNSChangeAction(enum.StrEnum):
    UPSERT = "upsert"
    DELETE = "delete"


class ManagedRecordType(enum.StrEnum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    CAA = "CAA"
    SRV = "SRV"
    NS = "NS"
    TLSA = "TLSA"
    SVCB = "SVCB"
    HTTPS = "HTTPS"


FQDN = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=253)]


class MoneyBreakdown(BaseModel):
    provider_cost_usd: str
    hyrule_fee_usd: str
    tax_usd: str = "0.00"
    total_usd: str
    currency: Literal["USD"] = "USD"


class DomainTLDSummary(BaseModel):
    tld: str
    registration: MoneyBreakdown
    renewal: MoneyBreakdown
    refreshed_at: datetime


class DomainTLDListResponse(BaseModel):
    tlds: list[DomainTLDSummary]
    refreshed_at: datetime | None = None


class DomainCheckResponse(BaseModel):
    domain: str
    eligible: bool
    available: bool | None
    premium: bool | None = None
    reason: str | None = None
    registration: MoneyBreakdown | None = None
    renewal: MoneyBreakdown | None = None
    checked_at: datetime


class DomainQuoteRequest(BaseModel):
    domain: FQDN
    action: DomainAction = DomainAction.REGISTER


class DomainQuoteResponse(BaseModel):
    quote_id: str
    domain: str
    action: DomainAction
    period_years: Literal[1] = 1
    price: MoneyBreakdown
    available: bool
    expires_at: datetime
    terms_version: str


class DomainRegistrationRequest(BaseModel):
    """One-year, wallet-owned registration sold through x402."""

    domain: FQDN
    client_order_id: str = Field(min_length=16, max_length=128)
    accept_terms: Literal[True]
    quote_id: str | None = Field(default=None, min_length=8, max_length=40)
    max_price_usd: Decimal | None = Field(default=None, ge=Decimal("0"))


class DomainRegistrationResponse(BaseModel):
    registration_id: str
    order_id: str
    domain: str
    status: str
    amount_usd: str
    owner_wallet: str
    terms_version: str
    status_url: str
    management_url: str
    operation_id: str | None = None
    created_at: datetime
    updated_at: datetime


class DomainRegistrationStatusResponse(BaseModel):
    registration_id: str
    domain: str
    status: str
    operation_id: str | None = None
    created_at: datetime
    updated_at: datetime


class DomainSalesStatusResponse(BaseModel):
    enabled: bool
    registration_period_years: Literal[1] = 1
    payment_method: Literal["USDC"] = "USDC"
    terms_version: str
    minimum_hyrule_fee_usd: str
    eligible_tld_count: int
    max_registrations_per_wallet_24h: int


class NativePaymentInstructions(BaseModel):
    intent_id: str
    asset: Literal["BTC", "XMR"]
    address: str
    amount_crypto: str
    amount_usd: str
    qr_code_uri: str
    rate_valid_until: datetime | None = None
    expires_at: datetime


class DomainOrderRequest(BaseModel):
    quote_id: str = Field(min_length=8, max_length=40)
    payment_method: DomainPaymentMethod = DomainPaymentMethod.USDC
    refund_address: str | None = Field(default=None, min_length=14, max_length=128)
    terms_version: str = Field(min_length=1, max_length=64)
    vm_quote_id: str | None = Field(default=None, min_length=8, max_length=40)
    on_domain_failure: DomainFailurePolicy = DomainFailurePolicy.KEEP_VM

    @model_validator(mode="after")
    def require_native_refund_address(self) -> DomainOrderRequest:
        if self.payment_method in (DomainPaymentMethod.BTC, DomainPaymentMethod.XMR):
            if not self.refund_address:
                raise ValueError("refund_address is required for BTC/XMR payments")
            address = self.refund_address.strip()
            valid = (
                _valid_btc_mainnet_address(address)
                if self.payment_method is DomainPaymentMethod.BTC
                else _valid_xmr_mainnet_address(address)
            )
            if not valid:
                raise ValueError(
                    f"refund_address must be a valid {self.payment_method.value.upper()} "
                    "mainnet address"
                )
            self.refund_address = address
        elif self.refund_address is not None:
            raise ValueError("refund_address is only accepted for BTC/XMR payments")
        return self


class DomainOrderResponse(BaseModel):
    order_id: str
    domain: str
    action: DomainAction
    status: DomainOrderStatus
    amount_usd: str
    payment_method: DomainPaymentMethod
    payment: NativePaymentInstructions | None = None
    operation_id: str | None = None
    vm_id: str | None = None
    error_code: str | None = None
    created_at: datetime
    updated_at: datetime


class DomainSummary(BaseModel):
    domain: str
    status: str
    expires_at: datetime | None
    renewal_notice_days: int | None = None
    nameserver_mode: NameserverMode
    nameservers: list[str]
    dnssec_mode: DNSSECMode
    dnssec_status: str


class DomainListResponse(BaseModel):
    domains: list[DomainSummary]


class DomainDetailResponse(DomainSummary):
    registered_at: datetime
    provider_status: str | None = None
    can_renew: bool = False
    can_transfer: bool = False
    linked_vm_id: str | None = None


class NameserverUpdateRequest(BaseModel):
    mode: NameserverMode
    nameservers: list[str] = Field(default_factory=list, max_length=13)

    @model_validator(mode="after")
    def validate_mode(self) -> NameserverUpdateRequest:
        if self.mode is NameserverMode.MANAGED and self.nameservers:
            raise ValueError("managed mode does not accept custom nameservers")
        if self.mode is NameserverMode.EXTERNAL and not (2 <= len(self.nameservers) <= 13):
            raise ValueError("external mode requires between 2 and 13 nameservers")
        return self


class DSRecord(BaseModel):
    key_tag: int = Field(ge=0, le=65535)
    algorithm: int = Field(ge=1, le=255)
    digest_type: int = Field(ge=1, le=255)
    digest: str = Field(pattern=r"^[0-9A-Fa-f]+$", min_length=16, max_length=256)


class DNSSECUpdateRequest(BaseModel):
    mode: DNSSECMode
    ds_records: list[DSRecord] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def validate_mode(self) -> DNSSECUpdateRequest:
        if self.mode is DNSSECMode.EXTERNAL and not self.ds_records:
            raise ValueError("external DNSSEC requires DS records")
        if self.mode is not DNSSECMode.EXTERNAL and self.ds_records:
            raise ValueError("DS records are only accepted in external mode")
        return self


class DNSRRSet(BaseModel):
    name: str = Field(default="@", max_length=253)
    type: ManagedRecordType
    ttl: int = Field(default=3600, ge=60, le=86400)
    values: list[str] = Field(min_length=1, max_length=64)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        value = value.strip().lower().rstrip(".")
        return value or "@"


class DNSChange(BaseModel):
    action: DNSChangeAction
    rrset: DNSRRSet


class DNSChangesetRequest(BaseModel):
    changes: list[DNSChange] = Field(min_length=1, max_length=100)


class DNSZoneResponse(BaseModel):
    domain: str
    revision: int
    records: list[DNSRRSet]
    dnssec_mode: DNSSECMode
    dnssec_status: str


class DomainOperationResponse(BaseModel):
    operation_id: str
    domain: str
    kind: str
    status: DomainOperationStatus
    error_code: str | None = None
    error_detail: str | None = None
    result: dict[str, Any] | None = None
    secret: str | None = Field(
        default=None,
        description="One-time transfer auth code; omitted after its first successful read.",
    )
    created_at: datetime
    updated_at: datetime


class DomainTransferOutRequest(BaseModel):
    nonce: str = Field(min_length=16, max_length=128)
    signature: str = Field(min_length=64, max_length=256)


class LegacyDomainClaimRequest(BaseModel):
    token: str = Field(pattern=r"^hyr_dom_", min_length=20, max_length=128)
