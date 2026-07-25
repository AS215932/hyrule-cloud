"""DB-backed Prometheus exposition for payments and fleet counters.

Aggregates the payment_events ledger plus VM/domain tables into Prometheus
text format. DB-backed rather than prometheus_client on purpose: uvicorn runs
multiple workers, and Postgres aggregates give every worker the same answer
with no multiprocess-registry lifecycle. The values are cumulative counts from
append-only/monotonic sources, so counter semantics (rate/increase) hold.

Auth: 8402 is also the public API port behind Caddy, so this endpoint is
disabled unless HYRULE_METRICS_TOKEN is set, and then requires
`Authorization: Bearer <token>` (mon's Prometheus sends it via
credentials_file).
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Request, Response
from sqlalchemy import func, select

from hyrule_cloud.db import DomainRow, PaymentEventRow, VMRow
from hyrule_cloud.models import VMStatus

router = APIRouter(tags=["Observability"])

_CACHE_TTL_SECONDS = 10.0
_cache: dict[str, tuple[float, str]] = {}


def _esc(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _metric(lines: list[str], name: str, help_text: str, kind: str) -> None:
    lines.append(f"# HELP {name} {help_text}")
    lines.append(f"# TYPE {name} {kind}")


def _render_dns_product_metrics(lines: list[str], state: Any | None) -> None:
    blocklists = getattr(state, "dns_blocklists", None)
    if blocklists is not None and hasattr(blocklists, "metrics_snapshot"):
        snapshot = blocklists.metrics_snapshot()
        catalog = snapshot["catalog"]
        _metric(
            lines,
            "hyrule_dns_blocklist_ready",
            "Whether the compiled blocklist snapshot meets the paid-product evidence floor.",
            "gauge",
        )
        lines.append(f"hyrule_dns_blocklist_ready {1 if catalog.ready else 0}")
        _metric(
            lines,
            "hyrule_dns_blocklist_usable_sources",
            "Usable blocklist sources in the current catalog snapshot.",
            "gauge",
        )
        lines.append(
            f"hyrule_dns_blocklist_usable_sources {catalog.usable_source_count}"
        )
        _metric(
            lines,
            "hyrule_dns_blocklist_source_age_seconds",
            "Age of the last successful source validation.",
            "gauge",
        )
        _metric(
            lines,
            "hyrule_dns_blocklist_source_rules",
            "Compiled rules by blocklist source.",
            "gauge",
        )
        for source in catalog.sources:
            status = getattr(source.status, "value", source.status)
            if source.age_seconds is not None:
                lines.append(
                    f'hyrule_dns_blocklist_source_age_seconds{{source_id="{_esc(source.source_id)}",'
                    f'status="{_esc(status)}"}} {source.age_seconds}'
                )
            lines.append(
                f'hyrule_dns_blocklist_source_rules{{source_id="{_esc(source.source_id)}"}} '
                f"{source.rule_count}"
            )
        _metric(
            lines,
            "hyrule_dns_blocklist_checks_total",
            "Delivered blocklist checks by verdict.",
            "counter",
        )
        for verdict, count in snapshot["checks"].items():
            lines.append(
                f'hyrule_dns_blocklist_checks_total{{verdict="{_esc(verdict)}"}} {count}'
            )
        _metric(
            lines,
            "hyrule_dns_blocklist_lookup_latency_ms",
            "Cumulative local blocklist lookup latency and sample count.",
            "summary",
        )
        lines.append(
            "hyrule_dns_blocklist_lookup_latency_ms_sum "
            f'{snapshot["lookup_latency_ms_total"]}'
        )
        lines.append(
            f'hyrule_dns_blocklist_lookup_latency_ms_count {snapshot["lookup_samples"]}'
        )

    filtering = getattr(state, "dns_filtering", None)
    if filtering is not None and hasattr(filtering, "metrics_snapshot"):
        snapshot = filtering.metrics_snapshot()
        _metric(
            lines,
            "hyrule_dns_filtering_checks_total",
            "Delivered live DNS filtering checks by aggregate result.",
            "counter",
        )
        for result, count in snapshot["overall"].items():
            lines.append(
                f'hyrule_dns_filtering_checks_total{{result="{_esc(result)}"}} {count}'
            )
        _metric(
            lines,
            "hyrule_dns_filtering_profile_results_total",
            "DNS filtering profile outcomes.",
            "counter",
        )
        for key, count in snapshot["profiles"].items():
            profile_id, status = key.split("|", 1)
            lines.append(
                f'hyrule_dns_filtering_profile_results_total{{profile_id="{_esc(profile_id)}",'
                f'status="{_esc(status)}"}} {count}'
            )
        _metric(
            lines,
            "hyrule_dns_filtering_profile_latency_ms",
            "Cumulative filtered DoH latency and sample count by profile.",
            "summary",
        )
        totals = snapshot["profile_latency_ms_total"]
        samples = snapshot["profile_latency_samples"]
        for profile_id, total in totals.items():
            lines.append(
                f'hyrule_dns_filtering_profile_latency_ms_sum{{profile_id="{_esc(profile_id)}"}} '
                f"{total}"
            )
            lines.append(
                f'hyrule_dns_filtering_profile_latency_ms_count{{profile_id="{_esc(profile_id)}"}} '
                f"{samples.get(profile_id, 0)}"
            )


async def _render(session_factory: Any, state: Any | None = None) -> str:
    lines: list[str] = []
    now = datetime.now(UTC)
    async with session_factory() as session:
        _metric(
            lines,
            "hyrule_payment_events_total",
            "x402 payment-gate outcomes from the payment_events ledger.",
            "counter",
        )
        rows = (
            await session.execute(
                select(
                    PaymentEventRow.event_type,
                    PaymentEventRow.service_group,
                    PaymentEventRow.network,
                    func.count(),
                ).group_by(
                    PaymentEventRow.event_type,
                    PaymentEventRow.service_group,
                    PaymentEventRow.network,
                )
            )
        ).all()
        for event_type, group, network, count in rows:
            lines.append(
                f'hyrule_payment_events_total{{event_type="{_esc(event_type)}",'
                f'service_group="{_esc(group)}",network="{_esc(network or "")}"}} {count}'
            )

        _metric(
            lines,
            "hyrule_payment_revenue_usd_total",
            "Settled x402 revenue in USD.",
            "counter",
        )
        rows = (
            await session.execute(
                select(
                    PaymentEventRow.service_group,
                    PaymentEventRow.network,
                    func.sum(PaymentEventRow.amount_usd),
                )
                .where(PaymentEventRow.event_type == "settled")
                .group_by(PaymentEventRow.service_group, PaymentEventRow.network)
            )
        ).all()
        for group, network, total in rows:
            lines.append(
                f'hyrule_payment_revenue_usd_total{{service_group="{_esc(group)}",'
                f'network="{_esc(network or "")}"}} {total or 0}'
            )

        _metric(
            lines,
            "hyrule_payment_unique_payers",
            "Distinct wallets that have settled at least one payment (all time).",
            "gauge",
        )
        unique_all = (
            await session.execute(
                select(func.count(func.distinct(PaymentEventRow.payer_wallet))).where(
                    PaymentEventRow.event_type == "settled",
                    PaymentEventRow.payer_wallet.is_not(None),
                )
            )
        ).scalar_one()
        lines.append(f"hyrule_payment_unique_payers {unique_all}")

        _metric(
            lines,
            "hyrule_payment_unique_payers_24h",
            "Distinct wallets that settled a payment in the last 24 hours.",
            "gauge",
        )
        unique_24h = (
            await session.execute(
                select(func.count(func.distinct(PaymentEventRow.payer_wallet))).where(
                    PaymentEventRow.event_type == "settled",
                    PaymentEventRow.payer_wallet.is_not(None),
                    PaymentEventRow.created_at >= now - timedelta(hours=24),
                )
            )
        ).scalar_one()
        lines.append(f"hyrule_payment_unique_payers_24h {unique_24h}")

        _metric(
            lines,
            "hyrule_vms_active",
            "Live VMs by lifecycle status (destroyed/failed rows are retained "
            "in the DB but excluded here so the gauge tracks the actual fleet).",
            "gauge",
        )
        rows = (
            await session.execute(
                select(VMRow.status, func.count())
                .where(VMRow.status.notin_([VMStatus.DESTROYED, VMStatus.FAILED]))
                .group_by(VMRow.status)
            )
        ).all()
        for status, count in rows:
            value = getattr(status, "value", status)
            lines.append(f'hyrule_vms_active{{status="{_esc(value)}"}} {count}')

        _metric(
            lines,
            "hyrule_vm_provision_total",
            "VM provisioning outcomes: ready = ever reached provisioned; "
            "failed = errored before provisioning. Both monotonic (rows survive destroy).",
            "counter",
        )
        ready = (
            await session.execute(
                select(func.count()).select_from(VMRow).where(VMRow.provisioned_at.is_not(None))
            )
        ).scalar_one()
        failed = (
            await session.execute(
                select(func.count())
                .select_from(VMRow)
                .where(VMRow.error.is_not(None), VMRow.provisioned_at.is_(None))
            )
        ).scalar_one()
        lines.append(f'hyrule_vm_provision_total{{result="ready"}} {ready}')
        lines.append(f'hyrule_vm_provision_total{{result="failed"}} {failed}')

        _metric(lines, "hyrule_domains_total", "Registered domains by status.", "gauge")
        rows = (
            await session.execute(select(DomainRow.status, func.count()).group_by(DomainRow.status))
        ).all()
        for status, count in rows:
            value = getattr(status, "value", status)
            lines.append(f'hyrule_domains_total{{status="{_esc(value)}"}} {count}')

    _render_dns_product_metrics(lines, state)

    return "\n".join(lines) + "\n"


@router.get("/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    state = getattr(request.app.state, "_typed_state", None)
    config = getattr(state, "config", None)
    session_factory = getattr(state, "session_factory", None)
    token = getattr(config, "metrics_token", "") if config is not None else ""
    if not token or session_factory is None:
        # Disabled unless explicitly configured — this port is publicly reachable.
        return Response(status_code=404)
    if request.headers.get("Authorization", "") != f"Bearer {token}":
        return Response(status_code=401, headers={"WWW-Authenticate": "Bearer"})

    now = time.monotonic()
    cached = _cache.get("body")
    if cached is not None and now - cached[0] < _CACHE_TTL_SECONDS:
        body = cached[1]
    else:
        body = await _render(session_factory, state)
        _cache["body"] = (now, body)
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")
