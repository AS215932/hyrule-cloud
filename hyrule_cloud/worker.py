"""Dedicated scheduler/outbox worker for lifecycle and payment side effects."""

from __future__ import annotations

import asyncio
import logging
import signal
import socket
import sys
from datetime import UTC, datetime, timedelta

import structlog

from hyrule_cloud.config import HyruleConfig
from hyrule_cloud.db import create_db_engine, create_session_factory, init_db
from hyrule_cloud.domains.service import DomainService
from hyrule_cloud.logging_config import SAFE_DICT_TRACEBACKS
from hyrule_cloud.orchestrator import Orchestrator
from hyrule_cloud.providers.native_crypto import NativeCryptoProvider
from hyrule_cloud.providers.rates import RateProvider
from hyrule_cloud.services.admin_operations import process_admin_operations
from hyrule_cloud.services.intents import scan_pending_intents

structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True, key="ts"),
        SAFE_DICT_TRACEBACKS,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
    cache_logger_on_first_use=True,
)

log = structlog.get_logger().bind(service="hyrule-cloud-worker")


async def run_worker() -> None:
    config = HyruleConfig()
    engine = create_db_engine(config.database_url)
    await init_db(engine)
    sessions = create_session_factory(engine)
    orchestrator = Orchestrator(config, sessions)
    rates = RateProvider()
    native = NativeCryptoProvider(config.payment)
    await orchestrator.startup()
    await rates.start()
    await native.start()
    domains = DomainService(
        config,
        sessions,
        orchestrator.openprovider,
        rates,
        native,
        orchestrator,
    )
    orchestrator.domains = domains
    recovered_bundles = await domains.recover_bundle_provisioning()

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    now = datetime.now(UTC)
    next_intents = now
    next_payment_handoffs = now
    next_jobs = now
    next_expiry = now
    next_quotes = now
    next_catalog = now
    next_reconcile = now
    next_renewal_state = now
    next_admin_operations = now
    worker_id = f"{socket.gethostname()}:{id(stop)}"
    log.info(
        "worker_started",
        worker_id=worker_id,
        recovered_bundle_vms=recovered_bundles,
    )
    try:
        while not stop.is_set():
            now = datetime.now(UTC)
            if now >= next_intents:
                try:
                    await scan_pending_intents(
                        session_factory=sessions,
                        provider=native,
                        rates=rates,
                        orch=orchestrator,
                    )
                except Exception:
                    log.exception("intent_scan_failed")
                next_intents = now + timedelta(seconds=15)
            if now >= next_payment_handoffs:
                try:
                    await domains.recover_x402_handoffs()
                except Exception:
                    log.exception("domain_payment_handoff_recovery_failed")
                next_payment_handoffs = now + timedelta(seconds=15)
            if now >= next_jobs:
                try:
                    await domains.process_jobs(worker_id=worker_id, limit=20)
                except Exception:
                    log.exception("domain_jobs_failed")
                next_jobs = now + timedelta(seconds=config.domain.worker_poll_seconds)
            if now >= next_admin_operations:
                try:
                    await process_admin_operations(sessions, orchestrator, limit=10)
                except Exception:
                    log.exception("admin_operations_failed")
                next_admin_operations = now + timedelta(seconds=5)
            if now >= next_expiry:
                try:
                    await orchestrator.check_expiries()
                except Exception:
                    log.exception("vm_expiry_scan_failed")
                next_expiry = now + timedelta(minutes=5)
            if now >= next_quotes:
                try:
                    await domains.expire_quotes()
                except Exception:
                    log.exception("domain_quote_expiry_failed")
                next_quotes = now + timedelta(minutes=1)
            if now >= next_catalog:
                try:
                    if config.domain.enabled:
                        await domains.catalog.sync()
                except Exception:
                    log.exception("domain_catalog_sync_failed")
                next_catalog = now + timedelta(seconds=config.domain.catalog_sync_seconds)
            if now >= next_reconcile:
                try:
                    await domains.reconcile_pending()
                except Exception:
                    log.exception("domain_reconciliation_failed")
                next_reconcile = now + timedelta(days=1)
            if now >= next_renewal_state:
                try:
                    await domains.refresh_renewal_states()
                except Exception:
                    log.exception("domain_renewal_state_refresh_failed")
                next_renewal_state = now + timedelta(hours=1)
            try:
                await asyncio.wait_for(stop.wait(), timeout=1.0)
            except TimeoutError:
                pass
    finally:
        await domains.close()
        await native.close()
        await rates.close()
        await orchestrator.shutdown()
        await engine.dispose()
        log.info("worker_stopped")


def main() -> None:
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
