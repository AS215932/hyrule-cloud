"""Durable domain blocklist catalog, compiler, and read-only lookup service."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import sqlite3
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import structlog

from hyrule_cloud.config import DNSBlocklistConfig, HyruleConfig
from hyrule_cloud.models import (
    DNSBlocklistCategory,
    DNSBlocklistCheckResponse,
    DNSBlocklistSourceInfo,
    DNSBlocklistSourceOutcome,
    DNSBlocklistSourceResult,
    DNSBlocklistSourcesResponse,
    DNSBlocklistVerdict,
    SourceStatus,
)
from hyrule_cloud.services.dns.domain import domain_suffixes, normalize_domain

log = structlog.get_logger().bind(component="dns_blocklists")


class BlocklistUnavailableError(RuntimeError):
    """No snapshot meets the paid product's minimum evidence contract."""


@dataclass(frozen=True, slots=True)
class BlocklistSource:
    source_id: str
    name: str
    categories: tuple[DNSBlocklistCategory, ...]
    source_url: str
    license: str
    license_url: str
    format: str
    minimum_rules: int


def _source(
    source_id: str,
    name: str,
    categories: tuple[DNSBlocklistCategory, ...],
    source_url: str,
    license: str,
    license_url: str,
    format: str,
    minimum_rules: int,
) -> BlocklistSource:
    return BlocklistSource(
        source_id=source_id,
        name=name,
        categories=categories,
        source_url=source_url,
        license=license,
        license_url=license_url,
        format=format,
        minimum_rules=minimum_rules,
    )


_ADS = (DNSBlocklistCategory.ADS,)
_PRIVACY = (DNSBlocklistCategory.TRACKERS, DNSBlocklistCategory.TELEMETRY)
_ADS_PRIVACY = (DNSBlocklistCategory.ADS, *_PRIVACY)
_THREATS = (
    DNSBlocklistCategory.PHISHING,
    DNSBlocklistCategory.MALWARE,
    DNSBlocklistCategory.SCAM,
    DNSBlocklistCategory.C2,
)

BLOCKLIST_SOURCES: tuple[BlocklistSource, ...] = (
    _source(
        "easylist",
        "EasyList",
        _ADS,
        "https://easylist.to/easylist/easylist.txt",
        "GPL-3.0-or-later OR CC-BY-SA-3.0",
        "https://easylist.to/pages/licence.html",
        "adblock",
        1_000,
    ),
    _source(
        "easyprivacy",
        "EasyPrivacy",
        _PRIVACY,
        "https://easylist.to/easylist/easyprivacy.txt",
        "GPL-3.0-or-later OR CC-BY-SA-3.0",
        "https://easylist.to/pages/licence.html",
        "adblock",
        1_000,
    ),
    _source(
        "adguard_dns",
        "AdGuard DNS filter",
        (*_ADS_PRIVACY, DNSBlocklistCategory.MALWARE),
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "GPL-3.0",
        "https://github.com/AdguardTeam/AdGuardSDNSFilter/blob/master/LICENSE",
        "adblock-dns",
        20_000,
    ),
    _source(
        "oisd_big",
        "OISD Big",
        (*_ADS_PRIVACY, *_THREATS),
        "https://big.oisd.nl/",
        "GPL-3.0",
        "https://oisd.nl/faq",
        "adblock-dns",
        50_000,
    ),
    _source(
        "hagezi_pro",
        "HaGeZi Pro",
        (*_ADS_PRIVACY, DNSBlocklistCategory.MALWARE),
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/pro.txt",
        "GPL-3.0",
        "https://github.com/hagezi/dns-blocklists/blob/main/LICENSE",
        "domains",
        50_000,
    ),
    _source(
        "hagezi_tif_medium",
        "HaGeZi Threat Intelligence Feeds Medium",
        _THREATS,
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt",
        "GPL-3.0",
        "https://github.com/hagezi/dns-blocklists/blob/main/LICENSE",
        "adblock-dns",
        10_000,
    ),
    _source(
        "1hosts_lite",
        "1Hosts Lite",
        (*_ADS_PRIVACY, DNSBlocklistCategory.MALWARE),
        "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/domains.wildcards",
        "MPL-2.0",
        "https://github.com/badmojr/1Hosts/blob/master/LICENSE",
        "wildcard-domains",
        25_000,
    ),
    _source(
        "stevenblack_unified",
        "StevenBlack Unified hosts",
        (*_ADS_PRIVACY, DNSBlocklistCategory.MALWARE),
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "MIT",
        "https://github.com/StevenBlack/hosts/blob/master/license.txt",
        "hosts",
        25_000,
    ),
    _source(
        "hblock",
        "hBlock",
        (*_ADS_PRIVACY, DNSBlocklistCategory.MALWARE),
        "https://hblock.molinero.dev/hosts_domains.txt",
        "MIT",
        "https://github.com/hectorm/hblock/blob/master/LICENSE.md",
        "domains",
        25_000,
    ),
    *tuple(
        _source(
            f"blocklistproject_{source_id}",
            f"Block List Project: {display}",
            categories,
            f"https://blocklistproject.github.io/Lists/{source_id}.txt",
            "Unlicense",
            "https://github.com/blocklistproject/Lists/blob/master/LICENSE",
            "hosts",
            minimum,
        )
        for source_id, display, categories, minimum in (
            ("ads", "Ads", _ADS, 5_000),
            ("tracking", "Tracking", _PRIVACY, 1_000),
            ("abuse", "Abuse", (DNSBlocklistCategory.SCAM,), 100),
            ("malware", "Malware", (DNSBlocklistCategory.MALWARE,), 1_000),
            ("phishing", "Phishing", (DNSBlocklistCategory.PHISHING,), 1_000),
            ("ransomware", "Ransomware", (DNSBlocklistCategory.MALWARE,), 100),
            ("scam", "Scam", (DNSBlocklistCategory.SCAM,), 100),
        )
    ),
)


def catalog_version(sources: tuple[BlocklistSource, ...] = BLOCKLIST_SOURCES) -> str:
    payload = [
        {
            "id": source.source_id,
            "url": source.source_url,
            "categories": [category.value for category in source.categories],
            "license": source.license,
            "format": source.format,
        }
        for source in sources
    ]
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]
    return f"blcat_{digest}"


@dataclass(frozen=True, slots=True)
class ParsedRule:
    domain: str
    match_kind: str
    action: str


_HOSTS_IPS = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1"})
_ABP_RE = re.compile(r"^\|\|([^/^$|*]+)\^(?:\$([^\s]+))?$")
_RPZ_RE = re.compile(r"^(\*\.)?([^\s]+)\s+(?:\d+\s+)?(?:IN\s+)?CNAME\s+\.$", re.I)


def parse_rule_line(line: str) -> ParsedRule | None:
    """Parse only rules whose result is decidable from a domain name alone."""

    value = line.lstrip("\ufeff").strip()
    if not value or value.startswith(("!", "#", "[")):
        return None

    # Hosts sources may include an inline comment and more than one hostname.
    if "#" in value:
        value = value.split("#", 1)[0].strip()
    fields = value.split()
    if fields and fields[0] in _HOSTS_IPS:
        if len(fields) < 2 or fields[1].lower() in {"localhost", "localhost.localdomain"}:
            return None
        try:
            return ParsedRule(normalize_domain(fields[1]), "exact", "block")
        except ValueError:
            return None

    rpz = _RPZ_RE.fullmatch(value)
    if rpz:
        try:
            domain = normalize_domain(rpz.group(2))
        except ValueError:
            return None
        return ParsedRule(domain, "wildcard" if rpz.group(1) else "exact", "block")

    action = "block"
    if value.startswith("@@"):
        action = "allow"
        value = value[2:]
    adblock = _ABP_RE.fullmatch(value)
    if adblock:
        modifiers = set(filter(None, (adblock.group(2) or "").lower().split(",")))
        # `important` changes precedence but not whether the hostname itself
        # matches. Every other modifier needs URL/browser request context.
        if modifiers - {"important"}:
            return None
        try:
            domain = normalize_domain(adblock.group(1))
        except ValueError:
            return None
        return ParsedRule(domain, "suffix", action)

    if value.startswith("*."):
        try:
            return ParsedRule(normalize_domain(value[2:]), "wildcard", action)
        except ValueError:
            return None

    # Reject cosmetic filters, regexes, URLs, options and any other browser
    # syntax rather than guessing at DNS semantics.
    if any(token in value for token in ("/", "$", "|", "^", "##", "#@#", "*")):
        return None
    try:
        return ParsedRule(normalize_domain(value), "exact", action)
    except ValueError:
        return None


def iter_parsed_rules(path: Path) -> Iterator[ParsedRule]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            parsed = parse_rule_line(line)
            if parsed is not None:
                yield parsed


def _rule_counts(path: Path) -> tuple[int, int]:
    accepted = 0
    total_candidates = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            stripped = line.lstrip("\ufeff").strip()
            if not stripped or stripped.startswith(("!", "#", "[")):
                continue
            total_candidates += 1
            if parse_rule_line(line) is not None:
                accepted += 1
    return accepted, max(0, total_candidates - accepted)


def _parse_datetime(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


class BlocklistService:
    """Owns worker refreshes and API-side read-only snapshot access."""

    def __init__(
        self,
        config: DNSBlocklistConfig,
        *,
        sources: tuple[BlocklistSource, ...] = BLOCKLIST_SOURCES,
    ) -> None:
        self.config = config
        self.sources = sources
        self._source_by_id = {source.source_id: source for source in sources}
        self._check_counts: dict[str, int] = {}
        self._lookup_latency_ms_total = 0.0
        self._lookup_samples = 0

    @property
    def data_dir(self) -> Path:
        return self.config.data_dir

    @property
    def current_path(self) -> Path:
        return self.data_dir / "current.json"

    def _raw_path(self, source: BlocklistSource) -> Path:
        return self.data_dir / "raw" / f"{source.source_id}.txt"

    def _state_path(self, source: BlocklistSource) -> Path:
        return self.data_dir / "state" / f"{source.source_id}.json"

    def _snapshot(self) -> dict[str, Any]:
        snapshot = _read_json(self.current_path)
        if snapshot.get("catalog_version") != catalog_version(self.sources):
            return {}
        relative_database = snapshot.get("database")
        if not isinstance(relative_database, str):
            return {}
        database = (self.data_dir / relative_database).resolve()
        root = self.data_dir.resolve()
        if not database.is_relative_to(root) or not database.is_file():
            return {}
        snapshot["database_path"] = str(database)
        return snapshot

    def _source_health(
        self,
        source: BlocklistSource,
        state: dict[str, Any],
        *,
        now: datetime,
    ) -> tuple[SourceStatus, int | None]:
        validated_at = _parse_datetime(state.get("validated_at"))
        age_seconds = (
            max(0, int((now - validated_at).total_seconds()))
            if validated_at is not None
            else None
        )
        if (
            state.get("source_url") not in {None, source.source_url}
            or not self._raw_path(source).is_file()
            or age_seconds is None
        ):
            return SourceStatus.NOT_CONFIGURED, age_seconds
        if age_seconds > self.config.max_age_seconds:
            return SourceStatus.UNAVAILABLE, age_seconds
        if state.get("last_error"):
            return SourceStatus.DEGRADED, age_seconds
        if age_seconds > self.config.stale_after_seconds:
            return SourceStatus.STALE, age_seconds
        return SourceStatus.OK, age_seconds

    def _minimum_source_count(self) -> int:
        return math.ceil(len(self.sources) * self.config.minimum_coverage)

    def _source_infos(
        self,
        snapshot: dict[str, Any] | None = None,
    ) -> list[DNSBlocklistSourceInfo]:
        now = datetime.now(UTC)
        snapshot_states = (snapshot or {}).get("sources", {})
        if not isinstance(snapshot_states, dict):
            snapshot_states = {}
        infos: list[DNSBlocklistSourceInfo] = []
        for source in self.sources:
            state = snapshot_states.get(source.source_id)
            if not isinstance(state, dict):
                state = _read_json(self._state_path(source))
            status, age_seconds = self._source_health(source, state, now=now)
            infos.append(
                DNSBlocklistSourceInfo(
                    source_id=source.source_id,
                    name=source.name,
                    categories=list(source.categories),
                    license=source.license,
                    license_url=source.license_url,
                    source_url=source.source_url,
                    format=source.format,
                    status=status,
                    content_updated_at=_parse_datetime(state.get("content_updated_at")),
                    last_checked_at=_parse_datetime(state.get("validated_at")),
                    age_seconds=age_seconds,
                    rule_count=int(state.get("rule_count") or 0),
                    rejected_rule_count=int(state.get("rejected_rule_count") or 0),
                    error=str(state["last_error"]) if state.get("last_error") else None,
                )
            )
        return infos

    def sources_response(self) -> DNSBlocklistSourcesResponse:
        snapshot = self._snapshot()
        infos = self._source_infos(snapshot)
        usable = sum(
            info.status in {SourceStatus.OK, SourceStatus.STALE, SourceStatus.DEGRADED}
            for info in infos
        )
        minimum = self._minimum_source_count()
        initial_complete = all(
            info.content_updated_at is not None
            and info.status != SourceStatus.NOT_CONFIGURED
            for info in infos
        )
        ready = bool(
            self.config.enabled
            and snapshot
            and initial_complete
            and usable >= minimum
        )
        return DNSBlocklistSourcesResponse(
            ready=ready,
            catalog_version=catalog_version(self.sources),
            snapshot_id=str(snapshot.get("snapshot_id")) if snapshot else None,
            required_source_count=len(self.sources),
            usable_source_count=usable,
            minimum_usable_source_count=minimum,
            sources=infos,
        )

    def is_ready(self) -> bool:
        return self.sources_response().ready

    def metrics_snapshot(self) -> dict[str, object]:
        return {
            "catalog": self.sources_response(),
            "checks": dict(self._check_counts),
            "lookup_latency_ms_total": self._lookup_latency_ms_total,
            "lookup_samples": self._lookup_samples,
        }

    async def refresh(self) -> DNSBlocklistSourcesResponse:
        """Download every source with validators, then publish one generation."""

        if not self.config.enabled:
            return self.sources_response()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        (self.data_dir / "raw").mkdir(parents=True, exist_ok=True)
        (self.data_dir / "state").mkdir(parents=True, exist_ok=True)
        (self.data_dir / "tmp").mkdir(parents=True, exist_ok=True)
        (self.data_dir / "generations").mkdir(parents=True, exist_ok=True)

        timeout = httpx.Timeout(self.config.request_timeout_seconds)
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "Hyrule-Cloud-Blocklist/1.0 (+https://hyrule.host)"},
        ) as client:
            # Bound source fanout so one refresh does not create a burst against
            # GitHub and the independent list maintainers.
            semaphore = asyncio.Semaphore(4)

            async def guarded(source: BlocklistSource) -> None:
                async with semaphore:
                    await self._refresh_source(client, source)

            await asyncio.gather(*(guarded(source) for source in self.sources))

        await asyncio.to_thread(self.compile_snapshot)
        return self.sources_response()

    async def _refresh_source(
        self,
        client: httpx.AsyncClient,
        source: BlocklistSource,
    ) -> None:
        state_path = self._state_path(source)
        raw_path = self._raw_path(source)
        state = _read_json(state_path)
        headers: dict[str, str] = {}
        same_source_url = state.get("source_url") in {None, source.source_url}
        if same_source_url and state.get("etag"):
            headers["If-None-Match"] = str(state["etag"])
        if same_source_url and state.get("last_modified"):
            headers["If-Modified-Since"] = str(state["last_modified"])
        now = datetime.now(UTC)
        state["last_attempt_at"] = now.isoformat()
        temporary = self.data_dir / "tmp" / f"{source.source_id}.{uuid.uuid4().hex}.download"

        try:
            async with client.stream("GET", source.source_url, headers=headers) as response:
                if response.status_code == 304:
                    if not raw_path.is_file():
                        raise RuntimeError("source returned 304 but no local raw file exists")
                    state.update(
                        {
                            "source_url": source.source_url,
                            "validated_at": now.isoformat(),
                            "last_error": None,
                        }
                    )
                    _atomic_json(state_path, state)
                    log.info("dns_blocklist_source_unchanged", source_id=source.source_id)
                    return
                response.raise_for_status()
                size = 0
                with temporary.open("wb") as output:
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > self.config.max_download_bytes:
                            raise RuntimeError(
                                f"download exceeds {self.config.max_download_bytes} bytes"
                            )
                        output.write(chunk)

                accepted, rejected = await asyncio.to_thread(_rule_counts, temporary)
                if accepted < source.minimum_rules:
                    raise RuntimeError(
                        f"parsed {accepted} rules; minimum is {source.minimum_rules}"
                    )
                previous = int(state.get("rule_count") or 0)
                if previous:
                    ratio = accepted / previous
                    if ratio < self.config.minimum_change_ratio:
                        raise RuntimeError(
                            f"rule count fell from {previous} to {accepted} ({ratio:.2f}x)"
                        )
                    if ratio > self.config.maximum_change_ratio:
                        raise RuntimeError(
                            f"rule count grew from {previous} to {accepted} ({ratio:.2f}x)"
                        )

                raw_path.parent.mkdir(parents=True, exist_ok=True)
                os.replace(temporary, raw_path)
                digest = await asyncio.to_thread(_sha256_file, raw_path)
                state.update(
                    {
                        "source_url": source.source_url,
                        "etag": response.headers.get("etag"),
                        "last_modified": response.headers.get("last-modified"),
                        "validated_at": now.isoformat(),
                        "content_updated_at": now.isoformat(),
                        "sha256": digest,
                        "download_bytes": size,
                        "rule_count": accepted,
                        "rejected_rule_count": rejected,
                        "last_error": None,
                    }
                )
                _atomic_json(state_path, state)
                log.info(
                    "dns_blocklist_source_refreshed",
                    source_id=source.source_id,
                    rule_count=accepted,
                    rejected_rule_count=rejected,
                    download_bytes=size,
                )
        except Exception as exc:
            temporary.unlink(missing_ok=True)
            state["last_error"] = str(exc)[:500]
            _atomic_json(state_path, state)
            log.warning(
                "dns_blocklist_source_refresh_failed",
                source_id=source.source_id,
                error=str(exc),
            )

    def compile_snapshot(self) -> None:
        """Compile existing last-good raw sources and atomically publish them."""

        generations = self.data_dir / "generations"
        generations.mkdir(parents=True, exist_ok=True)
        generation = datetime.now(UTC).strftime("%Y%m%dT%H%M%S") + f"-{uuid.uuid4().hex[:8]}"
        snapshot_id = f"blsnap_{generation}"
        temporary = generations / f".{generation}.sqlite.tmp"
        target = generations / f"{generation}.sqlite"
        temporary.unlink(missing_ok=True)

        connection = sqlite3.connect(temporary)
        source_states: dict[str, dict[str, Any]] = {}
        compiled = 0
        try:
            connection.executescript(
                """
                PRAGMA journal_mode=OFF;
                PRAGMA synchronous=OFF;
                PRAGMA temp_store=MEMORY;
                CREATE TABLE rules (
                    source_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    match_kind TEXT NOT NULL,
                    action TEXT NOT NULL,
                    PRIMARY KEY (source_id, domain, match_kind, action)
                ) WITHOUT ROWID;
                CREATE INDEX rules_domain_idx ON rules(domain);
                CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
                """
            )
            for source in self.sources:
                raw_path = self._raw_path(source)
                state = _read_json(self._state_path(source))
                source_states[source.source_id] = dict(state)
                if not raw_path.is_file():
                    continue
                batch: list[tuple[str, str, str, str]] = []
                parsed_count = 0
                for rule in iter_parsed_rules(raw_path):
                    batch.append((source.source_id, rule.domain, rule.match_kind, rule.action))
                    parsed_count += 1
                    if len(batch) >= 10_000:
                        connection.executemany(
                            "INSERT OR IGNORE INTO rules VALUES (?, ?, ?, ?)", batch
                        )
                        batch.clear()
                if batch:
                    connection.executemany(
                        "INSERT OR IGNORE INTO rules VALUES (?, ?, ?, ?)", batch
                    )
                unique_count = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM rules WHERE source_id = ?",
                        (source.source_id,),
                    ).fetchone()[0]
                )
                state["rule_count"] = unique_count
                state.setdefault("parsed_rule_count", parsed_count)
                source_states[source.source_id] = state
                compiled += 1

            if compiled == 0:
                raise BlocklistUnavailableError("no last-good blocklist source files exist")

            version = catalog_version(self.sources)
            connection.executemany(
                "INSERT INTO metadata(key, value) VALUES (?, ?)",
                (
                    ("catalog_version", version),
                    ("snapshot_id", snapshot_id),
                    ("built_at", datetime.now(UTC).isoformat()),
                ),
            )
            connection.commit()
            integrity = connection.execute("PRAGMA integrity_check").fetchone()
            if not integrity or integrity[0] != "ok":
                raise RuntimeError(f"compiled index integrity check failed: {integrity}")
        except Exception:
            connection.close()
            temporary.unlink(missing_ok=True)
            raise
        else:
            connection.close()

        os.replace(temporary, target)
        built_at = datetime.now(UTC).isoformat()
        pointer = {
            "catalog_version": catalog_version(self.sources),
            "snapshot_id": snapshot_id,
            "database": str(target.relative_to(self.data_dir)),
            "built_at": built_at,
            "sources": source_states,
        }
        _atomic_json(self.current_path, pointer)
        self._remove_old_generations(keep={target.name})
        log.info(
            "dns_blocklist_snapshot_published",
            snapshot_id=snapshot_id,
            compiled_sources=compiled,
        )

    def _remove_old_generations(self, *, keep: set[str]) -> None:
        generations = sorted(
            (self.data_dir / "generations").glob("*.sqlite"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        keep.update(path.name for path in generations[:2])
        for path in generations:
            if path.name not in keep:
                path.unlink(missing_ok=True)

    async def check(self, input_domain: str) -> DNSBlocklistCheckResponse:
        normalized = normalize_domain(input_domain)
        # A lookup is one indexed SQLite SELECT over at most 126 suffixes and
        # normally completes in sub-millisecond time. Keeping it on the event
        # loop also avoids handing a read-only connection across threads; the
        # expensive parsing/compilation work remains worker-only.
        started = time.perf_counter()
        result = self._check_sync(input_domain, normalized)
        self._lookup_latency_ms_total += (time.perf_counter() - started) * 1000.0
        self._lookup_samples += 1
        self._check_counts[result.verdict.value] = (
            self._check_counts.get(result.verdict.value, 0) + 1
        )
        return result

    def _check_sync(
        self,
        input_domain: str,
        normalized: str,
    ) -> DNSBlocklistCheckResponse:
        sources_response = self.sources_response()
        if not sources_response.ready or sources_response.snapshot_id is None:
            raise BlocklistUnavailableError("blocklist snapshot does not meet minimum coverage")
        snapshot = self._snapshot()
        database_path = snapshot.get("database_path")
        if not isinstance(database_path, str):
            raise BlocklistUnavailableError("compiled blocklist database is unavailable")

        candidates = domain_suffixes(normalized)
        placeholders = ",".join("?" for _ in candidates)
        connection = sqlite3.connect(f"file:{database_path}?mode=ro", uri=True)
        try:
            connection.execute("PRAGMA query_only=ON")
            rows = connection.execute(
                f"SELECT source_id, domain, match_kind, action FROM rules WHERE domain IN ({placeholders})",
                candidates,
            ).fetchall()
        finally:
            connection.close()

        best: dict[str, tuple[str, str, str]] = {}
        for source_id, domain, match_kind, action in rows:
            if match_kind == "exact" and domain != normalized:
                continue
            if match_kind == "wildcard" and domain == normalized:
                continue
            if normalized != domain and not normalized.endswith(f".{domain}"):
                continue
            current = best.get(source_id)
            rank = (domain.count("."), len(domain), action == "allow")
            if current is None:
                best[source_id] = (domain, match_kind, action)
                continue
            current_rank = (
                current[0].count("."),
                len(current[0]),
                current[2] == "allow",
            )
            if rank > current_rank:
                best[source_id] = (domain, match_kind, action)

        info_by_id = {info.source_id: info for info in sources_response.sources}
        results: list[DNSBlocklistSourceResult] = []
        matched_categories: set[DNSBlocklistCategory] = set()
        matched_count = 0
        checked_count = 0
        partial = False
        usable_statuses = {SourceStatus.OK, SourceStatus.STALE, SourceStatus.DEGRADED}
        for source in self.sources:
            info = info_by_id[source.source_id]
            if info.status not in usable_statuses:
                partial = True
                outcome = DNSBlocklistSourceOutcome.UNAVAILABLE
                match = None
            else:
                checked_count += 1
                if info.status != SourceStatus.OK:
                    partial = True
                match = best.get(source.source_id)
                if match is None:
                    outcome = DNSBlocklistSourceOutcome.NOT_LISTED
                elif match[2] == "allow":
                    outcome = DNSBlocklistSourceOutcome.EXCEPTED
                else:
                    outcome = DNSBlocklistSourceOutcome.LISTED
                    matched_count += 1
                    matched_categories.update(source.categories)
            results.append(
                DNSBlocklistSourceResult(
                    source_id=source.source_id,
                    source_name=source.name,
                    categories=list(source.categories),
                    outcome=outcome,
                    matched_domain=match[0] if match else None,
                    match_kind=match[1] if match else None,
                    source_status=info.status,
                    source_age_seconds=info.age_seconds,
                )
            )

        if matched_count:
            verdict = DNSBlocklistVerdict.LISTED
        elif partial:
            verdict = DNSBlocklistVerdict.INCONCLUSIVE
        else:
            verdict = DNSBlocklistVerdict.NOT_LISTED
        return DNSBlocklistCheckResponse(
            input_domain=input_domain,
            normalized_domain=normalized,
            verdict=verdict,
            categories=sorted(matched_categories, key=lambda category: category.value),
            checked_source_count=checked_count,
            matched_source_count=matched_count,
            required_source_count=len(self.sources),
            results=results,
            catalog_version=sources_response.catalog_version,
            snapshot_id=sources_response.snapshot_id,
            partial=partial,
        )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def blocklist_catalog_ready(config: DNSBlocklistConfig | None = None) -> bool:
    if config is None:
        config = HyruleConfig().dns_blocklists
    return BlocklistService(config).is_ready()
