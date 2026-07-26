# `/v1/lookalike` — dnstwist-style typosquat detection over x402

**Status:** proposed — design review, no code yet.
**Baseline:** `main` @ `6d3daf7`. Every file/line reference below was verified against that commit.

## Context

We already sell ~26 network-intelligence operations over x402 (`/v1/dns/lookup`,
`/v1/whois/lookup`, `/v1/web/tls/deep`, …). Brand-protection / typosquat detection is a
well-established commercial category we don't cover, and it composes unusually well with
assets we already own: a domain normalizer, a cached DNS layer, an RDAP client, a local
phishing/malware blocklist catalog, and a web/TLS prober.

The buyer is an autonomous agent monitoring a brand: it pays once, gets a ranked list of
lookalike domains, and knows which are live, mail-capable, freshly registered, or already
known-malicious.

There is no prior art — `dnstwist|typosquat|permutation|homoglyph` returns nothing in this
repo or `hyrule-web`. This is a new product built from existing parts.

**Repos touched:** `hyrule-cloud` (the product) and `hyrule-web` (one catalog entry).

### Decisions taken

| | Decision |
|---|---|
| Execution | **Async job** on the existing `diagnostic_jobs` primitives — not an inline scan |
| Scope | Tiers `existence / standard / **deep**` — deep adds RDAP + HTTP/TLS |
| Engine | **Port** dnstwist's algorithms + glyph tables under Apache-2.0 attribution |
| Pricing | **Dynamic**: `$0.02 base + $0.01 per 25 permutations + $0.15 flat for deep` |
| Registrar upsell | **No.** Detection only — no `availability_url`, no defensive-registration block |

### Open items needing a human answer before PR 1

- **Apache-2.0 attribution sign-off** (Risk 5) — are we comfortable carrying an Apache-2.0
  attribution header in a proprietary service? Precedent exists (per-source `license` /
  `license_url` metadata for blocklists), but this is a call, not a technical question.
- **RDAP bootstrap strategy** (Risk 3) — proxy through `rdap.org`, or bootstrap from IANA's
  RDAP bootstrap JSON and hit registry endpoints directly?

---

## Why async, and what it changes

We would be the **first real consumer of `DiagnosticJobRow`** — the `diagnostic_jobs` table
(`alembic/versions/011_diagnostic_job_primitives.py`, `db.py:814`) and the helpers in
`services/diagnostics/jobs.py` exist and are referenced by nothing else. The row's docstring
says it was built for exactly this:

> Product namespaces (/v1/web, /v1/path, /v1/threat, /v1/voip, etc.) share this shape so job
> tokens, artifacts, expiry, and source metadata behave consistently.

Columns cover everything we need — `service`, `kind`, `status`, `target`, `owner_wallet`,
`payment_tx`, `access_token_hash`, `request`, `result`, `sources`, `artifact_*`, `price_usd`,
`error`, `started_at`/`completed_at`/`expires_at`. **No new migration is needed** (`service`
is `String(32)` → `"lookalike"`; `kind` is `String(64)` → `"lookalike_scan"`).

Async is a straight upgrade for this product specifically:

- **The HTTP request deadline disappears**, so the permutation cap can be 1 000 (max 5 000)
  rather than the ~400 a 20 s inline scan would allow, and the deep tier can cover *all*
  registered hits instead of an arbitrary top-25.
- **Amplification control moves to the worker queue**, which is a far better global throttle
  than per-request semaphores: fan-out is bounded by a small job concurrency rather than by
  however many HTTP requests happen to be in flight.
- **Results become durable and re-downloadable** for 7 days, which is what makes this a
  report worth $0.20–$0.60 rather than a $0.05 lookup.

### The one thing it costs us: deliver-then-settle

Async forces **charge-at-submit**. An x402 payment authorization carries a short validity
window (EIP-3009 `validBefore`; facilitators typically allow ~60 s), so holding a verified
authorization across a multi-minute job and settling afterwards is not safe — it would
routinely expire and we'd deliver work we can't collect on. `/v1/bgp/jobs` already resolves
this the same way: `require_payment()` (verify **and** settle) at submit, `api/bgp.py:260`.

Two consequences, both handled:

1. **Every quality gate moves in front of the charge.** Worker readiness, queue depth,
   per-payer quota, input validation, and — importantly — **resolving the target domain's own
   baseline** all happen before `require_payment`. That last one is one cheap DNS query, and
   without the target's A/AAAA/NS every `shares_*_with_target` verdict is unreliable and the
   whole ranking is garbage. Refusing before charging is house doctrine: `/v1/bgp/jobs`
   returns `not_implemented` rather than "bill for a job that would sit queued forever"
   (`api/bgp.py:245-252`).
2. **Failure after the charge records a refund obligation** via the existing `RefundService`
   (`services/refunds.py:38` — *"Records refund obligations for failed paid provisioning"*,
   writes a `refund_owed` ledger row). Job → `status=failed` + `error` + refund. A *partial*
   result is delivered as `partial: true` with per-source health and is **not** refunded.

---

## Why port dnstwist instead of depending on it

Verified upstream (PyPI JSON + `raw.githubusercontent.com/elceef/dnstwist/master/dnstwist.py`):
Apache-2.0 (`"ASL 2.0"`), latest `20250130`, all deps optional (`extra == "full"`).
Licensing is clean either way. The blockers are technical:

- **`socket.setdefaulttimeout(12.0)` at module line 34**, top level — a process-global
  mutation of default socket behaviour inside a payment API.
- `Fuzzer.__init__` calls `domain_tld()` (line 703), which tries `from tld import parse_tld`
  (file I/O, self-updating PSL) and otherwise falls back to a hardcoded ccSLD list — a
  **second domain parser** that would diverge from our `normalize_domain()`.
- `Fuzzer.generate()` materialises the full unbounded set before filtering. Our cap needs
  *ranked, lazy, early-stopping* generation.
- `Fuzzer._tld()` is literally `return set(self.tld_dictionary)` — half the class is inert
  unless we supply the data anyway.
- `VALID_FQDN_REGEX` (line 137) is **looser** than our `_LABEL_RE` (it permits a trailing
  hyphen in the final label).
- We run `mypy strict = true`; dnstwist ships no stubs.

Mitigation for what we take on: copy `glyphs_ascii` / `glyphs_unicode` / `glyphs_idn_by_tld`
verbatim with a `# Source: dnstwist @ <commit>, Apache-2.0` header, and pin table cardinality
in a test so an accidental edit is caught.

*Fallback if this is rejected:* add `dnstwist>=20250130` and import `Fuzzer` inside a function
that saves/restores `socket.getdefaulttimeout()`. Not recommended.

---

## Placement

New router `hyrule_cloud/api/lookalike.py`, `prefix="/v1/lookalike"`.

Not under `/v1/domains` — `domains/api.py:127` builds a separate registrar OpenAPI doc from
`route.path.startswith("/v1/domains")`, so an intel route would leak into the registrar
contract. Not under `/v1/dns` — that product promises one-domain-in / one-answer-out and has
a completely different abuse profile.

---

## Reuse map

| Need | Existing code |
|---|---|
| Job table + row | `db.py:814` `DiagnosticJobRow`; migration `011` already applied |
| Job id / token / envelope | `services/diagnostics/jobs.py` — `generate_job_identity()`, `hash_job_access_token()`, `build_job_response()` |
| Job status/result models | `models.py:810` `DiagnosticJobStatus`, `:819` `DiagnosticJobKind`, `:828` `DiagnosticJobResponse`, `DiagnosticJobResultResponse` |
| Async job route shape | `api/bgp.py:243-330` — create / status / download, `?token=`, 404-on-mismatch |
| Worker host loop | `worker.py:61` `run_worker()`, `:117` main loop, session factory at `:65` |
| Refund on failure | `services/refunds.py:38` `RefundService` |
| Domain validation / IDNA boundary | `services/dns/domain.py` — `normalize_domain()`, `domain_suffixes()`, `_LABEL_RE` |
| DNS resolution | `services/dns/lookup.py` — `lookup_values(name, rtype)`, 60 s cache |
| Bounded fan-out + deadline | `services/dns/filtering.py:279` `_collect` |
| Quality floor / metrics shape | `filtering.py:203` `meets_quality_floor`, `:191` `metrics_snapshot` |
| Gate readiness predicate shape | `filtering.py:489` `dns_filtering_enabled` |
| Payment helpers | `api/_contract.py` — `payment_price`, `require_payment`, `quote`, `not_implemented` |
| TTL cache | `services/cache.py:23` — note `set(key, value, ttl_seconds)`; **TTL is per-`set`**, not per-cache |
| RDAP (deep tier) | `services/registry/lookup.py:59` `rdap_lookup()`, 24 h module cache at `:22` |
| Blocklist hit | `services/dns/blocklists.py` — `BlocklistService.check()`, `is_ready()`; local SQLite, **zero network** |
| HTTP/TLS probe (deep tier) | `services/web/checks.py` `run_web_check()` |
| SSRF guard | `services/safety.py:131` — ⚠️ synchronous, calls `socket.getaddrinfo` at `:105` |
| Catalog registration | `services/discovery.py` — `:40` `PriceSpec`, `:83` `_TAG_PREFIXES`, `:308` `_body_operation`, `:384` `_fixed`, `:609` `PAID_OPERATIONS`, `:1089` `_gate_enabled` |
| Per-payer quota counter | `domains/api.py:65,92-104` — `cachetools.TTLCache` + `derive_ip_prefix_hash` |

### Two easy-to-miss couplings

1. `discovery.py:83 _TAG_PREFIXES` **must** gain a `/v1/lookalike` entry. `hyrule-web`
   computes `category = tags[0] if tags else …` (`hyrule_web/catalog.py:350`) and
   `executable = bool(tags)` (`:358`) — an untagged operation renders in the web toolbox as
   **non-executable with a handoff URL**.
2. `tests/test_network_intel_contracts.py:18` asserts the app's OpenAPI paths equal exactly
   the enabled catalog operations. **Route wiring and catalog registration cannot be separate
   PRs** — CI fails the moment a route exists without a `PAID_OPERATIONS` entry.

---

## Permutation engine — `services/lookalike/fuzz.py`

Fuzzers as a `StrEnum`, **in generation order** — ranked by real-world attack frequency so
hitting the cap truncates the least valuable tail first:

`original, omission, transposition, replacement, insertion, repetition, hyphenation,
bitsquatting, vowel_swap, addition, plural, homoglyph, tld_swap, subdomain, dictionary, cyrillic`

`homoglyph` runs **one** substitution round by default (upstream does `mix(mix(x))`, which
explodes quadratically); the second round is opt-in. `cyrillic` is off by default.

### IDNA contract (load-bearing)

Generation operates on the **U-label** of the registrable label:

1. `normalized = normalize_domain(body.domain)` → lower-case A-label, ≥2 labels.
2. `split_registrable(normalized)` → `(subdomain, sld, tld)` via `domain_suffixes()` plus a
   small curated ccSLD set (`co.uk`, `com.au`, `co.jp`, …). **No PSL package.**
3. `sld_u = idna.decode(sld)` if it starts with `xn--`, else `sld`. On failure, treat as
   ASCII-only and skip `homoglyph`/`cyrillic`.
4. Run fuzzers on `sld_u`. ASCII-only fuzzers (`bitsquatting`, `insertion`, `replacement`)
   are skipped when the source label is non-ASCII.
5. Reassemble, then `idna.encode(candidate, uts46=True, std3_rules=False)` — the **`idna`
   package**, not `str.encode("idna")`. The stdlib codec is IDNA2003 and maps `ß`→`ss`,
   silently erasing a real attack vector; browsers and registries enforce IDNA2008/UTS-46.
   `idna` is already present transitively (`uv.lock`), but **declare it explicitly in
   `pyproject.toml`** since we import it directly.
6. **Re-validate every A-label through `normalize_domain()`; drop anything that raises.**
   This is the safety chokepoint — everything downstream sees only clean A-labels.
7. Dedupe on the A-label, first fuzzer wins. Keep `unicode_domain` alongside so the report
   can show `аpple.com` next to `xn--pple-43d.com`. Drop candidates equal to the input.

Generation is a **lazy ranked generator** that stops at the cap — it never materialises the
full set. Surface `generated_permutation_count` vs `scanned_permutation_count` + `truncated`.

Edge cases needing tests: `subdomain` emitting `..` or a leading `-`; `bitsquatting` emitting
an edge hyphen; homoglyphs pushing a punycode label past 63 bytes (`idna.encode` raises →
dropped, which silently reduces homoglyph yield on long domains and must **not** trip the
completion ratio); `xn--` input; single-char SLDs; `example.co.uk` → `("", "example", "co.uk")`.

`tld_swap` ships a **static curated ~40-TLD default in `fuzz.py`** — it must not depend on
`/v1/domains/tlds`, since `DomainService.list_tlds()` raises 503 when the catalog is unsynced.

---

## Enrichment tiers

**`existence`** — **NS first, A/AAAA only if NS answered.** A registered-but-parked domain
always has NS at the parent; a live domain may have no A/AAAA. Typosquat neighbourhoods are
85–95 % unregistered, so NXDOMAIN-on-NS short-circuits ~3× of query volume. Fields:
`registered`, `dns_rcode`, `a`, `aaaa`, `ns`.

**`standard`** — plus, **for registered permutations only**: `MX` (mail-interception risk —
the highest-signal cheap field); `BlocklistService.check()` (local, zero network, always on
when `is_ready()`); and **A/AAAA + NS overlap with the original domain**. That overlap is the
false-positive killer — a permutation on the brand's own IPs/nameservers is a defensive
registration, not an attack.

**`deep`** — plus, for registered permutations only, up to `deep_max_targets` (default 250):
- **RDAP** via `rdap_lookup()` → `registrar`, `created_at`, `age_days`, `status`.
- HTTP/TLS via `run_web_check()` → `http_status`, `final_url`, `redirects_to_target`,
  `server`, `tls_issuer`, `tls_subject_cn`.
- **No content-similarity hashing in v1** (needs ppdeep/tlsh; slowest, most abusable arm).
- **No port-43 WHOIS.** RDAP-only — see Risks.

### Risk scoring — a pure, deterministic, unit-testable table (`score_permutation()`)

| Rule | Effect |
|---|---|
| registered | → `LOW` |
| has MX | +1 level |
| has A/AAAA and not sharing address/NS with target | +1 |
| blocklist LISTED in phishing/malware/scam/c2 | → `CRITICAL` |
| RDAP `age_days < 90` | +1 |
| fuzzer ∈ {homoglyph, cyrillic} and registered | +1 (deliberate deception, not a fat finger) |
| `web.redirects_to_target` | → force `INFO` |
| shares address **or** nameservers with target | → force `INFO` |

Clamped at `CRITICAL`; every bump appends a stable code to `reasons`.

### Completion policy

The worker marks the job `completed` when `resolved / attempted >= minimum_resolved_ratio`
(0.90). Otherwise `failed` with `error` + **refund obligation**. Additionally:

- If `deep` and <50 % of selected deep targets returned → complete as `standard` with
  `degraded_to: "standard"` and record a **partial refund obligation** for the `$0.15` deep
  surcharge. Async makes this cleaner than an inline design would: we refund the difference
  rather than silently downgrading the charge.
- `partial: true` with per-source `SourceHealth` for anything less than total success that
  still clears the ratio — delivered, not refunded.

---

## API surface

**Free:** `GET /v1/lookalike/capabilities`, `GET /v1/lookalike/pricing`,
`GET /v1/lookalike/fuzzers` (id, description, `ascii_only`, `default` — mirrors
`api/dns.py:208` `/v1/dns/filtering/resolvers`), `POST /v1/lookalike/jobs/quote`,
`POST /v1/lookalike/permutations/quote`, and the job **status** route (polling is free).

**Paid:**

| Route | Shape |
|---|---|
| `POST /v1/lookalike/permutations` | **Sync**, fixed price. Pure computation, zero I/O — no reason to queue it. Returns the ranked permutation set. |
| `POST /v1/lookalike/jobs` | **Async**, dynamic price. Charges, enqueues, returns the job envelope. |
| `GET /v1/lookalike/jobs/{job_id}?token=` | Free. Status **and, once complete, the full result inline** via the existing `DiagnosticJobResultResponse` — so the normal path is one poll, not poll-then-download. |
| `GET /v1/lookalike/jobs/{job_id}/download?token=` | Free. Gzipped JSON artifact for large scans. |

Token handling copies `api/bgp.py` exactly: cleartext returned **once** at submit, only
`sha256` stored in `access_token_hash`, and a mismatch returns **404 not 403** so the route is
not an enumeration oracle. `expires_at = created + 7 days`. Download returns **409** when the
artifact isn't ready and **410** when it has expired.

`capabilities.separation_of_concerns` = *"/v1/lookalike only observes. It never registers,
buys, or blocks a domain."*

### Models (`hyrule_cloud/models.py`)

Add `LOOKALIKE_SCAN = "lookalike_scan"` to `DiagnosticJobKind` (`models.py:819`). Then:

```python
class LookalikeFuzzer(StrEnum):     # 16 members, generation order above
class LookalikeEnrichment(StrEnum): EXISTENCE, STANDARD, DEEP
class LookalikeRisk(StrEnum):       CRITICAL, HIGH, MEDIUM, LOW, INFO

class LookalikeJobRequest(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    fuzzers: list[LookalikeFuzzer] = Field(default_factory=list)
    enrichment: LookalikeEnrichment = LookalikeEnrichment.STANDARD
    max_permutations: int | None = Field(default=None, ge=1, le=5000)
    tlds: list[str] = Field(default_factory=list, max_length=50)
    keywords: list[str] = Field(default_factory=list, max_length=20)
    include_unregistered: bool = True
# LookalikePermutationsRequest = same minus enrichment/include_unregistered

class LookalikePermutation:    domain, unicode_domain|None, fuzzer, idn: bool
class LookalikeTargetBaseline: domain, a[], aaaa[], ns[], mx[], resolved: bool
class LookalikeRegistryFacts:  source|None, registrar|None, created_at|None, age_days|None, status[], error|None
class LookalikeWebFacts:       http_status|None, final_url|None, redirects_to_target: bool,
                               server|None, tls_issuer|None, tls_subject_cn|None, error|None

class LookalikeFinding:
    permutation, registered: bool, risk: LookalikeRisk, reasons: list[str]   # stable codes
    dns_rcode|None, a[], aaaa[], ns[], mx[]
    shares_address_with_target: bool = False
    shares_nameservers_with_target: bool = False
    blocklist: DNSBlocklistCheckResponse | None = None     # reuse existing model
    registry: LookalikeRegistryFacts | None = None
    web: LookalikeWebFacts | None = None
    errors: list[str] = []

class LookalikeScanResult(BaseModel):        # stored in DiagnosticJobRow.result
    input_domain, normalized_domain, target: LookalikeTargetBaseline
    enrichment, degraded_to|None, fuzzers[]
    generated_permutation_count, scanned_permutation_count
    registered_count, critical_count, high_count
    findings: list[LookalikeFinding]
    truncated: bool, partial: bool
    sources: dict[str, SourceHealth]      # "dns" | "rdap" | "blocklists" | "http"
    generated_at: datetime
```

Validators: keywords `^[a-z0-9-]{1,30}$`; TLDs normalized via `normalize_domain(f"x.{tld}")`;
fuzzers deduped into canonical order; **SLD shorter than 3 chars → 422** (a 2-char SLD is
near-total garbage at maximum fan-out cost).

### Pricing

`PaymentConfig` (`config.py:256`) gains four `Decimal` fields:

```python
price_lookalike_permutations: Decimal = Decimal("0.005")
price_lookalike_scan_base:    Decimal = Decimal("0.02")
price_lookalike_scan_per_25:  Decimal = Decimal("0.01")
price_lookalike_scan_deep:    Decimal = Decimal("0.15")
```

`total = base + ceil(scanned / 25) * per_25 + (deep if enrichment == deep else 0)`

| Permutations | Tier | Total |
|---|---|---|
| 100 | standard | `$0.06` |
| 400 | standard | `$0.18` |
| 1 000 | standard | `$0.42` |
| 1 000 | deep | `$0.57` |

Deep is a **flat surcharge, not per-target**: you cannot know how many permutations are
registered until the job runs, and the charge happens at submit. Flat surcharge + the
`degraded_to` partial refund keeps the advertised `PriceSpec` truthful.

The route computes the exact amount by **running the pure generator at submit**, before
`require_payment` — cheap, no network, and it means the quote and the charge always agree.
`/jobs/quote` runs the same generator and returns `scanned_permutation_count` in its
`QuoteLineItem`s.

```python
_LOOKALIKE_JOB_PRICE = PriceSpec(
    "dynamic",
    (("price_lookalike_scan_base","0.02"), ("price_lookalike_scan_per_25","0.01"),
     ("price_lookalike_scan_deep","0.15")),
    bounded=False,                  # total scales with permutation count, like _VM_PRICE
    literal_min=Decimal("0.03"),    # real floor; otherwise minimum() reports 0.01
)
```

**Gate** `"lookalike"` → new branch in `_gate_enabled` (`discovery.py:1089`, before the
`raise ValueError`) returning `lookalike_enabled() and lookalike_worker_enabled()`. Plus a
belt-and-braces route-level `not_implemented("lookalike.jobs.create", …)` when the worker is
down — the exact `/v1/bgp/jobs` precedent (`api/bgp.py:245-252`), so we never bill for a job
that would sit queued forever. Deliberately **not** gated on the blocklist catalog — that
enrichment is additive and degrades to absent.

---

## Amplification / abuse

This is the main engineering risk. A `$0.42` job can become 1 000 permutations × ~1.4 queries
≈ 1 400 DNS queries to rtr's Unbound, plus RDAP/HTTP out the **single shared NAT64 failover
IPv4**. Getting that IP throttled would break `/v1/whois/lookup`, `/v1/rdap/lookup`, and
`/v1/ip/lookup` fleet-wide. There is no edge rate limiting today (Caddy has none; nftables
egress is `policy accept`). Controls, in priority order:

1. **The worker queue is the primary throttle** — `max_concurrent_jobs = 2`, claimed with
   `SELECT … FOR UPDATE SKIP LOCKED` on `diagnostic_jobs` so the API process and the worker
   never double-run a job. Total fleet fan-out is bounded by a constant, independent of how
   many agents are buying.
2. **Queue-depth admission control at submit** — count `queued` jobs for `service="lookalike"`;
   over `max_queue_depth` (default 50) → **503 before charging**, with the queue depth in the
   message so an agent can back off.
3. **Hard cap at generation** — default 1 000, absolute 5 000 via `Field(le=5000)` *and*
   `min(request, config.max_permutations)`. Lazy generator, early stop.
4. **NS-first short-circuit** — ~3× real query reduction.
5. **Per-worker semaphores** — `dns_concurrency=16`, `registry_concurrency=4`,
   `probe_concurrency=4`, owned by the singleton service in the worker process.
6. **Shared 15-minute DNS cache**, 65 536 entries. Typosquat neighbourhoods overlap heavily
   across related brands, and re-scanning the same brand is the expected usage.
7. **Never fan out WHOIS.** RDAP-only over HTTPS, behind `registry_concurrency`.
8. **Do not call `assert_safe_active_probe_target()` per target** — it is synchronous and
   calls `socket.getaddrinfo` (`safety.py:105`). **Reuse the A/AAAA already resolved** and run
   only `assert_public_host` / `_is_blocked_ip` over those literals. No second resolution, and
   it closes the DNS-rebinding window.
9. **Per-payer quota** — 20 jobs/hour keyed on payer address, else IP-prefix hash, reusing the
   `domains/api.py:92-104` counter → **429 + `Retry-After` before charging**.
10. **Job-level deadline** — 10 min wall clock; on expiry the job completes `partial` if it
    cleared the ratio, else `failed` + refund. Nothing runs unbounded.
11. **Keep using rtr's Unbound** (`configure=True` → `/etc/resolv.conf`). Do **not** fan out
    to public resolvers per permutation — that is precisely what gets us blocked.
12. **Blast-radius metrics** (below) + an alert on `rate(hyrule_lookalike_registry_queries_total[5m])`.

An in-flight payment-signature replay guard (as `/v1/dns/blocklists/check` uses at
`api/dns.py:60-72`) is **not** needed here — `require_payment` settles at submit, so a
replayed signature fails at the facilitator rather than multiplying fan-out.

### `LookalikeConfig(BaseSettings)`, `env_prefix="LOOKALIKE_"`

Registered on `HyruleConfig` alongside `DNSFilteringConfig` (`config.py:242`).

```
enabled=True                  worker_enabled=False              max_concurrent_jobs=2
max_permutations=1000 (25..5000)                                max_queue_depth=50
dns_concurrency=16            registry_concurrency=4            probe_concurrency=4
query_timeout_seconds=2.0     registry_timeout_seconds=6.0      probe_timeout_seconds=5.0
job_deadline_seconds=600      deep_max_targets=250 (1..1000)    deep_enabled=True
dns_cache_ttl_seconds=900     job_ttl_days=7                    minimum_resolved_ratio=0.90
job_quota_per_hour=20         cyrillic_enabled=False
```

---

## PR sequence

**PR 1 — permutation engine (pure, no I/O).** `services/lookalike/{__init__,fuzz,domain}.py`.
`tests/test_lookalike_fuzz.py`: per-fuzzer golden sets for `google.com`; `xn--` round-trip;
every homoglyph output survives `normalize_domain`; `subdomain` never emits an invalid label;
`bitsquatting` never emits an edge hyphen; ranked generation stops exactly at the cap with
`generated > scanned`; `example.co.uk` split; glyph-table cardinality pins. Green standalone.

**PR 2 — models + config.** `models.py` enums/models + `DiagnosticJobKind.LOOKALIKE_SCAN`;
`config.py` `LookalikeConfig` + `HyruleConfig` registration + 4 `price_lookalike_*` fields;
`.env.example`. Tests: exhaustive risk-table cases; config env-prefix and bounds;
request-validator rejections; pricing arithmetic.

**PR 3 — scan service (network, no routes, no queue).** `services/lookalike/scan.py`:
`LookalikeService` (semaphores, `_dns_facts`, `_registry_facts`, `_web_facts`, `_collect`,
`resolve_baseline`, `metrics_snapshot`, `close`) + `lookalike_enabled()` /
`lookalike_worker_enabled()`. Tests via a stub service: NS-first short-circuit query counts;
semaphore shared across two concurrent scans; deadline cancels and sets `partial`; ratio below
floor is reported, not raised; `deep` degrades to `standard` with `degraded_to` set.

**PR 4 — job runner in the worker.** `services/lookalike/jobs.py` — claim (`FOR UPDATE SKIP
LOCKED`), run, persist `result`/`sources`/`completed_at`, expire stale rows; failure path calls
`RefundService`; partial-deep path refunds the surcharge. Wire into `worker.py:117`'s loop next
to `_refresh_dns_blocklists`. Tests: claim is exclusive under concurrency; queued → running →
completed transitions; failure writes `refund_owed`; `degraded_to` refunds only the surcharge;
expiry sweeps to `expired`.

**PR 5 — routes + app wiring + discovery catalog (must be one PR — see coupling #2).**
`api/lookalike.py` (submit / status / download / free trio), `state.py` field, `app.py`
lifespan + `include_router` + teardown. `discovery.py`: `_TAG_PREFIXES` entry (`:83`,
`("/v1/lookalike", ("network-intel", "brand-protection"))`), `_LOOKALIKE_JOB_PRICE`, two
`_body_operation()` entries with import-time-validated examples, `_gate_enabled` branch
(`:1089`). `tests/test_lookalike_routes.py` reusing `_Gate` / `_FailingSettlementGate` from
`tests/test_dns_blocking_products.py`: unpaid 402 / paid 200; `not_implemented` when
`worker_enabled=False` **with `gate.settled == 0`**; 503 on queue depth before charging; 429 on
quota before charging; 503 when the target baseline won't resolve, before charging; token
mismatch → 404; download 409 not-ready / 410 expired; quote arithmetic (`"0.06"`); exact
`/v1/lookalike/pricing` JSON. Add `LOOKALIKE_ENABLED=true` + `LOOKALIKE_WORKER_ENABLED=true` to
`_enable_all_catalog_gates` (`tests/test_x402_openapi_discovery.py:29`) and assert
`x-payment-info.price == {"mode":"dynamic","currency":"USD","min":"0.03"}`.

**PR 6 — metrics.** `_render_lookalike_metrics` next to `_render_dns_product_metrics`
(`api/metrics.py:42`): `hyrule_lookalike_jobs_total{enrichment,result}`, `..._job_queue_depth`,
`..._job_duration_seconds_{sum,count}`, `..._permutations_scanned_total`,
`..._dns_queries_total`, `..._registry_queries_total{source}`, `..._rate_limited_total{reason}`,
`..._refunds_total{reason}`. Exposition-line test.

**PR 7 — client + MCP + canary.** `client.py` `lookalike_permutations` / `lookalike_job` /
`lookalike_job_status` (with a poll helper); two `@mcp.tool()`s (`mcp_server.py:749-766`
pattern) — the scan tool submits and polls to completion so an agent sees one call. Extend
`scripts/x402_canary.py` `TESTS` with a small `existence` job and a poll-until-done assertion.
Extend `tests/test_mcp_payment_tools.py`.

**PR 8 — skill.** `skills/hyrule-lookalike-domains/SKILL.md` + `skills/README.md` publish-order
entry after `hyrule-dns-registry`, documenting the submit→poll flow, the token, the 7-day
retention, and an explicit acceptable-use line. Test: the skill documents no 501 route.

**PR 9 — `hyrule-web` catalog.** `hyrule_web/catalog.py:31` `_CATALOG_PRESENTATION`:

```python
"/v1/lookalike/jobs": ("TYPOSQUAT",
    "Scan a domain for lookalike permutations and report which are registered, live, mail-capable, or already flagged."),
"/v1/lookalike/permutations": ("PERMUTE",
    "Generate the typosquat and homoglyph permutation set for a domain without any lookups."),
```

Extend `tests/test_tool_catalog.py` for `tool_code == "TYPOSQUAT"`; leave the generic-fallback
test untouched.

**Ops follow-up (`network-operations`, separate PR):** add `PAYMENT_PRICE_LOOKALIKE_*`,
`LOOKALIKE_ENABLED`, and `LOOKALIKE_WORKER_ENABLED` to
`ansible/roles/vault_agent/templates/hyrule-cloud.env.ctmpl.j2` (+ the
`configs/hyrule-cloud.env.j2` mirror) so prices and the worker switch are Vault-tunable rather
than code-default-only; add `network_flows_outbound` entries for api → public RDAP/HTTPS and
re-render `docs/network-flows.md`. Then a normal promote-SHA PR bumps `hyrule_cloud_version`.

**Deployment order:** land every PR with `LOOKALIKE_ENABLED=false`. Then enable the product
with `LOOKALIKE_WORKER_ENABLED=false` to smoke the free surfaces, then flip the worker. The
gate keeps both paid ops out of `/openapi.json` and `/.well-known/x402.json` until PR 6's
metrics exist and a canary job completes — that is exactly what `_gate_enabled` is for.

---

## Verification

**Per PR (local):** `uv run pytest tests/ -x` and `uv run mypy hyrule_cloud` (strict).
PRs 1–2 are pure and must be green standalone.

**Contract gates that will catch a miss:**

- `tests/test_x402_openapi_discovery.py` — schema ops must equal `PAID_OPERATIONS` keys.
- `tests/test_network_intel_contracts.py:18` — app paths == enabled catalog ops; plus
  fail-closed-without-payment and 501-before-charging.
- `_body_operation` validates request/response examples against the models **at import time** —
  a broken example fails the build, not a test.
- No new migration: assert `alembic upgrade head` is a no-op and `DiagnosticJobRow` accepts
  `service="lookalike"`, `kind="lookalike_scan"` within the existing column widths.

**End-to-end, gate on, before flipping prod:**

```bash
curl -s https://cloud.hyrule.host/v1/lookalike/capabilities | jq
curl -s -XPOST https://cloud.hyrule.host/v1/lookalike/jobs/quote \
     -d '{"domain":"hyrule.host","enrichment":"standard","max_permutations":100}' | jq
# unpaid must be 402
curl -s -o /dev/null -w '%{http_code}\n' -XPOST https://cloud.hyrule.host/v1/lookalike/jobs \
     -d '{"domain":"hyrule.host"}'
# real spend + poll to completion
python scripts/x402_canary.py list            # prices, no spend
python scripts/x402_canary.py run lookalike   # submits, polls, asserts completed + settlement header
```

Then re-fetch the status URL **with a wrong token** and confirm **404**, and confirm the result
is still downloadable within 7 days and `410` after expiry is forced.

Correctness spot-check: scan `hyrule.host` and confirm permutations pointing at our own
IPs/nameservers come back `INFO` with `shares_address_with_target: true` — that is the
false-positive path, and the one most likely to be wrong.

**Failure-path check (do this deliberately — it is the part async makes riskier):** submit a
job, kill the worker mid-run, confirm the job lands `failed` with an `error` **and** a
`refund_owed` ledger row for the full amount. Then submit a `deep` job against a domain with no
registered permutations and confirm `degraded_to` is absent (nothing to degrade) rather than a
spurious surcharge refund.

**Blast-radius measurement on staging before enabling the worker:** run one full-cap
1 000-permutation `deep` job while watching Unbound `total.num.queries` / `num.query.tcpout` on
rtr and NAT64 session counts (`jool -i nat64 stats display --all | awk '$2 != 0'`). Confirm no
`POOL4_MISMATCH` growth and no Unbound rate-limit drops.

**Post-deploy:** check the `mon` Icinga problem list before and a few minutes after the
promote-SHA apply, per the deployment-safety rule.

---

## Risks and open items

1. **Charge-at-submit is the structural risk of going async.** We take money before doing the
   work, so the refund path is not optional — it is load-bearing and must be tested (see the
   failure-path check). Every refusable condition must be checked *before* `require_payment`.
2. **We would be the first consumer of `diagnostic_jobs`.** The schema is unused in production,
   so assume nothing about it is proven — verify the `FOR UPDATE SKIP LOCKED` claim under real
   Postgres, not just SQLite, and confirm the JSONB columns round-trip our result model.
3. **Registry ToS is the sharpest legal edge.** Verisign's WHOIS ToS forbids "high volume,
   automated, electronic processes". Mitigated by dropping port-43 entirely. **Open question:**
   bootstrap from IANA's RDAP bootstrap JSON and hit registry RDAP endpoints directly (24 h
   cached) rather than proxying through `rdap.org`, which is a *bootstrap redirector* and
   antisocial to hammer. Async makes this more pressing, not less — the deep tier covers 250
   targets per job.
4. **Dual-use.** Typosquat *detection* is standard commercial brand protection (dnstwist is
   Apache-2.0 and widely used in exactly this role). Choosing detection-only — no registrar
   links — removes the "shopping list of deceptive domains you can buy from us" framing
   entirely. Remaining mitigations: `cyrillic` and 2-round `homoglyph` are opt-in;
   `owner_wallet` + `target` are persisted on every job row, so abuse is attributable by
   construction; explicit acceptable-use line in the SKILL.md.
5. **Apache-2.0 attribution header** in a proprietary service — permitted, but wants a one-line
   sign-off. **Open question.** Precedent exists: we already carry per-source `license` /
   `license_url` metadata for blocklists.
6. **Unbound headroom is unmeasured.** The worker queue bounds this far better than an inline
   design would, but the authoritative-side and NAT64-session impact of a 1 000-permutation job
   is still unknown. Measured by the staging step above.
7. **Glyph-table maintenance** becomes ours. Cardinality-pinning tests catch accidental edits;
   upstream drift is a manual periodic refresh.
8. **Agent UX cost of async** — a submit→poll flow is two round trips instead of one. Mitigated
   by returning the full result inline from the status route (`DiagnosticJobResultResponse`
   already supports this) and by having the MCP tool poll internally. If agents turn out to want
   a one-shot call, a v2 `wait_seconds` parameter that long-polls up to ~25 s before returning
   the job envelope is the obvious addition.
9. **Homoglyph yield silently drops on long domains** (punycode >63 bytes). Surfaced via
   `generated_permutation_count` vs `scanned_permutation_count`; must not trip the completion
   ratio.
