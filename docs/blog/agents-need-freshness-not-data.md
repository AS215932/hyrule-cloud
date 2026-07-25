# Your agent doesn't need more BGP data. It needs to know how old the data is.

*A real failure from running agents on our own network, and the fix we shipped.*

---

## The line that made us build this

> "Had I had this, I wouldn't have filed #480 on a false premise."

That's from a debugging session on AS215932 last night. An agent — with full access to our routers, packet capture, and every free public BGP API — investigated a routing problem, reached a confident conclusion, filed a GitHub issue, committed documentation, and posted a summary to a pull request.

The conclusion was wrong. Not because the data was wrong. Because the data was **ten hours old and didn't say so.**

## What actually happened

We had a real problem: customer VMs pulling packages at ~50 KB/s over native IPv6, while the same bytes over NAT64 moved at 96 MB/s. A 1,800× gap.

The diagnosis was solid and took real work — traceroute, tunnel byte counters, and a packet capture on the edge router filtered to the CDN's prefix. It showed a fully asymmetric session: requests leaving via our Swiss core, responses coming back through the Dutch one, with TCP reordering wrecking throughput. Egress policy was fine. The return path was never steered.

The fix: announce two `/48` more-specifics from the good core only. Longest-prefix-match is honoured by every AS on the internet, so return traffic gets pulled onto the good path deterministically. We deployed it.

Then came the only question that mattered: **did the announcement propagate?**

```bash
curl -s "https://stat.ripe.net/data/routing-status/data.json?resource=2a0c:b641:b51::/48"
```

```json
"visibility": { "v6": { "ris_peers_seeing": 0, "total_ris_peers": 324 } },
"origins": []
```

Zero out of 324 peers. Clear answer: the upstream is filtering us. The agent verified a plausible mechanism — no IRR `route6` object existed for the /48s, and transit providers build prefix-filters from IRR — filed an issue, committed a doc update, and posted a PR comment explaining that the change was inert.

Every step of that reasoning was sound. The premise was garbage.

## The tell, buried in the payload

```json
"query_time": "2026-07-24T16:00:00"
```

That response was served at 01:35 the next morning. The snapshot was from 16:00 the previous day — **35,997 seconds stale**, and hours older than the announcement it was being asked about. It could not have seen the /48s under any circumstances.

RIPEstat serves real-time and batch-computed data calls **from the same hostname, with the same response envelope**. `routing-status` is a periodic snapshot. `looking-glass` is computed at query time. Nothing in the URL, the status code, or the shape of the response distinguishes them. The freshness is one field, several levels deep, in a payload the caller is mostly skimming for the number they came for.

The real-time call, run thirty seconds later:

```
collectors: 4   peer entries: 6
as_paths: ['49544 58057 215932', '58057 215932', '56755 215932']
```

Live. Propagating. Visible via both our transit and our IX. The issue was filed on a false premise, and the fix it demanded — register IRR objects, chase the upstream — was not the thing standing in the way.

There's a second-order lesson in the correction, too. Once we measured properly, comparing the more-specific against the covering aggregate as a control, the real constraint appeared: the /48s reached *exactly* the same six peer-paths as the aggregate did via that upstream. Nothing was being filtered. That upstream just has a small footprint — about 1.6% of the observed paths to our network. "Being filtered" and "announced through a transit with narrow reach" look identical if you only measure the prefix you changed. You need the control to tell them apart, and an agent will only think to use one if the tooling makes freshness and comparison natural rather than expert knowledge.

## Why this is an agent problem specifically

A human network engineer has scar tissue. They know `routing-status` lags, because they've been burned. That knowledge lives in their head, not in the API.

An agent has no scar tissue. It has a schema. And the schema said `ris_peers_seeing: 0` with no warning attached — so it did exactly what a competent engineer would do with a trustworthy zero: it reasoned forward, confidently, and wrote its conclusion into three durable places.

**The expensive part was never the tokens.** The lookup cost fractions of a cent in compute. The cost was a wrong conclusion propagating into an issue tracker, a docs commit, and a PR comment — artifacts a human then has to find, read, disbelieve, and retract. Agents don't fail by producing garbage you can spot. They fail by producing something indistinguishable from good work, at speed, in permanent places.

Free data isn't cheap when it's silently stale. It's the most expensive kind.

## What we shipped

Not "more data." The same upstream, with the thing that was missing made structural.

**1. Freshness is a first-class field, not a footnote.** Every source now carries an explicit class, an observation timestamp, and an age:

```json
"routing_status": {
  "freshness": {
    "class": "delayed",
    "observed_at": "2026-07-24T16:00:00+00:00",
    "age_seconds": 35997,
    "stale": true
  }
}
```

**2. Stale data is reported as stale.** The old code hardcoded `status: "ok"` for a snapshot source regardless of its age. Now a source past its freshness budget returns `status: "stale"` with a message that names the fix:

> `snapshot is 35997s old; it cannot reflect announcements made since 2026-07-24T16:00:00. Use dataset live_looking_glass for a real-time answer.`

**3. A real-time dataset exists, and the docs say when to use it.** `live_looking_glass` queries RIS collector RIBs at request time — the only dataset that can answer "is this live right now?"

**4. The endpoint description tells an agent how to choose.** This is the part that matters for autonomous use. The old description was *"Paid BGP/routing lookup by prefix, IP, ASN, or router-table dataset"* — a list of nouns. An agent can't pick from that. The new one is written for a machine deciding between options:

> `live_looking_glass` ($0.01) queries RIS collector RIBs at request time and is the ONLY dataset that can answer 'is this prefix propagating right now?' — use it after any announcement, withdrawal, or filter change. `public_routing` ($0.005) is a periodically-recomputed snapshot that can be many hours stale; it is fine for 'who normally originates this?' but will report a freshly-announced prefix as invisible.

Selection criteria, freshness guarantee, and failure mode — in the discovery manifest, where an agent reads it before spending anything.

**5. Unimplemented means unimplemented.** Our internal router-table vantage isn't wired up yet. It now returns `status: "not_configured"` explicitly rather than a quiet empty result, because it's billed at a premium tier and silence would mean charging for data we never produced.

## The honest part

We did **not** ship this and then claim it would have saved us. We checked first — and the original endpoint would have failed identically, because it called the same stale `routing-status` and never called `looking-glass`. Paying $0.005 would have bought the same wrong answer with a receipt attached.

That's the actual lesson, and it cuts against the easy pitch: **a paid API is not automatically better than a free one.** Wrapping a stale source in a price tag just adds a charge to a bad answer. What makes an answer worth paying for is that it's *accountable* — it tells you what it saw, when it saw it, and when it can't help you.

And to be clear about the boundary: for our *own* routers, we don't pay anything. Internal MCP tooling reads our RIBs and runs packet captures directly. The paid surface is for the outside view — how the world sees a prefix — which is genuinely the harder thing to get right, and the thing we were wrong about.

## Two vantages, because they answer different questions

This session was the argument for multi-vantage, made the hard way:

- **External (RIS collectors):** does the world see this prefix? — Said yes. Correct.
- **Internal (our own RIBs and captures):** where does return traffic actually land? — Said Dutch core. Also correct.

Both true simultaneously. The announcement propagated *and* the return path hadn't moved yet. Either vantage alone tells you a confident half-truth. That's why we're building both, and why we label which one you're looking at.

## What this costs

| | |
|---|---|
| `public_routing` (snapshot, labelled) | $0.005 |
| `live_looking_glass` (real-time RIS) | $0.01 |
| One wrong issue, one bad commit, one retracted PR comment | considerably more |

A cent is not a compelling price for data you can `curl`. It's a compelling price for data that **refuses to mislead your agent** — and that difference only shows up on the day it matters, which is always a day you didn't plan for.

---

*Built on AS215932. The incident, the packet captures, and the fix are in the open at [github.com/AS215932/network-operations](https://github.com/AS215932/network-operations) — including the issue we filed on a false premise, and the correction.*
