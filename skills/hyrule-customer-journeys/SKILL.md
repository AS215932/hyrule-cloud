---
name: hyrule-customer-journeys
description: "Run and document one of Hyrule's outcome-led x402 proof journeys: diagnose a broken website/TLS deployment, buy and verify an agent email identity then diagnose a rejected message, or deploy a fresh VM and return connection details. Use when the result must include an exact prompt, reproducible command, evidence, exact cost, and elapsed time."
---

# Hyrule Customer Journeys

Turn a requested outcome into one bounded, reproducible proof. Do not market a
catalog of endpoints. Use the smallest sequence of Hyrule calls that produces
the requested evidence.

## Select the journey

- Website/TLS: explain why a URL or TLS deployment is broken.
- Agent identity/email: buy a domain and mailbox, prove controlled send and
  receive, then explain any rejection or spam placement.
- VM deployment: provision a fresh VM for a declared workload, use its
  automatic hostname, and return connection details.

Read the matching exact prompt in [references/exact-prompts.md](references/exact-prompts.md).
Preserve the user's budget, candidate domains, recipient, and workload rather
than silently inventing replacements.

## Execute a proof

1. Record UTC start time and a redacted run id.
2. Discover current products, prices, terms, payment networks, and readiness.
3. Quote every state-changing purchase. Ask once before exceeding the user's
   total cap; otherwise proceed within the stated authority.
4. Use a high-entropy idempotency key for each paid create. Save capability
   tokens outside logs and redact them from the result.
5. Poll every asynchronous resource to a terminal or usable state.
6. Verify the outcome from the public internet, not only from a control-plane
   success field.
7. Record each settled amount separately. Do not count free discovery or 402
   challenges as spend.
8. Record UTC finish time and elapsed seconds.

## Produce the customer-journey result

Return these fields in order:

- Outcome and one-sentence explanation.
- Redacted resource identifiers and public evidence.
- Exact commands/calls used, with secrets replaced by `<redacted>`.
- Cost table: quoted, settled, uncharged, and total.
- Elapsed time: quote, payment, provisioning/diagnosis, verification, total.
- Findings ranked by severity, with observation separated from inference.
- Remediation or connection details.
- Cleanup/expiry dates and anything that will be deleted automatically.

Never label a template, simulation, or planned canary as a real result. If a
provider or launch gate is unavailable, stop before payment and report the
precise gate instead.
