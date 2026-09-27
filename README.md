# THOR

**Evidence-driven web application security research**
by Nipun Dilshan · v5.1.0

Authorised targets only.

---

## Contents

1. [What this is](#1-what-this-is)
2. [The problem it was built for](#2-the-problem-it-was-built-for)
3. [The one idea everything follows from](#3-the-one-idea-everything-follows-from)
4. [Install](#4-install)
5. [Your first engagement, start to finish](#5-your-first-engagement-start-to-finish)
6. [How it works, layer by layer](#6-how-it-works-layer-by-layer)
7. [The safety model](#7-the-safety-model)
8. [The AI layer](#8-the-ai-layer)
9. [Command reference](#9-command-reference)
10. [What lives where](#10-what-lives-where)
11. [Testing philosophy](#11-testing-philosophy)
12. [Honest limitations](#12-honest-limitations)
13. [Where this actually ranks](#13-where-this-actually-ranks)
14. [Authorisation](#14-authorisation)

---

# 1. What this is

THOR is a command-line research platform for finding authorisation and
business-logic flaws in web applications you are authorised to test.

It is not a scanner. A scanner takes a URL, fires payloads, and reports
what came back looking odd. THOR builds a model of the application —
identities, tenants, objects, workflows — states the security rules that
model implies, and then tries to prove those rules false. A finding is
what survives the attempt.

Concretely: ~15,700 lines of Python across 42 modules, 44 CLI commands,
190 tests, and no runtime dependency beyond `httpx`, `pyyaml` and
`cryptography`. Everything lives in one SQLite file. It runs on a laptop
and costs nothing to operate.

```
                    OBSERVE                    corpus, recon, source, mobile
                       ↓
                     MODEL                     knowledge graph
                       ↓
              SECURITY INVARIANTS              what should hold
                       ↓
                  HYPOTHESES                   what could fail
                       ↓
             INFORMATION-GAIN RANK             what to test first
                       ↓
                 EXPERIMENT                    scope-gated, pinned, audited
                       ↓
              DETERMINISTIC ORACLES            bytes, not opinions
                       ↓
                 DISPROOF                      executed, not reasoned
                       ↓
              LIFECYCLE GATES                  code, not judgement
                       ↓
        ROOT CAUSE · CHAINS · EVIDENCE
                       ↓
                    REPORT
```

That column is a loop, not a pipeline. A confirmed hypothesis re-enters at
MODEL, because one proven boundary failure usually changes which of the
remaining questions is worth asking.

---

# 2. The problem it was built for

A researcher finding one or two valid bugs a month is usually not short of
effort or tooling. They are short of three things:

**Target selection.** Most hours go into surfaces that were never going to
pay. Nothing tells you which of 400 subdomains deserves the evening.

**Duplicates.** A valid finding three people already reported pays nothing
and costs the same hours. Above roughly 40% duplicates, the bottleneck is
not detection at all — it is which programs you pick and how fast you get
there.

**Report quality.** Triagers close reports that are not obviously
reproducible. A finding without a control, a disproof and a clean
reproduction is a coin flip regardless of whether it is real.

There is also a newer problem. Apple throttled bug bounty submissions over
AI-hallucinated reports. curl ended payments when the proportion of
legitimate reports fell below 5%. GitHub moved some payouts to swag. The
cost of a confidently wrong report has risen sharply, and an AI tool that
produces them is a liability to the person running it, not just to the
program.

THOR is built around that fact. The design goal is not maximum findings;
it is **a tool that cannot produce an unproven finding**.

---

# 3. The one idea everything follows from

**The AI never decides whether a vulnerability exists.**

Verdicts come from `diff.py` and `oracles.py` comparing observed bytes. A
model classifies parameters, ranks targets, proposes hypotheses and writes
prose from confirmed evidence. It has no path to creating or confirming a
finding, and three independent mechanisms enforce that:

1. `states.advance()` raises `PermissionError` for the AI actor.
2. A SQLite trigger aborts any write to `status`, `severity`,
   `disproof_done`, `evidence_ids`, `fingerprint`, `vuln_class`, `route`
   or `asset` made under `as_ai(db)`.
3. CI greps `ai.py` for `INSERT INTO findings` and authoritative `UPDATE`
   statements, and fails the build.

Three mechanisms because the first two were both once bypassed by the same
hole: the AI's attack-chain path called a function that inserted directly
into `findings`, with `disproof_done=1` and a model-chosen severity. A
model could produce a critical finding claiming its own disproof had run.
The module's docstring said *"No chain is inferred from a model's
narrative"* the entire time.

That is the recurring lesson in this codebase: **a documented invariant is
not an enforced one.**

---

# 4. Install

```bash
tar xzf thor-toolkit.tar.gz
cd thor_build
pip install -e ".[dev]"
make safety              # 140 negative security tests — run these first
thor doctor              # tools, scope, database
```

`[dev]` includes tree-sitter, which AST data-flow needs. Runtime-only:

```bash
pip install -e ".[ast,keyring]"
```

Without tree-sitter, `thor source scan` still extracts routes and says
plainly that data-flow was skipped. It does not fall back to regex and
call the result taint analysis.

## Recon tools (all optional; `thor doctor` prints these)

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
pipx install uro arjun
```

No amass — `subfinder + crt.sh + alterx + dnsx` covers the same ground in
minutes rather than hours.

## The vault key

Credentials are encrypted at rest and THOR refuses to store them any other
way. Set this before importing traffic:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
export THOR_VAULT_KEY=<that value>
```

Or install `keyring` and let the OS hold it, or use
`THOR_VAULT_PASSPHRASE`.

---

# 5. Your first engagement, start to finish

```bash
thor init --domain target.com          # writes scope.yaml + thor.db
$EDITOR scope.yaml                     # ← the important step
thor doctor
thor budget                            # what the engagement may spend
```

`scope.yaml` is the authority for everything. Copy the program's published
scope into it exactly:

```yaml
engagement: acme-public

allowed_hosts:
  - "api.acme.com"
  - "*.acme.com"

denied_hosts: []
allowed_methods: [GET, HEAD, POST, OPTIONS]
allowed_ports: []
denied_path_patterns:
  - "/logout"
  - "/(delete|remove|purge)/"

max_rps: 3                    # engagement-wide, not per engine
max_requests: 20000           # engagement-wide, survives restarts
max_concurrency: 4            # engagement-wide

window_start: "22:00"         # optional testing window
window_end: "05:00"
window_timezone: "Asia/Colombo"

sensitive: false              # gates engines that can write
destructive: false            # gates race testing and method sweeps

notes: |
  Program URL:
  Authorised by:
  Date:
```

Then:

```bash
# 1. surface map, overnight, zero tokens
thor recon target.com
thor triage                            # ranked by anomaly score

# 2. identities — at least two users plus anon
thor identity add userA --header "Authorization: Bearer ..." --tenant acme
thor identity add userB --header "Authorization: Bearer ..." --tenant globex
thor identity add anon  --role anonymous

# 3. authenticated traffic from Burp or a HAR export
thor capture session.xml --corpus prod --identity userA

# 4. optional, high value
thor source scan ./repo                # routes + AST data-flow
thor mobile analyse app.apk            # endpoints the web client never calls

# 5. model and reason
thor graph build --corpus prod
thor invariants
thor reason --corpus prod --persist
thor hypotheses next                   # what it would test, and why

# 6. hunt — deterministic, hours, no tokens
thor loop --corpus prod --minutes 240

# 7. correlate before writing anything
thor state advance
thor chain
thor rootcause
thor findings

# 8. clear the gates, then report
thor state gates --id 1
thor ai brief --kind impact            # then /impact in Claude Code
thor ai apply --kind impact --file answers/impact.json
thor state advance
thor report --id 1
thor reproduce 1
```

What the loop prints:

```
[invariants] catalogue: 34 rules (34 newly installed)
[loop] round 1 · 240m left
[loop] H-001 (tenant)  gain 1.30 = 1.0u × 1.0tena × 1.0n × 1.3d / 1.0c × 1.0r
  ✓ confirmed     tenant isolation may be enforced at routing rather than at
                  object retrieval
[loop] round 2 · 238m left
[loop] H-002 (authz)   gain 1.17 = 1.0u × 0.9auth × 1.0n × 1.3d / 1.0c × 1.0r
  ✗ disproved     GET /api/billing/invoices/{id} resolves an object the
                  caller does not own
[loop] round 4 · 233m left
[loop] H-003 (authz)   gain 0.21 = 0.238u × 0.9auth × 1.0n × 1.0d / 1.04c × 1.0r
[invariants] 2 violated, 0 hold, 32 untested
[state] 0 advanced, 1 held {"deduped": 1}
[state]   1 blocked by has_impact
[loop] 4 round(s): 1 confirmed, 3 disproved, 0 blocked
[loop] 1 replan(s), 4 hypotheses opened
[loop] findings 0 → 1
```

---

# 6. How it works, layer by layer

## 6.1 OBSERVE — getting the application into the database

| Source | Command | What it contributes |
|---|---|---|
| Recon | `thor recon` | subdomains, live hosts, endpoints, technologies, ports |
| Corpus | `thor capture` | **authenticated traffic** — the one that matters most |
| Source | `thor source scan` | route tables, AST data-flow, authority reachability |
| Mobile | `thor mobile analyse` | endpoints the web client never calls |

The corpus is the critical input. THOR's strength is authorisation
reasoning, and you cannot reason about authorisation without knowing what
a legitimate authorised request looks like. A Burp or HAR export of ten
minutes of real use as `userA` is worth more than a week of crawling.

Captured traffic is **sanitised before storage** — see §7.3.

## 6.2 MODEL — from requests to a world model

`schema.py` infers a grammar per endpoint: which fields exist, their
types, their roles (`id`, `money`, `target`, `file`, `email`, `state`),
and how stable each is across requests. Roles matter because payloads are
keyed to them — a traversal payload goes to a `file` field and nowhere
else.

`graph.py` builds a property graph in SQLite:

```
Asset ── exposes ──► Endpoint ── accepts ──► Parameter
  │                     │
  │                     └── accesses ──► Object ── owned_by ──► Identity
  │                                         │
  └── serves ──► Application            belongs_to ──► Tenant
```

Objects are learned from response bodies, not guessed from URLs. It
handles nested resources, JSON:API `relationships` arrays, GraphQL global
IDs, `customer_id`-style suffixes and opaque references — and explicitly
ignores pagination cursors, which look exactly like object ids and are
not.

## 6.3 INVARIANTS — what should be true

34 rules across 13 families, each naming an engine that can falsify it:

| Family | Count | Examples |
|---|---|---|
| authorization | 9 | object ownership, function-level, field-level, write, delete, bulk export |
| token | 6 | signature, algorithm, audience/issuer, OAuth code single-use, PKCE |
| workflow | 5 | monotonic state, server-computed state, terminal-state immutability, single-use under concurrency |
| tenancy | 2 | isolation, server-derived tenant |
| input | 2 | query separation, path canonicalisation |
| quota | 2 | quantity bounds, value conservation |
| identity · cache · egress · integrity · navigation · logic · injection | 1 each | |

The rule that keeps this honest: **an invariant with no engine that can
falsify it does not go in, and an invariant with no entry in the evidence
map cannot be evaluated.** Both are unit-tested. Twelve invariants once
shipped in the second state — installed, counted, invisible in every
report. `thor invariants` said "22 rules" while the catalogue held 34.

## 6.4 HYPOTHESES — what could fail, and what it costs to find out

`reason.py` turns violated-or-untested invariants into falsifiable
hypotheses, each with a statement, the invariant it tests, the target, an
exact experiment plan, a predicted observation and a falsifier.

Selection is by decomposed information gain:

```
        uncertainty × boundary_weight × novelty × coverage_deficit
gain =  ─────────────────────────────────────────────────────────
                        cost × risk_penalty
```

Every term is printed with its value:

```
gain 1.17 = 1.0u × 0.9auth × 1.0n × 1.3d / 1.0c × 1.0r
```

This is not a score to trust — it is an arithmetic statement you can argue
with. When a hypothesis ranks highly for a reason you disagree with, you
can see which term did it, and the fix is usually to correct the model
rather than the number. There are no magic constants.

Gains are recomputed every round. In the sample output above, H-003 fell
from 1.17 to 0.21 because two rounds of measurement raised its cost and
its disproved siblings cut its uncertainty.

## 6.5 EXPERIMENT — hypothesis-native execution

The loop does not walk a list of engines. `experiment.py` holds 17 engine
plans; `select()` re-scores every open hypothesis each round, `execute()`
runs the plan the winner names, and `replan()` fires on a confirmation:

```
OBSERVE → MODEL → HYPOTHESISE → SELECT → EXECUTE → JUDGE → UPDATE → REPLAN
                       ▲                                              │
                       └──────── a confirmation re-plans ─────────────┘
```

23 engines are declared with risk levels; 17 have plans the loop can
schedule; 4 are observation-only; 2 are declared and explicitly **not
implemented** (`smuggling`, `websocket`), with the reason printed by
`thor risk`. A unit test stops that table drifting back into claiming
capabilities that are not there — `websocket` sat there for months with a
risk level, a severity mapping and no implementation, telling operators
THOR could test WebSockets.

## 6.6 The control is re-fetched, not remembered

Every cross-identity comparison needs a control: the owner's own response
to the same request. THOR fetches it **immediately before the probe**, not
from the capture.

This is not pedantry. You export a Burp session in the evening and hunt
overnight; by probe time the object has a new timestamp, an incremented
counter, a field someone shipped that afternoon. Compared against the
stale capture the probe no longer looks like "the same object", a real
IDOR scores under threshold, and it is filed `inconclusive`. Nothing in
the output says a bug was probably missed, because from the engine's point
of view nothing happened.

One extra request per candidate, roughly 20–30% more traffic on an authz
run. A cheaper run that cannot tell a leak from drift is not cheaper.

The same refresh catches the other failure mode: if the owner now gets a
401 on their own object, the captured session has expired and every probe
against it is noise — so the candidate is skipped and you are told to
re-capture, rather than banking a row of `denied` verdicts that read like
a well-secured endpoint.

## 6.7 ORACLES — seven ways to judge, none of which match payload echo

| Oracle | What it takes as proof |
|---|---|
| `error` | a parser-level error the control did not produce |
| `boolean` | true- and false-condition responses differ, and the control matches neither |
| `timing` | delay payloads separate from controls with no distribution overlap |
| `oast` | an out-of-band callback correlated to this specific experiment |
| `differential` | the probe moved the response in a way an inert control did not |
| `reflection` | the payload landed in a parsing-relevant context, HTML-ish content type, breaking characters unencoded — and for template injection, the arithmetic actually evaluated |
| `invariant` | a 200 response computed a negative total, or stored a client-supplied state |

**A payload appearing in a response is never, on its own, a finding.** That
single rule removes most of what automated scanners report. Reflected XSS
requires a render context; SSTI requires `{{7*191}}` to return `1337`;
SQLi requires an error plus a boolean differential.

Blind classes require OAST. Without `interactsh-client` or a Collaborator
domain they are **skipped, not guessed**.

## 6.8 DISPROOF — executed, not reasoned about

Before a cross-identity finding is recorded, THOR sends the same request
with no credentials. If the anonymous request also returns the resource,
the resource is public and the finding is reclassified — not a broken
authorisation boundary. One extra request; it eliminates the most common
false IDOR.

The race engine works the same way, by contradiction. Two concurrent 200s
are not a race: an idempotent endpoint returns 200 to every copy. So after
the concurrent burst it sends one more sequential request. If that
succeeds, the operation accepts repeats by design and there was nothing to
bypass. If it is rejected, the server *does* enforce single-use — just not
under concurrency, which is the finding.

The control runs *after* the burst for a reason found by running it: a
single-use resource can only be spent once, so probing first consumes the
very thing being tested, and the real bug reads as clean.

## 6.9 THE FINDING LIFECYCLE — gates, not judgement

```
observed → hypothesis → candidate → verification_required
        → verified → deduped → report_ready → submitted
```

| Gate | Requires |
|---|---|
| `has_evidence` | stored request/response bytes, not a summary |
| `oracle_fired` | a named deterministic oracle above threshold |
| `control_executed` | the inert control was actually sent |
| `scope_proven` | every experiment carries the address the scope gate validated |
| `replayable` | method, URL, status **and a response hash to compare against** |
| `dedupe_checked` | a duplicate determination recorded for *this* finding |
| `has_impact` | impact written by a human — `[auto]` text is rejected |

Each result is recorded against that finding in `finding_gate_results`
with the evidence it read and the version of the rule, so "why is this
report-ready" has an answer months later.

```bash
thor state                  # everything, and where it is stuck
thor state gates --id 4     # which gate is holding it, and why
thor state advance
```

```
  hypothesis               PASS
  candidate                PASS
  verification_required    PASS
  verified                 PASS
  deduped                  PASS
  report_ready             HELD
        ✗ has_impact: no impact written — run /impact
  submitted                —

  '—' is not reachable until the gate above it passes.
```

Three of these seven were once theatre, and the failures ran in both
directions: `dedupe_checked` returned true if the `rootcauses` table
merely existed, so every finding passed the moment one unrelated finding
was analysed; `scope_proven` did `url LIKE '%asset%'`, which matched
`example.com` inside `notexample.com.evil.net` *and* blocked seven of ten
genuine findings whose asset string did not appear in a URL. Both came
from inferring gate facts later instead of recording them when the
evidence was produced.

## 6.10 CORRELATION — root cause, chains, dedupe

**Root cause.** Twenty IDORs behind one broken middleware is one bug.
Submitted separately that is nineteen duplicates and an annoyed triager.

```
CRITICAL  Application-wide object-level authorisation on api.target  (7)

  7 authz findings span 4 unrelated top-level resource families
  (billing, crm, hr, support) across 4 route prefixes. That breadth rules
  out a per-route mistake or a single middleware. The likely cause is a
  shared data-access layer that resolves objects by identifier without
  scoping the query to the caller.
```

Four rules, each stating the *defect it proposes* rather than just the
similarity. Three routes under one prefix are attributed to shared
middleware, not to the data layer — the more specific claim wins. Grouping
is metadata in a relation table, never a finding state.

**Chains.** A chain is a severity-escalating claim, so it needs more
evidence than a single finding, not less. Every link must itself have
reached VERIFIED, and the chain's severity is the highest among its links,
never the proposer's — including when the proposer is the AI.

```bash
thor chain              # build, propose, verify what can be verified
thor chain candidates   # what was proposed and why it did or did not verify
```

A "chain" with one link is not a chain; it is the same bug with a more
exciting title. Those become **severity escalations** on the finding
itself, under a named rule:

```
**Severity basis:** raised above the baseline for this class by:
  - `pii-returned-to-unauthorised-identity` (high→critical): the
    unauthorised response contained PII fields (email) belonging to
    another user
```

Every automatic severity change works this way. Nothing escalates because
it feels worse, and a triager can see which rule did it and argue with it.

## 6.11 EVIDENCE AND REPORTING

```bash
thor evidence 1     # a replayable bundle
thor report --id 1  # triager-ready markdown
thor reproduce 1
```

```
finding.json        the finding, credentials redacted
request.json        every step, bodies base64-encoded, plus provenance
replay.py           a constant — reads request.json, sends, compares
replay.sh           a constant — two lines, `exec python3 replay.py`
creds.json.example  a template you fill in; never written from the vault
```

Running it:

```
[owner baseline] GET http://api.acme.com/api/billing/invoices/5001
  expected: 200 75 bytes sha256=2157d8092fa315b4
  observed: 200 75 bytes sha256=2157d8092fa315b4 -> REPRODUCED

[probe as userB] GET http://api.acme.com/api/billing/invoices/5001
  expected: 200 75 bytes sha256=2157d8092fa315b4
  observed: 200 75 bytes sha256=2157d8092fa315b4 -> REPRODUCED
```

The bundle is deliberately not a general HTTP client. It refuses any host
outside the allowlist recorded from the finding's own steps, does not
follow redirects (a redirect can leave the authorised host), stops at a
recorded request budget, and supports `--dry-run`. It carries provenance —
tool version, bundle version, scope hash, experiment ids — so a bundle
replayed a year later under a different scope is recognisable as a
different experiment.

Reports include a **Limitations** section stating what the finding does
not establish. A report that only argues one way reads as advocacy; naming
the limits is what makes the rest credible, and it stops a triager finding
the gap first.

## 6.12 LEARNING

```bash
thor learn
```

```
arm                                              hits  runs  rate  90% CI
tenant|header|scoping|bulk_export|foreign_key       6     9  0.64  0.38-0.90
oauth|redirect|-|auth_flow|-                        5    14  0.38  0.19-0.57
cors|-|-|collection|-                               0    44  0.02  0.00-0.06
```

Thompson sampling over Beta posteriors built from your own outcomes. Arms
are keyed on `engine | technique | role | archetype | relation`, not engine
alone: "authz testing works" is not a useful prior, but "authz testing via
header swap against a bulk-export archetype on a foreign-key relation
works" is one you can act on — and it stops a strong result on admin
routes raising expectations everywhere else.

Cold arms are uniform, so the loop explores; it becomes opinionated only
once it has evidence. Disproved hypotheses are kept deliberately, so the
scheduler stops retrying what already failed.

---

# 7. The safety model

This is the part that matters most, and the part that has been wrong most
often.

## 7.1 Scope and destination pinning

`scope.yaml` is the authority. Every outbound request passes
`Scope.check()`, which returns a pinned `Destination`; `net.py` connects
to that address and nowhere else. There is no bypass path.

`Scope.check()` handles what breaks naive allowlists: IDNA normalisation,
trailing dots, userinfo (`https://allowed.com@evil.com`), IPv4-mapped
IPv6, decimal and octal IP encodings, and a hard deny list for RFC1918,
loopback, link-local and cloud metadata addresses that no scope file can
override.

Redirects are revalidated hop by hop rather than followed by the HTTP
library, and the connection is pinned to the validated address so DNS
cannot change under it between resolution and connection.

Two details are load-bearing and easy to break:

- **`trust_env=False`.** Left at its default, httpx reads
  `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` from the environment — and a
  proxy terminates the connection itself, so the address that was
  validated and pinned is no longer the address the socket reaches. The
  whole gate, undone by an environment variable. A safety test asserts
  this for all six proxy variables.
- **No engine may construct its own client or budget.**

## 7.2 One engagement boundary, not one per engine

```bash
thor budget
```

```
engagement     acme-public
requests       1284 / 20000   (18716 left)
rate limit     3 rps, engagement-wide
concurrency    4, engagement-wide
window         22:00-05:00 Asia/Colombo
```

Every engine reaches the same budget, rate limiter and concurrency
semaphore through `runtime.py`. They used to build their own: each
`Client(scope)` did `Budget(scope.max_rps, scope.max_requests)`, so a
scope permitting 20,000 requests permitted that many **per engine** —
nineteen times over — and `max_rps: 3` became 3 rps each.

The `Budget` docstring said "Global request budget" the whole time.

A published rate limit is a term of the authorisation, not a courtesy.
"My scanner had a bug" is not a defence anyone accepts. The counter is
persisted, so it survives restarts too — running `thor loop` four times
used to send four budgets' worth against a program that authorised one.
Clearing it is deliberate:

```bash
thor budget reset --confirm
```

Testing windows are evaluated in `window_timezone`, and an unrecognised
timezone falls back to UTC rather than to local time, so a typo cannot
silently shift a contractual window.

## 7.3 Credentials

```
identities table  ──►  credential_ref (cred_a1b2c3…)
                              │
                              ▼
                   encrypted vault (Fernet)
                   key from OS keyring, passphrase, or THOR_VAULT_KEY
```

Vaulting identities was the easy half. **A Burp or HAR export carries the
same bearer token, plus the session cookie, plus whatever password was
posted to `/login`** — and the corpus importer wrote all of it straight
into `requests`. Four columns leaked: headers, request body, response
body, and `object_refs`, which treated `password` as an object identifier
and stored its value (and would have tried swapping it between identities
as an IDOR test).

So the import sanitises before it stores:

```
requests table                          vault
  headers      <vaulted:a4dc…>      ──►  original headers
  body         {"password":"<vaulted:3c78…>"}   original body
  resp_body    sanitised            ──►  original response
  body_sha256 / resp_sha256   hashes of the ORIGINAL, so a replay can
                              still prove it reproduced the request
```

Structure survives: object references, business fields and response shapes
are untouched, so schema inference and differential comparison work
exactly as before. Only credential *values* change, to a stable
fingerprint, so two requests carrying the same session still correlate. If
the originals cannot be encrypted, **the import fails** rather than
storing them in the clear.

Redaction on the way out is not a substitute. The database is the thing
that gets copied between machines, attached to reports, and kept long
after the engagement ends.

There was a test asserting none of this leaked. It read `t.db` and checked
the token was absent. SQLite in WAL mode keeps recent writes in
`t.db-wal`, so it inspected a 4 KB file header while 144 KB of secrets sat
beside it, and passed for months. Every test now reads `*.db*`.

**A credential that will not resolve stops the run.** If the vault is
locked or a reference is missing, `identity.load_all()` raises rather than
returning an identity without its Authorization header. The old behaviour
was worse than a crash: `userA`, `userB` and `anon` all collapsed into the
same credential-free identity, every probe went out unauthenticated, every
one came back 401, and each was recorded as `denied`. The run reported a
cleanly secured application, having tested nothing, with complete
confidence.

## 7.4 Risk gate

| Level | Meaning | Engines |
|---|---|---|
| PASSIVE | reads stored data only | schema, anomaly |
| SAFE | ordinary reads | recon, authz, graphql, cors, pathacl, redirect, tenant, jsintel, sourcemap |
| ACTIVE | sends crafted input | jwt, cache, protopollution, fuzz, oauth |
| SENSITIVE | can write | bfla, massassign, workflow, upload |
| DESTRUCTIVE | genuinely changes state | race, smuggling |

`sensitive: true` and `destructive: true` raise the ceiling. `thor risk`
shows what is permitted, what is gated off, and what is declared but not
implemented.

## 7.5 Audit trail

Every request, refusal, verdict and state transition goes to
`.thor/audit.jsonl` with correlation ids:

```json
{"ts":"2026-09-27T00:06:50Z","run":"94613ebb2229","engagement":"acme",
 "engine":"authz","event":"hypothesis.closed","hypothesis":2,
 "status":"confirmed","gain":1.17,"leaks":1}
```

`vault.redact()` runs on every path out — bundles, reports, AI briefs, and
the audit log itself.

---

# 8. The AI layer

THOR is built for a Claude Pro subscription: roughly 10–40 prompts per
five hours, shared with everything else you use Claude for. That budget
shapes the design.

**There is no agent loop.** The full cycle runs as deterministic code, for
hours, at zero token cost. The model is consulted only at checkpoints the
loop names when it finishes:

```
[loop] AI checkpoints worth a prompt:
  /impact    — 1 verified finding(s) need an impact section
  /dedupe    — check disclosures; duplicates cost more than false positives
  /fuzz      — design app-specific logic mutations for business fields
```

A real agent loop would exhaust a Pro quota in about ten minutes — and the
XBOW-benchmark attribution study found it would not beat a plain coding
agent anyway.

| The AI may | The AI may not |
|---|---|
| classify parameters and object references | create a finding |
| rank targets for attention | change a finding's status |
| propose hypotheses and experiments | set severity |
| propose attack chains | mark a disproof complete |
| write impact, remediation, narrative, CVSS | invent evidence or a response |
| review root-cause grouping | decide a duplicate |

When it tries anyway, you are told:

```
[state] REFUSED AI writes to ['severity', 'status'] on finding 1 — these
decide whether the finding is true, and only code that observed bytes may
set them
```

That message exists because containment used to be silent: the fields were
filtered out one layer earlier and nobody learned the model had reached
for them. A model reaching for `status` is the clearest available signal
that it is trying to decide the finding.

**Prompt injection.** Target-derived text — response bodies, HTML, JS,
source comments, mobile strings, GraphQL descriptions — is fenced with
`ai._wrap_untrusted()` before it reaches a model. Page content is data,
never instructions. Safety tests cover injection attempts in bodies,
headers, source comments and JS strings.

**Slash commands.** Fourteen in `.claude/commands/` turn the checkpoints
into one-word prompts: `/thor`, `/loop`, `/reason`, `/hypotheses`,
`/state`, `/boundary`, `/triage`, `/classify`, `/fuzz`, `/chains`,
`/rootcause`, `/dedupe`, `/impact`, `/source`.

---

# 9. Command reference

**Setup and posture**

```bash
thor init [--domain X]              write scope.yaml + thor.db
thor doctor                         tools, scope, database
thor risk                           which engines the scope permits
thor budget [reset --confirm]       engagement-wide request ceiling
thor vault check                    what the vault can open
thor identity add|list              vault-backed credentials
```

**Observation**

```bash
thor recon <domain>                 full surface map
thor triage                         rank targets by anomaly score
thor nuclei                         known-CVE pass
thor capture <har|xml> --corpus X   import authenticated traffic
thor source scan|dataflow|correlate <path>
thor mobile analyse <apk>
thor snapshot · thor diff           attack-surface change detection
```

**Model and plan**

```bash
thor schema --corpus X              infer request grammars
thor graph build|show               the knowledge graph
thor invariants                     which hold, which are violated
thor reason --corpus X [--persist]  ranked hypotheses
thor hypotheses [next|run|replan]   the ledger and planner
```

**Engines**

```bash
thor authz        cross-identity replay (IDOR / BOLA)
thor tenant       cross-tenant isolation matrix
thor bfla         method swap + privileged route access
thor massassign   privileged field injection
thor fuzz         grammar-aware semantic fuzzing, seven oracles
thor oauth        OAuth / OIDC (RFC 9700)
thor workflow     business-logic state machine
thor detect       targeted detectors
thor probe        redirect, sourcemap, prototype pollution, upload
thor race         concurrency (destructive; needs a control)
thor all          full deterministic sweep
thor loop --corpus X --minutes N    the whole thing, hypothesis-native
```

**Findings and output**

```bash
thor promote                        experiments → findings
thor state [gates|advance|reject]   the lifecycle
thor chain [candidates|verify]      attack chains
thor rootcause                      group by shared defect
thor findings · thor stats · thor learn · thor status
thor evidence <id> · thor report --id <id> · thor reproduce <id>
thor audit [--tail N]
thor ai brief --kind {triage,classify,impact,fuzz,chains}
thor ai apply --kind X --file answers/X.json
```

---

# 10. What lives where

```
thor/
  scope.py       the authority. host/port/method/path rules, DNS pinning
  net.py         the ONLY HTTP client. scope-gated, pinned, audited
  runtime.py     the engagement: one budget, rate limit, concurrency
  vault.py       encrypted credentials + capture sanitisation
  identity.py    identity resolution, fails closed
  db.py          SQLite schema, migrations, serialised writes
  audit.py       structured event log

  corpus.py      HAR/Burp import, object-reference extraction
  recon.py       subdomain → live host → endpoint pipeline
  schema.py      request grammar inference
  graph.py       the knowledge graph
  sourceintel.py route extraction from source
  dataflow.py    tree-sitter AST taint, call graph, authority reachability
  mobile.py      APK/IPA endpoint extraction
  jsintel.py     JS bundle analysis

  invariants.py  34 security invariants
  reason.py      hypothesis generation, information gain
  experiment.py  17 engine plans, selection, execution, judgement
  learn.py       Thompson sampling over outcomes
  loop.py        the deterministic research loop

  engine.py      authz, bfla, massassign, race
  probes.py      tenant, prototype pollution, redirect, upload
  detectors.py   targeted detectors
  fuzz.py        grammar-aware semantic fuzzing
  oauth.py       OAuth / OIDC
  workflow.py    business-logic state machine
  oracles.py     the seven oracles
  diff.py        response normalisation and comparison
  oast.py        out-of-band correlation

  states.py      the finding lifecycle and its gates
  evidence.py    promotion, severity, bundles
  chain.py       chain candidates, verification, severity escalations
  rootcause.py   defect grouping
  replay.py      the standalone reproduction runner
  report.py      triager-ready markdown
  risk.py        engine risk levels and the gate
  ai.py          briefs and answer application
  cli.py         44 commands

tests/
  safety/        140 negative tests — run first, alone
  unit/          38
  regression/    12 end-to-end suites against labs with planted bugs + decoys
```

---

# 11. Testing philosophy

```bash
make safety       # 140 negative security tests
make unit         # 38
make regression   # 12 end-to-end suites
make test         # all 190
```

**The safety suite runs first and alone.** If THOR can be made to send an
out-of-scope request, leak a credential, exceed the engagement's budget,
or let a captured response body run a command on your laptop, its hit rate
is irrelevant. CI asserts the suite has not shrunk below 136 tests, so it
cannot be quietly emptied to make a build pass.

Six structural assertions hold by construction, independent of any test
exercising them: replay scripts are fixed templates, no engine mints its
own budget, `trust_env` is disabled, `ai.py` has no path to `findings`,
only `states.py` writes `findings.status`, and the corpus sanitises.

The regression labs plant known bugs **and decoys**. The decoys matter as
much:

```
--- planted vulnerabilities found ---
  PASS  IDOR · SQLi · SSTI · SSRF→metadata · path traversal
  PASS  negative-total logic · ACL bypass · reflected XSS
  PASS  cross-tenant via header · OAuth redirect bypass
  PASS  workflow replay · prototype pollution · guard mismatch
  PASS  TOCTOU proved with a sequential control

--- decoys correctly ignored ---
  PASS  correctly scoped 403 endpoint
  PASS  genuinely public endpoint
  PASS  reflects into JSON (not a render context)
  PASS  reflects but HTML-encoded
  PASS  idempotent endpoint (two 200s is not a race)
```

A CLI smoke test runs every subcommand the way a shell does, and a second
test fails if a new subcommand is missing from its list. An import rewrite
once left fifteen of forty-seven commands raising `NameError` at call time
while the whole suite stayed green — unit tests import modules and call
functions, and the CLI is the one layer none of them touch.

## Two lessons worth stating plainly

**Run the thing before believing the tests.** Every serious defect in
recent versions was found by running a real engagement and reading the
output, or by writing the exploit first — never by reading code, and never
by the suite, which was green throughout.

**A documented invariant is not an enforced one.** Two of the worst
defects were hidden by artefacts that looked like coverage: the "no bearer
token in the database" assertion read `t.db` while the secrets sat in
`t.db-wal`, and `Budget`'s docstring claimed "Global" while its
constructor made a new one per caller. When a docstring states an
invariant, add the test that enforces it or delete the claim.

---

# 12. Honest limitations

- **It has never been run against a real target.** Every one of the 190
  tests is against a lab written by the same process that wrote the tool.
  That is the single most important caveat in this document. The
  false-negative rate in the wild is unknown, and labs systematically
  flatter the tool that plants the bugs in them.
- **Not the most powerful exploitation engine.** It detects and proves; it
  does not chain to shell, escalate, or pivot.
- **No browser.** No DOM XSS, no postMessage, no client-side prototype
  pollution, no single-page-app flows that never issue a distinguishable
  request. A real coverage gap, not a design statement.
- **Duplicate checking is half-built.** Local signals and root-cause
  grouping are computed; the remote disclosure check is a `/dedupe` prompt
  because it needs judgement about what counts as the same bug.
- **Data-flow is inter-procedural but not whole-program.** Taint follows
  function parameters across files to bounded depth, and authority follows
  the caller chain. A taint crossing a service boundary, a queue, a
  dynamic dispatch or an ORM's own scoping is not followed — those come
  back UNKNOWN rather than being reported as missing checks.
- **The loop cannot invent engines.** It schedules what exists. A new bug
  class needs a plan and an oracle that can judge it; the scheduler is
  never the bottleneck, the oracle is.
- **Information gain is a heuristic, not a measurement.** Legible and
  arguable, not optimal.
- **The state machine can strand a real bug.** A finding that cannot clear
  `replayable` on a target with per-request nonces is genuinely blocked,
  and THOR will not wave it through. That is the intended trade: a missed
  finding is a cost you absorb, a stream of unproven reports is your
  account.
- **The anomaly scorer needs ≥8 hosts** for a meaningful baseline.
- **Timing oracle under-reports.** It demands no control overlap, so
  behind a CDN expect nothing.
- **One target at a time.** No distributed execution, no fleet.

## Deliberately not included

| | why not |
|---|---|
| Neo4j, Postgres, Redis, pgvector, OpenSearch | Five datastores before the first finding. SQLite does JSON, FTS and recursive CTEs. |
| Cloud / Kubernetes / CI-CD modelling | Different disciplines. The correlation value needs cloud observations to correlate *with*, and a web-app corpus has none. |
| gRPC, JSON-RPC | Need proto definitions or reflection a web-app engagement rarely has. An engine with nothing to feed it is a capability claim, not a capability. |
| Request smuggling, active cache poisoning | Can affect other users of a live service. |
| Multi-agent AI debate | Five times the cost for a verdict that is still a model's opinion. |
| Per-finding Bayesian confidence | Theatre unless calibrated. Real posteriors live in `learn.py`, where the data to fit them exists. |
| Browser automation | Genuinely valuable; also a subsystem. Deferred honestly rather than half-built. |
| Web dashboard, SaaS | Productising something before it has found a bug. |
| An agent loop | Would exhaust a Pro quota in ten minutes and underperform a plain coding agent. |

---

# 13. Where this actually ranks

You asked for an honest ranking. Here it is, including the parts that are
not flattering.

## 13.1 The caveat that outranks everything else

**THOR has never been run against a real target.**

Every one of the 190 tests is against a lab written by the same process
that wrote the tool. That is a structural problem, not a gap in effort: a
lab flatters the tool that plants the bugs in it. I know THOR finds the
IDOR I hid in `test_pipeline.py` because I hid it where an engine I wrote
would look.

What is genuinely unknown until you run it on a real program:

- the false-negative rate — how many real bugs it walks past
- whether the gates strand findings that a human would report
- whether the information-gain ordering beats simply running every engine
- whether the duplicate rate is any better than your current one
- whether any of the modelling survives contact with a real application's
  weirdness

Everything below should be read with that in mind. A tool with 190 passing
tests and zero field validation is an *argument*, not a result.

## 13.2 What it is genuinely good at

Three things, stated at the confidence the evidence supports:

**Authorisation reasoning across multiple identities.** Modelling
identities, tenants and object ownership as first-class entities, then
systematically replaying across them with a contemporaneous control and an
executed anonymous disproof, is more rigorous than what most scanners do
here — most test as a single user and cannot reason about ownership at
all. *Confidence: high on the design, unmeasured on real targets.*

**Refusing to report what it has not proved.** Seven per-finding gates, an
AI layer with no write path to a verdict, oracles that never treat payload
echo as evidence, and a disproof that is executed rather than reasoned
about. I do not know another open tool with an explicit "this cannot be
reported yet, and here is the gate holding it" mechanism. *Confidence:
high — this one is verifiable by reading the code and the tests.*

**Reproducible evidence.** A bundle that replays with hashes, refuses
hosts outside the finding's own allowlist, and carries provenance. Reports
that state their own limitations. *Confidence: high.*

That is a narrow set. Notice what is not on it: finding more bugs.

## 13.3 Head to head

| Against | Who wins | Honest reason |
|---|---|---|
| **Burp Suite Pro** (~$475/yr) | **Burp, clearly** | It is a platform: interception, Repeater, Intruder, a mature scanner, Collaborator, 300+ extensions, and a human in the loop. THOR consumes Burp's exports and is a complement, not a replacement. If you buy one thing, buy Burp. |
| **Caido** | Caido | Same relationship as Burp: a better interactive platform. THOR sits downstream of it. |
| **Nuclei** (free) | **Nuclei, by a wide margin, on breadth** | ~10,000 templates covering CVEs, misconfigurations, exposures, takeovers. THOR has 27 vulnerability classes and no CVE knowledge at all. Different job: a template cannot find an authorisation flaw specific to your app's object model, and THOR cannot find last week's CVE. THOR shells out to nuclei for exactly this reason. |
| **ZAP** (free) | ZAP on coverage, THOR on precision | ZAP has a mature crawler, more classes, and an active community. It also produces materially more false positives, and tests as one identity. |
| **Invicti / Acunetix / Detectify** ($10k–50k/yr) | **Them, overall** | Mature crawling, JS rendering, enterprise reporting, support. Invicti's "proof-based scanning" is philosophically close to THOR's oracles and got there first, commercially. THOR's multi-identity authz modelling is more sophisticated than most commercial DAST — but that is one axis out of ten. |
| **XBOW** | **XBOW, clearly** | Reached the top of the HackerOne US leaderboard with real, paid findings. Large team, large funding, real exploitation, real validation. THOR is one person's tool with one philosophical advantage and no field record. The gap is not close. |
| **Shannon (96.15%), LuaN1aoAgent (90.4%)** on the cleaned XBOW benchmark | **Them, on exploitation** | They will out-exploit THOR substantially. They will not tell you which subdomain is worth an hour, whether three people already reported it, or that seven findings share one middleware. |
| **CodeQL / Semgrep** | **Them, overwhelmingly, on source** | CodeQL does whole-program interprocedural dataflow with a query language and years of engineering. `dataflow.py` is ~1,000 lines with bounded-depth propagation. THOR's only source advantage is that it correlates a source finding to *live runtime behaviour on the same target*, which CodeQL does not attempt. |
| **reconftw / Osmedeus** | Them, on recon | Broader recon pipelines. THOR's recon is deliberately minimal and wraps the same ProjectDiscovery tools. |
| **PentestGPT and similar LLM wrappers** | **THOR** | Most are a model with a prompt and no verification layer. This is the one comparison THOR wins comfortably, and it is not a high bar. |
| **A skilled operator driving Claude Code directly, no harness** | **Genuinely unclear — and this is the comparison that matters** | See below. |

## 13.4 The comparison that actually matters

The baseline worth measuring against is not XBOW. It is **you, with
Claude Code, and no THOR at all.**

Published attribution work on the XBOW benchmark found a default coding
CLI solved a large share of web exploitation tasks unaided (~92.3%
pass@1), that security-specific prompting made results *worse*, and that
harness architecture contributed only about 5–10 percentage points of
residual. That is a hostile finding for a tool like this, and it should
be taken seriously rather than explained away.

THOR's honest claims against that baseline are **workflow** claims, not
detection claims:

| Claim | Real? |
|---|---|
| Runs for hours at zero token cost | Yes. A Pro plan gives ~10–40 prompts per five hours; `thor loop` uses none. |
| Cannot hallucinate a finding | Yes, and it is enforced three ways. A bare agent can and does. |
| Produces a bundle a triager can replay | Yes. An agent produces a transcript. |
| Remembers across engagements | Yes — Beta posteriors over your own outcomes. |
| Enforces a scope and rate limit | Yes. An agent respects them if you remind it every time. |
| **Finds more bugs than you would with Claude Code** | **Unproven. Possibly false.** |

If you only measure findings-per-target, THOR may not beat that baseline.
Its case rests on cost, safety, reproducibility and duplicate avoidance —
which is a real case for a bug bounty hunter, because those are the things
that decide whether a finding turns into a payout. But it is a different
case from "it finds more".

## 13.5 A number, since you asked

Two numbers, because they differ sharply and conflating them is how tools
get oversold.

**As an architecture: 8 / 10.** The evidence discipline, the per-finding
gates, the AI containment, the engagement-wide safety boundary and the
recorded-fact approach to verification are genuinely unusual, and several
of them I have not seen in comparable tools. It loses points for coverage
gaps that are design choices with real costs (no browser), and for a
source layer well behind the state of the art.

**As a tool you would rely on today: 5 / 10.** Unvalidated in the field,
narrow class coverage, no client-side testing, one author, no users, weeks
old. Every one of those is a legitimate reason for someone to pick Burp
plus nuclei instead and be better off this month.

Per axis:

| Axis | THOR | Notes |
|---|---|---|
| Evidence & reproducibility | 9 | The strongest part |
| Safety / scope discipline | 9 | Engagement-wide budget, pinning, vault, audit |
| False-positive resistance | 8.5 | By design; unmeasured in the field |
| Authorisation / multi-identity depth | 8.5 | The reason to use it at all |
| Root cause & duplicate grouping | 7.5 | Local signals good, remote check manual |
| Hypothesis planning | 7 | Legible, arguable, not proven better than round-robin |
| Cost | 10 | Free, and the loop spends no tokens |
| Vulnerability class breadth | 5 | 27 classes, no CVEs, no client-side |
| Recon breadth | 5 | Deliberately thin; wraps standard tools |
| Source analysis | 4 | Bounded; CodeQL is a 9 here |
| Exploitation depth | 2 | Detects and proves; does not exploit |
| Client-side / browser | 1 | Absent |
| **Real-world validation** | **0** | **The number that should worry you** |
| Maturity / support / ecosystem | 3 | One author, no users |

## 13.6 Who should and should not use this

**Worth trying if:** you already have authenticated traffic for a target,
you are hunting authorisation and business-logic bugs specifically, you
care more about report quality than report count, and your duplicate rate
is what is hurting you.

**Not worth it if:** you want broad automated coverage (use nuclei plus a
DAST), you are hunting client-side bugs (it has no browser), you want
something battle-tested (it is not), or you want a tool that exploits
rather than proves.

## 13.7 How to find out for real

The ranking above is my estimate. Here is how to replace it with a
measurement, which is worth more:

1. Pick **five programs you already know**, where you have a baseline
   sense of what is findable.
2. Run THOR on each with the same time budget you would normally spend.
3. Track four numbers, nothing else:
   - **validated findings per 100 hours** (your current baseline: roughly
     1–2 per month — so anything above ~3 per month is a real result)
   - **duplicate rate** — above ~40%, the problem is program selection,
     not the tool, and no amount of engineering here fixes that
   - **cost per accepted report** in hours
   - **anomaly precision** — of the top 10 ranked targets, how many
     yielded anything
4. Then run the same five programs with Claude Code and no THOR, and
   compare. If the harness does not beat that baseline, the honest
   conclusion is to delete the harness, and I would rather you reach it
   with data than keep using something out of sunk cost.

Report what you find. The most useful thing you could tell me is a case
where a gate blocked something you could demonstrate by hand — that is a
gate that is wrong in the strict direction, and it still costs you
reports.

---

# 14. Authorisation

Only run THOR against targets you are explicitly authorised to test. Put
the program URL and the authorisation date in `scope.yaml`'s `notes` field
so the record travels with the engagement.

The scope gate will refuse anything else, and the audit log will record
that it did.
