# The admin page

One optional second listener, on the same process and the same database, that
shows the operator what the server is holding: who is asking, which nodes are
serving, what the queue looks like right now, and what the books have settled
today, this week, and over the lifetime of the deployment.

```bash
potluck-server serve --config server.json --admin-ui 9802
# potluck-server: server platform-1 serving https://127.0.0.1:8801 (node link wss://…)
# potluck-server: admin page http://127.0.0.1:9802/ (loopback only, read-only;
#   tunnel it with ssh -L 9802:127.0.0.1:9802 <host>)
```

Open `http://127.0.0.1:9802/` on the server's own machine, or tunnel to it from
yours:

```bash
ssh -L 9802:127.0.0.1:9802 server.example.com
# then open http://127.0.0.1:9802/ locally
```

The flag is the whole configuration. There is no `admin_ui` key in
`server.json`, no account to create and no token to mint: without the flag no
socket is bound and the database is not opened a second time, so a server that
was not asked for a page has exactly the surface it had before.

## What it is not

It is not a console. Every route is a `SELECT`; there is no endpoint that
changes anything, and the page offers no button that could. Minting an invite,
revoking a key and reconciling the books stay where they are — in
`potluck-server admin`, which authenticates by being run on the server, and
prints its own evidence.

It is not authenticated, either, and that is the reason for the two invariants
below. The page names every consumer subject, every node and every receipt this
server has settled. On a reachable interface that is a public read-out of the
operator's books over plain HTTP, so it is not on a reachable interface.

## Loopback only

The listener binds an IPv4 loopback literal — `127.0.0.1` by default, and any
address in `127.0.0.0/8` — and refuses to start on anything else:

| asked for | answer |
| --- | --- |
| `127.0.0.1`, `127.9.9.9` | bound |
| `0.0.0.0`, `::` | refused: these mean every interface |
| `::1` | refused: this listener is IPv4, and a second family is a second way to be wrong |
| `localhost`, any hostname | refused: a name is resolved through host files this process does not control |
| `10.0.0.5`, any routable address | refused |

The refusal is `NonLoopbackAdminBindError`, its own type rather than a message
to grep for, so a caller can tell "this address would publish the books" from
"this port is busy". `serve --admin-ui` takes a port and cannot ask for an
address; the check exists for the programmatic caller, and it runs before the
store is opened and before any socket exists.

Reach the page from another machine through a tunnel, which authenticates with
the SSH key the operator already holds and leaves the listener on loopback:

```bash
ssh -L 9802:127.0.0.1:9802 server.example.com     # one shell
xdg-open http://127.0.0.1:9802/                    # the same machine, a browser
```

Do not put this port behind the reverse proxy that fronts the gateway, and do
not forward it with a `GatewayPorts`-style SSH option. Both turn a
loopback-only page into a public one, and unlike the gateway it has no rate
limit, no authentication and no TLS.

## Read-only

The page opens the server's database with `ServerStore.open_read_only`, a
`file:…?mode=ro` URI. Read-only is therefore SQLite's answer rather than the
reader's promise: a statement that writes is refused by the engine with
`attempt to write a readonly database`, and the schema creation and migration
every other opener runs are not attempted at all, because a reader has no
business upgrading a database another process owns.

Nothing else about the server changes when the page is on. The database stays
in WAL mode, so a reader does not block the single writer and sees every
committed row, including one written after it opened; the page holds no lock
between two polls. The suite asserts the invariant against the file rather than
against the code: serving every endpoint, with the server's own writer still
holding the database open, leaves the database and its write-ahead log
byte-identical.

## No dependencies

`GET /` answers one HTML document with its CSS and JavaScript inline. No CDN,
no framework, no webfont, no image, no second request to any other host: a
server deployed on a machine with no route to the internet still gets its
dashboard, and the page cannot be used to make an operator's browser contact a
host the operator did not choose.

Every response carries the browser-side half of the same rule:

```
Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline';
  style-src 'unsafe-inline'; connect-src 'self'; form-action 'none'; base-uri 'none'
Cache-Control: no-store
X-Content-Type-Options: nosniff
```

`default-src 'none'` means an edit that forgets the rule still cannot load
anything, and `connect-src 'self'` is the only fetch the page may make — to the
five endpoints below, on the origin that served it. `no-store` keeps a shared
proxy or a browser profile from holding on to numbers that describe a live
server.

## Endpoints

Same origin as the page, `GET` only, canonical JSON (RFC 8785) — the same
spelling the wire uses, so a document can be hashed and compared. Any other
verb answers `405` with `Allow: GET`; an unknown path answers `404`.

| path | what it returns |
| --- | --- |
| `/admin/api/overview.json` | the health cards: consumers, nodes, requests, tokens, milli-credits, throughput, queue, database size, platform id and version |
| `/admin/api/consumers.json` | every consumer subject, ranked by what it spent |
| `/admin/api/nodes.json` | every node, with its link state and the work it settled |
| `/admin/api/sessions.json` | the agent-session aggregates, most recently active first |
| `/admin/api/receipts.json` | the most recently settled requests' current receipts |

The four listings take `?limit=`, defaulting to 50 and capped at 500. A limit
outside `1..500`, or one that is not an integer, answers `400` with the reason:
an empty table and a server with nothing in it are the same picture, and only
one of them is true.

```bash
curl -s http://127.0.0.1:9802/admin/api/overview.json
curl -s 'http://127.0.0.1:9802/admin/api/consumers.json?limit=10'
```

## What the numbers mean

The aggregates read the store's own tables, so a figure on the page is a figure
the books hold, spelled the way `admin reconcile` and `admin session-list`
spell it.

**Windows are a cohort.** Every windowed figure counts the requests *admitted*
inside it, together with the tokens and credit those requests settled. A
request admitted at 23:59 and settled at 00:01 belongs to the day it was
admitted and to no other, so "today" answers what today's requests cost rather
than what settled while the clock said today. "Today" starts at UTC midnight,
which is the only day boundary a store that writes every instant in UTC can
name without guessing a timezone. `tokens_per_hour_1h` and
`tokens_per_hour_24h` are the same rule over an hour and a day; the 24-hour
rate is the window's total divided by 24 and rounded, because canonical JSON
carries no floats.

**Tokens and milli-credits are two numbers.** Tokens are the receipt's own
measured total, what the upstream consumed; milli-credits are what the winning
attempt recorded, what the consumer was billed. They are equal while pricing is
face value and are read from different places so that a rate card changing one
cannot silently change the other. The pair is the one `admin reconcile`
cross-checks.

**A correction is counted once.** A settlement correction writes a second
receipt for the same request, stating the corrected total rather than the
difference, so every aggregate reads a request's *current* receipt — its highest
log index — and `/admin/api/receipts.json` lists one row per request. The
corrected-away revision stays in the table, in the transparency log and in
`admin reconcile`'s reach; it is simply not the current one.

**A node's work is the work it settled.** `requests_served`, `tokens` and
`milli_credits` count the requests whose winning attempt was this node's. An
offer a node refused, and a superseded branch that spent tokens nobody was
billed for, are facts about attempts — visible in the store and in `admin
reconcile`, not here. A node that is connected and has served nothing appears
with zeros, which is the state an operator most wants to see.

**Consumers include the ones who never asked.** The ranking is over every
subject this server knows as a consumer: every consumer credential, every
consumer identity and every subject a request names. A subject that joined and
never asked is listed with zeros and no last-seen instant, rather than being
absent and leaving the operator to notice.

**Sessions are the store's aggregate.** `sessions.json` is the same rows
`admin session-list` prints, under a cap: requests counted at admission, tokens
and credit counted only for turns that settled. A request that named no session
— which is every request the client's `request` command makes — is aggregated
nowhere, and the page says so with an empty table rather than with an estimate.

**Queue and in-flight are the server's own definitions.** Queue depth is the
number of requests in `ROUTING`, which is exactly the set the admission gate
counts against `max_queue_depth`; in-flight is the number in `RUNNING` or
`RECOVERING`, which is work a node has and has not finished.

**A hole is not a zero.** If a receipt's winning attempt is missing from the
attempts table, its milli-credits and node are reported as absent (`null`)
rather than as 0: the first says the page cannot tell, the second would say the
consumer was billed nothing. That missing row is a defect `admin reconcile`
names.

**Database size is the filesystem's answer**, in bytes and rendered for the
card: the database file, plus the write-ahead log the running server has not
checkpointed yet. A WAL that grows without bound is a checkpoint problem, and
it is visible here before it is a disk problem.

## The page

A dark single page, no images: a header naming the platform, the server version
and the instant the numbers were read, then a row of cards and four tables.

1. **cards** — consumers (total and active in 7 days), nodes (connected over
   total, with sharing off), queue depth and in-flight, requests, tokens and
   milli-credits (today with the 7-day figure beneath), tokens per hour (last
   hour, with the 24-hour average beneath), and the database size with its WAL;
2. **consumers** — subject, requests, tokens, milli-credits, sessions, last
   seen, ranked by spend;
3. **contribution nodes** — node, model, link state, sharing, requests served,
   tokens, milli-credits, last seen;
4. **agent sessions** — session, subject, requests, tokens, milli-credits, last
   node, last seen;
5. **recent receipts** — receipt, subject, node, tokens, milli-credits, the
   request's status, its log index and when it settled.

It re-reads all five endpoints every 10 seconds. A poll that fails says so in a
banner and leaves the last good numbers up, because blanking the page would hide
the figures an operator is watching while telling them nothing about why they
vanished. Cell values are written through `textContent`, never parsed as
markup, so a subject id or a model name that looks like HTML is displayed
instead of executed.

## Costs

The page polls five aggregate queries every ten seconds, and the listings rank
over a consumer's or node's whole history. At the deployment this document
targets — one process, one SQLite file, a few dozen people — that is
sub-second work on the reader side and nothing at all on the writer's, which
WAL keeps unblocked. The expensive part is the per-request join to a receipt;
it is bounded by the number of settled requests, not by the number of stored
events, because tokens are read from the receipt rather than from the stream.
