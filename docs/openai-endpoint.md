# The OpenAI-compatible endpoint

One server, one port, and a second surface next to the platform's own
`/v1/*` API: `POST /openai/v1/chat/completions` and `GET /openai/v1/models`,
authenticated with an operator-issued API key instead of an Ed25519 signature.

The point is a drop-in `base_url`. A tool that already speaks OpenAI's Chat
Completions API — an IDE plugin, a chat client, a script using the `openai`
package — points at the server and works, with no potluck-specific code, and
every request it makes is metered, settled and receipted by the same books as a
signed request.

```
base_url:  https://<server-host>:<port>/openai/v1
api_key:   ak-...            # minted by the operator, or issued by an invite at
                             # join — see below
```

## Minting a key

A key speaks for a consumer that already exists — an identity that joined with an
invite, or a consumer credential provisioned in `server.json`. It does not create
an identity and it cannot widen what that consumer may spend; it adds a ceiling
of its own and a way to withdraw access to one tool without touching anything
else.

```bash
potluck-server admin api-key --config server.json \
    --subject consumer-1a2b3c --quota 500000 --name "the IDE on the laptop"
# ak-<43 url-safe characters>            <- printed once, to stdout

potluck-server admin api-key-list --config server.json
# apikey-9f2c1a name="the IDE on the laptop" subject=consumer-1a2b3c
#   tenant=t-9f2c1a quota=1000/500000 remaining=499000 deadline=default
#   expires=never last_used=2026-10-12T09:31:07+00:00 active

potluck-server admin api-key-revoke --config server.json --key-id apikey-9f2c1a
```

* `--subject` is required and must name a consumer the server holds; a subject
  it does not know is refused rather than minted a key that could never settle.
* `--quota` is the total milli-credits the key may draw from that consumer's
  account. Under the default rate card one billed token costs one
  milli-credit, so `500000` is roughly half a million tokens.
* `--expires-in` (`30m`, `12h`, `90d`) is optional; omit it for a key that does
  not expire.
* `--deadline-ms` is optional and is the wall-clock budget every request on this
  key is given. Omit it and the endpoint's own default applies — see
  [Long tasks](#long-tasks-and-the-request-deadline).
* Only the SHA-256 digest of the key is stored. No command can read a key back,
  so a lost key is replaced, not recovered.
* Revocation takes effect on a running server immediately: every request on this
  surface re-reads the key's row. Revoking the *identity* behind a key
  (`admin revoke-key`) withdraws its keys too.

An invite can carry this instruction instead of an operator running it after the
fact — see [A key an invite issues](#a-key-an-invite-issues).

## A key an invite issues

The round trip above is optional. `--with-api-key` puts the instruction on the
invite, and the join that redeems it hands the joiner a key:

```bash
potluck-server admin invite --config server.json --role consumer \
    --tenant friends --quota 500000 --with-api-key
# <invite code>                              <- printed once, to stdout

potluck-server admin invite-list --config server.json
# 3f0c1a2b…c9d4 role=consumer tenant=friends api-key=yes uses=0/1 expires=… active
```

The person given that code needs no second command, and no operator to run one:

```bash
potluck join --server https://<server> --invite <code>
# potluck: joined as consumer-1a2b3c (role consumer, tenant friends, key consumer-1a2b3c); …
# ak-<43 url-safe characters>                <- printed once, on its own line
# potluck: this invite also issued an API key for the OpenAI-compatible endpoint …
#   base_url: https://<server>/openai/v1
#   shown once; store it now — the server stored only its digest, so a lost key is
#   replaced by the operator, never recovered
```

What the flag does, and what it deliberately does not do:

* **The key is minted at the join, not with the invite.** An invite nobody has
  redeemed has no key, no subject and no quota behind it, so a code that leaks
  before it is used is still only a way to join — and there is nothing to revoke
  until somebody joins. An unredeemed invite can spend nothing.
* **The key's quota is the invite's quota.** `--quota` funds the joiner's account
  once *and* caps the key they are handed, so one number is the whole budget for
  that member's tool. `--with-api-key` with `--quota 0` is refused at the
  command: a key with no quota admits nothing.
* **Only `--role consumer` may carry it.** A key spends a consumer account and a
  node has none, so `--role node --with-api-key` is refused rather than minted an
  invite that could only fail in front of whoever redeemed it.
* **The key stays its own credential.** It appears in `admin api-key-list` named
  `issued at join`, and `admin api-key-revoke` withdraws that one key: the
  identity keeps signing requests and its account keeps its balance.
  `admin revoke-key` on the identity withdraws the identity and every key it
  holds, exactly as before.
* **It carries no expiry and no per-request deadline of its own**, so it lives as
  long as the identity, stays revocable either way, and each request on it gets
  this endpoint's default window. A member who needs a longer window for
  agent-sized turns gets a key minted by hand with `--deadline-ms` — a separate
  key, with a separate quota, which the first one can then be revoked against.
* **A re-join shows no key.** `potluck join` is idempotent on the identity and
  the server kept only a digest, so a second run cannot reproduce the first
  one's plaintext and does not mint a second key. A lost key is replaced
  (`admin api-key --subject <subject>`), not recovered.
* **Nothing else about the request changes.** A key issued at join is admitted
  exactly like one an operator minted by hand — `gateway_authenticated`, the
  same dispatch, the same books, the same receipts. Arriving beside an identity
  does not make it a consumer signature; see
  [what the key authorizes](#billing-receipts-and-what-the-key-authorizes).

## Using it

```bash
curl https://<server>/openai/v1/chat/completions \
  -H "Authorization: Bearer $POTLUCK_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "model": "coding-pool",
        "messages": [
          {"role": "system", "content": "answer in one word"},
          {"role": "user", "content": "what settles a request?"}
        ],
        "temperature": 0.2
      }'
```

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://<server>/openai/v1",
    api_key="ak-...",
)

completion = client.chat.completions.create(
    model="coding-pool",
    messages=[{"role": "user", "content": "what settles a request?"}],
)
print(completion.choices[0].message.content)
print(completion.usage.total_tokens)   # the amount the server billed

for chunk in client.chat.completions.create(
    model="coding-pool",
    messages=[{"role": "user", "content": "and what backs the receipt?"}],
    stream=True,
    stream_options={"include_usage": True},
):
    ...
```

Which models exist is a question for the pool, not a catalogue: `GET
/openai/v1/models` lists what the connected, sharing nodes advertise right now,
and `GET /openai/v1/models/{id}` answers for one of them.

## What is supported

| Endpoint | Status |
|---|---|
| `POST /openai/v1/chat/completions` | supported, buffered and streaming |
| `GET /openai/v1/models`, `GET /openai/v1/models/{id}` | supported |
| `POST /openai/v1/embeddings` | **not implemented** — `404`, `error.type: not_supported` |
| `POST /openai/v1/completions` (legacy text completions) | **not implemented** — `404`, `error.type: not_supported` |
| audio, files, batches, fine-tuning, assistants, responses | **not implemented** — `404` |

The refusal is explicit on purpose: a tool pointed at the wrong surface is told
what is missing, rather than left to read a generic `404` as a wrong `base_url`.

### Request fields

| Field | Handling |
|---|---|
| `model` | required; must be one the pool can run now, else `404 model_not_found` |
| `messages` | required, non-empty; forwarded to the upstream **verbatim**, every turn, including `system`/`developer`/`assistant`/`tool` roles and structured (multimodal) content parts |
| `stream` | `false` (default) answers with one `chat.completion`; `true` answers with SSE `chat.completion.chunk` frames |
| `stream_options.include_usage` | with `stream: true`, adds one terminal chunk carrying `usage` and empty `choices` |
| `temperature`, `top_p`, `max_tokens`, `max_completion_tokens`, `stop`, `presence_penalty`, `frequency_penalty`, `seed`, `logit_bias`, `user`, `response_format` | forwarded to the upstream |
| anything else (`n`, `tools`, `tool_choice`, `logprobs`, `modalities`, …) | **ignored**, not forwarded |

`n` and `tools` are ignored because this surface produces exactly one text
choice: a response that silently dropped the other choices, or a model's tool
call it could not render, would be a wrong answer that looks like a right one.
A client that needs tool calling should use the platform's own `/v1/*` API.

### Agent sessions

One header, and nothing else about the request changes:

```
x-potluck-session: sess-9f2c1a…
```

A session is a label for one run of an agent loop, so the server can aggregate
that run's turns and prefer the node that served its last one. It is not a
credential and grants nothing: the aggregate it feeds is keyed by the tenant and
subject the **API key** authenticated, so naming somebody else's session cannot
attribute a charge to them.

An OpenAI SDK client sends it without touching the body:

```python
client = openai.OpenAI(
    base_url="https://<server>/openai/v1",
    api_key=os.environ["POTLUCK_API_KEY"],
    default_headers={"x-potluck-session": session_id},
)
```

`potluck serve-openai` — the loopback signing proxy in the client package — mints
one session per endpoint run and stamps it on every request it signs, printing it
at startup. A signed request on the platform's own `/v1/*` surface carries the
same identifier as a `session_id` field in the body instead, because that surface
is one canonical document.

What the server does with it:

* **Aggregation.** Requests, native tokens and milli-credits per session, with
  the tokens and credit counted only from turns that actually settled — so a
  session's totals are the books' numbers, not an estimate.
* **Sticky node preference.** The next turn of a session is offered to the node
  that served its last settled one, when that node is still connected, still
  sharing, not revoked, and has not declined this request. It is a preference and
  never a constraint: a node that is no longer a candidate is skipped, not waited
  for, so a session cannot be pinned to a node that went away.

```bash
potluck-server admin session-list --config server.json [--subject consumer-1a2b3c]
# sess-9f2c1a… subject=consumer-1a2b3c tenant=t-9f2c1a requests=14
#   tokens=183240 milli_credits=183240 last_node=node-A
#   last_seen=2026-10-12T09:31:07+00:00

potluck-server admin session-show --config server.json --session sess-9f2c1a…
# session=sess-9f2c1a… subject=consumer-1a2b3c tenant=t-9f2c1a
#   requests=14
#   tokens=183240
#   milli_credits=183240
#   last_node=node-A
#   created_at=2026-10-12T09:02:11+00:00
#   last_seen=2026-10-12T09:31:07+00:00
#   receipts=14
#     R-31 request=req-1f0c… log_index=30
```

`session-show` lists the receipts rather than only the totals, because a total an
operator cannot check against the records behind it is a claim rather than an
account: each id it names verifies on its own with `verify receipt`.

A session identifier may be empty, over 128 characters, or carry whitespace or a
control character — all refused with `400 invalid_request` rather than trimmed or
silently dropped, because it travels in a header and is printed by an operator
command. A caller that named a session and was quietly given none would read the
aggregate of a run it never joined.

The forwarded set is the set the platform has decided to honour, so an
upstream-specific field cannot become an undocumented way to change what a
contributor's node asks a provider for.

### Response fields

A buffered answer is a full `chat.completion`: `id` (`chatcmpl-…`, also sent as
the `x-request-id` header), `object`, `created`, `model`, one `choices[]` entry
with `message.role`, `message.content`, `message.refusal: null`,
`finish_reason: "stop"`, `logprobs: null`, and `usage`.

A stream is, in order: a chunk whose delta carries `role: "assistant"`, one
chunk per committed increment, a chunk with an empty delta and
`finish_reason: "stop"`, the usage chunk when `include_usage` was asked for, and
`data: [DONE]`. The `200` and the SSE headers are held until the first increment
exists or the request is terminal, so a request that fails before producing
anything is answered with its real status rather than with a `200` carrying an
error inside a stream. Once a frame has gone out, a later failure travels as an
error frame followed by `[DONE]`.

`usage.total_tokens` is the amount the server **billed** — the settled total on
the winning attempt's own row — not a sum of the two halves, so the number a
caller reads is the number the receipt behind it names. `prompt_tokens` and
`completion_tokens` come from the contributing node's final measurement, and stay
`0` when a node reported no split rather than being guessed from the total.

## Errors

Every refusal is OpenAI's error object — `{"error": {"message", "type", "code",
"param"}}` — with the server's `request_id` added to the body and the
`x-request-id` header when one exists.

| Status | `code` | `type` | When |
|---|---|---|---|
| `400` | `invalid_request` | `invalid_request_error` | body not JSON, no `messages`, an unknown role, a parameter of the wrong type, a value this server cannot forward |
| `401` | `invalid_api_key` | `invalid_request_error` | missing header, another scheme, unknown key, revoked key, expired key, or a key whose subject was revoked — all one answer, so the endpoint cannot be used to probe which keys exist |
| `400` | `invalid_request` | `invalid_request_error` | an `x-potluck-session` header this server cannot store |
| `404` | `model_not_found` | `invalid_request_error` | no node of this server runs that model; the message names the models it has nodes for |
| `404` | `not_supported` | `not_supported` | an OpenAI endpoint this platform does not implement |
| `429` | `insufficient_quota` | `insufficient_quota` | the key has spent its quota |
| `429` | `rate_limit_exceeded` | `rate_limit_error` | the key is at its concurrency ceiling or its request rate, **or** the server's dispatch queue is at its bound |

`model_not_found` is a statement about the *model*, not about the moment. It
answers a model no node of this server has advertised — a typo, which waiting
cannot fix — and it is read across every willing node, connected or not, because
a pool whose nodes are all mid-restart still serves the models they advertise. A
model the server does serve but has nothing free for right now is not refused at
all: it is queued, see [Limits](#limits).

A full dispatch queue and a per-key ceiling are different facts with the same
remedy, and the remedy is what an OpenAI client acts on: `429` with
`rate_limit_exceeded` is what makes an existing client's own backoff do the right
thing without learning a new code. The message says which of the two it was.
| `502` | `upstream_failed` | `server_error` | the server ended the request in failure; the message carries the server's own `billing_note` |
| `504` | `deadline_passed` | `server_error` | the request was still unfinished when the wait window closed, or the server's own deadline expired it |

`type` follows OpenAI's documented pairings, where OpenAI documents the case:
a condition the caller can act on is an `invalid_request_error` carrying a
specific `code`, a spent quota is `insufficient_quota`, a fault of the platform
is a `server_error`. Two values are this platform's own and are named as such
here: `not_supported`, and `rate_limit_error` for a per-key ceiling, where
OpenAI's own rate-limit errors name the dimension exceeded (`requests`,
`tokens`) instead — which does not describe a limit one key has hit.

A `504` is not a claim that the work stopped. The request may still be running
and is billed only if it settles, so the answer names the request id and points
at the way to check what it cost:

```bash
potluck-server verify receipt --config server.json --receipt-id R-12
potluck-server admin reconcile --config server.json
```

## Limits

Per key, so one leaked key or one client stuck in a retry loop cannot occupy a
server that every other key shares:

* **4 requests in flight**, counted from the durable request rows — the ceiling
  means the same thing after a restart, and a request an interrupted server left
  running still occupies its slot. A slot is never held past its deadline, though:
  every admission ends the overdue requests it finds before it decides anything,
  so a key whose slots are held by requests that can no longer finish is not
  refused at its ceiling forever.
* **60 requests per minute**, counted in the running process; a restart clears
  the window, which costs one window and nothing else.
* **one wait window that rides ~10% past the request's budget** per connection,
  deliberately longer than the request's own budget, so the server's deadline
  decides first and the answer names a request that can still be verified.

Per server, so a pool with nothing free holds a bounded amount of work rather
than every request that arrives:

* **a dispatch queue of 100 requests** by default, configurable in `server.json`
  as `max_queue_depth`, and switchable off entirely with `queue_enabled: false`.
  A request no node can take right now is *held* rather than refused: it waits in
  first-come-first-served order and is offered to a node when one frees up. At
  the bound the next request is refused with `429`.
* Holding a request changes **when** it is answered and never whether it is
  billed honestly. A queued request still carries its own deadline, and the same
  sweep that has always ended an overdue request ends it — as `EXPIRED`, with the
  server's own reason on its billing note, no attempt behind it, and no charge.
* The queue's position is best-effort, not promised: the order requests are
  offered in is their arrival order, but a request's own deadline — not its place
  in line — is what bounds its wait.

Both queue transitions land on the request's own event stream as `request.queued`
and `request.dispatched`, on the same ordered, replayable, never-rewritten stream
a node's `output.delta` rides. A request dispatched straight from its own
admission never joined the queue and gets neither frame.

The subject's own account balance remains the authority on money: a key whose
quota is left but whose subject's account is empty is refused by settlement,
exactly as a signed request would be.

### Long tasks and the request deadline

Two budgets, and they are not the same thing:

| Budget | Default | Set by | What it ends |
|---|---|---|---|
| the **request deadline** | thirty minutes | `admin api-key --deadline-ms` per key, else this surface's default | the *request*, at the server: past it the sweep ends the request `EXPIRED` and it is not billed |
| the **wait window** | the request budget +10% | derived, not configurable | the *HTTP connection*: past it the caller gets `504 deadline_passed` naming the request, which by then has ended |

Both windows are agent-sized by default and `--deadline-ms` raises the request
deadline to at most twenty-four hours (a hard ceiling, because a deadline that
never fires is how a request that can never finish holds a concurrency slot
forever). Through a reverse proxy, long turns should use **streaming**: streamed
increments keep the connection alive for however long the answer runs, while a
buffered call that is silently waiting can be closed by an intermediary's own
idle timeout before the server's deadline says anything. A caller that does lose
the connection gets the `504` with the request id, and the work — if it settles —
is still collected and verifiable:

```bash
potluck-server verify receipt --config server.json --receipt-id R-12
```

A caller that wants one long HTTP request to stay open for the whole turn needs a
key whose `--deadline-ms` is at or below the wait window; a caller that wants a
genuinely long turn needs the `504`-then-collect shape above, or the platform's
own `/v1/*` API, whose consumer client resumes by cursor rather than holding one
socket.

## Billing, receipts and what the key authorizes

Metering and settlement are not a second implementation. A request admitted here
runs the same dispatch, the same signed usage report from the contributing node,
the same ledger movement, the same transparency log and the same receipt as a
signed request, and the charge lands in the **subject's own account**. The key's
quota counts what those settlements actually billed, in the same transaction that
records them, so a replayed report cannot spend one request twice against a
quota.

One thing differs, and it is worth being precise about, because it is a
difference in *evidence*:

* A signed request carries the consumer's own Ed25519 signature over the exact
  conversation, model, delivery mode, parameters and ceiling. The party being
  charged signed the work.
* A request admitted on an API key carries an authorization signed by the
  platform's settlement key, labelled `auth_method: "gateway_authenticated"` —
  the protocol's own second method. The server signed the terms it admitted, on
  the strength of a credential it issued. The receipt keeps that label.

Both verify. `potluck-server verify receipt` follows the record's declared
method and reports `signature_valid: pass` for either, and an `auth_method`
this build does not define is reported as an anomaly rather than passed under a
guessed purpose. They are not the same strength of authorization, and nothing
here presents one as the other: a gateway-authenticated receipt proves the
platform admitted these terms for this subject and billed exactly this amount,
while a consumer-signed receipt additionally proves the consumer itself signed
them.

## Observability

Every request on this surface emits one structured line (canonical JSON, at
`INFO` on the `aipotluck_server.gateway_server` logger, which `serve` sends to
stderr):

```json
{"completion_tokens":200,"endpoint":"openai_chat_completions","key_id":"apikey-9f2c1a",
 "latency_ms":1284,"model":"coding-pool","outcome":"SUCCEEDED","prompt_tokens":800,
 "request_id":"req-1f0c…","status":200,"subject_id":"consumer-1a2b3c","total_tokens":1000}
```

`outcome` is the terminal request status, or `refused:<code>` for a refusal,
`client_gone` for a caller that hung up, `not_supported` and `model_not_found`
for the read endpoints. The line is written before the response goes out, so a
caller holding an answer is guaranteed the line describing it is already in the
log. A key is named by its id and never by its value: the plaintext is
credential material, and a log is exactly where such material must not
accumulate.
