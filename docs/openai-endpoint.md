# The OpenAI-compatible endpoint

One center, one port, and a second surface next to the platform's own
`/v1/*` API: `POST /openai/v1/chat/completions` and `GET /openai/v1/models`,
authenticated with an operator-issued API key instead of an Ed25519 signature.

The point is a drop-in `base_url`. A tool that already speaks OpenAI's Chat
Completions API — an IDE plugin, a chat client, a script using the `openai`
package — points at the center and works, with no potluck-specific code, and
every request it makes is metered, settled and receipted by the same books as a
signed request.

```
base_url:  https://<center-host>:<port>/openai/v1
api_key:   ak-...            # minted by the operator, see below
```

## Minting a key

A key speaks for a consumer that already exists — an identity that joined with an
invite, or a consumer credential provisioned in `center.json`. It does not create
an identity and it cannot widen what that consumer may spend; it adds a ceiling
of its own and a way to withdraw access to one tool without touching anything
else.

```bash
potluck-server admin api-key --config center.json \
    --subject consumer-1a2b3c --quota 500000 --name "the IDE on the laptop"
# ak-<43 url-safe characters>            <- printed once, to stdout

potluck-server admin api-key-list --config center.json
# apikey-9f2c1a name="the IDE on the laptop" subject=consumer-1a2b3c
#   tenant=t-9f2c1a quota=1000/500000 remaining=499000 expires=never
#   last_used=2026-10-12T09:31:07+00:00 active

potluck-server admin api-key-revoke --config center.json --key-id apikey-9f2c1a
```

* `--subject` is required and must name a consumer the center holds; a subject
  it does not know is refused rather than minted a key that could never settle.
* `--quota` is the total milli-credits the key may draw from that consumer's
  account. Under the default rate card one billed token costs one
  milli-credit, so `500000` is roughly half a million tokens.
* `--expires-in` (`30m`, `12h`, `90d`) is optional; omit it for a key that does
  not expire.
* Only the SHA-256 digest of the key is stored. No command can read a key back,
  so a lost key is replaced, not recovered.
* Revocation takes effect on a running center immediately: every request on this
  surface re-reads the key's row. Revoking the *identity* behind a key
  (`admin revoke-key`) withdraws its keys too.

## Using it

```bash
curl https://<center>/openai/v1/chat/completions \
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
    base_url="https://<center>/openai/v1",
    api_key="ak-...",
)

completion = client.chat.completions.create(
    model="coding-pool",
    messages=[{"role": "user", "content": "what settles a request?"}],
)
print(completion.choices[0].message.content)
print(completion.usage.total_tokens)   # the amount the center billed

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

`usage.total_tokens` is the amount the center **billed** — the settled total on
the winning attempt's own row — not a sum of the two halves, so the number a
caller reads is the number the receipt behind it names. `prompt_tokens` and
`completion_tokens` come from the contributing node's final measurement, and stay
`0` when a node reported no split rather than being guessed from the total.

## Errors

Every refusal is OpenAI's error object — `{"error": {"message", "type", "code",
"param"}}` — with the center's `request_id` added to the body and the
`x-request-id` header when one exists.

| Status | `code` | `type` | When |
|---|---|---|---|
| `400` | `invalid_request` | `invalid_request_error` | body not JSON, no `messages`, an unknown role, a parameter of the wrong type, a value this center cannot forward |
| `401` | `invalid_api_key` | `invalid_request_error` | missing header, another scheme, unknown key, revoked key, expired key, or a key whose subject was revoked — all one answer, so the endpoint cannot be used to probe which keys exist |
| `404` | `model_not_found` | `invalid_request_error` | no connected, sharing node runs that model; the message names the models the pool can serve |
| `404` | `not_supported` | `not_supported` | an OpenAI endpoint this platform does not implement |
| `429` | `insufficient_quota` | `insufficient_quota` | the key has spent its quota |
| `429` | `rate_limit_exceeded` | `rate_limit_error` | the key is at its concurrency ceiling or its request rate |
| `502` | `upstream_failed` | `server_error` | the center ended the request in failure; the message carries the center's own `billing_note` |
| `504` | `deadline_passed` | `server_error` | the request was still unfinished when the wait window closed, or the center's own deadline expired it |

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
potluck-server verify receipt --config center.json --receipt-id R-12
potluck-server admin reconcile --config center.json
```

## Limits

Per key, so one leaked key or one client stuck in a retry loop cannot occupy a
center that every other key shares:

* **4 requests in flight**, counted from the durable request rows — the ceiling
  means the same thing after a restart, and a request an interrupted center left
  running still occupies its slot. A slot is never held past its deadline, though:
  every admission ends the overdue requests it finds before it decides anything,
  so a key whose slots are held by requests that can no longer finish is not
  refused at its ceiling forever.
* **60 requests per minute**, counted in the running process; a restart clears
  the window, which costs one window and nothing else.
* **one wait window of ~110s** per connection, deliberately longer than the
  request's own 100s budget, so the center's deadline decides first and the
  answer names a request that can still be verified.

The subject's own account balance remains the authority on money: a key whose
quota is left but whose subject's account is empty is refused by settlement,
exactly as a signed request would be.

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
  the protocol's own second method. The center signed the terms it admitted, on
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
