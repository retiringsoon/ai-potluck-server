# ai-potluck-server

[![ci](https://github.com/retiringsoon/ai-potluck-server/actions/workflows/ci.yml/badge.svg)](https://github.com/retiringsoon/ai-potluck-server/actions/workflows/ci.yml)


The server of an AI potluck network: one process over one embedded SQLite
database. It runs the HTTP/WebSocket/SSE gateway, keeps the settlement books
(ledger, transparency log, receipts), and ships the operator CLI
`potluck-server` (`serve`, `admin invite|invite-list|revoke-key|api-key|api-key-list|api-key-revoke|reconcile`,
`verify receipt`).

Module layout follows one rule: the protocol and verification primitives live
in [`ai-potluck`](../ai-potluck) — the client package this one depends on — so
a client can verify a receipt without trusting the server. Server bookkeeping
and the gateway live here, and this package imports those verification
primitives from `aipotluck` to keep its own books. Consumers and contributors
never install this package; they install `ai-potluck` and run `potluck`.

## Install

```bash
uv venv --python 3.13 .venv
uv pip install -e ".[dev]"           # ai-potluck comes from the package index
.venv/bin/potluck-server --help
```

From a source checkout of both repositories (ai-potluck is not published yet):

```bash
uv pip install -e ".[dev]" -e "file://$(cd ../ai-potluck && pwd)"
```

Operator deployment (TLS, service supervision, tunnels, backups) is documented
in the client repository:
[ai-potluck/docs/server-deployment.md](../ai-potluck/docs/server-deployment.md).

## Run

```bash
potluck-server serve --config server.json
potluck-server admin invite --config server.json --role consumer --tenant friends
potluck-server admin invite --config server.json --role consumer --with-api-key
potluck-server admin reconcile --config server.json
potluck-server verify receipt --config server.json --receipt-id R-1
```

## OpenAI-compatible endpoint

The same process also serves `POST /openai/v1/chat/completions` and `GET
/openai/v1/models`, authenticated with an operator-issued API key, so a tool
that already speaks OpenAI's API works against the pool with nothing but a
`base_url`:

```bash
potluck-server admin api-key --config server.json \
    --subject consumer-1a2b3c --quota 500000 --name "the IDE"
# ak-…  (printed once; only its digest is stored)
```

An invite can carry that instruction instead, so the person who redeems it needs
no second command and no operator to run one:

```bash
potluck-server admin invite --config server.json --role consumer \
    --tenant friends --quota 500000 --with-api-key
# <code>  (printed once)   -> `potluck join` prints the key it issued, once
```

```python
client = OpenAI(base_url="https://<server>/openai/v1", api_key="ak-…")
client.chat.completions.create(model="coding-pool", messages=[…])
```

A key is capped by its own quota, revocable without a restart, rate-limited per
key, and it spends the **subject's own account** through the same metering,
settlement, transparency log and receipts as a signed request. One issued at join
is minted at that moment and not before — an unredeemed invite can spend nothing
— inherits the invite's quota, and stays a separate credential: revoking it
withdraws one tool, not the member. The full
reference — parameters, response and stream shape, the error table, limits,
observability, and exactly how a key-authorized receipt differs in evidence from
a consumer-signed one — is [docs/openai-endpoint.md](docs/openai-endpoint.md).

Embeddings and the legacy completions endpoint are not implemented and say so
(`404`, `error.type: not_supported`) rather than failing quietly.

## Development

```bash
uv venv --python 3.13 .venv
uv pip install -e ".[dev]" -e "file://$(cd ../ai-potluck && pwd)"

.venv/bin/python -m pytest tests/ -q --basetemp=.pytest_basetemp -n auto
.venv/bin/ruff check src/ tests/
.venv/bin/mypy
./scripts/release_gate.sh   # end-to-end: real install + the default join/ask path
```

The test suite here covers the server (gateway service and server, the server
store, provisioning, operator reconciliation) plus the cross-package
integration paths — client CLIs, connector and contributor wizard driven
against a real in-process server. The client-only protocol and unit tests live
in the `ai-potluck` repository.

`release_gate.sh` is what makes a commit releasable: it installs into a
throwaway prefix, then walks the documented default path — a fresh server with
no hand-written credentials, a node that joins on an invite alone, `share run`
against a local fake upstream, a consumer that joins on an invite alone, and
`ask` streaming and buffered, then again after a server restart, ending in
receipt verification on both sides and both reconciliations. It drives both
packages, which is why it lives here. It needs uv, a clean working tree in both
repositories, and permission to bind localhost ports; any failed step exits
non-zero with redacted logs.

`--basetemp` is only needed in sandboxes that block pytest from creating its
temporary directory under the system temp path. `-n auto` runs the suite in
parallel under xdist, which is safe because every server binds `port=0` and
every file a test touches is under its own `tmp_path`; drop it when debugging a
single test. `mypy` runs with `--strict` (configured in `pyproject.toml`) and
must stay at zero warnings.
