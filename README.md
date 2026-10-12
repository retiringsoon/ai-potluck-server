# ai-potluck-server

[![ci](https://github.com/retiringsoon/ai-potluck-server/actions/workflows/ci.yml/badge.svg)](https://github.com/retiringsoon/ai-potluck-server/actions/workflows/ci.yml)


The center of an AI potluck network: one process over one embedded SQLite
database. It runs the HTTP/WebSocket/SSE gateway, keeps the settlement books
(ledger, transparency log, receipts), and ships the operator CLI
`potluck-server` (`serve`, `admin invite|invite-list|revoke-key|reconcile`,
`verify receipt`).

Module layout follows one rule: the protocol and verification primitives live
in [`ai-potluck`](../ai-potluck) — the client package this one depends on — so
a client can verify a receipt without trusting the center. Center bookkeeping
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
[ai-potluck/docs/center-deployment.md](../ai-potluck/docs/center-deployment.md).

## Run

```bash
potluck-server serve --config center.json
potluck-server admin invite --config center.json --role consumer --tenant friends
potluck-server admin reconcile --config center.json
potluck-server verify receipt --config center.json --receipt-id R-1
```

## Development

```bash
uv venv --python 3.13 .venv
uv pip install -e ".[dev]" -e "file://$(cd ../ai-potluck && pwd)"

.venv/bin/python -m pytest tests/ -q --basetemp=.pytest_basetemp
.venv/bin/ruff check src/ tests/
.venv/bin/mypy
./scripts/release_gate.sh   # end-to-end: real install + the default join/ask path
```

The test suite here covers the center (gateway service and server, the center
store, provisioning, operator reconciliation) plus the cross-package
integration paths — client CLIs, connector and contributor wizard driven
against a real in-process center. The client-only protocol and unit tests live
in the `ai-potluck` repository.

`release_gate.sh` is what makes a commit releasable: it installs into a
throwaway prefix, then walks the documented default path — a fresh center with
no hand-written credentials, a node that joins on an invite alone, `share run`
against a local fake upstream, a consumer that joins on an invite alone, and
`ask` streaming and buffered, then again after a center restart, ending in
receipt verification on both sides and both reconciliations. It drives both
packages, which is why it lives here. It needs uv, a clean working tree in both
repositories, and permission to bind localhost ports; any failed step exits
non-zero with redacted logs.

`--basetemp` is only needed in sandboxes that block pytest from creating its
temporary directory under the system temp path. `mypy` runs with `--strict`
(configured in `pyproject.toml`) and must stay at zero warnings.
