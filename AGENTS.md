# AGENTS.md — ai-potluck-server

Entry point for AI agents working in this repository. Read this before editing
code; [CONTRIBUTING.md](CONTRIBUTING.md) has the human workflow, and its rules
apply to agents too.

## What this repo is

ai-potluck-server is the center of an AI potluck network: one process over
one embedded SQLite database, running the HTTP/WebSocket/SSE gateway, the
settlement books (ledger, transparency log, receipts), and the operator CLI
`potluck-server`. It routes, meters, and settles — it never sees an upstream
credential, and clients can check its arithmetic against the public books.

**Companion repo:** [ai-potluck](https://github.com/retiringsoon/ai-potluck)
is the client (consumer + contributor CLIs, connector) and the protocol core.
Dependency direction is one-way: **verification primitives (canonical JSON,
Ed25519 signing, metering, ledger replay, transparency proofs) live in the
client package; the accounting gateway here depends on `aipotluck` and imports
those primitives to keep its own books**, so a client can verify a receipt
without trusting the center. Never make the client import from this package.

## Layout map (`src/aipotluck_server/`)

| Module | Purpose |
| --- | --- |
| `gateway_service.py` | Center domain logic: admission, dispatch, events, settlement — touches no socket and no disk directly |
| `gateway_server.py` | Transport half: terminates HTTPS/SSE for consumers and WSS for contribution nodes |
| `persistence.py` | Durable center store; keeps the whole world replayable (attempt winners, books, checkpoints) |
| `deploy.py` | `center.json` schema, provisioning, and inspection |
| `reconcile.py` | Operator-side reconciliation: read the center's own books |
| `cli.py` | `potluck-server` entry point (`serve`, `admin`, `verify`); `__main__.py` mirrors it |

Also: `tests/` (center suite + cross-package integration paths),
`scripts/release_gate.sh` (end-to-end install-and-run gate for both packages).
Operator deployment docs live in the client repo:
[center-deployment.md](https://github.com/retiringsoon/ai-potluck/blob/dev/docs/center-deployment.md).

## Build / test / verify

```bash
uv venv --python 3.11 .venv
uv pip install -e ".[dev]" -e "file://$(cd ../ai-potluck && pwd)"
python -m pytest tests/ -q --basetemp=.pytest_bt   # --basetemp is required locally
ruff check .
mypy                                                # strict
./scripts/release_gate.sh                           # end-to-end, both packages, clean trees
```

**Verification is evidence-based.** Never claim green without running the
command; a change is complete only when ruff, mypy, and the full pytest suite
all pass. The release gate additionally requires both this tree and the
sibling client checkout to be clean, so run it against committed work.

## Invariants (do not break)

1. **Signing semantics.** Ed25519 domain separation and canonical JSON
   (RFC 8785) — defined in the client package, consumed here — are the trust
   root. The center must never fork, re-implement, or reinterpret them; if
   they need to change, that is a protocol change in ai-potluck first.
2. **The books are the product.** Metering, settlement, the ledger, and the
   transparency log: any change must ship behavior-level tests (observable
   outcomes — balances, receipts, inclusion proofs, reconciliation reports —
   not implementation details). Restart and interruption paths must stay
   neither-double-charged nor silently-free.
3. **Fail loud.** Config loading and initialization must never swallow
   errors: reject unknown `center.json` keys, raise on missing required
   fields, and never paper over problems with `config.get(key, default)`. A
   wrong config must fail at startup with an actionable message, not
   misbehave at runtime.
4. **Forward-only.** No compatibility shims, no dual code paths. Deleting an
   old path and updating all its callers happens in the same change set. The
   only exception is persisted data formats (the SQLite store), which need a
   migration script.

## Agent hygiene

- Docs and code speak the same language: English.
- Never introduce absolute local paths, machine names, credentials, or other
  private/environment-specific information into committed files.
- Keep changes minimal and self-consistent: no drive-by refactors, no
  speculative scaffolding, no leftover TODOs or dead code.
