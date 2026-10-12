# Contributing to ai-potluck-server

Thanks for helping make shared AI access provable. This repo is the center:
the HTTP/WebSocket/SSE gateway, the settlement books, and the operator CLI
`potluck-server`. The client and protocol/verification core live in
[ai-potluck](https://github.com/retiringsoon/ai-potluck), which this package
depends on.

## Branching and dev workflow

- `dev` is the integration branch. All feature work lands here first.
- `main` is the release surface. It only ever receives verified merges from
  `dev` — never direct feature commits.
- Create your feature branch from `dev`:

  ```bash
  git checkout dev && git pull
  git checkout -b feat/your-change
  ```

- When the change is complete, open a pull request **into `dev`**.

## Local development setup

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/). Until `ai-potluck`
is published to a package index, install it from a sibling source checkout:

```bash
git clone https://github.com/retiringsoon/ai-potluck ../ai-potluck   # once
uv venv --python 3.11 .venv
uv pip install -e ".[dev]" -e "file://$(cd ../ai-potluck && pwd)"
```

### Tests

```bash
python -m pytest tests/ -q --basetemp=.pytest_bt
```

`--basetemp` is **required** for local runs: the sandboxed environments many
contributors use cannot write to the system temp directory. CI omits it
because runner temp space is writable. The suite includes cross-package
integration tests that drive real client CLIs and a real center.

### Lint and types

```bash
ruff check .
mypy
```

`mypy` runs in strict mode over `src/aipotluck_server` (configured in
`pyproject.toml`). A change is done only when ruff, mypy, and the full pytest
suite are all green — see [AGENTS.md](AGENTS.md) for the evidence rule.

### Release gate

```bash
./scripts/release_gate.sh
```

Proves a candidate source install of **both** packages works end to end
through the path a user actually takes (real `install.sh`, invite-only join,
default ask flow, restart accounting, two-sided receipt verification). It
requires a sibling `../ai-potluck` checkout (override with `CLIENT_ROOT`) and
**both trees clean**, so a pass is a statement about a commit, not about
uncommitted edits. Run it before calling any release-candidate change
releasable.

## Commit discipline

- **One commit = one user-visible value.** Prefix by kind: `feat:`, `fix:`,
  `docs:`, `test:`, `refactor:`. If you cannot state the user-visible value
  in the subject line, split or squash.
- Commit messages describe *what changed and why*, not the process. No
  session diaries, no absolute local paths, no throwaway branch names.
- Run the test suite before committing. Do not commit red.

## Pull request standards

- **Behavior-level tests.** Test what an operator or counterparty can
  observe — gateway behavior, books, receipts, reconciliation output — not
  implementation details. Every fix ships with a test that fails before the
  fix and passes after.
- **All green.** ruff, mypy (strict), and the full pytest suite pass in CI
  before review.
- **Docs in the same PR.** If the change affects `center.json`, operator
  commands, or the network contract, update `README.md` (and the client
  repo's `docs/` when the contract moves) in the same pull request.
- Keep PRs small and coherent; split unrelated refactors from behavior changes.

## Where to look next

- [AGENTS.md](AGENTS.md) — repo invariants (signing, books, fail-loud config,
  forward-only) that every change must respect.
- [SECURITY.md](SECURITY.md) — how to report a vulnerability privately.
- Client repo docs:
  [network contract](https://github.com/retiringsoon/ai-potluck/blob/dev/docs/network-contract-v0.1.md),
  [center deployment](https://github.com/retiringsoon/ai-potluck/blob/dev/docs/center-deployment.md).
- Questions or ideas before opening an issue:
  [Discussions](https://github.com/retiringsoon/ai-potluck-server/discussions).
