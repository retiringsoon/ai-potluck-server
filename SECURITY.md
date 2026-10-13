# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

Only the latest release line on `main` receives security fixes. Fixes land on
`dev` first and reach `main` through the normal release flow.

## Reporting a vulnerability

Use **GitHub Private Vulnerability Reporting** — do not open a public issue:

<https://github.com/retiringsoon/ai-potluck-server/security/advisories/new>

Include: affected version, steps to reproduce, impact, and whether the report
also affects [ai-potluck](https://github.com/retiringsoon/ai-potluck) (file it
there too if so; cross-repo fixes are coordinated through both advisories).

## Response expectations

- Acknowledgement within 3 business days.
- Triage and an initial severity assessment within 7 business days.
- We aim to ship a fix or mitigation before public disclosure, and to agree on
  a disclosure timeline with you (default: 90 days).

## Scope

Highest priority — the trust core the server operates:

- Settlement books: ledger, receipts, and reconciliation correctness
- Transparency log integrity and checkpoint validation
- Metering and allocation arithmetic as applied by the gateway
- Admission control: invites, identity binding, and key revocation
- Protocol verification primitives (shared with
  [ai-potluck](https://github.com/retiringsoon/ai-potluck): Ed25519
  domain-separated signing, canonical JSON)

## Out of scope

- Denial-of-service reports (resource exhaustion, flood attacks)
- Social engineering of operators, contributors, or consumers
- Attacks requiring physical access to a participant's machine
