"""AI potluck server: the gateway and the books behind it.

The server side of the potluck network: the gateway service and server,
metering-driven settlement over the durable server store, and the operator
reconciliation. Module layout follows one rule — the protocol and verification
primitives live in the ``ai-potluck`` package this one depends on, so a client
can verify a receipt without trusting the server; server bookkeeping and the
gateway live here, and this package imports those verification primitives
from ``aipotluck`` to keep its own books.
"""

from __future__ import annotations

__version__ = "0.2.2"
