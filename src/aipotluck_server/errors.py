"""Center-side failures the shared protocol hierarchy does not name.

`aipotluck.errors` owns the vocabulary both packages speak — a signature that
does not verify, an account that cannot cover a charge, a record that conflicts
— and every failure the center raises is one of those, so a caller can handle
the platform's answers without knowing which package raised them.

Two conditions belong to the center alone, because they exist only on the
admission path that authenticates a caller with an operator-issued API key
rather than with a signature it produced. They live here rather than in the
domain module so the transport can map them to a status without importing the
module it is deliberately testable without, and rather than in
`aipotluck.errors` because neither is part of the wire protocol: no peer ever
receives one as a protocol message.
"""

from __future__ import annotations

from aipotluck.errors import PotluckError


class ApiKeyUnavailable(PotluckError):
    """Raised when a presented API key cannot authenticate anybody.

    One class for every reason a key may be unusable — unknown, revoked,
    expired, presented before it was minted, or bound to a subject whose
    identity was revoked — because the answer must not tell a caller which one
    it hit. A response that distinguishes an unknown key from a revoked one
    turns the endpoint into an oracle for the key table.
    """


class ApiKeyRateLimited(PotluckError):
    """Raised when an API key exceeds its concurrency ceiling or request rate.

    The endpoint is shared by every key the center has issued, so one key — a
    leaked one, or a client stuck in a retry loop — must not be able to occupy
    the center's dispatch or drown out the subjects sharing it. Distinct from an
    exhausted quota, which is about money rather than about load.
    """


class ModelUnavailable(PotluckError):
    """Raised when no connected contribution node can run the requested model.

    Refused at admission rather than queued: a request nothing can run would
    otherwise sit until its deadline and answer as a timeout, which tells the
    caller nothing about the one thing that was actually wrong. The platform's
    own consumer client refuses the same way, before it creates a request it
    knows cannot start.
    """
