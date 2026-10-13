"""Server-side failures the shared protocol hierarchy does not name.

`aipotluck.errors` owns the vocabulary both packages speak — a signature that
does not verify, an account that cannot cover a charge, a record that conflicts
— and every failure the server raises is one of those, so a caller can handle
the platform's answers without knowing which package raised them.

Two conditions belong to the server alone, because they exist only on the
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

    The endpoint is shared by every key the server has issued, so one key — a
    leaked one, or a client stuck in a retry loop — must not be able to occupy
    the server's dispatch or drown out the subjects sharing it. Distinct from an
    exhausted quota, which is about money rather than about load.
    """


class ModelUnavailable(PotluckError):
    """Raised when no connected contribution node can run the requested model.

    Refused at admission rather than queued: a request nothing can run would
    otherwise sit until its deadline and answer as a timeout, which tells the
    caller nothing about the one thing that was actually wrong. The platform's
    own consumer client refuses the same way, before it creates a request it
    knows cannot start.

    This is the *model* refusal and not the *capacity* one. A server that serves
    the model but has nothing free this instant does not raise it: that request
    waits in the dispatch queue, because a busy pool is a condition that ends and
    an unserved model is not.
    """


class AdminUiError(PotluckError):
    """Raised when the operator's admin page cannot be started.

    The page is an optional second listener the operator switches on with
    ``serve --admin-ui``, so its refusals are named rather than folded into the
    gateway's: a server whose admin page failed to start has to say that it was
    the admin page, and a server that started without one has to be told why.
    """


class NonLoopbackAdminBindError(AdminUiError):
    """Raised for an admin-page bind address that is not an IPv4 loopback literal.

    A distinct type rather than a message match, for the same reason the client's
    local endpoint has its own: refusing to become reachable from another machine
    is this listener's one security invariant, and a caller must be able to tell
    it apart from a port that was merely busy. ``0.0.0.0`` and ``::`` mean every
    interface, a hostname is resolved through host files this process does not
    control, and ``::1`` is a second address family — all four are refused.

    The page holds no credential and offers no action, but it names every subject
    and node this server has settled for, and it is served over plain HTTP: on a
    reachable interface that is a public read-out of the operator's books.
    """


class QueueFull(PotluckError):
    """Raised when the server's dispatch queue is already at its bound.

    The queue exists so a request that nothing can dispatch this instant waits
    instead of being refused; the bound exists so waiting cannot grow without
    limit. This is the answer when the two meet: the server is holding as much
    unfinished work as its operator agreed it would hold, so the honest response
    is "retry later" rather than a promise it cannot keep.

    Distinct from `ApiKeyRateLimited`, which is about one key's own share, and
    from `ModelUnavailable`, which is about work nothing can ever run. A caller
    backs off for this one and re-authenticates or re-checks its model for the
    others.
    """
