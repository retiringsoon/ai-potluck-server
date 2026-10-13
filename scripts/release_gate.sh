#!/bin/sh
# Release gate for the ai-potluck platform: prove a candidate source install of
# BOTH packages (ai-potluck and ai-potluck-server) works end to end
# through the path a user actually takes, before the commit is called releasable.
#
# Why this exists: the P0-3 defect was a `dist/` wheel built hours behind HEAD,
# so it did not even accept the arguments the review's smoke passed. The F04
# defect was subtler and worse: the gate installed the package with `uv` instead
# of running `install.sh`, pre-registered the node's credential in `server.json`
# by hand, passed `--node-token-file`, and pinned `--model` and `--max-charge` —
# so it proved a path no user takes and missed every defect hiding in the default
# one. A check that only proves "the code imports" cannot catch either; the
# install has to be the real installer and the smoke has to be the README's
# default flow.
#
# What it takes: a source to install (`--source`, default the checkout this
# script lives in) and the requirement that the checkout is clean, so a pass is a
# statement about a commit rather than about somebody's uncommitted edits.
#
# What a pass proves, in order:
#   1. the real `install.sh` installs into a fresh prefix, and the CLI it
#      produced imports the installed package rather than this source tree;
#   2. a fresh server with *zero* hand-written credentials starts;
#   3. a contribution node joins with an invite only — no `--node-token-file`, no
#      identity fields — and the token `join` saved is what `share run` uses;
#   4. a consumer joins with an invite only and asks with the *default* model and
#      the *default* charge ceiling: no `--model`, no `--max-charge`;
#   5. the streaming ask printed its first increment while it was still running
#      (not merely an answer in the final stdout), and the buffered ask is
#      verified separately through its own waiting notice;
#   6. the same identity asks again, asks again after the server restarts, and
#      the three asks leave three distinct receipts — the restart was neither
#      charged twice nor settled as free;
#   7. an API key minted for the joined consumer answers
#      ``POST /openai/v1/chat/completions`` over real HTTP — buffered and
#      streaming — against the same real node, and each of those two requests
#      settled into a receipt the operator side verifies. This is the second
#      admission path, and a gate that only ever signs a request cannot see a
#      defect only an API-key admission can reach;
#   8. an invite minted `--with-api-key` hands the joining consumer a key on
#      stdout — the only channel that plaintext ever travels on — and that key
#      answers a chat completion against the same real node and settles into a
#      receipt the operator side verifies. This is the path a member takes with
#      no operator round trip, and the one where a key that authenticated but
#      could never settle would be invisible to every step above;
#   9. the receipt verifies on both sides, and both reconciliations agree. After
#      a restart the node side may name exactly one class of difference: an offer
#      the node never accepted, which the server holds as FAILED with the
#      settlement HELD and no receipt. Anything else — a *settled* attempt the
#      node has no record of, above all — fails the gate.
#
# What it never does: it never touches a real upstream or a real key (the smoke
# uses `sk-smoke-*` fakes, a throwaway server and scripts/dev_fake_upstream.py),
# never moves an existing installation aside, and never leaves a process or a
# work directory behind. A failing run keeps only redacted logs and prints the
# path to them.
#
# Usage: scripts/release_gate.sh [--source SPEC] [--server-source SPEC]
#                                [--python X.Y] [--keep-work]
#   Runs from an ai-potluck-server checkout; the client checkout defaults to the
#   sibling ../ai-potluck (override with CLIENT_ROOT). Both trees must be clean.
#   --source is what the client's install.sh installs: the client checkout by
#   default, or any spec `uv pip install` accepts. --server-source is what gets
#   installed into the same prefix afterwards: this checkout by default. A
#   remote spec only means something when the checkout is at the same commit,
#   because the gate checks the installed versions against both pyproject.toml
#   files.
#   --python pins the CPython minor version install.sh builds the venv with.
#   --keep-work keeps the work directory (logs, prefix, databases) for inspection.
#
# Exit codes: 0 the gate passed, 1 a prerequisite was not met (dirty tree, no uv,
# no source), 2 the install or the smoke failed.

set -eu

# The smoke reads its readiness from the CLIs' redirected stdout, and CPython
# block-buffers stdout when it is not a terminal — so without this the startup
# lines sit in a buffer and every wait times out. Unbuffered output is what makes
# "wait for the serving line" a real readiness check rather than a sleep.
PYTHONUNBUFFERED=1
export PYTHONUNBUFFERED
# A stray PYTHONPATH would let the smoke import this source tree instead of the
# installed package, which is exactly the drift this gate exists to catch.
unset PYTHONPATH

die() {
    printf 'release_gate.sh: %s\n' "$1" >&2
    exit "${2:-1}"
}

usage() {
    awk 'NR > 1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
}

SOURCE=""
SERVER_SOURCE=""
GATE_PYTHON=""
KEEP_WORK=no
while [ $# -gt 0 ]; do
    case "$1" in
        --source) SOURCE=${2:?--source needs a checkout path or a package spec}; shift 2 ;;
        --server-source) SERVER_SOURCE=${2:?--server-source needs a checkout path or a package spec}; shift 2 ;;
        --python) GATE_PYTHON=${2:?--python needs a version}; shift 2 ;;
        --keep-work) KEEP_WORK=yes; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
done

# shellcheck disable=SC1007  # the leading assignment is how CDPATH is neutralised
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CLIENT_ROOT=${CLIENT_ROOT:-"$ROOT/../ai-potluck"}
[ -f "$CLIENT_ROOT/install.sh" ] || die "no ai-potluck checkout at $CLIENT_ROOT (set CLIENT_ROOT)"
CLIENT_ROOT=$(CDPATH= cd -- "$CLIENT_ROOT" && pwd)

# The smoke's constants. The model is *not* passed to `ask`: the consumer uses
# the default, which is inferred from the online nodes, and the fake upstream is
# started with this name so the inference has something to find. The charge
# ceiling is likewise left at the CLI default.
MODEL=coding-pool
TENANT=smoke
NO_NODE_GRACE=30
ASK_TIMEOUT=120
# Pacing for the fake upstream's stream. It has to be slow enough that the first
# increment is provably on stdout before the ask finishes.
CHUNK_DELAY=0.6
# Quota for the API key the OpenAI-compatible face is smoked with. Two small
# completions cost a fraction of it; the point of naming a ceiling at all is that
# the gate mints a key the way an operator does, capped and revocable.
API_KEY_QUOTA=5000

command -v git >/dev/null 2>&1 || die 'git is required'
command -v uv >/dev/null 2>&1 || die 'uv is required (https://docs.astral.sh/uv/)'

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/pyproject.toml" | head -1)
[ -n "$VERSION" ] || die "no version in $ROOT/pyproject.toml"
CLIENT_VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$CLIENT_ROOT/pyproject.toml" | head -1)
[ -n "$CLIENT_VERSION" ] || die "no version in $CLIENT_ROOT/pyproject.toml"

# A pass has to be a statement about a commit. The install comes from the
# working tree, so a dirty tree means the gate would be blessing bytes that no
# commit records and nobody can reproduce.
for TREE in "$ROOT" "$CLIENT_ROOT"; do
    DIRTY=$(git -C "$TREE" status --porcelain)
    if [ -n "$DIRTY" ]; then
        printf 'release_gate.sh: refusing to gate a release over a dirty working tree (%s)\n' \
            "$TREE" >&2
        printf '%s\n' "$DIRTY" >&2
        die 'commit or stash the changes first, then rerun'
    fi
done
HEAD_SHA=$(git -C "$ROOT" rev-parse HEAD)
SHORT_SHA=$(printf '%s' "$HEAD_SHA" | cut -c1-9)
printf 'release_gate.sh: gating ai-potluck-server %s with ai-potluck %s at %s\n' \
    "$VERSION" "$CLIENT_VERSION" "$SHORT_SHA"

# Work dir and cleanup. WORK is removed on every exit unless --keep-work; a
# failure log directory is created separately and kept so the reason survives.
WORK=$(mktemp -d "${TMPDIR:-/tmp}/potluck-release-gate.XXXXXX")
# Normalise once: TMPDIR may or may not end in a slash, and every later message,
# path comparison and log line reads better without a doubled separator in it.
WORK=$(CDPATH= cd -- "$WORK" && pwd)
mkdir -p "$WORK/logs"
SERVER_PID=""
UPSTREAM_PID=""
NODE_PID=""

cleanup() {
    rc=$?
    trap - EXIT INT TERM
    for pid in "$NODE_PID" "$UPSTREAM_PID" "$SERVER_PID"; do
        [ -n "$pid" ] || continue
        kill "$pid" 2>/dev/null || true
    done
    # Give the CLIs a moment to run their stop handlers, then force anything
    # still alive so the gate cannot leave a listener or a link behind.
    sleep 1
    for pid in "$NODE_PID" "$UPSTREAM_PID" "$SERVER_PID"; do
        [ -n "$pid" ] || continue
        kill -9 "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    if [ "$KEEP_WORK" = yes ]; then
        printf 'release_gate.sh: work directory kept at %s\n' "$WORK"
    else
        rm -rf "$WORK"
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

# The smoke's fake secrets. Generated before the failure path is defined so a
# failure that happens early can still redact them from any log.
UPSTREAM_KEY="sk-smoke-fake-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
NODE_INVITE=""
CONSUMER_INVITE=""
KEYED_INVITE=""
JOIN_API_KEY=""

# Fail-closed redaction: the smoke only ever uses fake secrets and single-use
# invite codes for a throwaway server, but a failure log must never become a
# place a real one could accumulate if this script is reused.
redact_log() {
    sed -e 's|[Bb]earer [A-Za-z0-9._~+/-]*|Bearer <redacted>|g' "$1" > "$1.redacted"
    for secret in "$UPSTREAM_KEY" "$NODE_INVITE" "$CONSUMER_INVITE" "$KEYED_INVITE" \
            "$JOIN_API_KEY"; do
        [ -n "$secret" ] || continue
        mv "$1.redacted" "$1.redacted.tmp"
        sed -e "s|$secret|<redacted>|g" "$1.redacted.tmp" > "$1.redacted"
        rm -f "$1.redacted.tmp"
    done
    mv "$1.redacted" "$1"
}

# A failed step keeps redacted logs and exits 2 without leaving the smoke
# running; the path is printed so the operator can read the real cause.
fail() {
    FAIL_DIR=$(mktemp -d "${TMPDIR:-/tmp}/potluck-release-gate-failure.XXXXXX")
    for log in "$WORK"/logs/*; do
        [ -f "$log" ] || continue
        cp "$log" "$FAIL_DIR/$(basename "$log")"
        redact_log "$FAIL_DIR/$(basename "$log")" 2>/dev/null || true
    done
    printf 'release_gate.sh: FAIL %s\n' "$1" >&2
    printf 'release_gate.sh: ai-potluck-server %s at %s is NOT releasable\n' \
        "$VERSION" "$SHORT_SHA" >&2
    printf 'release_gate.sh: redacted logs kept at %s (remove when done)\n' "$FAIL_DIR" >&2
    exit 2
}

# Print one numbered step, so the transcript reads as the sequence it is.
STEP=0
step() {
    STEP=$((STEP + 1))
    printf 'release_gate.sh: [%d] %s\n' "$STEP" "$1"
}

# Echo a command as evidence, with the throwaway secrets replaced. The point is
# that the transcript shows *which flags were used*: a reader can see that no
# `--model`, no `--max-charge` and no `--node-token-file` was passed.
show() {
    line=$(printf '%s' "$*" | sed -e "s|$UPSTREAM_KEY|<upstream-key>|g")
    for secret in "$NODE_INVITE" "$CONSUMER_INVITE" "$KEYED_INVITE"; do
        [ -n "$secret" ] || continue
        line=$(printf '%s' "$line" | sed -e "s|$secret|<invite>|g")
    done
    if [ -n "$JOIN_API_KEY" ]; then
        line=$(printf '%s' "$line" | sed -e "s|$JOIN_API_KEY|<api key>|g")
    fi
    printf 'release_gate.sh:     $ %s\n' "$line"
}

# Wait for a marker line in a log, dying early if the process it belongs to does.
wait_for_line() {
    log_file=$1
    needle=$2
    seconds=$3
    pid=${4:-}
    ticks=$((seconds * 10))
    n=0
    while [ "$n" -lt "$ticks" ]; do
        if grep -qF -- "$needle" "$log_file" 2>/dev/null; then return 0; fi
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then return 1; fi
        n=$((n + 1))
        sleep 0.1
    done
    return 1
}

# --------------------------------------------------------------------------
# Install it the way a user does: the real installer, a fresh prefix
# --------------------------------------------------------------------------

HOME_DIR="$WORK/home"
step "run the client's install.sh into a fresh prefix ($HOME_DIR)"
set -- --prefix "$HOME_DIR"
if [ -n "$GATE_PYTHON" ]; then set -- "$@" --python "$GATE_PYTHON"; fi
if [ -n "$SOURCE" ]; then set -- "$@" --source "$SOURCE"; fi
show "install.sh $*"
if ! "$CLIENT_ROOT/install.sh" "$@" >"$WORK/logs/install.log" 2>&1; then
    tail -40 "$WORK/logs/install.log" >&2
    fail 'install.sh did not install potluck'
fi

POTLUCK="$HOME_DIR/bin/potluck"
HOME_PY="$HOME_DIR/venv/bin/python"
[ -x "$POTLUCK" ] || fail 'install.sh produced no launcher'
[ -x "$HOME_PY" ] || fail 'install.sh produced no virtualenv'

step "install ai-potluck-server into the same prefix"
SERVER_SOURCE=${SERVER_SOURCE:-$ROOT}
show "uv pip install --python <prefix venv> $SERVER_SOURCE"
uv pip install --python "$HOME_PY" "$SERVER_SOURCE" \
    >"$WORK/logs/install-server.log" 2>&1 \
    || { tail -40 "$WORK/logs/install-server.log" >&2
         fail 'installing ai-potluck-server into the prefix failed'; }
ln -sf "$HOME_DIR/venv/bin/potluck-server" "$HOME_DIR/bin/potluck-server"
POTLUCK_SERVER="$HOME_DIR/bin/potluck-server"
[ -x "$HOME_DIR/venv/bin/potluck-server" ] || fail 'the server package produced no launcher'
grep -qF 'preflight ok' "$WORK/logs/install.log" \
    || fail 'install.sh did not report its pre-install compatibility check'
grep -qF 'install.sh: installing' "$WORK/logs/install.log" \
    || fail 'install.sh did not report what it installed'
printf 'release_gate.sh:     %s\n' "$(grep -F 'preflight ok' "$WORK/logs/install.log" | head -1)"

INSTALLED_VERSION=$("$POTLUCK" version </dev/null | head -1 \
    | sed -n 's/^potluck \([0-9][0-9.]*\).*/\1/p')
if [ "$INSTALLED_VERSION" != "$CLIENT_VERSION" ]; then
    printf 'release_gate.sh: installed potluck reports %s, client pyproject says %s\n' \
        "${INSTALLED_VERSION:-<nothing>}" "$CLIENT_VERSION" >&2
    fail 'the installed client CLI does not report the version of its checkout'
fi
INSTALLED_SERVER_VERSION=$("$POTLUCK_SERVER" version </dev/null | head -1 \
    | sed -n 's/^potluck-server \([0-9][0-9.]*\).*/\1/p')
if [ "$INSTALLED_SERVER_VERSION" != "$VERSION" ]; then
    printf 'release_gate.sh: installed potluck-server reports %s, pyproject says %s\n' \
        "${INSTALLED_SERVER_VERSION:-<nothing>}" "$VERSION" >&2
    fail 'the installed server CLI does not report the version of this checkout'
fi

# The installed package has to be the one in the prefix. Importing this source
# tree instead would let the smoke pass on code that no install ever shipped. The
# comparison is against the venv's own prefix rather than a string this script
# built, so path normalisation cannot decide the outcome.
VENV_PREFIX=$("$HOME_PY" -c 'import sys; print(sys.prefix)' </dev/null)
for MODULE in aipotluck aipotluck_server; do
    IMPORTED_FROM=$("$HOME_PY" -c "import $MODULE; print($MODULE.__file__)" </dev/null)
    case "$IMPORTED_FROM" in
        "$VENV_PREFIX"/*) : ;;
        *) printf 'release_gate.sh: the installed CLI imports %s from %s\n' \
               "$MODULE" "$IMPORTED_FROM" >&2
           fail 'the smoke would not be testing the installed package' ;;
    esac
done
printf 'release_gate.sh: installed potluck %s + potluck-server %s under %s\n' \
    "$INSTALLED_VERSION" "$INSTALLED_SERVER_VERSION" "$VENV_PREFIX"

now_ms() {
    "$HOME_PY" -c 'import time; print(int(time.time() * 1000))'
}

# Run the smoke from the work dir, never from the checkout, so nothing can pick
# up the source tree by accident.
cd "$WORK"

# --------------------------------------------------------------------------
# The default path: fresh server, invite-only node, invite-only consumer
# --------------------------------------------------------------------------

mkdir -p "$WORK/server" "$WORK/node" "$WORK/consumer"
printf '%s\n' "$UPSTREAM_KEY" > "$WORK/upstream-key"
chmod 600 "$WORK/upstream-key"

step 'server keygen'
"$POTLUCK" keygen --out "$WORK/server/settlement.key" \
    >"$WORK/logs/keygen.log" 2>&1 </dev/null || fail 'keygen failed'
SETTLEMENT_KEY=$(cat "$WORK/server/settlement.key")
SERVER_JSON="$WORK/server/server.json"

# A free port is chosen once and written into the config, rather than letting
# `serve` pick one per start: the consumer's saved identity holds the server URL,
# and the restart step below has to come back on the same address, exactly as an
# operator's restart would.
SERVER_PORT=$("$HOME_PY" -c \
    'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
[ -n "$SERVER_PORT" ] || fail 'could not reserve a port for the server'
SERVER_URL="http://127.0.0.1:$SERVER_PORT"

step 'write a fresh server config with zero hand-written credentials'
# `credentials` is empty on purpose. The F04 defect was a node credential typed
# into this file by the gate; the default path has the server mint the node's
# token when it redeems the invite, and that is what is being proven here.
cat > "$SERVER_JSON" <<JSON
{
  "host": "127.0.0.1",
  "port": $SERVER_PORT,
  "database_path": "$WORK/server/server.db",
  "platform_id": "smoke-server",
  "settlement_key_id": "smoke-settlement-key",
  "settlement_private_key_b64": "$SETTLEMENT_KEY",
  "certfile": null,
  "keyfile": null,
  "credentials": [],
  "providers": [],
  "consumer_floats": []
}
JSON
chmod 600 "$SERVER_JSON"

start_server() {
    # A separate log per start: `wait_for_line` looks for the serving line, and a
    # previous start's line still sitting in the same file would make a restart
    # that never came up look ready.
    server_log=$1
    "$POTLUCK_SERVER" serve --config "$SERVER_JSON" >>"$server_log" 2>&1 </dev/null &
    SERVER_PID=$!
    wait_for_line "$server_log" 'serving http' 30 "$SERVER_PID" \
        || fail "the server did not start (see $(basename "$server_log"))"
}

step "start the server ($SERVER_URL)"
start_server "$WORK/logs/server.log"

step 'start the local fake upstream'
show "python scripts/dev_fake_upstream.py --port 0 --model $MODEL --key <upstream-key> --chunk-delay $CHUNK_DELAY"
"$HOME_PY" "$CLIENT_ROOT/scripts/dev_fake_upstream.py" \
    --port 0 --model "$MODEL" --key "$UPSTREAM_KEY" --chunk-delay "$CHUNK_DELAY" \
    >"$WORK/logs/upstream.log" 2>&1 &
UPSTREAM_PID=$!
wait_for_line "$WORK/logs/upstream.log" 'listening on' 30 "$UPSTREAM_PID" \
    || fail 'the fake upstream did not start'
UPSTREAM_PORT=$(sed -n 's/.*listening on 127.0.0.1:\([0-9]*\).*/\1/p' \
    "$WORK/logs/upstream.log" | head -1)
[ -n "$UPSTREAM_PORT" ] || fail 'could not read the fake upstream port'
UPSTREAM_URL="http://127.0.0.1:$UPSTREAM_PORT/v1/chat/completions"

# The reply marker is read from the fixture that emits it, so the gate cannot
# drift from it; its first word is what the first streamed increment carries.
REPLY_MARKER=$(sed -n 's/^REPLY_MARKER = "\(.*\)"/\1/p' "$CLIENT_ROOT/scripts/dev_fake_upstream.py")
[ -n "$REPLY_MARKER" ] || fail 'could not read REPLY_MARKER from dev_fake_upstream.py'
FIRST_DELTA=${REPLY_MARKER%% *}

step 'mint the node and consumer invites (the operator default path)'
show "potluck-server admin invite --config server.json --role node --tenant $TENANT"
NODE_INVITE=$("$POTLUCK_SERVER" admin invite --config "$SERVER_JSON" --role node --tenant "$TENANT" \
    2>>"$WORK/logs/invite.log" </dev/null) || fail 'minting the node invite failed'
show "potluck-server admin invite --config server.json --role consumer --tenant $TENANT"
CONSUMER_INVITE=$("$POTLUCK_SERVER" admin invite --config "$SERVER_JSON" --role consumer \
    --tenant "$TENANT" 2>>"$WORK/logs/invite.log" </dev/null) \
    || fail 'minting the consumer invite failed'
[ -n "$NODE_INVITE" ] && [ -n "$CONSUMER_INVITE" ] || fail 'an invite came back empty'

step 'node joins with the invite only (no token file, no identity fields)'
show "potluck join --node --server $SERVER_URL --invite <invite> --config-dir node --upstream-endpoint $UPSTREAM_URL --upstream-model $MODEL --upstream-key-file upstream-key"
if ! "$POTLUCK" join --node --server "$SERVER_URL" --invite "$NODE_INVITE" \
        --config-dir "$WORK/node" \
        --upstream-endpoint "$UPSTREAM_URL" \
        --upstream-model "$MODEL" \
        --upstream-key-file "$WORK/upstream-key" \
        >"$WORK/logs/node-join.log" 2>&1 </dev/null; then
    tail -30 "$WORK/logs/node-join.log" >&2
    fail 'the node join or its self-check failed'
fi
NODE_TOKEN_FILE="$WORK/node/node_token.json"
[ -f "$NODE_TOKEN_FILE" ] \
    || fail 'join did not save the node token the server issued (no node_token.json)'
TOKEN_MODE=$(ls -l "$NODE_TOKEN_FILE" | awk '{print $1}')
case "$TOKEN_MODE" in
    *------*) : ;;
    *) fail "node_token.json is $TOKEN_MODE, expected 0600" ;;
esac
printf 'release_gate.sh:     node token saved by join as %s (mode %s)\n' \
    "$(basename "$NODE_TOKEN_FILE")" "$TOKEN_MODE"

step 'node starts sharing'
show 'potluck share run --config node/node.json'
"$POTLUCK" share run --config "$WORK/node/node.json" \
    >"$WORK/logs/node.log" 2>&1 </dev/null &
NODE_PID=$!
wait_for_line "$WORK/logs/node.log" 'connecting to' 30 "$NODE_PID" \
    || fail 'share run did not start the node link'

step 'consumer joins with the invite only'
show "potluck join --server $SERVER_URL --invite <invite> --config-dir consumer"
if ! "$POTLUCK" join --server "$SERVER_URL" --invite "$CONSUMER_INVITE" \
        --config-dir "$WORK/consumer" \
        >"$WORK/logs/consumer-join.log" 2>&1 </dev/null; then
    tail -30 "$WORK/logs/consumer-join.log" >&2
    fail 'the consumer join failed'
fi

# --------------------------------------------------------------------------
# Default asks: streaming first, then buffered, then the same identity again
# --------------------------------------------------------------------------

# Run one streaming `ask` and prove the first increment reached stdout *while the
# command was still running*. A final stdout that contains the answer is exactly
# what a buffered client pretending to stream would also produce, so the evidence
# here is the timing: the answer's first word is in the file, and the process has
# not exited yet.
STREAM_ASK_RC=0
STREAM_FIRST_AT=0
STREAM_END_AT=0
STREAM_WAS_RUNNING=no
run_stream_ask() {
    out=$1
    err=$2
    question=$3
    show "potluck ask '$question' --config-dir consumer --stream (no --model, no --max-charge)"
    "$POTLUCK" ask "$question" --config-dir "$WORK/consumer" --stream \
        --no-node-grace "$NO_NODE_GRACE" --timeout "$ASK_TIMEOUT" \
        >"$out" 2>"$err" </dev/null &
    ask_pid=$!
    started=$(now_ms)
    STREAM_FIRST_AT=0
    ticks=0
    while [ "$ticks" -lt 2400 ]; do
        if grep -qF -- "$FIRST_DELTA" "$out" 2>/dev/null; then
            STREAM_FIRST_AT=$(now_ms)
            if kill -0 "$ask_pid" 2>/dev/null; then
                STREAM_WAS_RUNNING=yes
            else
                STREAM_WAS_RUNNING=no
            fi
            break
        fi
        if ! kill -0 "$ask_pid" 2>/dev/null; then break; fi
        ticks=$((ticks + 1))
        sleep 0.05
    done
    STREAM_ASK_RC=0
    wait "$ask_pid" || STREAM_ASK_RC=$?
    STREAM_END_AT=$(now_ms)
    printf 'release_gate.sh:     first increment at +%sms, ask exited at +%sms (rc=%s, still running when the first output appeared: %s)\n' \
        "$((STREAM_FIRST_AT - started))" "$((STREAM_END_AT - started))" \
        "$STREAM_ASK_RC" "$STREAM_WAS_RUNNING"
}

# Read the receipt id out of an ask's cost line ("... receipt R-1)").
receipt_of() {
    grep -F 'receipt R-' "$1" | head -1 | sed -n 's/.*receipt \(R-[0-9]*\).*/\1/p'
}

# Assert one finished ask: exit status, answer text, cost/receipt line, and that
# the model came from the default inference rather than from a flag.
check_ask() {
    label=$1
    out=$2
    err=$3
    rc=$4
    if [ "$rc" != 0 ]; then
        tail -30 "$err" >&2
        fail "the $label ask did not exit 0"
    fi
    grep -qF -- "$REPLY_MARKER" "$out" \
        || fail "the $label ask output does not carry the upstream answer text"
    grep -qF 'receipt R-' "$out" \
        || fail "the $label ask output does not carry a receipt line"
    grep -qF 'no --model given' "$err" \
        || fail "the $label ask did not infer the default model (no default-model notice)"
    printf 'release_gate.sh:     %s\n' "$(grep -F -- "$REPLY_MARKER" "$out" | head -1)"
    printf 'release_gate.sh:     %s\n' "$(grep -F 'receipt R-' "$out" | head -1)"
}

step 'streaming ask with the default model and the default charge'
run_stream_ask "$WORK/logs/ask-stream.out" "$WORK/logs/ask-stream.err" 'gate streaming smoke'
check_ask streaming "$WORK/logs/ask-stream.out" "$WORK/logs/ask-stream.err" "$STREAM_ASK_RC"
[ "$STREAM_WAS_RUNNING" = yes ] \
    || fail 'the first streamed increment appeared only after the ask had already exited'
[ "$STREAM_FIRST_AT" -lt "$STREAM_END_AT" ] \
    || fail 'the first streamed increment was not observed before completion'

RECEIPT_ID=$(receipt_of "$WORK/logs/ask-stream.out")
[ -n "$RECEIPT_ID" ] || fail 'could not read the receipt id from the streaming ask'

step 'buffered ask (default mode) with the same identity'
show "potluck ask 'gate buffered smoke' --config-dir consumer (no --stream, no --model, no --max-charge)"
BUFFERED_RC=0
"$POTLUCK" ask 'gate buffered smoke' --config-dir "$WORK/consumer" \
    --no-node-grace "$NO_NODE_GRACE" --timeout "$ASK_TIMEOUT" \
    >"$WORK/logs/ask-buffered.out" 2>"$WORK/logs/ask-buffered.err" </dev/null || BUFFERED_RC=$?
check_ask buffered "$WORK/logs/ask-buffered.out" "$WORK/logs/ask-buffered.err" "$BUFFERED_RC"
grep -qF 'waiting for generation' "$WORK/logs/ask-buffered.err" \
    || fail 'the buffered ask did not show its waiting notice (was it really buffered?)'

# --------------------------------------------------------------------------
# Before anything is disturbed, the two sides have to agree exactly
# --------------------------------------------------------------------------

step 'reconcile the node against the server (nothing has restarted yet)'
show 'potluck share reconcile --config node/node.json'
"$POTLUCK" share reconcile --config "$WORK/node/node.json" \
    >"$WORK/logs/reconcile-node.log" 2>&1 </dev/null \
    || { tail -20 "$WORK/logs/reconcile-node.log" >&2
         fail 'share reconcile reported a difference before any restart'; }

step 'reconcile the server against itself'
show 'potluck-server admin reconcile --config server.json'
"$POTLUCK_SERVER" admin reconcile --config "$SERVER_JSON" \
    >"$WORK/logs/reconcile-server.log" 2>&1 </dev/null \
    || { tail -20 "$WORK/logs/reconcile-server.log" >&2
         fail 'admin reconcile reported a difference inside the server books'; }

# --------------------------------------------------------------------------
# The server restarts; the same identities keep working
# --------------------------------------------------------------------------

step 'restart the server on the same address'
OLD_SERVER_PID=$SERVER_PID
SERVER_PID=""
kill "$OLD_SERVER_PID" 2>/dev/null || true
ticks=0
while [ "$ticks" -lt 100 ] && kill -0 "$OLD_SERVER_PID" 2>/dev/null; do
    ticks=$((ticks + 1))
    sleep 0.1
done
kill -9 "$OLD_SERVER_PID" 2>/dev/null || true
# Reap only this child: a bare `wait` would block on the node and the upstream,
# which are both supposed to still be running.
wait "$OLD_SERVER_PID" 2>/dev/null || true
printf 'release_gate.sh:     server stopped; the node link has to reconnect on its own\n'
start_server "$WORK/logs/server-restart.log"

step 'ask again after the restart, same identity, same defaults'
run_stream_ask "$WORK/logs/ask-restart.out" "$WORK/logs/ask-restart.err" 'after-restart smoke'
check_ask 'after-restart' "$WORK/logs/ask-restart.out" "$WORK/logs/ask-restart.err" "$STREAM_ASK_RC"
[ "$STREAM_WAS_RUNNING" = yes ] \
    || fail 'after the restart the first streamed increment appeared only after the ask exited'
RESTART_RECEIPT_ID=$(receipt_of "$WORK/logs/ask-restart.out")
[ -n "$RESTART_RECEIPT_ID" ] || fail 'could not read the receipt id from the after-restart ask'

step 'three asks, three distinct receipts: the restart was not charged twice'
# A restart can leave the server holding an offer the node never accepted. The
# retry then produces the answer *and* a receipt of its own, so the proof that
# nobody paid twice is that each successful ask has its own receipt id.
BUFFERED_RECEIPT_ID=$(receipt_of "$WORK/logs/ask-buffered.out")
printf 'release_gate.sh:     receipts: %s (stream), %s (buffered), %s (after restart)\n' \
    "$RECEIPT_ID" "$BUFFERED_RECEIPT_ID" "$RESTART_RECEIPT_ID"
[ -n "$BUFFERED_RECEIPT_ID" ] || fail 'could not read the receipt id from the buffered ask'
if [ "$RECEIPT_ID" = "$BUFFERED_RECEIPT_ID" ] \
        || [ "$RECEIPT_ID" = "$RESTART_RECEIPT_ID" ] \
        || [ "$BUFFERED_RECEIPT_ID" = "$RESTART_RECEIPT_ID" ]; then
    fail 'two asks share one receipt id: a request was settled twice or not at all'
fi

# --------------------------------------------------------------------------
# The OpenAI-compatible face: an API key over real HTTP, both delivery modes
# --------------------------------------------------------------------------

# Everything above drives the platform's own surface on a signed request. The
# OpenAI-compatible endpoint admits on an API key instead, through the second
# admission path, and a defect only that path can reach is invisible to a gate
# that never mints a key: a server whose store could not hold a conversation
# answered every POST /openai/v1/chat/completions with a 502 naming a request
# that "has no stored dispatch inputs", and left each of those requests in
# ROUTING forever, holding its key's concurrency slot. So the gate mints a key,
# calls the endpoint over real HTTP against the real node in both delivery modes,
# and verifies the receipt each request settled into.

cat > "$WORK/openai_smoke.py" <<'PY'
"""One chat completion against the server's OpenAI-compatible endpoint.

Standard library only: the gate's prefix installs the two packages and nothing
else, and what has to be proved is the wire contract — the status, the answer, the
settled counts, the request id — not that one particular SDK parses it. The API
key arrives on stdin, so it lands in neither the environment nor a log.

Stdout is two lines: a human summary, then the request id. Failures go to stderr.
"""
import http.client
import json
import os
import sys
import urllib.parse

base = urllib.parse.urlsplit(os.environ["SERVER_URL"])
key = sys.stdin.readline().strip()
mode = os.environ["MODE"]
stream = mode == "stream"
marker = os.environ["REPLY_MARKER"]
body: dict[str, object] = {
    "model": os.environ["MODEL"],
    "messages": [{"role": "user", "content": os.environ["QUESTION"]}],
    "stream": stream,
}
if stream:
    body["stream_options"] = {"include_usage": True}

connection = http.client.HTTPConnection(base.hostname, base.port, timeout=180)
connection.request(
    "POST",
    "/openai/v1/chat/completions",
    body=json.dumps(body).encode("utf-8"),
    headers={"authorization": f"Bearer {key}", "content-type": "application/json"},
)
response = connection.getresponse()
request_id = response.getheader("x-request-id") or ""
if response.status != 200:
    print(
        f"{mode}: the endpoint answered {response.status}: "
        f"{response.read().decode('utf-8', 'replace')}",
        file=sys.stderr,
    )
    sys.exit(1)

text = ""
usage = None
frames = 0
if stream:
    terminated = False
    for line in response:
        payload = line.decode("utf-8").strip()
        if not payload.startswith("data: "):
            continue
        document = payload[len("data: "):]
        if document == "[DONE]":
            terminated = True
            break
        frames += 1
        chunk = json.loads(document)
        if chunk.get("usage"):
            usage = chunk["usage"]
        for choice in chunk.get("choices", []):
            text += (choice.get("delta") or {}).get("content") or ""
    if not terminated:
        print(f"{mode}: the stream never reached its terminator", file=sys.stderr)
        sys.exit(1)
    if frames < 2:
        print(f"{mode}: {frames} frame(s) is not an increment stream", file=sys.stderr)
        sys.exit(1)
else:
    completion = json.loads(response.read())
    text = completion["choices"][0]["message"]["content"]
    usage = completion.get("usage")
connection.close()

if marker not in text:
    print(f"{mode}: the answer is not the upstream's: {text!r}", file=sys.stderr)
    sys.exit(1)
if not usage or not usage.get("total_tokens"):
    print(f"{mode}: the response reported no settled tokens: {usage!r}", file=sys.stderr)
    sys.exit(1)
if not request_id.startswith("req-"):
    print(f"{mode}: no request id came back with the answer: {request_id!r}", file=sys.stderr)
    sys.exit(1)
print(f"{mode}: {frames or 1} frame(s), {usage['total_tokens']} tokens settled")
print(request_id)
PY

# The receipt a request settled into, read from the server's own books: the
# endpoint answers with a request id, and `service_unit_id` is that request.
receipt_for_request() {
    "$HOME_PY" - "$WORK/server/server.db" "$1" <<'PY'
import sys

from aipotluck_server.persistence import ServerStore

store = ServerStore.open_existing(sys.argv[1])
try:
    for settlement in store.settlements():
        if settlement.service_unit_id == sys.argv[2]:
            print(settlement.receipt_id)
            break
finally:
    store.close()
PY
}

# Run one chat completion and hand back its stdout, which the caller captures: a
# summary line and then the request id. Nothing else may print to stdout here,
# which is why the command this runs is echoed by the step rather than by this
# function.
run_openai_completion() {
    key=$1
    mode=$2
    question=$3
    err=$4
    printf '%s\n' "$key" \
        | MODE="$mode" QUESTION="$question" SERVER_URL="$SERVER_URL" MODEL="$MODEL" \
            REPLY_MARKER="$REPLY_MARKER" "$HOME_PY" "$WORK/openai_smoke.py" 2>"$err"
}

check_openai_completion() {
    label=$1
    out=$2
    err=$3
    if [ -z "$out" ]; then
        tail -20 "$err" >&2
        fail "the $label chat completion was not answered"
    fi
    printf 'release_gate.sh:     %s\n' "$(printf '%s\n' "$out" | head -1)"
}

step 'mint an API key for the joined consumer'
CONSUMER_SUBJECT=$("$HOME_PY" -c \
    'import json, pathlib; print(json.loads(pathlib.Path("consumer/config.json").read_text())["subject_id"])' \
    </dev/null)
[ -n "$CONSUMER_SUBJECT" ] || fail 'could not read the joined consumer subject id'
show "potluck-server admin api-key --config server.json --subject $CONSUMER_SUBJECT --quota $API_KEY_QUOTA"
# stdout carries the plaintext and nothing else; it is captured, never logged.
API_KEY=$("$POTLUCK_SERVER" admin api-key --config "$SERVER_JSON" \
    --subject "$CONSUMER_SUBJECT" --quota "$API_KEY_QUOTA" --name 'release gate' \
    2>"$WORK/logs/api-key.err" </dev/null) \
    || { tail -20 "$WORK/logs/api-key.err" >&2; fail 'minting an API key failed'; }
case "$API_KEY" in
    ak-*) : ;;
    *) fail 'admin api-key printed no key on stdout' ;;
esac
printf 'release_gate.sh:     minted %s for %s (the plaintext is never written to a log)\n' \
    "$(printf '%s' "$API_KEY" | cut -c1-6)..." "$CONSUMER_SUBJECT"

step 'the API key answers a buffered chat completion against the real node'
show 'POST /openai/v1/chat/completions (Authorization: Bearer <api key>, "stream": false)'
OPENAI_BUFFERED=$(run_openai_completion "$API_KEY" buffered 'gate api-key buffered' \
    "$WORK/logs/openai-buffered.err") \
    || { tail -20 "$WORK/logs/openai-buffered.err" >&2
         fail 'the buffered chat completion on an API key was not answered'; }
check_openai_completion buffered "$OPENAI_BUFFERED" "$WORK/logs/openai-buffered.err"
OPENAI_BUFFERED_REQUEST=$(printf '%s\n' "$OPENAI_BUFFERED" | tail -1)

step 'the same key answers a streaming chat completion'
show 'POST /openai/v1/chat/completions (Authorization: Bearer <api key>, "stream": true)'
OPENAI_STREAM=$(run_openai_completion "$API_KEY" stream 'gate api-key streaming' \
    "$WORK/logs/openai-stream.err") \
    || { tail -20 "$WORK/logs/openai-stream.err" >&2
         fail 'the streaming chat completion on an API key was not answered'; }
check_openai_completion streaming "$OPENAI_STREAM" "$WORK/logs/openai-stream.err"
OPENAI_STREAM_REQUEST=$(printf '%s\n' "$OPENAI_STREAM" | tail -1)

if [ "$OPENAI_BUFFERED_REQUEST" = "$OPENAI_STREAM_REQUEST" ]; then
    fail 'both API-key calls were answered as one request'
fi

step 'both API-key requests settled into receipts an operator can verify'
for OPENAI_REQUEST in "$OPENAI_BUFFERED_REQUEST" "$OPENAI_STREAM_REQUEST"; do
    OPENAI_RECEIPT=$(receipt_for_request "$OPENAI_REQUEST" </dev/null)
    [ -n "$OPENAI_RECEIPT" ] \
        || fail "the API-key request $OPENAI_REQUEST settled into no receipt"
    show "potluck-server verify receipt --config server.json --receipt-id $OPENAI_RECEIPT"
    "$POTLUCK_SERVER" verify receipt --config "$SERVER_JSON" --receipt-id "$OPENAI_RECEIPT" \
        >"$WORK/logs/verify-api-key-$OPENAI_RECEIPT.log" 2>&1 </dev/null \
        || { tail -20 "$WORK/logs/verify-api-key-$OPENAI_RECEIPT.log" >&2
             fail "the receipt $OPENAI_RECEIPT for $OPENAI_REQUEST did not verify"; }
    printf 'release_gate.sh:     %s -> %s verified\n' "$OPENAI_REQUEST" "$OPENAI_RECEIPT"
done

# --------------------------------------------------------------------------
# The shorter path: an invite that issues its own key
# --------------------------------------------------------------------------

# Every step above mints a key by hand, for a subject an operator read out of a
# listing. The path a member actually takes is one command shorter: the invite
# carries the instruction, and `potluck join` is the only channel the key's
# plaintext ever travels on. That channel is what this proves — the key a join
# printed is a live key, bound to the identity that just joined, and it reaches a
# settled receipt through the same real node. A key that authenticated and then
# could never settle (a subject with no account, a quota of zero) would answer
# every step above and fail only here.

step 'mint an invite that issues its own API key when redeemed'
show "potluck-server admin invite --config server.json --role consumer --tenant $TENANT --with-api-key --quota $API_KEY_QUOTA"
KEYED_INVITE=$("$POTLUCK_SERVER" admin invite --config "$SERVER_JSON" --role consumer \
    --tenant "$TENANT" --with-api-key --quota "$API_KEY_QUOTA" \
    2>>"$WORK/logs/invite.log" </dev/null) || fail 'minting a key-issuing invite failed'
[ -n "$KEYED_INVITE" ] || fail 'the key-issuing invite came back empty'

step 'a second consumer joins on it and is handed the key'
show "potluck join --server $SERVER_URL --invite <invite> --config-dir consumer-keyed"
# stdout is captured, not logged: it carries the plaintext exactly once, and a
# log file is the one place a credential must not accumulate.
JOIN_OUT=$("$POTLUCK" join --server "$SERVER_URL" --invite "$KEYED_INVITE" \
    --config-dir "$WORK/consumer-keyed" 2>"$WORK/logs/consumer-keyed-join.err" </dev/null) \
    || { tail -30 "$WORK/logs/consumer-keyed-join.err" >&2
         fail 'the join on a key-issuing invite failed'; }
JOIN_API_KEY=$(printf '%s\n' "$JOIN_OUT" | grep -m1 '^ak-') \
    || fail 'join printed no API key for an invite minted --with-api-key'
case "$JOIN_OUT" in
    *"$SERVER_URL/openai/v1"*) : ;;
    *) fail 'join did not name the base_url the issued key belongs to' ;;
esac
case "$JOIN_OUT" in
    *'shown once; store it now'*) : ;;
    *) fail 'join did not say the issued key is shown once' ;;
esac
printf 'release_gate.sh:     join issued %s to the identity it saved (the plaintext is never written to a log)\n' \
    "$(printf '%s' "$JOIN_API_KEY" | cut -c1-6)..."

step 'the key join issued answers a chat completion against the real node'
show 'POST /openai/v1/chat/completions (Authorization: Bearer <the key join issued>, "stream": false)'
KEYED_COMPLETION=$(run_openai_completion "$JOIN_API_KEY" buffered 'gate join-issued key' \
    "$WORK/logs/openai-keyed.err") \
    || { tail -20 "$WORK/logs/openai-keyed.err" >&2
         fail 'the chat completion on the key join issued was not answered'; }
check_openai_completion buffered "$KEYED_COMPLETION" "$WORK/logs/openai-keyed.err"
KEYED_REQUEST=$(printf '%s\n' "$KEYED_COMPLETION" | tail -1)
if [ "$KEYED_REQUEST" = "$OPENAI_BUFFERED_REQUEST" ] \
        || [ "$KEYED_REQUEST" = "$OPENAI_STREAM_REQUEST" ]; then
    fail 'the join-issued key was answered as one of the earlier requests'
fi

step 'that request settled into a receipt an operator can verify'
KEYED_RECEIPT=$(receipt_for_request "$KEYED_REQUEST" </dev/null)
[ -n "$KEYED_RECEIPT" ] \
    || fail "the join-issued key's request $KEYED_REQUEST settled into no receipt"
show "potluck-server verify receipt --config server.json --receipt-id $KEYED_RECEIPT"
"$POTLUCK_SERVER" verify receipt --config "$SERVER_JSON" --receipt-id "$KEYED_RECEIPT" \
    >"$WORK/logs/verify-keyed-$KEYED_RECEIPT.log" 2>&1 </dev/null \
    || { tail -20 "$WORK/logs/verify-keyed-$KEYED_RECEIPT.log" >&2
         fail "the receipt $KEYED_RECEIPT for the join-issued key did not verify"; }
printf 'release_gate.sh:     %s -> %s verified\n' "$KEYED_REQUEST" "$KEYED_RECEIPT"

# --------------------------------------------------------------------------
# After the restart the records still have to add up
# --------------------------------------------------------------------------

step "verify $RECEIPT_ID as the consumer (over HTTP, with the identity join saved)"
show "potluck verify receipt --config-dir consumer --receipt-id $RECEIPT_ID"
"$POTLUCK" verify receipt --config-dir "$WORK/consumer" --receipt-id "$RECEIPT_ID" \
    >"$WORK/logs/verify-consumer.log" 2>&1 </dev/null \
    || fail 'the consumer-side receipt verification reported a contradiction'
grep -qF 'signature_valid' "$WORK/logs/verify-consumer.log" \
    || fail 'the consumer-side verification printed no dimensions'

step "verify $RESTART_RECEIPT_ID as the operator (against the server database)"
show "potluck-server verify receipt --config server.json --receipt-id $RESTART_RECEIPT_ID"
"$POTLUCK_SERVER" verify receipt --config "$SERVER_JSON" --receipt-id "$RESTART_RECEIPT_ID" \
    >"$WORK/logs/verify-operator.log" 2>&1 </dev/null \
    || fail 'the operator-side receipt verification reported a contradiction'

step 'reconcile the node against the server after the restart'
show 'potluck share reconcile --config node/node.json --json'
RECONCILE_RC=0
"$POTLUCK" share reconcile --config "$WORK/node/node.json" --json \
    >"$WORK/logs/reconcile-node-restart.json" 2>"$WORK/logs/reconcile-node-restart.err" \
    </dev/null || RECONCILE_RC=$?
cat "$WORK/logs/reconcile-node-restart.json"
if [ "$RECONCILE_RC" = 0 ]; then
    printf 'release_gate.sh:     node and server agree\n'
elif [ "$RECONCILE_RC" = 1 ]; then
    # One shape of difference is the restart window itself and is *correct*
    # behaviour: the server dispatched an offer into a link that had just gone,
    # the node never accepted it, so the server marked that attempt FAILED with
    # the settlement HELD and no receipt, and the retry delivered the answer.
    # `share reconcile` naming it is the honest report, not a defect — what would
    # be a defect is a *settled* attempt the node has no record of, which is what
    # this check refuses.
    JSON=$(cat "$WORK/logs/reconcile-node-restart.json")
    TOTAL=$(printf '%s' "$JSON" | grep -o '"kind":"' | wc -l | tr -d ' ')
    MISSING=$(printf '%s' "$JSON" | grep -o '"kind":"missing_locally"' | wc -l | tr -d ' ')
    UNSETTLED=$(printf '%s' "$JSON" \
        | grep -o 'status=FAILED usage_tokens=[^ ]* settlement=HELD receipt=<none>' \
        | wc -l | tr -d ' ')
    if [ "$TOTAL" = 0 ] || [ "$TOTAL" != "$MISSING" ] || [ "$MISSING" != "$UNSETTLED" ]; then
        fail 'after the restart the node and server disagree about something that is not an unaccepted, unsettled offer'
    fi
    printf 'release_gate.sh:     %s difference(s), all of them the restart window: an offer the node never accepted, FAILED with the settlement HELD and no receipt, so nothing was charged for it\n' \
        "$TOTAL"
else
    fail "share reconcile exited $RECONCILE_RC"
fi

step 'reconcile the server against itself again'
show 'potluck-server admin reconcile --config server.json'
"$POTLUCK_SERVER" admin reconcile --config "$SERVER_JSON" \
    >"$WORK/logs/reconcile-server-restart.log" 2>&1 </dev/null \
    || { tail -20 "$WORK/logs/reconcile-server-restart.log" >&2
         fail 'admin reconcile reported a difference after the restart'; }

# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------

printf 'release_gate.sh: PASS potluck %s at %s\n' "$VERSION" "$SHORT_SHA"
printf 'release_gate.sh: install.sh into a fresh prefix; the installed package is what ran\n'
printf 'release_gate.sh: fresh server (no hand-written credentials) + invite-only node and consumer\n'
printf 'release_gate.sh: default-model/default-charge asks: streaming (first increment before completion), buffered, repeat, after restart\n'
printf 'release_gate.sh: an API key answered /openai/v1/chat/completions buffered and streaming against the real node: %s %s\n' \
    "$OPENAI_BUFFERED_REQUEST" "$OPENAI_STREAM_REQUEST"
printf 'release_gate.sh: an invite minted --with-api-key handed its key to the consumer join, which answered %s\n' \
    "$KEYED_REQUEST"
printf 'release_gate.sh: receipts %s %s %s distinct; verified on both sides; node and server reconcile clean\n' \
    "$RECEIPT_ID" "$BUFFERED_RECEIPT_ID" "$RESTART_RECEIPT_ID"
