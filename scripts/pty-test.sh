#!/usr/bin/env bash
# Run an interactive huh session on a PTY against huhd; see Tests/PtyE2E.lean. TRANSPORT is quic
# or tcp.
set -euo pipefail
cd "$(dirname "$0")/.."
bin=$PWD/.lake/build/bin
port=${PORT:-22227}

work=$(mktemp -d)
srv=
trap '[ -n "$srv" ] && kill "$srv" 2>/dev/null; rm -rf "$work"' EXIT
export HOME=$work/home
export SHELL=/bin/sh
mkdir -p "$HOME"
source scripts/transport.sh

"$bin/huh-keygen" -C client -N "" >/dev/null
"$bin/huh-keygen" --host >/dev/null
cp "$HOME/.huh/id.pub" "$HOME/.huh/authorized_keys"
"$bin/huh-keygen" -f "$HOME/.huh/enc" -C encrypted -N hunter2 >/dev/null
cat "$HOME/.huh/enc.pub" >> "$HOME/.huh/authorized_keys"
"$bin/huh-keygen" -H "127.0.0.1:$port" > "$HOME/.huh/known_hosts"

"$bin/huhd" $listen "127.0.0.1:$port" 2>"$work/server.log" &
srv=$!
wait_listening "$work/server.log" 1

if ! "$bin/huh-pty-test" "$huh" "$port"; then
  echo "server log:"; cat "$work/server.log"; exit 1
fi
