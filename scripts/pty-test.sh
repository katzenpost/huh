#!/usr/bin/env bash
# Run an interactive huh session on a PTY against huhd; see Tests/PtyE2E.lean.
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

"$bin/huh-keygen" -C client >/dev/null
"$bin/huh-keygen" -f "$HOME/.huh/host_key" >/dev/null
cp "$HOME/.huh/id.pub" "$HOME/.huh/authorized_keys"
echo "127.0.0.1:$port $(cut -d' ' -f1,2 "$HOME/.huh/host_key.pub")" > "$HOME/.huh/known_hosts"

"$bin/huhd" --listen "127.0.0.1:$port" 2>"$work/server.log" &
srv=$!
until (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; do sleep 0.1; done

if ! "$bin/huh-pty-test" "$bin/huh" "$port"; then
  echo "server log:"; cat "$work/server.log"; exit 1
fi
