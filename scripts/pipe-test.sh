#!/usr/bin/env bash
# Send a random file through huh in pipe mode to huhd, then check it arrived intact.
# SIZE sets the file size in bytes, PORT the local port, TRANSPORT quic or tcp.
set -euo pipefail
cd "$(dirname "$0")/.."
bin=$PWD/.lake/build/bin
size=${SIZE:-1048576}
port=${PORT:-22222}

work=$(mktemp -d)
srv=
trap '[ -n "$srv" ] && kill "$srv" 2>/dev/null; rm -rf "$work"' EXIT
export HOME=$work/home
mkdir -p "$HOME"
source scripts/transport.sh

"$bin/huh-keygen" -C client -N "" >/dev/null
"$bin/huh-keygen" --host >/dev/null
cp "$HOME/.huh/id.pub" "$HOME/.huh/authorized_keys"
"$bin/huh-keygen" -H "127.0.0.1:$port" > "$HOME/.huh/known_hosts"

"$bin/huhd" $listen "127.0.0.1:$port" 2>"$work/server.log" &
srv=$!
wait_listening "$work/server.log" 1

head -c "$size" /dev/urandom > "$work/sent"
start=$(date +%s)
if ! "$huh" -p "$port" 127.0.0.1 "cat > $work/received" < "$work/sent"; then
  echo "pipe test: huh failed"; cat "$work/server.log"; exit 1
fi
end=$(date +%s)
if cmp "$work/sent" "$work/received"; then
  echo "pipe test (${TRANSPORT:-quic}): $size bytes match ($((end - start)) s)"
else
  echo "pipe test: files differ"; cat "$work/server.log"; exit 1
fi
