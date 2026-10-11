#!/usr/bin/env bash
# Send a random file through huh in pipe mode to huhd behind socat, then check it arrived intact.
# SIZE sets the file size in bytes, PORT the local port.
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

"$bin/huh-keygen" -C client >/dev/null
"$bin/huh-keygen" -f "$HOME/.huh/host_key" >/dev/null
cp "$HOME/.huh/id.pub" "$HOME/.huh/authorized_keys"
echo "127.0.0.1:$port $(cut -d' ' -f1,2 "$HOME/.huh/host_key.pub")" > "$HOME/.huh/known_hosts"

socat "TCP-LISTEN:$port,bind=127.0.0.1,reuseaddr,fork" "EXEC:$bin/huhd -e" 2>"$work/server.log" &
srv=$!
until nc -z 127.0.0.1 "$port" 2>/dev/null; do sleep 0.1; done

head -c "$size" /dev/urandom > "$work/sent"
start=$(date +%s)
if ! "$bin/huh" -p "$port" 127.0.0.1 "cat > $work/received" < "$work/sent"; then
  echo "pipe test: huh failed"; cat "$work/server.log"; exit 1
fi
end=$(date +%s)
if cmp "$work/sent" "$work/received"; then
  echo "pipe test: $size bytes match ($((end - start)) s)"
else
  echo "pipe test: files differ"; cat "$work/server.log"; exit 1
fi
