#!/usr/bin/env bash
# SIGTERM to huhd hangs up its sessions and exits cleanly; SIGTERM to huh ends its session and
# the remote command gets SIGHUP. PORT sets the local port.
set -euo pipefail
cd "$(dirname "$0")/.."
bin=$PWD/.lake/build/bin
port=${PORT:-22228}

work=$(mktemp -d)
srv=
trap '[ -n "$srv" ] && kill -9 "$srv" 2>/dev/null; rm -rf "$work"' EXIT
export HOME=$work/home
export SHELL=/bin/sh
mkdir -p "$HOME"
failures=0
check() { if eval "$2"; then echo "  ok    $1"; else echo "  FAIL  $1"; failures=$((failures + 1)); fi; }
wait_for() { for _ in $(seq 100); do eval "$1" && return 0; sleep 0.1; done; return 1; }

"$bin/huh-keygen" -C client >/dev/null
"$bin/huh-keygen" -f "$HOME/.huh/host_key" >/dev/null
cp "$HOME/.huh/id.pub" "$HOME/.huh/authorized_keys"
echo "127.0.0.1:$port $(cut -d' ' -f1,2 "$HOME/.huh/host_key.pub")" > "$HOME/.huh/known_hosts"

start_server() {
  "$bin/huhd" --listen "127.0.0.1:$port" 2>>"$work/server.log" &
  srv=$!
  until (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; do sleep 0.1; done
}

# huhd: the session ends with the remote command's SIGHUP, and the server exits 0
start_server
"$bin/huh" -p "$port" 127.0.0.1 "echo \$\$ > $work/remote1; exec sleep 60" & client=$!
wait_for "[ -s $work/remote1 ]"
kill -TERM "$srv"
set +e; wait "$client"; code=$?; wait "$srv"; srvcode=$?; set -e
srv=
check "huh reports the remote SIGHUP after huhd gets SIGTERM (exit $code)" "[ $code = 129 ]"
check "huhd exits 0 on SIGTERM (exit $srvcode)" "[ $srvcode = 0 ]"
check "huhd logs its shutdown" "grep -q 'shutting down' $work/server.log"

# huh: exits 143, and the server hangs up the remote command
start_server
"$bin/huh" -p "$port" 127.0.0.1 "echo \$\$ > $work/remote2; exec sleep 60" & client=$!
wait_for "[ -s $work/remote2 ]"
kill -TERM "$client"
set +e; wait "$client"; code=$?; set -e
check "huh exits 143 on SIGTERM (exit $code)" "[ $code = 143 ]"
check "the remote command is hung up" "wait_for '! kill -0 $(cat "$work/remote2") 2>/dev/null'"
check "huhd keeps serving" "[ \"\$(\"$bin/huh\" -p $port 127.0.0.1 'echo STILL')\" = STILL ]"
kill -TERM "$srv"; wait "$srv" || true; srv=

echo "signal test: $failures failures"
[ "$failures" = 0 ] || { echo "server log:"; cat "$work/server.log"; exit 1; }
