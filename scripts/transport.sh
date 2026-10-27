# Sourced by the end-to-end tests once $bin and $work are set. TRANSPORT is quic (the default)
# or tcp; $huh is the client to run and $listen huhd's flag for the listen address.
case ${TRANSPORT:-quic} in
  quic) listen=--listen; huh=$bin/huh ;;
  tcp)
    listen=--tcp-listen
    huh=$work/huh-tcp
    printf '#!/bin/sh\nexec %s --tcp "$@"\n' "$bin/huh" > "$huh"
    chmod +x "$huh" ;;
  *) echo "TRANSPORT is quic or tcp"; exit 2 ;;
esac

# Wait until the server logging to $1 has said it is listening $2 times.
wait_listening() {
  until [ "$(grep -c "listening on" "$1" 2>/dev/null || true)" -ge "$2" ] 2>/dev/null; do sleep 0.1; done
}
