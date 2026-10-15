# huh

A small remote shell written in Lean 4. `huh` is the client and `huhd` the server. They talk
over TCP using the Noise `pqXX` handshake with hybrid ML-KEM-768 + X25519, ChaCha20-Poly1305
and BLAKE2s (via [uproar](https://github.com/katzenpost/uproar)). Each side authenticates the
other by its static public key, much as SSH does with keys only.

## Build

You need:

- [elan](https://github.com/leanprover/elan), which installs the Lean version pinned in
  `lean-toolchain`
- a C compiler, for the small shim in `c/huh_ffi.c`
- git

Then build everything:

    make build

The binaries land in `.lake/build/bin/`: `huh`, `huhd` and `huh-keygen`. The first build
fetches and compiles the dependencies, including Mathlib, so it takes a while.

To install them:

    install -m 755 .lake/build/bin/{huh,huhd,huh-keygen} /usr/local/bin/

## Keys

Everything lives in `~/.huh/`:

| File              | Who uses it | What it holds                                         |
|-------------------|-------------|-------------------------------------------------------|
| `id`, `id.pub`    | `huh`       | your private key and its public half                  |
| `known_hosts`     | `huh`       | the host keys of servers you have connected to        |
| `host_key`        | `huhd`      | the server's private key (`host_key.pub` beside it)   |
| `authorized_keys` | `huhd`      | public keys allowed to log in, one per line           |

Private key files must be readable by their owner only. `huh-keygen` creates them that way, and
both programs refuse to use a key file that anyone else can read.

On the client, make your key:

    huh-keygen -C alice@laptop

This writes `~/.huh/id` and `~/.huh/id.pub` and prints the key's fingerprint. Use `-f path` to
write somewhere else.

On the server, as the account people will log in to, make a host key and authorize your client:

    huh-keygen -f ~/.huh/host_key
    cat id.pub >> ~/.huh/authorized_keys      # the client's id.pub, copied over

A public key line looks like `huh-mlkem768hx25519 <hex> [comment]`.

## Run the server

    huhd --listen 0.0.0.0:2222

| Option                   | What it does                                                  | Default                   |
|--------------------------|---------------------------------------------------------------|---------------------------|
| `--listen addr:port`     | address to listen on; repeat it for several, e.g. `--listen 127.0.0.1:2222 --listen [::1]:2222` | `0.0.0.0:2222` |
| `--host-key path`        | the server's private key                                      | `~/.huh/host_key`         |
| `--authorized-keys path` | public keys allowed to log in                                 | `~/.huh/authorized_keys`  |
| `--syslog`               | log to syslog instead of stderr                               | off                       |

On Linux, `--listen [::]:2222` accepts both IPv4 and IPv6. Don't combine it with
`0.0.0.0:2222`: the second bind fails, and huhd then exits with an error.

`huhd` logs clients in as the user it runs as, starting that user's shell from `$SHELL` or the
passwd entry, in their home directory. Run one `huhd` per account that should accept logins.
The session's environment holds:

- `HOME`, `USER`, `LOGNAME`, `SHELL` and a basic `PATH`
- `TERM`, when the client asked for a terminal
- `HUH_CLIENT`, the client's address

A client must finish the handshake within 30 seconds.

On SIGTERM or SIGINT, `huhd`:

1. stops accepting connections
2. sends SIGHUP to every session's processes
3. gives them 5 seconds to exit, so clients get their exit status
4. kills whatever is left
5. exits 0

### systemd

`dist/huhd.service` runs `huhd` as a system service:

    install -m 644 dist/huhd.service /etc/systemd/system/
    # set User= to the account to log clients in to
    systemctl daemon-reload
    systemctl enable --now huhd

Logs go to the journal: `journalctl -u huhd`.

## Use the client

    huh [-i key] [-t|-T] [-p port] host [command...]

    huh server.example.org                  # interactive shell
    huh -p 2200 server.example.org uptime   # run one command
    huh server.example.org 'cat > backup.tar' < backup.tar

| Option    | What it does                                                                      |
|-----------|-----------------------------------------------------------------------------------|
| `-i key`  | private key to use; default `~/.huh/id`                                           |
| `-t`      | ask for a terminal (PTY) on the server                                            |
| `-T`      | don't ask for a terminal                                                          |
| `-p port` | server port; default `2222`                                                       |

With neither `-t` nor `-T`, you get a terminal when stdin is a terminal and no command is given,
and plain pipes otherwise. The pipe mode keeps stdout and stderr separate and is safe for binary
data. With a terminal:

- your terminal is in raw mode for the session
- window size changes are passed to the server
- Ctrl-C reaches the remote program

`huh` exits with:

- the remote command's exit code
- 128 + the signal number if it was killed by a signal
- 255 if the connection failed
- 143 if `huh` itself got SIGTERM; your terminal is restored first and the remote side is hung up

### Host keys

The first time you connect to a `host:port`, `huh` shows the server's key fingerprint and asks
whether to trust it. Answering `yes` saves the key in `~/.huh/known_hosts`. If the key later
changes, `huh` refuses to connect; delete the old line from `known_hosts` if the change is
expected.

To trust a server without the prompt, add a line yourself:

    echo "server.example.org:2222 $(cut -d' ' -f1,2 host_key.pub)" >> ~/.huh/known_hosts

The host part is written exactly as you type it on the command line, with the port.

## Tests

    make test          # unit tests
    make axioms        # the proofs use only Lean's own axioms
    make pipe-test     # a file sent through huh to a local huhd arrives intact (SIZE=bytes)
    make pty-test      # an interactive session on a pseudo-terminal
    make signal-test   # SIGTERM handling in huh and huhd

## License

AGPL-3.0-only
