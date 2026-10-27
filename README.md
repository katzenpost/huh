# huh

A small remote shell written in Lean 4. `huh` is the client and `huhd` the server. They talk
over QUIC (via [lean_quic](https://github.com/katzenpost/lean_quic)), or TCP, using the Noise
`pqXX` handshake with hybrid ML-KEM-768 + X25519, ChaCha20-Poly1305 and BLAKE2s (via
[uproar](https://github.com/katzenpost/uproar)). Each side authenticates the other by its static
public key, much as SSH does with keys only. Over QUIC, the client also authenticates the server
at the QUIC layer: TLS 1.3 with X25519MLKEM768 key exchange and an ML-DSA-65 certificate,
accepted only under a pin from known-hosts. A client's private key can be
encrypted under a passphrase, stretched with Argon2id (via
[Cryptlib](https://github.com/katzenpost/cryptlib)).

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

| File                               | Who uses it | What it holds                                  |
|------------------------------------|-------------|------------------------------------------------|
| `id.private`, `id.pub`             | `huh`       | your private key and its public half           |
| `known_hosts`                      | `huh`       | the host keys of servers you have connected to |
| `host_key.private`, `host_key.pub` | `huhd`      | the server's private key and its public half   |
| `authorized_keys`                  | `huhd`      | public keys allowed to log in, one per line    |

Private key file names always end in `.private`, and the public half sits beside it as `.pub`.
`huh`, `huhd` and `huh-keygen -p` refuse a private key file with any other name. Key files from
before this rule, `~/.huh/id` and `~/.huh/host_key`, only need renaming:
`mv ~/.huh/id ~/.huh/id.private`.

Private key files must be readable by their owner only. `huh-keygen` creates them that way, and
both programs refuse to use a key file that anyone else can read.

On the client, make your key:

    huh-keygen -C alice@laptop

This asks for a passphrase, writes `~/.huh/id.private` and `~/.huh/id.pub`, and prints the key's
fingerprint. Use `-f path` to write somewhere else; `-f work` and `-f work.private` both mean
`work.private` and `work.pub`.

The passphrase encrypts the private key, and `huh` asks for it each time it connects, on the
terminal with echo off, allowing three tries. Leaving it empty stores the key unencrypted. `-N passphrase` sets it without asking, for scripts (`-N ""`
for none). To change or remove the passphrase of an existing key:

    huh-keygen -p                    # ~/.huh/id.private, or -f path

An encrypted key file is 96 bytes:

    "huhkey" 1 0 ‖ m ‖ t ‖ p ‖ salt (16) ‖ nonce (12) ‖ ChaCha20-Poly1305(seed) (48)

The cipher key is Argon2id (RFC 9106) of the passphrase and the salt, with `m` KiB of memory, `t`
passes and `p` lanes, each stored as a 32-bit little-endian number. `huh-keygen` uses 64 MiB, 2
passes and 1 lane, about a second to unlock. The header before the ciphertext is authenticated
too, so a changed parameter is caught like a wrong passphrase. An unencrypted key file is the
bare 32-byte seed.

On the server, as the account people will log in to, make a host key and authorize your client:

    huh-keygen --host
    cat id.pub >> ~/.huh/authorized_keys      # the client's id.pub, copied over

`--host` writes `~/.huh/host_key.private` and never asks for a passphrase. Host keys are never
encrypted, so a server can start on its own after a reboot. `huhd` refuses an encrypted key.

A public key line looks like `huh-mlkem768hx25519 <hex> [comment]`. A host's adds its QUIC pin
after the key, `quic-mldsa65=<hex>`: the SHA-256 of the SubjectPublicKeyInfo of the host's
ML-DSA-65 key, which is derived from the host key, so one file holds both. To give clients a
ready known-hosts line for this server, see [Known hosts](#known-hosts).

### huh-keygen

    huh-keygen [-f keyfile] [-C comment] [-N passphrase]   # a client key
    huh-keygen --host [-f keyfile] [-C comment]            # a host key
    huh-keygen -p [-f keyfile] [-N passphrase]             # change a client key's passphrase
    huh-keygen -H host:port [-f keyfile]                   # print a known-hosts line

| Option          | What it does                                                                   |
|-----------------|--------------------------------------------------------------------------------|
| `-f keyfile`    | the key file; `.private` is added if missing. Default `~/.huh/id.private`, or `~/.huh/host_key.private` with `--host` and `-H` |
| `-C comment`    | comment written after the public key                                           |
| `-N passphrase` | the new passphrase, without asking; `""` for none                              |
| `-p`            | change or remove the passphrase of an existing client key                      |
| `--host`        | make a host key: never encrypted, never asks                                   |
| `-H host:port`  | print a hashed known-hosts line for the key's `.pub`, with its QUIC pin        |

`huh-keygen` never overwrites an existing key file.

## Run the server

    huhd --listen 0.0.0.0:2222

| Option                   | What it does                                                  | Default                   |
|--------------------------|---------------------------------------------------------------|---------------------------|
| `--listen addr:port`     | QUIC (UDP) address to listen on; repeat it for several, e.g. `--listen 127.0.0.1:2222 --listen [::1]:2222` | `0.0.0.0:2222`, unless `--tcp-listen` is given |
| `--tcp-listen addr:port` | TCP address to listen on; repeat it for several                | none                      |
| `--host-key path`        | the server's private key, ending in `.private`                | `~/.huh/host_key.private` |
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

A client must finish the handshake within 30 seconds. A QUIC connection that opens no stream
within 30 seconds of its QUIC handshake is closed.

On SIGTERM or SIGINT, `huhd`:

1. stops accepting connections
2. sends SIGHUP to every session's processes
3. gives them 5 seconds to exit, so clients get their exit status (over QUIC, also time for the
   clients to receive the rest of their sessions)
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

    huh [-i key] [-t|-T] [-p port] [--tcp] host [command...]

    huh server.example.org                  # interactive shell
    huh -p 2200 server.example.org uptime   # run one command
    huh server.example.org 'cat > backup.tar' < backup.tar

| Option    | What it does                                                                      |
|-----------|-----------------------------------------------------------------------------------|
| `-i key`  | private key to use, ending in `.private`; default `~/.huh/id.private`             |
| `-t`      | ask for a terminal (PTY) on the server                                            |
| `-T`      | don't ask for a terminal                                                          |
| `-p port` | server port; default `2222`                                                       |
| `--tcp`   | connect over TCP instead of QUIC                                                  |

With neither `-t` nor `-T`, you get a terminal when stdin is a terminal and no command is given,
and plain pipes otherwise. The pipe mode keeps stdout and stderr separate and is safe for binary
data. With a terminal:

- your terminal is in raw mode for the session
- window size changes are passed to the server
- Ctrl-C reaches the remote program

`huh` exits with:

- the remote command's exit code
- 128 + the signal number if it was killed by a signal
- 255 if the connection failed, or the key's passphrase was wrong three times. Over QUIC, a server
  that vanishes without closing the connection is noticed after 30 seconds of silence.
- 143 if `huh` itself got SIGTERM; your terminal is restored first and the remote side is hung up

### Known hosts

`~/.huh/known_hosts` records the key of every server you trust, one per line:

    |b2|<salt>|<hash> huh-mlkem768hx25519 <hex> quic-mldsa65=<hex>
    server.example.org:2222 huh-mlkem768hx25519 <hex>

The first field names the server as `host:port`, written exactly as you type it on the command
line, with the port (`huh -p 2200 server` is `server:2200`). It is either:

- **hashed:** the BLAKE2s hash of `host:port`, keyed with a random 32-byte salt, both in hex.
  This is what `huh` and `huh-keygen` write, so the file doesn't reveal which servers you use.
- **plain:** `host:port` in plain text. `huh` reads these too.

Blank lines and lines starting with `#` are ignored.

Over QUIC, `huh` needs the server's QUIC pin before it sends anything, so it connects only to a
`host:port` whose line has one, and refuses a server that presents another key. Add the line
with `huh-keygen -H`, below. A line without a pin works with `--tcp` only.

Over TCP, the first time you connect to a `host:port` that isn't in the file, `huh` shows the
server's key fingerprint and asks whether to trust it. Answering `yes` adds a hashed line,
without a QUIC pin.

If a server's key later changes, `huh` refuses to connect and names the line holding the old key.
Delete that line if you expect the change.

To trust a server, get its `host_key.pub` and add a line with `huh-keygen -H`. This prints a
hashed known-hosts line for a public key, with the QUIC pin; it never creates a key:

    huh-keygen -H server.example.org:2222 -f host_key.pub >> ~/.huh/known_hosts

`-f` takes a `.pub` file, or a private key file, in which case it reads the `.pub` beside it.
Without `-f`, it uses `~/.huh/host_key.pub`. A host key's `.pub` from before QUIC has no pin; the
pin is then derived from the private key beside it, so a server's admin can print the line for
clients directly:

    huh-keygen -H server.example.org:2222

## Tests

    make test          # unit tests
    make axioms        # the proofs use only Lean's own axioms
    make pipe-test     # a file sent through huh to a local huhd arrives intact (SIZE=bytes)
    make pty-test      # an interactive session on a pseudo-terminal, and the passphrase prompt
    make signal-test   # SIGTERM handling in huh and huhd

The end-to-end tests run over QUIC; set `TRANSPORT=tcp` to run them over TCP.

## License

AGPL-3.0-only
