/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.Frame
import Huh.QuicId
import LeanQUIC
import Std.Async.DNS
import Std.Sync.CancellationToken
import Std.Sync.Channel

/-! # Frames over QUIC

A session is one bidirectional QUIC stream carrying the same frames as over TCP. One task per
endpoint owns the UDP socket and every connection on it: it waits for a datagram, a timer or a
nudge from a session, then moves stream data between the connections and the sessions' channels
and sends what the connections have to send.

The server authenticates with ML-DSA-65 under its derived QUIC identity, and the client accepts it
only under a pin from known-hosts. Clients are authenticated by the Noise handshake inside. -/

namespace Huh.Quic

open Std Std.Async Std.Net
open LeanQUIC
open LeanQUIC.UDP (nowUs randomBytes randomSeed Peers epochCertificate epochGenesis epochPeriod)

def alpn : ByteArray := "huh/1".toUTF8

/-- Unacknowledged bytes a session may have written to its stream. -/
def sendWindow : Nat := 1024 * 1024

/-- Received bytes a session may leave unread before the stream's flow control holds the peer. -/
def recvWindow : Nat := 1024 * 1024

/-- PINGs after this long without sending. Besides keeping the connection inside the 30-second
idle timeout, a PING to a server whose process is gone draws the port unreachable that ends it. -/
def keepAliveMs : Nat := 5000

def quicConfig : LeanQUIC.Config :=
  { keepAlive := keepAliveMs, maxStreamsBidi := 1, maxStreamsUni := 0 }

/-! ## A session's end of a stream -/

/-- Frames go out through `out` and arrive as chunks of the stream on `inp`, which closes at the
end of the stream. `kick` wakes the endpoint after a session sends or reads. -/
structure Link where
  out : CloseableChannel ByteArray
  inp : CloseableChannel ByteArray
  /-- Bytes on `inp` not yet read by the session. -/
  unread : IO.Ref Nat
  /-- The rest of the chunk the session is reading. -/
  pending : IO.Ref ByteArray
  /-- Set by the session to close the connection now. -/
  abort : IO.Ref Bool
  kick : CloseableChannel Unit
  /-- Resolved once the connection is gone, or its close is sent. -/
  done : IO.Promise Unit
  /-- The connection's address, as `host:port`. -/
  peer : String
  /-- Why the connection was lost, when we gave up on it. -/
  lost : IO.Ref (Option String)

def Link.new (kick : CloseableChannel Unit) (peer : String) : IO Link :=
  return { out := ← CloseableChannel.new (some 64), inp := ← CloseableChannel.new,
           unread := ← IO.mkRef 0, pending := ← IO.mkRef .empty, abort := ← IO.mkRef false,
           kick, done := ← IO.Promise.new, peer, lost := ← IO.mkRef none }

def Link.nudge (l : Link) : BaseIO Unit := discard <| l.kick.trySend ()

/-- Queue a frame; waits while the stream has `sendWindow` bytes unacknowledged. -/
def Link.send (l : Link) (frame : ByteArray) : IO Unit := do
  let t ← l.out.send (← encodeFrame frame)
  l.nudge
  if let Except.error _ ← IO.wait t then throw (IO.userError ((← l.lost.get).getD "connection closed"))

/-- Up to `n` bytes, taking the next chunk with `next`; empty at the end of the stream. -/
def Link.readWith (l : Link) (next : IO (Option ByteArray)) (n : USize) : IO ByteArray := do
  let mut buf ← l.pending.get
  if buf.isEmpty then
    let some chunk ← next
      | if let some r ← l.lost.get then throw (IO.userError r) else return .empty
    l.unread.modify (· - chunk.size)
    l.nudge
    buf := chunk
  let k := min n.toNat buf.size
  l.pending.set (buf.extract k buf.size)
  return buf.extract 0 k

def Link.read (l : Link) (n : USize) : IO ByteArray :=
  l.readWith (do IO.wait (← l.inp.recv)) n

/-- Up to `n` bytes, or an error once `deadline` is cancelled. -/
def Link.readBefore (l : Link) (deadline : CancellationToken) (n : USize) : IO ByteArray :=
  l.readWith (Selectable.one #[
    .case l.inp.recvSelector pure,
    .case deadline.selector fun _ => throw (IO.userError "handshake timed out")]).block n

def Link.frames (l : Link) : Frames := ⟨l.send, readFrameWith l.read⟩

/-- Wait up to `ms` milliseconds for the connection to be gone. -/
def Link.awaitDone (l : Link) (ms : Nat) : IO Unit := do
  let timer ← IO.asTask (IO.sleep ms.toUInt32)
  discard <| IO.waitAny [l.done.result!.map fun _ => (), timer.map fun _ => ()]

/-- Close the connection without waiting for anything still unsent, returning once the close is
sent, or after a second. -/
def Link.close (l : Link) : IO Unit := do
  l.abort.set true
  l.nudge
  l.awaitDone 1000

/-- No more frames: the stream finishes once they are sent, and a server closes the connection
when the peer has them all. -/
def Link.finish (l : Link) : IO Unit := do
  try l.out.close catch _ => pure ()
  l.nudge

/-! ## The endpoint -/

structure Peer where
  udp : UDP.Peer
  stream : Option Nat := none
  link : Option Link := none
  finished : Bool := false
  /-- A server closes an established connection that has not opened its stream by then. -/
  streamDeadline : Option Nat := none
  /-- After the peer's port was reported unreachable: when to give up on it unless an authenticated
  packet has moved its idle deadline from the one recorded. -/
  unreachable : Option (Nat × Option Nat) := none

inductive Event where
  | datagram (data : ByteArray) (from_ : Option SocketAddress)
  | timeout
  | kick
  /-- An ICMP port unreachable for the connected socket. -/
  | refused

/-- A datagram, the earliest deadline, a nudge from a session, or a port unreachable. Any other
failed receive counts as a nudge. -/
def wait (sock : UDP.Socket) (kick : CloseableChannel Unit) (deadline : Option Nat) : Async Event := do
  let now ← nowUs
  let ms := match deadline with
    | some d => if d ≤ now then 0 else (d - now + 999) / 1000
    | none => 1000
  if ms == 0 then return .timeout
  let sleep ← Sleep.mk (Std.Time.Millisecond.Offset.ofNat ms)
  let ev ← try
      Selectable.one #[
        .case (sock.recvSelector 65536) fun (d, a) => pure (Event.datagram d a),
        .case sleep.selector fun _ => pure Event.timeout,
        .case kick.recvSelector fun _ => pure Event.kick]
    catch
      | .noSuchThing _ 111 _ => pure Event.refused
      | _ => pure Event.kick
  sleep.stop
  pure ev

def unacked (c : Conn) (id : Nat) : Nat :=
  match c.streams[id]? with
  | some s => s.send.written - s.send.ackedTo
  | none => 0

/-- Move data between a connection's stream and its session, as far as the windows allow. -/
def service (p : Peer) (isServer : Bool) : IO Peer := do
  let (some id, some l) := (p.stream, p.link) | return p
  let mut c := p.udp.conn
  let mut finished := p.finished
  if ← l.abort.get then
    c := c.close (← nowUs)
  while !finished && unacked c id < sendWindow do
    match ← l.out.tryRecv with
    | some d => c := c.write id d
    | none =>
      if ← l.out.isClosed then
        c := c.finish id
        finished := true
      break
  repeat
    if (← l.unread.get) ≥ recvWindow || c.readable id == 0 then break
    let (c', d) := c.read id 65536
    c := c'
    l.unread.modify (· + d.size)
    discard <| l.inp.send d
  if c.recvFinished id then try l.inp.close catch _ => pure ()
  -- The server's last frame is the exit status: once the client has it all, the session is over.
  if isServer && finished && c.sendFinished id && !c.isClosed then
    c := c.close (← nowUs)
  return { p with udp := { p.udp with conn := c }, finished }

/-- A connection is gone, for `reason` if we gave up on it: unblock its session. -/
def Link.hangUp (l : Link) (reason : Option String := none) : IO Unit := do
  l.lost.set reason
  try l.inp.close catch _ => pure ()
  try l.out.close catch _ => pure ()
  l.done.resolve ()

/-- The peer's port was reported unreachable. ICMP can be forged, so this only starts a check: a
PING, and the peer is gone if nothing authenticated arrives within three PTOs. -/
def suspect (p : Peer) (now : Nat) : Peer :=
  if p.unreachable.isSome then p else
  let c := p.udp.conn
  let c := if c.isEstablished then { c with pendingControl := c.pendingControl.push .ping } else c
  let wait := max 1000000 (3 * c.recovery.ptoDuration .application)
  { p with unreachable := some (now + wait, c.idleDeadline), udp := { p.udp with conn := c } }

/-- Send everything a connection has to send now. -/
def flush (sock : UDP.Socket) (p : Peer) (dest : Option SocketAddress) : Async Peer := do
  let mut c := p.udp.conn
  let mut refused := false
  for _ in [0:4096] do
    let (c', d) := c.poll (← nowUs)
    c := c'
    match d with
    | some d => try sock.send d dest catch | .noSuchThing _ 111 _ => refused := true | _ => pure ()
    | none => break
  let p := { p with udp := { p.udp with conn := c } }
  if refused then return suspect p (← nowUs)
  pure p

/-- Why a connection closed, from `Conn.closeReason`: whether we closed it, the error code, and the
reason. -/
def closeMessage : Option (Bool × Nat × String) → String
  | some (true, 0x100 + 42, _) => "the server's certificate does not match its QUIC pin in known_hosts"
  | some (true, _, "idle timeout") => "no answer"
  | some (true, _, "unreachable") => "nothing is listening there"
  | some (true, code, r) => s!"{r} (error {code})"
  | some (false, code, r) => s!"closed by the server: {r} (error {code})"
  | none => "connection closed"

/-- What the endpoint does as a server: accept connections under the ML-DSA-65 key seeded by
`signingKey`, its certificate renewed every epoch, and hand each session to `onSession`. -/
structure Serving where
  signingKey : Vector UInt8 32
  onSession : Link → IO Unit
  /-- How long a client has to open its stream. -/
  streamTimeoutMs : Nat

def currentEpoch : IO Nat := do
  let unix := (← Std.Time.Timestamp.now).toSecondsSinceUnixEpoch.val.toNat
  return (unix - epochGenesis) / epochPeriod

/-- Run the endpoint until `stop` is set and every connection is gone. A client endpoint starts
with its one connection, and resolves `ready` when its stream is open. -/
partial def run (sock : UDP.Socket) (kick : CloseableChannel Unit) (serving : Option Serving)
    (initial : Option (Peer × IO.Promise (Except String Link))) (stop : IO.Ref Bool) : IO Unit := do
  let resetKey ← randomBytes 32
  let tokenKey ← randomBytes 32
  let mkEndpoint : Option Serving → IO (Option (Endpoint.Config × Nat)) := fun
    | some s => do
      let cert ← epochCertificate s.signingKey .mldsa65
      return some ({ quic := { quicConfig with resetKey }, tokenKey,
                     tls := { alpn, transportParams := .empty, scheme := .mldsa65, signingKey := s.signingKey,
                              certificate := cert } }, ← currentEpoch)
    | none => pure none
  let peerName (a : SocketAddress) : String := toString a
  -- Every session's link, so that none is left waiting if the loop fails.
  let links ← IO.mkRef (#[] : Array Link)
  let rec loop (ps : Peers) (peers : Std.HashMap Nat Peer) (ep : Option (Endpoint.Config × Nat)) :
      Async Unit := do
    let mut peers := peers
    let mut ps := ps
    let mut ep := ep
    -- Service and send, and drop closed connections.
    for (i, p) in peers.toList do
      let p ← (service p serving.isSome : IO _)
      if p.udp.conn.isClosed then
        let reason := match p.udp.conn.closeReason with
          | some (true, code, r) => if r.isEmpty then none else some (closeMessage (some (true, code, r)))
          | _ => none
        if let some l := p.link then (l.hangUp reason : IO _)
        peers := peers.erase i
        ps := { ps with conns := ps.conns.erase i, byCid := p.udp.cids.foldl (·.erase ·) ps.byCid }
        if let some (_, ready) := initial then ready.resolve (.error (closeMessage p.udp.conn.closeReason))
        continue
      let dest := if serving.isSome then
        some ((p.udp.addrs.find? (·.1 == p.udp.conn.peerAddr)).map (·.2) |>.getD p.udp.addr) else none
      let p ← flush sock p dest
      if let some l := p.link then
        if ← (l.abort.get : IO _) then l.done.resolve ()
      peers := peers.insert i p
      ps := ps.put i p.udp
    if peers.isEmpty && (serving.isNone || (← stop.get)) then return
    let earliest : Option Nat → Option Nat → Option Nat
      | some a, some b => some (min a b) | none, b => b | a, none => a
    let deadline := peers.fold (fun acc _ p =>
      earliest acc (earliest p.udp.conn.nextTimeout (earliest p.streamDeadline (p.unreachable.map (·.1))))) none
    let ev ← wait sock kick deadline
    let now ← nowUs
    match ev with
    | .kick => repeat if (← (kick.tryRecv : IO _)).isNone then break
    | .timeout =>
      for (i, p) in peers.toList do
        if p.udp.conn.nextTimeout.any (· ≤ now) then
          peers := peers.insert i { p with udp := { p.udp with conn := p.udp.conn.onTimeout now } }
        if p.streamDeadline.any (· ≤ now) then
          let c := (peers[i]?.map (·.udp.conn)).getD p.udp.conn
          peers := peers.insert i { p with streamDeadline := none, udp := { p.udp with conn := c.close now } }
        if let some (d, idle) := p.unreachable then
          if d ≤ now then
            let p := peers[i]?.getD p
            let c := p.udp.conn
            let c := if c.idleDeadline == idle && !c.isClosed then
                { c with phase := .closed, closeReason := some (true, 0, "unreachable") } else c
            peers := peers.insert i { p with unreachable := none, udp := { p.udp with conn := c } }
    | .refused => for (i, p) in peers.toList do peers := peers.insert i (suspect p now)
    | .datagram _ none => pure ()
    | .datagram d (some addr) =>
      let some (hdr, _) := parseHeader d 0 cidLength | return ← loop ps peers ep
      let name := (peerName addr).toUTF8
      match ps.byCid[hdr.dcid]?, ps.byCid[hdr.dcid]?.bind (peers[·]?) with
      | some i, some p =>
        let addrs := ((name, addr) :: p.udp.addrs.filter (·.1 != name)).take 4
        peers := peers.insert i { p with udp := { p.udp with addrs, conn := p.udp.conn.recvFrom now name d } }
      | _, _ =>
        if let (some s, false) := (serving, ← stop.get) then
          if let some (_, e) := ep then
            if (← currentEpoch) != e then ep ← (mkEndpoint (some s) : IO _)
          if let some (cfg, _) := ep then
            match Endpoint.onUnknown cfg name d now (← randomBytes cidLength) (← randomSeed) with
            | .drop => pure ()
            | .retry pkt | .reset pkt => try sock.send pkt (some addr) catch _ => pure ()
            | .accept c cids =>
              let i := ps.next
              let udp : UDP.Peer := { addr, addrs := [(name, addr)], conn := c.recvFrom now name d,
                                      initial := cids, cids := [] }
              ps := { ps with next := i + 1 }.put i udp
              peers := peers.insert i { udp }
    -- New streams: the client opens its one stream, the server takes the client's.
    for (i, p) in peers.toList do
      if p.stream.isSome || !p.udp.conn.isEstablished then continue
      match serving, initial with
      | some s, _ =>
        let (c, ids) := p.udp.conn.takeIncoming
        let some id := ids.find? (!Conn.isUni ·)
          | let streamDeadline := p.streamDeadline <|> some (now + s.streamTimeoutMs * 1000)
            peers := peers.insert i { p with udp := { p.udp with conn := c }, streamDeadline }
        let l ← (Link.new kick (peerName p.udp.addr) : IO _)
        links.modify (·.push l)
        peers := peers.insert i { p with udp := { p.udp with conn := c }, stream := some id, link := some l,
                                         streamDeadline := none }
        discard <| (IO.asTask (prio := .dedicated) (s.onSession l) : IO _)
      | none, some (_, ready) =>
        let (c, id) := p.udp.conn.openStream
        let some id := id | continue
        let l ← (Link.new kick (peerName p.udp.addr) : IO _)
        links.modify (·.push l)
        peers := peers.insert i { p with udp := { p.udp with conn := c }, stream := some id, link := some l }
        ready.resolve (.ok l)
      | none, none => pure ()
    loop ps peers ep
  let (ps, peers) := match initial with
    | some (p, _) => (({} : Peers).put 0 p.udp |> fun ps => { ps with next := 1 }, ({} : Std.HashMap Nat Peer).insert 0 p)
    | none => ({}, {})
  try (loop ps peers (← mkEndpoint serving)).block
  catch e =>
    for l in ← links.get do l.hangUp
    throw e

/-! ## Dialing and listening -/

def bindAny (sock : UDP.Socket) : SocketAddress → IO Unit
  | .v4 _ => sock.bind (.v4 { addr := IPv4Addr.ofParts 0 0 0 0, port := 0 })
  | .v6 _ => sock.bind (.v6 { addr := IPv6Addr.ofParts 0 0 0 0 0 0 0 0, port := 0 })

/-- Connect to `addr`, accepting the server only under one of `pins`, and open the session's
stream. -/
def connect (addr : SocketAddress) (pins : List ByteArray) : IO Link := do
  let sock ← UDP.Socket.mk
  bindAny sock addr
  sock.connect addr
  let tls : LeanTLS.Handshake.Client.Config := { alpn, transportParams := .empty, pins, schemes := [.mldsa65] }
  let local_ ← randomBytes cidLength
  let c ← match Conn.newClient quicConfig tls (← randomSeed) local_ (← randomBytes cidLength) (← nowUs) with
    | .ok c => pure c
    | .error a => throw (IO.userError s!"TLS: {reprStr a}")
  let kick ← CloseableChannel.new
  let ready ← IO.Promise.new
  let udp : UDP.Peer := { addr, addrs := [], conn := c, initial := [local_], cids := [] }
  let stop ← IO.mkRef false
  discard <| IO.asTask (prio := .dedicated) do
    try run sock kick none (some ({ udp }, ready)) stop
    catch e => ready.resolve (.error (toString e))
    ready.resolve (.error "connection closed")
  IO.ofExcept ((← IO.wait ready.result!).mapError IO.userError)

/-- Connect to the first address of `host` that answers. -/
def dial (host : String) (port : UInt16) (pins : List ByteArray) : IO Link := do
  -- getaddrinfo lists an address once per socket type
  let addrs := (← (DNS.getAddrInfo host (toString port)).block).toList.eraseDups
  let mut err := IO.userError s!"{host}: no addresses"
  for a in addrs do
    let addr : SocketAddress := match a with
      | .v4 a => .v4 ⟨a, port⟩
      | .v6 a => .v6 ⟨a, port⟩
    try return ← connect addr pins
    catch e => err := IO.userError s!"{addr}: {e}"
  throw err

/-- A bound server endpoint: its address, and its task. -/
structure Server where
  addr : SocketAddress
  task : Task (Except IO.Error Unit)
  stopFlag : IO.Ref Bool
  kick : CloseableChannel Unit

/-- Accept no more connections; the task ends once the open ones are gone. -/
def Server.stop (s : Server) : BaseIO Unit := do
  s.stopFlag.set true
  discard <| s.kick.trySend ()

/-- Serve on `addr` under the QUIC identity of `hostSeed`, running `onSession` for each session on
its own task. A connection that opens no stream within `streamTimeoutMs` of the QUIC handshake
is closed. -/
def listen (addr : SocketAddress) (hostSeed : ByteArray) (onSession : Link → IO Unit)
    (streamTimeoutMs : Nat := 10000) : IO Server := do
  let sock ← UDP.Socket.mk
  sock.bind addr
  let kick ← CloseableChannel.new
  let stopFlag ← IO.mkRef false
  let serving : Serving := { signingKey := QuicId.signingSeed hostSeed, onSession, streamTimeoutMs }
  let task ← IO.asTask (prio := .dedicated) (run sock kick (some serving) none stopFlag)
  return { addr := ← sock.getSockName, task, stopFlag, kick }

end Huh.Quic
