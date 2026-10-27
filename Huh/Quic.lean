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

A session is one bidirectional QUIC stream carrying the same frames as over TCP. An endpoint owns
the UDP socket and every connection on it, with one task for each direction: one receives
datagrams into the connections, the other moves stream data between the connections and the
sessions' channels and sends what the connections have to send.

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

/-- Act on whichever of a connection's deadlines have passed. -/
def expire (p : Peer) (now : Nat) : Peer := Id.run do
  let mut p := p
  if p.udp.conn.nextTimeout.any (· ≤ now) then
    p := { p with udp := { p.udp with conn := p.udp.conn.onTimeout now } }
  if p.streamDeadline.any (· ≤ now) then
    p := { p with streamDeadline := none, udp := { p.udp with conn := p.udp.conn.close now } }
  if let some (d, idle) := p.unreachable then
    if d ≤ now then
      let c := p.udp.conn
      let c := if c.idleDeadline == idle && !c.isClosed then
          { c with phase := .closed, closeReason := some (true, 0, "unreachable") } else c
      p := { p with unreachable := none, udp := { p.udp with conn := c } }
  return p

/-- Take everything a connection has to send now. -/
def drain (p : Peer) : IO (Peer × Array ByteArray) := do
  let mut c := p.udp.conn
  let mut out := #[]
  for _ in [0:4096] do
    let (c', d) := c.poll (← nowUs)
    c := c'
    match d with
    | some d => out := out.push d
    | none => break
  return ({ p with udp := { p.udp with conn := c } }, out)

/-- Send `ds`, starting every send before waiting for any; whether the peer's port was reported
unreachable. -/
def sendAll (sock : UDP.Socket) (ds : Array ByteArray) (dest : Option SocketAddress) : IO Bool := do
  let mut sends := #[]
  let mut refused := false
  for d in ds do
    try sends := sends.push (← sock.native.send #[d] dest)
    catch | .noSuchThing _ 111 _ => refused := true | _ => pure ()
  for r in sends do
    if let some (.error (.noSuchThing _ 111 _)) ← IO.wait r.result? then refused := true
  return refused

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

/-- An endpoint's connections, shared by its two tasks. -/
structure State where
  ps : Peers := {}
  peers : Std.HashMap Nat Peer := {}
  ep : Option (Endpoint.Config × Nat) := none

/-- Wait for a nudge, or until `deadline`. -/
def idle (kick : CloseableChannel Unit) (deadline : Option Nat) : Async Unit := do
  let now ← nowUs
  let ms := match deadline with
    | some d => if d ≤ now then 0 else (d - now + 999) / 1000
    | none => 1000
  if ms == 0 then return
  let sleep ← Sleep.mk (Std.Time.Millisecond.Offset.ofNat ms)
  Selectable.one #[
    .case kick.recvSelector fun _ => pure (),
    .case sleep.selector fun _ => pure ()]
  sleep.stop

/-- Run the endpoint until `stop` is set and every connection is gone. A client endpoint starts
with its one connection, and resolves `ready` when its stream is open.

One task receives: it hands each datagram to its connection, or to the server to start one. The
other sends: it acts on deadlines, moves stream data between the connections and their sessions,
and sends what the connections have to send, waiting for a nudge from the receiving task or a
session when there is nothing to do. -/
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
  let nudge : BaseIO Unit := discard <| kick.trySend ()
  -- Every session's link, so that none is left waiting if the endpoint fails.
  let links ← IO.mkRef (#[] : Array Link)
  let s : State := { ep := ← mkEndpoint serving }
  let state ← Std.Mutex.new <| match initial with
    | some (p, _) => { s with ps := { ({} : Peers).put 0 p.udp with next := 1 }, peers := ({} : Std.HashMap Nat Peer).insert 0 p }
    | none => s
  -- A datagram for a connection, or one that may start a new one.
  let receive (s : State) (d : ByteArray) (addr : SocketAddress) : IO State := do
    let now ← nowUs
    let some (hdr, _) := parseHeader d 0 cidLength | return s
    let name := (peerName addr).toUTF8
    match s.ps.byCid[hdr.dcid]?, s.ps.byCid[hdr.dcid]?.bind (s.peers[·]?) with
    | some i, some p =>
      let addrs := ((name, addr) :: p.udp.addrs.filter (·.1 != name)).take 4
      return { s with peers := s.peers.insert i { p with udp := { p.udp with addrs, conn := p.udp.conn.recvFrom now name d } } }
    | _, _ =>
      let (some srv, false) := (serving, ← stop.get) | return s
      let mut ep := s.ep
      if let some (_, e) := ep then
        if (← currentEpoch) != e then ep ← mkEndpoint (some srv)
      let some (cfg, _) := ep | return { s with ep }
      match Endpoint.onUnknown cfg name d now (← randomBytes cidLength) (← randomSeed) with
      | .drop => return { s with ep }
      | .retry pkt | .reset pkt =>
        try discard <| sock.native.send #[pkt] (some addr) catch _ => pure ()
        return { s with ep }
      | .accept c cids =>
        let i := s.ps.next
        let udp : UDP.Peer := { addr, addrs := [(name, addr)], conn := c.recvFrom now name d,
                                initial := cids, cids := [] }
        return { s with ep, ps := { s.ps with next := i + 1 }.put i udp, peers := s.peers.insert i { udp } }
  -- New streams: the client opens its one stream, the server takes the client's.
  let openStreams (peers : Std.HashMap Nat Peer) (now : Nat) : IO (Std.HashMap Nat Peer) := do
    let mut peers := peers
    for (i, p) in peers.toList do
      if p.stream.isSome || !p.udp.conn.isEstablished then continue
      match serving, initial with
      | some s, _ =>
        let (c, ids) := p.udp.conn.takeIncoming
        let some id := ids.find? (!Conn.isUni ·)
          | let streamDeadline := p.streamDeadline <|> some (now + s.streamTimeoutMs * 1000)
            peers := peers.insert i { p with udp := { p.udp with conn := c }, streamDeadline }
        let l ← Link.new kick (peerName p.udp.addr)
        links.modify (·.push l)
        peers := peers.insert i { p with udp := { p.udp with conn := c }, stream := some id, link := some l,
                                         streamDeadline := none }
        discard <| IO.asTask (prio := .dedicated) (s.onSession l)
      | none, some (_, ready) =>
        let (c, id) := p.udp.conn.openStream
        let some id := id | continue
        let l ← Link.new kick (peerName p.udp.addr)
        links.modify (·.push l)
        peers := peers.insert i { p with udp := { p.udp with conn := c }, stream := some id, link := some l }
        ready.resolve (.ok l)
      | none, none => pure ()
    return peers
  -- Service every connection and take what it has to send, dropping the closed ones; and the
  -- links of sessions that closed their connection.
  let collect (s : State) : IO (State × Array (Nat × Array ByteArray × Option SocketAddress) × Array Link) := do
    let mut s := s
    let mut out := #[]
    let mut aborted := #[]
    for (i, p) in s.peers.toList do
      let p ← service p serving.isSome
      if p.udp.conn.isClosed then
        let reason := match p.udp.conn.closeReason with
          | some (true, code, r) => if r.isEmpty then none else some (closeMessage (some (true, code, r)))
          | _ => none
        if let some l := p.link then l.hangUp reason
        s := { s with peers := s.peers.erase i,
                      ps := { s.ps with conns := s.ps.conns.erase i, byCid := p.udp.cids.foldl (·.erase ·) s.ps.byCid } }
        if let some (_, ready) := initial then ready.resolve (.error (closeMessage p.udp.conn.closeReason))
        continue
      let dest := if serving.isSome then
        some ((p.udp.addrs.find? (·.1 == p.udp.conn.peerAddr)).map (·.2) |>.getD p.udp.addr) else none
      let (p, ds) ← drain p
      if !ds.isEmpty then out := out.push (i, ds, dest)
      if let some l := p.link then
        if ← l.abort.get then aborted := aborted.push l
      s := { s with peers := s.peers.insert i p, ps := s.ps.put i p.udp }
    return (s, out, aborted)
  let earliest : Option Nat → Option Nat → Option Nat
    | some a, some b => some (min a b) | none, b => b | a, none => a
  let rec sending : IO Unit := do
    let (out, aborted, deadline, over) ← state.atomically do
      let now ← nowUs
      let s ← get
      let peers ← openStreams (s.peers.map fun _ p => expire p now) now
      let (s, out, aborted) ← collect { s with peers }
      set s
      let deadline := s.peers.fold (fun acc _ p =>
        earliest acc (earliest p.udp.conn.nextTimeout (earliest p.streamDeadline (p.unreachable.map (·.1))))) none
      return (out, aborted, deadline, s.peers.isEmpty && (serving.isNone || (← stop.get)))
    for (i, ds, dest) in out do
      if ← sendAll sock ds dest then
        let now ← nowUs
        state.atomically (modify fun s => { s with peers := s.peers.modify i (suspect · now) })
        nudge
    for l in aborted do l.done.resolve ()
    if over then return
    if (← kick.tryRecv).isNone then (idle kick deadline).block
    repeat if (← kick.tryRecv).isNone then break
    sending
  let stopped ← IO.mkRef false
  let receiving : IO Unit := do
    while !(← stopped.get) do
      try
        match ← IO.wait (← sock.native.recv 65536).result? with
        | none | some (.ok (_, none)) => pure ()
        | some (.ok (d, some addr)) =>
          state.atomically do set (← receive (← get) d addr)
          nudge
        | some (.error (.noSuchThing _ 111 _)) =>
          let now ← nowUs
          state.atomically (modify fun s => { s with peers := s.peers.map fun _ p => suspect p now })
          nudge
        | some (.error _) => nudge
      catch _ => nudge
  let receiver ← IO.asTask (prio := .dedicated) receiving
  try sending
  catch e =>
    for l in ← links.get do l.hangUp
    throw e
  finally
    stopped.set true
    while !(← IO.hasFinished receiver) do
      sock.native.cancelRecv
      IO.sleep 1

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
