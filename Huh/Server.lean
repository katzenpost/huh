/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.Frame
import Huh.Handshake
import Huh.Secure
import Huh.Session
import Huh.Keys
import Huh.Log
import Huh.Net
import Huh.Quic
import Std.Sync.Channel
import Std.Async.Signal
import Std.Data.HashMap

/-! # The server end of a session

`session` runs one connection over a pair of frame functions and a process spawner, and returns
once the exit status is sent; `listen` accepts TCP connections and serves each with real
processes. -/

namespace Huh

/-- Runs `a` and `b` concurrently and returns `a`'s result once it is done, failing as soon as
either fails. -/
def raceFailures {α} (a : IO α) (b : IO Unit) : IO α := do
  let ta ← IO.asTask (prio := .dedicated) a
  let tb ← IO.asTask (prio := .dedicated) b
  let first ← IO.waitAny [ta.map (·.map some), tb.map (·.map fun _ => none)]
  match first with
  | .error e => throw e
  | .ok (some a) => pure a
  | .ok none => IO.ofExcept (← IO.wait ta)

end Huh

namespace Huh.Server

open Uproar

/-- A running child as the session sees it. Reads return empty at end of stream. -/
structure Proc where
  pty : Bool
  write : ByteArray → IO Unit
  closeStdin : IO Unit
  resize : UInt16 → UInt16 → IO Unit
  signal : String → IO Unit
  readStdout : IO ByteArray
  readStderr : Option (IO ByteArray)
  wait : IO ExitStatus

abbrev Spawner := Option PtyReq → Option ByteArray → IO Proc

structure Config where
  hostKey : KeyPair
  /-- The host key's seed, from which the QUIC identity is derived. -/
  hostSeed : ByteArray := .empty
  authorized : List ByteArray
  log : UInt32 → String → IO Unit

abbrev Outbox := Std.CloseableChannel.Sync Msg

/-- Forward a child's output until end of stream. -/
partial def pump (read : IO ByteArray) (wrap : ByteArray → Msg) (out : Outbox) : IO Unit := do
  let b ← read
  if b.size == 0 then return
  out.send (wrap b)
  pump read wrap out

/-- Seal and send messages until `exit` has been sent. -/
partial def writer (frames : Frames) (snd : Sender) (out : Outbox) : IO Unit := do
  let some m ← out.recv | throw (IO.userError "outbox closed before exit")
  let (ct, snd) ← IO.ofExcept ((snd.seal m).mapError IO.userError)
  frames.send ct
  if let .exit _ := m then return
  writer frames snd out

/-- Once the child has exited and its output is drained, report how it exited. -/
def finish (p : Proc) (out : Outbox) : IO Unit := do
  let mut readers := #[← IO.asTask (prio := .dedicated) (pump p.readStdout .stdout out)]
  if let some e := p.readStderr then
    readers := readers.push (← IO.asTask (prio := .dedicated) (pump e .stderr out))
  let status ← p.wait
  for t in readers do let _ ← IO.wait t
  out.send (.exit status)

def act (p : Proc) : Action → IO Unit
  | .stdin d => p.write d
  | .closeStdin => p.closeStdin
  | .resize r c => p.resize r c
  | .signal n => match String.fromUTF8? n with
    | some n => p.signal n
    | none => pure ()
  | .spawn .. => pure ()

/-- Handle client messages until the connection ends. Ending is an error unless `exit` has gone
out, in which case the client hanging up is expected. -/
partial def reader (frames : Frames) (rcv : Receiver) (phase : Phase) (proc : Option Proc)
    (spawn : Spawner) (out : Outbox) : IO Unit := do
  let hangup {α} (why : String) : IO α := do
    if let some p := proc then try p.signal "HUP" catch _ => pure ()
    throw (IO.userError why)
  let some ct ← frames.recv | hangup "client closed the connection"
  let (m, rcv) ← match rcv.open ct with
    | .ok r => pure r
    | .error e => hangup s!"open: {e}"
  let some (phase, a) := step phase m | hangup "protocol violation"
  let proc ← match a, proc with
    | .spawn pty cmd, none => do
      let p ← spawn pty cmd
      discard <| IO.asTask (prio := .dedicated) (finish p out)
      pure p
    | a, some p => do
      try act p a catch _ => pure ()
      pure p
    | _, none => hangup "protocol violation"
  reader frames rcv phase (some proc) spawn out

/-- One connection: handshake, then serve the session until the exit status is sent. The
handshake reads with `handshakeRecv`, which can give up early. -/
def session (cfg : Config) (peer : String) (frames : Frames) (spawn : Spawner)
    (handshakeRecv : IO (Option ByteArray) := frames.recv) : IO Unit := do
  let est ← handshake false cfg.hostKey frames.send handshakeRecv
    (fun k => pure (cfg.authorized.contains k))
  cfg.log logInfo s!"{peer}: accepted {fingerprint est.remoteStatic}"
  let (snd, rcv) := split est.transport
  let out : Outbox ← Std.CloseableChannel.Sync.new
  raceFailures (writer frames snd out) (reader frames rcv .awaitOpen none spawn out)

/-! ## Real processes -/

def text (b : ByteArray) : Option String := do
  guard (!b.data.contains 0)
  String.fromUTF8? b

/-- `(user, home, shell)`, from the environment systemd sets for `User=`, else the passwd entry. -/
def account : IO (String × String × String) := do
  match ← IO.getEnv "USER", ← IO.getEnv "HOME", ← IO.getEnv "SHELL" with
  | some u, some h, some s => pure (u, h, s)
  | _, _, _ => FFI.getpw

def exitStatus (code : UInt32) (sig : String) : ExitStatus :=
  if sig.isEmpty then .code code.toUInt8 else .signal sig.toUTF8

def spawnReal (peer : String) : Spawner := fun pty cmd => do
  let (user, home, shell) ← account
  let name := (System.FilePath.mk shell).fileName.getD shell
  let argv ← match cmd with
    | none => pure #["-" ++ name]
    | some c => do
      let some c := text c | throw (IO.userError "command is not text")
      pure #[name, "-c", c]
  let envp := #[s!"HOME={home}", s!"USER={user}", s!"LOGNAME={user}", s!"SHELL={shell}",
    "PATH=/usr/local/bin:/usr/bin:/bin", s!"HUH_CLIENT={peer}"]
  let signal (pid : UInt32) (n : String) : IO Unit := discard <| FFI.killGroup pid n
  let wait (pid : UInt32) : IO ExitStatus := do let (c, s) ← FFI.wait pid; pure (exitStatus c s)
  match pty with
  | some p =>
    let term := (text p.term).getD "dumb"
    let (pid, m) ← FFI.spawnPty shell argv (envp.push s!"TERM={term}") home p.rows p.cols
    return { pty := true, write := FFI.write m, closeStdin := FFI.write m ⟨#[4]⟩,
             resize := FFI.ptyResize m, signal := signal pid,
             readStdout := FFI.read m maxData.toUSize, readStderr := none, wait := wait pid }
  | none =>
    let (pid, i, o, e) ← FFI.spawnPipes shell argv envp home
    return { pty := false, write := FFI.write i, closeStdin := FFI.close i,
             resize := fun _ _ => pure (), signal := signal pid,
             readStdout := FFI.read o maxData.toUSize,
             readStderr := some (FFI.read e maxData.toUSize), wait := wait pid }

/-! ## Listening -/

open Std.Async Std.Net

/-- Serve one accepted connection until its session ends. Failures are logged, never thrown. -/
def connection (cfg : Config) (c : Net.Socket) (spawn : String → Spawner := spawnReal)
    (timeoutMs : Nat := handshakeTimeoutMs.toNat) : IO Unit := do
  let peer ← try pure (toString (← c.getPeerName)) catch _ => pure "unknown"
  try
    let deadline ← Net.deadline timeoutMs
    session cfg peer (Net.frames c) (spawn peer) (readFrameWith (Net.recvChunkBefore c deadline))
  catch e => cfg.log logWarning s!"{peer}: {e}"
  try c.shutdown.block catch _ => pure ()

/-- How long a finished QUIC session waits for the client to receive the rest of it. Unlike
TCP's, a QUIC connection's unsent data is lost when the process exits. -/
def quicDrainMs : Nat := 5000

/-- Serve one QUIC session until it ends and the client has all of it, or `quicDrainMs` has
passed. Failures are logged, never thrown. -/
def quicConnection (cfg : Config) (l : Quic.Link) (spawn : String → Spawner := spawnReal)
    (timeoutMs : Nat := handshakeTimeoutMs.toNat) : IO Unit := do
  try
    let deadline ← Net.deadline timeoutMs
    session cfg l.peer l.frames (spawn l.peer) (readFrameWith (l.readBefore deadline))
    l.finish
    l.awaitDone quicDrainMs
  catch e =>
    cfg.log logWarning s!"{l.peer}: {e}"
    l.close

def bind (addr : SocketAddress) : IO TCP.Socket.Server := do
  let srv ← TCP.Socket.Server.mk
  srv.bind addr
  srv.listen 128
  srv.noDelay
  srv.keepAlive true 60
  return srv

/-- How long a shutdown waits for hung-up sessions to report their exit before killing them. -/
def shutdownGraceMs : Nat := 5000

/-- One served connection: how to signal its child, once there is one, and whether it is over. -/
structure Conn where
  id : Nat
  signal : IO.Ref (Option (String → IO Unit))
  done : IO.Promise Unit

/-- The connections being served, so that a shutdown can hang them up and wait for them. -/
structure Live where
  stopping : IO.Ref Bool
  next : IO.Ref Nat
  conns : IO.Ref (Std.HashMap Nat Conn)

def Live.new : IO Live := return ⟨← IO.mkRef false, ← IO.mkRef 0, ← IO.mkRef {}⟩

def Live.add (live : Live) : IO Conn := do
  let id ← live.next.modifyGet fun n => (n, n + 1)
  let c : Conn := ⟨id, ← IO.mkRef none, ← IO.Promise.new⟩
  live.conns.modify (·.insert id c)
  return c

def Live.remove (live : Live) (c : Conn) : IO Unit := do
  live.conns.modify (·.erase c.id)
  c.done.resolve ()

/-- Remember how to signal what `spawn` starts. A child started after a shutdown began is hung
up at once; the shutdown may have looked at this connection before the child existed. -/
def Live.track (live : Live) (c : Conn) (spawn : Spawner) : Spawner := fun pty cmd => do
  let p ← spawn pty cmd
  c.signal.set (some p.signal)
  if ← live.stopping.get then try p.signal "HUP" catch _ => pure ()
  return p

def Live.signalAll (live : Live) (name : String) : IO Unit := do
  for (_, c) in ← live.conns.get do
    if let some signal ← c.signal.get then try signal name catch _ => pure ()

/-- Stop accepting, hang up every child, and wait up to `graceMs` for the sessions to send their
exit status. Children still running after that are killed. -/
def Live.shutdown (live : Live) (graceMs : Nat := shutdownGraceMs) : IO Unit := do
  live.stopping.set true
  live.signalAll "HUP"
  let pending := (← live.conns.get).toList.map fun (_, c) => c.done.result!
  let all ← IO.mapTasks (fun _ => pure ()) pending
  let timer ← IO.asTask (IO.sleep graceMs.toUInt32)
  discard <| IO.waitAny [all.map fun _ => (), timer.map fun _ => ()]
  live.signalAll "KILL"

/-- Accept connections until a shutdown begins, serving each on its own task. -/
partial def acceptLoop (live : Live) (cfg : Config) (srv : TCP.Socket.Server)
    (spawn : String → Spawner := spawnReal) (timeoutMs : Nat := handshakeTimeoutMs.toNat) :
    IO Unit := do
  try
    let c ← srv.accept.block
    if ← live.stopping.get then
      try c.shutdown.block catch _ => pure ()
      return
    let conn ← live.add
    discard <| IO.asTask (prio := .dedicated) do
      connection cfg c (fun peer => live.track conn (spawn peer)) timeoutMs
      live.remove conn
  catch e =>
    cfg.log logWarning s!"accept: {e}"
    IO.sleep 100
  acceptLoop live cfg srv spawn timeoutMs

/-- Serve QUIC sessions on `addr` until `Quic.Server.stop`. -/
def listenQuic (live : Live) (cfg : Config) (addr : SocketAddress)
    (spawn : String → Spawner := spawnReal) (timeoutMs : Nat := handshakeTimeoutMs.toNat) :
    IO Quic.Server :=
  Quic.listen addr cfg.hostSeed (streamTimeoutMs := timeoutMs) fun l => do
    if ← live.stopping.get then l.close; return
    let conn ← live.add
    quicConnection cfg l (fun peer => live.track conn (spawn peer)) timeoutMs
    live.remove conn

/-- Listen on every QUIC (UDP) and TCP address and serve connections until SIGTERM or SIGINT,
then shut down. Accept loops are still blocked in `accept` on return, so the caller should end
the process. -/
def listen (cfg : Config) (quicAddrs tcpAddrs : Array SocketAddress) : IO Unit := do
  FFI.ignoreSigpipe
  let term ← (← Signal.Waiter.mk .sigterm false).wait
  let int ← (← Signal.Waiter.mk .sigint false).wait
  let live ← Live.new
  -- bind everything first, so a bad address fails before any connection is served
  let srvs ← tcpAddrs.mapM fun a => do
    try pure (a, ← bind a) catch e => throw (IO.userError s!"listen on tcp {a}: {e}")
  let quics ← quicAddrs.mapM fun a => do
    try listenQuic live cfg a catch e => throw (IO.userError s!"listen on quic {a}: {e}")
  for q in quics do
    cfg.log logInfo s!"listening on quic {q.addr}"
  for (a, srv) in srvs do
    cfg.log logInfo s!"listening on tcp {a}"
    discard <| IO.asTask (prio := .dedicated) (acceptLoop live cfg srv)
  discard <| IO.waitAny [term, int]
  cfg.log logInfo "shutting down"
  for q in quics do q.stop
  live.shutdown

end Huh.Server
