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
import Std.Sync.Channel

/-! # The server end of a session

`session` runs one connection over a pair of frame functions and a process spawner, and returns
once the exit status is sent; `serve` connects it to stdin, stdout and real processes. -/

namespace Huh

/-- Sending and receiving whole frames; `recv` is `none` at end of stream. -/
structure Frames where
  send : ByteArray → IO Unit
  recv : IO (Option ByteArray)

def Frames.ofStreams (inp out : IO.FS.Stream) : Frames := ⟨writeFrame out, readFrame inp⟩

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

/-- One connection: handshake, then serve the session until the exit status is sent. -/
def session (cfg : Config) (peer : String) (frames : Frames) (spawn : Spawner)
    (onEstablished : IO Unit := pure ()) : IO Unit := do
  let est ← handshake false cfg.hostKey frames.send frames.recv
    (fun k => pure (cfg.authorized.contains k))
  onEstablished
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

/-- Serve the connection on stdin and stdout, then end the process. -/
def serve (cfg : Config) : IO Unit := do
  FFI.ignoreSigpipe
  let peer := (← IO.getEnv "REMOTE_ADDR").getD "unknown"
  let established ← IO.mkRef false
  discard <| IO.asTask (prio := .dedicated) do
    IO.sleep handshakeTimeoutMs
    unless ← established.get do
      cfg.log logWarning s!"{peer}: handshake timed out"
      IO.Process.exit 1
  try
    session cfg peer (Frames.ofStreams (← IO.getStdin) (← IO.getStdout)) (spawnReal peer)
      (established.set true)
    IO.Process.exit 0
  catch e =>
    cfg.log logWarning s!"{peer}: {e}"
    IO.Process.exit 1

end Huh.Server
