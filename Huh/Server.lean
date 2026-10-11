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

/-! # One connection, on stdin and stdout -/

namespace Huh.Server

open Uproar

structure Config where
  hostKey : KeyPair
  authorized : List ByteArray
  logStderr : Bool := false

inductive Child where
  | pty (pid master : UInt32)
  | pipes (pid stdin stdout stderr : UInt32)

def Child.pid : Child → UInt32
  | .pty pid _ | .pipes pid .. => pid

abbrev Outbox := Std.CloseableChannel.Sync Msg

def die {α} (cfg : Config) (msg : String) : IO α := do
  log cfg.logStderr logWarning msg
  IO.Process.exit 1

def text (b : ByteArray) : Option String := do
  guard (!b.data.contains 0)
  String.fromUTF8? b

/-- `(user, home, shell)`, from the environment systemd sets for `User=`, else the passwd entry. -/
def account : IO (String × String × String) := do
  match ← IO.getEnv "USER", ← IO.getEnv "HOME", ← IO.getEnv "SHELL" with
  | some u, some h, some s => pure (u, h, s)
  | _, _, _ => FFI.getpw

def spawn (peer : String) (pty : Option PtyReq) (cmd : Option ByteArray) : IO Child := do
  let (user, home, shell) ← account
  let name := (System.FilePath.mk shell).fileName.getD shell
  let argv ← match cmd with
    | none => pure #["-" ++ name]
    | some c => do
      let some c := text c | throw (IO.userError "command is not text")
      pure #[name, "-c", c]
  let mut envp := #[s!"HOME={home}", s!"USER={user}", s!"LOGNAME={user}", s!"SHELL={shell}",
    "PATH=/usr/local/bin:/usr/bin:/bin", s!"HUH_CLIENT={peer}"]
  match pty with
  | some p =>
    let term := (text p.term).getD "dumb"
    envp := envp.push s!"TERM={term}"
    let (pid, master) ← FFI.spawnPty shell argv envp home p.rows p.cols
    return .pty pid master
  | none =>
    let (pid, i, o, e) ← FFI.spawnPipes shell argv envp home
    return .pipes pid i o e

/-- Forward a child's output until end of stream. -/
partial def pump (fd : UInt32) (wrap : ByteArray → Msg) (out : Outbox) : IO Unit := do
  let b ← FFI.read fd maxData.toUSize
  if b.size == 0 then return
  out.send (wrap b)
  pump fd wrap out

/-- Seal and send everything in the outbox; the process ends after `exit` is sent. -/
partial def writer (cfg : Config) (net : IO.FS.Stream) (snd : Sender) (out : Outbox) : IO Unit := do
  let some m ← out.recv | IO.Process.exit 0
  let (ct, snd) ← match snd.seal m with
    | .ok r => pure r
    | .error e => die cfg s!"seal: {e}"
  try writeFrame net ct catch _ => IO.Process.exit 1
  if let .exit _ := m then IO.Process.exit 0
  writer cfg net snd out

def exitStatus (code : UInt32) (sig : String) : ExitStatus :=
  if sig.isEmpty then .code code.toUInt8 else .signal sig.toUTF8

/-- Once the child has exited and its output is drained, report how it exited. -/
def finish (child : Child) (out : Outbox) : IO Unit := do
  let readers ← match child with
    | .pty _ master => pure #[← IO.asTask (prio := .dedicated) (pump master .stdout out)]
    | .pipes _ _ o e => pure #[← IO.asTask (prio := .dedicated) (pump o .stdout out),
                                ← IO.asTask (prio := .dedicated) (pump e .stderr out)]
  let (code, sig) ← FFI.wait child.pid
  for t in readers do let _ ← IO.wait t
  out.send (.exit (exitStatus code sig))

def act (child : Child) : Action → IO Unit
  | .stdin d => match child with
    | .pty _ m | .pipes _ m .. => FFI.write m d
  | .closeStdin => match child with
    | .pty _ m => FFI.write m ⟨#[4]⟩
    | .pipes _ i .. => FFI.close i
  | .resize r c => match child with
    | .pty _ m => FFI.ptyResize m r c
    | .pipes .. => pure ()
  | .signal n => do
    match text n with
    | some n => discard <| FFI.killGroup child.pid n
    | none => pure ()
  | .spawn .. => pure ()

def hangup {α} (cfg : Config) (child : Option Child) (why : String) : IO α := do
  if let some c := child then discard <| FFI.killGroup c.pid "HUP"
  die cfg why

partial def reader (cfg : Config) (net : IO.FS.Stream) (rcv : Receiver) (phase : Phase)
    (child : Option Child) (spawnChild : Option PtyReq → Option ByteArray → IO Child)
    (out : Outbox) : IO Unit := do
  let frame ← try readFrame net catch e => hangup cfg child s!"read: {e}"
  let some ct := frame | hangup cfg child "client closed the connection"
  let (m, rcv) ← match rcv.open ct with
    | .ok r => pure r
    | .error e => hangup cfg child s!"open: {e}"
  let some (phase, a) := step phase m | hangup cfg child "protocol violation"
  let child ← match a, child with
    | .spawn pty cmd, none => do
      let c ← spawnChild pty cmd
      discard <| IO.asTask (prio := .dedicated) (finish c out)
      pure c
    | a, some c => do
      try act c a catch _ => pure ()
      pure c
    | _, none => hangup cfg none "protocol violation"
  reader cfg net rcv phase (some child) spawnChild out

def serve (cfg : Config) : IO Unit := do
  FFI.ignoreSigpipe
  let net ← IO.getStdin
  let netOut ← IO.getStdout
  let peer := (← IO.getEnv "REMOTE_ADDR").getD "unknown"
  let established ← IO.mkRef false
  discard <| IO.asTask (prio := .dedicated) do
    IO.sleep handshakeTimeoutMs
    unless ← established.get do die cfg s!"{peer}: handshake timed out"
  let est ← try
      handshake false cfg.hostKey (writeFrame netOut) (readFrame net)
        (fun k => pure (cfg.authorized.contains k))
    catch e => die cfg s!"{peer}: handshake failed: {e}"
  established.set true
  log cfg.logStderr logInfo s!"{peer}: accepted {fingerprint est.remoteStatic}"
  let (snd, rcv) := split est.transport
  let out : Outbox ← Std.CloseableChannel.Sync.new
  discard <| IO.asTask (prio := .dedicated) (writer cfg netOut snd out)
  let spawnChild (pty : Option PtyReq) (cmd : Option ByteArray) : IO Child := do
    try spawn peer pty cmd
    catch e => die cfg s!"{peer}: spawn failed: {e}"
  reader cfg net rcv .awaitOpen none spawnChild out

end Huh.Server
