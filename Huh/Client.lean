/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.Server
import Std.Async.Signal

/-! # The client end of a session

`session` runs one connection over a pair of frame functions and a terminal, and returns the
remote exit code; `run` connects it to a transport command and the real terminal. -/

namespace Huh.Client

open Uproar

/-- The local side of a session. `readStdin` returns empty at end of input. -/
structure Terminal where
  readStdin : IO ByteArray
  writeStdout : ByteArray → IO Unit
  writeStderr : ByteArray → IO Unit
  winsize : IO (UInt16 × UInt16)
  /-- Arms a wait for the next size change and returns an action that blocks until it happens. -/
  resized : IO (IO Unit)

structure Config where
  key : KeyPair
  verifyHost : ByteArray → IO Bool
  pty : Option PtyReq
  cmd : Option ByteArray

abbrev Outbox := Std.CloseableChannel.Sync Msg

def signalNumber (name : String) : UInt32 :=
  match name with
  | "HUP" => 1 | "INT" => 2 | "QUIT" => 3 | "ILL" => 4 | "ABRT" => 6 | "FPE" => 8 | "KILL" => 9
  | "SEGV" => 11 | "PIPE" => 13 | "ALRM" => 14 | "TERM" => 15 | "USR1" => 10 | "USR2" => 12
  | _ => 127

def exitCode : ExitStatus → UInt32
  | .code c => c.toUInt32
  | .signal n => 128 + signalNumber ((String.fromUTF8? n).getD "")

partial def writer (frames : Frames) (snd : Sender) (out : Outbox) : IO Unit := do
  let some m ← out.recv | return
  let (ct, snd) ← IO.ofExcept ((snd.seal m).mapError IO.userError)
  frames.send ct
  writer frames snd out

partial def pumpStdin (term : Terminal) (out : Outbox) : IO Unit := do
  let b ← try term.readStdin catch _ => pure ByteArray.empty
  if b.size == 0 then out.send .stdinEof; return
  out.send (.stdin b)
  pumpStdin term out

/-- Arms the next wait before reading the size, so a change in between is not missed. -/
partial def watchSize (term : Terminal) (out : Outbox) (last : UInt16 × UInt16) : IO Unit := do
  let next ← term.resized
  let now ← try term.winsize catch _ => pure last
  if now != last then out.send (.windowChange now.1 now.2)
  next
  watchSize term out now

partial def reader (frames : Frames) (term : Terminal) (rcv : Receiver) (phase : Phase) :
    IO UInt32 := do
  let some ct ← frames.recv | throw (IO.userError "connection closed")
  let (m, rcv) ← IO.ofExcept ((rcv.open ct).mapError IO.userError)
  let some (phase, a) := step phase m | throw (IO.userError "protocol violation")
  match a with
  | .stdout d => term.writeStdout d
  | .stderr d => term.writeStderr d
  | .exit s => return exitCode s
  reader frames term rcv phase

/-- One connection: handshake, open the session, and return the remote exit code. -/
def session (cfg : Config) (frames : Frames) (term : Terminal)
    (onEstablished : IO Unit := pure ()) : IO UInt32 := do
  let est ← handshake true cfg.key frames.send frames.recv cfg.verifyHost
  onEstablished
  let (snd, rcv) := split est.transport
  let out : Outbox ← Std.CloseableChannel.Sync.new
  out.send (.open_ cfg.pty cfg.cmd)
  discard <| IO.asTask (prio := .dedicated) (pumpStdin term out)
  if let some p := cfg.pty then
    discard <| IO.asTask (prio := .dedicated) (watchSize term out (p.rows, p.cols))
  let code ← raceFailures (reader frames term rcv .running) (writer frames snd out)
  out.close
  return code

/-! ## The real terminal and transport -/

def ask (question : String) : IO Bool := do
  let tty ← IO.FS.Handle.mk "/dev/tty" .readWrite
  tty.putStr question
  tty.flush
  let answer ← tty.getLine
  return answer.trimAscii.toString == "yes"

/-- Known key: accept. Different key: refuse. Unknown host: ask, and remember on yes. -/
def verifyKnownHost (knownHosts : System.FilePath) (hostId : String) (pub : ByteArray) : IO Bool := do
  let known := (parseKnownHosts (← readTextOrEmpty knownHosts)).filter (·.1 == hostId)
  if known.any (·.2 == pub) then return true
  if !known.isEmpty then
    IO.eprintln s!"huh: THE HOST KEY FOR {hostId} HAS CHANGED to {fingerprint pub}; refusing."
    IO.eprintln s!"huh: remove the old line from {knownHosts} if the change is expected."
    return false
  let yes ← ask s!"{hostId} is unknown, with key {fingerprint pub}.\nConnect and remember it? (yes/no) "
  if yes then
    if let some dir := knownHosts.parent then IO.FS.createDirAll dir
    let h ← IO.FS.Handle.mk knownHosts .append
    h.putStrLn (hostId ++ " " ++ publicLine pub)
  return yes

def realTerminal : IO Terminal := do
  let winch ← Std.Async.Signal.Waiter.mk .sigwinch true
  return { readStdin := FFI.read 0 maxData.toUSize, writeStdout := FFI.write 1,
           writeStderr := FFI.write 2, winsize := FFI.ttyWinsize 0,
           resized := do let t ← winch.wait; return discard (IO.wait t) }

/-- How far a connection got before it failed. -/
inductive Stage where
  | connecting | verifyingHost | authenticating | established
  deriving BEq, Repr

/-- What to tell the user when the connection to `target` fails at `stage` with error `e`.
`transportExit` is the transport's status if it has already exited. -/
def failureMessage (stage : Stage) (target transport : String) (transportExit : Option UInt32)
    (keyFp e : String) : String :=
  match stage, transportExit with
  | .connecting, some c => s!"could not connect to {target}: `{transport}` exited with status {c}"
  | .connecting, none => s!"could not connect to {target}: {e}"
  | .verifyingHost, _ => if e == "peer key rejected" then s!"not connecting to {target}"
    else s!"handshake with {target} failed: {e}"
  | .authenticating, _ =>
    s!"{target} ended the handshake after receiving our key {keyFp}; is it in the server's authorized_keys? ({e})"
  | .established, _ => s!"connection to {target} lost: {e}"

/-- Run a session with `target` over `transport`'s stdin and stdout, in raw mode when a PTY is
requested. -/
def run (cfg : Config) (target transport : String) : IO UInt32 := do
  FFI.ignoreSigpipe
  let child ← IO.Process.spawn
    { cmd := "/bin/sh", args := #["-c", transport], stdin := .piped, stdout := .piped }
  let (toNet, child) ← child.takeStdin
  let stage ← IO.mkRef Stage.connecting
  let recv := readFrame (IO.FS.Stream.ofHandle child.stdout)
  let frames : Frames := ⟨writeFrame (IO.FS.Stream.ofHandle toNet), do
    let f ← recv
    if f.isSome && (← stage.get) == .connecting then stage.set .verifyingHost
    return f⟩
  let verifyHost pub := do
    let ok ← cfg.verifyHost pub
    if ok then stage.set .authenticating
    return ok
  let saved ← IO.mkRef none
  let established := do
    stage.set .established
    if cfg.pty.isSome then saved.set (some (← FFI.ttyRaw 0))
  let restore := do if let some s ← saved.get then FFI.ttyRestore 0 s
  try
    let code ← session { cfg with verifyHost } frames (← realTerminal) established
    restore
    return code
  catch e =>
    restore
    let exit ← try child.tryWait catch _ => pure none
    IO.eprintln s!"huh: {failureMessage (← stage.get) target transport exit (fingerprint cfg.key.pub) (toString e)}"
    return 255

end Huh.Client
