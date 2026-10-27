/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.Server
import Std.Async.Signal

/-! # The client end of a session

`session` runs one connection over a pair of frame functions and a terminal, and returns the
remote exit code; `run` connects it to a TCP server and the real terminal. -/

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

/-! ## The real terminal and network -/

def ask (question : String) : IO Bool := do
  let tty ← IO.FS.Handle.mk "/dev/tty" .readWrite
  tty.putStr question
  tty.flush
  let answer ← tty.getLine
  return answer.trimAscii.toString == "yes"

/-- Known key: accept. Different key: refuse. Unknown host: ask, and remember it hashed on yes. -/
def verifyKnownHost (knownHosts : System.FilePath) (hostId : String) (pub : ByteArray) : IO Bool := do
  match checkHost (← readTextOrEmpty knownHosts) hostId pub with
  | .known => return true
  | .changed lines =>
    let which := ", ".intercalate (lines.map toString)
    IO.eprintln s!"huh: THE HOST KEY FOR {hostId} HAS CHANGED to {fingerprint pub}; refusing."
    IO.eprintln s!"huh: if the change is expected, remove line {which} of {knownHosts}."
    return false
  | .unknown =>
    let yes ← ask s!"{hostId} is unknown, with key {fingerprint pub}.\nConnect and remember it? (yes/no) "
    if yes then
      if let some dir := knownHosts.parent then IO.FS.createDirAll dir
      let h ← IO.FS.Handle.mk knownHosts .append
      h.putStrLn (knownHostLine (← IO.getRandomBytes 32) hostId pub)
    return yes

def realTerminal : IO Terminal := do
  let winch ← Std.Async.Signal.Waiter.mk .sigwinch true
  return { readStdin := FFI.read 0 maxData.toUSize, writeStdout := FFI.write 1,
           writeStderr := FFI.write 2, winsize := FFI.ttyWinsize 0,
           resized := do let t ← winch.wait; return discard (IO.wait t) }

/-- How to reach the server: QUIC, accepting it under one of the pins, or plain TCP. -/
inductive Transport where
  | quic (pins : List ByteArray)
  | tcp

/-- Run a session with `host`, in raw mode when a PTY is requested. SIGTERM ends it early with
exit code 143, after the terminal is restored. -/
def run (cfg : Config) (transport : Transport) (host : String) (port : UInt16) : IO UInt32 := do
  FFI.ignoreSigpipe
  let term ← (← Std.Async.Signal.Waiter.mk .sigterm false).wait
  let saved ← IO.mkRef none
  let raw := if cfg.pty.isSome then do saved.set (some (← FFI.ttyRaw 0)) else pure ()
  let restore := do if let some s ← saved.get then FFI.ttyRestore 0 s
  let close ← IO.mkRef (pure () : IO Unit)
  let hangup := do try (← close.get) catch _ => pure ()
  try
    let conversation ← IO.asTask (prio := .dedicated) do
      let frames ← match transport with
        | .quic pins => do
          let l ← Quic.dial host port pins
          close.set l.close
          pure l.frames
        | .tcp => do
          let s ← Net.dial host port
          close.set s.shutdown.block
          pure (Net.frames s)
      session cfg frames (← realTerminal) raw
    let terminated := (ExceptT.run term).map fun _ => .ok (128 + signalNumber "TERM")
    let code ← IO.ofExcept (← IO.waitAny [conversation, terminated])
    restore
    hangup
    return code
  catch e =>
    restore
    hangup
    IO.eprintln s!"huh: {e}"
    return 255

end Huh.Client
