/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.Msg

/-! # Which messages each side accepts, and when -/

namespace Huh

namespace Server

inductive Phase where
  | awaitOpen
  | running (pty : Bool) (stdinOpen : Bool)

/-- What a client message asks the server to do. -/
inductive Action where
  | spawn (pty : Option PtyReq) (cmd : Option ByteArray)
  | stdin (data : ByteArray)
  | closeStdin
  | resize (rows cols : UInt16)
  | signal (name : ByteArray)

/-- `none` is a protocol violation, which ends the connection. -/
def step : Phase → Msg → Option (Phase × Action)
  | .awaitOpen, .open_ pty cmd => some (.running pty.isSome true, .spawn pty cmd)
  | .running p true, .stdin d => some (.running p true, .stdin d)
  | .running p true, .stdinEof => some (.running p false, .closeStdin)
  | .running true s, .windowChange r c => some (.running true s, .resize r c)
  | .running p s, .signal n => some (.running p s, .signal n)
  | _, _ => none

theorem step_awaitOpen {m : Msg} {r : Phase × Action} (h : step .awaitOpen m = some r) :
    ∃ pty cmd, m = .open_ pty cmd := by
  cases m <;> simp [step] at h ⊢

theorem step_running_ne_open {p s : Bool} {pty cmd} :
    step (.running p s) (.open_ pty cmd) = none := by cases p <;> cases s <;> rfl

theorem step_stdin_closed {p : Bool} {d : ByteArray} : step (.running p false) (.stdin d) = none := by
  cases p <;> rfl

end Server

namespace Client

inductive Phase where
  | running
  | exited

inductive Action where
  | stdout (data : ByteArray)
  | stderr (data : ByteArray)
  | exit (status : ExitStatus)

def step : Phase → Msg → Option (Phase × Action)
  | .running, .stdout d => some (.running, .stdout d)
  | .running, .stderr d => some (.running, .stderr d)
  | .running, .exit s => some (.exited, .exit s)
  | _, _ => none

theorem step_exited {m : Msg} : step .exited m = none := by cases m <;> rfl

end Client

end Huh
