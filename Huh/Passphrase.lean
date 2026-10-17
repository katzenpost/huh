/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.FFI
import Std.Async.Signal

/-! # Reading a passphrase from the terminal -/

namespace Huh

/-- One line from `fd`, keeping at most 1024 bytes of it; `none` at end of input before any. -/
partial def readTtyLine (fd : UInt32) (acc : ByteArray := .empty) : IO (Option ByteArray) := do
  let b ← FFI.read fd 1
  if b.isEmpty then return if acc.isEmpty then none else some acc
  if b[0]! == 10 || b[0]! == 13 then return some acc
  readTtyLine fd (if acc.size < 1024 then acc ++ b else acc)

/-- Print `prompt` on `/dev/tty` and read a line from it with echo off, as readpassphrase(3)
does. A signal that arrives meanwhile restores the terminal and exits with `128 + signal`, so
Ctrl-C never leaves echo off. -/
def readPassphrase (prompt : String) : IO String := do
  let waiters ← [.sigint, .sigterm, .sighup, .sigquit].mapM (Std.Async.Signal.Waiter.mk · false)
  let signals ← waiters.mapM fun w => return (ExceptT.run (← w.wait)).map (·.map Sum.inl)
  let (fd, saved) ← try FFI.ttyOpenNoEcho
    catch _ => waiters.forM (·.stop); throw (IO.userError "no terminal to read a passphrase from")
  FFI.write fd prompt.toUTF8
  let line ← IO.asTask (prio := .dedicated) (readTtyLine fd)
  let r ← IO.waitAny (line.map (·.map Sum.inr) :: signals)
  waiters.forM (·.stop)
  FFI.ttyRestore fd saved
  FFI.write fd "\n".toUTF8
  FFI.close fd
  match ← IO.ofExcept r with
  | .inl (sig : Int) => IO.Process.exit (128 + sig.toNat.toUInt8)
  | .inr none => throw (IO.userError "no passphrase read")
  | .inr (some bytes) =>
    match String.fromUTF8? bytes with
    | some s => return s
    | none => throw (IO.userError "the passphrase is not UTF-8")

end Huh
