/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

/-! # Session messages

A message is a tag byte and big-endian fields. Byte strings carry a 16-bit length, except the
data of `stdin`, `stdout` and `stderr`, which runs to the end of the message. -/

namespace Huh

structure PtyReq where
  term : ByteArray
  rows : UInt16
  cols : UInt16

inductive ExitStatus where
  | code (c : UInt8)
  | signal (name : ByteArray)

inductive Msg where
  | open_ (pty : Option PtyReq) (cmd : Option ByteArray)
  | stdin (data : ByteArray)
  | stdinEof
  | windowChange (rows cols : UInt16)
  | signal (name : ByteArray)
  | stdout (data : ByteArray)
  | stderr (data : ByteArray)
  | exit (status : ExitStatus)

/-- A decoder consumes a prefix of its input and returns the rest. -/
abbrev Dec (α : Type) := ByteArray → Option (α × ByteArray)

namespace Dec

instance : Monad Dec where
  pure a b := some (a, b)
  bind m f b := (m b).bind fun (a, rest) => f a rest

def u8 : Dec UInt8 := fun b =>
  if h : 0 < b.size then some (b[0], b.extract 1 b.size) else none

def u16 : Dec UInt16 := do
  let hi ← u8
  let lo ← u8
  pure (UInt16.ofNat (hi.toNat * 256 + lo.toNat))

def take (n : Nat) : Dec ByteArray := fun b =>
  if n ≤ b.size then some (b.extract 0 n, b.extract n b.size) else none

def bytes16 : Dec ByteArray := do take (← u16).toNat

def rest : Dec ByteArray := fun b => some (b, ByteArray.empty)

def eof : Dec Unit := fun b => if b.size = 0 then some ((), b) else none

def flag : Dec Bool := do
  match ← u8 with
  | 0 => pure false
  | 1 => pure true
  | _ => fun _ => none

def opt {α} (d : Dec α) : Dec (Option α) := do
  if ← flag then some <$> d else pure none

end Dec

namespace Enc

def u8 (v : UInt8) : ByteArray := ⟨#[v]⟩

def u16 (v : UInt16) : ByteArray :=
  ⟨#[UInt8.ofNat (v.toNat / 256), UInt8.ofNat (v.toNat % 256)]⟩

def bytes16 (b : ByteArray) : ByteArray := u16 (UInt16.ofNat b.size) ++ b

def flag (b : Bool) : ByteArray := u8 (if b then 1 else 0)

def opt {α} (e : α → ByteArray) : Option α → ByteArray
  | none => flag false
  | some a => flag true ++ e a

end Enc

def PtyReq.encode (p : PtyReq) : ByteArray := Enc.bytes16 p.term ++ Enc.u16 p.rows ++ Enc.u16 p.cols

def PtyReq.decode : Dec PtyReq := do
  let term ← Dec.bytes16
  let rows ← Dec.u16
  let cols ← Dec.u16
  pure { term, rows, cols }

namespace Msg

def encode : Msg → ByteArray
  | open_ pty cmd => Enc.u8 1 ++ Enc.opt PtyReq.encode pty ++ Enc.opt Enc.bytes16 cmd
  | stdin d => Enc.u8 2 ++ d
  | stdinEof => Enc.u8 3
  | windowChange r c => Enc.u8 4 ++ Enc.u16 r ++ Enc.u16 c
  | signal n => Enc.u8 5 ++ Enc.bytes16 n
  | stdout d => Enc.u8 6 ++ d
  | stderr d => Enc.u8 7 ++ d
  | exit (.code c) => Enc.u8 8 ++ Enc.u8 0 ++ Enc.u8 c
  | exit (.signal n) => Enc.u8 8 ++ Enc.u8 1 ++ Enc.bytes16 n

def exitBody : UInt8 → Dec Msg
  | 0 => do let c ← Dec.u8; Dec.eof; pure (exit (.code c))
  | 1 => do let n ← Dec.bytes16; Dec.eof; pure (exit (.signal n))
  | _ => fun _ => none

def body : UInt8 → Dec Msg
  | 1 => do
    let pty ← Dec.opt PtyReq.decode
    let cmd ← Dec.opt Dec.bytes16
    Dec.eof
    pure (open_ pty cmd)
  | 2 => do pure (stdin (← Dec.rest))
  | 3 => do Dec.eof; pure stdinEof
  | 4 => do
    let r ← Dec.u16
    let c ← Dec.u16
    Dec.eof
    pure (windowChange r c)
  | 5 => do let n ← Dec.bytes16; Dec.eof; pure (signal n)
  | 6 => do pure (stdout (← Dec.rest))
  | 7 => do pure (stderr (← Dec.rest))
  | 8 => do exitBody (← Dec.u8)
  | _ => fun _ => none

def decoder : Dec Msg := do body (← Dec.u8)

def decode (b : ByteArray) : Option Msg := (decoder b).map (·.1)

/-- Every length-prefixed field fits its 16-bit length. -/
def WellFormed : Msg → Prop
  | open_ pty cmd =>
    (∀ p ∈ pty, p.term.size < 2 ^ 16) ∧ (∀ c ∈ cmd, c.size < 2 ^ 16)
  | signal n => n.size < 2 ^ 16
  | exit (.signal n) => n.size < 2 ^ 16
  | _ => True

instance (m : Msg) : Decidable m.WellFormed := by
  cases m <;> unfold WellFormed <;> try infer_instance
  case exit s => cases s <;> infer_instance

end Msg

end Huh
