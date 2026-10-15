/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Uproar.Crypto

/-! # Frames: a 16-bit big-endian length, then a Noise message -/

namespace Huh

open Uproar (maxMessageLen)

/-- Up to `n` bytes from `read`, fewer only at end of stream. `read k` returns at most `k` bytes,
and empty at end of stream. -/
partial def readExactWith (read : USize → IO ByteArray) (n : Nat) (acc : ByteArray := ByteArray.empty) :
    IO ByteArray := do
  if acc.size ≥ n then return acc
  let chunk ← read (n - acc.size).toUSize
  if chunk.size == 0 then return acc
  readExactWith read n (acc ++ chunk)

/-- The next frame, or `none` at a clean end of stream. -/
def readFrameWith (read : USize → IO ByteArray) : IO (Option ByteArray) := do
  let hdr ← readExactWith read 2
  if hdr.size == 0 then return none
  if hdr.size < 2 then throw (IO.userError "truncated frame header")
  let n := hdr[0]!.toNat * 256 + hdr[1]!.toNat
  let body ← readExactWith read n
  if body.size < n then throw (IO.userError "truncated frame")
  return some body

/-- The header and body of a frame. -/
def encodeFrame (msg : ByteArray) : IO ByteArray := do
  if msg.size > maxMessageLen then throw (IO.userError "frame too long")
  return ByteArray.mk #[UInt8.ofNat (msg.size / 256), UInt8.ofNat (msg.size % 256)] ++ msg

def readFrame (s : IO.FS.Stream) : IO (Option ByteArray) := readFrameWith s.read

def writeFrame (s : IO.FS.Stream) (msg : ByteArray) : IO Unit := do
  s.write (← encodeFrame msg)
  s.flush

/-- Sending and receiving whole frames; `recv` is `none` at end of stream. -/
structure Frames where
  send : ByteArray → IO Unit
  recv : IO (Option ByteArray)

def Frames.ofStreams (inp out : IO.FS.Stream) : Frames := ⟨writeFrame out, readFrame inp⟩

end Huh
