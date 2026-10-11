/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Uproar.Crypto

/-! # Frames: a 16-bit big-endian length, then a Noise message -/

namespace Huh

open Uproar (maxMessageLen)

/-- Up to `n` bytes, fewer only at end of stream. -/
partial def readExact (s : IO.FS.Stream) (n : Nat) (acc : ByteArray := ByteArray.empty) :
    IO ByteArray := do
  if acc.size ≥ n then return acc
  let chunk ← s.read (n - acc.size).toUSize
  if chunk.size == 0 then return acc
  readExact s n (acc ++ chunk)

/-- The next frame, or `none` at a clean end of stream. -/
def readFrame (s : IO.FS.Stream) : IO (Option ByteArray) := do
  let hdr ← readExact s 2
  if hdr.size == 0 then return none
  if hdr.size < 2 then throw (IO.userError "truncated frame header")
  let n := hdr[0]!.toNat * 256 + hdr[1]!.toNat
  let body ← readExact s n
  if body.size < n then throw (IO.userError "truncated frame")
  return some body

def writeFrame (s : IO.FS.Stream) (msg : ByteArray) : IO Unit := do
  if msg.size > maxMessageLen then throw (IO.userError "frame too long")
  s.write (ByteArray.mk #[UInt8.ofNat (msg.size / 256), UInt8.ofNat (msg.size % 256)] ++ msg)
  s.flush

end Huh
