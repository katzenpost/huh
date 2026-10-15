/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.Frame
import Std.Async.TCP
import Std.Async.DNS
import Std.Async.Timer
import Std.Sync.CancellationToken

/-! # Frames over TCP, listen addresses and dialing -/

namespace Huh.Net

open Std Std.Async Std.Net

abbrev Socket := TCP.Socket.Client

/-- Up to `n` bytes; empty at end of stream. -/
def recvChunk (c : Socket) (n : USize) : IO ByteArray := do
  return (← (c.recv? n.toUInt64).block).getD .empty

/-- Up to `n` bytes, or an error once `deadline` is cancelled. -/
def recvChunkBefore (c : Socket) (deadline : CancellationToken) (n : USize) : IO ByteArray :=
  (Selectable.one #[
    .case (c.recvSelector n.toUInt64) fun r => pure (r.getD .empty),
    .case deadline.selector fun _ => throw (IO.userError "handshake timed out")]).block

def send (c : Socket) (frame : ByteArray) : IO Unit := do
  (c.send (← encodeFrame frame)).block

def frames (c : Socket) : Frames := ⟨send c, readFrameWith (recvChunk c)⟩

/-- A token that is cancelled `ms` milliseconds from now. -/
def deadline (ms : Nat) : IO CancellationToken := do
  let token ← CancellationToken.new
  discard <| (do Async.sleep (.ofNat ms); token.cancel : Async Unit).toIO
  return token

def parsePort (s : String) : Option UInt16 := do
  let n ← s.toNat?
  guard (n < 65536)
  return n.toUInt16

/-- `1.2.3.4:2222` or `[::1]:2222`. -/
def parseAddr (s : String) : Option SocketAddress := do
  let parts := s.splitOn ":"
  let port ← parsePort (← parts.getLast?)
  let host := ":".intercalate parts.dropLast
  if host.startsWith "[" && host.endsWith "]" then
    let a ← IPv6Addr.ofString ((host.drop 1).dropEnd 1).toString
    return .v6 ⟨a, port⟩
  let a ← IPv4Addr.ofString host
  return .v4 ⟨a, port⟩

def withPort (a : IPAddr) (port : UInt16) : SocketAddress :=
  match a with
  | .v4 a => .v4 ⟨a, port⟩
  | .v6 a => .v6 ⟨a, port⟩

/-- Connect to the first address of `host` that accepts. -/
def dial (host : String) (port : UInt16) : IO Socket := do
  let addrs ← (DNS.getAddrInfo host (toString port)).block
  let mut err := IO.userError s!"{host}: no addresses"
  for a in addrs do
    let c ← TCP.Socket.Client.mk
    try
      (c.connect (withPort a port)).block
      c.noDelay
      return c
    catch e => err := IO.userError s!"{withPort a port}: {e}"
  throw err

end Huh.Net
