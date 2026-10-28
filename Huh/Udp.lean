/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Std.Net.Addr

/-! # Blocking UDP sockets that send and receive datagrams in batches

Each call is one `sendmmsg` or `recvmmsg` in the calling thread, so a batch of datagrams costs one
system call and no wakeups of other threads. -/

namespace Huh.Udp

open Std.Net

@[extern "huh_udp_open"] opaque openRaw (v6 : Bool) (timeoutMs : UInt32) : IO UInt32
@[extern "huh_udp_bind"] opaque bindRaw (fd : UInt32) (addr : @& ByteArray) : IO Unit
@[extern "huh_udp_connect"] opaque connectRaw (fd : UInt32) (addr : @& ByteArray) : IO Unit
@[extern "huh_udp_local"] opaque localRaw (fd : UInt32) : IO ByteArray
@[extern "huh_udp_send"] opaque sendRaw (fd : UInt32) (ds : @& Array ByteArray) (dest : @& ByteArray) : IO Bool
@[extern "huh_udp_recv"] opaque recvRaw (fd : UInt32) (max : UInt32) : IO (Array (ByteArray × ByteArray))
@[extern "huh_udp_shutdown"] opaque shutdownRaw (fd : UInt32) : IO Unit
@[extern "huh_close"] opaque closeRaw (fd : UInt32) : IO Unit

/-- The IP bytes, then the port, big-endian. -/
def encodeAddr : SocketAddress → ByteArray
  | .v4 a => ⟨a.addr.octets.toArray ++ #[(a.port >>> 8).toUInt8, a.port.toUInt8]⟩
  | .v6 a => ⟨(a.addr.segments.toArray.flatMap fun (s : UInt16) => #[(s >>> 8).toUInt8, s.toUInt8]) ++
      #[(a.port >>> 8).toUInt8, a.port.toUInt8]⟩

def decodeAddr (b : ByteArray) : SocketAddress :=
  let be (i : Nat) : UInt16 := b[i]!.toUInt16 <<< 8 ||| b[i + 1]!.toUInt16
  if b.size == 18 then
    .v6 { addr := ⟨Vector.ofFn fun i => be (2 * i.val)⟩, port := be 16 }
  else
    .v4 { addr := ⟨Vector.ofFn fun i => b[i.val]!⟩, port := be 4 }

structure Socket where
  fd : UInt32

/-- A socket for addresses like `addr`; `recv` gives up after `timeoutMs`. -/
def Socket.new (addr : SocketAddress) (timeoutMs : UInt32 := 1000) : IO Socket :=
  return ⟨← openRaw (addr matches .v6 _) timeoutMs⟩

def Socket.bind (s : Socket) (a : SocketAddress) : IO Unit := bindRaw s.fd (encodeAddr a)
def Socket.connect (s : Socket) (a : SocketAddress) : IO Unit := connectRaw s.fd (encodeAddr a)
def Socket.getSockName (s : Socket) : IO SocketAddress := return decodeAddr (← localRaw s.fd)
def Socket.close (s : Socket) : IO Unit := closeRaw s.fd
/-- Wake a thread waiting in `recv`; no more datagrams are received. -/
def Socket.shutdown (s : Socket) : IO Unit := shutdownRaw s.fd

/-- Send `ds` to `dest`, or to the connected peer; whether the peer's port was reported
unreachable. -/
def Socket.send (s : Socket) (ds : Array ByteArray) (dest : Option SocketAddress) : IO Bool :=
  sendRaw s.fd ds ((dest.map encodeAddr).getD .empty)

/-- Up to `max` of the datagrams waiting, with their senders, after waiting up to the timeout for
one. -/
def Socket.recv (s : Socket) (max : UInt32) : IO (Array (ByteArray × SocketAddress)) :=
  return (← recvRaw s.fd max).map fun (d, a) => (d, decodeAddr a)

end Huh.Udp
