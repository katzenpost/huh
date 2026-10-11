/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.Protocol
import Uproar.Transport
import Uproar.IO

/-! # Running pqXX over a pair of frame functions -/

namespace Huh

open Uproar

def liftNoise {α} (x : Result α) : IO α :=
  IO.ofExcept (x.mapError fun e => IO.userError s!"noise: {reprStr e}")

structure Established where
  transport : TransportState
  remoteStatic : ByteArray

/-- `verify` sees the peer's static key as soon as it arrives, before this party sends anything
more: after message 2 for the client and message 3 for the server. -/
def handshake (initiator : Bool) (s : KeyPair) (send : ByteArray → IO Unit)
    (recv : IO (Option ByteArray)) (verify : ByteArray → IO Bool) : IO Established := do
  let mut st ← liftNoise (HandshakeState.initialize protocol
    { initiator, prologue, s := some s, seeds := ← randomSeeds })
  while !HandshakeState.isFinished protocol st do
    if protocol.pattern.initiatorSends st.msgIndex == initiator then
      let (msg, st') ← liftNoise (HandshakeState.writeMessage protocol st ByteArray.empty)
      send msg
      st := st'
    else
      let some msg ← recv | throw (IO.userError "connection closed during handshake")
      let known := st.rs.isSome
      let (payload, st') ← liftNoise (HandshakeState.readMessage protocol st msg)
      if payload.size != 0 then throw (IO.userError "unexpected handshake payload")
      st := st'
      if let (false, some rs) := (known, st.rs) then
        unless ← verify rs do throw (IO.userError "peer key rejected")
  let some rs := st.rs | throw (IO.userError "handshake ended without a peer key")
  return ⟨← liftNoise (TransportState.ofHandshake protocol st), rs⟩

end Huh
