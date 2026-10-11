/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.Protocol
import Huh.Msg
import Uproar.Transport

/-! # Sealing and opening session messages

A transport splits into a sending half and a receiving half, so the two directions can be owned by
different tasks. Each half rekeys every `rekeyInterval` messages. -/

namespace Huh

open Uproar

structure Sender where
  t : TransportState
  interval : Nat := rekeyInterval
  count : Nat := 0

structure Receiver where
  t : TransportState
  interval : Nat := rekeyInterval
  count : Nat := 0

def split (t : TransportState) (interval : Nat := rekeyInterval) : Sender × Receiver :=
  ({ t := { t with recv := none }, interval }, { t := { t with send := none }, interval })

def Sender.seal (snd : Sender) (m : Msg) : Except String (ByteArray × Sender) := do
  unless decide m.WellFormed do throw "malformed message"
  let pt := m.encode
  if pt.size > maxPayload then throw "message too long"
  let (ct, t) ← (snd.t.writeMessage protocol.cipher pt).mapError reprStr
  let count := snd.count + 1
  let t := if count % snd.interval == 0 then t.rekeySend protocol.cipher else t
  return (ct, { snd with t, count })

def Receiver.open (rcv : Receiver) (ct : ByteArray) : Except String (Msg × Receiver) := do
  let (pt, t) ← (rcv.t.readMessage protocol.cipher ct).mapError reprStr
  let some m := Msg.decode pt | throw "malformed message"
  let count := rcv.count + 1
  let t := if count % rcv.interval == 0 then t.rekeyRecv protocol.cipher else t
  return (m, { rcv with t, count })

/-- The most data one `stdin`, `stdout` or `stderr` message carries. -/
def maxData : Nat := maxPayload - 1

end Huh
