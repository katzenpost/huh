import Huh
import Tests.Msg
import Tests.Session
import Uproar.Session
import Uproar.IO

open Uproar Huh

def handshake : IO Unit := do
  let lift {α} (x : Result α) : IO α := IO.ofExcept (x.mapError reprStr)
  let iS ← lift (kem.ofSeed ((← randomSeeds) 0))
  let rS ← lift (kem.ofSeed ((← randomSeeds) 0))
  let ini ← lift (HandshakeState.initialize protocol
    { initiator := true, prologue, s := some iS, seeds := ← randomSeeds })
  let res ← lift (HandshakeState.initialize protocol
    { initiator := false, prologue, s := some rS, seeds := ← randomSeeds })
  let msgs := ["", "", "", "", "to responder", "to initiator"].map String.toUTF8
  let (_, ini, res) ← lift (exchange protocol (.hs ini) (.hs res) msgs)
  if ini.handshakeHash != res.handshakeHash then throw (IO.userError "handshake hashes differ")

def main : IO UInt32 := do
  if (Suites.kemByName kem.name).isNone then
    IO.println s!"FAIL {kem.name} is not in the registry"; return 1
  if !(protocolNameValid protocol.name) then
    IO.println s!"FAIL invalid protocol name {protocol.name}"; return 1
  handshake
  IO.println s!"{protocol.name}: handshake ok"
  let failed := (← Tests.Msg.run) + (← Tests.Session.run)
  pure (if failed == 0 then 0 else 1)
