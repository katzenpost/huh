import Huh

open Huh Uproar

namespace Tests

/-- Collects failures for one test module. -/
structure Suite where
  name : String
  failures : IO.Ref Nat

def Suite.new (name : String) : IO Suite := return ⟨name, ← IO.mkRef 0⟩

def Suite.expect (s : Suite) (ok : Bool) (what : String) : IO Unit := do
  unless ok do
    s.failures.modify (· + 1)
    IO.println s!"  FAIL {s.name}: {what}"

/-- Expect `act` to throw. -/
def Suite.throws {α} (s : Suite) (what : String) (act : IO α) : IO Unit := do
  match ← act.toBaseIO with
  | .ok _ => s.expect false s!"{what}: expected an error"
  | .error _ => pure ()

def Suite.finish (s : Suite) : IO Nat := do
  let n ← s.failures.get
  IO.println s!"{s.name}: {n} failures"
  (← IO.getStdout).flush
  return n

def bytes (s : String) : ByteArray := s.toUTF8

def fixedKey (b : UInt8) : Vector UInt8 32 := Vector.replicate 32 b

/-- A sender and receiver sharing a cipher key, without a handshake. -/
def channel (interval : Nat := rekeyInterval) (key : UInt8 := 1) (recvInterval := interval) :
    Sender × Receiver :=
  let cs := CipherState.init (fixedKey key)
  ({ t := ⟨some cs, none, ByteArray.empty⟩, interval },
   { t := ⟨none, some cs, ByteArray.empty⟩, interval := recvInterval })

def sealAll (snd : Sender) (msgs : List Msg) : IO (List ByteArray × Sender) := do
  let mut snd := snd
  let mut out := #[]
  for m in msgs do
    let (ct, s) ← IO.ofExcept ((snd.seal m).mapError IO.userError)
    out := out.push ct
    snd := s
  return (out.toList, snd)

/-- Frames that replay `incoming` and record what is sent. -/
def scriptedFrames (incoming : List ByteArray) : IO (Frames × IO.Ref (Array ByteArray)) := do
  let pending ← IO.mkRef incoming
  let sent ← IO.mkRef #[]
  let recv := do
    match ← pending.get with
    | [] => return none
    | b :: rest => pending.set rest; return some b
  return (⟨fun b => sent.modify (·.push b), recv⟩, sent)

/-- Everything currently queued in an outbox. -/
partial def drain (out : Std.CloseableChannel.Sync Msg) (acc : Array Msg := #[]) : IO (Array Msg) := do
  match ← out.tryRecv with
  | some m => drain out (acc.push m)
  | none => return acc

def Msg.same (a b : Msg) : Bool := a.encode == b.encode

def sameMsgs (a b : List Msg) : Bool := a.length == b.length && (a.zip b).all fun (x, y) => Msg.same x y

end Tests
