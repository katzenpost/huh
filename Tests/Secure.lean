import Tests.Util

open Huh Uproar

namespace Tests.Secure

def openAll (rcv : Receiver) (cts : List ByteArray) : Except String (List Msg) := do
  let mut rcv := rcv
  let mut out := #[]
  for ct in cts do
    let (m, r) ← rcv.open ct
    out := out.push m
    rcv := r
  return out.toList

def msgs (n : Nat) : List Msg := (List.range n).map fun i => .stdout (bytes s!"message {i}")

def flipLast (b : ByteArray) : ByteArray := b.set! (b.size - 1) (b.get! (b.size - 1) ^^^ 1)

def run : IO Nat := do
  let t ← Suite.new "secure"
  let (snd, rcv) := channel
  let (cts, _) ← sealAll snd (msgs 10)
  t.expect ((openAll rcv cts).toOption.map (sameMsgs · (msgs 10)) == some true) "round trip"
  let (snd, rcv) := channel (interval := 3)
  let (cts, _) ← sealAll snd (msgs 10)
  t.expect ((openAll rcv cts).toOption.map (sameMsgs · (msgs 10)) == some true) "rekey every 3 messages"
  let (snd, rcv) := channel (interval := 3) (recvInterval := 4)
  let (cts, _) ← sealAll snd (msgs 5)
  t.expect (openAll rcv (cts.take 3)).toBool "messages before the first rekey"
  t.expect (!(openAll rcv cts).toBool) "receiver that skips a rekey is rejected"
  let (snd, rcv) := channel (key := 1)
  let (_, other) := channel (key := 2)
  let (cts, _) ← sealAll snd (msgs 3)
  t.expect (!(openAll other cts).toBool) "wrong key"
  t.expect (!(openAll rcv [flipLast cts[0]!]).toBool) "tampered message"
  t.expect (!(openAll rcv [cts[1]!]).toBool) "skipped message"
  t.expect (!(openAll rcv (cts.take 1 ++ cts.take 1)).toBool) "replayed message"
  t.expect (snd.seal (.stdout (ByteArray.mk (Array.replicate maxData 0)))).toBool "largest data message"
  t.expect (!(snd.seal (.stdout (ByteArray.mk (Array.replicate (maxData + 1) 0)))).toBool) "oversize data"
  t.expect (!(snd.seal (.signal (ByteArray.mk (Array.replicate 65536 65)))).toBool) "malformed message"
  let (ct, _) ← IO.ofExcept ((snd.t.writeMessage protocol.cipher (ByteArray.mk #[0])).mapError (IO.userError ∘ reprStr))
  t.expect (!(rcv.open ct).toBool) "authentic but undecodable payload"
  t.finish

end Tests.Secure
