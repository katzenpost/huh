import Tests.Util
import Tests.Server
import Tests.Client
import Tests.Loopback

open Huh Uproar Std.Net

namespace Tests.Quic

def hostSeed : ByteArray := ByteArray.mk (Array.replicate 32 5)

def loopback : SocketAddress := .v4 ⟨IPv4Addr.ofParts 127 0 0 1, 0⟩

/-- A server that sends every frame back, and finishes when the client does. -/
def echo : IO (Huh.Quic.Server × UInt16) := do
  let srv ← Huh.Quic.listen loopback hostSeed fun l => do
    let fs := l.frames
    repeat
      let some f ← fs.recv | break
      fs.send f
    l.finish
  return (srv, srv.addr.port)

def identity (t : Suite) : IO Unit := do
  let pin := QuicId.pin hostSeed
  t.expect (pin.size == 32) "pin size"
  t.expect (pin == QuicId.pin hostSeed) "pin is deterministic"
  t.expect (pin != QuicId.pin (ByteArray.mk (Array.replicate 32 6))) "pins differ between hosts"
  t.expect (Cryptlib.Util.Bytes.ofVector (QuicId.signingSeed hostSeed) != hostSeed) "signing seed is not the host seed"
  -- two certificates for the key, as each epoch reissues it, share the pin
  for _ in [0:2] do
    let cert ← LeanQUIC.UDP.epochCertificate (QuicId.signingSeed hostSeed) .mldsa65
    t.expect (LeanQUIC.UDP.spkiPin cert == some pin) "the certificate's pin is the derived pin"

def run : IO Nat := do
  let t ← Suite.new "quic"
  identity t
  let pin := QuicId.pin hostSeed

  -- frames over a real QUIC connection
  let (srv, port) ← echo
  let addr : SocketAddress := .v4 ⟨IPv4Addr.ofParts 127 0 0 1, port⟩
  let l ← Huh.Quic.connect addr [pin]
  let fs := l.frames
  let big := ByteArray.mk (Array.replicate maxMessageLen 9)
  for f in [bytes "abc", ByteArray.empty, big] do fs.send f
  t.expect ((← fs.recv) == some (bytes "abc")) "first frame"
  t.expect ((← fs.recv) == some ByteArray.empty) "empty frame"
  t.expect ((← fs.recv) == some big) "largest frame"
  -- 4 MiB each way, more than the windows, with the client sending and receiving at once
  let chunk := ByteArray.mk (Array.ofFn (n := 32768) fun i => i.val.toUInt8)
  let start ← IO.monoMsNow
  let sender ← IO.asTask (prio := .dedicated) do for _ in [0:128] do fs.send chunk
  let mut got := 0
  for _ in [0:128] do
    if (← fs.recv) == some chunk then got := got + 1
  discard <| IO.wait sender
  t.expect (got == 128) s!"4 MiB echoed: {got} of 128 frames, {(← IO.monoMsNow) - start} ms"
  l.finish
  t.expect ((← fs.recv) == none) "end of stream after finishing"
  l.close

  -- dial by name
  let l ← Huh.Quic.dial "127.0.0.1" port [pin]
  l.frames.send (bytes "x")
  t.expect ((← l.frames.recv) == some (bytes "x")) "dial by name"
  l.close

  -- the client accepts no other identity
  let r ← (Huh.Quic.connect addr [QuicId.pin (ByteArray.mk (Array.replicate 32 6))]).toBaseIO
  t.expect (match r with | .error e => toString e == Huh.Quic.closeMessage (some (true, 298, "")) | _ => false)
    "wrong pin refused, and said so"
  srv.stop

  -- whole sessions
  let ck ← Tests.Loopback.keyOf "client"
  let sk ← Tests.Loopback.keyOf "server"
  let cfg : Huh.Server.Config :=
    { hostKey := sk, hostSeed, authorized := [ck.pub], log := fun _ _ => pure () }
  let spawn : String → Huh.Server.Spawner := fun _ _ _ => do
    Tests.Server.fakeProc (← IO.mkRef #[]) [bytes "o1", bytes "o2"] [bytes "e1"] (.code 7)
  let live ← Huh.Server.Live.new
  let q ← Huh.Server.listenQuic live cfg loopback spawn (timeoutMs := 300)
  let session (key : KeyPair) : IO (Except IO.Error UInt32 × ByteArray × ByteArray) := do
    let (term, out, err) ← Tests.Client.fakeTerminal []
    let ccfg : Huh.Client.Config :=
      { key, verifyHost := fun k => pure (k == sk.pub), pty := none, cmd := some (bytes "x") }
    let l ← Huh.Quic.dial "127.0.0.1" q.addr.port [pin]
    let r ← (Huh.Client.session ccfg l.frames term).toBaseIO
    l.close
    return (r, ← out.get, ← err.get)
  let (r, out, err) ← session ck
  t.expect (r.toOption == some 7 && out == bytes "o1o2" && err == bytes "e1")
    s!"session over QUIC: {r.toOption} {out.size} {err.size}"
  let (r, _, _) ← session (← Tests.Loopback.keyOf "stranger")
  t.expect (!r.toBool) "unauthorized client refused"
  -- a silent client is dropped after the handshake deadline
  let silent ← Huh.Quic.dial "127.0.0.1" q.addr.port [pin]
  let start ← IO.monoMsNow
  let dropped ← silent.frames.recv.toBaseIO
  let waited := (← IO.monoMsNow) - start
  t.expect ((dropped.toOption.bind id).isNone && waited ≥ 250) s!"silent client dropped after {waited} ms"
  q.stop
  let ended ← IO.asTask (IO.wait q.task)
  let timer ← IO.asTask (IO.sleep 5000)
  discard <| IO.waitAny [ended.map fun _ => (), timer.map fun _ => ()]
  t.expect (← IO.hasFinished ended) "the endpoint ends once stopped and its connections are gone"
  t.finish

end Tests.Quic
