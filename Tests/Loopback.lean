import Huh
import Std.Sync.Channel

open Huh Uproar

namespace Tests.Loopback

abbrev Pipe := Std.CloseableChannel.Sync ByteArray

def keyOf (label : String) : IO KeyPair :=
  IO.ofExcept ((keyPairOfSeed (CryptWalker.Util.Bytes.ofVector (CryptWalker.Hash.Blake2s.hash label.toUTF8))).mapError
    IO.userError)

/-- Runs `act` over the given pipes, closing its outgoing pipe when it finishes either way. -/
def party (out : Pipe) (inp : Pipe) (initiator : Bool) (s : KeyPair) (verify : ByteArray → IO Bool) :
    IO (Task (Except IO.Error Established)) :=
  IO.asTask (prio := .dedicated) do
    try handshake initiator s (fun b => out.send b) (inp.recv) verify
    finally out.close

def connect (verifyC verifyS : ByteArray → IO Bool) (c s : KeyPair) :
    IO (Except IO.Error Established × Except IO.Error Established × Nat) := do
  let c2s : Pipe ← Std.CloseableChannel.Sync.new
  let s2c : Pipe ← Std.CloseableChannel.Sync.new
  let counted : Pipe ← Std.CloseableChannel.Sync.new
  let seen ← IO.mkRef 0
  -- count what the server actually receives
  let relay ← IO.asTask (prio := .dedicated) do
    repeat
      let some b ← c2s.recv | break
      seen.modify (· + 1)
      counted.send b
    counted.close
  let server ← party s2c counted false s verifyS
  let client ← party c2s s2c true c verifyC
  let rc ← IO.wait client
  let rs ← IO.wait server
  let _ ← IO.wait relay
  return (rc, rs, ← seen.get)

def flipLast (b : ByteArray) : ByteArray := b.set! (b.size - 1) (b.get! (b.size - 1) ^^^ 1)

def run : IO Nat := do
  let c ← keyOf "client"
  let s ← keyOf "server"
  let mut failed := 0
  let check (ok : Bool) (why : String) : IO Nat := do
    if ok then pure 0 else IO.println s!"  FAIL {why}"; pure 1
  -- honest run
  let (.ok ec, .ok es, _) ← connect (fun k => pure (k == s.pub)) (fun k => pure (k == c.pub)) c s
    | IO.println "  FAIL honest handshake"; return 1
  failed := failed + (← check (ec.remoteStatic == s.pub && es.remoteStatic == c.pub) "remote statics")
  failed := failed + (← check (ec.transport.handshakeHash == es.transport.handshakeHash) "handshake hash")
  let (cs, cr) := split ec.transport
  let (ss, sr) := split es.transport
  let m := Msg.stdin "hello".toUTF8
  let (ct, _) ← IO.ofExcept ((cs.seal m).mapError IO.userError)
  match sr.open ct with
  | .ok (m', _) => failed := failed + (← check (m'.encode == m.encode) "client to server")
  | .error e => failed := failed + (← check false s!"client to server: {e}")
  failed := failed + (← check (sr.open (flipLast ct)).toBool.not "tampered message accepted")
  let (ct, _) ← IO.ofExcept ((ss.seal (.exit (.code 7))).mapError IO.userError)
  failed := failed + (← check (cr.open ct).toBool "server to client")
  -- unauthorized client: server refuses after message 3 and never sends message 4
  let (rc, rs, _) ← connect (fun k => pure (k == s.pub)) (fun _ => pure false) c s
  failed := failed + (← check (!rc.toBool && !rs.toBool) "unauthorized client accepted")
  -- changed host key: client stops after message 2, so the server sees only message 1
  let (rc, rs, seen) ← connect (fun _ => pure false) (fun k => pure (k == c.pub)) c s
  failed := failed + (← check (!rc.toBool && !rs.toBool) "changed host key accepted")
  failed := failed + (← check (seen == 1) s!"client sent {seen} messages to an unverified host")
  IO.println s!"loopback: {failed} failures"
  return failed

end Tests.Loopback
