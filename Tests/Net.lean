import Tests.Util
import Tests.Server
import Tests.Client
import Tests.Loopback

open Huh Uproar Std.Async Std.Net

namespace Tests.Net

/-- A listening socket on a free loopback port, and that port. -/
def listener : IO (TCP.Socket.Server × UInt16) := do
  let srv ← Server.bind (.v4 ⟨IPv4Addr.ofParts 127 0 0 1, 0⟩)
  return (srv, (← srv.getSockName).port)

/-- A connected pair: `(client, server side)`. -/
def pair : IO (Net.Socket × Net.Socket) := do
  let (srv, port) ← listener
  let accepted ← srv.accept.toIO
  let c ← Net.dial "127.0.0.1" port
  return (c, ← accepted.block)

def clientKey : IO KeyPair := Tests.Loopback.keyOf "client"
def serverKey : IO KeyPair := Tests.Loopback.keyOf "server"

/-- A whole client session with `cmd`: its result, stdout and stderr. -/
def honestOn (port : UInt16) : IO (Except IO.Error UInt32 × ByteArray × ByteArray) := do
  let sk ← serverKey
  let (term, out, err) ← Tests.Client.fakeTerminal []
  let ccfg : Huh.Client.Config :=
    { key := ← clientKey, verifyHost := fun k => pure (k == sk.pub), pty := none, cmd := some (bytes "x") }
  let r ← (do Huh.Client.session ccfg (Net.frames (← Net.dial "127.0.0.1" port)) term).toBaseIO
  return (r, ← out.get, ← err.get)

instance : Nonempty ExitStatus := ⟨.code 0⟩

/-- A child that runs until it gets one of `fatal`, then dies of it. `started` resolves when it
is spawned. -/
def signalledProc (fatal : List String) (started : IO.Promise Unit) : IO Huh.Server.Proc := do
  let exited : IO.Promise ExitStatus ← IO.Promise.new
  let dead ← IO.mkRef false
  started.resolve ()
  return {
    pty := false, write := fun _ => pure (), closeStdin := pure (), resize := fun _ _ => pure ()
    signal := fun n => do
      if fatal.contains n then
        unless ← dead.swap true do exited.resolve (.signal n.toUTF8)
    readStdout := pure ByteArray.empty, readStderr := none
    wait := IO.wait exited.result! }

/-- Shut down a server with one session whose child dies of `fatal`; the client's exit code and
how long the shutdown took. -/
def shutdownWith (fatal : List String) (graceMs : Nat) : IO (Except IO.Error UInt32 × Nat × Bool) := do
  let started ← IO.Promise.new
  let cfg : Huh.Server.Config :=
    { hostKey := ← serverKey, authorized := [(← clientKey).pub], log := fun _ _ => pure () }
  let (srv, port) ← listener
  let live ← Huh.Server.Live.new
  discard <| IO.asTask (prio := .dedicated)
    (Huh.Server.acceptLoop live cfg srv (fun _ _ _ => signalledProc fatal started))
  let client ← IO.asTask (prio := .dedicated) (honestOn port)
  IO.wait started.result!
  let start ← IO.monoMsNow
  live.shutdown graceMs
  let took := (← IO.monoMsNow) - start
  let (r, _, _) ← IO.ofExcept (← IO.wait client)
  -- a connection after the shutdown began is closed without a handshake
  let late ← Net.dial "127.0.0.1" port
  let closed := (← (late.recv? 16).block) == none
  return (r, took, closed)

def shutdown (t : Suite) : IO Unit := do
  let (r, took, closed) ← shutdownWith ["HUP"] 5000
  t.expect (r.toOption == some 129) s!"shutdown hangs up the child: {r.toOption}"
  t.expect (took < 2000) s!"shutdown waits only for the sessions: {took} ms"
  t.expect closed "no new sessions after a shutdown"
  let (r, took, _) ← shutdownWith ["KILL"] 300
  t.expect (r.toOption == some 137) s!"shutdown kills a child that ignores HUP: {r.toOption}"
  t.expect (took ≥ 300) s!"shutdown gives a stubborn child the grace period: {took} ms"

def run : IO Nat := do
  let t ← Suite.new "net"
  -- parseAddr
  let addr (s : String) := (Net.parseAddr s).map toString
  t.expect (addr "127.0.0.1:2222" == some "127.0.0.1:2222") "parse IPv4"
  t.expect ((Net.parseAddr "[::1]:2222").map (·.port) == some 2222) "parse IPv6"
  t.expect ((Net.parseAddr "[::1]:2222").map (·.family) == some .ipv6) "parse IPv6 family"
  for bad in ["127.0.0.1", "127.0.0.1:", "127.0.0.1:65536", "::1:22", "host:22", "", "1.2.3:4"] do
    t.expect (Net.parseAddr bad).isNone s!"rejects {bad.quote}"

  -- frames over a real socket
  let (c, s) ← pair
  let big := ByteArray.mk (Array.replicate maxMessageLen 9)
  for f in [bytes "abc", ByteArray.empty, big] do Net.send c f
  -- one frame a byte at a time
  for b in [0, 2, 104, 105] do c.send (ByteArray.mk #[b]) |>.block
  c.shutdown.block
  let fs := Net.frames s
  t.expect ((← fs.recv) == some (bytes "abc")) "first frame"
  t.expect ((← fs.recv) == some ByteArray.empty) "empty frame"
  t.expect ((← fs.recv) == some big) "largest frame"
  t.expect ((← fs.recv) == some (bytes "hi")) "frame sent a byte at a time"
  t.expect ((← fs.recv) == none) "end of stream"
  let (c, s) ← pair
  c.send (ByteArray.mk #[0, 5, 1, 2]) |>.block
  c.shutdown.block
  t.throws "truncated frame" (Net.frames s).recv

  -- dial
  let (srv, port) ← listener
  let accepted ← srv.accept.toIO
  t.expect ((← (Net.dial "localhost" port).toBaseIO).toBool) "dial localhost"
  discard <| accepted.block
  t.throws "dial a closed port" (Net.dial "127.0.0.1" 1)

  -- whole sessions against an accept loop
  let ck ← clientKey
  let sk ← serverKey
  let logs ← IO.mkRef (#[] : Array String)
  let cfg : Huh.Server.Config :=
    { hostKey := sk, authorized := [ck.pub], log := fun _ m => logs.modify (·.push m) }
  let spawn : String → Huh.Server.Spawner := fun _ _ _ => do
    Tests.Server.fakeProc (← IO.mkRef #[]) [bytes "o1", bytes "o2"] [bytes "e1"] (.code 7)
  let (srv, port) ← listener
  let live ← Huh.Server.Live.new
  discard <| IO.asTask (prio := .dedicated) (Huh.Server.acceptLoop live cfg srv spawn (timeoutMs := 300))
  let honest : IO (Except IO.Error UInt32 × ByteArray × ByteArray) := honestOn port
  let (r, out, err) ← honest
  t.expect (r.toOption == some 7 && out == bytes "o1o2" && err == bytes "e1")
    s!"session over TCP: {r.toOption} {out.size} {err.size}"

  -- a silent client is dropped after the handshake deadline
  let silent ← Net.dial "127.0.0.1" port
  let start ← IO.monoMsNow
  let got ← (silent.recv? 16).block
  let waited := (← IO.monoMsNow) - start
  t.expect (got == none && waited ≥ 250) s!"silent client dropped after {waited} ms"
  IO.sleep 50
  t.expect ((← logs.get).any (·.endsWith "handshake timed out")) s!"timeout logged: {← logs.get}"

  -- a client sending garbage fails alone; a concurrent honest session still succeeds
  let bad ← Net.dial "127.0.0.1" port
  let honestTask ← IO.asTask (prio := .dedicated) honest
  Net.send bad (bytes "not a handshake message")
  let (r, out, _) ← IO.ofExcept (← IO.wait honestTask)
  t.expect (r.toOption == some 7 && out == bytes "o1o2") "honest session next to a bad client"
  t.expect ((← (bad.recv? 16).block) == none) "bad client disconnected"
  shutdown t
  t.finish

end Tests.Net
