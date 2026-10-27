import Tests.Msg
import Tests.Session
import Tests.Frame
import Tests.Secure
import Tests.Keys
import Tests.Server
import Tests.Client
import Tests.FFI
import Tests.Loopback
import Tests.Net
import Tests.Quic

open Huh Uproar

def main : IO UInt32 := do
  let mut failed := 0
  for (name, test) in [("msg", Tests.Msg.run), ("session", Tests.Session.run),
      ("frame", Tests.Frame.run), ("secure", Tests.Secure.run), ("keys", Tests.Keys.run),
      ("server", Tests.Server.run), ("client", Tests.Client.run), ("ffi", Tests.FFI.run),
      ("loopback", Tests.Loopback.run), ("net", Tests.Net.run),
      ("quic", Tests.Quic.run)] do
    let n ← try test catch e => IO.println s!"  FAIL {name}: {e}"; pure 1
    (← IO.getStdout).flush
    failed := failed + n
  IO.println s!"total failures: {failed}"
  (← IO.getStdout).flush
  -- the net and quic tests leave endpoints running, which would keep the process alive
  IO.Process.exit (if failed == 0 then 0 else 1)
