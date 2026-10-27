import Tests.Util
import Tests.Secure

open Huh Uproar Huh.Client

namespace Tests.Client

def fakeTerminal (input : List ByteArray) :
    IO (Terminal × IO.Ref ByteArray × IO.Ref ByteArray) := do
  let pending ← IO.mkRef input
  let out ← IO.mkRef ByteArray.empty
  let err ← IO.mkRef ByteArray.empty
  let term : Terminal := {
    readStdin := do
      match ← pending.get with
      | [] => return ByteArray.empty
      | b :: rest => pending.set rest; return b
    writeStdout := fun d => out.modify (· ++ d)
    writeStderr := fun d => err.modify (· ++ d)
    winsize := pure (24, 80)
    resized := pure (IO.sleep 1000000) }
  return (term, out, err)

def run : IO Nat := do
  let t ← Suite.new "client"
  t.expect (exitCode (.code 0) == 0 && exitCode (.code 42) == 42 && exitCode (.code 255) == 255) "exit codes"
  t.expect (exitCode (.signal (bytes "TERM")) == 143 && exitCode (.signal (bytes "KILL")) == 137) "signal exit codes"
  t.expect (exitCode (.signal (bytes "NOPE")) == 255) "unknown signal"

  -- pumpStdin
  let (term, _, _) ← fakeTerminal [bytes "a", bytes "b"]
  let out : Outbox ← Std.CloseableChannel.Sync.new
  pumpStdin term out
  t.expect (sameMsgs (← drain out).toList [.stdin (bytes "a"), .stdin (bytes "b"), .stdinEof]) "pumpStdin"

  -- watchSize: one message per change, none when the size is unchanged; stops when `resized` throws
  let (term, _, _) ← fakeTerminal []
  let sizes ← IO.mkRef [((24, 80) : UInt16 × UInt16), (24, 80), (30, 100), (30, 100), (40, 120)]
  let term := { term with
    winsize := do
      let s :: rest ← sizes.get | throw (IO.userError "no more sizes")
      sizes.set rest; return s
    resized := do
      if (← sizes.get).isEmpty then throw (IO.userError "done")
      return pure () }
  let out : Outbox ← Std.CloseableChannel.Sync.new
  try watchSize term out (24, 80) catch _ => pure ()
  t.expect (sameMsgs (← drain out).toList [.windowChange 30 100, .windowChange 40 120]) "watchSize"

  -- writer
  let (snd, rcv) := channel
  let out : Outbox ← Std.CloseableChannel.Sync.new
  for m in [Msg.open_ none none, .stdinEof] do out.send m
  out.close
  let (frames, sent) ← scriptedFrames []
  writer frames snd out
  t.expect ((Tests.Secure.openAll rcv (← sent.get).toList).toOption.map
    (sameMsgs · [.open_ none none, .stdinEof]) == some true) "writer"

  -- reader
  let readerRun (msgs : List Msg) : IO (Except IO.Error UInt32 × ByteArray × ByteArray) := do
    let (snd, rcv) := channel
    let (cts, _) ← sealAll snd msgs
    let (frames, _) ← scriptedFrames cts
    let (term, out, err) ← fakeTerminal []
    let r ← (reader frames term rcv .running).toBaseIO
    return (r, ← out.get, ← err.get)
  let (r, out, err) ← readerRun
    [.stdout (bytes "a"), .stderr (bytes "b"), .stdout (bytes "c"), .exit (.code 7), .stdout (bytes "late")]
  t.expect (r.toOption == some 7 && out == bytes "ac" && err == bytes "b") "reader"
  let (r, out, _) ← readerRun [.stdout (bytes "a")]
  t.expect (!r.toBool && out == bytes "a") "reader without exit"
  let (r, _, _) ← readerRun [.stdin (bytes "a")]
  t.expect (!r.toBool) "reader rejects client messages"
  let (r, _, _) ← readerRun [.exit (.signal (bytes "INT"))]
  t.expect (r.toOption == some 130) "reader exit by signal"

  -- failureMessage
  let msg (st : Stage) (e : String) := failureMessage st "h:1" "FP" e
  t.expect (msg .connecting "refused" == "could not connect to h:1: refused") "failure: connecting"
  t.expect (msg .verifyingHost "peer key rejected" == "not connecting to h:1") "failure: host rejected"
  t.expect (msg .verifyingHost "bad" == "handshake with h:1 failed: bad") "failure: handshake"
  t.expect (((msg .authenticating "connection closed during handshake").splitOn "authorized_keys").length > 1)
    "failure: client key rejected"
  t.expect (msg .established "x" == "connection to h:1 lost: x") "failure: established"
  t.finish

end Tests.Client
