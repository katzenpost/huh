import Tests.Util
import Tests.Secure

open Huh Uproar Huh.Server

namespace Tests.Server

/-- A child whose output is fixed in advance and which records what it is asked to do. -/
def fakeProc (log : IO.Ref (Array String)) (stdout stderr : List ByteArray) (status : ExitStatus) :
    IO Proc := do
  let out ← IO.mkRef stdout
  let err ← IO.mkRef stderr
  let next (r : IO.Ref (List ByteArray)) : IO ByteArray := do
    match ← r.get with
    | [] => return ByteArray.empty
    | b :: rest => r.set rest; return b
  return {
    pty := false
    write := fun d => log.modify (·.push s!"write {String.fromUTF8! d}")
    closeStdin := log.modify (·.push "closeStdin")
    resize := fun r c => log.modify (·.push s!"resize {r}x{c}")
    signal := fun n => log.modify (·.push s!"signal {n}")
    readStdout := next out
    readStderr := some (next err)
    wait := pure status }

def outbox : IO Outbox := Std.CloseableChannel.Sync.new

def run : IO Nat := do
  let t ← Suite.new "server"
  t.expect (match exitStatus 3 "" with | .code 3 => true | _ => false) "exit status code"
  t.expect (match exitStatus 0 "TERM" with | .signal n => n == bytes "TERM" | _ => false) "exit status signal"
  t.expect (text (bytes "ls -l") == some "ls -l") "text"
  t.expect (text (ByteArray.mk #[108, 0, 115]) == none) "text with NUL"
  t.expect (text (ByteArray.mk #[0xff]) == none) "text that is not UTF-8"

  -- act
  let log ← IO.mkRef #[]
  let p ← fakeProc log [] [] (.code 0)
  for a in [Action.stdin (bytes "hi"), .closeStdin, .resize 24 80, .signal (bytes "INT"),
            .signal (ByteArray.mk #[0xff])] do
    act p a
  t.expect ((← log.get) == #["write hi", "closeStdin", "resize 24x80", "signal INT"]) "act"

  -- pump
  let out ← outbox
  pump (← fakeProc log [] [] (.code 0)).readStdout .stdout out
  t.expect ((← drain out).isEmpty) "pump with no output"
  let p ← fakeProc log [bytes "a", bytes "b"] [] (.code 0)
  pump p.readStdout .stdout out
  t.expect (sameMsgs (← drain out).toList [.stdout (bytes "a"), .stdout (bytes "b")]) "pump"

  -- finish: all output, then exit last
  let p ← fakeProc log [bytes "o1", bytes "o2"] [bytes "e1"] (.code 7)
  finish p out
  let ms := (← drain out).toList
  let outs := ms.filter fun | .stdout _ => true | _ => false
  let errs := ms.filter fun | .stderr _ => true | _ => false
  t.expect (ms.length == 4) s!"finish sends 4 messages, sent {ms.length}"
  t.expect (sameMsgs outs [.stdout (bytes "o1"), .stdout (bytes "o2")]) "finish keeps stdout in order"
  t.expect (sameMsgs errs [.stderr (bytes "e1")]) "finish forwards stderr"
  t.expect (match ms.getLast? with | some (.exit (.code 7)) => true | _ => false) "finish ends with exit"

  -- writer
  let (snd, rcv) := channel
  let out ← outbox
  for m in [Msg.stdout (bytes "x"), .exit (.code 0), .stdout (bytes "after exit")] do out.send m
  let (frames, sent) ← scriptedFrames []
  writer frames snd out
  let cts := (← sent.get).toList
  t.expect (cts.length == 2) s!"writer stops after exit, sent {cts.length}"
  t.expect ((Tests.Secure.openAll rcv cts).toOption.map
    (sameMsgs · [.stdout (bytes "x"), .exit (.code 0)]) == some true) "writer seals in order"
  let out ← outbox
  out.close
  t.throws "writer with outbox closed before exit" (writer frames snd out)

  -- reader
  let readerRun (msgs : List Msg) (tamper := false) : IO (Except IO.Error Unit × Array String) := do
    let (snd, rcv) := channel
    let (cts, _) ← sealAll snd msgs
    let cts := if tamper then cts.map Tests.Secure.flipLast else cts
    let (frames, _) ← scriptedFrames cts
    let log ← IO.mkRef #[]
    let spawn : Spawner := fun pty cmd => do
      log.modify (·.push s!"spawn pty={pty.isSome} cmd={(cmd.bind String.fromUTF8?).getD "-"}")
      fakeProc log [] [] (.code 0)
    let r ← (reader frames rcv .awaitOpen none spawn (← outbox)).toBaseIO
    return (r, ← log.get)
  let (r, log) ← readerRun [.open_ none (some (bytes "cat")), .stdin (bytes "hi"), .stdinEof]
  t.expect (!r.toBool && log == #["spawn pty=false cmd=cat", "write hi", "closeStdin", "signal HUP"])
    s!"reader session, then hang up on close: {log}"
  let (r, log) ← readerRun [.stdin (bytes "hi")]
  t.expect (!r.toBool && log.isEmpty) s!"reader rejects stdin before open: {log}"
  let (r, log) ← readerRun [.open_ none none, .open_ none none]
  t.expect (!r.toBool && log == #["spawn pty=false cmd=-", "signal HUP"]) s!"reader rejects a second open: {log}"
  let (r, log) ← readerRun [.open_ none none, .stdout (bytes "x")]
  t.expect (!r.toBool && log.back? == some "signal HUP") s!"reader rejects server messages: {log}"
  let (r, log) ← readerRun [.open_ none none] (tamper := true)
  t.expect (!r.toBool && log.isEmpty) s!"reader rejects a tampered frame: {log}"
  let (_, log) ← readerRun [.open_ (some ⟨bytes "xterm", 24, 80⟩) none, .windowChange 50 100]
  t.expect (log.contains "resize 50x100") s!"reader resizes a PTY: {log}"
  t.finish

end Tests.Server
