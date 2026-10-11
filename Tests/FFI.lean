import Huh.FFI

open Huh

namespace Tests.FFI

partial def drain (fd : UInt32) (acc : ByteArray := ByteArray.empty) : IO ByteArray := do
  let b ← FFI.read fd 4096
  if b.size == 0 then return acc
  drain fd (acc ++ b)

def text (b : ByteArray) : String := String.fromUTF8? b |>.getD "<binary>"

def run : IO Nat := do
  let mut failed := 0
  let (pid, master) ← FFI.spawnPty "/bin/sh" #["sh", "-c", "tty; stty size; exit 3"] #["PATH=/bin:/usr/bin"] "/" 33 99
  let out := text (← drain master)
  FFI.close master
  let (code, sig) ← FFI.wait pid
  unless out.startsWith "/dev/pts/" && (out.splitOn "33 99").length == 2 && code == 3 && sig.isEmpty do
    failed := failed + 1; IO.println s!"  FAIL pty spawn: {out.quote} {code} {sig}"
  let (pid, i, o, e) ← FFI.spawnPipes "/bin/sh" #["sh", "-c", "cat; echo err >&2; exit 5"] #[] "/"
  FFI.write i "hello\n".toUTF8
  FFI.close i
  let out := text (← drain o)
  let err := text (← drain e)
  let (code, _) ← FFI.wait pid
  unless out == "hello\n" && err == "err\n" && code == 5 do
    failed := failed + 1; IO.println s!"  FAIL pipe spawn: {out.quote} {err.quote} {code}"
  let (pid, i, o, e) ← FFI.spawnPipes "/bin/sleep" #["sleep", "30"] #[] "/"
  let known ← FFI.killGroup pid "TERM"
  let (_, sig) ← FFI.wait pid
  for fd in [i, o, e] do FFI.close fd
  unless known && sig == "TERM" do
    failed := failed + 1; IO.println s!"  FAIL kill: {sig}"
  unless !(← FFI.killGroup pid "NOPE") do failed := failed + 1; IO.println "  FAIL unknown signal"
  match ← (FFI.spawnPipes "/nonexistent" #["x"] #[] "/").toBaseIO with
  | .ok _ => failed := failed + 1; IO.println "  FAIL spawned a missing program"
  | .error _ => pure ()
  IO.println s!"ffi: {failed} failures"
  return failed

end Tests.FFI
