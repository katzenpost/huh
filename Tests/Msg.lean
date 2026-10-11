import Huh

open Huh

namespace Tests.Msg

def samples : List Msg :=
  [.open_ none none,
   .open_ (some { term := "xterm-256color".toUTF8, rows := 50, cols := 132 }) none,
   .open_ none (some "ls -l /".toUTF8),
   .open_ (some { term := ByteArray.empty, rows := 65535, cols := 0 }) (some ⟨#[0, 255, 10]⟩),
   .stdin ByteArray.empty, .stdin ⟨#[1, 2, 3]⟩, .stdinEof, .windowChange 24 80,
   .signal "INT".toUTF8, .stdout ⟨Array.replicate 65000 7⟩, .stderr "oops\n".toUTF8,
   .exit (.code 0), .exit (.code 255), .exit (.signal "KILL".toUTF8)]

def malformed : List (String × ByteArray) :=
  [("empty", ByteArray.empty),
   ("unknown tag", ⟨#[0]⟩),
   ("unknown tag 9", ⟨#[9]⟩),
   ("trailing byte after stdinEof", ⟨#[3, 0]⟩),
   ("truncated windowChange", ⟨#[4, 0, 24, 0]⟩),
   ("trailing byte after windowChange", ⟨#[4, 0, 24, 0, 80, 1]⟩),
   ("bad option flag", ⟨#[1, 2, 0]⟩),
   ("signal length past end", ⟨#[5, 0, 9, 65]⟩),
   ("unknown exit kind", ⟨#[8, 2, 0]⟩),
   ("open without cmd flag", ⟨#[1, 0]⟩)]

def encodeEq (a b : Msg) : Bool := a.encode == b.encode

def run : IO Nat := do
  let mut failed := 0
  for m in samples do
    match Msg.decode m.encode with
    | some m' => if !encodeEq m m' then failed := failed + 1; IO.println "  FAIL round trip mismatch"
    | none => failed := failed + 1; IO.println s!"  FAIL round trip rejected tag {m.encode[0]!}"
  for (why, b) in malformed do
    if (Msg.decode b).isSome then failed := failed + 1; IO.println s!"  FAIL accepted {why}"
  IO.println s!"msg codec: {samples.length} round trips, {malformed.length} rejections, {failed} failures"
  pure failed

end Tests.Msg
