import Huh

open Huh

namespace Tests.Session

def serverRun (msgs : List Msg) : Option Server.Phase :=
  msgs.foldlM (fun ph m => (Server.step ph m).map (·.1)) .awaitOpen

def run : IO Nat := do
  let cases : List (String × List Msg × Bool) :=
    [("open then stdin", [.open_ none none, .stdin ⟨#[1]⟩, .stdinEof], true),
     ("stdin before open", [.stdin ⟨#[1]⟩], false),
     ("second open", [.open_ none none, .open_ none none], false),
     ("stdin after eof", [.open_ none none, .stdinEof, .stdin ⟨#[1]⟩], false),
     ("resize without pty", [.open_ none none, .windowChange 1 1], false),
     ("resize with pty", [.open_ (some ⟨ByteArray.empty, 1, 1⟩) none, .windowChange 2 2], true),
     ("signal", [.open_ none none, .signal "INT".toUTF8], true),
     ("server message from client", [.open_ none none, .stdout ⟨#[1]⟩], false)]
  let mut failed := 0
  for (why, msgs, ok) in cases do
    if (serverRun msgs).isSome != ok then failed := failed + 1; IO.println s!"  FAIL {why}"
  IO.println s!"session machine: {cases.length} cases, {failed} failures"
  pure failed

end Tests.Session
