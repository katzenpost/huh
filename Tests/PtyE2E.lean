import Huh.FFI

/-! End to end over a PTY: run the `huh` client on a pseudo-terminal we control, against a live
`huhd`, and check what an interactive session needs. Usage: `huh-pty-test <huh> <port>`; `HOME`
must hold the client key and known hosts. -/

open Huh

def text (b : ByteArray) : String := String.ofList (b.toList.map fun c => Char.ofNat c.toNat)

def contains (s pat : String) : Bool := (s.splitOn pat).length > 1

partial def collect (master : UInt32) (out : IO.Ref ByteArray) : IO Unit := do
  let b ← try FFI.read master 4096 catch _ => pure ByteArray.empty
  if b.size == 0 then return
  out.modify (· ++ b)
  collect master out

/-- The output position just past the first `pat` after `start`, or `none` after `ms`
milliseconds. `text` maps each byte to one character, so string and byte positions agree. -/
partial def expect (out : IO.Ref ByteArray) (pat : String) (ms : Nat) (start : Nat) : IO (Option Nat) := do
  let all ← out.get
  let s := text (all.extract start all.size)
  if let before :: _ :: _ := s.splitOn pat then return some (start + before.length + pat.length)
  if ms == 0 then return none
  IO.sleep 20
  expect out pat (ms - min ms 20) start

def main (args : List String) : IO UInt32 := do
  let [huh, port] := args | IO.eprintln "usage: huh-pty-test <huh> <port>"; return 2
  let home := (← IO.getEnv "HOME").getD "/"
  let envp := #[s!"HOME={home}", "PATH=/usr/local/bin:/usr/bin:/bin", "TERM=xterm-huhtest"]
  let cmd := s!"{huh} -p {port} 127.0.0.1; echo EXIT=$?; stty -a"
  let (pid, master) ← FFI.spawnPty "/bin/sh" #["sh", "-c", cmd] envp home 30 100
  let out ← IO.mkRef ByteArray.empty
  let _ ← IO.asTask (prio := .dedicated) (collect master out)
  let failures ← IO.mkRef 0
  let mark ← IO.mkRef 0
  let step (what : String) (input : String) (pat : String) (ms : Nat := 20000) : IO Unit := do
    unless input.isEmpty do FFI.write master input.toUTF8
    match ← expect out pat ms (← mark.get) with
    | some n => mark.set n; IO.println s!"  ok    {what}"
    | none =>
      failures.modify (· + 1)
      let all ← out.get
      IO.println s!"  FAIL  {what}: no {pat.quote} in {(text (all.extract (← mark.get) all.size)).quote}"
  step "session starts" "echo READY$((40+2))\n" "READY42"
  step "remote has a tty" "tty; echo T$((1))\n" "/dev/pts/"
  step "initial window size" "stty size; echo S$((1))\n" "30 100"
  step "TERM is forwarded" "echo TERM=$TERM.$((7))\n" "TERM=xterm-huhtest.7"
  -- without the interrupt, the next marker would only appear after 30 seconds
  FFI.write master "sleep 30; echo SLEPT$((1))\n".toUTF8
  IO.sleep 1000
  step "Ctrl-C interrupts the remote command" "\x03echo AFTER$((2+3))\n" "AFTER5" (ms := 5000)
  FFI.ptyResize master 45 120
  IO.sleep 1000
  step "window resize reaches the remote side" "stty size; echo R$((1))\n" "45 120"
  step "exit status comes back" "exit 7\n" "EXIT=7"
  step "local terminal is restored" "" " icanon"
  let (_, _) ← FFI.wait pid
  let all ← out.get
  let after := text (all.extract (← mark.get) all.size)
  if contains after "-icanon" then
    failures.modify (· + 1); IO.println "  FAIL  local terminal left in raw mode"
  let n ← failures.get
  IO.println s!"pty test: {n} failures"
  return if n == 0 then 0 else 1
