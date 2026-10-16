import Huh.Client

open Huh

def usage : String :=
  "usage: huh [-i key] [-t|-T] [-p port] host [command...]"

structure Args where
  key : Option String := none
  pty : Option Bool := none
  port : UInt16 := 2222
  host : String := ""
  cmd : List String := []

def parseArgs (a : Args) : List String → Option Args
  | "-i" :: k :: rest => parseArgs { a with key := some k } rest
  | "-t" :: rest => parseArgs { a with pty := some true } rest
  | "-T" :: rest => parseArgs { a with pty := some false } rest
  | "-p" :: p :: rest => do parseArgs { a with port := ← Net.parsePort p } rest
  | host :: cmd => if host.startsWith "-" then none else some { a with host, cmd }
  | [] => none

def main (args : List String) : IO UInt32 := do
  let some a := parseArgs {} args | IO.eprintln usage; return 2
  let dir ← huhDir
  let keyPath := a.key.getD (dir / "id.private").toString
  let fail (msg : String) : IO UInt32 := do IO.eprintln s!"huh: {msg}"; return 255
  let file ← try readKeyFile keyPath catch e => return ← fail (toString e)
  let private_ ← try FFI.filePrivate keyPath catch e => return ← fail (toString e)
  unless private_ do return ← fail s!"{keyPath} must be private to its owner"
  let key ← try
      match file with
      | .plain seed => IO.ofExcept ((keyPairOfSeed seed).mapError IO.userError)
      | .encrypted f =>
        unlockWith f (FFI.readPassphrase s!"Passphrase for {keyPath}: ")
          (IO.eprintln s!"huh: {·}")
    catch e => return ← fail (toString e)
  let tty ← FFI.isatty 0
  let pty ← if a.pty.getD (tty && a.cmd.isEmpty) then do
      let (rows, cols) ← if tty then FFI.ttyWinsize 0 else pure (24, 80)
      let term := (← IO.getEnv "TERM").getD "dumb"
      pure (some ({ term := term.toUTF8, rows, cols } : PtyReq))
    else pure none
  let cmd := if a.cmd.isEmpty then none else some (" ".intercalate a.cmd).toUTF8
  let hostId := s!"{a.host}:{a.port}"
  let cfg : Client.Config :=
    { key := key, verifyHost := Client.verifyKnownHost (dir / "known_hosts") hostId, pty, cmd }
  let code ← Client.run cfg a.host a.port
  IO.Process.exit code.toUInt8
