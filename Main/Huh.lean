import Huh.Client

open Huh

def usage : String :=
  "usage: huh [-i key] [-t|-T] [-p port] [--transport cmd] host [command...]"

structure Args where
  key : Option String := none
  pty : Option Bool := none
  port : String := "2222"
  transport : String := "nc %h %p"
  host : String := ""
  cmd : List String := []

def parseArgs (a : Args) : List String → Option Args
  | "-i" :: k :: rest => parseArgs { a with key := some k } rest
  | "-t" :: rest => parseArgs { a with pty := some true } rest
  | "-T" :: rest => parseArgs { a with pty := some false } rest
  | "-p" :: p :: rest => parseArgs { a with port := p } rest
  | "--transport" :: t :: rest => parseArgs { a with transport := t } rest
  | host :: cmd => if host.startsWith "-" then none else some { a with host, cmd }
  | [] => none

def main (args : List String) : IO UInt32 := do
  let some a := parseArgs {} args | IO.eprintln usage; return 2
  let dir ← huhDir
  let keyPath := a.key.getD (dir / "id").toString
  let fail (msg : String) : IO UInt32 := do IO.eprintln s!"huh: {msg}"; return 255
  unless ← System.FilePath.pathExists keyPath do
    return ← fail (if a.key.isSome then s!"no key at {keyPath}"
      else s!"no key at {keyPath}; create one with huh-keygen")
  let private_ ← try FFI.filePrivate keyPath catch e => return ← fail (toString e)
  unless private_ do return ← fail s!"{keyPath} must be private to its owner"
  let key ← try readPrivate keyPath catch e => return ← fail (toString e)
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
  let transport := (a.transport.replace "%h" a.host).replace "%p" a.port
  let code ← Client.run cfg hostId transport
  IO.Process.exit code.toUInt8
