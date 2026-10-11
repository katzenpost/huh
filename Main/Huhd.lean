import Huh.Server

open Huh

def usage : String := "usage: huhd [-e] [--host-key path] [--authorized-keys path]"

structure Args where
  hostKey : Option String := none
  authorized : Option String := none
  logStderr : Bool := false

def parseArgs (a : Args) : List String → Option Args
  | [] => some a
  | "-e" :: rest => parseArgs { a with logStderr := true } rest
  | "--host-key" :: p :: rest => parseArgs { a with hostKey := some p } rest
  | "--authorized-keys" :: p :: rest => parseArgs { a with authorized := some p } rest
  | _ => none

def main (args : List String) : IO UInt32 := do
  let some a := parseArgs {} args | IO.eprintln usage; return 2
  let dir ← huhDir
  let hostKey := a.hostKey.getD (dir / "host_key").toString
  let authorized := a.authorized.getD (dir / "authorized_keys").toString
  let fail (msg : String) : IO UInt32 := do log a.logStderr logWarning msg; return 1
  let private_ ← try FFI.filePrivate hostKey catch e => return ← fail (toString e)
  unless private_ do return ← fail s!"{hostKey} must be private to its owner"
  let kp ← try readPrivate hostKey catch e => return ← fail (toString e)
  let keys := parseAuthorized (← readTextOrEmpty authorized)
  Server.serve { hostKey := kp, authorized := keys, logStderr := a.logStderr }
  return 0
