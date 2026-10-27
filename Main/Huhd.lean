import Huh.Server

open Huh

def usage : String :=
  "usage: huhd [--listen addr:port]... [--tcp-listen addr:port]... [--syslog] [--host-key path]\n" ++
  "            [--authorized-keys path]"

structure Args where
  hostKey : Option String := none
  authorized : Option String := none
  listen : Array String := #[]
  tcpListen : Array String := #[]
  syslog : Bool := false

def parseArgs (a : Args) : List String → Option Args
  | [] => some a
  | "--listen" :: addr :: rest => parseArgs { a with listen := a.listen.push addr } rest
  | "--tcp-listen" :: addr :: rest => parseArgs { a with tcpListen := a.tcpListen.push addr } rest
  | "--syslog" :: rest => parseArgs { a with syslog := true } rest
  | "--host-key" :: p :: rest => parseArgs { a with hostKey := some p } rest
  | "--authorized-keys" :: p :: rest => parseArgs { a with authorized := some p } rest
  | _ => none

def main (args : List String) : IO UInt32 := do
  let some a := parseArgs {} args | IO.eprintln usage; return 2
  let listen := if a.listen.isEmpty && a.tcpListen.isEmpty then #["0.0.0.0:2222"] else a.listen
  let some addrs := listen.mapM Net.parseAddr | IO.eprintln usage; return 2
  let some tcpAddrs := a.tcpListen.mapM Net.parseAddr | IO.eprintln usage; return 2
  let dir ← huhDir
  let hostKey := a.hostKey.getD (dir / "host_key.private").toString
  let authorized := a.authorized.getD (dir / "authorized_keys").toString
  let fail (msg : String) : IO UInt32 := do log a.syslog logWarning msg; return 1
  let seed ← try readHostSeed hostKey catch e => return ← fail (toString e)
  let .ok kp := keyPairOfSeed seed | return ← fail s!"{hostKey}: not a host key"
  let private_ ← try FFI.filePrivate hostKey catch e => return ← fail (toString e)
  unless private_ do return ← fail s!"{hostKey} must be private to its owner"
  let keys := parseAuthorized (← readTextOrEmpty authorized)
  let cfg : Server.Config := { hostKey := kp, hostSeed := seed, authorized := keys, log := log a.syslog }
  try Server.listen cfg addrs tcpAddrs
  catch e => discard <| fail (toString e); IO.Process.exit 1
  -- the accept loops never return, and would keep the process alive
  IO.Process.exit 0
