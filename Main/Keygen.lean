import Huh.Keys

open Huh

def usage : String :=
  "usage: huh-keygen [-f keyfile] [-C comment]\n       huh-keygen -H host:port [-f keyfile]"

structure Args where
  path : Option String := none
  comment : String := ""
  host : Option String := none

def parseArgs (a : Args) : List String → Option Args
  | [] => some a
  | "-f" :: path :: rest => parseArgs { a with path := some path } rest
  | "-C" :: c :: rest => parseArgs { a with comment := c } rest
  | "-H" :: h :: rest => parseArgs { a with host := some h } rest
  | _ => none

/-- `host:port` as `huh` names a host: a non-empty host, a colon, then a port number. -/
def validHostId (h : String) : Bool :=
  let parts := h.splitOn ":"
  let portOk := match parts.getLast?.bind String.toNat? with
    | some n => decide (n < 65536)
    | none => false
  parts.length ≥ 2 && !(":".intercalate parts.dropLast).isEmpty && portOk

/-- Print a hashed known-hosts line for the public key of `keyfile`, or for `keyfile` itself
when it is a `.pub` file. -/
def printKnownHost (host : String) (keyfile : System.FilePath) : IO UInt32 := do
  unless validHostId host do IO.eprintln s!"{host}: expected host:port"; return 2
  let pubPath := if keyfile.extension == some "pub" then keyfile
    else System.FilePath.mk (keyfile.toString ++ ".pub")
  let text ← try IO.FS.readFile pubPath catch e => IO.eprintln s!"{e}"; return 1
  let [pub] := parseAuthorized text | IO.eprintln s!"{pubPath}: expected one public key"; return 1
  IO.println (knownHostLine (← IO.getRandomBytes 32) host pub)
  return 0

def main (args : List String) : IO UInt32 := do
  let some a := parseArgs {} args | IO.eprintln usage; return 2
  if let some host := a.host then
    let keyfile ← match a.path with
      | some p => pure (System.FilePath.mk p)
      | none => do pure ((← huhDir) / "host_key")
    return ← printKnownHost host keyfile
  let path ← match a.path with
    | some p => pure (System.FilePath.mk p)
    | none => do
      let dir ← huhDir
      IO.FS.createDirAll dir
      IO.setAccessRights dir ⟨⟨true, true, true⟩, {}, {}⟩
      pure (dir / "id")
  if ← path.pathExists then IO.eprintln s!"{path} already exists"; return 1
  let seed ← IO.getRandomBytes 32
  let kp ← IO.ofExcept ((keyPairOfSeed seed).mapError IO.userError)
  IO.FS.writeBinFile path ByteArray.empty
  IO.setAccessRights path ⟨⟨true, true, false⟩, {}, {}⟩
  IO.FS.writeBinFile path seed
  IO.FS.writeFile (path.toString ++ ".pub") (publicLine kp.pub a.comment ++ "\n")
  IO.println s!"{path}.pub {fingerprint kp.pub}"
  return 0
