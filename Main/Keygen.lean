import Huh.Keys
import Huh.FFI

open Huh

def usage : String :=
  "usage: huh-keygen [-f keyfile] [-C comment] [-N passphrase]\n" ++
  "       huh-keygen --host [-f keyfile] [-C comment]\n" ++
  "       huh-keygen -p [-f keyfile] [-N passphrase]\n" ++
  "       huh-keygen -H host:port [-f keyfile]"

structure Args where
  path : Option String := none
  comment : String := ""
  host : Option String := none
  pass : Option String := none
  change : Bool := false
  hostKey : Bool := false

def parseArgs (a : Args) : List String → Option Args
  | [] => some a
  | "-f" :: path :: rest => parseArgs { a with path := some path } rest
  | "-C" :: c :: rest => parseArgs { a with comment := c } rest
  | "-H" :: h :: rest => parseArgs { a with host := some h } rest
  | "-N" :: p :: rest => parseArgs { a with pass := some p } rest
  | "-p" :: rest => parseArgs { a with change := true } rest
  | "--host" :: rest => parseArgs { a with hostKey := true } rest
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
    else publicPath (privatePath keyfile)
  let text ← try IO.FS.readFile pubPath catch e => IO.eprintln s!"{e}"; return 1
  let [pub] := parseAuthorized text | IO.eprintln s!"{pubPath}: expected one public key"; return 1
  IO.println (knownHostLine (← IO.getRandomBytes 32) host pub)
  return 0

/-- The new passphrase: `-N`, or asked for twice. Empty means none. -/
def newPassphrase (given : Option String) : IO String := do
  if let some p := given then return p
  let p ← FFI.readPassphrase "Enter passphrase (empty for none): "
  if p.isEmpty then return p
  unless (← FFI.readPassphrase "Enter the same passphrase again: ") == p do
    throw (IO.userError "the passphrases don't match")
  return p

/-- The key file's contents for `seed`: the seed itself without a passphrase, else encrypted. -/
def sealSeed (pass : String) (seed : ByteArray) : IO ByteArray := do
  if pass.isEmpty then return seed
  IO.ofExcept ((encryptSeed defaultKdf (← IO.getRandomBytes 16) (← IO.getRandomBytes 12) pass
    seed).mapError IO.userError)

/-- Write `bytes` to a new file that only its owner can read. -/
def writePrivate (path : System.FilePath) (bytes : ByteArray) : IO Unit := do
  IO.FS.writeBinFile path ByteArray.empty
  IO.setAccessRights path ⟨⟨true, true, false⟩, {}, {}⟩
  IO.FS.writeBinFile path bytes

/-- `-p`: re-encrypt a client key under a new passphrase, or none. -/
def changePassphrase (path : System.FilePath) (given : Option String) : IO UInt32 := do
  let seed ← match ← readKeyFile path with
    | .plain seed => pure seed
    | .encrypted f =>
      unlockSeedWith f (FFI.readPassphrase s!"Old passphrase for {path}: ") (IO.eprintln ·)
  let tmp : System.FilePath := path.toString ++ ".tmp"
  writePrivate tmp (← sealSeed (← newPassphrase given) seed)
  IO.FS.rename tmp path
  IO.println s!"{path}: passphrase changed"
  return 0

def main (args : List String) : IO UInt32 := do
  let some a := parseArgs {} args | IO.eprintln usage; return 2
  if a.hostKey && (a.pass.isSome || a.change) then
    IO.eprintln "huh-keygen: host keys are never encrypted"; IO.eprintln usage; return 2
  let dir ← huhDir
  let defaultName := if a.hostKey || a.host.isSome then "host_key" else "id"
  let given := a.path.map System.FilePath.mk
  if let some host := a.host then
    return ← printKnownHost host (given.getD (dir / defaultName))
  let path := privatePath (given.getD (dir / defaultName))
  try
    if a.change then return ← changePassphrase path a.pass
    if a.path.isNone then
      IO.FS.createDirAll dir
      IO.setAccessRights dir ⟨⟨true, true, true⟩, {}, {}⟩
    if ← path.pathExists then IO.eprintln s!"{path} already exists"; return 1
    let pass ← if a.hostKey then pure "" else newPassphrase a.pass
    let seed ← IO.getRandomBytes 32
    let kp ← IO.ofExcept ((keyPairOfSeed seed).mapError IO.userError)
    writePrivate path (← sealSeed pass seed)
    IO.FS.writeFile (publicPath path) (publicLine kp.pub a.comment ++ "\n")
    IO.println s!"{publicPath path} {fingerprint kp.pub}"
    return 0
  catch e =>
    IO.eprintln s!"huh-keygen: {e}"
    return 1
