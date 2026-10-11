import Huh.Keys

open Huh

def usage : String := "usage: huh-keygen [-f keyfile] [-C comment]"

def parseArgs : List String → Option (Option String × String)
  | [] => some (none, "")
  | "-f" :: path :: rest => do let (_, c) ← parseArgs rest; return (some path, c)
  | "-C" :: c :: rest => do let (p, _) ← parseArgs rest; return (p, c)
  | _ => none

def main (args : List String) : IO UInt32 := do
  let some (path?, comment) := parseArgs args | IO.eprintln usage; return 2
  let path ← match path? with
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
  IO.FS.writeFile (path.toString ++ ".pub") (publicLine kp.pub comment ++ "\n")
  IO.println s!"{path}.pub {fingerprint kp.pub}"
  return 0
