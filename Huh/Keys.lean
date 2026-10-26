/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.Protocol
import Cryptlib.Util.HexBytes
import Cryptlib.Primitives.Hash.Blake2s
import Cryptlib.Primitives.KDF.Argon2
import Cryptlib.Primitives.Cipher.ChaChaPoly

/-! # Key files

A private key file's name ends in `.private`. It holds the 32-byte seed the key pair is derived
from, either as is or encrypted under a passphrase. Host keys are always plain, since a host must
be able to start unattended. An encrypted file is

    "huhkey" 1 0 ‖ m ‖ t ‖ p ‖ salt (16) ‖ nonce (12) ‖ ChaCha20-Poly1305(seed) (48)

with `m` (memory in KiB), `t` (passes) and `p` (lanes) as 32-bit little-endian numbers. The
cipher key is Argon2id of the passphrase and salt under those parameters, and the 48-byte header
before the ciphertext is the associated data. Public keys are written
one per line as `huh-mlkem768hx25519 <hex> [comment]`. A known-hosts line puts the host first:
`host:port` in plain text, or hashed as `|b2|<salt>|<hash>`, the BLAKE2s of `host:port` keyed
with a random 32-byte salt, both in hex. -/

namespace Huh

open Uproar
open Cryptlib.Util.HexBytes (byteArrayToHex hexStringToByteArray)

def algorithm : String := "huh-mlkem768hx25519"

def keyPairOfSeed (seed : ByteArray) : Except String KeyPair := do
  if seed.size != 32 then throw "a private key is 32 bytes"
  (kem.ofSeed (Cryptlib.Util.Bytes.toVecN 32 seed)).mapError reprStr

def publicLine (pub : ByteArray) (comment : String := "") : String :=
  s!"{algorithm} {byteArrayToHex pub}" ++ (if comment.isEmpty then "" else s!" {comment}")

def parsePublic (alg hex : String) : Option ByteArray := do
  guard (alg == algorithm)
  let pub ← hexStringToByteArray hex
  guard (pub.size == kem.pubLen)
  return pub

def fingerprint (pub : ByteArray) : String :=
  let h := Cryptlib.Util.Bytes.ofVector (Cryptlib.Primitives.Hash.Blake2s.hash pub)
  "BLAKE2s:" ++ byteArrayToHex (h.extract 0 16)

def fields (line : String) : List String :=
  (line.splitOn " ").filter (!·.isEmpty)

def contentLines (text : String) : List String :=
  (text.splitOn "\n").filter fun l => !l.trimAscii.isEmpty && !l.trimAscii.startsWith "#"

def parseAuthorized (text : String) : List ByteArray :=
  (contentLines text).filterMap fun l =>
    match fields l with
    | alg :: hex :: _ => parsePublic alg hex
    | _ => none

/-- Known-hosts entries with their line numbers, counted from 1: `(line, host, key)`. -/
def knownHostEntries (text : String) : List (Nat × String × ByteArray) :=
  (text.splitOn "\n").zipIdx.filterMap fun (l, i) => do
    guard (!l.trimAscii.startsWith "#")
    let host :: alg :: hex :: _ := fields l | none
    return (i + 1, host, ← parsePublic alg hex)

def parseKnownHosts (text : String) : List (String × ByteArray) :=
  (knownHostEntries text).map (·.2)

def hostHash (salt : ByteArray) (hostId : String) : ByteArray :=
  Cryptlib.Util.Bytes.ofVector (Cryptlib.Primitives.Hash.Blake2s.hashKeyed salt hostId.toUTF8)

/-- `host:port` hashed under `salt`, as a known-hosts line writes it. -/
def hashHost (salt : ByteArray) (hostId : String) : String :=
  s!"|b2|{byteArrayToHex salt}|{byteArrayToHex (hostHash salt hostId)}"

/-- Whether a known-hosts host field, plain or hashed, names `hostId`. -/
def hostMatches (field hostId : String) : Bool :=
  match field.splitOn "|" with
  | ["", "b2", salt, hash] =>
    match hexStringToByteArray salt, hexStringToByteArray hash with
    | some salt, some hash => salt.size == 32 && hostHash salt hostId == hash
    | _, _ => false
  | _ => field == hostId

def knownHostLine (salt : ByteArray) (hostId : String) (pub : ByteArray) : String :=
  hashHost salt hostId ++ " " ++ publicLine pub

inductive HostCheck where
  | known
  /-- Recorded with other keys, on these lines. -/
  | changed (lines : List Nat)
  | unknown
  deriving BEq, Repr

def checkHost (knownHosts hostId : String) (pub : ByteArray) : HostCheck :=
  let entries := (knownHostEntries knownHosts).filter (hostMatches ·.2.1 hostId)
  if entries.any (·.2.2 == pub) then .known
  else if entries.isEmpty then .unknown
  else .changed (entries.map (·.1))

def readTextOrEmpty (path : System.FilePath) : IO String := do
  if ← path.pathExists then IO.FS.readFile path else pure ""

/-- Argon2id parameters for a private key's passphrase. -/
structure KdfParams where
  memoryKiB : Nat
  passes : Nat
  lanes : Nat
  deriving BEq, Repr

/-- 64 MiB and 2 passes: about a second to unlock. -/
def defaultKdf : KdfParams := { memoryKiB := 65536, passes := 2, lanes := 1 }

/-- The most a key file may ask for, so a hostile file can't exhaust memory or time. -/
def kdfAllowed (k : KdfParams) : Bool :=
  k.memoryKiB ≤ 1048576 && k.passes ≤ 64 && 1 ≤ k.lanes && k.lanes ≤ 16

def keyMagic : ByteArray := "huhkey".toUTF8 ++ ⟨#[1, 0]⟩

def keyHeaderLen : Nat := 48

def encryptedKeyLen : Nat := keyHeaderLen + 32 + 16

private def le32 (x : Nat) : ByteArray :=
  ⟨#[x.toUInt8, (x >>> 8).toUInt8, (x >>> 16).toUInt8, (x >>> 24).toUInt8]⟩

private def readLe32 (b : ByteArray) (o : Nat) : Nat :=
  (b.get! o).toNat ||| ((b.get! (o + 1)).toNat <<< 8) ||| ((b.get! (o + 2)).toNat <<< 16) |||
    ((b.get! (o + 3)).toNat <<< 24)

/-- The ChaCha20-Poly1305 key for `pass`: Argon2id with a 32-byte tag. -/
def passphraseKey (k : KdfParams) (salt : ByteArray) (pass : String) :
    Except String (Vector UInt8 32) := do
  let tag ← Cryptlib.Primitives.KDF.Argon2.hash
    { variant := .id, parallelism := k.lanes, tagLength := 32, memoryKiB := k.memoryKiB,
      passes := k.passes } pass.toUTF8 salt
  return Cryptlib.Util.Bytes.toVecN 32 tag

/-- An encrypted key file for `seed`, with a 16-byte `salt` and 12-byte `nonce`. -/
def encryptSeed (k : KdfParams) (salt nonce : ByteArray) (pass : String) (seed : ByteArray) :
    Except String ByteArray := do
  if salt.size != 16 || nonce.size != 12 then throw "the salt is 16 bytes and the nonce 12"
  let header := keyMagic ++ le32 k.memoryKiB ++ le32 k.passes ++ le32 k.lanes ++ salt ++ nonce
  let key ← passphraseKey k salt pass
  return header ++ Cryptlib.Primitives.Cipher.ChaChaPoly.encrypt key
    (Cryptlib.Util.Bytes.toVecN 12 nonce) header seed

/-- The seed in an encrypted key file. -/
def decryptSeed (file : ByteArray) (pass : String) : Except String ByteArray := do
  if file.size != encryptedKeyLen || file.extract 0 8 != keyMagic then
    throw "not an encrypted huh private key"
  let k : KdfParams := { memoryKiB := readLe32 file 8, passes := readLe32 file 12,
                         lanes := readLe32 file 16 }
  unless kdfAllowed k do throw "the key file asks for too much memory or time to unlock"
  let header := file.extract 0 keyHeaderLen
  let key ← passphraseKey k (file.extract 20 36) pass
  let some seed := Cryptlib.Primitives.Cipher.ChaChaPoly.decrypt key
      (Cryptlib.Util.Bytes.toVecN 12 (file.extract 36 48)) header
      (file.extract keyHeaderLen file.size)
    | throw "wrong passphrase or damaged key file"
  return seed

inductive KeyFile where
  | plain (seed : ByteArray)
  | encrypted (file : ByteArray)

def parseKeyFile (file : ByteArray) : Except String KeyFile :=
  if file.size == 32 then pure (.plain file)
  else if file.extract 0 8 == keyMagic then pure (.encrypted file)
  else throw "not a huh private key"

/-- The seed in an encrypted key file, asking for the passphrase up to `attempts` times. `warn`
reports each failure. -/
def unlockSeedWith (file : ByteArray) (ask : IO String) (warn : String → IO Unit)
    (attempts : Nat := 3) : IO ByteArray := do
  let mut err := "no passphrase given"
  for _ in [0:attempts] do
    match decryptSeed file (← ask) with
    | .ok seed => return seed
    | .error e => err := e; warn e
  throw (IO.userError err)

def unlockWith (file : ByteArray) (ask : IO String) (warn : String → IO Unit)
    (attempts : Nat := 3) : IO KeyPair := do
  IO.ofExcept ((keyPairOfSeed (← unlockSeedWith file ask warn attempts)).mapError IO.userError)

/-- `path` with `.private` appended, unless its name already ends in it. -/
def privatePath (path : System.FilePath) : System.FilePath :=
  if path.extension == some "private" then path else ⟨path.toString ++ ".private"⟩

/-- The public key file beside a private one: `x.private` → `x.pub`. -/
def publicPath (priv : System.FilePath) : System.FilePath := priv.withExtension "pub"

def checkPrivateName (path : System.FilePath) : Except String Unit :=
  unless path.extension == some "private" do
    throw s!"{path}: private key files must end in .private"

/-- Read a private key file by name, which must end in `.private`. When it is missing but the
same name without `.private` exists, from before key files had to end in it, say how to rename. -/
def readKeyFile (path : System.FilePath) : IO KeyFile := do
  IO.ofExcept ((checkPrivateName path).mapError IO.userError)
  let old := path.withExtension ""
  if !(← path.pathExists) && (← old.pathExists) then
    throw (IO.userError s!"{path} not found; private key files now end in .private: mv {old} {path}")
  IO.ofExcept ((parseKeyFile (← IO.FS.readBinFile path)).mapError fun e => IO.userError s!"{path}: {e}")

/-- A host's private key, which must not be encrypted. -/
def readHostKey (path : System.FilePath) : IO KeyPair := do
  match ← readKeyFile path with
  | .plain seed =>
    IO.ofExcept ((keyPairOfSeed seed).mapError fun e => IO.userError s!"{path}: {e}")
  | .encrypted _ => throw (IO.userError s!"{path}: host keys must not be encrypted")

def homeDir : IO System.FilePath := do
  let some home ← IO.getEnv "HOME" | throw (IO.userError "HOME is not set")
  return home

def huhDir : IO System.FilePath := return (← homeDir) / ".huh"

end Huh
