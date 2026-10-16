/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.Protocol
import CryptWalker.Util.newhex
import CryptWalker.Hash.Blake2s

/-! # Key files

A private key file holds the 32-byte seed the key pair is derived from. Public keys are written
one per line as `huh-mlkem768hx25519 <hex> [comment]`. A known-hosts line puts the host first:
`host:port` in plain text, or hashed as `|b2|<salt>|<hash>`, the BLAKE2s of `host:port` keyed
with a random 32-byte salt, both in hex. -/

namespace Huh

open Uproar
open CryptWalker.Util.newhex (byteArrayToHex hexStringToByteArray)

def algorithm : String := "huh-mlkem768hx25519"

def keyPairOfSeed (seed : ByteArray) : Except String KeyPair := do
  if seed.size != 32 then throw "a private key is 32 bytes"
  (kem.ofSeed (CryptWalker.Util.Bytes.toVecN 32 seed)).mapError reprStr

def publicLine (pub : ByteArray) (comment : String := "") : String :=
  s!"{algorithm} {byteArrayToHex pub}" ++ (if comment.isEmpty then "" else s!" {comment}")

def parsePublic (alg hex : String) : Option ByteArray := do
  guard (alg == algorithm)
  let pub ← hexStringToByteArray hex
  guard (pub.size == kem.pubLen)
  return pub

def fingerprint (pub : ByteArray) : String :=
  let h := CryptWalker.Util.Bytes.ofVector (CryptWalker.Hash.Blake2s.hash pub)
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
  CryptWalker.Util.Bytes.ofVector (CryptWalker.Hash.Blake2s.hashKeyed salt hostId.toUTF8)

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

def readPrivate (path : System.FilePath) : IO KeyPair := do
  IO.ofExcept ((keyPairOfSeed (← IO.FS.readBinFile path)).mapError fun e => IO.userError s!"{path}: {e}")

def homeDir : IO System.FilePath := do
  let some home ← IO.getEnv "HOME" | throw (IO.userError "HOME is not set")
  return home

def huhDir : IO System.FilePath := return (← homeDir) / ".huh"

end Huh
