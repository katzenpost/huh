/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.Protocol
import CryptWalker.Util.newhex
import CryptWalker.Hash.Blake2s

/-! # Key files

A private key file holds the 32-byte seed the key pair is derived from. Public keys are written
one per line as `huh-mlkem768hx25519 <hex> [comment]`; a known-hosts line puts `host:port`
first. -/

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

def parseKnownHosts (text : String) : List (String × ByteArray) :=
  (contentLines text).filterMap fun l =>
    match fields l with
    | host :: alg :: hex :: _ => (host, ·) <$> parsePublic alg hex
    | _ => none

def readTextOrEmpty (path : System.FilePath) : IO String := do
  if ← path.pathExists then IO.FS.readFile path else pure ""

def readPrivate (path : System.FilePath) : IO KeyPair := do
  IO.ofExcept ((keyPairOfSeed (← IO.FS.readBinFile path)).mapError fun e => IO.userError s!"{path}: {e}")

def homeDir : IO System.FilePath := do
  let some home ← IO.getEnv "HOME" | throw (IO.userError "HOME is not set")
  return home

def huhDir : IO System.FilePath := return (← homeDir) / ".huh"

end Huh
