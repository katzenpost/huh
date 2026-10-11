import Tests.Util

open Huh Uproar

namespace Tests.Keys

def seed (b : UInt8) : ByteArray := ByteArray.mk (Array.replicate 32 b)

def run : IO Nat := do
  let t ← Suite.new "keys"
  t.expect (!(keyPairOfSeed (ByteArray.mk (Array.replicate 31 0))).toBool) "31-byte seed"
  let some a := (keyPairOfSeed (seed 1)).toOption | t.expect false "32-byte seed"; t.finish
  let some a' := (keyPairOfSeed (seed 1)).toOption | t.expect false "32-byte seed again"; t.finish
  let some b := (keyPairOfSeed (seed 2)).toOption | t.expect false "second seed"; t.finish
  t.expect (a.pub.size == kem.pubLen) "public key size"
  t.expect (a.pub == a'.pub && a.priv == a'.priv) "deterministic"
  t.expect (a.pub != b.pub) "different seeds, different keys"
  let line := publicLine a.pub "alice@laptop"
  t.expect (match fields line with
    | [alg, hex, "alice@laptop"] => parsePublic alg hex == some a.pub
    | _ => false) "public line round trip"
  t.expect ((fields (publicLine a.pub)).length == 2) "public line without comment"
  t.expect (parsePublic "ssh-ed25519" (fields line)[1]! == none) "wrong algorithm"
  t.expect (parsePublic algorithm "zz" == none) "bad hex"
  t.expect (parsePublic algorithm "0011" == none) "short key"
  let authorized := String.intercalate "\n"
    ["# comment", "", publicLine a.pub "a", "   ", "garbage line", publicLine b.pub,
     "ssh-rsa AAAA x", "  " ++ publicLine a.pub "indented"]
  t.expect (parseAuthorized authorized == [a.pub, b.pub, a.pub]) "authorized keys"
  let known := String.intercalate "\n"
    ["h1:2222 " ++ publicLine a.pub, "# h2:2222 " ++ publicLine b.pub, "h3:22 " ++ publicLine b.pub,
     "h4:22 nonsense"]
  t.expect (parseKnownHosts known == [("h1:2222", a.pub), ("h3:22", b.pub)]) "known hosts"
  let fp := fingerprint a.pub
  t.expect (fp.startsWith "BLAKE2s:" && fp.length == 8 + 32) "fingerprint format"
  t.expect (fp == fingerprint a'.pub && fp != fingerprint b.pub) "fingerprint identifies the key"
  t.finish

end Tests.Keys
