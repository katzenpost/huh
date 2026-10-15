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
  -- hashed host names
  let salt := seed 7
  let hashed := hashHost salt "h1:2222"
  t.expect (hashed.startsWith "|b2|" && (hashed.splitOn "h1").length == 1) "hashed host hides the name"
  t.expect (hostMatches hashed "h1:2222") "hashed host matches its name"
  t.expect (!hostMatches hashed "h1:2223" && !hostMatches hashed "h2:2222") "hashed host matches nothing else"
  t.expect (hashHost (seed 8) "h1:2222" != hashed) "salt changes the hash"
  t.expect (hostMatches "h1:2222" "h1:2222" && !hostMatches "h1:2222" "h1:22") "plain host"
  for bad in ["|b2|zz|00", "|b2|" ++ (hashed.splitOn "|")[3]!, "|b2|00|" ++ (hashed.splitOn "|")[3]!,
              "|b2||", "|1|abc|def"] do
    t.expect (!hostMatches bad "h1:2222") s!"malformed hashed host {bad.quote}"
  let line := knownHostLine salt "h1:2222" a.pub
  t.expect (parseKnownHosts line == [(hashed, a.pub)]) "known host line round trip"
  let file := String.intercalate "\n"
    ["# mine", knownHostLine (seed 1) "h1:2222" a.pub, "h2:22 " ++ publicLine b.pub, "",
     knownHostLine (seed 2) "h3:22" a.pub, "h3:22 " ++ publicLine a.pub]
  t.expect ((knownHostEntries file).map (·.1) == [2, 3, 5, 6]) "known host line numbers"
  t.expect (checkHost file "h1:2222" a.pub == .known) "hashed host known"
  t.expect (checkHost file "h2:22" b.pub == .known) "plain host known"
  t.expect (checkHost file "h1:2222" b.pub == .changed [2]) "hashed host changed"
  t.expect (checkHost file "h3:22" b.pub == .changed [5, 6]) "host changed on every line"
  t.expect (checkHost file "h4:22" a.pub == .unknown) "unknown host"
  t.expect (checkHost "" "h1:2222" a.pub == .unknown) "empty known hosts"
  let fp := fingerprint a.pub
  t.expect (fp.startsWith "BLAKE2s:" && fp.length == 8 + 32) "fingerprint format"
  t.expect (fp == fingerprint a'.pub && fp != fingerprint b.pub) "fingerprint identifies the key"
  t.finish

end Tests.Keys
