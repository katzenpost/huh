import Tests.Util

open Huh Uproar

namespace Tests.Keys

def seed (b : UInt8) : ByteArray := ByteArray.mk (Array.replicate 32 b)

/-- Small Argon2id parameters, so the tests stay fast. -/
def tinyKdf : KdfParams := { memoryKiB := 8, passes := 1, lanes := 1 }

def contains (s pat : String) : Bool := (s.splitOn pat).length > 1

def flip (b : ByteArray) (i : Nat) : ByteArray := b.set! i (b.get! i ^^^ 1)

def encrypted (t : Suite) : IO Unit := do
  let salt := ByteArray.mk (Array.replicate 16 9)
  let nonce := ByteArray.mk (Array.replicate 12 8)
  let .ok file := encryptSeed tinyKdf salt nonce "hunter2" (seed 1)
    | t.expect false "encrypt a seed"
  t.expect (file.size == encryptedKeyLen) "encrypted key size"
  t.expect (decryptSeed file "hunter2" == .ok (seed 1)) "decrypt with the passphrase"
  t.expect (!(decryptSeed file "hunter3").toBool) "wrong passphrase"
  t.expect (!(decryptSeed file "").toBool) "empty passphrase"
  for (i, what) in [(3, "magic"), (8, "memory"), (12, "passes"), (25, "salt"), (40, "nonce"),
                    (50, "ciphertext"), (encryptedKeyLen - 1, "tag")] do
    t.expect (!(decryptSeed (flip file i) "hunter2").toBool) s!"flipped bit in the {what}"
  t.expect (!(decryptSeed (file.extract 0 (file.size - 1)) "hunter2").toBool) "truncated"
  -- 2 GiB: refused before Argon2 runs, or this test would take a long time
  let big := (file.set! 8 0).set! 9 0 |>.set! 10 0x20 |>.set! 11 0
  t.expect (match decryptSeed big "hunter2" with
    | .error e => contains e "too much" | .ok _ => false) "too much memory asked for"
  let lanes := (file.set! 16 0).set! 17 1
  t.expect (!(decryptSeed lanes "hunter2").toBool) "too many lanes"
  t.expect (match parseKeyFile (seed 1) with | .ok (.plain s) => s == seed 1 | _ => false)
    "a 32-byte file is a plain key"
  t.expect (match parseKeyFile file with | .ok (.encrypted _) => true | _ => false)
    "an encrypted key file"
  t.expect (!(parseKeyFile (ByteArray.mk (Array.replicate 33 0))).toBool) "not a key file"
  let answers ← IO.mkRef ["nope", "hunter2"]
  let ask : IO String := do
    let a ← answers.get
    answers.set a.tail
    return a.headD ""
  let warned ← IO.mkRef 0
  let kp ← unlockWith file ask (fun _ => warned.modify (· + 1))
  t.expect (some kp.pub == ((keyPairOfSeed (seed 1)).toOption.map (·.pub)) && (← warned.get) == 1)
    "unlock on the second attempt"
  answers.set ["a", "b", "c", "hunter2"]
  t.throws "three wrong passphrases" (unlockWith file ask (fun _ => pure ()))

def names (t : Suite) : IO Unit := do
  t.expect (privatePath "x" == "x.private") "privatePath appends .private"
  t.expect (privatePath "d/x.private" == "d/x.private") "privatePath keeps .private"
  t.expect (publicPath "d/x.private" == "d/x.pub") "publicPath"
  t.expect ((checkPrivateName "d/x.private").toBool) ".private name accepted"
  t.expect (!(checkPrivateName "d/x").toBool) "name without .private refused"
  t.expect (!(checkPrivateName "d/x.pub").toBool) ".pub name refused"

def files (t : Suite) : IO Unit := do
  let dir ← IO.FS.createTempDir
  let .ok enc := encryptSeed tinyKdf (ByteArray.mk (Array.replicate 16 9))
      (ByteArray.mk (Array.replicate 12 8)) "pw" (seed 2)
    | t.expect false "encrypt a seed"
  IO.FS.writeBinFile (dir / "plain.private") (seed 1)
  IO.FS.writeBinFile (dir / "enc.private") enc
  IO.FS.writeBinFile (dir / "old") (seed 1)
  let hk ← readHostKey (dir / "plain.private")
  t.expect (some hk.pub == ((keyPairOfSeed (seed 1)).toOption.map (·.pub))) "read a host key"
  match ← (readHostKey (dir / "enc.private")).toBaseIO with
  | .error e => t.expect (contains (toString e) "host keys must not be encrypted") "encrypted host key"
  | .ok _ => t.expect false "encrypted host key refused"
  match ← (readKeyFile (dir / "old.private")).toBaseIO with
  | .error e => t.expect (contains (toString e) "mv ") "old key name: say how to rename"
  | .ok _ => t.expect false "old key name refused"
  t.throws "key file without .private" (readKeyFile (dir / "old"))
  IO.FS.removeDirAll dir

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
  -- QUIC pins
  let pin := seed 9
  t.expect (parsePin (pinField pin) == some pin) "pin field round trip"
  for bad in ["quic-mldsa65=00", "quic-mldsa65=zz", "quic-ed25519=" ++ (pinField pin).drop 13, "alice@laptop"] do
    t.expect (parsePin bad == none) s!"bad pin field {bad.quote}"
  t.expect (match fields (hostPublicLine a.pub pin "host") with
    | [alg, hex, p, "host"] => parsePublic alg hex == some a.pub && parsePin p == some pin
    | _ => false) "host public line round trip"
  t.expect (parseAuthorized (hostPublicLine a.pub pin) == [a.pub]) "a host public line is a public key"
  let pinned := String.intercalate "\n"
    [knownHostLine (seed 1) "h1:2222" a.pub pin, knownHostLine (seed 2) "h2:22" b.pub,
     "h3:22 " ++ hostPublicLine b.pub (seed 10) "comment", "h1:2222 " ++ hostPublicLine a.pub (seed 11)]
  t.expect (parseKnownHosts pinned == [(hashHost (seed 1) "h1:2222", a.pub), (hashHost (seed 2) "h2:22", b.pub),
    ("h3:22", b.pub), ("h1:2222", a.pub)]) "pinned known hosts parse"
  t.expect (hostPins pinned "h1:2222" == [pin, seed 11]) "pins for a host"
  t.expect (hostPins pinned "h2:22" == []) "no pin recorded"
  t.expect (hostPins pinned "h3:22" == [seed 10]) "plain host pin"
  t.expect (hostPins pinned "h4:22" == []) "unknown host has no pin"
  t.expect (checkHost pinned "h1:2222" a.pub == .known) "pinned host known"
  t.expect (checkHost pinned "h3:22" a.pub == .changed [3]) "pinned host changed"
  let fp := fingerprint a.pub
  t.expect (fp.startsWith "BLAKE2s:" && fp.length == 8 + 32) "fingerprint format"
  t.expect (fp == fingerprint a'.pub && fp != fingerprint b.pub) "fingerprint identifies the key"
  encrypted t
  names t
  files t
  t.finish

end Tests.Keys
