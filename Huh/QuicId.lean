/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.Keys
import LeanTLS.X509
import LeanTLS.KeySchedule

/-! # A host's QUIC identity

QUIC's TLS handshake authenticates the server with ML-DSA-65. The signing key seed is derived from
the host key seed, so one key file holds both identities:
`ξ = BLAKE2s(key = host seed, "huh/1 quic mldsa65")`. Clients pin the SHA-256 of the key's
SubjectPublicKeyInfo, which stays the same as the certificate is reissued. -/

namespace Huh.QuicId

open Cryptlib.Util.Bytes (ofVector)

def signingSeed (hostSeed : ByteArray) : Vector UInt8 32 :=
  Cryptlib.Primitives.Hash.Blake2s.hashKeyed hostSeed "huh/1 quic mldsa65".toUTF8

def publicKey (hostSeed : ByteArray) : ByteArray :=
  match LeanTLS.Handshake.Scheme.mldsa65.authKey (signingSeed hostSeed) with
  | .mldsa65 key => key
  | .ed25519 key => ofVector key

def pin (hostSeed : ByteArray) : ByteArray :=
  LeanTLS.KeySchedule.hash (LeanTLS.X509.mldsa65Spki (publicKey hostSeed))

end Huh.QuicId
