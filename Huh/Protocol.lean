/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Uproar.Suites

/-! # The huh protocol: pqXX over hybrid ML-KEM-768 + X25519 -/

namespace Huh

open Uproar

def kem : KEMFn := ⟨CryptWalker.KEM.kemMLKEMHedged768X25519, "MLKEM768HedgedX25519"⟩

def protocol : Protocol := ⟨Patterns.pqXX, .kem kem kem, Suites.chaChaPoly, Suites.blake2s⟩

def prologue : ByteArray := "huh/1".toUTF8

/-- Each direction rekeys after this many transport messages. -/
def rekeyInterval : Nat := 2 ^ 20

/-- The largest session message that fits in one transport message. -/
def maxPayload : Nat := maxMessageLen - 16

def handshakeTimeoutMs : UInt32 := 30000

end Huh
