/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.Msg

/-! # Decoding inverts encoding -/

namespace Huh

open ByteArray

namespace Dec

theorem bind_apply {α β} (m : Dec α) (f : α → Dec β) (b : ByteArray) :
    (m >>= f) b = (m b).bind fun (a, rest) => f a rest := rfl

theorem pure_apply {α} (a : α) (b : ByteArray) : (pure a : Dec α) b = some (a, b) := rfl

theorem u8_append (v : UInt8) (r : ByteArray) : u8 (Enc.u8 v ++ r) = some (v, r) := by
  have hs : (Enc.u8 v).size = 1 := rfl
  have h0 : 0 < (Enc.u8 v ++ r).size := by rw [size_append, hs]; omega
  simp only [u8, h0, dite_true, Option.some.injEq, Prod.mk.injEq]
  refine ⟨?_, extract_append_eq_right hs.symm (by simp [size_append])⟩
  rw [getElem_append_left (by simp [hs])]
  rfl

theorem u16_append (v : UInt16) (r : ByteArray) : u16 (Enc.u16 v ++ r) = some (v, r) := by
  have : Enc.u16 v ++ r = Enc.u8 (UInt8.ofNat (v.toNat / 256)) ++
      (Enc.u8 (UInt8.ofNat (v.toNat % 256)) ++ r) := by
    rw [← append_assoc]; rfl
  simp only [u16, bind_apply, this, u8_append, Option.bind_some, pure_apply, Option.some.injEq,
    Prod.mk.injEq, and_true]
  have hv := v.toNat_lt
  apply UInt16.toNat_inj.mp
  simp only [UInt16.toNat_ofNat', UInt8.toNat_ofNat']
  omega

theorem take_append (x r : ByteArray) : take x.size (x ++ r) = some (x, r) := by
  simp [take, size_append, extract_append_eq_left, extract_append_eq_right]

theorem bytes16_append (x r : ByteArray) (h : x.size < 2 ^ 16) :
    bytes16 (Enc.bytes16 x ++ r) = some (x, r) := by
  have hn : (UInt16.ofNat x.size).toNat = x.size := by
    simp only [UInt16.toNat_ofNat']; omega
  simp only [bytes16, Enc.bytes16, bind_apply, append_assoc, u16_append, Option.bind_some, hn,
    take_append]

theorem rest_append (x : ByteArray) : rest x = some (x, ByteArray.empty) := rfl

theorem eof_empty : eof ByteArray.empty = some ((), ByteArray.empty) := rfl

theorem flag_append (v : Bool) (r : ByteArray) : flag (Enc.flag v ++ r) = some (v, r) := by
  cases v <;> simp [flag, Enc.flag, bind_apply, u8_append] <;> rfl

theorem opt_append {α} (d : Dec α) (e : α → ByteArray) (P : α → Prop)
    (hd : ∀ a r, P a → d (e a ++ r) = some (a, r)) (o : Option α) (r : ByteArray)
    (ho : ∀ a ∈ o, P a) : opt d (Enc.opt e o ++ r) = some (o, r) := by
  cases o with
  | none => simp [opt, Enc.opt, bind_apply, flag_append, pure_apply]
  | some a =>
    simp only [opt, Enc.opt, bind_apply, append_assoc, flag_append, Option.bind_some, ↓reduceIte,
      Functor.map]
    rw [hd a r (ho a rfl)]
    rfl

end Dec

theorem self_of_append {α} {d : Dec α} {e : ByteArray} {a : α}
    (h : d (e ++ ByteArray.empty) = some (a, ByteArray.empty)) : d e = some (a, ByteArray.empty) := by
  rwa [append_empty] at h

namespace Msg

open Dec

theorem decoder_tag (t : UInt8) (r : ByteArray) : decoder (Enc.u8 t ++ r) = body t r := by
  simp [decoder, bind_apply, u8_append]

theorem ptyReq_append (p : PtyReq) (r : ByteArray) (h : p.term.size < 2 ^ 16) :
    PtyReq.decode (p.encode ++ r) = some (p, r) := by
  simp only [PtyReq.decode, PtyReq.encode, bind_apply, append_assoc, bytes16_append _ _ h,
    Option.bind_some, u16_append, pure_apply]

theorem decode_encode (m : Msg) (h : m.WellFormed) : decode m.encode = some m := by
  cases m with
  | open_ pty cmd =>
    obtain ⟨hp, hc⟩ := h
    have hcmd := self_of_append (opt_append _ _ _ (fun a r h => bytes16_append a r h) cmd _ hc)
    simp only [decode, encode, append_assoc, decoder_tag, body, bind_apply,
      opt_append _ _ _ (fun p r h => ptyReq_append p r h) pty _ hp, Option.bind_some, hcmd]
    rfl
  | stdin d | stdout d | stderr d => simp [decode, encode, decoder_tag, body, bind_apply] <;> rfl
  | stdinEof => rfl
  | windowChange r c =>
    have hc := self_of_append (u16_append c ByteArray.empty)
    simp only [decode, encode, append_assoc, decoder_tag, body, bind_apply, u16_append,
      Option.bind_some, hc]
    rfl
  | signal n =>
    have hn := self_of_append (bytes16_append n ByteArray.empty h)
    simp only [decode, encode, decoder_tag, body, bind_apply, hn, Option.bind_some]
    rfl
  | exit s =>
    cases s with
    | code c =>
      have hc := self_of_append (u8_append c ByteArray.empty)
      simp only [decode, encode, append_assoc, decoder_tag, body, bind_apply, u8_append,
        Option.bind_some, exitBody, hc]
      rfl
    | signal n =>
      have hn := self_of_append (bytes16_append n ByteArray.empty h)
      simp only [decode, encode, append_assoc, decoder_tag, body, bind_apply, u8_append,
        Option.bind_some, exitBody, hn]
      rfl

end Msg

end Huh
