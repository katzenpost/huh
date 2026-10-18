/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh
import LeanBench

/-! # huh's own work per data message

Each bench handles one full data message, `maxData` bytes, which is what `huh` sends per frame
when piping a file. Cryptography is benchmarked in uproar and Cryptlib. Inputs are read from
refs so the compiler cannot hoist the work out of the timed action. -/

open Huh

def cfg : LeanBench.BenchConfig := { suite := some "huh", samples := 20, warmup := 2 }

def data : ByteArray := ByteArray.mk (Array.ofFn fun (i : Fin maxData) => (i.val * 7 % 251).toUInt8)

/-- Split input into data messages, as the stdin and output pumps do. -/
def chunks (b : ByteArray) : Array ByteArray := Id.run do
  let mut out := #[]
  let mut i := 0
  while i < b.size do
    out := out.push (b.extract i (i + maxData))
    i := i + maxData
  return out

def main (args : List String) : IO UInt32 := do
  let out ← IO.mkRef ByteArray.empty
  let sink (b : ByteArray) : IO Unit := out.set b
  let input ← IO.mkRef data
  let encoded ← IO.mkRef (Msg.stdout data).encode
  let framed ← IO.mkRef ByteArray.empty
  let mib ← IO.mkRef (ByteArray.mk (Array.replicate (1024 * 1024) 7))
  let outbox : Std.CloseableChannel.Sync Msg ← Std.CloseableChannel.Sync.new
  let benches : Array LeanBench.Bench := #[
    { name := "Msg.encode 64KB", config := cfg,
      action := do sink (Msg.stdout (← input.get)).encode },
    { name := "Msg.decode 64KB", config := cfg,
      action := do
        sink (match Msg.decode (← encoded.get) with | some (.stdout d) => d | _ => ByteArray.empty) },
    { name := "writeFrame 64KB", config := cfg,
      action := do
        let r ← IO.mkRef ({} : IO.FS.Stream.Buffer)
        writeFrame (IO.FS.Stream.ofBuffer r) (← encoded.get)
        framed.set (← r.get).data },
    { name := "readFrame 64KB", config := cfg,
      setup? := some do
        let r ← IO.mkRef ({} : IO.FS.Stream.Buffer)
        writeFrame (IO.FS.Stream.ofBuffer r) (← encoded.get)
        framed.set (← r.get).data
      action := do
        let r ← IO.mkRef ({ data := ← framed.get } : IO.FS.Stream.Buffer)
        sink ((← readFrame (IO.FS.Stream.ofBuffer r)).getD ByteArray.empty) },
    { name := "chunk 1MiB into data messages", config := cfg,
      action := do sink ((chunks (← mib.get)).back?.getD ByteArray.empty) },
    { name := "outbox send+recv 64KB", config := cfg,
      action := do
        outbox.send (.stdout (← input.get))
        match ← outbox.recv with
        | some (.stdout d) => sink d
        | _ => pure () }]
  benches.forM LeanBench.register
  LeanBench.runMain args
