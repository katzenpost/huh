import Tests.Util

open Huh

namespace Tests.Frame

def streamOf (data : ByteArray) : IO (IO.FS.Stream × IO.Ref IO.FS.Stream.Buffer) := do
  let r ← IO.mkRef ({ data } : IO.FS.Stream.Buffer)
  return (IO.FS.Stream.ofBuffer r, r)

def run : IO Nat := do
  let t ← Suite.new "frame"
  let (s, r) ← streamOf ByteArray.empty
  writeFrame s (bytes "abc")
  t.expect ((← r.get).data == ByteArray.mk #[0, 3, 97, 98, 99]) "writeFrame layout"
  writeFrame s ByteArray.empty
  let big := ByteArray.mk (Array.replicate 65535 9)
  writeFrame s big
  t.throws "frame of 65536 bytes" (writeFrame s (ByteArray.mk (Array.replicate 65536 9)))
  let (s, _) ← streamOf (← r.get).data
  t.expect ((← readFrame s) == some (bytes "abc")) "first frame"
  t.expect ((← readFrame s) == some ByteArray.empty) "empty frame"
  t.expect ((← readFrame s) == some big) "largest frame"
  t.expect ((← readFrame s) == none) "end of stream"
  let (s, _) ← streamOf (ByteArray.mk #[0])
  t.throws "truncated header" (readFrame s)
  let (s, _) ← streamOf (ByteArray.mk #[0, 5, 1, 2])
  t.throws "truncated body" (readFrame s)
  let (s, _) ← streamOf (ByteArray.mk #[0, 0, 0, 1, 7])
  t.expect ((← readFrame s) == some ByteArray.empty) "zero-length frame then more"
  t.expect ((← readFrame s) == some (ByteArray.mk #[7])) "frame after a zero-length one"
  t.finish

end Tests.Frame
