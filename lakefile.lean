import Lake
open Lake DSL System

package huh where
  version := v!"0.2.0"
  description := "Secure remote shell based on PQ Noise"
  keywords := #["ssh", "remote-shell", "noise", "post-quantum", "cryptography"]
  license := "AGPL-3.0-only"
  leanOptions := #[⟨`pp.unicode.fun, true⟩, ⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

require uproar from git "https://github.com/katzenpost/uproar.git" @ "c9f471ecbeb6c80809aafe50c7d3bce6e4a8791c"

-- Directly, for Argon2 (Cryptlib.Primitives.KDF.Argon2), and at lean_tls's revision for ML-DSA-65.
require cryptlib from git "https://github.com/katzenpost/cryptlib.git" @ "e5419ef812c1b5f59c9e96cb59b402a54a534fdb"

require lean_quic from git "https://github.com/katzenpost/lean_quic.git" @ "2e81d8b05306115c2706f2a1c7e2523428a7c635"

@[default_target]
lean_lib Huh

lean_lib Tests

target huh_ffi.o pkg : FilePath := do
  let src ← inputTextFile (pkg.dir / "c" / "huh_ffi.c")
  buildO (pkg.buildDir / "c" / "huh_ffi.o") src
    #["-I", (← getLeanIncludeDir).toString] #["-fPIC", "-O2", "-Wall", "-D_GNU_SOURCE"]

extern_lib huhffi pkg := do
  buildStaticLib (pkg.staticLibDir / nameToStaticLib "huhffi") #[← huh_ffi.o.fetch]

lean_exe huh where
  root := `Main.Huh

lean_exe huhd where
  root := `Main.Huhd

lean_exe «huh-keygen» where
  root := `Main.Keygen

lean_exe «huh-test» where
  root := `Tests.Main

lean_exe «huh-pty-test» where
  root := `Tests.PtyE2E
