import Lake
open Lake DSL System

package huh where
  version := v!"0.2.0"
  description := "Secure remote shell based on PQ Noise"
  keywords := #["ssh", "remote-shell", "noise", "post-quantum", "cryptography"]
  license := "AGPL-3.0-only"
  leanOptions := #[⟨`pp.unicode.fun, true⟩, ⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

require uproar from git "https://github.com/katzenpost/uproar.git" @ "2fcd8cee8d843b75645d6766f207d5d4f6613d4a"

-- Directly, for Argon2 (Cryptlib.Primitives.KDF.Argon2), and at lean_tls's revision for ML-DSA-65.
require cryptlib from git "https://github.com/katzenpost/cryptlib.git" @ "afb26ca42f7e648f6b69b6559db17bfbf83b7f6a"

require lean_quic from git "https://github.com/katzenpost/lean_quic.git" @ "11a697a17e0ef18c9a8f9580369c2d7e8061a132"

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
