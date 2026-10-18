import Lake
open Lake DSL System

package huh where
  version := v!"0.1.0"
  description := "Secure remote shell based on PQ Noise"
  keywords := #["ssh", "remote-shell", "noise", "post-quantum", "cryptography"]
  license := "AGPL-3.0-only"
  leanOptions := #[⟨`pp.unicode.fun, true⟩, ⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

require uproar from git "https://github.com/katzenpost/uproar.git" @ "3d107803c9685c250553a2ee05119d517d507572"

-- Directly, for Argon2 (Cryptlib.Primitives.KDF.Argon2), which uproar's pinned revision predates.
require cryptlib from git "https://github.com/katzenpost/cryptlib.git" @ "6f651738d26db5ac18dd5670bf501cfc63723175"

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
