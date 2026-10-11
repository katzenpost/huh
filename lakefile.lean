import Lake
open Lake DSL System

package huh where
  leanOptions := #[⟨`pp.unicode.fun, true⟩, ⟨`autoImplicit, false⟩, ⟨`relaxedAutoImplicit, false⟩]

require uproar from git "https://github.com/katzenpost/uproar.git" @ "noise"

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
