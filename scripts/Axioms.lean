import Huh

open Lean Elab Command

-- Every theorem in a `Huh` module may depend only on Lean's own axioms.
#eval show CommandElabM Unit from do
  let env ← getEnv
  let allowed := [``propext, ``Classical.choice, ``Quot.sound]
  let mut checked : Nat := 0
  let mut bad : Array (Name × Name) := #[]
  for (name, ci) in env.constants.toList do
    let some idx := env.getModuleIdxFor? name | continue
    unless (`Huh).isPrefixOf (env.header.moduleNames[idx.toNat]!) do continue
    let .thmInfo _ := ci | continue
    checked := checked + 1
    for a in ← liftCoreM (collectAxioms name) do
      unless allowed.contains a do bad := bad.push (name, a)
  for (n, a) in bad do logError m!"{n} depends on {a}"
  if bad.isEmpty then logInfo m!"{checked} theorems depend on Lean's own axioms only"
