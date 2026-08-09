import qualification.aeneas.generated.algebra.Funs

open Aeneas Aeneas.Std Result
open auths_algebra_kernel

private def accepted : generated.AttenuationChecks where
  root_preserved := true
  depth_decreases := true
  profile_attenuates := true
  permissions_attenuate := true
  validity_attenuates := true
  audiences_attenuate := true
  action_constraint_attenuates := true
  budget_attenuates := true
  status_attenuates := true
  assurance_attenuates := true
  extensions_attenuate := true

example : generated.attenuation_checks_accept accepted = ok true := by
  rfl

example :
    generated.attenuation_checks_accept
      { accepted with permissions_attenuate := false } = ok false := by
  rfl
