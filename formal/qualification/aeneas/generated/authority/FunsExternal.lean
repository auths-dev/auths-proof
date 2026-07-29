-- REVIEWED TRANSPARENT LINKS FOR AENEAS-GENERATED PRODUCTION AUTHORITY CODE.
--
-- Every rich leaf predicate below is imported from the mechanically
-- translated `auths-model` production source. The sole local definition is
-- the ten-field conjunction generated from `formal/algebra-contract-v1.toml`;
-- `cargo xtask formal` rejects drift from that contract.
import Aeneas
import qualification.aeneas.generated.authority.Types
import qualification.aeneas.generated.model.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false
set_option maxHeartbeats 1000000
set_option maxRecDepth 2048

open auths_authority

@[rust_fun "auths_algebra_kernel::generated::attenuation_checks_accept"]
def auths_algebra_kernel.generated.attenuation_checks_accept
(checks : auths_algebra_kernel.generated.AttenuationChecks) : Result Bool := do
  if checks.root_preserved then
    if checks.depth_decreases then
      if checks.profile_attenuates then
        if checks.permissions_attenuate then
          if checks.validity_attenuates then
            if checks.audiences_attenuate then
              if checks.action_constraint_attenuates then
                if checks.budget_attenuates then
                  if checks.status_attenuates then
                    ok checks.assurance_attenuates
                  else ok false
                else ok false
              else ok false
            else ok false
          else ok false
        else ok false
      else ok false
    else ok false
  else ok false
