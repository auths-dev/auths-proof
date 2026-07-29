import qualification.aeneas.generated.authority.Funs

open Aeneas Aeneas.Std Result
open auths_authority

-- This file deliberately imports the complete translated delegation and
-- terminal-coverage evaluators. The runner additionally checks their
-- translation inventories and executes the matching production Rust boundary
-- corpus. Keeping this as its own import closure avoids conflating Aeneas'
-- crate-local copy of the algebra carrier with the standalone algebra case.

#check evaluate_grant_view
#check evaluate_action_coverage_view
#check DelegationOutcome.Accepted
#check DelegationOutcome.Denied
#check CoverageDecision.Authorized
#check CoverageDecision.Denied
