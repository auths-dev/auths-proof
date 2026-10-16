import Auths.Verifier.StatusExamples
-- Exact shipping selector components: first-rule lookup, freshness, and the
-- public principal/grant port result under the approval view. The independent
-- filter/max relation and anchor views remain separate obligations.
#check Auths.StatusSelection.sequence_floor_refines
#check Auths.StatusSelection.approver_visibility_refines
#check Auths.StatusSelection.principal_method_approver_refines
#check Auths.StatusSelection.grant_method_approver_refines
#check Auths.StatusSelection.Examples.active_selected_horizon
#check Auths.StatusSelection.Examples.rollback_despite_newer
#check Auths.StatusSelection.Examples.newer_discards_old_stale_revocation
#check Auths.StatusSelection.Examples.latest_ties_conservatively_revoke
