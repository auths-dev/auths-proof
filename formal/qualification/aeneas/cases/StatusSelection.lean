import Auths.Verifier.StatusAnchorExamples
import Auths.Verifier.StatusExamples
-- Exact shipping selector components: first-rule lookup, freshness, and the
-- public port results against the independent specification. All-view source
-- statements require ordered listed scopes; constructor validity and evidence
-- authentication remain separate obligations.
#check Auths.StatusSelection.sequence_floor_refines
#check Auths.StatusSelection.approver_visibility_refines
#check Auths.StatusSelection.principal_method_approver_refines
#check Auths.StatusSelection.grant_method_approver_refines
#check Auths.StatusSelection.Examples.active_selected_horizon
#check Auths.StatusSelection.Examples.rollback_despite_newer
#check Auths.StatusSelection.Examples.newer_discards_old_stale_revocation
#check Auths.StatusSelection.Examples.latest_ties_conservatively_revoke

#check Auths.StatusSelection.Search.search_loop
#check Auths.StatusSelection.Search.scope_contains
#check Auths.StatusSelection.visibility_refines
#check Auths.StatusSelection.principal_method_all_views
#check Auths.StatusSelection.grant_method_all_views
#check Auths.StatusSelection.AnchorExamples.first_listed_anchor
#check Auths.StatusSelection.AnchorExamples.last_listed_anchor
#check Auths.StatusSelection.AnchorExamples.unlisted_anchor_refused
#check Auths.StatusSelection.AnchorExamples.own_anchor_active
#check Auths.StatusSelection.AnchorExamples.other_anchor_hidden
