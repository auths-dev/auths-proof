import Auths.Attenuation
import Auths.Composition
import Auths.Diversity

namespace Auths

def theoremInventory : List String :=
  [
    "attenuation_refl",
    "attenuation_trans",
    "attenuation_antisymm",
    "coverage_downward_closed",
    "delegate_preserves_root",
    "delegate_updates_subject",
    "attenuation_kernel_refines",
    "delegate_strict_depth",
    "finite_chain",
    "delegate_never_widens",
    "chain_transitive_attenuation",
    "authorized_action_covered",
    "all_commutative",
    "all_associative",
    "all_idempotent",
    "any_commutative",
    "any_associative",
    "any_idempotent",
    "threshold_one_eq_any",
    "threshold_n_eq_all",
    "threshold_monotone_k",
    "composition_permutation_invariant",
    "canonical_diagnostic_permutation_invariant",
    "every_leaf_visited_once",
    "validated_plan_terminates",
    "evaluation_cost_linear_in_nodes",
    "authorized_implies_threshold_met",
    "denied_implies_threshold_impossible",
    "indeterminate_implies_threshold_reachable"
  ]

end Auths
