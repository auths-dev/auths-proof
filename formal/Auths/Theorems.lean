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
    "binary_composition_swap_invariant",
    "canonical_diagnostic_permutation_invariant",
    "plan_visit_is_leaf_enumeration",
    "plan_cost_is_node_count",
    "authorized_implies_threshold_met",
    "denied_implies_threshold_impossible",
    "indeterminate_implies_threshold_reachable"
  ]

end Auths
