import Auths.Codec.RequirementKeys
import Auths.Codec.ProtocolReencoding
import Mathlib.Data.List.Sort
import Mathlib.Tactic

open Aeneas Aeneas.Std Result
open AuthsProtocolCodec

namespace Auths.Codec.CanonicalValues

/- Canonicalization has an independent normal-form relation. It does not
mean that an asserted flag is true or that an expected decoder/encoder call
succeeded. A digest key may have ties: these lemmas assume no injectivity of
the identifier function, and stable ordering retains the input order of ties. -/

section Model
variable {Value : Type} (identifier : Value → List Nat)

def ordered (left right : Value) : Prop := identifier left ≤ identifier right
instance order_decidable : DecidableRel (ordered identifier) := fun _ _ => inferInstanceAs (Decidable (_ ≤ _))
local instance : Std.Total (ordered identifier) := ⟨fun _ _ => le_total _ _⟩
local instance : IsTrans Value (ordered identifier) := ⟨fun _ _ _ left right => le_trans left right⟩

def normalize (values : List Value) : List Value := values.insertionSort (ordered identifier)

theorem normalize_permutation (values : List Value) : (normalize identifier values).Perm values :=
  List.perm_insertionSort _ _

theorem normalize_ordered (values : List Value) : (normalize identifier values).Pairwise (ordered identifier) :=
  List.pairwise_insertionSort _ _

theorem normalize_idempotent (values : List Value) :
    normalize identifier (normalize identifier values) = normalize identifier values :=
  List.Pairwise.insertionSort_eq (normalize_ordered identifier values)

theorem normal_form_iff (values : List Value) :
    normalize identifier values = values ↔ values.Pairwise (ordered identifier) := by
  constructor
  · intro same
    simpa only [same] using normalize_ordered identifier values
  · intro sorted
    exact List.Pairwise.insertionSort_eq sorted

theorem normalize_fields (predicate : Value → Prop) (values : List Value) :
    (∀ value ∈ normalize identifier values, predicate value) ↔ ∀ value ∈ values, predicate value := by
  have same := normalize_permutation identifier values
  constructor
  · intro valid value member
    exact valid value (same.mem_iff.mpr member)
  · intro valid value member
    exact valid value (same.mem_iff.mp member)

/-- Every requirement is retained, including multiplicity. This preserves
the independent conjunction meaning; diagnostics and work remain separate
actual-consumer obligations. -/
theorem normalize_preserves_conjunction {Action : Type} (requires : Value → Action → Prop)
    (values : List Value) (action : Action) :
    (∀ requirement ∈ normalize identifier values, requires requirement action) ↔
      ∀ requirement ∈ values, requires requirement action :=
  normalize_fields identifier (fun requirement => requires requirement action) values

end Model

/-- Both public projections return the same complete stored value. Rust
exposes no mutable projection or unchecked conversion into this carrier.
Well-formedness must still be earned by its concrete source constructor. -/
theorem projections_agree {Value : Type} (carrier : canonical_value.Canonical Value) :
    @canonical_value.Canonical.as_value Value carrier =
      @canonical_value.Canonical.into_value Value carrier := rfl

theorem projections_total {Value : Type} (carrier : canonical_value.Canonical Value) :
    ∃ value, @canonical_value.Canonical.as_value Value carrier = ok value ∧
      @canonical_value.Canonical.into_value Value carrier = ok value := by
  exact ⟨_, rfl, rfl⟩

variable [primitive : Auths.Crypto.Sha256Primitives]

/-- A source data-flow consequence, not a complete normalization or inverse
claim: actual construction contains actual identifier normalization and model
construction before the wrapper can be returned. Their ordering/validity and
the full byte inverse must be proved separately. -/
theorem approval_constructor_trace (input : auths_model.approval.ApprovalRequirements)
    (output : canonical_value.Canonical auths_model.approval.ApprovalRequirements)
    (accepted : canonical_value.Canonical.new input = ok (.Ok output)) :
    ∃ borrowed normalized value,
      auths_model.approval.ApprovalRequirements.as_slice input = ok borrowed ∧
      approval.normalize_requirement_values borrowed 4#usize = ok (.Ok normalized) ∧
      auths_model.approval.ApprovalRequirements.new normalized = ok (.Ok value) ∧
      canonical_value.Canonical.as_value output = ok value := by
  unfold canonical_value.Canonical.new at accepted
  simp only [Bind.bind, Aeneas.Std.bind] at accepted
  repeat' first
    | casesm* _ × _
    | dsimp only at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [uncurry, Bind.bind, Aeneas.Std.bind,
        core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from,
        bind_tc_ok, bind_tc_fail, bind_tc_div, Result.ok.injEq,
        core.result.Result.Ok.injEq, reduceCtorEq] at accepted
    | contradiction
  all_goals subst_vars
  all_goals simp only [canonical_value.Canonical.as_value]
  all_goals aesop

end Auths.Codec.CanonicalValues
