import Auths.Refinement.Production
import qualification.aeneas.generated.model.Funs

/-!
# The translated bounded-policy link leaves refine their model

`digest_equal` and `bounded_policy_link_accepts` of
`auths_model::bounded_policy` are translated by the pinned Charon/Aeneas
route. Each theorem here states that a translated function terminates with
`ok` and returns exactly its model's result under an abstraction that maps a
digest to the natural-number values of its bytes. No theorem carries a
premise: a digest is a fixed 32-byte array.
-/

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP

namespace Auths.Product.Refinement.BoundedPolicy

/-- The byte values of a digest. -/
def digestBytes (digest : auths_model.Digest) : List Nat :=
  digest.val.map (·.val)

/-- The parent-link rule of the bounded-policy commitment extension over
digest bytes. A child that keeps the extension links exactly its parent's
extension digest; a child that adds the extension under an unbounded parent
carries no link. -/
def boundedPolicyLinkAccepts : Option (List Nat) → Option (List Nat) → Bool
  | some childLink, some parentDigest => decide (childLink = parentDigest)
  | some _, none => false
  | none, parentDigest => parentDigest.isNone

theorem digestBytes_eq_iff (left right : auths_model.Digest) :
    digestBytes left = digestBytes right ↔ left.val = right.val := by
  constructor
  · intro same
    apply List.map_injective_iff.mpr _ same
    intro first second sameValue
    exact UScalar.eq_of_val_eq sameValue
  · intro same
    simp [digestBytes, same]

@[step] theorem digest_equal_spec (left right : auths_model.Digest) :
    auths_model.bounded_policy.digest_equal left right
      ⦃ result => result = decide (digestBytes left = digestBytes right) ⦄ := by
  unfold auths_model.bounded_policy.digest_equal auths_model.Digest.as_bytes
  simp only [bind_tc_ok, Array.to_slice, lift]
  apply WP.spec_mono (Auths.Refinement.byte_slices_equal_spec _ _)
  intro result resultIff
  rw [Auths.Refinement.slice_eq_iff_val_eq] at resultIff
  simp only [digestBytes_eq_iff]
  cases result <;> simp_all

/-- Digest comparison is equality of the digests' byte values. -/
theorem translated_digest_equal_refines_model (left right : auths_model.Digest) :
    auths_model.bounded_policy.digest_equal left right =
      ok (decide (digestBytes left = digestBytes right)) := by
  obtain ⟨result, isOk, equal⟩ := spec_imp_exists (digest_equal_spec left right)
  rw [isOk, equal]

/-- The translated parent-link check is `boundedPolicyLinkAccepts` on the
digests' byte values. -/
theorem translated_bounded_policy_link_accepts_refines_model
    (childLink parentDigest : Option auths_model.Digest) :
    auths_model.bounded_policy.bounded_policy_link_accepts childLink parentDigest =
      ok (boundedPolicyLinkAccepts (childLink.map digestBytes)
        (parentDigest.map digestBytes)) := by
  unfold auths_model.bounded_policy.bounded_policy_link_accepts
  cases childLink with
  | none =>
      cases parentDigest <;> rfl
  | some childLink =>
      cases parentDigest with
      | none => rfl
      | some parentDigest =>
          exact translated_digest_equal_refines_model childLink parentDigest

end Auths.Product.Refinement.BoundedPolicy
