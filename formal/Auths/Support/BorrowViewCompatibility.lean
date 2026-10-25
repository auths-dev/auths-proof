import Auths.Support.NativePurePayload

/-!
Structural compatibility of a partial input with its current carrier. This
relation is independent of `put`/adapter success: partial sums must choose the
current alternative, products account for both components, and a whole owned
value may replace its alternative. No atom equality or supplied result is a
premise. Total reconstruction is conditional on this structural relation.

A Rust permission/loan interpretation must still show actual legitimate inputs
satisfy this relation. These scripts do not assert that bridge or erase the
representation helper's Result effect. All scripts await final elaboration.
-/
namespace Auths.Support.BorrowViewCompatibility
open SourceClosureRegions BorrowProjection
universe u

/-- An independently stated input invariant. `keep` owns a whole value;
`sum` retains the existing tag even if one branch selects no atomic fields. -/
def Compatible {Atom : Expr → Type u} : {shape : Shape} → (plan : Plan shape) →
    Data Atom shape → View Atom plan → Prop
  | _, .keep, _, _ => True
  | _, .skip, _, _ => True
  | _, .empty, current, _ => nomatch current
  | _, .product first second, .product left right, (one, two) =>
      Compatible first left one ∧ Compatible second right two
  | _, .sum first _, .left current, .inl incoming => Compatible first current incoming
  | _, .sum _ second, .right current, .inr incoming => Compatible second current incoming
  | _, .sum _ _, .left _, .inr _ => False
  | _, .sum _ _, .right _, .inl _ => False
  | _, .named contents, .named current, incoming => Compatible contents current incoming
  | _, .borrow contents, .borrow current, incoming => Compatible contents current incoming

/-- Reconstruct from supplied fields and the actual current carrier. A
compatibility proof supplies no atom, alternative, reference or ordinary result. -/
def restore {Atom : Expr → Type u} : {shape : Shape} → (plan : Plan shape) →
    (current : Data Atom shape) → (incoming : View Atom plan) →
    Compatible plan current incoming → Data Atom shape
  | _, .keep, _, incoming, _ => incoming
  | _, .skip, current, _, _ => current
  | _, .empty, current, _, _ => nomatch current
  | _, .product first second, .product left right, (one, two), valid =>
      .product (restore first left one valid.1) (restore second right two valid.2)
  | _, .sum first _, .left current, .inl incoming, valid => .left (restore first current incoming valid)
  | _, .sum _ second, .right current, .inr incoming, valid => .right (restore second current incoming valid)
  | _, .sum _ _, .left _, .inr _, invalid => False.elim invalid
  | _, .sum _ _, .right _, .inl _, invalid => False.elim invalid
  | _, .named contents, .named current, incoming, valid => .named (restore contents current incoming valid)
  | _, .borrow contents, .borrow current, incoming, valid => .borrow (restore contents current incoming valid)

theorem put_is_total_on_compatible {Atom : Expr → Type u} {shape : Shape}
    (plan : Plan shape) (current : Data Atom shape) (incoming : View Atom plan)
    (valid : Compatible plan current incoming) :
    put plan current incoming = some (restore plan current incoming valid) := by
  induction plan generalizing current incoming with
  | keep => rfl
  | skip => rfl
  | empty => cases current
  | product first second firstIH secondIH =>
      cases current with
      | product left right =>
          rcases incoming with ⟨one, two⟩
          simp [put, restore, firstIH left one valid.1, secondIH right two valid.2]
  | sum first second firstIH secondIH =>
      cases current with
      | left current =>
          cases incoming with
          | inl incoming => simpa [put, restore] using congrArg (Option.map Data.left) (firstIH current incoming valid)
          | inr _ => exact False.elim valid
      | right current =>
          cases incoming with
          | inl _ => exact False.elim valid
          | inr incoming => simpa [put, restore] using congrArg (Option.map Data.right) (secondIH current incoming valid)
  | named contents ih =>
      cases current with
      | named current => simpa [put, restore] using congrArg (Option.map Data.named) (ih current incoming valid)
  | borrow contents ih =>
      cases current with
      | borrow current => simpa [put, restore] using congrArg (Option.map Data.borrow) (ih current incoming valid)

theorem current_view_is_compatible {Atom : Expr → Type u} {shape : Shape}
    (plan : Plan shape) (current : Data Atom shape) : Compatible plan current (get plan current) := by
  induction plan generalizing current with
  | keep => trivial
  | skip => trivial
  | empty => cases current
  | product first second firstIH secondIH =>
      cases current with
      | product left right => exact ⟨firstIH left, secondIH right⟩
  | sum first second firstIH secondIH =>
      cases current with
      | left current => exact firstIH current
      | right current => exact secondIH current
  | named contents ih => cases current with | named current => exact ih current
  | borrow contents ih => cases current with | borrow current => exact ih current

theorem accepted_input_is_compatible {Atom : Expr → Type u} {shape : Shape}
    (plan : Plan shape) (current after : Data Atom shape) (incoming : View Atom plan)
    (accepted : put plan current incoming = some after) : Compatible plan current incoming := by
  induction plan generalizing current after incoming with
  | keep => trivial
  | skip => trivial
  | empty => cases current
  | product first second firstIH secondIH =>
      cases current with
      | product left right =>
          rcases incoming with ⟨one, two⟩
          cases leftResult : put first left one with
          | none => simp [put, leftResult] at accepted
          | some newLeft =>
              cases rightResult : put second right two with
              | none => simp [put, leftResult, rightResult] at accepted
              | some newRight => exact ⟨firstIH left newLeft one leftResult, secondIH right newRight two rightResult⟩
  | sum first second firstIH secondIH =>
      cases current with
      | left current =>
          cases incoming with
          | inr _ => simp [put] at accepted
          | inl incoming =>
              cases result : put first current incoming with
              | none => simp [put, result] at accepted
              | some value => exact firstIH current value incoming result
      | right current =>
          cases incoming with
          | inl _ => simp [put] at accepted
          | inr incoming =>
              cases result : put second current incoming with
              | none => simp [put, result] at accepted
              | some value => exact secondIH current value incoming result
  | named contents ih =>
      cases current with
      | named current =>
          cases result : put contents current incoming with
          | none => simp [put, result] at accepted
          | some value => exact ih current value incoming result
  | borrow contents ih =>
      cases current with
      | borrow current =>
          cases result : put contents current incoming with
          | none => simp [put, result] at accepted
          | some value => exact ih current value incoming result

theorem compatibility_characterizes_reconstruction {Atom : Expr → Type u} {shape : Shape}
    (plan : Plan shape) (current : Data Atom shape) (incoming : View Atom plan) :
    Compatible plan current incoming ↔ ∃ after, put plan current incoming = some after := by
  constructor
  · intro valid
    exact ⟨restore plan current incoming valid, put_is_total_on_compatible plan current incoming valid⟩
  · rintro ⟨after, accepted⟩
    exact accepted_input_is_compatible plan current after incoming accepted

theorem total_restore_has_exact_selected_view {Atom : Expr → Type u} {shape : Shape}
    (plan : Plan shape) (current : Data Atom shape) (incoming : View Atom plan)
    (valid : Compatible plan current incoming) :
    get plan (restore plan current incoming valid) = incoming :=
  put_then_get plan current _ incoming (put_is_total_on_compatible plan current incoming valid)

theorem total_restore_preserves_current_frame {Atom : Expr → Type u} {shape : Shape}
    (plan : Plan shape) (current : Data Atom shape) (incoming : View Atom plan)
    (valid : Compatible plan current incoming) :
    get (CurrentBorrowCarrier.complement plan) (restore plan current incoming valid) =
      get (CurrentBorrowCarrier.complement plan) current :=
  CurrentBorrowCarrier.put_preserves_complement plan current _ incoming
    (put_is_total_on_compatible plan current incoming valid)

namespace Channel

def Compatible {Atom : Expr → Type u} (channel : FullBorrowABI.Channel)
    (current : Data Atom channel.outgoingShape) (incoming : Data Atom channel.incomingShape) : Prop :=
  BorrowViewCompatibility.Compatible channel.outgoingPlan current
    (FullBorrowABI.route channel (get channel.incomingPlan incoming))

def restore {Atom : Expr → Type u} (channel : FullBorrowABI.Channel)
    (current : Data Atom channel.outgoingShape) (incoming : Data Atom channel.incomingShape)
    (valid : Compatible channel current incoming) : Data Atom channel.outgoingShape :=
  BorrowViewCompatibility.restore channel.outgoingPlan current
    (FullBorrowABI.route channel (get channel.incomingPlan incoming)) valid

theorem adapt_is_total_on_compatible {Atom : Expr → Type u} (channel : FullBorrowABI.Channel)
    (current : Data Atom channel.outgoingShape) (incoming : Data Atom channel.incomingShape)
    (valid : Compatible channel current incoming) :
    FullBorrowABI.adapt channel current incoming = some (restore channel current incoming valid) :=
  put_is_total_on_compatible _ _ _ valid

theorem restore_has_exact_selected_view {Atom : Expr → Type u} (channel : FullBorrowABI.Channel)
    (current : Data Atom channel.outgoingShape) (incoming : Data Atom channel.incomingShape)
    (valid : Compatible channel current incoming) :
    get channel.outgoingPlan (restore channel current incoming valid) =
      FullBorrowABI.route channel (get channel.incomingPlan incoming) :=
  total_restore_has_exact_selected_view _ _ _ valid

theorem restore_preserves_current_frame {Atom : Expr → Type u} (channel : FullBorrowABI.Channel)
    (current : Data Atom channel.outgoingShape) (incoming : Data Atom channel.incomingShape)
    (valid : Compatible channel current incoming) :
    get (CurrentBorrowCarrier.complement channel.outgoingPlan) (restore channel current incoming valid) =
      get (CurrentBorrowCarrier.complement channel.outgoingPlan) current :=
  total_restore_preserves_current_frame _ _ _ valid

theorem matching_current_is_compatible {Atom : Expr → Type u} (channel : FullBorrowABI.Channel)
    (current : Data Atom channel.outgoingShape) :
    Compatible channel current (FullBorrowABI.matchingIncoming channel current) := by
  unfold Compatible
  rw [FullBorrowABI.matching_incoming_has_current_view]
  exact current_view_is_compatible _ _

end Channel

namespace Native
open NativePurePayload

def Compatible {typing : AtomTyping} {Atom : Ty → Type u} {inputLayout outputLayout}
    (channel : FullBorrowABI.Channel) (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (current : Value Atom outputLayout) (input : Value Atom inputLayout) : Prop :=
  Channel.Compatible channel (decode outgoing current) (decode incoming input)

def restore {typing : AtomTyping} {Atom : Ty → Type u} {inputLayout outputLayout}
    (channel : FullBorrowABI.Channel) (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (current : Value Atom outputLayout) (input : Value Atom inputLayout)
    (valid : Compatible channel incoming outgoing current input) : Value Atom outputLayout :=
  encode outgoing (Channel.restore channel (decode outgoing current) (decode incoming input) valid)

theorem adapt_is_total_on_compatible {typing : AtomTyping} {Atom : Ty → Type u} {inputLayout outputLayout}
    (channel : FullBorrowABI.Channel) (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (current : Value Atom outputLayout) (input : Value Atom inputLayout)
    (valid : Compatible channel incoming outgoing current input) :
    adaptNative channel incoming outgoing current input = some (restore channel incoming outgoing current input valid) := by
  unfold adaptNative restore
  rw [Channel.adapt_is_total_on_compatible channel (decode outgoing current) (decode incoming input) valid]
  rfl

theorem matching_current_is_compatible {typing : AtomTyping} {Atom : Ty → Type u} {inputLayout outputLayout}
    (channel : FullBorrowABI.Channel) (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout) (current : Value Atom outputLayout) :
    Compatible channel incoming outgoing current (matchingNativeInput channel incoming outgoing current) := by
  unfold Compatible matchingNativeInput
  rw [decode_encode]
  exact Channel.matching_current_is_compatible _ _

theorem total_restore_has_exact_selected_view {typing : AtomTyping} {Atom : Ty → Type u} {inputLayout outputLayout}
    (channel : FullBorrowABI.Channel) (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (current : Value Atom outputLayout) (input : Value Atom inputLayout)
    (valid : Compatible channel incoming outgoing current input) :
    get channel.outgoingPlan (decode outgoing (restore channel incoming outgoing current input valid)) =
      FullBorrowABI.route channel (get channel.incomingPlan (decode incoming input)) := by
  unfold restore
  rw [decode_encode]
  exact Channel.restore_has_exact_selected_view _ _ _ valid

theorem total_restore_preserves_current_frame {typing : AtomTyping} {Atom : Ty → Type u} {inputLayout outputLayout}
    (channel : FullBorrowABI.Channel) (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (current : Value Atom outputLayout) (input : Value Atom inputLayout)
    (valid : Compatible channel incoming outgoing current input) :
    get (CurrentBorrowCarrier.complement channel.outgoingPlan)
        (decode outgoing (restore channel incoming outgoing current input valid)) =
      get (CurrentBorrowCarrier.complement channel.outgoingPlan) (decode outgoing current) := by
  unfold restore
  rw [decode_encode]
  exact Channel.restore_preserves_current_frame _ _ _ valid

end Native
end Auths.Support.BorrowViewCompatibility
