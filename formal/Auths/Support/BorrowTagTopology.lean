import Auths.Support.BorrowViewCompatibility

/-!
The exact tag-only part of the independent partial-input invariant. No atom
payload or unselected incoming byte is compared. Whole ownership and skipped
views carry no tag obligation; partial sums retain their alternative recursively.
This provides a finite structural target for source carrier/loan preservation.
Permission-directed field stores and their finite sequences preserve that
target and the complete unselected frame. They reconstruct the exact final
value through the native codecs. The source heap/loan/call interpretation must
still justify that the actual Rust execution follows those store rules.
Scripts await final elaboration.
-/
namespace Auths.Support.BorrowTagTopology
open SourceClosureRegions BorrowProjection BorrowViewCompatibility
universe u

inductive Topology where
  | leaf
  | pair (first second : Topology)
  | left (contents : Topology)
  | right (contents : Topology)
  deriving DecidableEq, Repr

def currentTags {Atom : Expr → Type u} : {shape : Shape} → (plan : Plan shape) →
    Data Atom shape → Topology
  | _, .keep, _ | _, .skip, _ => .leaf
  | _, .empty, value => nomatch value
  | _, .product first second, .product left right => .pair (currentTags first left) (currentTags second right)
  | _, .sum first _, .left value => .left (currentTags first value)
  | _, .sum _ second, .right value => .right (currentTags second value)
  | _, .named contents, .named value => currentTags contents value
  | _, .borrow contents, .borrow value => currentTags contents value

def incomingTags {Atom : Expr → Type u} : {shape : Shape} → (plan : Plan shape) →
    View Atom plan → Topology
  | _, .keep, _ | _, .skip, _ => .leaf
  | _, .empty, value => nomatch value
  | _, .product first second, (one, two) => .pair (incomingTags first one) (incomingTags second two)
  | _, .sum first _, .inl value => .left (incomingTags first value)
  | _, .sum _ second, .inr value => .right (incomingTags second value)
  | _, .named contents, value => incomingTags contents value
  | _, .borrow contents, value => incomingTags contents value

theorem compatibility_is_exactly_tag_topology {Atom : Expr → Type u} {shape : Shape}
    (plan : Plan shape) (current : Data Atom shape) (incoming : View Atom plan) :
    Compatible plan current incoming ↔ currentTags plan current = incomingTags plan incoming := by
  induction plan generalizing current incoming with
  | keep => simp [Compatible, currentTags, incomingTags]
  | skip => simp [Compatible, currentTags, incomingTags]
  | empty => cases current
  | product first second firstIH secondIH =>
      cases current with
      | product left right =>
          rcases incoming with ⟨one, two⟩
          simpa [Compatible, currentTags, incomingTags] using and_congr (firstIH left one) (secondIH right two)
  | sum first second firstIH secondIH =>
      cases current with
      | left value =>
          cases incoming with
          | inl update => simpa [Compatible, currentTags, incomingTags] using firstIH value update
          | inr update => simp [Compatible, currentTags, incomingTags]
      | right value =>
          cases incoming with
          | inl update => simp [Compatible, currentTags, incomingTags]
          | inr update => simpa [Compatible, currentTags, incomingTags] using secondIH value update
  | named contents ih => cases current with | named value => exact ih value incoming
  | borrow contents ih => cases current with | borrow value => exact ih value incoming

theorem unchanged_tags_suffice_for_total_reconstruction {Atom : Expr → Type u} {shape : Shape}
    (plan : Plan shape) (current : Data Atom shape) (incoming : View Atom plan)
    (same : currentTags plan current = incomingTags plan incoming) :
    put plan current incoming = some (BorrowViewCompatibility.restore plan current incoming
      ((compatibility_is_exactly_tag_topology plan current incoming).mpr same)) :=
  put_is_total_on_compatible _ _ _ _

theorem self_view_has_same_tags {Atom : Expr → Type u} {shape : Shape}
    (plan : Plan shape) (current : Data Atom shape) :
    currentTags plan current = incomingTags plan (get plan current) :=
  (compatibility_is_exactly_tag_topology _ _ _).mp (current_view_is_compatible _ _)

theorem total_restore_preserves_partial_tag_topology {Atom : Expr → Type u} {shape : Shape}
    (plan : Plan shape) (current : Data Atom shape) (incoming : View Atom plan)
    (valid : Compatible plan current incoming) :
    currentTags plan (BorrowViewCompatibility.restore plan current incoming valid) = currentTags plan current := by
  have before := (compatibility_is_exactly_tag_topology plan current incoming).mp valid
  have after := self_view_has_same_tags plan (BorrowViewCompatibility.restore plan current incoming valid)
  rw [total_restore_has_exact_selected_view] at after
  exact after.trans before.symm

theorem whole_ownership_has_no_tag_restriction {Atom : Expr → Type u} {shape : Shape}
    (current incoming : Data Atom shape) : currentTags .keep current = incomingTags .keep incoming := rfl

theorem skipped_input_has_no_tag_restriction {Atom : Expr → Type u} {shape : Shape}
    (current : Data Atom shape) (incoming : View Atom (Plan.skip : Plan shape)) :
    currentTags .skip current = incomingTags .skip incoming := rfl

/-- A field store through the permissions represented by a selection plan.
Only a wholly selected field can be replaced. Passing through a partially
selected sum retains its constructor. No store is available through `skip`.
This is a typed value rule, not a claim that an arbitrary Rust call satisfies
it: the source heap/loan interpretation must justify each store and call. -/
inductive FieldStore {Atom : Expr → Type u} : {shape : Shape} → (plan : Plan shape) →
    Data Atom shape → Data Atom shape → Prop where
  | replace {shape : Shape} (before after : Data Atom shape) :
      FieldStore .keep before after
  | first {left right : Shape} {one : Plan left} {two : Plan right}
      {before after : Data Atom left} (other : Data Atom right)
      (store : FieldStore one before after) :
      FieldStore (.product one two) (.product before other) (.product after other)
  | second {left right : Shape} {one : Plan left} {two : Plan right}
      (other : Data Atom left) {before after : Data Atom right}
      (store : FieldStore two before after) :
      FieldStore (.product one two) (.product other before) (.product other after)
  | left {first second : Shape} {one : Plan first} {two : Plan second}
      {before after : Data Atom first} (store : FieldStore one before after) :
      FieldStore (.sum one two) (.left before) (.left after)
  | right {first second : Shape} {one : Plan first} {two : Plan second}
      {before after : Data Atom second} (store : FieldStore two before after) :
      FieldStore (.sum one two) (.right before) (.right after)
  | named {label : Label} {shape : Shape} {plan : Plan shape}
      {before after : Data Atom shape} (store : FieldStore plan before after) :
      FieldStore (.named (identity := label) plan) (.named before) (.named after)
  | borrow {mutable : Bool} {region : Region} {shape : Shape} {plan : Plan shape}
      {before after : Data Atom shape} (store : FieldStore plan before after) :
      FieldStore (.borrow (mutable := mutable) (region := region) plan)
        (.borrow before) (.borrow after)

/-- Finite sequences of permission-directed stores, including zero writes.
Call bodies and finite loop iterations compose through this relation; their
source-to-store interpretation is a separate obligation. -/
inductive FieldStores {Atom : Expr → Type u} {shape : Shape} (plan : Plan shape) :
    Data Atom shape → Data Atom shape → Prop where
  | refl (value : Data Atom shape) : FieldStores plan value value
  | step {before middle after : Data Atom shape}
      (earlier : FieldStores plan before middle) (last : FieldStore plan middle after) :
      FieldStores plan before after

theorem field_store_preserves_partial_tags {Atom : Expr → Type u} {shape : Shape}
    {plan : Plan shape} {before after : Data Atom shape}
    (store : FieldStore plan before after) :
    currentTags plan after = currentTags plan before := by
  induction store with
  | replace => rfl
  | first other store ih => simp only [currentTags, ih]
  | second other store ih => simp only [currentTags, ih]
  | left store ih => simp only [currentTags, ih]
  | right store ih => simp only [currentTags, ih]
  | named store ih => exact ih
  | borrow store ih => exact ih

theorem field_stores_preserve_partial_tags {Atom : Expr → Type u} {shape : Shape}
    {plan : Plan shape} {before after : Data Atom shape}
    (stores : FieldStores plan before after) :
    currentTags plan after = currentTags plan before := by
  induction stores with
  | refl => rfl
  | step earlier last ih => exact (field_store_preserves_partial_tags last).trans ih

theorem field_stores_compose {Atom : Expr → Type u} {shape : Shape}
    {plan : Plan shape} {before middle after : Data Atom shape}
    (first : FieldStores plan before middle) (second : FieldStores plan middle after) :
    FieldStores plan before after := by
  induction second with
  | refl => exact first
  | step earlier last ih => exact .step ih last

theorem field_store_preserves_frame {Atom : Expr → Type u} {shape : Shape}
    {plan : Plan shape} {before after : Data Atom shape}
    (store : FieldStore plan before after) :
    get (CurrentBorrowCarrier.complement plan) after =
      get (CurrentBorrowCarrier.complement plan) before := by
  induction store with
  | replace => rfl
  | first other store ih => simp only [CurrentBorrowCarrier.complement, get, ih]
  | second other store ih => simp only [CurrentBorrowCarrier.complement, get, ih]
  | left store ih => simp only [CurrentBorrowCarrier.complement, get, ih]
  | right store ih => simp only [CurrentBorrowCarrier.complement, get, ih]
  | named store ih => exact ih
  | borrow store ih => exact ih

theorem field_stores_preserve_frame {Atom : Expr → Type u} {shape : Shape}
    {plan : Plan shape} {before after : Data Atom shape}
    (stores : FieldStores plan before after) :
    get (CurrentBorrowCarrier.complement plan) after =
      get (CurrentBorrowCarrier.complement plan) before := by
  induction stores with
  | refl => rfl
  | step earlier last ih => exact (field_store_preserves_frame last).trans ih

/-- The selected fields together with the retained frame determine the entire
value, including every constructor and skipped field. No atomic equality
decision procedure is needed. -/
theorem view_and_frame_determine_value {Atom : Expr → Type u} {shape : Shape}
    (plan : Plan shape) (one two : Data Atom shape)
    (selected : get plan one = get plan two)
    (frame : get (CurrentBorrowCarrier.complement plan) one =
      get (CurrentBorrowCarrier.complement plan) two) : one = two := by
  induction plan generalizing one two with
  | keep => exact selected
  | skip => exact frame
  | empty => cases one
  | product first second firstIH secondIH =>
      cases one with
      | product left right =>
          cases two with
          | product otherLeft otherRight =>
              have leftSame := firstIH left otherLeft
                (congrArg Prod.fst selected) (congrArg Prod.fst frame)
              have rightSame := secondIH right otherRight
                (congrArg Prod.snd selected) (congrArg Prod.snd frame)
              cases leftSame
              cases rightSame
              rfl
  | sum first second firstIH secondIH =>
      cases one with
      | left value =>
          cases two with
          | left other =>
              exact congrArg Data.left (firstIH value other
                (Sum.inl.inj selected) (Sum.inl.inj frame))
          | right other => cases selected
      | right value =>
          cases two with
          | left other => cases selected
          | right other =>
              exact congrArg Data.right (secondIH value other
                (Sum.inr.inj selected) (Sum.inr.inj frame))
  | named contents ih =>
      cases one with
      | named value =>
          cases two with
          | named other => exact congrArg Data.named (ih value other selected frame)
  | borrow contents ih =>
      cases one with
      | borrow value =>
          cases two with
          | borrow other => exact congrArg Data.borrow (ih value other selected frame)

/-- The compatibility needed by the native restore follows from permitted
stores. It is not an additional successful-result or tag-equality premise. -/
theorem field_stores_supply_compatible_input {Atom : Expr → Type u} {shape : Shape}
    {plan : Plan shape} {before after : Data Atom shape}
    (stores : FieldStores plan before after) :
    Compatible plan before (get plan after) := by
  apply (compatibility_is_exactly_tag_topology plan before (get plan after)).mpr
  exact (field_stores_preserve_partial_tags stores).symm.trans
    (self_view_has_same_tags plan after)

theorem field_stores_make_reconstruction_total {Atom : Expr → Type u} {shape : Shape}
    {plan : Plan shape} {before after : Data Atom shape}
    (stores : FieldStores plan before after) :
    put plan before (get plan after) =
      some (BorrowViewCompatibility.restore plan before (get plan after)
        (field_stores_supply_compatible_input stores)) :=
  put_is_total_on_compatible _ _ _ _

theorem field_stores_preserve_other_fields {Atom : Expr → Type u} {shape : Shape}
    {plan : Plan shape} {before after : Data Atom shape}
    (stores : FieldStores plan before after) :
    get (CurrentBorrowCarrier.complement plan)
      (BorrowViewCompatibility.restore plan before (get plan after)
        (field_stores_supply_compatible_input stores)) =
      get (CurrentBorrowCarrier.complement plan) before :=
  total_restore_preserves_current_frame _ _ _ _

theorem field_stores_reconstruct_exact_final_value {Atom : Expr → Type u} {shape : Shape}
    {plan : Plan shape} {before after : Data Atom shape}
    (stores : FieldStores plan before after) :
    BorrowViewCompatibility.restore plan before (get plan after)
      (field_stores_supply_compatible_input stores) = after := by
  apply view_and_frame_determine_value plan
  · exact total_restore_has_exact_selected_view _ _ _ _
  · exact (field_stores_preserve_other_fields stores).trans
      (field_stores_preserve_frame stores).symm

theorem field_stores_execute_without_representation_failure {Atom : Expr → Type u} {shape : Shape}
    {plan : Plan shape} {before after : Data Atom shape}
    (stores : FieldStores plan before after) :
    put plan before (get plan after) = some after := by
  rw [field_stores_make_reconstruction_total stores,
    field_stores_reconstruct_exact_final_value stores]

theorem skipped_field_has_no_store {Atom : Expr → Type u} {shape : Shape}
    (before after : Data Atom shape) (store : FieldStore .skip before after) : False := by
  cases store

theorem skipped_field_sequence_leaves_value_unchanged {Atom : Expr → Type u} {shape : Shape}
    (before after : Data Atom shape) (stores : FieldStores .skip before after) : after = before :=
  field_stores_preserve_frame stores

theorem partial_sum_sequence_cannot_switch_left_to_right {Atom : Expr → Type u}
    {left right : Shape} (one : Plan left) (two : Plan right)
    (before : Data Atom left) (after : Data Atom right)
    (stores : FieldStores (.sum one two) (.left before) (.right after)) : False := by
  have impossible := field_stores_preserve_partial_tags stores
  cases impossible

theorem whole_sum_ownership_allows_replacing_alternative {Atom : Expr → Type u}
    {left right : Shape} (before : Data Atom left) (after : Data Atom right) :
    FieldStores .keep (.left before) (.right after) :=
  .step (.refl _) (.replace _ _)

/-- The existing typed focus write implements one permitted whole-field store.
This connects the store rules to the actual current-carrier update operation,
without supplying an output or reconstructing siblings from an old snapshot. -/
theorem focus_write_is_field_store {Atom : Expr → Type u} {root target : Shape}
    (focus : CurrentBorrowCarrier.Focus root target) (current : Data Atom root)
    (update : Data Atom target) :
    FieldStore (CurrentBorrowCarrier.liftPlan focus .keep) current
      (CurrentBorrowCarrier.write focus current update) := by
  induction focus generalizing current with
  | here => exact .replace current update
  | first next ih =>
      cases current with
      | product left right => exact .first right (ih left)
  | second next ih =>
      cases current with
      | product left right => exact .second left (ih right)
  | named next ih =>
      cases current with
      | named value => exact .named (ih value)
  | borrow next ih =>
      cases current with
      | borrow value => exact .borrow (ih value)

theorem focused_write_returns_compatible_view {Atom : Expr → Type u} {root target : Shape}
    (focus : CurrentBorrowCarrier.Focus root target) (current : Data Atom root)
    (update : Data Atom target) :
    Compatible (CurrentBorrowCarrier.liftPlan focus .keep) current
      (get (CurrentBorrowCarrier.liftPlan focus .keep)
        (CurrentBorrowCarrier.write focus current update)) :=
  field_stores_supply_compatible_input
    (.step (.refl current) (focus_write_is_field_store focus current update))

namespace Native
open NativePurePayload

/-- A sequence of field stores in the complete decoded outgoing native value.
The original source-call/heap interpretation must supply this derivation; no
arbitrary external call is assigned a store contract by this definition. -/
abbrev Stores {typing : AtomTyping} {Atom : Ty → Type u} {outputLayout}
    (channel : FullBorrowABI.Channel)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (before after : Value Atom outputLayout) : Prop :=
  FieldStores channel.outgoingPlan (decode outgoing before) (decode outgoing after)

theorem stores_supply_compatible_native_input {typing : AtomTyping} {Atom : Ty → Type u}
    {inputLayout outputLayout} (channel : FullBorrowABI.Channel)
    (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (before after : Value Atom outputLayout) (stores : Stores channel outgoing before after) :
    BorrowViewCompatibility.Native.Compatible channel incoming outgoing before
      (matchingNativeInput channel incoming outgoing after) := by
  unfold BorrowViewCompatibility.Native.Compatible BorrowViewCompatibility.Channel.Compatible
    matchingNativeInput
  rw [decode_encode, FullBorrowABI.matching_incoming_has_current_view]
  exact field_stores_supply_compatible_input stores

theorem stores_reconstruct_exact_native_value {typing : AtomTyping} {Atom : Ty → Type u}
    {inputLayout outputLayout} (channel : FullBorrowABI.Channel)
    (incoming : Codec typing channel.incomingShape inputLayout)
    (outgoing : Codec typing channel.outgoingShape outputLayout)
    (before after : Value Atom outputLayout) (stores : Stores channel outgoing before after) :
    adaptNative channel incoming outgoing before
      (matchingNativeInput channel incoming outgoing after) = some after := by
  unfold adaptNative matchingNativeInput
  rw [decode_encode]
  unfold FullBorrowABI.adapt
  rw [FullBorrowABI.matching_incoming_has_current_view,
    field_stores_execute_without_representation_failure stores]
  simp only [Option.map_some, encode_decode]

end Native

end Auths.Support.BorrowTagTopology
