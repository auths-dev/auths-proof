import Auths.Product.NativeCompilerText
import Auths.Product.NativeCompilerRuleInterfaces
import Auths.Product.RecipeConsumption

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeNameSet := AuthsNativeRecipe.alloc.collections.btree.set.BTreeSet String Global

def nameSet (input : NativeNameSet) : Finset String := input.elements.val.toFinset

def NameSetOrdered (input : NativeNameSet) : Prop := input.elements.val.Pairwise (· < ·)

def consumptionState (input : AuthsNativeRecipe.recipe.validate.Consumption) : RecipeConsumption.State :=
  ⟨nameSet input.all, nameSet input.body, nameSet input.binds⟩

def ConsumptionOrdered (input : AuthsNativeRecipe.recipe.validate.Consumption) : Prop :=
  NameSetOrdered input.all ∧ NameSetOrdered input.body ∧ NameSetOrdered input.binds

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

theorem text_bytes_injective : Function.Injective textBytes := by
  intro left right equal
  have sameBytes : left.toByteArray.toList = right.toByteArray.toList :=
    List.map_injective (fun _ _ same => UInt8.toNat_inj.mp same) equal
  apply String.toByteArray_inj.mp
  exact ByteArray.ext (by simpa using congrArg List.toArray sameBytes)

theorem native_text_view_bytes (text : String) (fits : TextFits text) :
    schemaSliceBytes (nativeTextView text fits) = textBytes text := native_text_bytes text

theorem native_text_view_array (text : String) (fits : TextFits text) :
    Auths.Codec.StdModel.bytes (nativeTextView text fits) = text.toByteArray := by
  simp [Auths.Codec.StdModel.bytes, nativeTextView, AuthsNativeRecipe.NativeModel.textBytes,
    List.map_map, UInt8.ofNat_toNat]

@[step] theorem native_text_view_owned (text : String) (fits : TextFits text) :
    AuthsNativeRecipe.Str.Insts.AllocBorrowToOwnedString.to_owned (nativeTextView text fits)
      ⦃ actual => actual = text ⦄ := by
  simp [AuthsNativeRecipe.Str.Insts.AllocBorrowToOwnedString.to_owned,
    native_text_view_array, spec_ok]

private theorem string_set_nodup (values : List String) (ordered : values.Pairwise (· < ·)) :
    values.Nodup := by
  induction values with
  | nil => simp
  | cons first rest ih =>
      obtain ⟨before, tail⟩ := List.pairwise_cons.mp ordered
      exact List.nodup_cons.mpr ⟨fun present => lt_irrefl first (before first present), ih tail⟩

/-- The concrete ordinary B-tree insertion earns ordering, exact membership,
the replacement flag and the physical number of retained elements together. -/
theorem native_name_insert_values (name : String) (values : List String)
    (ordered : values.Pairwise (· < ·)) :
    ∃ added updated,
      AuthsNativeRecipe.NativeModel.insertElement
        AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd name values = ok (added, updated) ∧
      updated.Pairwise (· < ·) ∧
      (∀ value, value ∈ updated ↔ value = name ∨ value ∈ values) ∧
      (added = true ↔ name ∉ values) ∧
      updated.length = values.length + (if added then 1 else 0) := by
  induction values with
  | nil => exact ⟨true, [name], rfl, by simp, by simp, by simp, by simp⟩
  | cons first rest ih =>
      obtain ⟨before, tailOrder⟩ := List.pairwise_cons.mp ordered
      cases comparison : compare name first with
      | lt =>
          have earlier : name < first := compare_lt_iff_lt.mp comparison
          have fresh : name ∉ first :: rest := by
            intro present
            rcases List.mem_cons.mp present with same | later
            · exact ne_of_lt earlier same
            · exact lt_asymm earlier (before name later)
          refine ⟨true, name :: first :: rest, ?_, ?_, ?_, ?_, ?_⟩
          · simp [AuthsNativeRecipe.NativeModel.insertElement, native_string_order_exact, comparison]
          · apply List.pairwise_cons.mpr
            refine ⟨?_, ordered⟩
            intro value member
            rcases List.mem_cons.mp member with rfl | later
            · exact earlier
            · exact lt_trans earlier (before value later)
          · intro value; simp
          · simp [fresh]
          · simp
      | eq =>
          have same : name = first := Std.compare_eq_iff_eq.mp comparison
          subst name
          exact ⟨false, first :: rest,
            by simp [AuthsNativeRecipe.NativeModel.insertElement, native_string_order_exact],
            ordered, by intro value; simp, by simp, by simp⟩
      | gt =>
          have later : first < name := compare_gt_iff_gt.mp comparison
          have different : name ≠ first := ne_of_gt later
          obtain ⟨added, updated, run, nextOrder, members, fresh, count⟩ := ih tailOrder
          refine ⟨added, first :: updated, ?_, ?_, ?_, ?_, ?_⟩
          · simp [AuthsNativeRecipe.NativeModel.insertElement, native_string_order_exact, comparison, run]
          · apply List.pairwise_cons.mpr
            refine ⟨?_, nextOrder⟩
            intro value member
            rcases (members value).mp member with rfl | previous
            · exact later
            · exact before value previous
          · intro value; simp only [List.mem_cons, members]; tauto
          · simpa [different] using fresh
          · simp only [List.length_cons]; omega

@[step] theorem native_name_set_insert (input : NativeNameSet) (name : String)
    (ordered : NameSetOrdered input) (room : input.elements.val.length < Usize.max) :
    AuthsNativeRecipe.alloc.collections.btree.set.BTreeSet.insert core.core.clone.CloneGlobal
      AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd input name ⦃ actual =>
      actual.1 = decide (name ∉ nameSet input) ∧
      nameSet actual.2 = insert name (nameSet input) ∧ NameSetOrdered actual.2 ∧
      actual.2.elements.val.length = input.elements.val.length + (if actual.1 then 1 else 0) ∧
      (∀ value ∈ actual.2.elements.val, value = name ∨ value ∈ input.elements.val) ⦄ := by
  obtain ⟨added, updated, run, nextOrder, members, fresh, count⟩ :=
    native_name_insert_values name input.elements.val ordered
  have bound : updated.length ≤ Usize.max := by rw [count]; split <;> omega
  unfold AuthsNativeRecipe.alloc.collections.btree.set.BTreeSet.insert
  rw [run]
  simp only [bind_tc_ok, dif_pos bound, spec_ok]
  have original : (AuthsNativeRecipe.alloc.vec.Vec.ofBase ⟨updated, bound⟩).val = updated := by
    simp [AuthsNativeRecipe.alloc.vec.Vec.ofBase, AuthsNativeRecipe.alloc.vec.Vec.val,
      auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.Vec.val,
      auths_composition.alloc.vec.SizedList.toList_ofList]
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · simpa only [nameSet, List.mem_toFinset, Bool.eq_iff_iff, decide_eq_true_eq] using fresh
  · apply Finset.ext
    intro value
    simpa only [nameSet, original, List.mem_toFinset, Finset.mem_insert] using members value
  · simpa only [NameSetOrdered, original] using nextOrder
  · simpa only [original] using count
  · simpa only [original] using fun value member => (members value).mp member

/-- Sorting and original-field containment earn the native storage bound.
Merely projecting a potentially duplicated list to a Finset would not suffice. -/
theorem native_name_set_storage_bound (input : NativeNameSet) (fields : List Rules.Entry)
    (ordered : NameSetOrdered input) (known : nameSet input ⊆ (fields.map Prod.fst).toFinset) :
    input.elements.val.length ≤ fields.length := by
  have exactCount := List.toFinset_card_of_nodup (string_set_nodup input.elements.val ordered)
  calc
    input.elements.val.length = (nameSet input).card := exactCount.symm
    _ ≤ (fields.map Prod.fst).toFinset.card := Finset.card_le_card known
    _ ≤ fields.length := by simpa using List.toFinset_card_le (fields.map Prod.fst)

private theorem owned_name_contains (values : List String) (wanted : String) :
    AuthsNativeRecipe.NativeModel.containsBorrowed (AuthsNativeRecipe.core.borrow.Borrow.Blanket String)
      AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd wanted values = ok (decide (wanted ∈ values)) := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
      simp only [AuthsNativeRecipe.NativeModel.containsBorrowed,
        AuthsNativeRecipe.core.borrow.Borrow.Blanket.borrow, bind_tc_ok, native_string_order_exact]
      by_cases same : wanted = first
      · simp [same]
      · have different : compare wanted first ≠ .eq := by simpa only [Std.compare_eq_iff_eq] using same
        simp [different, ih, same]

@[step] theorem native_name_set_contains_owned (input : NativeNameSet) (wanted : String) :
    AuthsNativeRecipe.alloc.collections.btree.set.BTreeSet.contains core.core.clone.CloneGlobal
      (AuthsNativeRecipe.core.borrow.Borrow.Blanket String)
      AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd
      AuthsNativeRecipe.alloc.string.String.Insts.CoreCmpOrd input wanted ⦃ actual =>
      actual = decide (wanted ∈ nameSet input) ⦄ := by
  simpa only [AuthsNativeRecipe.alloc.collections.btree.set.BTreeSet.contains,
    nameSet, List.mem_toFinset, spec_ok] using owned_name_contains input.elements.val wanted

end Auths.Product.NativeCompiler.StdModel
