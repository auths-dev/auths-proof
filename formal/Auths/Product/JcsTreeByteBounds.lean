import Auths.Product.JcsTreeWriter

/-!
Byte validity of the complete expected tree, earned from original encoding
and recursive object uniqueness. Every child is included. These are byte
value bounds, not aggregate allocation, work, stack or raw-input size bounds.
-/
namespace Auths.Product.JcsTreeEncoding
open FullJsonValue JcsObjectBuffer JcsObjectBytes

theorem admitted_number_encoding_has_byte_bounds (number : Number) (bytes : Bytes)
    (original : AdmittedIntegerBytes.encode number = some bytes) : BytesBounded bytes := by
  cases number with
  | floating bits => simp [AdmittedIntegerBytes.encode] at original
  | unsigned value =>
      unfold AdmittedIntegerBytes.encode at original
      split at original
      · cases Option.some.inj original
        exact JcsIntegerDecimal.unsigned_bytes_are_bounded value
      · simp at original
  | signed value =>
      unfold AdmittedIntegerBytes.encode at original
      split at original
      · cases Option.some.inj original
        exact JcsIntegerDecimal.signed_bytes_are_bounded value
      · simp at original

theorem array_contents_have_byte_bounds (values : List Bytes) (first : Bool)
    (each : ∀ value ∈ values, BytesBounded value) : BytesBounded (arrayContents first values) := by
  induction values generalizing first with
  | nil => simp [arrayContents, BytesBounded]
  | cons value rest ih =>
      have head := each value (by simp)
      have tail := ih false (fun child member => each child (List.mem_cons_of_mem _ member))
      cases first <;> simp_all [arrayContents, BytesBounded]

theorem array_encoding_has_byte_bounds (values : List Bytes) (each : ∀ value ∈ values, BytesBounded value) :
    BytesBounded (arrayBytes values) := by
  have contents := array_contents_have_byte_bounds values true each
  simpa [arrayBytes, BytesBounded] using contents

mutual
  theorem complete_encoding_has_byte_bounds {value : Value} {bytes : Bytes} (original : Encoding value bytes)
      (unique : FullJsonValue.Unique value) : BytesBounded bytes := by
    cases original with
    | null => simp [BytesBounded]
    | boolean value => cases value <;> simp [BytesBounded]
    | text value => exact JcsStringEncoding.quoted_bytes_bounded value
    | number original => exact admitted_number_encoding_has_byte_bounds _ _ original
    | array children =>
        exact array_encoding_has_byte_bounds _
          (encoded_values_have_byte_bounds children ((FullJsonValue.array_unique_iff _).mp unique))
    | object children =>
        have originalUnique := (FullJsonValue.object_unique_iff _).mp unique
        apply original_object_preserves_byte_bounds
        · rw [encoded_members_keep_original_names children]
          exact originalUnique.1
        · exact encoded_members_have_byte_bounds children originalUnique.2
  termination_by structural original

  theorem encoded_values_have_byte_bounds {values : List Value} {bytes : List Bytes}
      (original : ValuesEncoding values bytes) (unique : ∀ value ∈ values, FullJsonValue.Unique value) :
      ∀ output ∈ bytes, BytesBounded output := by
    cases original with
    | nil => simp
    | cons head tail =>
        intro output present
        rcases List.mem_cons.mp present with rfl | later
        · exact complete_encoding_has_byte_bounds head (unique _ (by simp))
        · exact encoded_values_have_byte_bounds tail
            (fun value member => unique value (List.mem_cons_of_mem _ member)) output later
  termination_by structural original

  theorem encoded_members_have_byte_bounds {members : List (String × Value)} {bytes : List (String × Bytes)}
      (original : MembersEncoding members bytes) (unique : ∀ member ∈ members, FullJsonValue.Unique member.2) :
      ∀ output ∈ bytes, BytesBounded output.2 := by
    cases original with
    | nil => simp
    | cons name head tail =>
        intro output present
        rcases List.mem_cons.mp present with rfl | later
        · exact complete_encoding_has_byte_bounds head (unique _ (by simp))
        · exact encoded_members_have_byte_bounds tail
            (fun member present => unique member (List.mem_cons_of_mem _ present)) output later
  termination_by structural original
end

theorem complete_unique_safe_tree_earns_bounded_writer (value : Value) (safe : FullJsonNumericSafety.SafeNumbers value)
    (unique : FullJsonValue.Unique value) :
    ∃ bytes events, Encoding value bytes ∧ JcsTreeWriter.Trace value bytes events ∧ BytesBounded bytes ∧
      ∀ state, JcsWriterFrames.run events state = (.ok (), JcsWriterFrames.emit bytes state) := by
  obtain ⟨bytes, events, encoded, trace, scheduled⟩ := JcsTreeWriter.complete_safe_tree_earns_useful_writer value safe
  exact ⟨bytes, events, encoded, trace, complete_encoding_has_byte_bounds encoded unique, scheduled⟩

end Auths.Product.JcsTreeEncoding
