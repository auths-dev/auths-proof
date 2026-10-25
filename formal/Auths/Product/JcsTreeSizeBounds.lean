import Auths.Product.JcsTreeByteBounds

/-!
Complete expected output-length envelopes from the same full original tree.
Every child and original UTF-8 key/value byte contributes. These are logical
output/sink bounds, not native allocation/work/stack or raw-byte parser bounds;
positional/default aliases can expand when a typed source is serialized.
-/
namespace Auths.Product.JcsTreeEncoding
open FullJsonValue JcsObjectBuffer

mutual
  def outputBound : Value → Nat
    | .null => 4
    | .boolean _ => 5
    | .number _ => 17
    | .text value => 6 * (NativeCompiler.textBytes value).length + 2
    | .array values => 2 + valuesBound values
    | .object members => 2 + membersBound members
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  def valuesBound : List Value → Nat
    | [] => 0
    | value :: rest => outputBound value + 1 + valuesBound rest
  termination_by values => sizeOf values
  decreasing_by all_goals simp_wf <;> omega

  def membersBound : List (String × Value) → Nat
    | [] => 0
    | (name, value) :: rest => 6 * (NativeCompiler.textBytes name).length + outputBound value + 4 + membersBound rest
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

theorem admitted_number_encoding_length (number : Number) (bytes : Bytes)
    (original : AdmittedIntegerBytes.encode number = some bytes) : bytes.length ≤ 17 := by
  cases number with
  | floating bits => simp [AdmittedIntegerBytes.encode] at original
  | unsigned value =>
      unfold AdmittedIntegerBytes.encode at original
      split at original
      · rename_i safe
        cases Option.some.inj original
        have bounded := JcsIntegerDecimal.admitted_unsigned_length value safe
        omega
      · simp at original
  | signed value =>
      unfold AdmittedIntegerBytes.encode at original
      split at original
      · rename_i safe
        cases Option.some.inj original
        exact JcsIntegerDecimal.admitted_signed_length value safe
      · simp at original

theorem array_contents_length_bound (values : List Bytes) (first : Bool) :
    (arrayContents first values).length ≤ (values.map (fun value => value.length + 1)).sum := by
  induction values generalizing first with
  | nil => simp [arrayContents]
  | cons value rest ih =>
      have tail := ih false
      cases first <;> simp only [arrayContents, Bool.false_eq_true, ↓reduceIte, List.nil_append,
        List.length_append, List.length_singleton, List.map_cons, List.sum_cons] <;> omega

theorem array_bytes_length_bound (values : List Bytes) :
    (arrayBytes values).length ≤ 2 + (values.map (fun value => value.length + 1)).sum := by
  have contents := array_contents_length_bound values true
  simp only [arrayBytes, List.length_cons, List.length_append, List.length_singleton]
  omega

mutual
  theorem complete_encoding_length_bound {value : Value} {bytes : Bytes} (original : Encoding value bytes)
      (unique : FullJsonValue.Unique value) : bytes.length ≤ outputBound value := by
    cases original with
    | null => simp [outputBound]
    | boolean value => cases value <;> simp [outputBound]
    | text value => exact JcsStringEncoding.quoted_length_relative_to_original_bytes value
    | number original => exact admitted_number_encoding_length _ _ original
    | array children =>
        have framing := array_bytes_length_bound _
        have childBounds := encoded_values_length_bound children ((FullJsonValue.array_unique_iff _).mp unique)
        exact framing.trans (Nat.add_le_add_left childBounds 2)
    | @object members outputs children =>
        have originalUnique := (FullJsonValue.object_unique_iff _).mp unique
        have names : (outputs.map Prod.fst).Nodup := by
          rw [encoded_members_keep_original_names children]
          exact originalUnique.1
        have framing := JcsObjectBytes.original_object_length_relative_to_original_parts _ names
        have childBounds := encoded_members_length_bound children originalUnique.2
        exact framing.trans (Nat.add_le_add_left childBounds 2)
  termination_by structural original

  theorem encoded_values_length_bound {values : List Value} {bytes : List Bytes}
      (original : ValuesEncoding values bytes) (unique : ∀ value ∈ values, FullJsonValue.Unique value) :
      (bytes.map (fun value => value.length + 1)).sum ≤ valuesBound values := by
    cases original with
    | nil => exact Nat.le_refl 0
    | cons head tail =>
        have first := complete_encoding_length_bound head (unique _ (by simp))
        have remaining := encoded_values_length_bound tail (fun value member => unique value (List.mem_cons_of_mem _ member))
        simp only [List.map_cons, List.sum_cons, valuesBound]
        omega
  termination_by structural original

  theorem encoded_members_length_bound {members : List (String × Value)} {bytes : List (String × Bytes)}
      (original : MembersEncoding members bytes) (unique : ∀ member ∈ members, FullJsonValue.Unique member.2) :
      (bytes.map (fun member => 6 * (NativeCompiler.textBytes member.1).length + member.2.length + 4)).sum ≤ membersBound members := by
    cases original with
    | nil => exact Nat.le_refl 0
    | cons name head tail =>
        have first := complete_encoding_length_bound head (unique _ (by simp))
        have remaining := encoded_members_length_bound tail (fun member present => unique member (List.mem_cons_of_mem _ present))
        simp only [List.map_cons, List.sum_cons, membersBound]
        omega
  termination_by structural original
end

theorem complete_unique_safe_tree_earns_size_bounded_writer (value : Value)
    (safe : FullJsonNumericSafety.SafeNumbers value) (unique : FullJsonValue.Unique value) :
    ∃ bytes events, Encoding value bytes ∧ JcsTreeWriter.Trace value bytes events ∧ JcsObjectBytes.BytesBounded bytes ∧
      bytes.length ≤ outputBound value ∧
      ∀ state, JcsWriterFrames.run events state = (.ok (), JcsWriterFrames.emit bytes state) := by
  obtain ⟨bytes, events, encoded, trace, byteBounds, schedule⟩ := complete_unique_safe_tree_earns_bounded_writer value safe unique
  exact ⟨bytes, events, encoded, trace, byteBounds, complete_encoding_length_bound encoded unique, schedule⟩

def currentSinkLength (state : JcsWriterFrames.State) : Nat :=
  match state.buffers with
  | [] => state.output.length
  | buffer :: _ => buffer.length

theorem emitted_current_sink_length (bytes : Bytes) (state : JcsWriterFrames.State) :
    currentSinkLength (JcsWriterFrames.emit bytes state) = currentSinkLength state + bytes.length := by
  cases state with
  | mk output objects keys buffers => cases buffers <;> simp [currentSinkLength, JcsWriterFrames.emit]

theorem complete_trace_current_sink_bound {value : Value} {bytes : Bytes} {events : List JcsWriterFrames.Event}
    (original : Encoding value bytes) (unique : FullJsonValue.Unique value) (trace : JcsTreeWriter.Trace value bytes events)
    (before : JcsWriterFrames.State) :
    ∃ after, JcsWriterFrames.run events before = (.ok (), after) ∧
      currentSinkLength after ≤ currentSinkLength before + outputBound value ∧
      after.objects = before.objects ∧ after.keys = before.keys := by
  have length := complete_encoding_length_bound original unique
  have frames := JcsWriterFrames.emit_keeps_objects_and_keys bytes before
  exact ⟨JcsWriterFrames.emit bytes before, JcsTreeWriter.complete_trace_restores_parent_frames trace before,
    by rw [emitted_current_sink_length]; omega, frames.1, frames.2⟩

end Auths.Product.JcsTreeEncoding
