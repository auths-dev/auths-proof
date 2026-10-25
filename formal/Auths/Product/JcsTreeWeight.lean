import Auths.Product.JcsTreeSizeBounds

/-!
A linear expected-output envelope in complete original decoded tree weight.
Weight counts every value node, original UTF-8 key/value byte and collection
edge. It is not raw source length, native heap usage or a parser-cost measure.
Their correspondence must be earned at the actual byte/library boundary.
-/
namespace Auths.Product.JcsTreeEncoding
open FullJsonValue

mutual
  def treeWeight : Value → Nat
    | .null | .boolean _ | .number _ => 1
    | .text value => 1 + (NativeCompiler.textBytes value).length
    | .array values => 1 + valuesWeight values
    | .object members => 1 + membersWeight members
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  def valuesWeight : List Value → Nat
    | [] => 0
    | value :: rest => treeWeight value + 1 + valuesWeight rest
  termination_by values => sizeOf values
  decreasing_by all_goals simp_wf <;> omega

  def membersWeight : List (String × Value) → Nat
    | [] => 0
    | (name, value) :: rest => (NativeCompiler.textBytes name).length + treeWeight value + 1 + membersWeight rest
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

mutual
  theorem output_bound_is_linear_in_original_weight (value : Value) : outputBound value ≤ 17 * treeWeight value := by
    cases value with
    | null | boolean _ | number _ => simp [outputBound, treeWeight]
    | text value => simp only [outputBound, treeWeight]; omega
    | array values =>
        have children := values_bound_is_linear_in_original_weight values
        simp only [outputBound, treeWeight]
        omega
    | object members =>
        have children := members_bound_is_linear_in_original_weight members
        simp only [outputBound, treeWeight]
        omega
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  theorem values_bound_is_linear_in_original_weight (values : List Value) : valuesBound values ≤ 17 * valuesWeight values := by
    cases values with
    | nil => exact Nat.le_refl 0
    | cons first rest =>
        have head := output_bound_is_linear_in_original_weight first
        have tail := values_bound_is_linear_in_original_weight rest
        simp only [valuesBound, valuesWeight]
        omega
  termination_by values => sizeOf values
  decreasing_by all_goals simp_wf <;> omega

  theorem members_bound_is_linear_in_original_weight (members : List (String × Value)) :
      membersBound members ≤ 17 * membersWeight members := by
    cases members with
    | nil => exact Nat.le_refl 0
    | cons first rest =>
        obtain ⟨name, value⟩ := first
        have head := output_bound_is_linear_in_original_weight value
        have tail := members_bound_is_linear_in_original_weight rest
        simp only [membersBound, membersWeight]
        omega
  termination_by members => sizeOf members
  decreasing_by all_goals simp_wf <;> omega
end

theorem complete_encoding_length_is_linear {value : Value} {bytes : List Nat} (original : Encoding value bytes)
    (unique : FullJsonValue.Unique value) : bytes.length ≤ 17 * treeWeight value :=
  (complete_encoding_length_bound original unique).trans (output_bound_is_linear_in_original_weight value)

end Auths.Product.JcsTreeEncoding
