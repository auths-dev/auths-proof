import Auths.Product.TemplateAst

namespace Auths.Product.TemplateAst

/-- Native depth rejection occurs before AST dispatch, member traversal or
piece allocation. The model retains that precedence even with zero fuel. -/
theorem emit_json_depth_refusal (fuel : Nat) (value : Value) (echo : Option (List Bytes))
    (depth : Nat) (initial : JsonBuild) (tooDeep : 6 < depth) :
    emitJson fuel value echo depth initial = .error .shape := by
  cases fuel <;> simp [emitJson, chargeNode, show ¬depth ≤ 6 by omega]

/-- The shared meter is checked before the first node increment, including
when a caller passes an already exhausted or invalid meter. -/
theorem emit_json_exhausted_refusal (fuel : Nat) (value : Value) (echo : Option (List Bytes))
    (depth : Nat) (initial : JsonBuild) (exhausted : 64 ≤ initial.nodes) :
    emitJson fuel value echo depth initial = .error .shape := by
  cases fuel <;> simp [emitJson, chargeNode, Nat.not_lt.mpr exhausted]

/-- Once enough fuel remains to reach the native depth guard, its exact
amount cannot affect any outcome. This covers every AST, echo, builder and
typed refusal; it does not assume successful or well-formed input. -/
theorem emit_json_fuel_irrelevant (first second : Nat) (value : Value)
    (echo : Option (List Bytes)) (depth : Nat) (initial : JsonBuild)
    (firstEnough : 7 ≤ depth + first) (secondEnough : 7 ≤ depth + second) :
    emitJson first value echo depth initial = emitJson second value echo depth initial := by
  induction first generalizing second value echo depth initial with
  | zero =>
    have tooDeep : 6 < depth := by omega
    rw [emit_json_depth_refusal _ _ _ _ _ tooDeep,
      emit_json_depth_refusal _ _ _ _ _ tooDeep]
  | succ first ih =>
    cases second with
    | zero =>
      have tooDeep : 6 < depth := by omega
      rw [emit_json_depth_refusal _ _ _ _ _ tooDeep,
        emit_json_depth_refusal _ _ _ _ _ tooDeep]
    | succ second =>
      have children : ∀ child nested output,
          emitJson first child nested (depth + 1) output =
            emitJson second child nested (depth + 1) output := by
        intro child nested output
        exact ih second child nested (depth + 1) output (by omega) (by omega)
      simpa only [emitJson, children]

/-- Seven is a complete presentation of native recursion at every starting
depth. A source refinement may normalize recursive calls to this one model
without introducing an extra truncation or a successful-input assumption. -/
theorem emit_json_normalized_fuel (fuel : Nat) (value : Value)
    (echo : Option (List Bytes)) (depth : Nat) (initial : JsonBuild)
    (enough : 7 ≤ depth + fuel) :
    emitJson fuel value echo depth initial = emitJson 7 value echo depth initial :=
  emit_json_fuel_irrelevant fuel 7 value echo depth initial enough (by omega)

/-- Decrementing fuel while incrementing native depth preserves completeness
for the actual recursive child call, including its first rejected depth. -/
theorem emit_json_child_fuel (fuel : Nat) (value : Value)
    (echo : Option (List Bytes)) (depth : Nat) (initial : JsonBuild)
    (enough : 7 ≤ depth + (fuel + 1)) :
    emitJson fuel value echo (depth + 1) initial = emitJson 7 value echo (depth + 1) initial :=
  emit_json_normalized_fuel fuel value echo (depth + 1) initial (by omega)

theorem emit_json_success_earns_recursion_domain (fuel : Nat) (value : Value)
    (echo : Option (List Bytes)) (depth : Nat) (initial output : JsonBuild)
    (run : emitJson fuel value echo depth initial = .ok output) :
    0 < fuel ∧ depth ≤ 6 ∧ initial.nodes < 64 := by
  cases fuel with
  | zero => simp [emitJson] at run
  | succ fuel =>
    cases charged : chargeNode initial.nodes depth with
    | error error => simp [emitJson, charged] at run
    | ok next =>
      have earned := charge_node_earns_domain initial.nodes depth next charged
      exact ⟨by omega, earned.2.1, earned.1⟩

end Auths.Product.TemplateAst
