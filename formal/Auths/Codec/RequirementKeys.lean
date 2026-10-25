import Auths.Codec.ProtocolValidity

open Aeneas Aeneas.Std
open AuthsProtocolCodec

namespace Auths.Codec.RequirementKeys

/- These are lossless representation keys. Membership and condition lists
retain every signed position. Equal semantics or an equal digest is not used
as a replacement for exact value identity in constructor duplicate checks. -/

inductive FactKey where
  | uint (value : Nat)
  | bytes (value : List Nat)
  | text (value : String)
  deriving DecidableEq

def fact : auths_model.observation.FactValue → FactKey
  | .Uint value => .uint value.val
  | .Bytes value => .bytes (value.val.map UScalar.val)
  | .Text value => .text value

inductive SubjectKey where
  | resource (value : String)
  | actionFact (value : String)
  deriving DecidableEq

def subject : auths_model.observation.ObservationSubject → SubjectKey
  | .Resource value => .resource value
  | .ActionFact value => .actionFact value

inductive TestKey where
  | literal (value : FactKey)
  | action (name : String)
  | range (lo hi : Nat)
  | member (values : List FactKey)
  deriving DecidableEq

def test : auths_model.observation.ConditionTest → TestKey
  | .EqLiteral value => .literal (fact value)
  | .EqAction value => .action value
  | .UintRange value => .range value.lo.val value.hi.val
  | .Member values => .member (values.val.map fact)

def condition (value : auths_model.observation.ObservationCondition) : String × TestKey :=
  (value.name, test value.test)

structure ObservationKey where
  observer : String
  schema : String
  subject : SubjectKey
  maximumAge : Nat
  conditions : List (String × TestKey)
  deriving DecidableEq

def observation (value : auths_model.observation.ObservationRequirement) : ObservationKey :=
  ⟨value.observer_anchor, value.schema, subject value.subject, value.max_age_seconds.val,
    value.conditions.val.map condition⟩

def approval (value : auths_model.approval.ApprovalRequirement) : List String × Nat :=
  (value.approvers.val, value.threshold.val)

private theorem bytes_injective : Function.Injective (fun values : alloc.vec.Vec Std.U8 =>
    values.val.map UScalar.val) := by
  intro left right same
  apply alloc.vec.contents_injective
  apply (List.map_injective_iff.mpr (show Function.Injective (fun value : Std.U8 => value.val) from by
    intro first second equal
    scalar_tac))
  exact same

theorem fact_injective : Function.Injective fact := by
  intro left right same
  cases left <;> cases right <;> simp only [fact, FactKey.uint.injEq, FactKey.bytes.injEq,
    FactKey.text.injEq, reduceCtorEq] at same
  all_goals try contradiction
  all_goals first | congr 1; scalar_tac | exact congrArg _ (bytes_injective same) | simpa using same

theorem subject_injective : Function.Injective subject := by
  intro left right same
  cases left <;> cases right <;> simp_all [subject]

theorem test_injective : Function.Injective test := by
  intro left right same
  cases left <;> cases right <;> simp only [test, TestKey.literal.injEq, TestKey.action.injEq,
    TestKey.range.injEq, TestKey.member.injEq, reduceCtorEq] at same
  all_goals try contradiction
  all_goals first
    | exact congrArg _ (fact_injective same)
    | simpa using same
    | congr 1 <;> casesm* auths_model.observation.UintRange <;> simp_all <;> scalar_tac
    | exact congrArg _ (alloc.vec.contents_injective ((List.map_injective_iff.mpr fact_injective) same))

theorem condition_injective : Function.Injective condition := by
  intro left right same
  cases left
  cases right
  simp only [condition, Prod.mk.injEq] at same
  obtain ⟨name, value⟩ := same
  have exactTest := test_injective value
  simp_all

theorem observation_injective : Function.Injective observation := by
  intro left right same
  cases left
  cases right
  simp only [observation, ObservationKey.mk.injEq] at same
  rcases same with ⟨observer, schema, target, age, conditions⟩
  have targetSame := subject_injective target
  have conditionsSame := alloc.vec.contents_injective ((List.map_injective_iff.mpr condition_injective) conditions)
  congr <;> simp_all
  all_goals scalar_tac

theorem approval_injective : Function.Injective approval := by
  intro left right same
  cases left
  cases right
  simp only [approval, Prod.mk.injEq] at same
  obtain ⟨values, threshold⟩ := same
  have valuesSame := alloc.vec.contents_injective values
  congr <;> simp_all
  all_goals scalar_tac

example : fact (.Uint 0#u64) ≠ fact (.Text "0") := by decide
example : subject (.Resource "same") ≠ subject (.ActionFact "same") := by decide
example : TestKey.member [.uint 1, .uint 2] ≠ .member [.uint 2, .uint 1] := by decide

end Auths.Codec.RequirementKeys
