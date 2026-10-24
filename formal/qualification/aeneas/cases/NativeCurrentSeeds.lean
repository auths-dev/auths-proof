import Auths.Support.NativeCurrentSeeds
import qualification.aeneas.cases.NativeCaptureValue
import qualification.aeneas.cases.NativeCurrentWiring
/- Forward and backward seeds share the same actual reflected execution.
   Unelaborated/unqualified; original native environments/permissions/continuations remain open. -/
namespace Auths.Qualification.NativeCurrentSeeds
open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.NativeCurrentSeeds
open Auths.Support.NativePurePayload Auths.Support.NativePureExpressions
open Auths.Qualification.NativeCaptureValue
open Auths.Qualification.BorrowProjection.Candidate3400
universe u
def seed0Shape : Shape := .atom (.node .literal [.natural 0])
def seed0Path : List PathStep := [.field 1, .mutableBorrow]
def seed0FromState (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Option (Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) seed0Shape) := do
  let (_, state) ← Auths.Support.NativeCaptureValue.runWithState actualProgram [⟨input0Shape, input0⟩, ⟨input1Shape, input1⟩]
  readSeed actualProgram state (.borrow 0) seed0Shape
def seed0FromReturned (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Option (Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) seed0Shape) := do
  let value ← Auths.Support.NativeCaptureValue.run actualProgram [⟨input0Shape, input0⟩, ⟨input1Shape, input1⟩]
  readReturnedAs seed0Shape seed0Path value
theorem seed0_is_exact_returned_capture (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) :
    seed0FromState Atom input0 input1 = seed0FromReturned Atom input0 input1 := by
  cases input0 with
  | borrow input0Body =>
    cases input1 with
    | named input1Body =>
      cases input1Body with
      | product input1BodyFirst input1BodyRest =>
        cases input1BodyFirst with
        | named input1BodyFirstBody =>
          cases input1BodyFirstBody with
          | named input1BodyFirstBodyBody =>
            cases input1BodyFirstBodyBody with
            | product input1BodyFirstBodyBodyFirst input1BodyFirstBodyBodyRest =>
              cases input1BodyFirstBodyBodyFirst with
              | named input1BodyFirstBodyBodyFirstBody =>
                cases input1BodyFirstBodyBodyFirstBody with
                | borrow input1BodyFirstBodyBodyFirstBodyBody =>
                  cases input1BodyFirstBodyBodyFirstBodyBody with
                  | named input1BodyFirstBodyBodyFirstBodyBodyBody =>
                    cases input1BodyFirstBodyBodyFirstBodyBodyBody with
                    | named input1BodyFirstBodyBodyFirstBodyBodyBodyBody =>
                      cases input1BodyFirstBodyBodyRest with
                      | unit =>
                        cases input1BodyRest with
                        | unit =>
                          rfl
def seed1Shape : Shape := .named (.nominal (.node .adt [.natural 507, .node .arguments [.node .regions [.region (.parameter 2)], .node .types [.node .mutRef [.region (.parameter 3), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]], .node .constants [], .node .traits []]])) (.sum (.named (.variant 0) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 2) (.borrow true (.parameter 3) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.variant 1) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 2) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty)))
def seed1Path : List PathStep := [.field 0, .field 0, .field 0, .mutableBorrow, .boxed]
def seed1FromState (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Option (Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) seed1Shape) := do
  let (_, state) ← Auths.Support.NativeCaptureValue.runWithState actualProgram [⟨input0Shape, input0⟩, ⟨input1Shape, input1⟩]
  readSeed actualProgram state (.symbolic 6) seed1Shape
def seed1FromReturned (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Option (Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) seed1Shape) := do
  let value ← Auths.Support.NativeCaptureValue.run actualProgram [⟨input0Shape, input0⟩, ⟨input1Shape, input1⟩]
  readReturnedAs seed1Shape seed1Path value
theorem seed1_is_exact_returned_capture (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) :
    seed1FromState Atom input0 input1 = seed1FromReturned Atom input0 input1 := by
  cases input0 with
  | borrow input0Body =>
    cases input1 with
    | named input1Body =>
      cases input1Body with
      | product input1BodyFirst input1BodyRest =>
        cases input1BodyFirst with
        | named input1BodyFirstBody =>
          cases input1BodyFirstBody with
          | named input1BodyFirstBodyBody =>
            cases input1BodyFirstBodyBody with
            | product input1BodyFirstBodyBodyFirst input1BodyFirstBodyBodyRest =>
              cases input1BodyFirstBodyBodyFirst with
              | named input1BodyFirstBodyBodyFirstBody =>
                cases input1BodyFirstBodyBodyFirstBody with
                | borrow input1BodyFirstBodyBodyFirstBodyBody =>
                  cases input1BodyFirstBodyBodyFirstBodyBody with
                  | named input1BodyFirstBodyBodyFirstBodyBodyBody =>
                    cases input1BodyFirstBodyBodyFirstBodyBodyBody with
                    | named input1BodyFirstBodyBodyFirstBodyBodyBodyBody =>
                      cases input1BodyFirstBodyBodyRest with
                      | unit =>
                        cases input1BodyRest with
                        | unit =>
                          rfl
structure Prepared (Atom : Ty → Type u) where
  value : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) outputShape
  current0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout
  current1 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout
def prepare (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Option (Prepared Atom) := do
  let (value, state) ← Auths.Support.NativeCaptureValue.runWithState actualProgram [⟨input0Shape, input0⟩, ⟨input1Shape, input1⟩]
  let captured ← Auths.Support.NativeCaptureValue.castData outputShape value
  let current0 ← readSeed actualProgram state (.borrow 0) seed0Shape
  let current1 ← readSeed actualProgram state (.symbolic 6) seed1Shape
  pure { value := captured, current0 := encode Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec current0, current1 := encode Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec current1 }
def prepareFromReturned (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Option (Prepared Atom) := do
  let value ← Auths.Support.NativeCaptureValue.run actualProgram [⟨input0Shape, input0⟩, ⟨input1Shape, input1⟩]
  let captured ← Auths.Support.NativeCaptureValue.castData outputShape value
  let current0 ← readReturnedAs seed0Shape seed0Path value
  let current1 ← readReturnedAs seed1Shape seed1Path value
  pure { value := captured, current0 := encode Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec current0, current1 := encode Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec current1 }
theorem prepared_seeds_are_from_returned_capture (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) :
    prepare Atom input0 input1 = prepareFromReturned Atom input0 input1 := by
  cases input0 with
  | borrow input0Body =>
    cases input1 with
    | named input1Body =>
      cases input1Body with
      | product input1BodyFirst input1BodyRest =>
        cases input1BodyFirst with
        | named input1BodyFirstBody =>
          cases input1BodyFirstBody with
          | named input1BodyFirstBodyBody =>
            cases input1BodyFirstBodyBody with
            | product input1BodyFirstBodyBodyFirst input1BodyFirstBodyBodyRest =>
              cases input1BodyFirstBodyBodyFirst with
              | named input1BodyFirstBodyBodyFirstBody =>
                cases input1BodyFirstBodyBodyFirstBody with
                | borrow input1BodyFirstBodyBodyFirstBodyBody =>
                  cases input1BodyFirstBodyBodyFirstBodyBody with
                  | named input1BodyFirstBodyBodyFirstBodyBodyBody =>
                    cases input1BodyFirstBodyBodyFirstBodyBodyBody with
                    | named input1BodyFirstBodyBodyFirstBodyBodyBodyBody =>
                      cases input1BodyFirstBodyBodyRest with
                      | unit =>
                        cases input1BodyRest with
                        | unit =>
                          rfl
theorem prepared_value_is_original_source_capture (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) :
    (prepare Atom input0 input1).map Prepared.value = some (construct (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0 input1) := by
  cases input0 with
  | borrow input0Body =>
    cases input1 with
    | named input1Body =>
      cases input1Body with
      | product input1BodyFirst input1BodyRest =>
        cases input1BodyFirst with
        | named input1BodyFirstBody =>
          cases input1BodyFirstBody with
          | named input1BodyFirstBodyBody =>
            cases input1BodyFirstBodyBody with
            | product input1BodyFirstBodyBodyFirst input1BodyFirstBodyBodyRest =>
              cases input1BodyFirstBodyBodyFirst with
              | named input1BodyFirstBodyBodyFirstBody =>
                cases input1BodyFirstBodyBodyFirstBody with
                | borrow input1BodyFirstBodyBodyFirstBodyBody =>
                  cases input1BodyFirstBodyBodyFirstBodyBody with
                  | named input1BodyFirstBodyBodyFirstBodyBodyBody =>
                    cases input1BodyFirstBodyBodyFirstBodyBodyBody with
                    | named input1BodyFirstBodyBodyFirstBodyBodyBodyBody =>
                      cases input1BodyFirstBodyBodyRest with
                      | unit =>
                        cases input1BodyRest with
                        | unit =>
                          rfl
def branch0FromForward (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← prepare Atom input0 input1
  Auths.Qualification.NativeCurrentWiring.branch0Run Atom captured.current0 captured.current1 incoming0
def branch0FromReturned (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← prepareFromReturned Atom input0 input1
  Auths.Qualification.NativeCurrentWiring.branch0Run Atom captured.current0 captured.current1 incoming0
def branch0Expected (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← prepare Atom input0 input1
  Auths.Qualification.NativeCurrentWiring.branch0Expected Atom captured.current0 captured.current1 incoming0
theorem branch0_uses_captured_current (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) :
    branch0FromForward Atom input0 input1 incoming0 = branch0FromReturned Atom input0 input1 incoming0 := by
  simp only [branch0FromForward, branch0FromReturned, prepared_seeds_are_from_returned_capture]
theorem branch0_refines_explicit_ending_model (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) :
    branch0FromForward Atom input0 input1 incoming0 = branch0Expected Atom input0 input1 incoming0 := by
  unfold branch0FromForward branch0Expected
  cases prepared : prepare Atom input0 input1 with
  | none => simp [prepared]
  | some captured =>
    simp only [prepared, Option.bind_some]
    exact Auths.Qualification.NativeCurrentWiring.branch0_executes_explicit_ending_model Atom captured.current0 captured.current1 incoming0
def branch1FromForward (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← prepare Atom input0 input1
  Auths.Qualification.NativeCurrentWiring.branch1Run Atom captured.current0 captured.current1 incoming0
def branch1FromReturned (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← prepareFromReturned Atom input0 input1
  Auths.Qualification.NativeCurrentWiring.branch1Run Atom captured.current0 captured.current1 incoming0
def branch1Expected (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← prepare Atom input0 input1
  Auths.Qualification.NativeCurrentWiring.branch1Expected Atom captured.current0 captured.current1 incoming0
theorem branch1_uses_captured_current (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) :
    branch1FromForward Atom input0 input1 incoming0 = branch1FromReturned Atom input0 input1 incoming0 := by
  simp only [branch1FromForward, branch1FromReturned, prepared_seeds_are_from_returned_capture]
theorem branch1_refines_explicit_ending_model (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) :
    branch1FromForward Atom input0 input1 incoming0 = branch1Expected Atom input0 input1 incoming0 := by
  unfold branch1FromForward branch1Expected
  cases prepared : prepare Atom input0 input1 with
  | none => simp [prepared]
  | some captured =>
    simp only [prepared, Option.bind_some]
    exact Auths.Qualification.NativeCurrentWiring.branch1_executes_explicit_ending_model Atom captured.current0 captured.current1 incoming0
def branch2FromForward (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← prepare Atom input0 input1
  Auths.Qualification.NativeCurrentWiring.branch2Run Atom captured.current0 captured.current1 incoming0
def branch2FromReturned (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← prepareFromReturned Atom input0 input1
  Auths.Qualification.NativeCurrentWiring.branch2Run Atom captured.current0 captured.current1 incoming0
def branch2Expected (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← prepare Atom input0 input1
  Auths.Qualification.NativeCurrentWiring.branch2Expected Atom captured.current0 captured.current1 incoming0
theorem branch2_uses_captured_current (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    branch2FromForward Atom input0 input1 incoming0 = branch2FromReturned Atom input0 input1 incoming0 := by
  simp only [branch2FromForward, branch2FromReturned, prepared_seeds_are_from_returned_capture]
theorem branch2_refines_explicit_ending_model (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    branch2FromForward Atom input0 input1 incoming0 = branch2Expected Atom input0 input1 incoming0 := by
  unfold branch2FromForward branch2Expected
  cases prepared : prepare Atom input0 input1 with
  | none => simp [prepared]
  | some captured =>
    simp only [prepared, Option.bind_some]
    exact Auths.Qualification.NativeCurrentWiring.branch2_executes_explicit_ending_model Atom captured.current0 captured.current1 incoming0
def branch3FromForward (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) : Option (Dynamic Atom) := do
  let captured ← prepare Atom input0 input1
  Auths.Qualification.NativeCurrentWiring.branch3Run Atom captured.current0 captured.current1 incoming0 incoming1
def branch3FromReturned (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) : Option (Dynamic Atom) := do
  let captured ← prepareFromReturned Atom input0 input1
  Auths.Qualification.NativeCurrentWiring.branch3Run Atom captured.current0 captured.current1 incoming0 incoming1
def branch3Expected (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) : Option (Dynamic Atom) := do
  let captured ← prepare Atom input0 input1
  Auths.Qualification.NativeCurrentWiring.branch3Expected Atom captured.current0 captured.current1 incoming0 incoming1
theorem branch3_uses_captured_current (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) :
    branch3FromForward Atom input0 input1 incoming0 incoming1 = branch3FromReturned Atom input0 input1 incoming0 incoming1 := by
  simp only [branch3FromForward, branch3FromReturned, prepared_seeds_are_from_returned_capture]
theorem branch3_refines_explicit_ending_model (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) :
    branch3FromForward Atom input0 input1 incoming0 incoming1 = branch3Expected Atom input0 input1 incoming0 incoming1 := by
  unfold branch3FromForward branch3Expected
  cases prepared : prepare Atom input0 input1 with
  | none => simp [prepared]
  | some captured =>
    simp only [prepared, Option.bind_some]
    exact Auths.Qualification.NativeCurrentWiring.branch3_executes_explicit_ending_model Atom captured.current0 captured.current1 incoming0 incoming1
end Auths.Qualification.NativeCurrentSeeds
