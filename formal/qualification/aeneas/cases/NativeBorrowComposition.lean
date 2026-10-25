import qualification.aeneas.cases.NativeBorrowTransport
import qualification.aeneas.cases.NativeBorrowView
/- Actual qualification-constructor native-view boundary composition.
   Unelaborated/unqualified; parent/default, native heap/loan and complete ABI adequacy remain required. -/
namespace Auths.Qualification.NativeBorrowComposition
open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection
open Auths.Qualification.NativeBorrowTransport
universe u
def branch0NativeBackward (Atom : Expr → Type u) (input0 : View Atom branch0Port0NativePlan) : View Atom branch0Port1NativePlan :=
  match Auths.Qualification.NativeBorrowView.branch0ConcreteBackward Atom
    (.cons (branch0Port0FromNative Atom input0) (.nil)) with
  | .cons (output0) (.nil) => branch0Port1ToNative Atom output0
def branch0Unroute (Atom : Expr → Type u) (output0 : View Atom branch0Port1NativePlan) : View Atom branch0Port0NativePlan :=
  branch0Port0ToNative Atom (branch0Port1FromNative Atom output0)
theorem branch0_native_inputs_round_trip (Atom : Expr → Type u) (input0 : View Atom branch0Port0NativePlan) :
    branch0Unroute Atom (branch0NativeBackward Atom input0) = input0 := by
  simp [branch0NativeBackward, branch0Unroute,
    Auths.Qualification.NativeBorrowView.branch0_routes_actual_candidate_views, branch0Port1_candidate_round_trip, branch0Port0_native_round_trip]
theorem branch0_native_outputs_round_trip (Atom : Expr → Type u) (output0 : View Atom branch0Port1NativePlan) :
    branch0NativeBackward Atom (branch0Unroute Atom output0) = output0 := by
  simp [branch0NativeBackward, branch0Unroute,
    Auths.Qualification.NativeBorrowView.branch0_routes_actual_candidate_views, branch0Port0_candidate_round_trip, branch0Port1_native_round_trip]
def branch1NativeBackward (Atom : Expr → Type u) (input0 : View Atom branch1Port0NativePlan) : View Atom branch1Port1NativePlan :=
  match Auths.Qualification.NativeBorrowView.branch1ConcreteBackward Atom
    (.cons (branch1Port0FromNative Atom input0) (.nil)) with
  | .cons (output0) (.nil) => branch1Port1ToNative Atom output0
def branch1Unroute (Atom : Expr → Type u) (output0 : View Atom branch1Port1NativePlan) : View Atom branch1Port0NativePlan :=
  branch1Port0ToNative Atom (branch1Port1FromNative Atom output0)
theorem branch1_native_inputs_round_trip (Atom : Expr → Type u) (input0 : View Atom branch1Port0NativePlan) :
    branch1Unroute Atom (branch1NativeBackward Atom input0) = input0 := by
  simp [branch1NativeBackward, branch1Unroute,
    Auths.Qualification.NativeBorrowView.branch1_routes_actual_candidate_views, branch1Port1_candidate_round_trip, branch1Port0_native_round_trip]
theorem branch1_native_outputs_round_trip (Atom : Expr → Type u) (output0 : View Atom branch1Port1NativePlan) :
    branch1NativeBackward Atom (branch1Unroute Atom output0) = output0 := by
  simp [branch1NativeBackward, branch1Unroute,
    Auths.Qualification.NativeBorrowView.branch1_routes_actual_candidate_views, branch1Port0_candidate_round_trip, branch1Port1_native_round_trip]
def branch2NativeBackward (Atom : Expr → Type u) (input0 : View Atom branch2Port0NativePlan) : View Atom branch2Port1NativePlan :=
  match Auths.Qualification.NativeBorrowView.branch2ConcreteBackward Atom
    (.cons (branch2Port0FromNative Atom input0) (.nil)) with
  | .cons (output0) (.nil) => branch2Port1ToNative Atom output0
def branch2Unroute (Atom : Expr → Type u) (output0 : View Atom branch2Port1NativePlan) : View Atom branch2Port0NativePlan :=
  branch2Port0ToNative Atom (branch2Port1FromNative Atom output0)
theorem branch2_native_inputs_round_trip (Atom : Expr → Type u) (input0 : View Atom branch2Port0NativePlan) :
    branch2Unroute Atom (branch2NativeBackward Atom input0) = input0 := by
  simp [branch2NativeBackward, branch2Unroute,
    Auths.Qualification.NativeBorrowView.branch2_routes_actual_candidate_views, branch2Port1_candidate_round_trip, branch2Port0_native_round_trip]
theorem branch2_native_outputs_round_trip (Atom : Expr → Type u) (output0 : View Atom branch2Port1NativePlan) :
    branch2NativeBackward Atom (branch2Unroute Atom output0) = output0 := by
  simp [branch2NativeBackward, branch2Unroute,
    Auths.Qualification.NativeBorrowView.branch2_routes_actual_candidate_views, branch2Port0_candidate_round_trip, branch2Port1_native_round_trip]
def branch3NativeBackward (Atom : Expr → Type u) (input0 : View Atom branch3Port0NativePlan) (input1 : View Atom branch3Port1NativePlan) : (View Atom branch3Port2NativePlan × View Atom branch3Port3NativePlan) :=
  match Auths.Qualification.NativeBorrowView.branch3ConcreteBackward Atom
    (.cons (branch3Port0FromNative Atom input0) (.cons (branch3Port1FromNative Atom input1) (.nil))) with
  | .cons (output0) (.cons (output1) (.nil)) => (branch3Port2ToNative Atom output0, branch3Port3ToNative Atom output1)
def branch3Unroute (Atom : Expr → Type u) (output0 : View Atom branch3Port2NativePlan) (output1 : View Atom branch3Port3NativePlan) : (View Atom branch3Port0NativePlan × View Atom branch3Port1NativePlan) :=
  (branch3Port0ToNative Atom (branch3Port2FromNative Atom output0), branch3Port1ToNative Atom (branch3Port3FromNative Atom output1))
theorem branch3_native_inputs_round_trip (Atom : Expr → Type u) (input0 : View Atom branch3Port0NativePlan) (input1 : View Atom branch3Port1NativePlan) :
    branch3Unroute Atom ((branch3NativeBackward Atom input0 input1).1) ((branch3NativeBackward Atom input0 input1).2) = (input0, input1) := by
  simp [branch3NativeBackward, branch3Unroute,
    Auths.Qualification.NativeBorrowView.branch3_routes_actual_candidate_views, branch3Port2_candidate_round_trip, branch3Port3_candidate_round_trip, branch3Port0_native_round_trip, branch3Port1_native_round_trip]
theorem branch3_native_outputs_round_trip (Atom : Expr → Type u) (output0 : View Atom branch3Port2NativePlan) (output1 : View Atom branch3Port3NativePlan) :
    branch3NativeBackward Atom ((branch3Unroute Atom output0 output1).1) ((branch3Unroute Atom output0 output1).2) = (output0, output1) := by
  simp [branch3NativeBackward, branch3Unroute,
    Auths.Qualification.NativeBorrowView.branch3_routes_actual_candidate_views, branch3Port0_candidate_round_trip, branch3Port1_candidate_round_trip, branch3Port2_native_round_trip, branch3Port3_native_round_trip]
end Auths.Qualification.NativeBorrowComposition
