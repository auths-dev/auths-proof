import Auths.Support.BorrowTransport
import qualification.aeneas.cases.NativeBorrowView
/- Actual native field shapes and pure-data value/view transports; unelaborated/unqualified.
   Native projection/lifetime/heap/loan validity, parent defaults and full ABI remain required. -/
namespace Auths.Qualification.NativeBorrowTransport
open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.BorrowTransport
universe u
def branch0Port0NativeShape : Shape := .atom (.node .literal [.natural 0])
def branch0Port0Mapping : List (Nat × Nat) := []
def branch0Port0Change : Change Auths.Qualification.NativeBorrowView.branch0Schema0.shape branch0Port0NativeShape := .atom (.node .literal [.natural 0])
theorem branch0Port0_metadata_is_exact : validMap branch0Port0Mapping && metadataMatch branch0Port0Mapping 15 branch0Port0Change = true := by
  rfl
def branch0Port0NativePlan : Plan branch0Port0NativeShape := .keep
theorem branch0Port0_selected_plan_matches_native : mapPlan branch0Port0Change Auths.Qualification.NativeBorrowView.branch0Schema0.plan = branch0Port0NativePlan := by
  rfl
def branch0Port0ToNative (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch0Schema0.Payload Atom) : View Atom branch0Port0NativePlan :=
  forwardView branch0Port0Change Auths.Qualification.NativeBorrowView.branch0Schema0.plan value
def branch0Port0FromNative (Atom : Expr → Type u) (value : View Atom branch0Port0NativePlan) : Auths.Qualification.NativeBorrowView.branch0Schema0.Payload Atom :=
  backwardView branch0Port0Change Auths.Qualification.NativeBorrowView.branch0Schema0.plan value
theorem branch0Port0_candidate_round_trip (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch0Schema0.Payload Atom) :
    branch0Port0FromNative Atom (branch0Port0ToNative Atom value) = value := by
  simp [branch0Port0FromNative, branch0Port0ToNative, view_forward_inverse]
theorem branch0Port0_native_round_trip (Atom : Expr → Type u) (value : View Atom branch0Port0NativePlan) :
    branch0Port0ToNative Atom (branch0Port0FromNative Atom value) = value := by
  simp [branch0Port0FromNative, branch0Port0ToNative, view_inverse_forward]
theorem branch0Port0_extraction_commutes (Atom : Expr → Type u) (value : Data Atom Auths.Qualification.NativeBorrowView.branch0Schema0.shape) :
    branch0Port0ToNative Atom (get Auths.Qualification.NativeBorrowView.branch0Schema0.plan value) =
      get branch0Port0NativePlan (forward branch0Port0Change value) := by
  simpa [branch0Port0ToNative, ← branch0Port0_selected_plan_matches_native] using extraction_commutes branch0Port0Change Auths.Qualification.NativeBorrowView.branch0Schema0.plan value
theorem branch0Port0_restoration_commutes (Atom : Expr → Type u) (before : Data Atom Auths.Qualification.NativeBorrowView.branch0Schema0.shape)
    (update : Auths.Qualification.NativeBorrowView.branch0Schema0.Payload Atom) :
    put branch0Port0NativePlan (forward branch0Port0Change before) (branch0Port0ToNative Atom update) =
      (put Auths.Qualification.NativeBorrowView.branch0Schema0.plan before update).map (forward branch0Port0Change) := by
  simpa [branch0Port0ToNative, ← branch0Port0_selected_plan_matches_native] using restoration_commutes branch0Port0Change Auths.Qualification.NativeBorrowView.branch0Schema0.plan before update
def branch0Port1NativeShape : Shape := .atom (.node .literal [.natural 0])
def branch0Port1Mapping : List (Nat × Nat) := []
def branch0Port1Change : Change Auths.Qualification.NativeBorrowView.branch0Schema0.shape branch0Port1NativeShape := .atom (.node .literal [.natural 0])
theorem branch0Port1_metadata_is_exact : validMap branch0Port1Mapping && metadataMatch branch0Port1Mapping 15 branch0Port1Change = true := by
  rfl
def branch0Port1NativePlan : Plan branch0Port1NativeShape := .keep
theorem branch0Port1_selected_plan_matches_native : mapPlan branch0Port1Change Auths.Qualification.NativeBorrowView.branch0Schema0.plan = branch0Port1NativePlan := by
  rfl
def branch0Port1ToNative (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch0Schema0.Payload Atom) : View Atom branch0Port1NativePlan :=
  forwardView branch0Port1Change Auths.Qualification.NativeBorrowView.branch0Schema0.plan value
def branch0Port1FromNative (Atom : Expr → Type u) (value : View Atom branch0Port1NativePlan) : Auths.Qualification.NativeBorrowView.branch0Schema0.Payload Atom :=
  backwardView branch0Port1Change Auths.Qualification.NativeBorrowView.branch0Schema0.plan value
theorem branch0Port1_candidate_round_trip (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch0Schema0.Payload Atom) :
    branch0Port1FromNative Atom (branch0Port1ToNative Atom value) = value := by
  simp [branch0Port1FromNative, branch0Port1ToNative, view_forward_inverse]
theorem branch0Port1_native_round_trip (Atom : Expr → Type u) (value : View Atom branch0Port1NativePlan) :
    branch0Port1ToNative Atom (branch0Port1FromNative Atom value) = value := by
  simp [branch0Port1FromNative, branch0Port1ToNative, view_inverse_forward]
theorem branch0Port1_extraction_commutes (Atom : Expr → Type u) (value : Data Atom Auths.Qualification.NativeBorrowView.branch0Schema0.shape) :
    branch0Port1ToNative Atom (get Auths.Qualification.NativeBorrowView.branch0Schema0.plan value) =
      get branch0Port1NativePlan (forward branch0Port1Change value) := by
  simpa [branch0Port1ToNative, ← branch0Port1_selected_plan_matches_native] using extraction_commutes branch0Port1Change Auths.Qualification.NativeBorrowView.branch0Schema0.plan value
theorem branch0Port1_restoration_commutes (Atom : Expr → Type u) (before : Data Atom Auths.Qualification.NativeBorrowView.branch0Schema0.shape)
    (update : Auths.Qualification.NativeBorrowView.branch0Schema0.Payload Atom) :
    put branch0Port1NativePlan (forward branch0Port1Change before) (branch0Port1ToNative Atom update) =
      (put Auths.Qualification.NativeBorrowView.branch0Schema0.plan before update).map (forward branch0Port1Change) := by
  simpa [branch0Port1ToNative, ← branch0Port1_selected_plan_matches_native] using restoration_commutes branch0Port1Change Auths.Qualification.NativeBorrowView.branch0Schema0.plan before update
def branch1Port0NativeShape : Shape := .named (.boxed) (.named (.nominal (.node .adt [.natural 507, .node .arguments [.node .regions [.region (.parameter 40)], .node .types [.node .mutRef [.region (.parameter 41), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]], .node .constants [], .node .traits []]])) (.sum (.named (.variant 0) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 40) (.borrow true (.parameter 41) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.variant 1) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 40) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty))))
def branch1Port0Mapping : List (Nat × Nat) := [(2, 40), (3, 41)]
def branch1Port0Change : Change Auths.Qualification.NativeBorrowView.branch1Schema0.shape branch1Port0NativeShape := .named (.named (.sum (.named (.product (.named (.borrow true (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.product (.named (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty))))
theorem branch1Port0_metadata_is_exact : validMap branch1Port0Mapping && metadataMatch branch1Port0Mapping 15 branch1Port0Change = true := by
  rfl
def branch1Port0NativePlan : Plan branch1Port0NativeShape := .keep
theorem branch1Port0_selected_plan_matches_native : mapPlan branch1Port0Change Auths.Qualification.NativeBorrowView.branch1Schema0.plan = branch1Port0NativePlan := by
  rfl
def branch1Port0ToNative (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch1Schema0.Payload Atom) : View Atom branch1Port0NativePlan :=
  forwardView branch1Port0Change Auths.Qualification.NativeBorrowView.branch1Schema0.plan value
def branch1Port0FromNative (Atom : Expr → Type u) (value : View Atom branch1Port0NativePlan) : Auths.Qualification.NativeBorrowView.branch1Schema0.Payload Atom :=
  backwardView branch1Port0Change Auths.Qualification.NativeBorrowView.branch1Schema0.plan value
theorem branch1Port0_candidate_round_trip (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch1Schema0.Payload Atom) :
    branch1Port0FromNative Atom (branch1Port0ToNative Atom value) = value := by
  simp [branch1Port0FromNative, branch1Port0ToNative, view_forward_inverse]
theorem branch1Port0_native_round_trip (Atom : Expr → Type u) (value : View Atom branch1Port0NativePlan) :
    branch1Port0ToNative Atom (branch1Port0FromNative Atom value) = value := by
  simp [branch1Port0FromNative, branch1Port0ToNative, view_inverse_forward]
theorem branch1Port0_extraction_commutes (Atom : Expr → Type u) (value : Data Atom Auths.Qualification.NativeBorrowView.branch1Schema0.shape) :
    branch1Port0ToNative Atom (get Auths.Qualification.NativeBorrowView.branch1Schema0.plan value) =
      get branch1Port0NativePlan (forward branch1Port0Change value) := by
  simpa [branch1Port0ToNative, ← branch1Port0_selected_plan_matches_native] using extraction_commutes branch1Port0Change Auths.Qualification.NativeBorrowView.branch1Schema0.plan value
theorem branch1Port0_restoration_commutes (Atom : Expr → Type u) (before : Data Atom Auths.Qualification.NativeBorrowView.branch1Schema0.shape)
    (update : Auths.Qualification.NativeBorrowView.branch1Schema0.Payload Atom) :
    put branch1Port0NativePlan (forward branch1Port0Change before) (branch1Port0ToNative Atom update) =
      (put Auths.Qualification.NativeBorrowView.branch1Schema0.plan before update).map (forward branch1Port0Change) := by
  simpa [branch1Port0ToNative, ← branch1Port0_selected_plan_matches_native] using restoration_commutes branch1Port0Change Auths.Qualification.NativeBorrowView.branch1Schema0.plan before update
def branch1Port1NativeShape : Shape := .named (.boxed) (.named (.nominal (.node .adt [.natural 507, .node .arguments [.node .regions [.region (.parameter 40)], .node .types [.node .mutRef [.region (.parameter 41), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]], .node .constants [], .node .traits []]])) (.sum (.named (.variant 0) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 40) (.borrow true (.parameter 41) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.variant 1) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 40) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty))))
def branch1Port1Mapping : List (Nat × Nat) := [(2, 40), (3, 41)]
def branch1Port1Change : Change Auths.Qualification.NativeBorrowView.branch1Schema0.shape branch1Port1NativeShape := .named (.named (.sum (.named (.product (.named (.borrow true (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.product (.named (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty))))
theorem branch1Port1_metadata_is_exact : validMap branch1Port1Mapping && metadataMatch branch1Port1Mapping 15 branch1Port1Change = true := by
  rfl
def branch1Port1NativePlan : Plan branch1Port1NativeShape := .keep
theorem branch1Port1_selected_plan_matches_native : mapPlan branch1Port1Change Auths.Qualification.NativeBorrowView.branch1Schema0.plan = branch1Port1NativePlan := by
  rfl
def branch1Port1ToNative (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch1Schema0.Payload Atom) : View Atom branch1Port1NativePlan :=
  forwardView branch1Port1Change Auths.Qualification.NativeBorrowView.branch1Schema0.plan value
def branch1Port1FromNative (Atom : Expr → Type u) (value : View Atom branch1Port1NativePlan) : Auths.Qualification.NativeBorrowView.branch1Schema0.Payload Atom :=
  backwardView branch1Port1Change Auths.Qualification.NativeBorrowView.branch1Schema0.plan value
theorem branch1Port1_candidate_round_trip (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch1Schema0.Payload Atom) :
    branch1Port1FromNative Atom (branch1Port1ToNative Atom value) = value := by
  simp [branch1Port1FromNative, branch1Port1ToNative, view_forward_inverse]
theorem branch1Port1_native_round_trip (Atom : Expr → Type u) (value : View Atom branch1Port1NativePlan) :
    branch1Port1ToNative Atom (branch1Port1FromNative Atom value) = value := by
  simp [branch1Port1FromNative, branch1Port1ToNative, view_inverse_forward]
theorem branch1Port1_extraction_commutes (Atom : Expr → Type u) (value : Data Atom Auths.Qualification.NativeBorrowView.branch1Schema0.shape) :
    branch1Port1ToNative Atom (get Auths.Qualification.NativeBorrowView.branch1Schema0.plan value) =
      get branch1Port1NativePlan (forward branch1Port1Change value) := by
  simpa [branch1Port1ToNative, ← branch1Port1_selected_plan_matches_native] using extraction_commutes branch1Port1Change Auths.Qualification.NativeBorrowView.branch1Schema0.plan value
theorem branch1Port1_restoration_commutes (Atom : Expr → Type u) (before : Data Atom Auths.Qualification.NativeBorrowView.branch1Schema0.shape)
    (update : Auths.Qualification.NativeBorrowView.branch1Schema0.Payload Atom) :
    put branch1Port1NativePlan (forward branch1Port1Change before) (branch1Port1ToNative Atom update) =
      (put Auths.Qualification.NativeBorrowView.branch1Schema0.plan before update).map (forward branch1Port1Change) := by
  simpa [branch1Port1ToNative, ← branch1Port1_selected_plan_matches_native] using restoration_commutes branch1Port1Change Auths.Qualification.NativeBorrowView.branch1Schema0.plan before update
def branch2Port0NativeShape : Shape := .named (.boxed) (.named (.nominal (.node .adt [.natural 507, .node .arguments [.node .regions [.region (.parameter 2)], .node .types [.node .mutRef [.region (.parameter 3), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]], .node .constants [], .node .traits []]])) (.sum (.named (.variant 0) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 2) (.borrow true (.parameter 3) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.variant 1) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 2) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty))))
def branch2Port0Mapping : List (Nat × Nat) := [(2, 2), (3, 3)]
def branch2Port0Change : Change Auths.Qualification.NativeBorrowView.branch2Schema0.shape branch2Port0NativeShape := .named (.named (.sum (.named (.product (.named (.borrow true (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.product (.named (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty))))
theorem branch2Port0_metadata_is_exact : validMap branch2Port0Mapping && metadataMatch branch2Port0Mapping 15 branch2Port0Change = true := by
  rfl
def branch2Port0NativePlan : Plan branch2Port0NativeShape := Auths.Support.BorrowProjection.select [.parameter 2] branch2Port0NativeShape
theorem branch2Port0_selected_plan_matches_native : mapPlan branch2Port0Change Auths.Qualification.NativeBorrowView.branch2Schema0.plan = branch2Port0NativePlan := by
  rfl
def branch2Port0ToNative (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch2Schema0.Payload Atom) : View Atom branch2Port0NativePlan :=
  forwardView branch2Port0Change Auths.Qualification.NativeBorrowView.branch2Schema0.plan value
def branch2Port0FromNative (Atom : Expr → Type u) (value : View Atom branch2Port0NativePlan) : Auths.Qualification.NativeBorrowView.branch2Schema0.Payload Atom :=
  backwardView branch2Port0Change Auths.Qualification.NativeBorrowView.branch2Schema0.plan value
theorem branch2Port0_candidate_round_trip (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch2Schema0.Payload Atom) :
    branch2Port0FromNative Atom (branch2Port0ToNative Atom value) = value := by
  simp [branch2Port0FromNative, branch2Port0ToNative, view_forward_inverse]
theorem branch2Port0_native_round_trip (Atom : Expr → Type u) (value : View Atom branch2Port0NativePlan) :
    branch2Port0ToNative Atom (branch2Port0FromNative Atom value) = value := by
  simp [branch2Port0FromNative, branch2Port0ToNative, view_inverse_forward]
theorem branch2Port0_extraction_commutes (Atom : Expr → Type u) (value : Data Atom Auths.Qualification.NativeBorrowView.branch2Schema0.shape) :
    branch2Port0ToNative Atom (get Auths.Qualification.NativeBorrowView.branch2Schema0.plan value) =
      get branch2Port0NativePlan (forward branch2Port0Change value) := by
  simpa [branch2Port0ToNative, ← branch2Port0_selected_plan_matches_native] using extraction_commutes branch2Port0Change Auths.Qualification.NativeBorrowView.branch2Schema0.plan value
theorem branch2Port0_restoration_commutes (Atom : Expr → Type u) (before : Data Atom Auths.Qualification.NativeBorrowView.branch2Schema0.shape)
    (update : Auths.Qualification.NativeBorrowView.branch2Schema0.Payload Atom) :
    put branch2Port0NativePlan (forward branch2Port0Change before) (branch2Port0ToNative Atom update) =
      (put Auths.Qualification.NativeBorrowView.branch2Schema0.plan before update).map (forward branch2Port0Change) := by
  simpa [branch2Port0ToNative, ← branch2Port0_selected_plan_matches_native] using restoration_commutes branch2Port0Change Auths.Qualification.NativeBorrowView.branch2Schema0.plan before update
def branch2Port1NativeShape : Shape := .named (.nominal (.node .adt [.natural 507, .node .arguments [.node .regions [.region (.parameter 59)], .node .types [.node .mutRef [.region (.parameter 60), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]], .node .constants [], .node .traits []]])) (.sum (.named (.variant 0) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 59) (.borrow true (.parameter 60) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.variant 1) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 59) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty)))
def branch2Port1Mapping : List (Nat × Nat) := [(2, 59), (3, 60)]
def branch2Port1Change : Change Auths.Qualification.NativeBorrowView.branch2Schema1.shape branch2Port1NativeShape := .named (.sum (.named (.product (.named (.borrow true (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.product (.named (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty)))
theorem branch2Port1_metadata_is_exact : validMap branch2Port1Mapping && metadataMatch branch2Port1Mapping 15 branch2Port1Change = true := by
  rfl
def branch2Port1NativePlan : Plan branch2Port1NativeShape := Auths.Support.BorrowProjection.select [.parameter 59] branch2Port1NativeShape
theorem branch2Port1_selected_plan_matches_native : mapPlan branch2Port1Change Auths.Qualification.NativeBorrowView.branch2Schema1.plan = branch2Port1NativePlan := by
  rfl
def branch2Port1ToNative (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch2Schema1.Payload Atom) : View Atom branch2Port1NativePlan :=
  forwardView branch2Port1Change Auths.Qualification.NativeBorrowView.branch2Schema1.plan value
def branch2Port1FromNative (Atom : Expr → Type u) (value : View Atom branch2Port1NativePlan) : Auths.Qualification.NativeBorrowView.branch2Schema1.Payload Atom :=
  backwardView branch2Port1Change Auths.Qualification.NativeBorrowView.branch2Schema1.plan value
theorem branch2Port1_candidate_round_trip (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch2Schema1.Payload Atom) :
    branch2Port1FromNative Atom (branch2Port1ToNative Atom value) = value := by
  simp [branch2Port1FromNative, branch2Port1ToNative, view_forward_inverse]
theorem branch2Port1_native_round_trip (Atom : Expr → Type u) (value : View Atom branch2Port1NativePlan) :
    branch2Port1ToNative Atom (branch2Port1FromNative Atom value) = value := by
  simp [branch2Port1FromNative, branch2Port1ToNative, view_inverse_forward]
theorem branch2Port1_extraction_commutes (Atom : Expr → Type u) (value : Data Atom Auths.Qualification.NativeBorrowView.branch2Schema1.shape) :
    branch2Port1ToNative Atom (get Auths.Qualification.NativeBorrowView.branch2Schema1.plan value) =
      get branch2Port1NativePlan (forward branch2Port1Change value) := by
  simpa [branch2Port1ToNative, ← branch2Port1_selected_plan_matches_native] using extraction_commutes branch2Port1Change Auths.Qualification.NativeBorrowView.branch2Schema1.plan value
theorem branch2Port1_restoration_commutes (Atom : Expr → Type u) (before : Data Atom Auths.Qualification.NativeBorrowView.branch2Schema1.shape)
    (update : Auths.Qualification.NativeBorrowView.branch2Schema1.Payload Atom) :
    put branch2Port1NativePlan (forward branch2Port1Change before) (branch2Port1ToNative Atom update) =
      (put Auths.Qualification.NativeBorrowView.branch2Schema1.plan before update).map (forward branch2Port1Change) := by
  simpa [branch2Port1ToNative, ← branch2Port1_selected_plan_matches_native] using restoration_commutes branch2Port1Change Auths.Qualification.NativeBorrowView.branch2Schema1.plan before update
def branch2Port2NativeShape : Shape := .named (.boxed) (.named (.nominal (.node .adt [.natural 507, .node .arguments [.node .regions [.region (.parameter 59)], .node .types [.node .mutRef [.region (.parameter 60), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]], .node .constants [], .node .traits []]])) (.sum (.named (.variant 0) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 59) (.borrow true (.parameter 60) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.variant 1) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 59) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty))))
def branch2Port2Mapping : List (Nat × Nat) := [(2, 59), (3, 60)]
def branch2Port2Change : Change Auths.Qualification.NativeBorrowView.branch2Schema0.shape branch2Port2NativeShape := .named (.named (.sum (.named (.product (.named (.borrow true (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.product (.named (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty))))
theorem branch2Port2_metadata_is_exact : validMap branch2Port2Mapping && metadataMatch branch2Port2Mapping 15 branch2Port2Change = true := by
  rfl
def branch2Port2NativePlan : Plan branch2Port2NativeShape := Auths.Support.BorrowProjection.select [.parameter 59] branch2Port2NativeShape
theorem branch2Port2_selected_plan_matches_native : mapPlan branch2Port2Change Auths.Qualification.NativeBorrowView.branch2Schema0.plan = branch2Port2NativePlan := by
  rfl
def branch2Port2ToNative (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch2Schema0.Payload Atom) : View Atom branch2Port2NativePlan :=
  forwardView branch2Port2Change Auths.Qualification.NativeBorrowView.branch2Schema0.plan value
def branch2Port2FromNative (Atom : Expr → Type u) (value : View Atom branch2Port2NativePlan) : Auths.Qualification.NativeBorrowView.branch2Schema0.Payload Atom :=
  backwardView branch2Port2Change Auths.Qualification.NativeBorrowView.branch2Schema0.plan value
theorem branch2Port2_candidate_round_trip (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch2Schema0.Payload Atom) :
    branch2Port2FromNative Atom (branch2Port2ToNative Atom value) = value := by
  simp [branch2Port2FromNative, branch2Port2ToNative, view_forward_inverse]
theorem branch2Port2_native_round_trip (Atom : Expr → Type u) (value : View Atom branch2Port2NativePlan) :
    branch2Port2ToNative Atom (branch2Port2FromNative Atom value) = value := by
  simp [branch2Port2FromNative, branch2Port2ToNative, view_inverse_forward]
theorem branch2Port2_extraction_commutes (Atom : Expr → Type u) (value : Data Atom Auths.Qualification.NativeBorrowView.branch2Schema0.shape) :
    branch2Port2ToNative Atom (get Auths.Qualification.NativeBorrowView.branch2Schema0.plan value) =
      get branch2Port2NativePlan (forward branch2Port2Change value) := by
  simpa [branch2Port2ToNative, ← branch2Port2_selected_plan_matches_native] using extraction_commutes branch2Port2Change Auths.Qualification.NativeBorrowView.branch2Schema0.plan value
theorem branch2Port2_restoration_commutes (Atom : Expr → Type u) (before : Data Atom Auths.Qualification.NativeBorrowView.branch2Schema0.shape)
    (update : Auths.Qualification.NativeBorrowView.branch2Schema0.Payload Atom) :
    put branch2Port2NativePlan (forward branch2Port2Change before) (branch2Port2ToNative Atom update) =
      (put Auths.Qualification.NativeBorrowView.branch2Schema0.plan before update).map (forward branch2Port2Change) := by
  simpa [branch2Port2ToNative, ← branch2Port2_selected_plan_matches_native] using restoration_commutes branch2Port2Change Auths.Qualification.NativeBorrowView.branch2Schema0.plan before update
def branch2Port3NativeShape : Shape := .named (.nominal (.node .adt [.natural 507, .node .arguments [.node .regions [.region (.parameter 2)], .node .types [.node .mutRef [.region (.parameter 3), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]], .node .constants [], .node .traits []]])) (.sum (.named (.variant 0) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 2) (.borrow true (.parameter 3) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.variant 1) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 2) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty)))
def branch2Port3Mapping : List (Nat × Nat) := [(2, 2), (3, 3)]
def branch2Port3Change : Change Auths.Qualification.NativeBorrowView.branch2Schema1.shape branch2Port3NativeShape := .named (.sum (.named (.product (.named (.borrow true (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.product (.named (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty)))
theorem branch2Port3_metadata_is_exact : validMap branch2Port3Mapping && metadataMatch branch2Port3Mapping 15 branch2Port3Change = true := by
  rfl
def branch2Port3NativePlan : Plan branch2Port3NativeShape := Auths.Support.BorrowProjection.select [.parameter 2] branch2Port3NativeShape
theorem branch2Port3_selected_plan_matches_native : mapPlan branch2Port3Change Auths.Qualification.NativeBorrowView.branch2Schema1.plan = branch2Port3NativePlan := by
  rfl
def branch2Port3ToNative (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch2Schema1.Payload Atom) : View Atom branch2Port3NativePlan :=
  forwardView branch2Port3Change Auths.Qualification.NativeBorrowView.branch2Schema1.plan value
def branch2Port3FromNative (Atom : Expr → Type u) (value : View Atom branch2Port3NativePlan) : Auths.Qualification.NativeBorrowView.branch2Schema1.Payload Atom :=
  backwardView branch2Port3Change Auths.Qualification.NativeBorrowView.branch2Schema1.plan value
theorem branch2Port3_candidate_round_trip (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch2Schema1.Payload Atom) :
    branch2Port3FromNative Atom (branch2Port3ToNative Atom value) = value := by
  simp [branch2Port3FromNative, branch2Port3ToNative, view_forward_inverse]
theorem branch2Port3_native_round_trip (Atom : Expr → Type u) (value : View Atom branch2Port3NativePlan) :
    branch2Port3ToNative Atom (branch2Port3FromNative Atom value) = value := by
  simp [branch2Port3FromNative, branch2Port3ToNative, view_inverse_forward]
theorem branch2Port3_extraction_commutes (Atom : Expr → Type u) (value : Data Atom Auths.Qualification.NativeBorrowView.branch2Schema1.shape) :
    branch2Port3ToNative Atom (get Auths.Qualification.NativeBorrowView.branch2Schema1.plan value) =
      get branch2Port3NativePlan (forward branch2Port3Change value) := by
  simpa [branch2Port3ToNative, ← branch2Port3_selected_plan_matches_native] using extraction_commutes branch2Port3Change Auths.Qualification.NativeBorrowView.branch2Schema1.plan value
theorem branch2Port3_restoration_commutes (Atom : Expr → Type u) (before : Data Atom Auths.Qualification.NativeBorrowView.branch2Schema1.shape)
    (update : Auths.Qualification.NativeBorrowView.branch2Schema1.Payload Atom) :
    put branch2Port3NativePlan (forward branch2Port3Change before) (branch2Port3ToNative Atom update) =
      (put Auths.Qualification.NativeBorrowView.branch2Schema1.plan before update).map (forward branch2Port3Change) := by
  simpa [branch2Port3ToNative, ← branch2Port3_selected_plan_matches_native] using restoration_commutes branch2Port3Change Auths.Qualification.NativeBorrowView.branch2Schema1.plan before update
def branch3Port0NativeShape : Shape := .named (.nominal (.node .adt [.natural 507, .node .arguments [.node .regions [.region (.parameter 2)], .node .types [.node .mutRef [.region (.parameter 3), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]], .node .constants [], .node .traits []]])) (.sum (.named (.variant 0) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 2) (.borrow true (.parameter 3) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.variant 1) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 2) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty)))
def branch3Port0Mapping : List (Nat × Nat) := [(2, 2), (3, 3)]
def branch3Port0Change : Change Auths.Qualification.NativeBorrowView.branch3Schema0.shape branch3Port0NativeShape := .named (.sum (.named (.product (.named (.borrow true (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.product (.named (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty)))
theorem branch3Port0_metadata_is_exact : validMap branch3Port0Mapping && metadataMatch branch3Port0Mapping 15 branch3Port0Change = true := by
  rfl
def branch3Port0NativePlan : Plan branch3Port0NativeShape := Auths.Support.BorrowProjection.select [.parameter 3] branch3Port0NativeShape
theorem branch3Port0_selected_plan_matches_native : mapPlan branch3Port0Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan = branch3Port0NativePlan := by
  rfl
def branch3Port0ToNative (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom) : View Atom branch3Port0NativePlan :=
  forwardView branch3Port0Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan value
def branch3Port0FromNative (Atom : Expr → Type u) (value : View Atom branch3Port0NativePlan) : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom :=
  backwardView branch3Port0Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan value
theorem branch3Port0_candidate_round_trip (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom) :
    branch3Port0FromNative Atom (branch3Port0ToNative Atom value) = value := by
  simp [branch3Port0FromNative, branch3Port0ToNative, view_forward_inverse]
theorem branch3Port0_native_round_trip (Atom : Expr → Type u) (value : View Atom branch3Port0NativePlan) :
    branch3Port0ToNative Atom (branch3Port0FromNative Atom value) = value := by
  simp [branch3Port0FromNative, branch3Port0ToNative, view_inverse_forward]
theorem branch3Port0_extraction_commutes (Atom : Expr → Type u) (value : Data Atom Auths.Qualification.NativeBorrowView.branch3Schema0.shape) :
    branch3Port0ToNative Atom (get Auths.Qualification.NativeBorrowView.branch3Schema0.plan value) =
      get branch3Port0NativePlan (forward branch3Port0Change value) := by
  simpa [branch3Port0ToNative, ← branch3Port0_selected_plan_matches_native] using extraction_commutes branch3Port0Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan value
theorem branch3Port0_restoration_commutes (Atom : Expr → Type u) (before : Data Atom Auths.Qualification.NativeBorrowView.branch3Schema0.shape)
    (update : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom) :
    put branch3Port0NativePlan (forward branch3Port0Change before) (branch3Port0ToNative Atom update) =
      (put Auths.Qualification.NativeBorrowView.branch3Schema0.plan before update).map (forward branch3Port0Change) := by
  simpa [branch3Port0ToNative, ← branch3Port0_selected_plan_matches_native] using restoration_commutes branch3Port0Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan before update
def branch3Port1NativeShape : Shape := .named (.boxed) (.named (.nominal (.node .adt [.natural 507, .node .arguments [.node .regions [.region (.parameter 2)], .node .types [.node .mutRef [.region (.parameter 3), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]], .node .constants [], .node .traits []]])) (.sum (.named (.variant 0) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 2) (.borrow true (.parameter 3) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.variant 1) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 2) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty))))
def branch3Port1Mapping : List (Nat × Nat) := [(2, 2), (3, 3)]
def branch3Port1Change : Change Auths.Qualification.NativeBorrowView.branch3Schema1.shape branch3Port1NativeShape := .named (.named (.sum (.named (.product (.named (.borrow true (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.product (.named (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty))))
theorem branch3Port1_metadata_is_exact : validMap branch3Port1Mapping && metadataMatch branch3Port1Mapping 15 branch3Port1Change = true := by
  rfl
def branch3Port1NativePlan : Plan branch3Port1NativeShape := Auths.Support.BorrowProjection.select [.parameter 3] branch3Port1NativeShape
theorem branch3Port1_selected_plan_matches_native : mapPlan branch3Port1Change Auths.Qualification.NativeBorrowView.branch3Schema1.plan = branch3Port1NativePlan := by
  rfl
def branch3Port1ToNative (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch3Schema1.Payload Atom) : View Atom branch3Port1NativePlan :=
  forwardView branch3Port1Change Auths.Qualification.NativeBorrowView.branch3Schema1.plan value
def branch3Port1FromNative (Atom : Expr → Type u) (value : View Atom branch3Port1NativePlan) : Auths.Qualification.NativeBorrowView.branch3Schema1.Payload Atom :=
  backwardView branch3Port1Change Auths.Qualification.NativeBorrowView.branch3Schema1.plan value
theorem branch3Port1_candidate_round_trip (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch3Schema1.Payload Atom) :
    branch3Port1FromNative Atom (branch3Port1ToNative Atom value) = value := by
  simp [branch3Port1FromNative, branch3Port1ToNative, view_forward_inverse]
theorem branch3Port1_native_round_trip (Atom : Expr → Type u) (value : View Atom branch3Port1NativePlan) :
    branch3Port1ToNative Atom (branch3Port1FromNative Atom value) = value := by
  simp [branch3Port1FromNative, branch3Port1ToNative, view_inverse_forward]
theorem branch3Port1_extraction_commutes (Atom : Expr → Type u) (value : Data Atom Auths.Qualification.NativeBorrowView.branch3Schema1.shape) :
    branch3Port1ToNative Atom (get Auths.Qualification.NativeBorrowView.branch3Schema1.plan value) =
      get branch3Port1NativePlan (forward branch3Port1Change value) := by
  simpa [branch3Port1ToNative, ← branch3Port1_selected_plan_matches_native] using extraction_commutes branch3Port1Change Auths.Qualification.NativeBorrowView.branch3Schema1.plan value
theorem branch3Port1_restoration_commutes (Atom : Expr → Type u) (before : Data Atom Auths.Qualification.NativeBorrowView.branch3Schema1.shape)
    (update : Auths.Qualification.NativeBorrowView.branch3Schema1.Payload Atom) :
    put branch3Port1NativePlan (forward branch3Port1Change before) (branch3Port1ToNative Atom update) =
      (put Auths.Qualification.NativeBorrowView.branch3Schema1.plan before update).map (forward branch3Port1Change) := by
  simpa [branch3Port1ToNative, ← branch3Port1_selected_plan_matches_native] using restoration_commutes branch3Port1Change Auths.Qualification.NativeBorrowView.branch3Schema1.plan before update
def branch3Port2NativeShape : Shape := .named (.nominal (.node .adt [.natural 507, .node .arguments [.node .regions [.region (.parameter 78)], .node .types [.node .mutRef [.region (.parameter 79), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]], .node .constants [], .node .traits []]])) (.sum (.named (.variant 0) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 78) (.borrow true (.parameter 79) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.variant 1) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 78) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty)))
def branch3Port2Mapping : List (Nat × Nat) := [(2, 78), (3, 79)]
def branch3Port2Change : Change Auths.Qualification.NativeBorrowView.branch3Schema0.shape branch3Port2NativeShape := .named (.sum (.named (.product (.named (.borrow true (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.product (.named (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty)))
theorem branch3Port2_metadata_is_exact : validMap branch3Port2Mapping && metadataMatch branch3Port2Mapping 15 branch3Port2Change = true := by
  rfl
def branch3Port2NativePlan : Plan branch3Port2NativeShape := Auths.Support.BorrowProjection.select [.parameter 79] branch3Port2NativeShape
theorem branch3Port2_selected_plan_matches_native : mapPlan branch3Port2Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan = branch3Port2NativePlan := by
  rfl
def branch3Port2ToNative (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom) : View Atom branch3Port2NativePlan :=
  forwardView branch3Port2Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan value
def branch3Port2FromNative (Atom : Expr → Type u) (value : View Atom branch3Port2NativePlan) : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom :=
  backwardView branch3Port2Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan value
theorem branch3Port2_candidate_round_trip (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom) :
    branch3Port2FromNative Atom (branch3Port2ToNative Atom value) = value := by
  simp [branch3Port2FromNative, branch3Port2ToNative, view_forward_inverse]
theorem branch3Port2_native_round_trip (Atom : Expr → Type u) (value : View Atom branch3Port2NativePlan) :
    branch3Port2ToNative Atom (branch3Port2FromNative Atom value) = value := by
  simp [branch3Port2FromNative, branch3Port2ToNative, view_inverse_forward]
theorem branch3Port2_extraction_commutes (Atom : Expr → Type u) (value : Data Atom Auths.Qualification.NativeBorrowView.branch3Schema0.shape) :
    branch3Port2ToNative Atom (get Auths.Qualification.NativeBorrowView.branch3Schema0.plan value) =
      get branch3Port2NativePlan (forward branch3Port2Change value) := by
  simpa [branch3Port2ToNative, ← branch3Port2_selected_plan_matches_native] using extraction_commutes branch3Port2Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan value
theorem branch3Port2_restoration_commutes (Atom : Expr → Type u) (before : Data Atom Auths.Qualification.NativeBorrowView.branch3Schema0.shape)
    (update : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom) :
    put branch3Port2NativePlan (forward branch3Port2Change before) (branch3Port2ToNative Atom update) =
      (put Auths.Qualification.NativeBorrowView.branch3Schema0.plan before update).map (forward branch3Port2Change) := by
  simpa [branch3Port2ToNative, ← branch3Port2_selected_plan_matches_native] using restoration_commutes branch3Port2Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan before update
def branch3Port3NativeShape : Shape := .named (.nominal (.node .adt [.natural 507, .node .arguments [.node .regions [.region (.parameter 78)], .node .types [.node .mutRef [.region (.parameter 79), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]], .node .constants [], .node .traits []]])) (.sum (.named (.variant 0) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 78) (.borrow true (.parameter 79) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.variant 1) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 78) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty)))
def branch3Port3Mapping : List (Nat × Nat) := [(2, 78), (3, 79)]
def branch3Port3Change : Change Auths.Qualification.NativeBorrowView.branch3Schema0.shape branch3Port3NativeShape := .named (.sum (.named (.product (.named (.borrow true (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.product (.named (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty)))
theorem branch3Port3_metadata_is_exact : validMap branch3Port3Mapping && metadataMatch branch3Port3Mapping 15 branch3Port3Change = true := by
  rfl
def branch3Port3NativePlan : Plan branch3Port3NativeShape := Auths.Support.BorrowProjection.select [.parameter 79] branch3Port3NativeShape
theorem branch3Port3_selected_plan_matches_native : mapPlan branch3Port3Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan = branch3Port3NativePlan := by
  rfl
def branch3Port3ToNative (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom) : View Atom branch3Port3NativePlan :=
  forwardView branch3Port3Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan value
def branch3Port3FromNative (Atom : Expr → Type u) (value : View Atom branch3Port3NativePlan) : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom :=
  backwardView branch3Port3Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan value
theorem branch3Port3_candidate_round_trip (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom) :
    branch3Port3FromNative Atom (branch3Port3ToNative Atom value) = value := by
  simp [branch3Port3FromNative, branch3Port3ToNative, view_forward_inverse]
theorem branch3Port3_native_round_trip (Atom : Expr → Type u) (value : View Atom branch3Port3NativePlan) :
    branch3Port3ToNative Atom (branch3Port3FromNative Atom value) = value := by
  simp [branch3Port3FromNative, branch3Port3ToNative, view_inverse_forward]
theorem branch3Port3_extraction_commutes (Atom : Expr → Type u) (value : Data Atom Auths.Qualification.NativeBorrowView.branch3Schema0.shape) :
    branch3Port3ToNative Atom (get Auths.Qualification.NativeBorrowView.branch3Schema0.plan value) =
      get branch3Port3NativePlan (forward branch3Port3Change value) := by
  simpa [branch3Port3ToNative, ← branch3Port3_selected_plan_matches_native] using extraction_commutes branch3Port3Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan value
theorem branch3Port3_restoration_commutes (Atom : Expr → Type u) (before : Data Atom Auths.Qualification.NativeBorrowView.branch3Schema0.shape)
    (update : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom) :
    put branch3Port3NativePlan (forward branch3Port3Change before) (branch3Port3ToNative Atom update) =
      (put Auths.Qualification.NativeBorrowView.branch3Schema0.plan before update).map (forward branch3Port3Change) := by
  simpa [branch3Port3ToNative, ← branch3Port3_selected_plan_matches_native] using restoration_commutes branch3Port3Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan before update
def branch3Port4NativeShape : Shape := .named (.boxed) (.named (.nominal (.node .adt [.natural 507, .node .arguments [.node .regions [.region (.parameter 78)], .node .types [.node .mutRef [.region (.parameter 79), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]], .node .constants [], .node .traits []]])) (.sum (.named (.variant 0) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 78) (.borrow true (.parameter 79) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.variant 1) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 78) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty))))
def branch3Port4Mapping : List (Nat × Nat) := [(2, 78), (3, 79)]
def branch3Port4Change : Change Auths.Qualification.NativeBorrowView.branch3Schema1.shape branch3Port4NativeShape := .named (.named (.sum (.named (.product (.named (.borrow true (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.product (.named (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty))))
theorem branch3Port4_metadata_is_exact : validMap branch3Port4Mapping && metadataMatch branch3Port4Mapping 15 branch3Port4Change = true := by
  rfl
def branch3Port4NativePlan : Plan branch3Port4NativeShape := Auths.Support.BorrowProjection.select [.parameter 79] branch3Port4NativeShape
theorem branch3Port4_selected_plan_matches_native : mapPlan branch3Port4Change Auths.Qualification.NativeBorrowView.branch3Schema1.plan = branch3Port4NativePlan := by
  rfl
def branch3Port4ToNative (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch3Schema1.Payload Atom) : View Atom branch3Port4NativePlan :=
  forwardView branch3Port4Change Auths.Qualification.NativeBorrowView.branch3Schema1.plan value
def branch3Port4FromNative (Atom : Expr → Type u) (value : View Atom branch3Port4NativePlan) : Auths.Qualification.NativeBorrowView.branch3Schema1.Payload Atom :=
  backwardView branch3Port4Change Auths.Qualification.NativeBorrowView.branch3Schema1.plan value
theorem branch3Port4_candidate_round_trip (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch3Schema1.Payload Atom) :
    branch3Port4FromNative Atom (branch3Port4ToNative Atom value) = value := by
  simp [branch3Port4FromNative, branch3Port4ToNative, view_forward_inverse]
theorem branch3Port4_native_round_trip (Atom : Expr → Type u) (value : View Atom branch3Port4NativePlan) :
    branch3Port4ToNative Atom (branch3Port4FromNative Atom value) = value := by
  simp [branch3Port4FromNative, branch3Port4ToNative, view_inverse_forward]
theorem branch3Port4_extraction_commutes (Atom : Expr → Type u) (value : Data Atom Auths.Qualification.NativeBorrowView.branch3Schema1.shape) :
    branch3Port4ToNative Atom (get Auths.Qualification.NativeBorrowView.branch3Schema1.plan value) =
      get branch3Port4NativePlan (forward branch3Port4Change value) := by
  simpa [branch3Port4ToNative, ← branch3Port4_selected_plan_matches_native] using extraction_commutes branch3Port4Change Auths.Qualification.NativeBorrowView.branch3Schema1.plan value
theorem branch3Port4_restoration_commutes (Atom : Expr → Type u) (before : Data Atom Auths.Qualification.NativeBorrowView.branch3Schema1.shape)
    (update : Auths.Qualification.NativeBorrowView.branch3Schema1.Payload Atom) :
    put branch3Port4NativePlan (forward branch3Port4Change before) (branch3Port4ToNative Atom update) =
      (put Auths.Qualification.NativeBorrowView.branch3Schema1.plan before update).map (forward branch3Port4Change) := by
  simpa [branch3Port4ToNative, ← branch3Port4_selected_plan_matches_native] using restoration_commutes branch3Port4Change Auths.Qualification.NativeBorrowView.branch3Schema1.plan before update
def branch3Port5NativeShape : Shape := .named (.nominal (.node .adt [.natural 507, .node .arguments [.node .regions [.region (.parameter 2)], .node .types [.node .mutRef [.region (.parameter 3), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]], .node .constants [], .node .traits []]])) (.sum (.named (.variant 0) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 2) (.borrow true (.parameter 3) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.variant 1) (.product (.named (.field 0 (some [112, 97, 121, 108, 111, 97, 100])) (.borrow true (.parameter 2) (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty)))
def branch3Port5Mapping : List (Nat × Nat) := [(2, 2), (3, 3)]
def branch3Port5Change : Change Auths.Qualification.NativeBorrowView.branch3Schema0.shape branch3Port5NativeShape := .named (.sum (.named (.product (.named (.borrow true (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]))))) (.unit))) (.sum (.named (.product (.named (.borrow true (.atom (.node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]])))) (.unit))) (.empty)))
theorem branch3Port5_metadata_is_exact : validMap branch3Port5Mapping && metadataMatch branch3Port5Mapping 15 branch3Port5Change = true := by
  rfl
def branch3Port5NativePlan : Plan branch3Port5NativeShape := Auths.Support.BorrowProjection.select [.parameter 3] branch3Port5NativeShape
theorem branch3Port5_selected_plan_matches_native : mapPlan branch3Port5Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan = branch3Port5NativePlan := by
  rfl
def branch3Port5ToNative (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom) : View Atom branch3Port5NativePlan :=
  forwardView branch3Port5Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan value
def branch3Port5FromNative (Atom : Expr → Type u) (value : View Atom branch3Port5NativePlan) : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom :=
  backwardView branch3Port5Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan value
theorem branch3Port5_candidate_round_trip (Atom : Expr → Type u) (value : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom) :
    branch3Port5FromNative Atom (branch3Port5ToNative Atom value) = value := by
  simp [branch3Port5FromNative, branch3Port5ToNative, view_forward_inverse]
theorem branch3Port5_native_round_trip (Atom : Expr → Type u) (value : View Atom branch3Port5NativePlan) :
    branch3Port5ToNative Atom (branch3Port5FromNative Atom value) = value := by
  simp [branch3Port5FromNative, branch3Port5ToNative, view_inverse_forward]
theorem branch3Port5_extraction_commutes (Atom : Expr → Type u) (value : Data Atom Auths.Qualification.NativeBorrowView.branch3Schema0.shape) :
    branch3Port5ToNative Atom (get Auths.Qualification.NativeBorrowView.branch3Schema0.plan value) =
      get branch3Port5NativePlan (forward branch3Port5Change value) := by
  simpa [branch3Port5ToNative, ← branch3Port5_selected_plan_matches_native] using extraction_commutes branch3Port5Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan value
theorem branch3Port5_restoration_commutes (Atom : Expr → Type u) (before : Data Atom Auths.Qualification.NativeBorrowView.branch3Schema0.shape)
    (update : Auths.Qualification.NativeBorrowView.branch3Schema0.Payload Atom) :
    put branch3Port5NativePlan (forward branch3Port5Change before) (branch3Port5ToNative Atom update) =
      (put Auths.Qualification.NativeBorrowView.branch3Schema0.plan before update).map (forward branch3Port5Change) := by
  simpa [branch3Port5ToNative, ← branch3Port5_selected_plan_matches_native] using restoration_commutes branch3Port5Change Auths.Qualification.NativeBorrowView.branch3Schema0.plan before update
end Auths.Qualification.NativeBorrowTransport
