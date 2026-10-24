import Auths.Support.NativeInputCompatibility
import Auths.Support.BorrowTagTopology
import qualification.aeneas.cases.NativeBindingClosures
/- Complete native helper/program compatibility conditions and computed success outputs.
   Unelaborated/unqualified; actual Rust input/loan, original environment and dispatch adequacy remain open. -/
namespace Auths.Qualification.NativeCompatiblePrograms
open Auths.Support.NativePurePayload Auths.Support.NativePureExpressions
open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection
open Auths.Qualification.NativePureExpressions
open Auths.Qualification.BorrowProjection.Candidate3400
universe u
def branch0Channel0Packing : Auths.Support.NativeValuePacking.Root Auths.Qualification.NativePurePayload.branch0Channel0Layout (.literal 0) := .atom (.literal 0)
theorem branch0Channel0_packing_fuel_suffices : Auths.Support.NativeValuePacking.rootFuel branch0Channel0Packing ≤ Auths.Qualification.NativePureExpressions.branch0Channel0Fuel := by decide
def branch0Channel0Compatible (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : Prop := Auths.Support.BorrowViewCompatibility.Native.Compatible Auths.Qualification.NativeBorrowFullABI.branch0Channel0 Auths.Qualification.NativePurePayload.branch0Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec current input
def branch0Channel0Total (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (valid : branch0Channel0Compatible Atom current input) : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout :=
  Auths.Support.BorrowViewCompatibility.Native.restore Auths.Qualification.NativeBorrowFullABI.branch0Channel0 Auths.Qualification.NativePurePayload.branch0Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec current input valid
def branch0Channel0Matching (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout :=
  matchingNativeInput Auths.Qualification.NativeBorrowFullABI.branch0Channel0 Auths.Qualification.NativePurePayload.branch0Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec current
theorem branch0Channel0_matching_input_is_compatible (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) :
    branch0Channel0Compatible Atom current (branch0Channel0Matching Atom current) := Auths.Support.BorrowViewCompatibility.Native.matching_current_is_compatible _ _ _ _
theorem branch0Channel0_whole_inputs_are_compatible (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : branch0Channel0Compatible Atom current input :=
  Auths.Support.NativeInputCompatibility.whole_input_is_compatible Auths.Qualification.NativeBorrowFullABI.branch0Channel0 Auths.Qualification.NativeBorrowFullABI.branch0Channel0_owns_whole_pointee Auths.Qualification.NativePurePayload.branch0Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec current input
theorem branch0Channel0_native_helper_has_computed_success (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (valid : branch0Channel0Compatible Atom current input) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch0Channel0Fuel Auths.Qualification.NativePureExpressions.branch0Channel0 current input =
      some (Auths.Support.NativeValuePacking.success builtins branch0Channel0Packing (branch0Channel0Total Atom current input valid)) := by
  rw [Auths.Qualification.NativePureExpressions.branch0Channel0_evaluates_as_selected_adapter]
  exact Auths.Support.NativeInputCompatibility.compatible_helper_has_success builtins Auths.Qualification.NativePureExpressions.branch0Channel0Fuel branch0Channel0Packing Auths.Qualification.NativeBorrowFullABI.branch0Channel0 Auths.Qualification.NativePurePayload.branch0Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec current input valid branch0Channel0_packing_fuel_suffices
theorem branch0Channel0_matching_input_executes_successfully (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch0Channel0Fuel Auths.Qualification.NativePureExpressions.branch0Channel0 current (branch0Channel0Matching Atom current) =
      some (Auths.Support.NativeValuePacking.success builtins branch0Channel0Packing current) := by
  rw [Auths.Qualification.NativePureExpressions.branch0Channel0_evaluates_as_selected_adapter]
  change expected builtins Auths.Qualification.NativePureExpressions.branch0Channel0Fuel _ (adaptNative Auths.Qualification.NativeBorrowFullABI.branch0Channel0 Auths.Qualification.NativePurePayload.branch0Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec current (branch0Channel0Matching Atom current)) = _
  rw [matching_native_input_is_accepted]
  exact Auths.Support.NativeValuePacking.expected_some_is_success builtins _ branch0Channel0Packing current branch0Channel0_packing_fuel_suffices
theorem branch0Channel0_field_stores_supply_compatible_input (Atom : Ty → Type u) (current after : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (stores : Auths.Support.BorrowTagTopology.Native.Stores Auths.Qualification.NativeBorrowFullABI.branch0Channel0 Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec current after) :
    branch0Channel0Compatible Atom current (branch0Channel0Matching Atom after) :=
  Auths.Support.BorrowTagTopology.Native.stores_supply_compatible_native_input Auths.Qualification.NativeBorrowFullABI.branch0Channel0 Auths.Qualification.NativePurePayload.branch0Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec current after stores
theorem branch0Channel0_field_stores_execute_exact_final_value (Atom : Ty → Type u) (current after : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (stores : Auths.Support.BorrowTagTopology.Native.Stores Auths.Qualification.NativeBorrowFullABI.branch0Channel0 Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec current after) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch0Channel0Fuel Auths.Qualification.NativePureExpressions.branch0Channel0 current (branch0Channel0Matching Atom after) =
      some (Auths.Support.NativeValuePacking.success builtins branch0Channel0Packing after) := by
  rw [Auths.Qualification.NativePureExpressions.branch0Channel0_evaluates_as_selected_adapter]
  change expected builtins Auths.Qualification.NativePureExpressions.branch0Channel0Fuel _ (adaptNative Auths.Qualification.NativeBorrowFullABI.branch0Channel0 Auths.Qualification.NativePurePayload.branch0Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec current (branch0Channel0Matching Atom after)) = _
  rw [Auths.Support.BorrowTagTopology.Native.stores_reconstruct_exact_native_value Auths.Qualification.NativeBorrowFullABI.branch0Channel0 Auths.Qualification.NativePurePayload.branch0Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec current after stores]
  exact Auths.Support.NativeValuePacking.expected_some_is_success builtins _ branch0Channel0Packing after branch0Channel0_packing_fuel_suffices
def branch1Channel0Packing : Auths.Support.NativeValuePacking.Root Auths.Qualification.NativePurePayload.branch1Channel0Layout (.nominal 507 [.nominal 5 [.literal 1]]) := .nominal (.nominal 507 [.nominal 5 [.literal 1]]) (.sum (.variant 0 (.cons 0 (some [112, 97, 121, 108, 111, 97, 100]) (.atom (.nominal 5 [.literal 1])) (.unit 1))) (.sum (.variant 1 (.cons 0 (some [112, 97, 121, 108, 111, 97, 100]) (.atom (.nominal 5 [.literal 1])) (.unit 1))) (.empty)))
theorem branch1Channel0_packing_fuel_suffices : Auths.Support.NativeValuePacking.rootFuel branch1Channel0Packing ≤ Auths.Qualification.NativePureExpressions.branch1Channel0Fuel := by decide
def branch1Channel0Compatible (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : Prop := Auths.Support.BorrowViewCompatibility.Native.Compatible Auths.Qualification.NativeBorrowFullABI.branch1Channel0 Auths.Qualification.NativePurePayload.branch1Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch1Channel0OutgoingCodec current input
def branch1Channel0Total (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) (valid : branch1Channel0Compatible Atom current input) : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout :=
  Auths.Support.BorrowViewCompatibility.Native.restore Auths.Qualification.NativeBorrowFullABI.branch1Channel0 Auths.Qualification.NativePurePayload.branch1Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch1Channel0OutgoingCodec current input valid
def branch1Channel0Matching (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout :=
  matchingNativeInput Auths.Qualification.NativeBorrowFullABI.branch1Channel0 Auths.Qualification.NativePurePayload.branch1Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch1Channel0OutgoingCodec current
theorem branch1Channel0_matching_input_is_compatible (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) :
    branch1Channel0Compatible Atom current (branch1Channel0Matching Atom current) := Auths.Support.BorrowViewCompatibility.Native.matching_current_is_compatible _ _ _ _
theorem branch1Channel0_whole_inputs_are_compatible (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : branch1Channel0Compatible Atom current input :=
  Auths.Support.NativeInputCompatibility.whole_input_is_compatible Auths.Qualification.NativeBorrowFullABI.branch1Channel0 Auths.Qualification.NativeBorrowFullABI.branch1Channel0_owns_whole_pointee Auths.Qualification.NativePurePayload.branch1Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch1Channel0OutgoingCodec current input
theorem branch1Channel0_native_helper_has_computed_success (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) (valid : branch1Channel0Compatible Atom current input) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch1Channel0Fuel Auths.Qualification.NativePureExpressions.branch1Channel0 current input =
      some (Auths.Support.NativeValuePacking.success builtins branch1Channel0Packing (branch1Channel0Total Atom current input valid)) := by
  rw [Auths.Qualification.NativePureExpressions.branch1Channel0_evaluates_as_selected_adapter]
  exact Auths.Support.NativeInputCompatibility.compatible_helper_has_success builtins Auths.Qualification.NativePureExpressions.branch1Channel0Fuel branch1Channel0Packing Auths.Qualification.NativeBorrowFullABI.branch1Channel0 Auths.Qualification.NativePurePayload.branch1Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch1Channel0OutgoingCodec current input valid branch1Channel0_packing_fuel_suffices
theorem branch1Channel0_matching_input_executes_successfully (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch1Channel0Fuel Auths.Qualification.NativePureExpressions.branch1Channel0 current (branch1Channel0Matching Atom current) =
      some (Auths.Support.NativeValuePacking.success builtins branch1Channel0Packing current) := by
  rw [Auths.Qualification.NativePureExpressions.branch1Channel0_evaluates_as_selected_adapter]
  change expected builtins Auths.Qualification.NativePureExpressions.branch1Channel0Fuel _ (adaptNative Auths.Qualification.NativeBorrowFullABI.branch1Channel0 Auths.Qualification.NativePurePayload.branch1Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch1Channel0OutgoingCodec current (branch1Channel0Matching Atom current)) = _
  rw [matching_native_input_is_accepted]
  exact Auths.Support.NativeValuePacking.expected_some_is_success builtins _ branch1Channel0Packing current branch1Channel0_packing_fuel_suffices
theorem branch1Channel0_field_stores_supply_compatible_input (Atom : Ty → Type u) (current after : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) (stores : Auths.Support.BorrowTagTopology.Native.Stores Auths.Qualification.NativeBorrowFullABI.branch1Channel0 Auths.Qualification.NativePurePayload.branch1Channel0OutgoingCodec current after) :
    branch1Channel0Compatible Atom current (branch1Channel0Matching Atom after) :=
  Auths.Support.BorrowTagTopology.Native.stores_supply_compatible_native_input Auths.Qualification.NativeBorrowFullABI.branch1Channel0 Auths.Qualification.NativePurePayload.branch1Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch1Channel0OutgoingCodec current after stores
theorem branch1Channel0_field_stores_execute_exact_final_value (Atom : Ty → Type u) (current after : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) (stores : Auths.Support.BorrowTagTopology.Native.Stores Auths.Qualification.NativeBorrowFullABI.branch1Channel0 Auths.Qualification.NativePurePayload.branch1Channel0OutgoingCodec current after) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch1Channel0Fuel Auths.Qualification.NativePureExpressions.branch1Channel0 current (branch1Channel0Matching Atom after) =
      some (Auths.Support.NativeValuePacking.success builtins branch1Channel0Packing after) := by
  rw [Auths.Qualification.NativePureExpressions.branch1Channel0_evaluates_as_selected_adapter]
  change expected builtins Auths.Qualification.NativePureExpressions.branch1Channel0Fuel _ (adaptNative Auths.Qualification.NativeBorrowFullABI.branch1Channel0 Auths.Qualification.NativePurePayload.branch1Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch1Channel0OutgoingCodec current (branch1Channel0Matching Atom after)) = _
  rw [Auths.Support.BorrowTagTopology.Native.stores_reconstruct_exact_native_value Auths.Qualification.NativeBorrowFullABI.branch1Channel0 Auths.Qualification.NativePurePayload.branch1Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch1Channel0OutgoingCodec current after stores]
  exact Auths.Support.NativeValuePacking.expected_some_is_success builtins _ branch1Channel0Packing after branch1Channel0_packing_fuel_suffices
def branch2Channel0Packing : Auths.Support.NativeValuePacking.Root Auths.Qualification.NativePurePayload.branch2Channel0Layout (.nominal 507 [.nominal 5 [.literal 1]]) := .nominal (.nominal 507 [.nominal 5 [.literal 1]]) (.sum (.variant 0 (.cons 0 (some [112, 97, 121, 108, 111, 97, 100]) (.atom (.nominal 5 [.literal 1])) (.unit 1))) (.sum (.variant 1 (.cons 0 (some [112, 97, 121, 108, 111, 97, 100]) (.atom (.nominal 5 [.literal 1])) (.unit 1))) (.empty)))
theorem branch2Channel0_packing_fuel_suffices : Auths.Support.NativeValuePacking.rootFuel branch2Channel0Packing ≤ Auths.Qualification.NativePureExpressions.branch2Channel0Fuel := by decide
def branch2Channel0Compatible (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Prop := Auths.Support.BorrowViewCompatibility.Native.Compatible Auths.Qualification.NativeBorrowFullABI.branch2Channel0 Auths.Qualification.NativePurePayload.branch2Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec current input
def branch2Channel0Total (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (valid : branch2Channel0Compatible Atom current input) : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout :=
  Auths.Support.BorrowViewCompatibility.Native.restore Auths.Qualification.NativeBorrowFullABI.branch2Channel0 Auths.Qualification.NativePurePayload.branch2Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec current input valid
def branch2Channel0Matching (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout :=
  matchingNativeInput Auths.Qualification.NativeBorrowFullABI.branch2Channel0 Auths.Qualification.NativePurePayload.branch2Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec current
theorem branch2Channel0_matching_input_is_compatible (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    branch2Channel0Compatible Atom current (branch2Channel0Matching Atom current) := Auths.Support.BorrowViewCompatibility.Native.matching_current_is_compatible _ _ _ _
theorem branch2Channel0_native_helper_has_computed_success (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (valid : branch2Channel0Compatible Atom current input) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch2Channel0Fuel Auths.Qualification.NativePureExpressions.branch2Channel0 current input =
      some (Auths.Support.NativeValuePacking.success builtins branch2Channel0Packing (branch2Channel0Total Atom current input valid)) := by
  rw [Auths.Qualification.NativePureExpressions.branch2Channel0_evaluates_as_selected_adapter]
  exact Auths.Support.NativeInputCompatibility.compatible_helper_has_success builtins Auths.Qualification.NativePureExpressions.branch2Channel0Fuel branch2Channel0Packing Auths.Qualification.NativeBorrowFullABI.branch2Channel0 Auths.Qualification.NativePurePayload.branch2Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec current input valid branch2Channel0_packing_fuel_suffices
theorem branch2Channel0_matching_input_executes_successfully (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch2Channel0Fuel Auths.Qualification.NativePureExpressions.branch2Channel0 current (branch2Channel0Matching Atom current) =
      some (Auths.Support.NativeValuePacking.success builtins branch2Channel0Packing current) := by
  rw [Auths.Qualification.NativePureExpressions.branch2Channel0_evaluates_as_selected_adapter]
  change expected builtins Auths.Qualification.NativePureExpressions.branch2Channel0Fuel _ (adaptNative Auths.Qualification.NativeBorrowFullABI.branch2Channel0 Auths.Qualification.NativePurePayload.branch2Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec current (branch2Channel0Matching Atom current)) = _
  rw [matching_native_input_is_accepted]
  exact Auths.Support.NativeValuePacking.expected_some_is_success builtins _ branch2Channel0Packing current branch2Channel0_packing_fuel_suffices
theorem branch2Channel0_field_stores_supply_compatible_input (Atom : Ty → Type u) (current after : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (stores : Auths.Support.BorrowTagTopology.Native.Stores Auths.Qualification.NativeBorrowFullABI.branch2Channel0 Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec current after) :
    branch2Channel0Compatible Atom current (branch2Channel0Matching Atom after) :=
  Auths.Support.BorrowTagTopology.Native.stores_supply_compatible_native_input Auths.Qualification.NativeBorrowFullABI.branch2Channel0 Auths.Qualification.NativePurePayload.branch2Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec current after stores
theorem branch2Channel0_field_stores_execute_exact_final_value (Atom : Ty → Type u) (current after : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (stores : Auths.Support.BorrowTagTopology.Native.Stores Auths.Qualification.NativeBorrowFullABI.branch2Channel0 Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec current after) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch2Channel0Fuel Auths.Qualification.NativePureExpressions.branch2Channel0 current (branch2Channel0Matching Atom after) =
      some (Auths.Support.NativeValuePacking.success builtins branch2Channel0Packing after) := by
  rw [Auths.Qualification.NativePureExpressions.branch2Channel0_evaluates_as_selected_adapter]
  change expected builtins Auths.Qualification.NativePureExpressions.branch2Channel0Fuel _ (adaptNative Auths.Qualification.NativeBorrowFullABI.branch2Channel0 Auths.Qualification.NativePurePayload.branch2Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec current (branch2Channel0Matching Atom after)) = _
  rw [Auths.Support.BorrowTagTopology.Native.stores_reconstruct_exact_native_value Auths.Qualification.NativeBorrowFullABI.branch2Channel0 Auths.Qualification.NativePurePayload.branch2Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec current after stores]
  exact Auths.Support.NativeValuePacking.expected_some_is_success builtins _ branch2Channel0Packing after branch2Channel0_packing_fuel_suffices
def branch3Channel0Packing : Auths.Support.NativeValuePacking.Root Auths.Qualification.NativePurePayload.branch3Channel0Layout (.nominal 507 [.nominal 5 [.literal 1]]) := .nominal (.nominal 507 [.nominal 5 [.literal 1]]) (.sum (.variant 0 (.cons 0 (some [112, 97, 121, 108, 111, 97, 100]) (.atom (.nominal 5 [.literal 1])) (.unit 1))) (.sum (.variant 1 (.cons 0 (some [112, 97, 121, 108, 111, 97, 100]) (.atom (.nominal 5 [.literal 1])) (.unit 1))) (.empty)))
theorem branch3Channel0_packing_fuel_suffices : Auths.Support.NativeValuePacking.rootFuel branch3Channel0Packing ≤ Auths.Qualification.NativePureExpressions.branch3Channel0Fuel := by decide
def branch3Channel0Compatible (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) : Prop := Auths.Support.BorrowViewCompatibility.Native.Compatible Auths.Qualification.NativeBorrowFullABI.branch3Channel0 Auths.Qualification.NativePurePayload.branch3Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel0OutgoingCodec current input
def branch3Channel0Total (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (valid : branch3Channel0Compatible Atom current input) : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout :=
  Auths.Support.BorrowViewCompatibility.Native.restore Auths.Qualification.NativeBorrowFullABI.branch3Channel0 Auths.Qualification.NativePurePayload.branch3Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel0OutgoingCodec current input valid
def branch3Channel0Matching (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout :=
  matchingNativeInput Auths.Qualification.NativeBorrowFullABI.branch3Channel0 Auths.Qualification.NativePurePayload.branch3Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel0OutgoingCodec current
theorem branch3Channel0_matching_input_is_compatible (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) :
    branch3Channel0Compatible Atom current (branch3Channel0Matching Atom current) := Auths.Support.BorrowViewCompatibility.Native.matching_current_is_compatible _ _ _ _
theorem branch3Channel0_native_helper_has_computed_success (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (valid : branch3Channel0Compatible Atom current input) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch3Channel0Fuel Auths.Qualification.NativePureExpressions.branch3Channel0 current input =
      some (Auths.Support.NativeValuePacking.success builtins branch3Channel0Packing (branch3Channel0Total Atom current input valid)) := by
  rw [Auths.Qualification.NativePureExpressions.branch3Channel0_evaluates_as_selected_adapter]
  exact Auths.Support.NativeInputCompatibility.compatible_helper_has_success builtins Auths.Qualification.NativePureExpressions.branch3Channel0Fuel branch3Channel0Packing Auths.Qualification.NativeBorrowFullABI.branch3Channel0 Auths.Qualification.NativePurePayload.branch3Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel0OutgoingCodec current input valid branch3Channel0_packing_fuel_suffices
theorem branch3Channel0_matching_input_executes_successfully (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch3Channel0Fuel Auths.Qualification.NativePureExpressions.branch3Channel0 current (branch3Channel0Matching Atom current) =
      some (Auths.Support.NativeValuePacking.success builtins branch3Channel0Packing current) := by
  rw [Auths.Qualification.NativePureExpressions.branch3Channel0_evaluates_as_selected_adapter]
  change expected builtins Auths.Qualification.NativePureExpressions.branch3Channel0Fuel _ (adaptNative Auths.Qualification.NativeBorrowFullABI.branch3Channel0 Auths.Qualification.NativePurePayload.branch3Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel0OutgoingCodec current (branch3Channel0Matching Atom current)) = _
  rw [matching_native_input_is_accepted]
  exact Auths.Support.NativeValuePacking.expected_some_is_success builtins _ branch3Channel0Packing current branch3Channel0_packing_fuel_suffices
theorem branch3Channel0_field_stores_supply_compatible_input (Atom : Ty → Type u) (current after : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (stores : Auths.Support.BorrowTagTopology.Native.Stores Auths.Qualification.NativeBorrowFullABI.branch3Channel0 Auths.Qualification.NativePurePayload.branch3Channel0OutgoingCodec current after) :
    branch3Channel0Compatible Atom current (branch3Channel0Matching Atom after) :=
  Auths.Support.BorrowTagTopology.Native.stores_supply_compatible_native_input Auths.Qualification.NativeBorrowFullABI.branch3Channel0 Auths.Qualification.NativePurePayload.branch3Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel0OutgoingCodec current after stores
theorem branch3Channel0_field_stores_execute_exact_final_value (Atom : Ty → Type u) (current after : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (stores : Auths.Support.BorrowTagTopology.Native.Stores Auths.Qualification.NativeBorrowFullABI.branch3Channel0 Auths.Qualification.NativePurePayload.branch3Channel0OutgoingCodec current after) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch3Channel0Fuel Auths.Qualification.NativePureExpressions.branch3Channel0 current (branch3Channel0Matching Atom after) =
      some (Auths.Support.NativeValuePacking.success builtins branch3Channel0Packing after) := by
  rw [Auths.Qualification.NativePureExpressions.branch3Channel0_evaluates_as_selected_adapter]
  change expected builtins Auths.Qualification.NativePureExpressions.branch3Channel0Fuel _ (adaptNative Auths.Qualification.NativeBorrowFullABI.branch3Channel0 Auths.Qualification.NativePurePayload.branch3Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel0OutgoingCodec current (branch3Channel0Matching Atom after)) = _
  rw [Auths.Support.BorrowTagTopology.Native.stores_reconstruct_exact_native_value Auths.Qualification.NativeBorrowFullABI.branch3Channel0 Auths.Qualification.NativePurePayload.branch3Channel0IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel0OutgoingCodec current after stores]
  exact Auths.Support.NativeValuePacking.expected_some_is_success builtins _ branch3Channel0Packing after branch3Channel0_packing_fuel_suffices
def branch3Channel1Packing : Auths.Support.NativeValuePacking.Root Auths.Qualification.NativePurePayload.branch3Channel1Layout (.nominal 507 [.nominal 5 [.literal 1]]) := .nominal (.nominal 507 [.nominal 5 [.literal 1]]) (.sum (.variant 0 (.cons 0 (some [112, 97, 121, 108, 111, 97, 100]) (.atom (.nominal 5 [.literal 1])) (.unit 1))) (.sum (.variant 1 (.cons 0 (some [112, 97, 121, 108, 111, 97, 100]) (.atom (.nominal 5 [.literal 1])) (.unit 1))) (.empty)))
theorem branch3Channel1_packing_fuel_suffices : Auths.Support.NativeValuePacking.rootFuel branch3Channel1Packing ≤ Auths.Qualification.NativePureExpressions.branch3Channel1Fuel := by decide
def branch3Channel1Compatible (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) : Prop := Auths.Support.BorrowViewCompatibility.Native.Compatible Auths.Qualification.NativeBorrowFullABI.branch3Channel1 Auths.Qualification.NativePurePayload.branch3Channel1IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel1OutgoingCodec current input
def branch3Channel1Total (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) (valid : branch3Channel1Compatible Atom current input) : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout :=
  Auths.Support.BorrowViewCompatibility.Native.restore Auths.Qualification.NativeBorrowFullABI.branch3Channel1 Auths.Qualification.NativePurePayload.branch3Channel1IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel1OutgoingCodec current input valid
def branch3Channel1Matching (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout :=
  matchingNativeInput Auths.Qualification.NativeBorrowFullABI.branch3Channel1 Auths.Qualification.NativePurePayload.branch3Channel1IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel1OutgoingCodec current
theorem branch3Channel1_matching_input_is_compatible (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) :
    branch3Channel1Compatible Atom current (branch3Channel1Matching Atom current) := Auths.Support.BorrowViewCompatibility.Native.matching_current_is_compatible _ _ _ _
theorem branch3Channel1_native_helper_has_computed_success (Atom : Ty → Type u) (current input : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) (valid : branch3Channel1Compatible Atom current input) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch3Channel1Fuel Auths.Qualification.NativePureExpressions.branch3Channel1 current input =
      some (Auths.Support.NativeValuePacking.success builtins branch3Channel1Packing (branch3Channel1Total Atom current input valid)) := by
  rw [Auths.Qualification.NativePureExpressions.branch3Channel1_evaluates_as_selected_adapter]
  exact Auths.Support.NativeInputCompatibility.compatible_helper_has_success builtins Auths.Qualification.NativePureExpressions.branch3Channel1Fuel branch3Channel1Packing Auths.Qualification.NativeBorrowFullABI.branch3Channel1 Auths.Qualification.NativePurePayload.branch3Channel1IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel1OutgoingCodec current input valid branch3Channel1_packing_fuel_suffices
theorem branch3Channel1_matching_input_executes_successfully (Atom : Ty → Type u) (current : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch3Channel1Fuel Auths.Qualification.NativePureExpressions.branch3Channel1 current (branch3Channel1Matching Atom current) =
      some (Auths.Support.NativeValuePacking.success builtins branch3Channel1Packing current) := by
  rw [Auths.Qualification.NativePureExpressions.branch3Channel1_evaluates_as_selected_adapter]
  change expected builtins Auths.Qualification.NativePureExpressions.branch3Channel1Fuel _ (adaptNative Auths.Qualification.NativeBorrowFullABI.branch3Channel1 Auths.Qualification.NativePurePayload.branch3Channel1IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel1OutgoingCodec current (branch3Channel1Matching Atom current)) = _
  rw [matching_native_input_is_accepted]
  exact Auths.Support.NativeValuePacking.expected_some_is_success builtins _ branch3Channel1Packing current branch3Channel1_packing_fuel_suffices
theorem branch3Channel1_field_stores_supply_compatible_input (Atom : Ty → Type u) (current after : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) (stores : Auths.Support.BorrowTagTopology.Native.Stores Auths.Qualification.NativeBorrowFullABI.branch3Channel1 Auths.Qualification.NativePurePayload.branch3Channel1OutgoingCodec current after) :
    branch3Channel1Compatible Atom current (branch3Channel1Matching Atom after) :=
  Auths.Support.BorrowTagTopology.Native.stores_supply_compatible_native_input Auths.Qualification.NativeBorrowFullABI.branch3Channel1 Auths.Qualification.NativePurePayload.branch3Channel1IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel1OutgoingCodec current after stores
theorem branch3Channel1_field_stores_execute_exact_final_value (Atom : Ty → Type u) (current after : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) (stores : Auths.Support.BorrowTagTopology.Native.Stores Auths.Qualification.NativeBorrowFullABI.branch3Channel1 Auths.Qualification.NativePurePayload.branch3Channel1OutgoingCodec current after) :
    execute builtins schemas Auths.Qualification.NativePureExpressions.branch3Channel1Fuel Auths.Qualification.NativePureExpressions.branch3Channel1 current (branch3Channel1Matching Atom after) =
      some (Auths.Support.NativeValuePacking.success builtins branch3Channel1Packing after) := by
  rw [Auths.Qualification.NativePureExpressions.branch3Channel1_evaluates_as_selected_adapter]
  change expected builtins Auths.Qualification.NativePureExpressions.branch3Channel1Fuel _ (adaptNative Auths.Qualification.NativeBorrowFullABI.branch3Channel1 Auths.Qualification.NativePurePayload.branch3Channel1IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel1OutgoingCodec current (branch3Channel1Matching Atom after)) = _
  rw [Auths.Support.BorrowTagTopology.Native.stores_reconstruct_exact_native_value Auths.Qualification.NativeBorrowFullABI.branch3Channel1 Auths.Qualification.NativePurePayload.branch3Channel1IncomingCodec Auths.Qualification.NativePurePayload.branch3Channel1OutgoingCodec current after stores]
  exact Auths.Support.NativeValuePacking.expected_some_is_success builtins _ branch3Channel1Packing after branch3Channel1_packing_fuel_suffices
def branch0Initial : Auths.Support.NativeInputCompatibility.Environment := [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (3, { variable := { identity := 3, type := .literal 0 }, source := { kind := .incoming, index := 0, type := .literal 0 } })]
def branch0Flow : List Auths.Support.NativeInputCompatibility.Operation := [.alias { target := { identity := 2, type := .literal 0 }, source := { identity := 3, type := .literal 0 } }, .output ({ variable := { identity := 2, type := .literal 0 }, source := { kind := .incoming, index := 0, type := .literal 0 } }) ({ variable := { identity := 2, type := .literal 0 }, source := { kind := .incoming, index := 0, type := .literal 0 } })]
def branch0Snapshots : List Auths.Support.NativeInputCompatibility.Environment := [[(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .incoming, index := 0, type := .literal 0 } }), (3, { variable := { identity := 3, type := .literal 0 }, source := { kind := .incoming, index := 0, type := .literal 0 } })], [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .incoming, index := 0, type := .literal 0 } }), (3, { variable := { identity := 3, type := .literal 0 }, source := { kind := .incoming, index := 0, type := .literal 0 } })]]
theorem branch0_all_value_references_follow_actual_earlier_bindings : Auths.Support.NativeInputCompatibility.scan branch0Initial branch0Flow = some branch0Snapshots := by decide
def branch0Compatible (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : Prop := branch0Channel0Compatible Atom incoming0 incoming0 ∧ True
def branch0Output0 (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (valid : branch0Compatible Atom counter writer incoming0) : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout :=
  branch0Channel0Total Atom incoming0 incoming0 valid.1
def branch0Success (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (valid : branch0Compatible Atom counter writer incoming0) : Dynamic Atom :=
  Auths.Support.NativeValuePacking.successMany builtins [Auths.Support.NativeValuePacking.rootValue branch0Channel0Packing (branch0Output0 Atom counter writer incoming0 valid)]
theorem branch0_compatible_inputs_execute_computed_success (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (valid : branch0Compatible Atom counter writer incoming0) :
    Auths.Qualification.NativeBindingClosures.branch0Run Atom counter writer incoming0 = some (branch0Success Atom counter writer incoming0 valid) := by
  unfold Auths.Qualification.NativeBindingClosures.branch0Run
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeBindingClosures.branch0Fuel Auths.Qualification.NativeBindingClosures.branch0 Auths.Qualification.NativeBindingClosures.branch0_well_typed]
  cases counter with
  | atom v0 =>
    cases writer with
    | named v1 =>
      cases v1 with
      | left v2 =>
        cases v2 with
        | named v4 =>
          cases v4 with
          | product v5 v6 =>
            cases v5 with
            | named v7 =>
              cases v7 with
              | atom v8 =>
                cases v6 with
                | unit =>
                  cases incoming0 with
                  | atom v9 =>
                    first
                    | exact False.elim (by simpa [branch0Compatible, branch0Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                    | rfl
      | right v3 =>
        cases v3 with
        | left v10 =>
          cases v10 with
          | named v12 =>
            cases v12 with
            | product v13 v14 =>
              cases v13 with
              | named v15 =>
                cases v15 with
                | atom v16 =>
                  cases v14 with
                  | unit =>
                    cases incoming0 with
                    | atom v17 =>
                      first
                      | exact False.elim (by simpa [branch0Compatible, branch0Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                      | rfl
        | right v11 =>
          cases v11
theorem branch0_incompatible_inputs_keep_explicit_representation_failure (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (invalid : ¬ branch0Compatible Atom counter writer incoming0) :
    Auths.Qualification.NativeBindingClosures.branch0Run Atom counter writer incoming0 = some (.constructor (.result (tupleType [.literal 0])) (some builtins.resultFail) [.constructor .error (some builtins.errorFailure) []]) := by
  unfold Auths.Qualification.NativeBindingClosures.branch0Run
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeBindingClosures.branch0Fuel Auths.Qualification.NativeBindingClosures.branch0 Auths.Qualification.NativeBindingClosures.branch0_well_typed]
  cases counter with
  | atom v18 =>
    cases writer with
    | named v19 =>
      cases v19 with
      | left v20 =>
        cases v20 with
        | named v22 =>
          cases v22 with
          | product v23 v24 =>
            cases v23 with
            | named v25 =>
              cases v25 with
              | atom v26 =>
                cases v24 with
                | unit =>
                  cases incoming0 with
                  | atom v27 =>
                    first
                    | exact False.elim (invalid (by simp [branch0Compatible, branch0Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                    | rfl
      | right v21 =>
        cases v21 with
        | left v28 =>
          cases v28 with
          | named v30 =>
            cases v30 with
            | product v31 v32 =>
              cases v31 with
              | named v33 =>
                cases v33 with
                | atom v34 =>
                  cases v32 with
                  | unit =>
                    cases incoming0 with
                    | atom v35 =>
                      first
                      | exact False.elim (invalid (by simp [branch0Compatible, branch0Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                      | rfl
        | right v29 =>
          cases v29
theorem branch0_compatible_bundle_invocation_succeeds (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (valid : branch0Compatible Atom counter writer incoming0) :
    Auths.Qualification.NativeBindingClosures.branch0Invoke Atom counter writer incoming0 = some (branch0Success Atom counter writer incoming0 valid) := by
  rw [Auths.Qualification.NativeBindingClosures.branch0_bundle_uses_its_exact_registry_program]
  exact branch0_compatible_inputs_execute_computed_success Atom counter writer incoming0 valid
def branch0Witness0 (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout := branch0Channel0Matching Atom counter
theorem branch0_matching_inputs_are_compatible (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : branch0Compatible Atom counter writer (branch0Witness0 Atom counter writer) := by
  exact ⟨branch0Channel0_whole_inputs_are_compatible Atom _ _, True.intro⟩
theorem branch0_has_successful_inputs_for_every_forward_current (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    Auths.Qualification.NativeBindingClosures.branch0Invoke Atom counter writer (branch0Witness0 Atom counter writer) = some (branch0Success Atom counter writer (branch0Witness0 Atom counter writer) (branch0_matching_inputs_are_compatible Atom counter writer)) :=
  branch0_compatible_bundle_invocation_succeeds Atom counter writer (branch0Witness0 Atom counter writer) (branch0_matching_inputs_are_compatible Atom counter writer)
def branch1Initial : Auths.Support.NativeInputCompatibility.Environment := [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (4, { variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } })]
def branch1Flow : List Auths.Support.NativeInputCompatibility.Operation := [.alias { target := { identity := 2, type := .literal 0 }, source := { identity := 0, type := .literal 0 } }, .alias { target := { identity := 5, type := .literal 0 }, source := { identity := 2, type := .literal 0 } }, .alias { target := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] } }, .output ({ variable := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }) ({ variable := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } })]
def branch1Snapshots : List Auths.Support.NativeInputCompatibility.Environment := [[(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (4, { variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } })], [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (4, { variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (5, { variable := { identity := 5, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } })], [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (3, { variable := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (4, { variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (5, { variable := { identity := 5, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } })], [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (3, { variable := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (4, { variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (5, { variable := { identity := 5, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } })]]
theorem branch1_all_value_references_follow_actual_earlier_bindings : Auths.Support.NativeInputCompatibility.scan branch1Initial branch1Flow = some branch1Snapshots := by decide
def branch1Compatible (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : Prop := branch1Channel0Compatible Atom incoming0 incoming0 ∧ True
def branch1Output0 (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) (valid : branch1Compatible Atom counter writer incoming0) : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout :=
  branch1Channel0Total Atom incoming0 incoming0 valid.1
def branch1Success (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) (valid : branch1Compatible Atom counter writer incoming0) : Dynamic Atom :=
  Auths.Support.NativeValuePacking.successMany builtins [Auths.Support.NativeValuePacking.rootValue branch1Channel0Packing (branch1Output0 Atom counter writer incoming0 valid)]
theorem branch1_compatible_inputs_execute_computed_success (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) (valid : branch1Compatible Atom counter writer incoming0) :
    Auths.Qualification.NativeBindingClosures.branch1Run Atom counter writer incoming0 = some (branch1Success Atom counter writer incoming0 valid) := by
  unfold Auths.Qualification.NativeBindingClosures.branch1Run
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeBindingClosures.branch1Fuel Auths.Qualification.NativeBindingClosures.branch1 Auths.Qualification.NativeBindingClosures.branch1_well_typed]
  cases counter with
  | atom v36 =>
    cases writer with
    | named v37 =>
      cases v37 with
      | left v38 =>
        cases v38 with
        | named v40 =>
          cases v40 with
          | product v41 v42 =>
            cases v41 with
            | named v43 =>
              cases v43 with
              | atom v44 =>
                cases v42 with
                | unit =>
                  cases incoming0 with
                  | named v45 =>
                    cases v45 with
                    | left v46 =>
                      cases v46 with
                      | named v48 =>
                        cases v48 with
                        | product v49 v50 =>
                          cases v49 with
                          | named v51 =>
                            cases v51 with
                            | atom v52 =>
                              cases v50 with
                              | unit =>
                                first
                                | exact False.elim (by simpa [branch1Compatible, branch1Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                | rfl
                    | right v47 =>
                      cases v47 with
                      | left v53 =>
                        cases v53 with
                        | named v55 =>
                          cases v55 with
                          | product v56 v57 =>
                            cases v56 with
                            | named v58 =>
                              cases v58 with
                              | atom v59 =>
                                cases v57 with
                                | unit =>
                                  first
                                  | exact False.elim (by simpa [branch1Compatible, branch1Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                  | rfl
                      | right v54 =>
                        cases v54
      | right v39 =>
        cases v39 with
        | left v60 =>
          cases v60 with
          | named v62 =>
            cases v62 with
            | product v63 v64 =>
              cases v63 with
              | named v65 =>
                cases v65 with
                | atom v66 =>
                  cases v64 with
                  | unit =>
                    cases incoming0 with
                    | named v67 =>
                      cases v67 with
                      | left v68 =>
                        cases v68 with
                        | named v70 =>
                          cases v70 with
                          | product v71 v72 =>
                            cases v71 with
                            | named v73 =>
                              cases v73 with
                              | atom v74 =>
                                cases v72 with
                                | unit =>
                                  first
                                  | exact False.elim (by simpa [branch1Compatible, branch1Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                  | rfl
                      | right v69 =>
                        cases v69 with
                        | left v75 =>
                          cases v75 with
                          | named v77 =>
                            cases v77 with
                            | product v78 v79 =>
                              cases v78 with
                              | named v80 =>
                                cases v80 with
                                | atom v81 =>
                                  cases v79 with
                                  | unit =>
                                    first
                                    | exact False.elim (by simpa [branch1Compatible, branch1Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                    | rfl
                        | right v76 =>
                          cases v76
        | right v61 =>
          cases v61
theorem branch1_incompatible_inputs_keep_explicit_representation_failure (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) (invalid : ¬ branch1Compatible Atom counter writer incoming0) :
    Auths.Qualification.NativeBindingClosures.branch1Run Atom counter writer incoming0 = some (.constructor (.result (tupleType [.nominal 507 [.nominal 5 [.literal 1]]])) (some builtins.resultFail) [.constructor .error (some builtins.errorFailure) []]) := by
  unfold Auths.Qualification.NativeBindingClosures.branch1Run
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeBindingClosures.branch1Fuel Auths.Qualification.NativeBindingClosures.branch1 Auths.Qualification.NativeBindingClosures.branch1_well_typed]
  cases counter with
  | atom v82 =>
    cases writer with
    | named v83 =>
      cases v83 with
      | left v84 =>
        cases v84 with
        | named v86 =>
          cases v86 with
          | product v87 v88 =>
            cases v87 with
            | named v89 =>
              cases v89 with
              | atom v90 =>
                cases v88 with
                | unit =>
                  cases incoming0 with
                  | named v91 =>
                    cases v91 with
                    | left v92 =>
                      cases v92 with
                      | named v94 =>
                        cases v94 with
                        | product v95 v96 =>
                          cases v95 with
                          | named v97 =>
                            cases v97 with
                            | atom v98 =>
                              cases v96 with
                              | unit =>
                                first
                                | exact False.elim (invalid (by simp [branch1Compatible, branch1Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                | rfl
                    | right v93 =>
                      cases v93 with
                      | left v99 =>
                        cases v99 with
                        | named v101 =>
                          cases v101 with
                          | product v102 v103 =>
                            cases v102 with
                            | named v104 =>
                              cases v104 with
                              | atom v105 =>
                                cases v103 with
                                | unit =>
                                  first
                                  | exact False.elim (invalid (by simp [branch1Compatible, branch1Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                  | rfl
                      | right v100 =>
                        cases v100
      | right v85 =>
        cases v85 with
        | left v106 =>
          cases v106 with
          | named v108 =>
            cases v108 with
            | product v109 v110 =>
              cases v109 with
              | named v111 =>
                cases v111 with
                | atom v112 =>
                  cases v110 with
                  | unit =>
                    cases incoming0 with
                    | named v113 =>
                      cases v113 with
                      | left v114 =>
                        cases v114 with
                        | named v116 =>
                          cases v116 with
                          | product v117 v118 =>
                            cases v117 with
                            | named v119 =>
                              cases v119 with
                              | atom v120 =>
                                cases v118 with
                                | unit =>
                                  first
                                  | exact False.elim (invalid (by simp [branch1Compatible, branch1Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                  | rfl
                      | right v115 =>
                        cases v115 with
                        | left v121 =>
                          cases v121 with
                          | named v123 =>
                            cases v123 with
                            | product v124 v125 =>
                              cases v124 with
                              | named v126 =>
                                cases v126 with
                                | atom v127 =>
                                  cases v125 with
                                  | unit =>
                                    first
                                    | exact False.elim (invalid (by simp [branch1Compatible, branch1Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                    | rfl
                        | right v122 =>
                          cases v122
        | right v107 =>
          cases v107
theorem branch1_compatible_bundle_invocation_succeeds (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) (valid : branch1Compatible Atom counter writer incoming0) :
    Auths.Qualification.NativeBindingClosures.branch1Invoke Atom counter writer incoming0 = some (branch1Success Atom counter writer incoming0 valid) := by
  rw [Auths.Qualification.NativeBindingClosures.branch1_bundle_uses_its_exact_registry_program]
  exact branch1_compatible_inputs_execute_computed_success Atom counter writer incoming0 valid
def branch1Witness0 (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout := branch1Channel0Matching Atom writer
theorem branch1_matching_inputs_are_compatible (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : branch1Compatible Atom counter writer (branch1Witness0 Atom counter writer) := by
  exact ⟨branch1Channel0_whole_inputs_are_compatible Atom _ _, True.intro⟩
theorem branch1_has_successful_inputs_for_every_forward_current (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    Auths.Qualification.NativeBindingClosures.branch1Invoke Atom counter writer (branch1Witness0 Atom counter writer) = some (branch1Success Atom counter writer (branch1Witness0 Atom counter writer) (branch1_matching_inputs_are_compatible Atom counter writer)) :=
  branch1_compatible_bundle_invocation_succeeds Atom counter writer (branch1Witness0 Atom counter writer) (branch1_matching_inputs_are_compatible Atom counter writer)
def branch2Initial : Auths.Support.NativeInputCompatibility.Environment := [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (4, { variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } })]
def branch2Flow : List Auths.Support.NativeInputCompatibility.Operation := [.alias { target := { identity := 2, type := .literal 0 }, source := { identity := 0, type := .literal 0 } }, .alias { target := { identity := 5, type := .literal 0 }, source := { identity := 2, type := .literal 0 } }, .alias { target := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] } }, .output ({ variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }) ({ variable := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } })]
def branch2Snapshots : List Auths.Support.NativeInputCompatibility.Environment := [[(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (4, { variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } })], [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (4, { variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (5, { variable := { identity := 5, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } })], [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (3, { variable := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (4, { variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (5, { variable := { identity := 5, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } })], [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (3, { variable := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (4, { variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (5, { variable := { identity := 5, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } })]]
theorem branch2_all_value_references_follow_actual_earlier_bindings : Auths.Support.NativeInputCompatibility.scan branch2Initial branch2Flow = some branch2Snapshots := by decide
def branch2Compatible (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Prop := branch2Channel0Compatible Atom writer incoming0 ∧ True
def branch2Output0 (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (valid : branch2Compatible Atom counter writer incoming0) : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout :=
  branch2Channel0Total Atom writer incoming0 valid.1
def branch2Success (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (valid : branch2Compatible Atom counter writer incoming0) : Dynamic Atom :=
  Auths.Support.NativeValuePacking.successMany builtins [Auths.Support.NativeValuePacking.rootValue branch2Channel0Packing (branch2Output0 Atom counter writer incoming0 valid)]
theorem branch2_compatible_inputs_execute_computed_success (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (valid : branch2Compatible Atom counter writer incoming0) :
    Auths.Qualification.NativeBindingClosures.branch2Run Atom counter writer incoming0 = some (branch2Success Atom counter writer incoming0 valid) := by
  unfold Auths.Qualification.NativeBindingClosures.branch2Run
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeBindingClosures.branch2Fuel Auths.Qualification.NativeBindingClosures.branch2 Auths.Qualification.NativeBindingClosures.branch2_well_typed]
  cases counter with
  | atom v128 =>
    cases writer with
    | named v129 =>
      cases v129 with
      | left v130 =>
        cases v130 with
        | named v132 =>
          cases v132 with
          | product v133 v134 =>
            cases v133 with
            | named v135 =>
              cases v135 with
              | atom v136 =>
                cases v134 with
                | unit =>
                  cases incoming0 with
                  | named v137 =>
                    cases v137 with
                    | left v138 =>
                      cases v138 with
                      | named v140 =>
                        cases v140 with
                        | product v141 v142 =>
                          cases v141 with
                          | named v143 =>
                            cases v143 with
                            | atom v144 =>
                              cases v142 with
                              | unit =>
                                first
                                | exact False.elim (by simpa [branch2Compatible, branch2Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                | rfl
                    | right v139 =>
                      cases v139 with
                      | left v145 =>
                        cases v145 with
                        | named v147 =>
                          cases v147 with
                          | product v148 v149 =>
                            cases v148 with
                            | named v150 =>
                              cases v150 with
                              | atom v151 =>
                                cases v149 with
                                | unit =>
                                  first
                                  | exact False.elim (by simpa [branch2Compatible, branch2Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                  | rfl
                      | right v146 =>
                        cases v146
      | right v131 =>
        cases v131 with
        | left v152 =>
          cases v152 with
          | named v154 =>
            cases v154 with
            | product v155 v156 =>
              cases v155 with
              | named v157 =>
                cases v157 with
                | atom v158 =>
                  cases v156 with
                  | unit =>
                    cases incoming0 with
                    | named v159 =>
                      cases v159 with
                      | left v160 =>
                        cases v160 with
                        | named v162 =>
                          cases v162 with
                          | product v163 v164 =>
                            cases v163 with
                            | named v165 =>
                              cases v165 with
                              | atom v166 =>
                                cases v164 with
                                | unit =>
                                  first
                                  | exact False.elim (by simpa [branch2Compatible, branch2Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                  | rfl
                      | right v161 =>
                        cases v161 with
                        | left v167 =>
                          cases v167 with
                          | named v169 =>
                            cases v169 with
                            | product v170 v171 =>
                              cases v170 with
                              | named v172 =>
                                cases v172 with
                                | atom v173 =>
                                  cases v171 with
                                  | unit =>
                                    first
                                    | exact False.elim (by simpa [branch2Compatible, branch2Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                    | rfl
                        | right v168 =>
                          cases v168
        | right v153 =>
          cases v153
theorem branch2_incompatible_inputs_keep_explicit_representation_failure (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (invalid : ¬ branch2Compatible Atom counter writer incoming0) :
    Auths.Qualification.NativeBindingClosures.branch2Run Atom counter writer incoming0 = some (.constructor (.result (tupleType [.nominal 507 [.nominal 5 [.literal 1]]])) (some builtins.resultFail) [.constructor .error (some builtins.errorFailure) []]) := by
  unfold Auths.Qualification.NativeBindingClosures.branch2Run
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeBindingClosures.branch2Fuel Auths.Qualification.NativeBindingClosures.branch2 Auths.Qualification.NativeBindingClosures.branch2_well_typed]
  cases counter with
  | atom v174 =>
    cases writer with
    | named v175 =>
      cases v175 with
      | left v176 =>
        cases v176 with
        | named v178 =>
          cases v178 with
          | product v179 v180 =>
            cases v179 with
            | named v181 =>
              cases v181 with
              | atom v182 =>
                cases v180 with
                | unit =>
                  cases incoming0 with
                  | named v183 =>
                    cases v183 with
                    | left v184 =>
                      cases v184 with
                      | named v186 =>
                        cases v186 with
                        | product v187 v188 =>
                          cases v187 with
                          | named v189 =>
                            cases v189 with
                            | atom v190 =>
                              cases v188 with
                              | unit =>
                                first
                                | exact False.elim (invalid (by simp [branch2Compatible, branch2Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                | rfl
                    | right v185 =>
                      cases v185 with
                      | left v191 =>
                        cases v191 with
                        | named v193 =>
                          cases v193 with
                          | product v194 v195 =>
                            cases v194 with
                            | named v196 =>
                              cases v196 with
                              | atom v197 =>
                                cases v195 with
                                | unit =>
                                  first
                                  | exact False.elim (invalid (by simp [branch2Compatible, branch2Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                  | rfl
                      | right v192 =>
                        cases v192
      | right v177 =>
        cases v177 with
        | left v198 =>
          cases v198 with
          | named v200 =>
            cases v200 with
            | product v201 v202 =>
              cases v201 with
              | named v203 =>
                cases v203 with
                | atom v204 =>
                  cases v202 with
                  | unit =>
                    cases incoming0 with
                    | named v205 =>
                      cases v205 with
                      | left v206 =>
                        cases v206 with
                        | named v208 =>
                          cases v208 with
                          | product v209 v210 =>
                            cases v209 with
                            | named v211 =>
                              cases v211 with
                              | atom v212 =>
                                cases v210 with
                                | unit =>
                                  first
                                  | exact False.elim (invalid (by simp [branch2Compatible, branch2Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                  | rfl
                      | right v207 =>
                        cases v207 with
                        | left v213 =>
                          cases v213 with
                          | named v215 =>
                            cases v215 with
                            | product v216 v217 =>
                              cases v216 with
                              | named v218 =>
                                cases v218 with
                                | atom v219 =>
                                  cases v217 with
                                  | unit =>
                                    first
                                    | exact False.elim (invalid (by simp [branch2Compatible, branch2Channel0Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                    | rfl
                        | right v214 =>
                          cases v214
        | right v199 =>
          cases v199
theorem branch2_compatible_bundle_invocation_succeeds (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (valid : branch2Compatible Atom counter writer incoming0) :
    Auths.Qualification.NativeBindingClosures.branch2Invoke Atom counter writer incoming0 = some (branch2Success Atom counter writer incoming0 valid) := by
  rw [Auths.Qualification.NativeBindingClosures.branch2_bundle_uses_its_exact_registry_program]
  exact branch2_compatible_inputs_execute_computed_success Atom counter writer incoming0 valid
def branch2Witness0 (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout := branch2Channel0Matching Atom writer
theorem branch2_matching_inputs_are_compatible (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : branch2Compatible Atom counter writer (branch2Witness0 Atom counter writer) := by
  exact ⟨branch2Channel0_matching_input_is_compatible Atom _, True.intro⟩
theorem branch2_has_successful_inputs_for_every_forward_current (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    Auths.Qualification.NativeBindingClosures.branch2Invoke Atom counter writer (branch2Witness0 Atom counter writer) = some (branch2Success Atom counter writer (branch2Witness0 Atom counter writer) (branch2_matching_inputs_are_compatible Atom counter writer)) :=
  branch2_compatible_bundle_invocation_succeeds Atom counter writer (branch2Witness0 Atom counter writer) (branch2_matching_inputs_are_compatible Atom counter writer)
def branch3Initial : Auths.Support.NativeInputCompatibility.Environment := [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (6, { variable := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (7, { variable := { identity := 7, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } })]
def branch3Flow : List Auths.Support.NativeInputCompatibility.Operation := [.alias { target := { identity := 2, type := .literal 0 }, source := { identity := 0, type := .literal 0 } }, .alias { target := { identity := 8, type := .literal 0 }, source := { identity := 2, type := .literal 0 } }, .alias { target := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }, .alias { target := { identity := 9, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] } }, .alias { target := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] } }, .output ({ variable := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }) ({ variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), .alias { target := { identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { identity := 7, type := .nominal 507 [.nominal 5 [.literal 1]] } }, .output ({ variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }) ({ variable := { identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } })]
def branch3Snapshots : List Auths.Support.NativeInputCompatibility.Environment := [[(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (6, { variable := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (7, { variable := { identity := 7, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } })], [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (6, { variable := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (7, { variable := { identity := 7, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (8, { variable := { identity := 8, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } })], [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (3, { variable := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (6, { variable := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (7, { variable := { identity := 7, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (8, { variable := { identity := 8, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } })], [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (3, { variable := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (6, { variable := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (7, { variable := { identity := 7, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (8, { variable := { identity := 8, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (9, { variable := { identity := 9, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } })], [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (3, { variable := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (4, { variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (6, { variable := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (7, { variable := { identity := 7, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (8, { variable := { identity := 8, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (9, { variable := { identity := 9, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } })], [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (3, { variable := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (4, { variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (6, { variable := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (7, { variable := { identity := 7, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (8, { variable := { identity := 8, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (9, { variable := { identity := 9, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } })], [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (3, { variable := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (4, { variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (5, { variable := { identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (6, { variable := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (7, { variable := { identity := 7, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (8, { variable := { identity := 8, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (9, { variable := { identity := 9, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } })], [(0, { variable := { identity := 0, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (1, { variable := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (2, { variable := { identity := 2, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (3, { variable := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (4, { variable := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (5, { variable := { identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (6, { variable := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (7, { variable := { identity := 7, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .incoming, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }), (8, { variable := { identity := 8, type := .literal 0 }, source := { kind := .root, index := 0, type := .literal 0 } }), (9, { variable := { identity := 9, type := .nominal 507 [.nominal 5 [.literal 1]] }, source := { kind := .root, index := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } })]]
theorem branch3_all_value_references_follow_actual_earlier_bindings : Auths.Support.NativeInputCompatibility.scan branch3Initial branch3Flow = some branch3Snapshots := by decide
def branch3Compatible (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) : Prop := branch3Channel0Compatible Atom writer incoming0 ∧ branch3Channel1Compatible Atom writer incoming1 ∧ True
def branch3Output0 (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) (valid : branch3Compatible Atom counter writer incoming0 incoming1) : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout :=
  branch3Channel0Total Atom writer incoming0 valid.1
def branch3Output1 (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) (valid : branch3Compatible Atom counter writer incoming0 incoming1) : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout :=
  branch3Channel1Total Atom writer incoming1 valid.2.1
def branch3Success (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) (valid : branch3Compatible Atom counter writer incoming0 incoming1) : Dynamic Atom :=
  Auths.Support.NativeValuePacking.successMany builtins [Auths.Support.NativeValuePacking.rootValue branch3Channel0Packing (branch3Output0 Atom counter writer incoming0 incoming1 valid), Auths.Support.NativeValuePacking.rootValue branch3Channel1Packing (branch3Output1 Atom counter writer incoming0 incoming1 valid)]
theorem branch3_compatible_inputs_execute_computed_success (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) (valid : branch3Compatible Atom counter writer incoming0 incoming1) :
    Auths.Qualification.NativeBindingClosures.branch3Run Atom counter writer incoming0 incoming1 = some (branch3Success Atom counter writer incoming0 incoming1 valid) := by
  unfold Auths.Qualification.NativeBindingClosures.branch3Run
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeBindingClosures.branch3Fuel Auths.Qualification.NativeBindingClosures.branch3 Auths.Qualification.NativeBindingClosures.branch3_well_typed]
  cases counter with
  | atom v220 =>
    cases writer with
    | named v221 =>
      cases v221 with
      | left v222 =>
        cases v222 with
        | named v224 =>
          cases v224 with
          | product v225 v226 =>
            cases v225 with
            | named v227 =>
              cases v227 with
              | atom v228 =>
                cases v226 with
                | unit =>
                  cases incoming0 with
                  | named v229 =>
                    cases v229 with
                    | left v230 =>
                      cases v230 with
                      | named v232 =>
                        cases v232 with
                        | product v233 v234 =>
                          cases v233 with
                          | named v235 =>
                            cases v235 with
                            | atom v236 =>
                              cases v234 with
                              | unit =>
                                cases incoming1 with
                                | named v237 =>
                                  cases v237 with
                                  | left v238 =>
                                    cases v238 with
                                    | named v240 =>
                                      cases v240 with
                                      | product v241 v242 =>
                                        cases v241 with
                                        | named v243 =>
                                          cases v243 with
                                          | atom v244 =>
                                            cases v242 with
                                            | unit =>
                                              first
                                              | exact False.elim (by simpa [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                              | rfl
                                  | right v239 =>
                                    cases v239 with
                                    | left v245 =>
                                      cases v245 with
                                      | named v247 =>
                                        cases v247 with
                                        | product v248 v249 =>
                                          cases v248 with
                                          | named v250 =>
                                            cases v250 with
                                            | atom v251 =>
                                              cases v249 with
                                              | unit =>
                                                first
                                                | exact False.elim (by simpa [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                                | rfl
                                    | right v246 =>
                                      cases v246
                    | right v231 =>
                      cases v231 with
                      | left v252 =>
                        cases v252 with
                        | named v254 =>
                          cases v254 with
                          | product v255 v256 =>
                            cases v255 with
                            | named v257 =>
                              cases v257 with
                              | atom v258 =>
                                cases v256 with
                                | unit =>
                                  cases incoming1 with
                                  | named v259 =>
                                    cases v259 with
                                    | left v260 =>
                                      cases v260 with
                                      | named v262 =>
                                        cases v262 with
                                        | product v263 v264 =>
                                          cases v263 with
                                          | named v265 =>
                                            cases v265 with
                                            | atom v266 =>
                                              cases v264 with
                                              | unit =>
                                                first
                                                | exact False.elim (by simpa [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                                | rfl
                                    | right v261 =>
                                      cases v261 with
                                      | left v267 =>
                                        cases v267 with
                                        | named v269 =>
                                          cases v269 with
                                          | product v270 v271 =>
                                            cases v270 with
                                            | named v272 =>
                                              cases v272 with
                                              | atom v273 =>
                                                cases v271 with
                                                | unit =>
                                                  first
                                                  | exact False.elim (by simpa [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                                  | rfl
                                      | right v268 =>
                                        cases v268
                      | right v253 =>
                        cases v253
      | right v223 =>
        cases v223 with
        | left v274 =>
          cases v274 with
          | named v276 =>
            cases v276 with
            | product v277 v278 =>
              cases v277 with
              | named v279 =>
                cases v279 with
                | atom v280 =>
                  cases v278 with
                  | unit =>
                    cases incoming0 with
                    | named v281 =>
                      cases v281 with
                      | left v282 =>
                        cases v282 with
                        | named v284 =>
                          cases v284 with
                          | product v285 v286 =>
                            cases v285 with
                            | named v287 =>
                              cases v287 with
                              | atom v288 =>
                                cases v286 with
                                | unit =>
                                  cases incoming1 with
                                  | named v289 =>
                                    cases v289 with
                                    | left v290 =>
                                      cases v290 with
                                      | named v292 =>
                                        cases v292 with
                                        | product v293 v294 =>
                                          cases v293 with
                                          | named v295 =>
                                            cases v295 with
                                            | atom v296 =>
                                              cases v294 with
                                              | unit =>
                                                first
                                                | exact False.elim (by simpa [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                                | rfl
                                    | right v291 =>
                                      cases v291 with
                                      | left v297 =>
                                        cases v297 with
                                        | named v299 =>
                                          cases v299 with
                                          | product v300 v301 =>
                                            cases v300 with
                                            | named v302 =>
                                              cases v302 with
                                              | atom v303 =>
                                                cases v301 with
                                                | unit =>
                                                  first
                                                  | exact False.elim (by simpa [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                                  | rfl
                                      | right v298 =>
                                        cases v298
                      | right v283 =>
                        cases v283 with
                        | left v304 =>
                          cases v304 with
                          | named v306 =>
                            cases v306 with
                            | product v307 v308 =>
                              cases v307 with
                              | named v309 =>
                                cases v309 with
                                | atom v310 =>
                                  cases v308 with
                                  | unit =>
                                    cases incoming1 with
                                    | named v311 =>
                                      cases v311 with
                                      | left v312 =>
                                        cases v312 with
                                        | named v314 =>
                                          cases v314 with
                                          | product v315 v316 =>
                                            cases v315 with
                                            | named v317 =>
                                              cases v317 with
                                              | atom v318 =>
                                                cases v316 with
                                                | unit =>
                                                  first
                                                  | exact False.elim (by simpa [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                                  | rfl
                                      | right v313 =>
                                        cases v313 with
                                        | left v319 =>
                                          cases v319 with
                                          | named v321 =>
                                            cases v321 with
                                            | product v322 v323 =>
                                              cases v322 with
                                              | named v324 =>
                                                cases v324 with
                                                | atom v325 =>
                                                  cases v323 with
                                                  | unit =>
                                                    first
                                                    | exact False.elim (by simpa [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible] using valid)
                                                    | rfl
                                        | right v320 =>
                                          cases v320
                        | right v305 =>
                          cases v305
        | right v275 =>
          cases v275
theorem branch3_incompatible_inputs_keep_explicit_representation_failure (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) (invalid : ¬ branch3Compatible Atom counter writer incoming0 incoming1) :
    Auths.Qualification.NativeBindingClosures.branch3Run Atom counter writer incoming0 incoming1 = some (.constructor (.result (tupleType [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (some builtins.resultFail) [.constructor .error (some builtins.errorFailure) []]) := by
  unfold Auths.Qualification.NativeBindingClosures.branch3Run
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeBindingClosures.branch3Fuel Auths.Qualification.NativeBindingClosures.branch3 Auths.Qualification.NativeBindingClosures.branch3_well_typed]
  cases counter with
  | atom v326 =>
    cases writer with
    | named v327 =>
      cases v327 with
      | left v328 =>
        cases v328 with
        | named v330 =>
          cases v330 with
          | product v331 v332 =>
            cases v331 with
            | named v333 =>
              cases v333 with
              | atom v334 =>
                cases v332 with
                | unit =>
                  cases incoming0 with
                  | named v335 =>
                    cases v335 with
                    | left v336 =>
                      cases v336 with
                      | named v338 =>
                        cases v338 with
                        | product v339 v340 =>
                          cases v339 with
                          | named v341 =>
                            cases v341 with
                            | atom v342 =>
                              cases v340 with
                              | unit =>
                                cases incoming1 with
                                | named v343 =>
                                  cases v343 with
                                  | left v344 =>
                                    cases v344 with
                                    | named v346 =>
                                      cases v346 with
                                      | product v347 v348 =>
                                        cases v347 with
                                        | named v349 =>
                                          cases v349 with
                                          | atom v350 =>
                                            cases v348 with
                                            | unit =>
                                              first
                                              | exact False.elim (invalid (by simp [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                              | rfl
                                  | right v345 =>
                                    cases v345 with
                                    | left v351 =>
                                      cases v351 with
                                      | named v353 =>
                                        cases v353 with
                                        | product v354 v355 =>
                                          cases v354 with
                                          | named v356 =>
                                            cases v356 with
                                            | atom v357 =>
                                              cases v355 with
                                              | unit =>
                                                first
                                                | exact False.elim (invalid (by simp [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                                | rfl
                                    | right v352 =>
                                      cases v352
                    | right v337 =>
                      cases v337 with
                      | left v358 =>
                        cases v358 with
                        | named v360 =>
                          cases v360 with
                          | product v361 v362 =>
                            cases v361 with
                            | named v363 =>
                              cases v363 with
                              | atom v364 =>
                                cases v362 with
                                | unit =>
                                  cases incoming1 with
                                  | named v365 =>
                                    cases v365 with
                                    | left v366 =>
                                      cases v366 with
                                      | named v368 =>
                                        cases v368 with
                                        | product v369 v370 =>
                                          cases v369 with
                                          | named v371 =>
                                            cases v371 with
                                            | atom v372 =>
                                              cases v370 with
                                              | unit =>
                                                first
                                                | exact False.elim (invalid (by simp [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                                | rfl
                                    | right v367 =>
                                      cases v367 with
                                      | left v373 =>
                                        cases v373 with
                                        | named v375 =>
                                          cases v375 with
                                          | product v376 v377 =>
                                            cases v376 with
                                            | named v378 =>
                                              cases v378 with
                                              | atom v379 =>
                                                cases v377 with
                                                | unit =>
                                                  first
                                                  | exact False.elim (invalid (by simp [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                                  | rfl
                                      | right v374 =>
                                        cases v374
                      | right v359 =>
                        cases v359
      | right v329 =>
        cases v329 with
        | left v380 =>
          cases v380 with
          | named v382 =>
            cases v382 with
            | product v383 v384 =>
              cases v383 with
              | named v385 =>
                cases v385 with
                | atom v386 =>
                  cases v384 with
                  | unit =>
                    cases incoming0 with
                    | named v387 =>
                      cases v387 with
                      | left v388 =>
                        cases v388 with
                        | named v390 =>
                          cases v390 with
                          | product v391 v392 =>
                            cases v391 with
                            | named v393 =>
                              cases v393 with
                              | atom v394 =>
                                cases v392 with
                                | unit =>
                                  cases incoming1 with
                                  | named v395 =>
                                    cases v395 with
                                    | left v396 =>
                                      cases v396 with
                                      | named v398 =>
                                        cases v398 with
                                        | product v399 v400 =>
                                          cases v399 with
                                          | named v401 =>
                                            cases v401 with
                                            | atom v402 =>
                                              cases v400 with
                                              | unit =>
                                                first
                                                | exact False.elim (invalid (by simp [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                                | rfl
                                    | right v397 =>
                                      cases v397 with
                                      | left v403 =>
                                        cases v403 with
                                        | named v405 =>
                                          cases v405 with
                                          | product v406 v407 =>
                                            cases v406 with
                                            | named v408 =>
                                              cases v408 with
                                              | atom v409 =>
                                                cases v407 with
                                                | unit =>
                                                  first
                                                  | exact False.elim (invalid (by simp [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                                  | rfl
                                      | right v404 =>
                                        cases v404
                      | right v389 =>
                        cases v389 with
                        | left v410 =>
                          cases v410 with
                          | named v412 =>
                            cases v412 with
                            | product v413 v414 =>
                              cases v413 with
                              | named v415 =>
                                cases v415 with
                                | atom v416 =>
                                  cases v414 with
                                  | unit =>
                                    cases incoming1 with
                                    | named v417 =>
                                      cases v417 with
                                      | left v418 =>
                                        cases v418 with
                                        | named v420 =>
                                          cases v420 with
                                          | product v421 v422 =>
                                            cases v421 with
                                            | named v423 =>
                                              cases v423 with
                                              | atom v424 =>
                                                cases v422 with
                                                | unit =>
                                                  first
                                                  | exact False.elim (invalid (by simp [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                                  | rfl
                                      | right v419 =>
                                        cases v419 with
                                        | left v425 =>
                                          cases v425 with
                                          | named v427 =>
                                            cases v427 with
                                            | product v428 v429 =>
                                              cases v428 with
                                              | named v430 =>
                                                cases v430 with
                                                | atom v431 =>
                                                  cases v429 with
                                                  | unit =>
                                                    first
                                                    | exact False.elim (invalid (by simp [branch3Compatible, branch3Channel0Compatible, branch3Channel1Compatible, Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible]))
                                                    | rfl
                                        | right v426 =>
                                          cases v426
                        | right v411 =>
                          cases v411
        | right v381 =>
          cases v381
theorem branch3_compatible_bundle_invocation_succeeds (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) (valid : branch3Compatible Atom counter writer incoming0 incoming1) :
    Auths.Qualification.NativeBindingClosures.branch3Invoke Atom counter writer incoming0 incoming1 = some (branch3Success Atom counter writer incoming0 incoming1 valid) := by
  rw [Auths.Qualification.NativeBindingClosures.branch3_bundle_uses_its_exact_registry_program]
  exact branch3_compatible_inputs_execute_computed_success Atom counter writer incoming0 incoming1 valid
def branch3Witness0 (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout := branch3Channel0Matching Atom writer
def branch3Witness1 (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout := branch3Channel1Matching Atom writer
theorem branch3_matching_inputs_are_compatible (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : branch3Compatible Atom counter writer (branch3Witness0 Atom counter writer) (branch3Witness1 Atom counter writer) := by
  exact ⟨branch3Channel0_matching_input_is_compatible Atom _, ⟨branch3Channel1_matching_input_is_compatible Atom _, True.intro⟩⟩
theorem branch3_has_successful_inputs_for_every_forward_current (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    Auths.Qualification.NativeBindingClosures.branch3Invoke Atom counter writer (branch3Witness0 Atom counter writer) (branch3Witness1 Atom counter writer) = some (branch3Success Atom counter writer (branch3Witness0 Atom counter writer) (branch3Witness1 Atom counter writer) (branch3_matching_inputs_are_compatible Atom counter writer)) :=
  branch3_compatible_bundle_invocation_succeeds Atom counter writer (branch3Witness0 Atom counter writer) (branch3Witness1 Atom counter writer) (branch3_matching_inputs_are_compatible Atom counter writer)
theorem preparation_is_total (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : (Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1).isSome = true := by
  cases result : Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1 with
  | none =>
    have value := Auths.Qualification.NativeCurrentSeeds.prepared_value_is_original_source_capture Atom input0 input1
    simp [result] at value
  | some value => rfl
def ownPrepared (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Auths.Qualification.NativeCurrentSeeds.Prepared Atom := (Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1).get (preparation_is_total Atom input0 input1)
theorem preparation_returns_own_prepared (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1 = some (ownPrepared Atom input0 input1) := by
  cases result : Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1 with
  | none =>
    have present := preparation_is_total Atom input0 input1
    simp [result] at present
  | some value => simp [ownPrepared, result]
def branch0OwnForwardCompatible (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : Prop := branch0Compatible Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0
theorem branch0_compatible_own_forward_capture_succeeds (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (valid : branch0OwnForwardCompatible Atom input0 input1 incoming0) :
    Auths.Qualification.NativeBindingClosures.branch0FromCapture Atom input0 input1 incoming0 = some (branch0Success Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0 valid) := by
  unfold Auths.Qualification.NativeBindingClosures.branch0FromCapture Auths.Qualification.NativeBindingClosures.capture
  rw [preparation_returns_own_prepared]
  simp only [Option.bind_some]
  change Auths.Qualification.NativeBindingClosures.branch0Invoke Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0 = _
  exact branch0_compatible_bundle_invocation_succeeds Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0 valid
def branch0OwnWitness0 (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout := branch0Witness0 Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1
theorem branch0_own_forward_witnesses_are_compatible (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : branch0OwnForwardCompatible Atom input0 input1 (branch0OwnWitness0 Atom input0 input1) := branch0_matching_inputs_are_compatible Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1
theorem branch0_own_forward_capture_has_successful_inputs (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) :
    Auths.Qualification.NativeBindingClosures.branch0FromCapture Atom input0 input1 (branch0OwnWitness0 Atom input0 input1) = some (branch0Success Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 (branch0OwnWitness0 Atom input0 input1) (branch0_own_forward_witnesses_are_compatible Atom input0 input1)) :=
  branch0_compatible_own_forward_capture_succeeds Atom input0 input1 (branch0OwnWitness0 Atom input0 input1) (branch0_own_forward_witnesses_are_compatible Atom input0 input1)
def branch1OwnForwardCompatible (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : Prop := branch1Compatible Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0
theorem branch1_compatible_own_forward_capture_succeeds (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) (valid : branch1OwnForwardCompatible Atom input0 input1 incoming0) :
    Auths.Qualification.NativeBindingClosures.branch1FromCapture Atom input0 input1 incoming0 = some (branch1Success Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0 valid) := by
  unfold Auths.Qualification.NativeBindingClosures.branch1FromCapture Auths.Qualification.NativeBindingClosures.capture
  rw [preparation_returns_own_prepared]
  simp only [Option.bind_some]
  change Auths.Qualification.NativeBindingClosures.branch1Invoke Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0 = _
  exact branch1_compatible_bundle_invocation_succeeds Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0 valid
def branch1OwnWitness0 (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout := branch1Witness0 Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1
theorem branch1_own_forward_witnesses_are_compatible (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : branch1OwnForwardCompatible Atom input0 input1 (branch1OwnWitness0 Atom input0 input1) := branch1_matching_inputs_are_compatible Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1
theorem branch1_own_forward_capture_has_successful_inputs (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) :
    Auths.Qualification.NativeBindingClosures.branch1FromCapture Atom input0 input1 (branch1OwnWitness0 Atom input0 input1) = some (branch1Success Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 (branch1OwnWitness0 Atom input0 input1) (branch1_own_forward_witnesses_are_compatible Atom input0 input1)) :=
  branch1_compatible_own_forward_capture_succeeds Atom input0 input1 (branch1OwnWitness0 Atom input0 input1) (branch1_own_forward_witnesses_are_compatible Atom input0 input1)
def branch2OwnForwardCompatible (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Prop := branch2Compatible Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0
theorem branch2_compatible_own_forward_capture_succeeds (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (valid : branch2OwnForwardCompatible Atom input0 input1 incoming0) :
    Auths.Qualification.NativeBindingClosures.branch2FromCapture Atom input0 input1 incoming0 = some (branch2Success Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0 valid) := by
  unfold Auths.Qualification.NativeBindingClosures.branch2FromCapture Auths.Qualification.NativeBindingClosures.capture
  rw [preparation_returns_own_prepared]
  simp only [Option.bind_some]
  change Auths.Qualification.NativeBindingClosures.branch2Invoke Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0 = _
  exact branch2_compatible_bundle_invocation_succeeds Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0 valid
def branch2OwnWitness0 (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout := branch2Witness0 Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1
theorem branch2_own_forward_witnesses_are_compatible (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : branch2OwnForwardCompatible Atom input0 input1 (branch2OwnWitness0 Atom input0 input1) := branch2_matching_inputs_are_compatible Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1
theorem branch2_own_forward_capture_has_successful_inputs (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) :
    Auths.Qualification.NativeBindingClosures.branch2FromCapture Atom input0 input1 (branch2OwnWitness0 Atom input0 input1) = some (branch2Success Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 (branch2OwnWitness0 Atom input0 input1) (branch2_own_forward_witnesses_are_compatible Atom input0 input1)) :=
  branch2_compatible_own_forward_capture_succeeds Atom input0 input1 (branch2OwnWitness0 Atom input0 input1) (branch2_own_forward_witnesses_are_compatible Atom input0 input1)
def branch3OwnForwardCompatible (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) : Prop := branch3Compatible Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0 incoming1
theorem branch3_compatible_own_forward_capture_succeeds (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) (valid : branch3OwnForwardCompatible Atom input0 input1 incoming0 incoming1) :
    Auths.Qualification.NativeBindingClosures.branch3FromCapture Atom input0 input1 incoming0 incoming1 = some (branch3Success Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0 incoming1 valid) := by
  unfold Auths.Qualification.NativeBindingClosures.branch3FromCapture Auths.Qualification.NativeBindingClosures.capture
  rw [preparation_returns_own_prepared]
  simp only [Option.bind_some]
  change Auths.Qualification.NativeBindingClosures.branch3Invoke Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0 incoming1 = _
  exact branch3_compatible_bundle_invocation_succeeds Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 incoming0 incoming1 valid
def branch3OwnWitness0 (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout := branch3Witness0 Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1
def branch3OwnWitness1 (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout := branch3Witness1 Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1
theorem branch3_own_forward_witnesses_are_compatible (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : branch3OwnForwardCompatible Atom input0 input1 (branch3OwnWitness0 Atom input0 input1) (branch3OwnWitness1 Atom input0 input1) := branch3_matching_inputs_are_compatible Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1
theorem branch3_own_forward_capture_has_successful_inputs (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) :
    Auths.Qualification.NativeBindingClosures.branch3FromCapture Atom input0 input1 (branch3OwnWitness0 Atom input0 input1) (branch3OwnWitness1 Atom input0 input1) = some (branch3Success Atom (ownPrepared Atom input0 input1).current0 (ownPrepared Atom input0 input1).current1 (branch3OwnWitness0 Atom input0 input1) (branch3OwnWitness1 Atom input0 input1) (branch3_own_forward_witnesses_are_compatible Atom input0 input1)) :=
  branch3_compatible_own_forward_capture_succeeds Atom input0 input1 (branch3OwnWitness0 Atom input0 input1) (branch3OwnWitness1 Atom input0 input1) (branch3_own_forward_witnesses_are_compatible Atom input0 input1)
end Auths.Qualification.NativeCompatiblePrograms
