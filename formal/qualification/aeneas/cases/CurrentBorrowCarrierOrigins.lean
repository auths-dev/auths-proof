import qualification.aeneas.cases.CurrentBorrowCarrier
import qualification.aeneas.cases.NativeCaptureValue
/- Actual producer-position checks over the retained forward-value syntax.
   Unelaborated/unqualified; native heap/loan and complete ABI adequacy remain required. -/
namespace Auths.Qualification.CurrentBorrowCarrierOrigins
open Auths.Support.CurrentBorrowCarrier
open Auths.Qualification.CurrentBorrowCarrier
theorem branch0Port0_locates_actual_returned_producer :
    locates (Focus.path branch0Port0Focus) (.borrow 0)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = true := by rfl
theorem branch0Port0_rejects_another_producer :
    locates (Focus.path branch0Port0Focus) (.borrow 1)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = false := by rfl
theorem branch0Port1_locates_actual_returned_producer :
    locates (Focus.path branch0Port1Focus) (.borrow 0)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = true := by rfl
theorem branch0Port1_rejects_another_producer :
    locates (Focus.path branch0Port1Focus) (.borrow 1)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = false := by rfl
theorem branch1Port0_locates_actual_returned_producer :
    locates (Focus.path branch1Port0Focus) (.borrow 1)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = true := by rfl
theorem branch1Port0_rejects_another_producer :
    locates (Focus.path branch1Port0Focus) (.borrow 2)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = false := by rfl
theorem branch1Port1_locates_actual_returned_producer :
    locates (Focus.path branch1Port1Focus) (.borrow 1)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = true := by rfl
theorem branch1Port1_rejects_another_producer :
    locates (Focus.path branch1Port1Focus) (.borrow 2)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = false := by rfl
theorem branch2Port0_locates_actual_returned_producer :
    locates (Focus.path branch2Port0Focus) (.symbolic 6)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = true := by rfl
theorem branch2Port0_rejects_another_producer :
    locates (Focus.path branch2Port0Focus) (.symbolic 7)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = false := by rfl
theorem branch2Port1_locates_actual_returned_producer :
    locates (Focus.path branch2Port1Focus) (.symbolic 6)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = true := by rfl
theorem branch2Port1_rejects_another_producer :
    locates (Focus.path branch2Port1Focus) (.symbolic 7)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = false := by rfl
theorem branch3Port0_locates_actual_returned_producer :
    locates (Focus.path branch3Port0Focus) (.symbolic 6)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = true := by rfl
theorem branch3Port0_rejects_another_producer :
    locates (Focus.path branch3Port0Focus) (.symbolic 7)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = false := by rfl
theorem branch3Port1_locates_actual_returned_producer :
    locates (Focus.path branch3Port1Focus) (.symbolic 6)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = true := by rfl
theorem branch3Port1_rejects_another_producer :
    locates (Focus.path branch3Port1Focus) (.symbolic 7)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = false := by rfl
theorem branch3Port2_locates_actual_returned_producer :
    locates (Focus.path branch3Port2Focus) (.symbolic 6)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = true := by rfl
theorem branch3Port2_rejects_another_producer :
    locates (Focus.path branch3Port2Focus) (.symbolic 7)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = false := by rfl
theorem branch3Port3_locates_actual_returned_producer :
    locates (Focus.path branch3Port3Focus) (.symbolic 6)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = true := by rfl
theorem branch3Port3_rejects_another_producer :
    locates (Focus.path branch3Port3Focus) (.symbolic 7)
      Auths.Qualification.NativeCaptureValue.actualProgram.result = false := by rfl
end Auths.Qualification.CurrentBorrowCarrierOrigins
