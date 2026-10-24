import Auths.Support.NativeDefaultBindings
import qualification.aeneas.cases.NativeCurrentSeeds
/- Actual shared native registry projections, not complete EndAbs execution.
   Unelaborated/unqualified; original dispatch/default activation/heap/loan adequacy remains open. -/
namespace Auths.Qualification.NativeDefaultBindings
open Auths.Support.NativeDefaultBindings Auths.Support.NativePurePayload
open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection
open Auths.Qualification.BorrowProjection.Candidate3400
universe u
def inputs : List (Nat × Ty) := [(2, .literal 0), (6, .nominal 507 [.nominal 5 [.literal 1]])]
def consumedBorrows : List (Nat × Nat) := [(0, 2), (1, 6)]
def branch0Initial : State := { next := 2, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]])], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [] }
def branch0Registrations : List Registration := [{ symbol := 7, type := .literal 0, origin := .borrow 0 }]
def branch0Snapshots : List State := [{ next := 3, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (7, { identity := 2, type := .literal 0 })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (2, { identity := 2, type := .literal 0 })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]]), (2, .literal 0)], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [(2, .variable { identity := 0, type := .literal 0 })] }]
theorem branch0_initial_native_projection_matches : initialize inputs consumedBorrows = some branch0Initial := by decide
theorem branch0_all_shared_native_registrations_match : scan branch0Initial branch0Registrations = some branch0Snapshots := by decide
def branch0Final : State := { next := 3, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (7, { identity := 2, type := .literal 0 })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (2, { identity := 2, type := .literal 0 })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]]), (2, .literal 0)], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [(2, .variable { identity := 0, type := .literal 0 })] }
theorem branch0_symbol7_default_names_immediate_variable : defaultForSymbol branch0Final 7 = some (.variable { identity := 0, type := .literal 0 }) := by decide
def branch1Initial : State := { next := 2, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]])], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [] }
def branch1Registrations : List Registration := [{ symbol := 8, type := .literal 0, origin := .borrow 0 }, { symbol := 9, type := .nominal 507 [.nominal 5 [.literal 1]], origin := .borrow 1 }]
def branch1Snapshots : List State := [{ next := 3, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (8, { identity := 2, type := .literal 0 })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (2, { identity := 2, type := .literal 0 })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]]), (2, .literal 0)], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [(2, .variable { identity := 0, type := .literal 0 })] }, { next := 4, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (8, { identity := 2, type := .literal 0 }), (9, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (2, { identity := 2, type := .literal 0 }), (3, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]]), (2, .literal 0), (3, .nominal 507 [.nominal 5 [.literal 1]])], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [(2, .variable { identity := 0, type := .literal 0 }), (3, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })] }]
theorem branch1_initial_native_projection_matches : initialize inputs consumedBorrows = some branch1Initial := by decide
theorem branch1_all_shared_native_registrations_match : scan branch1Initial branch1Registrations = some branch1Snapshots := by decide
def branch1Final : State := { next := 4, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (8, { identity := 2, type := .literal 0 }), (9, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (2, { identity := 2, type := .literal 0 }), (3, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]]), (2, .literal 0), (3, .nominal 507 [.nominal 5 [.literal 1]])], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [(2, .variable { identity := 0, type := .literal 0 }), (3, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })] }
theorem branch1_symbol8_default_names_immediate_variable : defaultForSymbol branch1Final 8 = some (.variable { identity := 0, type := .literal 0 }) := by decide
theorem branch1_symbol9_default_names_immediate_variable : defaultForSymbol branch1Final 9 = some (.variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }) := by decide
def branch2Initial : State := { next := 2, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]])], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [] }
def branch2Registrations : List Registration := [{ symbol := 10, type := .literal 0, origin := .borrow 0 }, { symbol := 11, type := .nominal 507 [.nominal 5 [.literal 1]], origin := .projection 6 (.nominal 507 [.nominal 5 [.literal 1]]) }]
def branch2Snapshots : List State := [{ next := 3, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (10, { identity := 2, type := .literal 0 })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (2, { identity := 2, type := .literal 0 })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]]), (2, .literal 0)], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [(2, .variable { identity := 0, type := .literal 0 })] }, { next := 4, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (10, { identity := 2, type := .literal 0 }), (11, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (2, { identity := 2, type := .literal 0 }), (3, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]]), (2, .literal 0), (3, .nominal 507 [.nominal 5 [.literal 1]])], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [(2, .variable { identity := 0, type := .literal 0 }), (3, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })] }]
theorem branch2_initial_native_projection_matches : initialize inputs consumedBorrows = some branch2Initial := by decide
theorem branch2_all_shared_native_registrations_match : scan branch2Initial branch2Registrations = some branch2Snapshots := by decide
def branch2Final : State := { next := 4, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (10, { identity := 2, type := .literal 0 }), (11, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (2, { identity := 2, type := .literal 0 }), (3, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]]), (2, .literal 0), (3, .nominal 507 [.nominal 5 [.literal 1]])], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [(2, .variable { identity := 0, type := .literal 0 }), (3, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })] }
theorem branch2_symbol10_default_names_immediate_variable : defaultForSymbol branch2Final 10 = some (.variable { identity := 0, type := .literal 0 }) := by decide
theorem branch2_symbol11_default_names_immediate_variable : defaultForSymbol branch2Final 11 = some (.variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }) := by decide
def branch3Initial : State := { next := 2, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]])], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [] }
def branch3Registrations : List Registration := [{ symbol := 12, type := .literal 0, origin := .borrow 0 }, { symbol := 13, type := .nominal 507 [.nominal 5 [.literal 1]], origin := .projection 6 (.nominal 507 [.nominal 5 [.literal 1]]) }, { symbol := 14, type := .nominal 507 [.nominal 5 [.literal 1]], origin := .projection 13 (.nominal 507 [.nominal 5 [.literal 1]]) }, { symbol := 15, type := .nominal 507 [.nominal 5 [.literal 1]], origin := .projection 6 (.nominal 507 [.nominal 5 [.literal 1]]) }]
def branch3Snapshots : List State := [{ next := 3, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (12, { identity := 2, type := .literal 0 })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (2, { identity := 2, type := .literal 0 })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]]), (2, .literal 0)], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [(2, .variable { identity := 0, type := .literal 0 })] }, { next := 4, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (12, { identity := 2, type := .literal 0 }), (13, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (2, { identity := 2, type := .literal 0 }), (3, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]]), (2, .literal 0), (3, .nominal 507 [.nominal 5 [.literal 1]])], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [(2, .variable { identity := 0, type := .literal 0 }), (3, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })] }, { next := 5, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (12, { identity := 2, type := .literal 0 }), (13, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }), (14, { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (2, { identity := 2, type := .literal 0 }), (3, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }), (4, { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]]), (2, .literal 0), (3, .nominal 507 [.nominal 5 [.literal 1]]), (4, .nominal 507 [.nominal 5 [.literal 1]])], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [(2, .variable { identity := 0, type := .literal 0 }), (3, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (4, .variable { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] })] }, { next := 6, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (12, { identity := 2, type := .literal 0 }), (13, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }), (14, { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }), (15, { identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (2, { identity := 2, type := .literal 0 }), (3, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }), (4, { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }), (5, { identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]]), (2, .literal 0), (3, .nominal 507 [.nominal 5 [.literal 1]]), (4, .nominal 507 [.nominal 5 [.literal 1]]), (5, .nominal 507 [.nominal 5 [.literal 1]])], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [(2, .variable { identity := 0, type := .literal 0 }), (3, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (4, .variable { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }), (5, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })] }]
theorem branch3_initial_native_projection_matches : initialize inputs consumedBorrows = some branch3Initial := by decide
theorem branch3_all_shared_native_registrations_match : scan branch3Initial branch3Registrations = some branch3Snapshots := by decide
def branch3Final : State := { next := 6, symbols := [(2, { identity := 0, type := .literal 0 }), (6, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (12, { identity := 2, type := .literal 0 }), (13, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }), (14, { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }), (15, { identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] })], variables := [(0, { identity := 0, type := .literal 0 }), (1, { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (2, { identity := 2, type := .literal 0 }), (3, { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }), (4, { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }), (5, { identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] })], types := [(0, .literal 0), (1, .nominal 507 [.nominal 5 [.literal 1]]), (2, .literal 0), (3, .nominal 507 [.nominal 5 [.literal 1]]), (4, .nominal 507 [.nominal 5 [.literal 1]]), (5, .nominal 507 [.nominal 5 [.literal 1]])], borrows := [(0, .variable { identity := 0, type := .literal 0 }), (1, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })], defaults := [(2, .variable { identity := 0, type := .literal 0 }), (3, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), (4, .variable { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }), (5, .variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] })] }
theorem branch3_symbol12_default_names_immediate_variable : defaultForSymbol branch3Final 12 = some (.variable { identity := 0, type := .literal 0 }) := by decide
theorem branch3_symbol13_default_names_immediate_variable : defaultForSymbol branch3Final 13 = some (.variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }) := by decide
theorem branch3_symbol14_default_names_immediate_variable : defaultForSymbol branch3Final 14 = some (.variable { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }) := by decide
theorem branch3_symbol15_default_names_immediate_variable : defaultForSymbol branch3Final 15 = some (.variable { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }) := by decide
def borrow0FromForward (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Option (Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) := do
  let (_, state) ← Auths.Support.NativeCaptureValue.runWithState Auths.Qualification.NativeCaptureValue.actualProgram [⟨input0Shape, input0⟩, ⟨input1Shape, input1⟩]
  let pointee ← Auths.Support.NativeCurrentSeeds.readSeed Auths.Qualification.NativeCaptureValue.actualProgram state (.borrow 0) Auths.Qualification.NativeBorrowFullABI.branch0Channel0.candidateShape
  pure (encode Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec (Auths.Support.BorrowTransport.forward Auths.Qualification.NativeBorrowFullABI.branch0Channel0.outgoingChange pointee))
def borrow0FromFocusedSeed (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Option (Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) := do
  let value ← Auths.Qualification.NativeCurrentSeeds.seed0FromState Atom input0 input1
  pure (encode Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec value)
theorem borrow0_consumed_alias_is_same_forward_value (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) :
    borrow0FromForward Atom input0 input1 = borrow0FromFocusedSeed Atom input0 input1 := by
  cases input0 with
  | borrow input0Body =>
    cases input0Body with
    | atom input0BodyValue =>
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
                        cases input1BodyFirstBodyBodyFirstBodyBodyBodyBody with
                        | left input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeft =>
                          cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeft with
                          | named input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBody =>
                            cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBody with
                            | product input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirst input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyRest =>
                              cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirst with
                              | named input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirstBody =>
                                cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirstBody with
                                | borrow input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirstBodyBody =>
                                  cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirstBodyBody with
                                  | borrow input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirstBodyBodyBody =>
                                    cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirstBodyBodyBody with
                                    | atom input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirstBodyBodyBodyValue =>
                                      cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyRest with
                                      | unit =>
                                        cases input1BodyFirstBodyBodyRest with
                                        | unit =>
                                          cases input1BodyRest with
                                          | unit =>
                                            rfl
                        | right input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRight =>
                          cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRight with
                          | left input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeft =>
                            cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeft with
                            | named input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBody =>
                              cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBody with
                              | product input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyFirst input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyRest =>
                                cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyFirst with
                                | named input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyFirstBody =>
                                  cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyFirstBody with
                                  | borrow input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyFirstBodyBody =>
                                    cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyFirstBodyBody with
                                    | atom input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyFirstBodyBodyValue =>
                                      cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyRest with
                                      | unit =>
                                        cases input1BodyFirstBodyBodyRest with
                                        | unit =>
                                          cases input1BodyRest with
                                          | unit =>
                                            rfl
                          | right input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightRight =>
                            cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightRight
def borrow1FromForward (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Option (Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) := do
  let (_, state) ← Auths.Support.NativeCaptureValue.runWithState Auths.Qualification.NativeCaptureValue.actualProgram [⟨input0Shape, input0⟩, ⟨input1Shape, input1⟩]
  let pointee ← Auths.Support.NativeCurrentSeeds.readSeed Auths.Qualification.NativeCaptureValue.actualProgram state (.borrow 1) Auths.Qualification.NativeBorrowFullABI.branch1Channel0.candidateShape
  pure (encode Auths.Qualification.NativePurePayload.branch1Channel0OutgoingCodec (Auths.Support.BorrowTransport.forward Auths.Qualification.NativeBorrowFullABI.branch1Channel0.outgoingChange pointee))
def borrow1FromFocusedSeed (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Option (Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) := do
  let value ← Auths.Qualification.NativeCurrentSeeds.seed1FromState Atom input0 input1
  pure (encode Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec value)
theorem borrow1_consumed_alias_is_same_forward_value (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) :
    borrow1FromForward Atom input0 input1 = borrow1FromFocusedSeed Atom input0 input1 := by
  cases input0 with
  | borrow input0Body =>
    cases input0Body with
    | atom input0BodyValue =>
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
                        cases input1BodyFirstBodyBodyFirstBodyBodyBodyBody with
                        | left input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeft =>
                          cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeft with
                          | named input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBody =>
                            cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBody with
                            | product input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirst input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyRest =>
                              cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirst with
                              | named input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirstBody =>
                                cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirstBody with
                                | borrow input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirstBodyBody =>
                                  cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirstBodyBody with
                                  | borrow input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirstBodyBodyBody =>
                                    cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirstBodyBodyBody with
                                    | atom input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyFirstBodyBodyBodyValue =>
                                      cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyLeftBodyRest with
                                      | unit =>
                                        cases input1BodyFirstBodyBodyRest with
                                        | unit =>
                                          cases input1BodyRest with
                                          | unit =>
                                            rfl
                        | right input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRight =>
                          cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRight with
                          | left input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeft =>
                            cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeft with
                            | named input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBody =>
                              cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBody with
                              | product input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyFirst input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyRest =>
                                cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyFirst with
                                | named input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyFirstBody =>
                                  cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyFirstBody with
                                  | borrow input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyFirstBodyBody =>
                                    cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyFirstBodyBody with
                                    | atom input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyFirstBodyBodyValue =>
                                      cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightLeftBodyRest with
                                      | unit =>
                                        cases input1BodyFirstBodyBodyRest with
                                        | unit =>
                                          cases input1BodyRest with
                                          | unit =>
                                            rfl
                          | right input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightRight =>
                            cases input1BodyFirstBodyBodyFirstBodyBodyBodyBodyRightRight
end Auths.Qualification.NativeDefaultBindings
