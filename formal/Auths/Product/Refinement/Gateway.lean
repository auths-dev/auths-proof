import Auths.Product.Recovery
import Auths.Product.RelativeCeiling
import Auths.Product.RequestConstruction
import Auths.Product.SubmitOrder
import qualification.aeneas.generated.gateway.Funs

/-!
# The translated gateway leaves refine their models

`recovery_capability`, the request-construction functions, the admission-order
step machine `next_step`, the attempt-record rule `valid_transition`, and the
relative-ceiling leaves of `auths-gateway-kernel` are translated by the pinned
Charon/Aeneas route. Each theorem here states that a translated function
terminates with `ok` and returns exactly its model's result under an
abstraction that maps machine integers to their natural-number values,
vectors and slices to lists, and the translated carriers to the model's.

The construction theorems carry one representation premise: every buffer the
function builds is shorter than `u32::MAX` bytes, so no `Vec::push` reaches
the translated capacity bound. The compiler bounds real plans far below it
(a body is at most 16 KiB, a path 8 KiB). The step machine, transition, and
relative-ceiling theorems carry no premise: the next denied-read index never
exceeds the declared count, and the relative-ceiling products stay below
`2^80` in `u128`.
-/

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP

namespace Auths.Product.Refinement.Gateway

open auths_gateway_kernel

set_option maxHeartbeats 4000000

/-! ## Recovery -/

def observationOf : recovery.StateObservation → Auths.Product.Recovery.Observation
  | .None => .none
  | .VerifiedLocator => .verifiedLocator
  | .ResponseLocator => .responseLocator

def mechanismOf : recovery.IdempotencyKind → Auths.Product.Recovery.Mechanism
  | .DerivedHeader => .derivedHeader
  | .OperationIdField => .operationIdField

def reentryOf : recovery.LostClaimReentry → Auths.Product.Recovery.Reentry
  | .None => .none
  | .Declared kind retention => .declared (mechanismOf kind) retention.val

def declarationsOf (declarations : recovery.RecoveryDeclarations) :
    Auths.Product.Recovery.Declarations where
  observation := observationOf declarations.observation
  echo := declarations.echo
  idempotency := reentryOf declarations.idempotency
  preEntry := declarations.pre_entry

def classOf : recovery.RecoveryClass → Auths.Product.Recovery.RecoveryClass
  | .Linked => .linked
  | .LinkedAfterResponse => .linkedAfterResponse
  | .Observed => .observed
  | .Recorded => .recorded

def resolutionOf : recovery.UnknownResolution → Auths.Product.Recovery.Resolution
  | .GatewayReobservation => .gatewayReobservation
  | .None => .none

def capabilityOf (capability : recovery.RecoveryCapability) :
    Auths.Product.Recovery.Capability where
  recoveryClass := classOf capability.«class»
  stateObservation := observationOf capability.state_observation
  providerLink := observationOf capability.provider_link
  unknownResolution := resolutionOf capability.unknown_resolution
  lostClaimReentry := reentryOf capability.lost_claim_reentry
  preEntryReread := capability.pre_entry_reread
  writeIsConditional := capability.write_is_conditional

/-- The translated recovery leaf returns exactly the model's capability. -/
theorem translated_recovery_capability_refines_model
    (declarations : recovery.RecoveryDeclarations) :
    recovery.recovery_capability declarations ⦃ capability =>
      capabilityOf capability =
        Auths.Product.Recovery.capability (declarationsOf declarations) ⦄ := by
  rcases declarations with ⟨_ | _ | _, _ | _, idempotency, preEntry⟩ <;>
    simp [recovery.recovery_capability, recovery.provider_link, recovery.recovery_class,
      recovery.unknown_resolution, capabilityOf, declarationsOf, Auths.Product.Recovery.capability,
      Auths.Product.Recovery.providerLink, Auths.Product.Recovery.classOf,
      Auths.Product.Recovery.resolutionOf, observationOf, classOf, resolutionOf]

/-! ## Construction: abstraction -/

abbrev Model := Auths.Product.RequestConstruction.Bytes

def byteList (bytes : List Std.U8) : List Nat := bytes.map (·.val)

def vecBytes (vector : alloc.vec.Vec Std.U8) : List Nat := byteList vector.val

def sliceBytes (slice : Slice Std.U8) : List Nat := byteList slice.val

theorem lt_usize_max {length : Nat} (small : length < 4294967295) : length < Usize.max := by
  rcases Usize.bounds_eq with equal | equal <;> rw [equal] <;>
    simp only [U32.max_eq, U64.max_eq] <;> omega

/-! ## Construction: byte copies -/

@[step] theorem append_bytes_spec (out : alloc.vec.Vec Std.U8) (bytes : Slice Std.U8)
    (fits : out.val.length + bytes.val.length < 4294967295) :
    construct.append_bytes out bytes ⦃ result => result.val = out.val ++ bytes.val ⦄ := by
  unfold construct.append_bytes construct.append_bytes_loop
  apply loop.spec_decr_nat
    (measure := fun state => bytes.val.length - state.2.val)
    (inv := fun state =>
      state.1.val = out.val ++ bytes.val.take state.2.val ∧ state.2.val ≤ bytes.val.length)
  · rintro ⟨current, index⟩ ⟨currentEq, indexBound⟩
    unfold construct.append_bytes_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < bytes.val.length := by simpa using withinBounds
      step as ⟨byte, byteEq⟩
      have pushFits : current.val.length < Usize.max := by
        apply lt_usize_max
        rw [currentEq, List.length_append, List.length_take]
        omega
      step as ⟨next, nextEq⟩
      step as ⟨nextIndex, nextIndexEq⟩
      refine ⟨?_, by omega, by omega⟩
      rw [nextEq, currentEq, nextIndexEq, byteEq, List.append_assoc,
        List.take_succ_eq_append_getElem inBounds]
    · simp only [spec_ok]
      have atEnd : bytes.val.length ≤ index.val := by simpa using withinBounds
      rw [currentEq, List.take_of_length_le atEnd]
  · exact ⟨by simp, by simp⟩

@[step] theorem copy_bytes_spec (bytes : Slice Std.U8)
    (fits : bytes.val.length < 4294967295) :
    construct.copy_bytes bytes ⦃ result => result.val = bytes.val ⦄ := by
  unfold construct.copy_bytes
  step with append_bytes_spec as ⟨result, resultEq⟩
  rw [resultEq]
  simp

/-! ## Construction: byte classes -/

open Auths.Product.RequestConstruction in
@[step] theorem is_alphanumeric_spec (byte : Std.U8) :
    construct.is_alphanumeric byte ⦃ result => result = alphanumeric byte.val ⦄ := by
  unfold construct.is_alphanumeric alphanumeric
  split_ifs <;> simp_all

open Auths.Product.RequestConstruction in
@[step] theorem is_path_literal_spec (byte : Std.U8) :
    construct.is_path_literal byte ⦃ result => result = pathLiteral byte.val ⦄ := by
  unfold construct.is_path_literal pathLiteral
  step as ⟨alpha, alphaEq⟩
  split_ifs <;> simp_all [UScalar.eq_equiv, beq_eq_decide]

open Auths.Product.RequestConstruction in
@[step] theorem is_form_literal_spec (byte : Std.U8) :
    construct.is_form_literal byte ⦃ result => result = formLiteral byte.val ⦄ := by
  unfold construct.is_form_literal formLiteral
  step as ⟨alpha, alphaEq⟩
  split_ifs <;> simp_all [UScalar.eq_equiv, beq_eq_decide]

open Auths.Product.RequestConstruction in
@[step] theorem is_account_byte_spec (byte : Std.U8) :
    construct.is_account_byte byte ⦃ result => result = accountByte byte.val ⦄ := by
  unfold construct.is_account_byte accountByte
  step as ⟨alpha, alphaEq⟩
  split_ifs <;> simp_all [UScalar.eq_equiv, beq_eq_decide]

open Auths.Product.RequestConstruction in
@[step] theorem hex_upper_spec (nibble : Std.U8) (small : nibble.val < 16) :
    construct.hex_upper nibble ⦃ result => result.val = hexUpper nibble.val ⦄ := by
  unfold construct.hex_upper hexUpper
  by_cases low : nibble.val < 10
  · have lowScalar : nibble < 10#u8 := by scalar_tac
    simp only [lowScalar, if_true, low]
    step as ⟨result, resultEq⟩
    omega
  · have highScalar : ¬ nibble < 10#u8 := by scalar_tac
    simp only [highScalar, if_false, low]
    step as ⟨shifted, shiftedEq⟩
    step as ⟨result, resultEq⟩
    omega

open Auths.Product.RequestConstruction in
@[step] theorem hex_lower_spec (nibble : Std.U8) (small : nibble.val < 16) :
    construct.hex_lower nibble ⦃ result => result.val = hexLower nibble.val ⦄ := by
  unfold construct.hex_lower hexLower
  by_cases low : nibble.val < 10
  · have lowScalar : nibble < 10#u8 := by scalar_tac
    simp only [lowScalar, if_true, low]
    step as ⟨result, resultEq⟩
    omega
  · have highScalar : ¬ nibble < 10#u8 := by scalar_tac
    simp only [highScalar, if_false, low]
    step as ⟨shifted, shiftedEq⟩
    step as ⟨result, resultEq⟩
    omega


/-! ## Construction: list lemmas -/

theorem flatMap_take_succ {α β : Type} (f : α → List β) (list : List α) (index : Nat)
    (inBounds : index < list.length) :
    (list.take (index + 1)).flatMap f = (list.take index).flatMap f ++ f list[index] := by
  rw [List.take_succ_eq_append_getElem inBounds, List.flatMap_append]
  simp

theorem length_flatMap_take_le {α β : Type} (f : α → List β) (list : List α) (index : Nat) :
    ((list.take index).flatMap f).length ≤ (list.flatMap f).length := by
  conv_rhs => rw [← List.take_append_drop index list]
  rw [List.flatMap_append, List.length_append]
  omega

theorem length_flatMap_take_succ_le {α β : Type} (f : α → List β) (list : List α)
    (index : Nat) (inBounds : index < list.length) :
    ((list.take index).flatMap f).length + (f list[index]).length ≤ (list.flatMap f).length := by
  have := length_flatMap_take_le f list (index + 1)
  rw [flatMap_take_succ f list index inBounds, List.length_append] at this
  exact this

theorem byteList_take (bytes : List Std.U8) (index : Nat) :
    byteList (bytes.take index) = (byteList bytes).take index := by
  simp [byteList, List.map_take]

theorem byteList_append (left right : List Std.U8) :
    byteList (left ++ right) = byteList left ++ byteList right := by
  simp [byteList]

theorem length_byteList (bytes : List Std.U8) : (byteList bytes).length = bytes.length := by
  simp [byteList]

/-! ## Construction: encoders -/

open Auths.Product.RequestConstruction in
@[step] theorem append_percent_spec (out : alloc.vec.Vec Std.U8) (byte : Std.U8)
    (fits : out.val.length + 3 < 4294967295) :
    construct.append_percent out byte ⦃ result =>
      byteList result.val = byteList out.val ++ percent byte.val ⦄ := by
  unfold construct.append_percent
  have first : out.val.length < Usize.max := lt_usize_max (by omega)
  step as ⟨out1, out1Eq⟩
  step as ⟨high, highEq⟩
  step with hex_upper_spec as ⟨highDigit, highDigitEq⟩
  have second : out1.val.length < Usize.max := lt_usize_max (by simp [out1Eq]; omega)
  step as ⟨out2, out2Eq⟩
  step as ⟨low, lowEq⟩
  step with hex_upper_spec as ⟨lowDigit, lowDigitEq⟩
  have third : out2.val.length < Usize.max := lt_usize_max (by simp [out2Eq, out1Eq]; omega)
  step as ⟨out3, out3Eq⟩
  simp [byteList, out3Eq, out2Eq, out1Eq, percent, highDigitEq, lowDigitEq, highEq, lowEq]

open Auths.Product.RequestConstruction in
@[step] theorem append_path_byte_spec (out : alloc.vec.Vec Std.U8) (byte : Std.U8)
    (fits : out.val.length + (pathByte byte.val).length < 4294967295) :
    construct.append_path_byte out byte ⦃ result =>
      byteList result.val = byteList out.val ++ pathByte byte.val ⦄ := by
  unfold construct.append_path_byte
  step as ⟨literal, literalEq⟩
  split <;> rename_i isLiteral
  · have pushFits : out.val.length < Usize.max :=
      lt_usize_max (by simp [pathByte, ← literalEq, isLiteral] at fits; omega)
    step as ⟨result, resultEq⟩
    simp [byteList, resultEq, pathByte, ← literalEq, isLiteral]
  · have percentFits : out.val.length + 3 < 4294967295 := by
      simp [pathByte, ← literalEq, isLiteral, percent] at fits; omega
    step with append_percent_spec as ⟨result, resultEq⟩
    simp [resultEq, pathByte, ← literalEq, isLiteral]

open Auths.Product.RequestConstruction in
@[step] theorem append_path_encoded_spec (out : alloc.vec.Vec Std.U8) (text : Slice Std.U8)
    (fits : out.val.length + (pathEncode (byteList text.val)).length < 4294967295) :
    construct.append_path_encoded out text ⦃ result =>
      byteList result.val = byteList out.val ++ pathEncode (byteList text.val) ⦄ := by
  unfold construct.append_path_encoded construct.append_path_encoded_loop
  apply loop.spec_decr_nat
    (measure := fun state => text.val.length - state.2.val)
    (inv := fun state =>
      byteList state.1.val = byteList out.val ++ pathEncode ((byteList text.val).take state.2.val) ∧
        state.2.val ≤ text.val.length)
  · rintro ⟨current, index⟩ ⟨currentEq, indexBound⟩
    unfold construct.append_path_encoded_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < text.val.length := by simpa using withinBounds
      have modelBounds : index.val < (byteList text.val).length := by
        rw [length_byteList]; exact inBounds
      step as ⟨byte, byteEq⟩
      have byteModel : byte.val = (byteList text.val)[index.val] := by
        simp [byteList, byteEq]
      have lengthCurrent : current.val.length =
          out.val.length + (pathEncode ((byteList text.val).take index.val)).length := by
        rw [← length_byteList current.val, currentEq, List.length_append, length_byteList]
      have bound := length_flatMap_take_succ_le pathByte (byteList text.val) index.val modelBounds
      step with append_path_byte_spec as ⟨next, nextEq⟩
      · unfold pathEncode at fits lengthCurrent
        rw [lengthCurrent, byteModel]
        omega
      step as ⟨nextIndex, nextIndexEq⟩
      refine ⟨?_, by omega, by omega⟩
      rw [nextEq, currentEq, nextIndexEq, byteModel, List.append_assoc]
      unfold pathEncode
      rw [flatMap_take_succ pathByte (byteList text.val) index.val modelBounds]
    · simp only [spec_ok]
      have atEnd : (byteList text.val).length ≤ index.val := by
        rw [length_byteList]; simpa using withinBounds
      rw [currentEq, List.take_of_length_le atEnd]
  · exact ⟨by simp [pathEncode], by simp⟩

macro "fits_tac" : tactic =>
  `(tactic| (apply lt_usize_max; simp_all [List.length_append]; omega))

/-- Closes the capacity side goals a `step` leaves from the hypothesis `fits`. -/
macro "side_fits" : tactic =>
  `(tactic| all_goals (try (simp_all [vecBytes, alloc.vec.Vec.deref, length_byteList, byteList] <;> omega)))

open Auths.Product.RequestConstruction in
@[step] theorem append_form_byte_spec (out : alloc.vec.Vec Std.U8) (byte : Std.U8)
    (fits : out.val.length + (formByte byte.val).length < 4294967295) :
    construct.append_form_byte out byte ⦃ result =>
      byteList result.val = byteList out.val ++ formByte byte.val ⦄ := by
  unfold construct.append_form_byte
  by_cases space : byte.val = 32
  · have spaceScalar : byte = 32#u8 := by scalar_tac
    simp only [spaceScalar, if_true]
    have pushFits : out.val.length < Usize.max :=
      lt_usize_max (by simp [formByte, space] at fits; omega)
    step as ⟨result, resultEq⟩
    simp [byteList, resultEq, formByte]
  · have notSpace : ¬ byte = 32#u8 := by scalar_tac
    simp only [notSpace, if_false]
    step as ⟨literal, literalEq⟩
    split <;> rename_i isLiteral
    · have pushFits : out.val.length < Usize.max :=
        lt_usize_max (by simp [formByte, space, ← literalEq, isLiteral] at fits; omega)
      step as ⟨result, resultEq⟩
      simp [byteList, resultEq, formByte, space, ← literalEq, isLiteral]
    · have percentFits : out.val.length + 3 < 4294967295 := by
        simp [formByte, space, ← literalEq, isLiteral, percent] at fits; omega
      step with append_percent_spec as ⟨result, resultEq⟩
      simp [resultEq, formByte, space, ← literalEq, isLiteral]

open Auths.Product.RequestConstruction in
@[step] theorem append_json_byte_spec (out : alloc.vec.Vec Std.U8) (byte : Std.U8)
    (fits : out.val.length + (jsonByte byte.val).length < 4294967295) :
    construct.append_json_byte out byte ⦃ result =>
      byteList result.val = byteList out.val ++ jsonByte byte.val ⦄ := by
  unfold construct.append_json_byte
  by_cases quote : byte.val = 34
  · have quoteScalar : byte = 34#u8 := by scalar_tac
    rw [if_pos quoteScalar]
    have twoFits : out.val.length + 2 < 4294967295 := by
      simp [jsonByte, quote] at fits; omega
    step as ⟨out1, out1Eq⟩
    have secondFits : out1.val.length < Usize.max := by fits_tac
    step as ⟨out2, out2Eq⟩
    simp [byteList, out2Eq, out1Eq, jsonByte, quote]
  have quoteScalar : ¬ byte = 34#u8 := by scalar_tac
  by_cases backslash : byte.val = 92
  · have backslashScalar : byte = 92#u8 := by scalar_tac
    rw [if_neg quoteScalar, if_pos backslashScalar]
    have twoFits : out.val.length + 2 < 4294967295 := by
      simp [jsonByte, backslash] at fits; omega
    step as ⟨out1, out1Eq⟩
    have secondFits : out1.val.length < Usize.max := by fits_tac
    step as ⟨out2, out2Eq⟩
    simp [byteList, out2Eq, out1Eq, jsonByte, backslash]
  have backslashScalar : ¬ byte = 92#u8 := by scalar_tac
  by_cases backspace : byte.val = 8
  · have backspaceScalar : byte = 8#u8 := by scalar_tac
    rw [if_neg quoteScalar, if_neg backslashScalar, if_pos backspaceScalar]
    have twoFits : out.val.length + 2 < 4294967295 := by
      simp [jsonByte, backspace] at fits; omega
    step as ⟨out1, out1Eq⟩
    have secondFits : out1.val.length < Usize.max := by fits_tac
    step as ⟨out2, out2Eq⟩
    simp [byteList, out2Eq, out1Eq, jsonByte, backspace]
  have backspaceScalar : ¬ byte = 8#u8 := by scalar_tac
  by_cases tab : byte.val = 9
  · have tabScalar : byte = 9#u8 := by scalar_tac
    rw [if_neg quoteScalar, if_neg backslashScalar, if_neg backspaceScalar, if_pos tabScalar]
    have twoFits : out.val.length + 2 < 4294967295 := by
      simp [jsonByte, tab] at fits; omega
    step as ⟨out1, out1Eq⟩
    have secondFits : out1.val.length < Usize.max := by fits_tac
    step as ⟨out2, out2Eq⟩
    simp [byteList, out2Eq, out1Eq, jsonByte, tab]
  have tabScalar : ¬ byte = 9#u8 := by scalar_tac
  by_cases newline : byte.val = 10
  · have newlineScalar : byte = 10#u8 := by scalar_tac
    rw [if_neg quoteScalar, if_neg backslashScalar, if_neg backspaceScalar, if_neg tabScalar, if_pos newlineScalar]
    have twoFits : out.val.length + 2 < 4294967295 := by
      simp [jsonByte, newline] at fits; omega
    step as ⟨out1, out1Eq⟩
    have secondFits : out1.val.length < Usize.max := by fits_tac
    step as ⟨out2, out2Eq⟩
    simp [byteList, out2Eq, out1Eq, jsonByte, newline]
  have newlineScalar : ¬ byte = 10#u8 := by scalar_tac
  by_cases formfeed : byte.val = 12
  · have formfeedScalar : byte = 12#u8 := by scalar_tac
    rw [if_neg quoteScalar, if_neg backslashScalar, if_neg backspaceScalar, if_neg tabScalar, if_neg newlineScalar, if_pos formfeedScalar]
    have twoFits : out.val.length + 2 < 4294967295 := by
      simp [jsonByte, formfeed] at fits; omega
    step as ⟨out1, out1Eq⟩
    have secondFits : out1.val.length < Usize.max := by fits_tac
    step as ⟨out2, out2Eq⟩
    simp [byteList, out2Eq, out1Eq, jsonByte, formfeed]
  have formfeedScalar : ¬ byte = 12#u8 := by scalar_tac
  by_cases carriage : byte.val = 13
  · have carriageScalar : byte = 13#u8 := by scalar_tac
    rw [if_neg quoteScalar, if_neg backslashScalar, if_neg backspaceScalar, if_neg tabScalar, if_neg newlineScalar, if_neg formfeedScalar, if_pos carriageScalar]
    have twoFits : out.val.length + 2 < 4294967295 := by
      simp [jsonByte, carriage] at fits; omega
    step as ⟨out1, out1Eq⟩
    have secondFits : out1.val.length < Usize.max := by fits_tac
    step as ⟨out2, out2Eq⟩
    simp [byteList, out2Eq, out1Eq, jsonByte, carriage]
  have carriageScalar : ¬ byte = 13#u8 := by scalar_tac
  by_cases control : byte.val < 32
  · have controlScalar : byte < 32#u8 := by scalar_tac
    rw [if_neg quoteScalar, if_neg backslashScalar, if_neg backspaceScalar, if_neg tabScalar, if_neg newlineScalar, if_neg formfeedScalar, if_neg carriageScalar, if_pos controlScalar]
    have longFits : out.val.length + 6 < 4294967295 := by
      simp [jsonByte, quote, backslash, backspace, tab, newline, formfeed, carriage, control] at fits; omega
    step as ⟨out1, out1Eq⟩
    have fits2 : out1.val.length < Usize.max := by fits_tac
    step as ⟨out2, out2Eq⟩
    have fits3 : out2.val.length < Usize.max := by fits_tac
    step as ⟨out3, out3Eq⟩
    have fits4 : out3.val.length < Usize.max := by fits_tac
    step as ⟨out4, out4Eq⟩
    step as ⟨high, highEq⟩
    step with hex_lower_spec as ⟨highDigit, highDigitEq⟩
    have fits5 : out4.val.length < Usize.max := by fits_tac
    step as ⟨out5, out5Eq⟩
    step as ⟨low, lowEq⟩
    step with hex_lower_spec as ⟨lowDigit, lowDigitEq⟩
    have fits6 : out5.val.length < Usize.max := by fits_tac
    step as ⟨out6, out6Eq⟩
    simp [byteList, out6Eq, out5Eq, out4Eq, out3Eq, out2Eq, out1Eq, jsonByte, quote, backslash, backspace, tab, newline, formfeed, carriage,
      control, highDigitEq, lowDigitEq, highEq, lowEq]
  · have controlScalar : ¬ byte < 32#u8 := by scalar_tac
    rw [if_neg quoteScalar, if_neg backslashScalar, if_neg backspaceScalar, if_neg tabScalar, if_neg newlineScalar, if_neg formfeedScalar, if_neg carriageScalar, if_neg controlScalar]
    have oneFits : out.val.length + 1 < 4294967295 := by
      simp [jsonByte, quote, backslash, backspace, tab, newline, formfeed, carriage, control] at fits; omega
    step as ⟨out1, out1Eq⟩
    simp [byteList, out1Eq, jsonByte, quote, backslash, backspace, tab, newline, formfeed, carriage, control]

open Auths.Product.RequestConstruction in
@[step] theorem append_form_encoded_spec (out : alloc.vec.Vec Std.U8) (text : Slice Std.U8)
    (fits : out.val.length + (formEncode (byteList text.val)).length < 4294967295) :
    construct.append_form_encoded out text ⦃ result =>
      byteList result.val = byteList out.val ++ formEncode (byteList text.val) ⦄ := by
  unfold construct.append_form_encoded construct.append_form_encoded_loop
  apply loop.spec_decr_nat
    (measure := fun state => text.val.length - state.2.val)
    (inv := fun state =>
      byteList state.1.val = byteList out.val ++ formEncode ((byteList text.val).take state.2.val) ∧
        state.2.val ≤ text.val.length)
  · rintro ⟨current, index⟩ ⟨currentEq, indexBound⟩
    unfold construct.append_form_encoded_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < text.val.length := by simpa using withinBounds
      have modelBounds : index.val < (byteList text.val).length := by
        rw [length_byteList]; exact inBounds
      step as ⟨byte, byteEq⟩
      have byteModel : byte.val = (byteList text.val)[index.val] := by
        simp [byteList, byteEq]
      have lengthCurrent : current.val.length =
          out.val.length + (formEncode ((byteList text.val).take index.val)).length := by
        rw [← length_byteList current.val, currentEq, List.length_append, length_byteList]
      have bound := length_flatMap_take_succ_le formByte (byteList text.val) index.val modelBounds
      step with append_form_byte_spec as ⟨next, nextEq⟩
      · unfold formEncode at fits lengthCurrent
        rw [lengthCurrent, byteModel]
        omega
      step as ⟨nextIndex, nextIndexEq⟩
      refine ⟨?_, by omega, by omega⟩
      rw [nextEq, currentEq, nextIndexEq, byteModel, List.append_assoc]
      unfold formEncode
      rw [flatMap_take_succ formByte (byteList text.val) index.val modelBounds]
    · simp only [spec_ok]
      have atEnd : (byteList text.val).length ≤ index.val := by
        rw [length_byteList]; simpa using withinBounds
      rw [currentEq, List.take_of_length_le atEnd]
  · exact ⟨by simp [formEncode], by simp⟩

open Auths.Product.RequestConstruction in
@[step] theorem append_json_escaped_spec (out : alloc.vec.Vec Std.U8) (text : Slice Std.U8)
    (fits : out.val.length + (jsonEscape (byteList text.val)).length < 4294967295) :
    construct.append_json_escaped out text ⦃ result =>
      byteList result.val = byteList out.val ++ jsonEscape (byteList text.val) ⦄ := by
  unfold construct.append_json_escaped construct.append_json_escaped_loop
  apply loop.spec_decr_nat
    (measure := fun state => text.val.length - state.2.val)
    (inv := fun state =>
      byteList state.1.val = byteList out.val ++ jsonEscape ((byteList text.val).take state.2.val) ∧
        state.2.val ≤ text.val.length)
  · rintro ⟨current, index⟩ ⟨currentEq, indexBound⟩
    unfold construct.append_json_escaped_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < text.val.length := by simpa using withinBounds
      have modelBounds : index.val < (byteList text.val).length := by
        rw [length_byteList]; exact inBounds
      step as ⟨byte, byteEq⟩
      have byteModel : byte.val = (byteList text.val)[index.val] := by
        simp [byteList, byteEq]
      have lengthCurrent : current.val.length =
          out.val.length + (jsonEscape ((byteList text.val).take index.val)).length := by
        rw [← length_byteList current.val, currentEq, List.length_append, length_byteList]
      have bound := length_flatMap_take_succ_le jsonByte (byteList text.val) index.val modelBounds
      step with append_json_byte_spec as ⟨next, nextEq⟩
      · unfold jsonEscape at fits lengthCurrent
        rw [lengthCurrent, byteModel]
        omega
      step as ⟨nextIndex, nextIndexEq⟩
      refine ⟨?_, by omega, by omega⟩
      rw [nextEq, currentEq, nextIndexEq, byteModel, List.append_assoc]
      unfold jsonEscape
      rw [flatMap_take_succ jsonByte (byteList text.val) index.val modelBounds]
    · simp only [spec_ok]
      have atEnd : (byteList text.val).length ≤ index.val := by
        rw [length_byteList]; simpa using withinBounds
      rw [currentEq, List.take_of_length_le atEnd]
  · exact ⟨by simp [jsonEscape], by simp⟩

/-! ## Construction: plan abstraction -/

section Abstraction
open Auths.Product.RequestConstruction

def argOf : construct.ArgumentValue → Arg
  | .Text text => .text (vecBytes text)
  | .Integer digits => .integer (vecBytes digits)
  | .Boolean value => .boolean value

def argsOf (arguments : Slice construct.ArgumentValue) : List Arg :=
  arguments.val.map argOf

def segmentOf : construct.SegmentPlan → Segment
  | .Fixed value => .fixed (vecBytes value)
  | .Field index => .field index.val

def headerOf (header : construct.Header) : Header :=
  ⟨vecBytes header.«name», vecBytes header.value⟩

def scopeOf (scope : construct.AccountScopePlan) : ScopePlan :=
  ⟨vecBytes scope.«name», scope.field.val⟩

def headerPlanOf (plan : construct.HeaderPlan) : HeaderPlan :=
  ⟨plan.versions.val.map headerOf, plan.account_scope.map scopeOf⟩

def jsonPieceOf : construct.JsonPiece → JsonPiece
  | .Raw value => .raw (vecBytes value)
  | .Field index => .field index.val
  | .Echo => .echo

def formPieceOf : construct.FormPiece → FormPiece
  | .Raw value => .raw (vecBytes value)
  | .Field index => .field index.val
  | .Json pieces => .json (pieces.val.map jsonPieceOf)
  | .Echo => .echo

def bodyPlanOf : construct.BodyPlan → BodyPlan
  | .Json pieces => .json (pieces.val.map jsonPieceOf)
  | .Form pieces => .form (pieces.val.map formPieceOf)

def methodOf : construct.RequestMethod → Method
  | .Get => .get
  | .Head => .head
  | .Post => .post
  | .Put => .put
  | .Patch => .patch
  | .Delete => .delete

def writePlanOf (plan : construct.WritePlan) : WritePlan where
  method := methodOf plan.method
  origin := vecBytes plan.origin
  path := plan.path.val.map segmentOf
  headers := headerPlanOf plan.headers
  idempotency := plan.idempotency_header.map vecBytes
  body := bodyPlanOf plan.body

def readPlanOf (plan : construct.ActionReadPlan) : ReadPlan where
  origin := vecBytes plan.origin
  path := plan.path.val.map segmentOf
  headers := headerPlanOf plan.headers

def credentialPlanOf (plan : construct.CredentialReadPlan) : CredentialPlan where
  method := methodOf plan.method
  origin := vecBytes plan.origin
  path := plan.path.val.map vecBytes
  versions := plan.versions.val.map headerOf

def requestOf (request : construct.BuiltRequest) : Request where
  method := methodOf request.method
  url := vecBytes request.url
  headers := request.headers.val.map headerOf
  body := vecBytes request.body

def errorOf : construct.ConstructError → ConstructError
  | .ArgumentMismatch => .argumentMismatch
  | .UnsafeSegment => .unsafeSegment
  | .PathTooLong => .pathTooLong
  | .HeaderValue => .headerValue
  | .BodySize => .bodySize

def resultOf {α β : Type} (value : α → β) :
    core.result.Result α construct.ConstructError → Except ConstructError β
  | .Ok result => .ok (value result)
  | .Err error => .error (errorOf error)

theorem argsOf_getElem? (arguments : Slice construct.ArgumentValue) (index : Nat) :
    (argsOf arguments)[index]? = arguments.val[index]?.map argOf := by
  simp [argsOf]

theorem length_argsOf (arguments : Slice construct.ArgumentValue) :
    (argsOf arguments).length = arguments.val.length := by
  simp [argsOf]

end Abstraction

@[simp] theorem vecBytes_deref (vector : alloc.vec.Vec Std.U8) :
    byteList (alloc.vec.Vec.deref vector).val = vecBytes vector := rfl

@[simp] theorem deref_val {T : Type} (vector : alloc.vec.Vec T) :
    (alloc.vec.Vec.deref vector).val = vector.val := rfl

/-! ## Construction: JSON values -/

open Auths.Product.RequestConstruction in
@[step] theorem append_json_string_spec (out : alloc.vec.Vec Std.U8) (text : Slice Std.U8)
    (fits : out.val.length + (jsonString (byteList text.val)).length < 4294967295) :
    construct.append_json_string out text ⦃ result =>
      byteList result.val = byteList out.val ++ jsonString (byteList text.val) ⦄ := by
  unfold construct.append_json_string
  simp only [jsonString, List.length_cons, List.length_append] at fits
  step as ⟨out1, out1Eq⟩
  step with append_json_escaped_spec as ⟨escaped, escapedEq⟩
  · simp [out1Eq]; omega
  have closeFits : escaped.val.length < Usize.max := by
    apply lt_usize_max
    rw [← length_byteList, escapedEq, List.length_append, length_byteList, out1Eq]
    simp; omega
  step as ⟨result, resultEq⟩
  simp [byteList, resultEq, jsonString]
  simp only [byteList] at escapedEq
  simp [out1Eq] at escapedEq
  simp [escapedEq]

open Auths.Product.RequestConstruction in
@[step] theorem append_json_argument_spec (out : alloc.vec.Vec Std.U8)
    (value : construct.ArgumentValue)
    (fits : out.val.length + (jsonArgument (argOf value)).length < 4294967295) :
    construct.append_json_argument out value ⦃ result =>
      byteList result.val = byteList out.val ++ jsonArgument (argOf value) ⦄ := by
  cases value with
  | Text text =>
      simp only [construct.append_json_argument, argOf, jsonArgument] at fits ⊢
      step with append_json_string_spec as ⟨result, resultEq⟩
      side_fits
  | Integer digits =>
      simp only [construct.append_json_argument, argOf, jsonArgument] at fits ⊢
      step with append_bytes_spec as ⟨result, resultEq⟩
      side_fits
  | Boolean flag =>
      cases flag with
      | true =>
          simp only [construct.append_json_argument, argOf, jsonArgument, List.length_cons,
            List.length_nil, if_true] at fits ⊢
          step as ⟨out1, out1Eq⟩
          have fits2 : out1.val.length < Usize.max := by fits_tac
          step as ⟨out2, out2Eq⟩
          have fits3 : out2.val.length < Usize.max := by fits_tac
          step as ⟨out3, out3Eq⟩
          have fits4 : out3.val.length < Usize.max := by fits_tac
          step as ⟨out4, out4Eq⟩
          simp [byteList, out4Eq, out3Eq, out2Eq, out1Eq]
      | false =>
          simp only [construct.append_json_argument, argOf, jsonArgument, List.length_cons,
            List.length_nil, Bool.false_eq_true, if_false] at fits ⊢
          step as ⟨out1, out1Eq⟩
          have fits2 : out1.val.length < Usize.max := by fits_tac
          step as ⟨out2, out2Eq⟩
          have fits3 : out2.val.length < Usize.max := by fits_tac
          step as ⟨out3, out3Eq⟩
          have fits4 : out3.val.length < Usize.max := by fits_tac
          step as ⟨out4, out4Eq⟩
          have fits5 : out4.val.length < Usize.max := by fits_tac
          step as ⟨out5, out5Eq⟩
          simp [byteList, out5Eq, out4Eq, out3Eq, out2Eq, out1Eq]

open Auths.Product.RequestConstruction in
@[step] theorem json_piece_valid_spec (piece : construct.JsonPiece)
    (arguments : Slice construct.ArgumentValue) :
    construct.json_piece_valid piece arguments ⦃ result =>
      result = jsonPieceValid (argsOf arguments) (jsonPieceOf piece) ⦄ := by
  rcases piece with bytes | field | _ <;>
    simp [construct.json_piece_valid, jsonPieceOf, jsonPieceValid, length_argsOf]

open Auths.Product.RequestConstruction in
@[step] theorem json_pieces_valid_spec (pieces : Slice construct.JsonPiece)
    (arguments : Slice construct.ArgumentValue) :
    construct.json_pieces_valid pieces arguments ⦃ result =>
      result = (pieces.val.map jsonPieceOf).all (jsonPieceValid (argsOf arguments)) ⦄ := by
  unfold construct.json_pieces_valid construct.json_pieces_valid_loop
  apply loop.spec_decr_nat
    (measure := fun index => pieces.val.length - index.val)
    (inv := fun index => index.val ≤ pieces.val.length ∧
      (pieces.val.map jsonPieceOf).all (jsonPieceValid (argsOf arguments)) =
        ((pieces.val.drop index.val).map jsonPieceOf).all (jsonPieceValid (argsOf arguments)))
  · intro index ⟨indexBound, allDrop⟩
    unfold construct.json_pieces_valid_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < pieces.val.length := by simpa using withinBounds
      step as ⟨piece, pieceEq⟩
      step with json_piece_valid_spec as ⟨valid, validEq⟩
      rw [List.drop_eq_getElem_cons inBounds, List.map_cons, List.all_cons, ← pieceEq,
        ← validEq] at allDrop
      split <;> rename_i isValid
      · step as ⟨next, nextEq⟩
        refine ⟨by omega, ?_, by omega⟩
        rw [allDrop, nextEq]
        simp [isValid]
      · simp only [spec_ok]
        simp [allDrop, isValid]
    · simp only [spec_ok]
      have atEnd : pieces.val.length ≤ index.val := by simpa using withinBounds
      rw [allDrop, List.drop_eq_nil_of_le atEnd]
      rfl
  · exact ⟨by simp, by simp⟩

open Auths.Product.RequestConstruction in
@[step] theorem append_json_piece_spec (out : alloc.vec.Vec Std.U8)
    (piece : construct.JsonPiece) (arguments : Slice construct.ArgumentValue)
    (echo : Slice Std.U8)
    (fits : out.val.length +
      (renderJsonPiece (argsOf arguments) (byteList echo.val) (jsonPieceOf piece)).length <
        4294967295) :
    construct.append_json_piece out piece arguments echo ⦃ result =>
      byteList result.val = byteList out.val ++
        renderJsonPiece (argsOf arguments) (byteList echo.val) (jsonPieceOf piece) ⦄ := by
  cases piece with
  | Raw bytes =>
      simp only [construct.append_json_piece, jsonPieceOf, renderJsonPiece] at fits ⊢
      step with append_bytes_spec as ⟨result, resultEq⟩
      side_fits
  | Field field =>
      simp only [construct.append_json_piece, jsonPieceOf, renderJsonPiece] at fits ⊢
      split <;> rename_i withinBounds
      · have inBounds : field.val < arguments.val.length := by simpa using withinBounds
        rw [argsOf_getElem?, List.getElem?_eq_getElem inBounds] at fits ⊢
        simp only [Option.map_some] at fits ⊢
        step as ⟨argument, argumentEq⟩
        rw [← argumentEq] at fits ⊢
        step with append_json_argument_spec as ⟨result, resultEq⟩
        side_fits
      · have outOfBounds : arguments.val.length ≤ field.val := by simpa using withinBounds
        rw [argsOf_getElem?, List.getElem?_eq_none outOfBounds]
        simp
  | Echo =>
      simp only [construct.append_json_piece, jsonPieceOf, renderJsonPiece] at fits ⊢
      step with append_json_string_spec as ⟨result, resultEq⟩
      side_fits

open Auths.Product.RequestConstruction in
@[step] theorem append_json_pieces_spec (out : alloc.vec.Vec Std.U8)
    (pieces : Slice construct.JsonPiece) (arguments : Slice construct.ArgumentValue)
    (echo : Slice Std.U8)
    (fits : out.val.length +
      (renderJson (argsOf arguments) (byteList echo.val) (pieces.val.map jsonPieceOf)).length <
        4294967295) :
    construct.append_json_pieces out pieces arguments echo ⦃ result =>
      byteList result.val = byteList out.val ++
        renderJson (argsOf arguments) (byteList echo.val) (pieces.val.map jsonPieceOf) ⦄ := by
  unfold construct.append_json_pieces construct.append_json_pieces_loop
  have renderMap : ∀ list : List construct.JsonPiece,
      renderJson (argsOf arguments) (byteList echo.val) (list.map jsonPieceOf) =
        list.flatMap (fun piece =>
          renderJsonPiece (argsOf arguments) (byteList echo.val) (jsonPieceOf piece)) := by
    intro list
    simp [renderJson, List.flatMap_map]
  rw [renderMap] at fits ⊢
  apply loop.spec_decr_nat
    (measure := fun state => pieces.val.length - state.2.val)
    (inv := fun state =>
      byteList state.1.val = byteList out.val ++
        (pieces.val.take state.2.val).flatMap (fun piece =>
          renderJsonPiece (argsOf arguments) (byteList echo.val) (jsonPieceOf piece)) ∧
        state.2.val ≤ pieces.val.length)
  · rintro ⟨current, index⟩ ⟨currentEq, indexBound⟩
    unfold construct.append_json_pieces_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < pieces.val.length := by simpa using withinBounds
      step as ⟨piece, pieceEq⟩
      have lengthCurrent : current.val.length = out.val.length +
          ((pieces.val.take index.val).flatMap (fun piece =>
            renderJsonPiece (argsOf arguments) (byteList echo.val) (jsonPieceOf piece))).length := by
        rw [← length_byteList current.val, currentEq, List.length_append, length_byteList]
      have bound := length_flatMap_take_succ_le (fun piece =>
        renderJsonPiece (argsOf arguments) (byteList echo.val) (jsonPieceOf piece))
        pieces.val index.val inBounds
      step with append_json_piece_spec as ⟨next, nextEq⟩
      step as ⟨nextIndex, nextIndexEq⟩
      refine ⟨?_, by omega, by omega⟩
      rw [nextEq, currentEq, nextIndexEq, pieceEq, List.append_assoc,
        flatMap_take_succ _ pieces.val index.val inBounds]
    · simp only [spec_ok]
      have atEnd : pieces.val.length ≤ index.val := by simpa using withinBounds
      rw [currentEq, List.take_of_length_le atEnd]
  · exact ⟨by simp, by simp⟩

open Auths.Product.RequestConstruction in
@[step] theorem form_piece_valid_spec (piece : construct.FormPiece)
    (arguments : Slice construct.ArgumentValue) :
    construct.form_piece_valid piece arguments ⦃ result =>
      result = formPieceValid (argsOf arguments) (formPieceOf piece) ⦄ := by
  rcases piece with bytes | field | pieces | _
  · simp [construct.form_piece_valid, formPieceOf, formPieceValid]
  · simp only [construct.form_piece_valid, formPieceOf, formPieceValid]
    split <;> rename_i withinBounds
    · have inBounds : field.val < arguments.val.length := by simpa using withinBounds
      rw [argsOf_getElem?, List.getElem?_eq_getElem inBounds]
      step as ⟨argument, argumentEq⟩
      rw [← argumentEq]
      rcases argument with text | digits | flag <;> simp [argOf]
    · have outOfBounds : arguments.val.length ≤ field.val := by simpa using withinBounds
      rw [argsOf_getElem?, List.getElem?_eq_none outOfBounds]
      simp
  · simp only [construct.form_piece_valid, formPieceOf, formPieceValid]
    step with json_pieces_valid_spec as ⟨valid, validEq⟩
    simpa [alloc.vec.Vec.deref] using validEq
  · simp [construct.form_piece_valid, formPieceOf, formPieceValid]

open Auths.Product.RequestConstruction in
@[step] theorem form_pieces_valid_spec (pieces : Slice construct.FormPiece)
    (arguments : Slice construct.ArgumentValue) :
    construct.form_pieces_valid pieces arguments ⦃ result =>
      result = (pieces.val.map formPieceOf).all (formPieceValid (argsOf arguments)) ⦄ := by
  unfold construct.form_pieces_valid construct.form_pieces_valid_loop
  apply loop.spec_decr_nat
    (measure := fun index => pieces.val.length - index.val)
    (inv := fun index => index.val ≤ pieces.val.length ∧
      (pieces.val.map formPieceOf).all (formPieceValid (argsOf arguments)) =
        ((pieces.val.drop index.val).map formPieceOf).all (formPieceValid (argsOf arguments)))
  · intro index ⟨indexBound, allDrop⟩
    unfold construct.form_pieces_valid_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < pieces.val.length := by simpa using withinBounds
      step as ⟨piece, pieceEq⟩
      step with form_piece_valid_spec as ⟨valid, validEq⟩
      rw [List.drop_eq_getElem_cons inBounds, List.map_cons, List.all_cons, ← pieceEq,
        ← validEq] at allDrop
      split <;> rename_i isValid
      · step as ⟨next, nextEq⟩
        refine ⟨by omega, ?_, by omega⟩
        rw [allDrop, nextEq]
        simp [isValid]
      · simp only [spec_ok]
        simp [allDrop, isValid]
    · simp only [spec_ok]
      have atEnd : pieces.val.length ≤ index.val := by simpa using withinBounds
      rw [allDrop, List.drop_eq_nil_of_le atEnd]
      rfl
  · exact ⟨by simp, by simp⟩


theorem length_le_formEncode (text : Auths.Product.RequestConstruction.Bytes) :
    text.length ≤ (Auths.Product.RequestConstruction.formEncode text).length := by
  induction text with
  | nil => simp [Auths.Product.RequestConstruction.formEncode]
  | cons byte rest inductive_hypothesis =>
      simp only [Auths.Product.RequestConstruction.formEncode, List.flatMap_cons,
        List.length_append, List.length_cons] at *
      have : 1 ≤ (Auths.Product.RequestConstruction.formByte byte).length := by
        unfold Auths.Product.RequestConstruction.formByte Auths.Product.RequestConstruction.percent
        split_ifs <;> simp
      omega

open Auths.Product.RequestConstruction in
@[step] theorem append_form_piece_spec (out : alloc.vec.Vec Std.U8)
    (piece : construct.FormPiece) (arguments : Slice construct.ArgumentValue)
    (echo : Slice Std.U8)
    (fits : out.val.length +
      (renderFormPiece (argsOf arguments) (byteList echo.val) (formPieceOf piece)).length <
        4294967295) :
    construct.append_form_piece out piece arguments echo ⦃ result =>
      byteList result.val = byteList out.val ++
        renderFormPiece (argsOf arguments) (byteList echo.val) (formPieceOf piece) ⦄ := by
  rcases piece with bytes | field | pieces | _
  · simp only [construct.append_form_piece, formPieceOf, renderFormPiece] at fits ⊢
    step with append_bytes_spec as ⟨result, resultEq⟩
    side_fits
  · simp only [construct.append_form_piece, formPieceOf, renderFormPiece] at fits ⊢
    split <;> rename_i withinBounds
    · have inBounds : field.val < arguments.val.length := by simpa using withinBounds
      rw [argsOf_getElem?, List.getElem?_eq_getElem inBounds] at fits ⊢
      step as ⟨argument, argumentEq⟩
      rw [← argumentEq] at fits ⊢
      rcases argument with text | digits | flag
      · simp only [Option.map_some, argOf] at fits ⊢
        step with append_form_encoded_spec as ⟨result, resultEq⟩
        side_fits
      · simp only [Option.map_some, argOf] at fits ⊢
        step with append_form_encoded_spec as ⟨result, resultEq⟩
        side_fits
      · simp [argOf]
    · have outOfBounds : arguments.val.length ≤ field.val := by simpa using withinBounds
      rw [argsOf_getElem?, List.getElem?_eq_none outOfBounds]
      simp
  · simp only [construct.append_form_piece, formPieceOf, renderFormPiece] at fits ⊢
    have jsonFits := length_le_formEncode
      (renderJson (argsOf arguments) (byteList echo.val) (pieces.val.map jsonPieceOf))
    step with append_json_pieces_spec as ⟨json, jsonEq⟩
    · simp only [deref_val]
      simp
      omega
    simp only [deref_val] at jsonEq
    step with append_form_encoded_spec as ⟨result, resultEq⟩
    · simp only [deref_val]
      rw [jsonEq]
      exact fits
    simp only [deref_val] at resultEq
    rw [resultEq, jsonEq]
    simp [byteList]
  · simp only [construct.append_form_piece, formPieceOf, renderFormPiece] at fits ⊢
    step with append_form_encoded_spec as ⟨result, resultEq⟩
    side_fits

open Auths.Product.RequestConstruction in
@[step] theorem append_form_pieces_spec (out : alloc.vec.Vec Std.U8)
    (pieces : Slice construct.FormPiece) (arguments : Slice construct.ArgumentValue)
    (echo : Slice Std.U8)
    (fits : out.val.length +
      ((pieces.val.map formPieceOf).flatMap
        (renderFormPiece (argsOf arguments) (byteList echo.val))).length < 4294967295) :
    construct.append_form_pieces out pieces arguments echo ⦃ result =>
      byteList result.val = byteList out.val ++
        (pieces.val.map formPieceOf).flatMap
          (renderFormPiece (argsOf arguments) (byteList echo.val)) ⦄ := by
  unfold construct.append_form_pieces construct.append_form_pieces_loop
  have renderMap : ∀ list : List construct.FormPiece,
      (list.map formPieceOf).flatMap (renderFormPiece (argsOf arguments) (byteList echo.val)) =
        list.flatMap (fun piece =>
          renderFormPiece (argsOf arguments) (byteList echo.val) (formPieceOf piece)) := by
    intro list
    simp [List.flatMap_map]
  rw [renderMap] at fits ⊢
  apply loop.spec_decr_nat
    (measure := fun state => pieces.val.length - state.2.val)
    (inv := fun state =>
      byteList state.1.val = byteList out.val ++
        (pieces.val.take state.2.val).flatMap (fun piece =>
          renderFormPiece (argsOf arguments) (byteList echo.val) (formPieceOf piece)) ∧
        state.2.val ≤ pieces.val.length)
  · rintro ⟨current, index⟩ ⟨currentEq, indexBound⟩
    unfold construct.append_form_pieces_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < pieces.val.length := by simpa using withinBounds
      step as ⟨piece, pieceEq⟩
      have lengthCurrent : current.val.length = out.val.length +
          ((pieces.val.take index.val).flatMap (fun piece =>
            renderFormPiece (argsOf arguments) (byteList echo.val) (formPieceOf piece))).length := by
        rw [← length_byteList current.val, currentEq, List.length_append, length_byteList]
      have bound := length_flatMap_take_succ_le (fun piece =>
        renderFormPiece (argsOf arguments) (byteList echo.val) (formPieceOf piece))
        pieces.val index.val inBounds
      step with append_form_piece_spec as ⟨next, nextEq⟩
      step as ⟨nextIndex, nextIndexEq⟩
      refine ⟨?_, by omega, by omega⟩
      rw [nextEq, currentEq, nextIndexEq, pieceEq, List.append_assoc,
        flatMap_take_succ _ pieces.val index.val inBounds]
    · simp only [spec_ok]
      have atEnd : pieces.val.length ≤ index.val := by simpa using withinBounds
      rw [currentEq, List.take_of_length_le atEnd]
  · exact ⟨by simp, by simp⟩

theorem max_body_bytes_val : construct.MAX_BODY_BYTES.val = 16384 := by
  unfold construct.MAX_BODY_BYTES
  rfl

open Auths.Product.RequestConstruction in
@[step] theorem build_body_spec (plan : construct.BodyPlan)
    (arguments : Slice construct.ArgumentValue) (echo : Slice Std.U8)
    (fits : (renderBody (argsOf arguments) (byteList echo.val) (bodyPlanOf plan)).length <
      4294967295) :
    construct.build_body plan arguments echo ⦃ result =>
      resultOf vecBytes result =
        buildBody (bodyPlanOf plan) (argsOf arguments) (byteList echo.val) ⦄ := by
  rcases plan with pieces | pieces
  · simp only [construct.build_body, bodyPlanOf, renderBody] at fits ⊢
    step with json_pieces_valid_spec as ⟨valid, validEq⟩
    simp only [deref_val] at validEq
    split <;> rename_i isValid
    · step with append_json_pieces_spec as ⟨body, bodyEq⟩
      · simpa using fits
      simp only [deref_val] at bodyEq
      have bodyModel : vecBytes body =
          renderJson (argsOf arguments) (byteList echo.val) (pieces.val.map jsonPieceOf) := by
        simpa [vecBytes, byteList] using bodyEq
      have bodyLength : body.val.length =
          (renderJson (argsOf arguments) (byteList echo.val) (pieces.val.map jsonPieceOf)).length := by
        rw [← bodyModel, vecBytes, length_byteList]
      have validModel : bodyValid (argsOf arguments) (.json (pieces.val.map jsonPieceOf)) = true := by
        simp [bodyValid, ← validEq, isValid]
      simp only [buildBody, validModel, if_true, renderBody]
      split <;> rename_i empty
      · have : body.val.length = 0 := by scalar_tac
        simp [resultOf, ← bodyLength, this, errorOf]
      · split <;> rename_i large
        · have : 16384 < body.val.length := by
            have := max_body_bytes_val
            scalar_tac
          simp [resultOf, ← bodyLength, this, maxBodyBytes, errorOf]
        · have notEmpty : body.val.length ≠ 0 := by scalar_tac
          have notLarge : ¬ 16384 < body.val.length := by
            have := max_body_bytes_val
            scalar_tac
          simp [resultOf, ← bodyLength, notEmpty, notLarge, maxBodyBytes, bodyModel]
    · have invalidModel : bodyValid (argsOf arguments) (.json (pieces.val.map jsonPieceOf)) = false := by
        simp [bodyValid, ← validEq, isValid]
      simp [buildBody, invalidModel, resultOf, errorOf]
  · simp only [construct.build_body, bodyPlanOf, renderBody] at fits ⊢
    step with form_pieces_valid_spec as ⟨valid, validEq⟩
    simp only [deref_val] at validEq
    split <;> rename_i isValid
    · step with append_form_pieces_spec as ⟨body, bodyEq⟩
      · simpa using fits
      simp only [deref_val] at bodyEq
      have bodyModel : vecBytes body =
          (pieces.val.map formPieceOf).flatMap
            (renderFormPiece (argsOf arguments) (byteList echo.val)) := by
        simpa [vecBytes, byteList] using bodyEq
      have bodyLength : body.val.length =
          ((pieces.val.map formPieceOf).flatMap
            (renderFormPiece (argsOf arguments) (byteList echo.val))).length := by
        rw [← bodyModel, vecBytes, length_byteList]
      have validModel : bodyValid (argsOf arguments) (.form (pieces.val.map formPieceOf)) = true := by
        simp [bodyValid, ← validEq, isValid]
      simp only [buildBody, validModel, if_true, renderBody]
      split <;> rename_i empty
      · have : body.val.length = 0 := by scalar_tac
        simp [resultOf, ← bodyLength, this, errorOf]
      · split <;> rename_i large
        · have : 16384 < body.val.length := by
            have := max_body_bytes_val
            scalar_tac
          simp [resultOf, ← bodyLength, this, maxBodyBytes, errorOf]
        · have notEmpty : body.val.length ≠ 0 := by scalar_tac
          have notLarge : ¬ 16384 < body.val.length := by
            have := max_body_bytes_val
            scalar_tac
          simp [resultOf, ← bodyLength, notEmpty, notLarge, maxBodyBytes, bodyModel]
    · have invalidModel : bodyValid (argsOf arguments) (.form (pieces.val.map formPieceOf)) = false := by
        simp [bodyValid, ← validEq, isValid]
      simp [buildBody, invalidModel, resultOf, errorOf]

/-! ## Construction: paths -/

theorem max_segment_value_bytes_val : construct.MAX_SEGMENT_VALUE_BYTES.val = 4096 := by
  unfold construct.MAX_SEGMENT_VALUE_BYTES
  rfl

theorem max_path_bytes_val : construct.MAX_PATH_BYTES.val = 8192 := by
  unfold construct.MAX_PATH_BYTES
  rfl

open Auths.Product.RequestConstruction in
@[step] theorem segment_value_valid_spec (text : Slice Std.U8) :
    construct.segment_value_valid text ⦃ result =>
      result = segmentValueValid (byteList text.val) ⦄ := by
  have maxValue := max_segment_value_bytes_val
  unfold construct.segment_value_valid
  rcases text with ⟨list, bounded⟩
  rcases list with _ | ⟨first, _ | ⟨second, rest⟩⟩
  · simp [segmentValueValid, byteList]
  · have firstScalar : (first = 46#u8) ↔ first.val = 46 := by
      simp [UScalar.eq_equiv]
    simp [segmentValueValid, byteList, maxSegmentValueBytes, Slice.len, Slice.index_usize,
      firstScalar]
    split_ifs <;> simp_all
  · have firstScalar : (first = 46#u8) ↔ first.val = 46 := by
      simp [UScalar.eq_equiv]
    have secondScalar : (second = 46#u8) ↔ second.val = 46 := by
      simp [UScalar.eq_equiv]
    rcases rest with _ | ⟨third, rest⟩
    · simp [segmentValueValid, byteList, maxSegmentValueBytes, Slice.len, Slice.index_usize,
        firstScalar, secondScalar]
      split_ifs <;> simp_all
      by_cases secondDot : second.val = 46 <;> simp [secondDot]
    · simp [segmentValueValid, byteList, maxSegmentValueBytes, Slice.len]
      split_ifs <;> simp_all
      scalar_tac

open Auths.Product.RequestConstruction in
@[step] theorem segment_error_spec (segment : construct.SegmentPlan)
    (arguments : Slice construct.ArgumentValue) :
    construct.segment_error segment arguments ⦃ result =>
      result.map errorOf = segmentError (argsOf arguments) (segmentOf segment) ⦄ := by
  rcases segment with value | field
  · simp [construct.segment_error, segmentOf, segmentError]
  · simp only [construct.segment_error, segmentOf, segmentError]
    split <;> rename_i outside
    · have outOfBounds : arguments.val.length ≤ field.val := by scalar_tac
      rw [argsOf_getElem?, List.getElem?_eq_none outOfBounds]
      simp [errorOf]
    · have inBounds : field.val < arguments.val.length := by scalar_tac
      rw [argsOf_getElem?, List.getElem?_eq_getElem inBounds]
      step as ⟨argument, argumentEq⟩
      rw [← argumentEq]
      rcases argument with text | digits | flag
      · simp only [Option.map_some, argOf]
        step with segment_value_valid_spec as ⟨valid, validEq⟩
        simp only [deref_val] at validEq
        split <;> rename_i isValid <;> simp [← validEq, isValid, vecBytes, errorOf]
      · simp [argOf, errorOf]
      · simp [argOf, errorOf]

open Auths.Product.RequestConstruction in
@[step] theorem path_error_spec (path : Slice construct.SegmentPlan)
    (arguments : Slice construct.ArgumentValue) :
    construct.path_error path arguments ⦃ result =>
      result.map errorOf = pathError (argsOf arguments) (path.val.map segmentOf) ⦄ := by
  unfold construct.path_error construct.path_error_loop
  apply loop.spec_decr_nat
    (measure := fun index => path.val.length - index.val)
    (inv := fun index => index.val ≤ path.val.length ∧
      pathError (argsOf arguments) (path.val.map segmentOf) =
        pathError (argsOf arguments) ((path.val.drop index.val).map segmentOf))
  · intro index ⟨indexBound, errorDrop⟩
    unfold construct.path_error_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < path.val.length := by simpa using withinBounds
      step as ⟨segment, segmentEq⟩
      step with segment_error_spec as ⟨error, errorEq⟩
      rw [List.drop_eq_getElem_cons inBounds, List.map_cons, ← segmentEq] at errorDrop
      simp only [pathError] at errorDrop
      rw [← errorEq] at errorDrop
      rcases error with _ | error
      · simp only [Option.isSome_none, Bool.false_eq_true, if_false]
        step as ⟨next, nextEq⟩
        refine ⟨by omega, ?_, by omega⟩
        rw [errorDrop, nextEq]
        rfl
      · simp only [Option.isSome_some, if_true, spec_ok]
        rw [errorDrop]
        rfl
    · simp only [spec_ok]
      have atEnd : path.val.length ≤ index.val := by simpa using withinBounds
      rw [errorDrop, List.drop_eq_nil_of_le atEnd]
      rfl
  · exact ⟨by simp, by simp⟩

open Auths.Product.RequestConstruction in
@[step] theorem append_segment_spec (out : alloc.vec.Vec Std.U8)
    (segment : construct.SegmentPlan) (arguments : Slice construct.ArgumentValue)
    (fits : out.val.length +
      (47 :: segmentBytes (argsOf arguments) (segmentOf segment)).length < 4294967295) :
    construct.append_segment out segment arguments ⦃ result =>
      byteList result.val = byteList out.val ++
        47 :: segmentBytes (argsOf arguments) (segmentOf segment) ⦄ := by
  simp only [List.length_cons] at fits
  unfold construct.append_segment
  step as ⟨out1, out1Eq⟩
  have out1Model : byteList out1.val = byteList out.val ++ [47] := by
    simp [out1Eq, byteList]
  have out1Length : out1.val.length = out.val.length + 1 := by simp [out1Eq]
  rcases segment with value | field
  · simp only [segmentOf, segmentBytes] at fits ⊢
    step with append_bytes_spec as ⟨result, resultEq⟩
    · simp only [deref_val]
      rw [out1Length]
      simp only [vecBytes, length_byteList] at fits
      omega
    simp only [deref_val] at resultEq
    rw [resultEq, byteList_append, out1Model]
    simp [vecBytes]
  · simp only [segmentOf, segmentBytes] at fits ⊢
    split <;> rename_i withinBounds
    · have inBounds : field.val < arguments.val.length := by simpa using withinBounds
      rw [argsOf_getElem?, List.getElem?_eq_getElem inBounds] at fits ⊢
      step as ⟨argument, argumentEq⟩
      rw [← argumentEq] at fits ⊢
      rcases argument with text | digits | flag
      · simp only [Option.map_some, argOf] at fits ⊢
        step with append_path_encoded_spec as ⟨result, resultEq⟩
        · simp only [deref_val]
          rw [out1Length]
          simp only [vecBytes] at fits
          omega
        simp only [deref_val] at resultEq
        rw [resultEq, out1Model]
        simp [vecBytes]
      · simp [argOf, out1Model]
      · simp [argOf, out1Model]
    · have outOfBounds : arguments.val.length ≤ field.val := by simpa using withinBounds
      rw [argsOf_getElem?, List.getElem?_eq_none outOfBounds]
      simp [out1Model]

open Auths.Product.RequestConstruction in
@[step] theorem append_segments_spec (out : alloc.vec.Vec Std.U8)
    (path : Slice construct.SegmentPlan) (arguments : Slice construct.ArgumentValue)
    (fits : out.val.length +
      (renderPath (argsOf arguments) (path.val.map segmentOf)).length <
        4294967295) :
    construct.append_segments out path arguments ⦃ result =>
      byteList result.val = byteList out.val ++
        renderPath (argsOf arguments) (path.val.map segmentOf) ⦄ := by
  unfold construct.append_segments construct.append_segments_loop
  have renderMap : ∀ list : List construct.SegmentPlan,
      renderPath (argsOf arguments) (list.map segmentOf) =
        list.flatMap (fun piece =>
          47 :: segmentBytes (argsOf arguments) (segmentOf piece)) := by
    intro list
    simp [renderPath, List.flatMap_map]
  rw [renderMap] at fits ⊢
  apply loop.spec_decr_nat
    (measure := fun state => path.val.length - state.2.val)
    (inv := fun state =>
      byteList state.1.val = byteList out.val ++
        (path.val.take state.2.val).flatMap (fun piece =>
          47 :: segmentBytes (argsOf arguments) (segmentOf piece)) ∧
        state.2.val ≤ path.val.length)
  · rintro ⟨current, index⟩ ⟨currentEq, indexBound⟩
    unfold construct.append_segments_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < path.val.length := by simpa using withinBounds
      step as ⟨piece, segmentEq⟩
      have lengthCurrent : current.val.length = out.val.length +
          ((path.val.take index.val).flatMap (fun piece =>
            47 :: segmentBytes (argsOf arguments) (segmentOf piece))).length := by
        rw [← length_byteList current.val, currentEq, List.length_append, length_byteList]
      have bound := length_flatMap_take_succ_le (fun piece =>
        47 :: segmentBytes (argsOf arguments) (segmentOf piece))
        path.val index.val inBounds
      step with append_segment_spec as ⟨next, nextEq⟩
      step as ⟨nextIndex, nextIndexEq⟩
      refine ⟨?_, by omega, by omega⟩
      rw [nextEq, currentEq, nextIndexEq, segmentEq, List.append_assoc,
        flatMap_take_succ _ path.val index.val inBounds]
    · simp only [spec_ok]
      have atEnd : path.val.length ≤ index.val := by simpa using withinBounds
      rw [currentEq, List.take_of_length_le atEnd]
  · exact ⟨by simp, by simp⟩


open Auths.Product.RequestConstruction in
@[step] theorem build_url_spec (origin : Slice Std.U8) (path : Slice construct.SegmentPlan)
    (arguments : Slice construct.ArgumentValue)
    (fits : origin.val.length + (renderPath (argsOf arguments) (path.val.map segmentOf)).length <
      4294967295) :
    construct.build_url origin path arguments ⦃ result =>
      resultOf vecBytes result =
        buildUrl (byteList origin.val) (path.val.map segmentOf) (argsOf arguments) ⦄ := by
  unfold construct.build_url
  step with path_error_spec as ⟨failure, failureEq⟩
  rcases failure with _ | error
  · simp only [Option.map_none] at failureEq
    simp only [buildUrl, ← failureEq]
    step with append_segments_spec as ⟨encoded, encodedEq⟩
    have encodedModel : vecBytes encoded = renderPath (argsOf arguments) (path.val.map segmentOf) := by
      simpa [vecBytes, byteList] using encodedEq
    have encodedLength : encoded.val.length =
        (renderPath (argsOf arguments) (path.val.map segmentOf)).length := by
      rw [← encodedModel, vecBytes, length_byteList]
    split <;> rename_i large
    · have : 8192 < encoded.val.length := by
        have := max_path_bytes_val
        scalar_tac
      simp [resultOf, errorOf, maxPathBytes, ← encodedLength, this]
    · have notLarge : ¬ 8192 < encoded.val.length := by
        have := max_path_bytes_val
        scalar_tac
      step with copy_bytes_spec as ⟨copy, copyEq⟩
      step with append_bytes_spec as ⟨result, resultEq⟩
      all_goals try (simp only [deref_val, copyEq] <;> omega)
      simp only [deref_val] at resultEq
      have lengthFits : (byteList encoded.val).length ≤ 8192 := by
        rw [length_byteList]
        omega
      simp [resultOf, maxPathBytes, vecBytes, resultEq, copyEq, byteList_append, ← encodedModel,
        lengthFits]
  · simp only [Option.map_some] at failureEq
    simp [buildUrl, ← failureEq, resultOf]

open Auths.Product.RequestConstruction in
@[step] theorem fixed_url_spec (origin : Slice Std.U8) (path : Slice (alloc.vec.Vec Std.U8))
    (fits : origin.val.length +
      ((path.val.map vecBytes).flatMap (fun segment => 47 :: segment)).length < 4294967295) :
    construct.fixed_url origin path ⦃ result =>
      byteList result.val = byteList origin.val ++
        (path.val.map vecBytes).flatMap (fun segment => 47 :: segment) ⦄ := by
  unfold construct.fixed_url construct.fixed_url_loop
  step with copy_bytes_spec as ⟨out, outEq⟩
  have renderMap : (path.val.map vecBytes).flatMap (fun segment => 47 :: segment) =
      path.val.flatMap (fun segment => 47 :: vecBytes segment) := by
    simp [List.flatMap_map]
  rw [renderMap] at fits ⊢
  apply loop.spec_decr_nat
    (measure := fun state => path.val.length - state.2.val)
    (inv := fun state =>
      byteList state.1.val = byteList origin.val ++
        (path.val.take state.2.val).flatMap (fun segment => 47 :: vecBytes segment) ∧
        state.2.val ≤ path.val.length)
  · rintro ⟨current, index⟩ ⟨currentEq, indexBound⟩
    unfold construct.fixed_url_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < path.val.length := by simpa using withinBounds
      have lengthCurrent : current.val.length = origin.val.length +
          ((path.val.take index.val).flatMap (fun segment => 47 :: vecBytes segment)).length := by
        rw [← length_byteList current.val, currentEq, List.length_append, length_byteList]
      have bound := length_flatMap_take_succ_le (fun segment => 47 :: vecBytes segment)
        path.val index.val inBounds
      simp only [List.length_cons] at bound
      step as ⟨out1, out1Eq⟩
      step as ⟨segment, segmentEq⟩
      step with append_bytes_spec as ⟨next, nextEq⟩
      · simp only [deref_val, out1Eq, List.length_append, List.length_singleton, lengthCurrent,
          segmentEq]
        simp only [vecBytes, length_byteList] at bound fits lengthCurrent ⊢
        omega
      step as ⟨nextIndex, nextIndexEq⟩
      refine ⟨?_, by omega, by omega⟩
      simp only [deref_val] at nextEq
      rw [nextEq, byteList_append, out1Eq, byteList_append, currentEq, nextIndexEq,
        flatMap_take_succ _ path.val index.val inBounds, segmentEq]
      simp [byteList, vecBytes]
    · simp only [spec_ok]
      have atEnd : path.val.length ≤ index.val := by simpa using withinBounds
      rw [currentEq, List.take_of_length_le atEnd]
  · exact ⟨by simp [outEq], by simp⟩

/-! ## Construction: headers -/

@[step] theorem copy_header_spec (header : construct.Header)
    (nameFits : header.«name».val.length < 4294967295)
    (valueFits : header.value.val.length < 4294967295) :
    construct.copy_header header ⦃ result => headerOf result = headerOf header ⦄ := by
  unfold construct.copy_header
  have nameSpec := copy_bytes_spec (alloc.vec.Vec.deref header.«name») (by simpa using nameFits)
  have valueSpec := copy_bytes_spec (alloc.vec.Vec.deref header.value) (by simpa using valueFits)
  step with nameSpec as ⟨nameCopy, nameEq⟩
  step with valueSpec as ⟨valueCopy, valueEq⟩
  simp only [deref_val] at nameEq valueEq
  simp [headerOf, vecBytes, nameEq, valueEq]

/-- Every header name and value is shorter than the capacity bound. -/
def HeadersFit (headers : List construct.Header) : Prop :=
  ∀ header ∈ headers, header.«name».val.length < 4294967295 ∧
    header.value.val.length < 4294967295

@[step] theorem append_version_headers_spec (out : alloc.vec.Vec construct.Header)
    (versions : Slice construct.Header)
    (countFits : out.val.length + versions.val.length < 4294967295)
    (headersFit : HeadersFit versions.val) :
    construct.append_version_headers out versions ⦃ result =>
      result.val.map headerOf = out.val.map headerOf ++ versions.val.map headerOf ⦄ := by
  unfold construct.append_version_headers construct.append_version_headers_loop
  apply loop.spec_decr_nat
    (measure := fun state => versions.val.length - state.2.val)
    (inv := fun state =>
      state.1.val.map headerOf = out.val.map headerOf ++ (versions.val.take state.2.val).map headerOf ∧
        state.1.val.length = out.val.length + state.2.val ∧
        state.2.val ≤ versions.val.length)
  · rintro ⟨current, index⟩ ⟨currentEq, currentLength, indexBound⟩
    dsimp only at currentEq currentLength indexBound
    unfold construct.append_version_headers_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < versions.val.length := by simpa using withinBounds
      step as ⟨header, headerEq⟩
      have fit := headersFit header (by rw [headerEq]; exact List.getElem_mem inBounds)
      step with copy_header_spec as ⟨copy, copyEq⟩
      have pushFits : current.val.length < Usize.max := by
        apply lt_usize_max
        omega
      step as ⟨next, nextEq⟩
      step as ⟨nextIndex, nextIndexEq⟩
      refine ⟨?_, ?_, by omega, by omega⟩
      · rw [nextEq, List.map_append, currentEq, nextIndexEq,
          List.take_succ_eq_append_getElem inBounds, List.map_append, List.append_assoc]
        simp only [List.map_cons, List.map_nil, copyEq, headerEq]
      · rw [nextEq, List.length_append, currentLength, nextIndexEq]
        simp
        omega
    · simp only [spec_ok]
      have atEnd : versions.val.length ≤ index.val := by simpa using withinBounds
      rw [currentEq, List.take_of_length_le atEnd]
  · exact ⟨by simp, by simp, by simp⟩

open Auths.Product.RequestConstruction in
@[step] theorem account_bytes_valid_spec (value : Slice Std.U8) (start : Std.Usize) :
    construct.account_bytes_valid value start ⦃ result =>
      result = ((byteList value.val).drop start.val).all accountByte ⦄ := by
  unfold construct.account_bytes_valid construct.account_bytes_valid_loop
  apply loop.spec_decr_nat
    (measure := fun index => value.val.length - index.val)
    (inv := fun index =>
      ((byteList value.val).drop start.val).all accountByte =
        ((byteList value.val).drop index.val).all accountByte)
  · intro index allDrop
    unfold construct.account_bytes_valid_loop.body
    dsimp only
    split <;> rename_i withinBounds
    · have inBounds : index.val < value.val.length := by simpa using withinBounds
      have modelBounds : index.val < (byteList value.val).length := by
        rw [length_byteList]; exact inBounds
      step as ⟨byte, byteEq⟩
      step with is_account_byte_spec as ⟨valid, validEq⟩
      have byteModel : byte.val = (byteList value.val)[index.val] := by simp [byteList, byteEq]
      rw [List.drop_eq_getElem_cons modelBounds, List.all_cons, ← byteModel] at allDrop
      split <;> rename_i isValid
      · step as ⟨next, nextEq⟩
        refine ⟨?_, by omega⟩
        rw [allDrop, nextEq, ← validEq, isValid]
        rfl
      · simp only [spec_ok]
        rw [allDrop, ← validEq]
        simp [isValid]
    · simp only [spec_ok]
      have atEnd : (byteList value.val).length ≤ index.val := by
        rw [length_byteList]; simpa using withinBounds
      rw [allDrop, List.drop_eq_nil_of_le atEnd]
      rfl
  · rfl

open Auths.Product.RequestConstruction in
@[step] theorem scope_value_valid_spec (grammar : construct.ScopeGrammar) (value : Slice Std.U8) :
    construct.scope_value_valid grammar value ⦃ result =>
      result = scopeValueValid (byteList value.val) ⦄ := by
  rcases value with ⟨list, bounded⟩
  by_cases long : 13 ≤ list.length
  · obtain ⟨a, b, c, d, e, rest, rfl⟩ : ∃ a b c d e rest, list = a :: b :: c :: d :: e :: rest := by
      rcases list with _ | ⟨a, _ | ⟨b, _ | ⟨c, _ | ⟨d, _ | ⟨e, rest⟩⟩⟩⟩⟩ <;>
        simp at long
      exact ⟨a, b, c, d, e, rest, rfl⟩
    have aScalar : (a = 97#u8) ↔ a.val = 97 := by simp [UScalar.eq_equiv]
    have bScalar : (b = 99#u8) ↔ b.val = 99 := by simp [UScalar.eq_equiv]
    have cScalar : (c = 99#u8) ↔ c.val = 99 := by simp [UScalar.eq_equiv]
    have dScalar : (d = 116#u8) ↔ d.val = 116 := by simp [UScalar.eq_equiv]
    have eScalar : (e = 95#u8) ↔ e.val = 95 := by simp [UScalar.eq_equiv]
    unfold construct.scope_value_valid
    have longScalar : (Slice.len ⟨a :: b :: c :: d :: e :: rest, bounded⟩) ≥ 13#usize := by
      simp only [ge_iff_le, UScalar.le_equiv, Slice.len_val]
      simp at long ⊢
      omega
    simp only [longScalar, if_true]
    by_cases short : rest.length + 5 ≤ 64
    · have shortScalar : (Slice.len ⟨a :: b :: c :: d :: e :: rest, bounded⟩) <= 64#usize := by
        simp only [UScalar.le_equiv, Slice.len_val]
        simp
        omega
      simp only [shortScalar, if_true]
      simp only [Slice.index_usize, Slice.getElem?_Usize_eq]
      simp only [UScalar.ofNatCore_val_eq, List.getElem?_cons_zero, List.getElem?_cons_succ,
        bind_tc_ok, aScalar, bScalar, cScalar, dScalar, eScalar]
      split_ifs with ha hb hc hd he
      · step with account_bytes_valid_spec as ⟨valid, validEq⟩
        simp [validEq, scopeValueValid, byteList, ha, hb, hc, hd, he, List.length_cons] at long ⊢
        omega
      all_goals simp_all [scopeValueValid, byteList]
    · have longValue : ¬ (Slice.len ⟨a :: b :: c :: d :: e :: rest, bounded⟩) <= 64#usize := by
        simp only [UScalar.le_equiv, Slice.len_val]
        simp
        omega
      simp only [longValue, if_false, spec_ok]
      simp [scopeValueValid, byteList]
      omega
  · unfold construct.scope_value_valid
    have shortScalar : ¬ (Slice.len ⟨list, bounded⟩) ≥ 13#usize := by
      simp only [ge_iff_le, UScalar.le_equiv, Slice.len_val]
      simp
      omega
    simp only [shortScalar, if_false, spec_ok]
    simp [scopeValueValid, byteList]
    omega

theorem scope_value_short {value : List Nat}
    (valid : Auths.Product.RequestConstruction.scopeValueValid value = true) :
    value.length ≤ 64 := by
  simp only [Auths.Product.RequestConstruction.scopeValueValid, Bool.and_eq_true,
    decide_eq_true_eq] at valid
  exact valid.1.1.2

open Auths.Product.RequestConstruction in
@[step] theorem account_scope_header_spec (plan : construct.AccountScopePlan)
    (arguments : Slice construct.ArgumentValue)
    (nameFits : plan.«name».val.length < 4294967295) :
    construct.account_scope_header plan arguments ⦃ result =>
      resultOf headerOf result = scopeHeader (scopeOf plan) (argsOf arguments) ⦄ := by
  unfold construct.account_scope_header
  simp only [scopeHeader, scopeOf]
  split <;> rename_i outside
  · have outOfBounds : arguments.val.length ≤ plan.field.val := by scalar_tac
    rw [argsOf_getElem?, List.getElem?_eq_none outOfBounds]
    simp [resultOf, errorOf]
  · have inBounds : plan.field.val < arguments.val.length := by scalar_tac
    rw [argsOf_getElem?, List.getElem?_eq_getElem inBounds]
    step as ⟨argument, argumentEq⟩
    rw [← argumentEq]
    rcases argument with text | digits | flag
    · simp only [Option.map_some, argOf]
      step with scope_value_valid_spec as ⟨valid, validEq⟩
      simp only [deref_val] at validEq
      split <;> rename_i isValid
      · have modelValid : scopeValueValid (vecBytes text) = true := by
          simpa [vecBytes, isValid] using validEq.symm
        have short := scope_value_short modelValid
        have nameSpec := copy_bytes_spec (alloc.vec.Vec.deref plan.«name») (by simpa using nameFits)
        have valueSpec := copy_bytes_spec (alloc.vec.Vec.deref text)
          (by simp only [deref_val]; simp only [vecBytes, length_byteList] at short; omega)
        step with nameSpec as ⟨nameCopy, nameEq⟩
        step with valueSpec as ⟨valueCopy, valueEq⟩
        simp only [deref_val] at nameEq valueEq
        have byteValid : scopeValueValid (byteList text.val) = true := modelValid
        simp [resultOf, headerOf, byteValid, vecBytes, nameEq, valueEq]
      · have modelInvalid : scopeValueValid (vecBytes text) = false := by
          simpa [vecBytes, isValid] using validEq.symm
        simp [resultOf, errorOf, modelInvalid]
    · simp [argOf, resultOf, errorOf]
    · simp [argOf, resultOf, errorOf]

/-- The header plan fits: every version header and the scope name are shorter
than the capacity bound, and so is the header count. -/
def HeaderPlanFits (plan : construct.HeaderPlan) : Prop :=
  plan.versions.val.length + 1 < 4294967295 ∧ HeadersFit plan.versions.val ∧
    ∀ scope, plan.account_scope = some scope → scope.«name».val.length < 4294967295

open Auths.Product.RequestConstruction in
@[step] theorem action_headers_spec (plan : construct.HeaderPlan)
    (arguments : Slice construct.ArgumentValue) (fits : HeaderPlanFits plan) :
    construct.action_headers plan arguments ⦃ result =>
      resultOf (fun headers : alloc.vec.Vec construct.Header => headers.val.map headerOf) result =
        actionHeaders (headerPlanOf plan) (argsOf arguments) ⦄ := by
  obtain ⟨countFits, headersFit, scopeFits⟩ := fits
  unfold construct.action_headers
  step with append_version_headers_spec as ⟨out, outEq⟩
  · simp
    omega
  · simpa using headersFit
  simp only [deref_val, List.map_nil, List.nil_append] at outEq
  simp only [actionHeaders, headerPlanOf]
  rcases scopeEquation : plan.account_scope with _ | scope
  · simp [resultOf, outEq]
  · simp only [Option.map_some]
    have nameFits := scopeFits scope scopeEquation
    step with account_scope_header_spec as ⟨header, headerEq⟩
    rcases header with header | error
    · simp only [resultOf] at headerEq
      rw [← headerEq]
      have outLength : out.val.length = plan.versions.val.length := by
        have := congrArg List.length outEq
        simpa using this
      have pushFits : out.val.length < Usize.max := by
        apply lt_usize_max
        omega
      step as ⟨next, nextEq⟩
      simp [resultOf, nextEq, outEq]
    · simp only [resultOf] at headerEq
      rw [← headerEq]
      simp [resultOf]

/-! ## Construction: requests -/

section Requests
open Auths.Product.RequestConstruction

/-- Every buffer a write builds is shorter than `u32::MAX` bytes: the origin
and encoded path, the rendered body, every header, and the idempotency key. -/
def WriteFits (plan : construct.WritePlan) (arguments : Slice construct.ArgumentValue)
    (echo key : Slice Std.U8) : Prop :=
  plan.origin.val.length +
      (renderPath (argsOf arguments) (plan.path.val.map segmentOf)).length < 4294967295 ∧
    (renderBody (argsOf arguments) (byteList echo.val) (bodyPlanOf plan.body)).length <
      4294967295 ∧
    HeaderPlanFits plan.headers ∧
    (∀ headerName, plan.idempotency_header = some headerName →
      headerName.val.length < 4294967295) ∧
    key.val.length < 4294967295

/-- Every buffer an action read builds is shorter than `u32::MAX` bytes. -/
def ReadFits (plan : construct.ActionReadPlan) (arguments : Slice construct.ArgumentValue) :
    Prop :=
  plan.origin.val.length +
      (renderPath (argsOf arguments) (plan.path.val.map segmentOf)).length < 4294967295 ∧
    HeaderPlanFits plan.headers

/-- Every buffer a credential read builds is shorter than `u32::MAX` bytes. -/
def CredentialFits (plan : construct.CredentialReadPlan) : Prop :=
  plan.origin.val.length +
      ((plan.path.val.map vecBytes).flatMap (fun segment => 47 :: segment)).length < 4294967295 ∧
    plan.versions.val.length < 4294967295 ∧ HeadersFit plan.versions.val

end Requests

open Auths.Product.RequestConstruction in
/-- The translated write construction returns exactly the model's request or
refusal. -/
theorem translated_construct_write_refines_model (plan : construct.WritePlan)
    (arguments : Slice construct.ArgumentValue) (echo key : Slice Std.U8)
    (fits : WriteFits plan arguments echo key) :
    construct.construct_write plan arguments echo key ⦃ result =>
      resultOf requestOf result =
        constructWrite (writePlanOf plan) (argsOf arguments) (byteList echo.val)
          (byteList key.val) ⦄ := by
  obtain ⟨urlFits, bodyFits, headerFits, nameFits, keyFits⟩ := fits
  unfold construct.construct_write
  step with build_url_spec as ⟨urlResult, urlEq⟩
  all_goals try (simpa using urlFits)
  simp only [deref_val] at urlEq
  simp only [constructWrite, writePlanOf]
  rcases urlResult with url | error
  · have urlModel : buildUrl (vecBytes plan.origin) (plan.path.val.map segmentOf)
        (argsOf arguments) = .ok (vecBytes url) := urlEq.symm
    rw [urlModel]
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with build_body_spec as ⟨bodyResult, bodyEq⟩
    rcases bodyResult with body | error
    · simp only [resultOf] at bodyEq
      rw [← bodyEq]
      simp only [bind_tc_ok]
      step with action_headers_spec as ⟨headerResult, headerEq⟩
      rcases headerResult with headers | error
      · simp only [resultOf] at headerEq
        rw [← headerEq]
        simp only [bind_tc_ok]
        rcases idempotency : plan.idempotency_header with _ | headerName
        · simp [resultOf, requestOf, writeHeaders]
        · have nameSpec := copy_bytes_spec (alloc.vec.Vec.deref headerName)
            (by simpa using nameFits headerName idempotency)
          step with nameSpec as ⟨nameCopy, nameCopyEq⟩
          step with copy_bytes_spec as ⟨keyCopy, keyCopyEq⟩
          have headersLength : headers.val.length ≤ plan.headers.versions.val.length + 1 := by
            have shape := Auths.Product.RequestConstruction.actionHeaders_ok headerEq.symm
            have mapped : (headers.val.map headerOf).length = headers.val.length :=
              List.length_map _
            rcases scopeEquation : plan.headers.account_scope with _ | scope
            · simp only [headerPlanOf, scopeEquation, Option.map_none] at shape
              rw [← mapped, shape]
              simp
            · simp only [headerPlanOf, scopeEquation, Option.map_some] at shape
              obtain ⟨value, _, _, equal⟩ := shape
              rw [← mapped, equal]
              simp
          have pushFits : headers.val.length < Usize.max := by
            apply lt_usize_max
            have := headerFits.1
            omega
          step as ⟨next, nextEq⟩
          simp only [deref_val] at nameCopyEq keyCopyEq
          simp [resultOf, requestOf, writeHeaders, nextEq, headerOf, vecBytes, nameCopyEq,
            keyCopyEq]
      · simp only [resultOf] at headerEq
        rw [← headerEq]
        simp [
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          resultOf]
    · simp only [resultOf] at bodyEq
      rw [← bodyEq]
      simp [
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        resultOf]
  · have urlModel : buildUrl (vecBytes plan.origin) (plan.path.val.map segmentOf)
        (argsOf arguments) = .error (errorOf error) := urlEq.symm
    rw [urlModel]
    simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      resultOf]

open Auths.Product.RequestConstruction in
/-- The translated action-read construction returns exactly the model's
request or refusal. -/
theorem translated_construct_action_read_refines_model (plan : construct.ActionReadPlan)
    (arguments : Slice construct.ArgumentValue) (fits : ReadFits plan arguments) :
    construct.construct_action_read plan arguments ⦃ result =>
      resultOf requestOf result = constructActionRead (readPlanOf plan) (argsOf arguments) ⦄ := by
  obtain ⟨urlFits, headerFits⟩ := fits
  unfold construct.construct_action_read
  step with build_url_spec as ⟨urlResult, urlEq⟩
  all_goals try (simpa using urlFits)
  simp only [deref_val] at urlEq
  simp only [constructActionRead, readPlanOf]
  rcases urlResult with url | error
  · have urlModel : buildUrl (vecBytes plan.origin) (plan.path.val.map segmentOf)
        (argsOf arguments) = .ok (vecBytes url) := urlEq.symm
    rw [urlModel]
    simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
    step with action_headers_spec as ⟨headerResult, headerEq⟩
    rcases headerResult with headers | error
    · simp only [resultOf] at headerEq
      rw [← headerEq]
      simp [resultOf, requestOf, methodOf, vecBytes, byteList]
    · simp only [resultOf] at headerEq
      rw [← headerEq]
      simp [core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        resultOf]
  · have urlModel : buildUrl (vecBytes plan.origin) (plan.path.val.map segmentOf)
        (argsOf arguments) = .error (errorOf error) := urlEq.symm
    rw [urlModel]
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      resultOf]

open Auths.Product.RequestConstruction in
/-- The translated credential-read construction returns exactly the model's
request: a function of the plan alone. -/
theorem translated_construct_credential_read_refines_model
    (plan : construct.CredentialReadPlan) (fits : CredentialFits plan) :
    construct.construct_credential_read plan ⦃ request =>
      requestOf request = constructCredentialRead (credentialPlanOf plan) ⦄ := by
  obtain ⟨urlFits, countFits, headersFit⟩ := fits
  unfold construct.construct_credential_read
  step with fixed_url_spec as ⟨url, urlEq⟩
  all_goals try (simpa using urlFits)
  step with append_version_headers_spec as ⟨headers, headersEq⟩
  all_goals try (simp; omega)
  simp only [deref_val] at urlEq headersEq
  simp only [requestOf, constructCredentialRead, credentialPlanOf, fixedUrl, vecBytes, urlEq]
  simp only [List.map_nil, List.nil_append] at headersEq
  simp [headersEq, byteList]

/-! ## Relative ceiling -/

theorem basis_points_per_whole_val : ratio.BASIS_POINTS_PER_WHOLE.val = 10000 := by
  unfold ratio.BASIS_POINTS_PER_WHOLE
  rfl

/-- The translated relative-ceiling check returns exactly the model's
comparison; neither `u128` product can overflow. -/
theorem translated_relative_ceiling_admits_refines_model (argument basis : Std.U64)
    (basisPoints : Std.U16) :
    ratio.relative_ceiling_admits argument basis basisPoints ⦃ admitted =>
      admitted = Auths.Product.RelativeCeiling.admits argument.val basis.val basisPoints.val ⦄ := by
  unfold ratio.relative_ceiling_admits
  simp only [lift, bind_tc_ok]
  have scaledArgument := UScalar.mul_spec (x := UScalar.cast .U128 argument)
    (y := ratio.BASIS_POINTS_PER_WHOLE) (by
      simp only [U64.cast_U128_val_eq, basis_points_per_whole_val]
      scalar_tac)
  obtain ⟨product, productEq, productVal⟩ := spec_imp_exists scaledArgument
  rw [productEq, bind_tc_ok]
  have scaledBasis := UScalar.mul_spec (x := UScalar.cast .U128 basis)
    (y := UScalar.cast .U128 basisPoints) (by
      simp only [U64.cast_U128_val_eq, U16.cast_U128_val_eq]
      have basisSmall : basis.val < 2 ^ 64 := by scalar_tac
      have pointsSmall : basisPoints.val < 2 ^ 16 := by scalar_tac
      have : basis.val * basisPoints.val < 2 ^ 64 * 2 ^ 16 :=
        Nat.mul_lt_mul'' basisSmall pointsSmall
      scalar_tac)
  obtain ⟨other, otherEq, otherVal⟩ := spec_imp_exists scaledBasis
  rw [otherEq, bind_tc_ok, spec_ok]
  simp only [U64.cast_U128_val_eq, U16.cast_U128_val_eq, basis_points_per_whole_val]
    at productVal otherVal
  simp only [Auths.Product.RelativeCeiling.admits, Auths.Product.RelativeCeiling.basisPointsPerWhole,
    UScalar.le_equiv, productVal, otherVal, decide_eq_decide]

theorem relative_ceiling_admits_eq (argument basis : Std.U64) (basisPoints : Std.U16) :
    ratio.relative_ceiling_admits argument basis basisPoints =
      ok (Auths.Product.RelativeCeiling.admits argument.val basis.val basisPoints.val) := by
  obtain ⟨result, resultEq, resultVal⟩ :=
    spec_imp_exists (translated_relative_ceiling_admits_refines_model argument basis basisPoints)
  rw [resultEq, resultVal]

/-- The translated basis returns exactly the model's basis. -/
theorem translated_relative_basis_refines_model (value : Std.U64) (subtrahend : Option Std.U64) :
    ratio.relative_basis value subtrahend ⦃ basis =>
      basis.map (·.val) =
        Auths.Product.RelativeCeiling.relativeBasis value.val (subtrahend.map (·.val)) ⦄ := by
  match subtrahend with
  | .none => simp [ratio.relative_basis, Auths.Product.RelativeCeiling.relativeBasis]
  | .some second =>
      simp only [ratio.relative_basis, Option.map_some,
        Auths.Product.RelativeCeiling.relativeBasis]
      split
      · rename_i within
        have within' : second.val ≤ value.val := by simpa using within
        obtain ⟨difference, differenceEq, differenceVal⟩ :=
          spec_imp_exists (UScalar.sub_spec (x := value) (y := second) within')
        rw [differenceEq, bind_tc_ok, spec_ok]
        simp [within', differenceVal.1]
      · rename_i beyond
        have beyond' : ¬ second.val ≤ value.val := by simpa using beyond
        simp [beyond']

/-! ## Admission order -/

section Order
open Auths.Product.SubmitOrder

def modeOf : order.Mode → Mode
  | .Entry => .entry
  | .ReadBack => .readBack
  | .Reobserve => .reobserve

def planOf (plan : order.SubmitPlan) : Plan where
  accountScope := plan.account_scope
  accountRead := plan.account_read
  deniedReads := plan.denied_reads.val
  preEntry := plan.pre_entry
  relativeCeiling := plan.relative_ceiling
  basisPoints := plan.basis_points.val

def phaseOf : order.Phase → Phase
  | .Start => .start
  | .Clock => .clock
  | .Verify => .verify
  | .Admit => .admit
  | .Scope => .scope
  | .Prepare => .prepare
  | .Claim => .claim
  | .Resume => .resume
  | .Reload mode => .reload (modeOf mode)
  | .Lease mode => .lease (modeOf mode)
  | .Prefix mode => .prefixGuard (modeOf mode)
  | .Account mode => .account (modeOf mode)
  | .Denied mode index => .denied (modeOf mode) index.val
  | .PreEntry => .preEntry
  | .Ceiling => .ceiling
  | .Checkpoint => .checkpoint
  | .EntryReload => .entryReload
  | .Deadline => .deadline
  | .Send => .send
  | .RecordResponse => .recordResponse
  | .RecordUnknown => .recordUnknown
  | .RecordNotEntered => .recordNotEntered
  | .ReadBack mode => .readBack (modeOf mode)
  | .Done => .done

def stateOf (state : order.SubmitState) : State where
  plan := planOf state.plan
  phase := phaseOf state.phase
  argument := state.argument.val

def verificationOf : order.Verification → Verification
  | .Refused => .refused
  | .Authorized argument => .authorized argument.val

def claimOf : order.ClaimResult → ClaimResult
  | .Inserted => .inserted
  | .Refused => .refused
  | .Replay => .replay
  | .Unavailable => .unavailable

def accountOf : order.AccountResult → AccountResult
  | .Equal => .equal
  | .Mismatch => .mismatch
  | .Unavailable => .unavailable

def deniedOf : order.DeniedResult → DeniedResult
  | .Refused => .refused
  | .Answered => .answered
  | .Unavailable => .unavailable

def preEntryOf : order.PreEntryResult → PreEntryResult
  | .Satisfied => .satisfied
  | .ConditionFalse => .conditionFalse
  | .Unavailable => .unavailable

def ceilingOf : order.CeilingRead → CeilingRead
  | .Unavailable => .unavailable
  | .Read basis bindsEqual => .read basis.val bindsEqual

def writeOf : order.WriteResult → WriteResult
  | .NotEntered => .notEntered
  | .Unknown => .unknown
  | .Response => .response

def responseOf : order.ResponseRecord → ResponseRecord
  | .Failed => .failed
  | .Recorded observable => .recorded observable

def eventOf : order.SubmitEvent → Event
  | .Start => .start
  | .Clock read => .clock read
  | .Verification result => .verification (verificationOf result)
  | .Admission admitted => .admission admitted
  | .Scope bound => .scope bound
  | .Preparation prepared => .preparation prepared
  | .Claim result => .claim (claimOf result)
  | .Resume resumable => .resume resumable
  | .Reload unchanged => .reload unchanged
  | .Lease leased => .lease leased
  | .Prefix allowed => .prefixGuard allowed
  | .Account result => .account (accountOf result)
  | .Denied result => .denied (deniedOf result)
  | .PreEntry result => .preEntry (preEntryOf result)
  | .Ceiling read => .ceiling (ceilingOf read)
  | .Recorded stored => .recorded stored
  | .Deadline within => .deadline within
  | .Write result => .write (writeOf result)
  | .Response record => .response (responseOf record)

def refusalCodeOf : order.Refusal → Refusal
  | .ConnectionChanged => .connectionChanged
  | .CredentialUnavailable => .credentialUnavailable
  | .ModeGuard => .modeGuard
  | .AccountMismatch => .accountMismatch
  | .AccountUnavailable => .accountUnavailable
  | .CapabilityExcess => .capabilityExcess
  | .CapabilityUnavailable => .capabilityUnavailable
  | .PreEntryConditionFalse => .preEntryConditionFalse
  | .PreEntryUnavailable => .preEntryUnavailable
  | .CeilingAbove => .ceilingAbove
  | .CeilingBindingMismatch => .ceilingBindingMismatch
  | .CeilingUnavailable => .ceilingUnavailable
  | .EntryDeadline => .entryDeadline
  | .TransportNotEntered => .transportNotEntered

def stopOf : order.Stop → Stop
  | .Refused => .refused
  | .StoreUnavailable => .storeUnavailable
  | .ClaimRefused => .claimRefused
  | .NotEntered => .notEntered
  | .Unknown => .unknown
  | .Response => .response
  | .Observed => .observed
  | .ReplayRefused => .replayRefused
  | .Halted => .halted

def actionOf : order.SubmitAction → Action
  | .ReadClock => .readClock
  | .Verify => .verify
  | .Admit => .admit
  | .BindScope => .bindScope
  | .Prepare => .prepare
  | .Claim => .claim
  | .Resume => .resume
  | .Reload mode => .reload (modeOf mode)
  | .Lease mode => .lease (modeOf mode)
  | .CheckPrefix mode => .checkPrefix (modeOf mode)
  | .ReadAccount mode => .readAccount (modeOf mode)
  | .DeniedRead mode index => .deniedRead (modeOf mode) index.val
  | .PreEntryRead => .preEntryRead
  | .CeilingRead => .ceilingRead
  | .RecordCheckpoint => .recordCheckpoint
  | .ReloadBeforeEntry => .reloadBeforeEntry
  | .CheckDeadline => .checkDeadline
  | .Send => .send
  | .RecordResponse => .recordResponse
  | .RecordUnknown => .recordUnknown
  | .RecordNotEntered refusal => .recordNotEntered (refusalCodeOf refusal)
  | .ReadBack mode => .readBack (modeOf mode)
  | .Stop reason => .stop (stopOf reason)

def decisionOf (decision : order.SubmitDecision) : Decision where
  state := stateOf decision.state
  action := actionOf decision.action

/-- The translated initial state is the model's `start` state of the
abstracted plan. -/
theorem translated_start_refines_model (plan : order.SubmitPlan) :
    ∃ state, order.start plan = ok state ∧ stateOf state = start (planOf plan) := by
  refine ⟨{ plan, phase := .Start, argument := 0#u64 }, rfl, ?_⟩
  simp [stateOf, start, phaseOf]

/-- The next denied index of a refused read never overflows `u8`: it is at
most the declared count. -/
theorem after_denied_refused_spec (state : order.SubmitState) (mode : order.Mode) (index : Std.U8) :
    order.after_denied state mode index .Refused ⦃ decision =>
      decisionOf decision = afterDenied (stateOf state) (modeOf mode) index.val .refused ⦄ := by
  unfold order.after_denied
  simp only [afterDenied, stateOf, planOf]
  split
  · rename_i below
    have below' : index.val < state.plan.denied_reads.val := by simpa using below
    have fits : index.val + (1#u8 : Std.U8).val ≤ UScalar.max .U8 := by scalar_tac
    obtain ⟨next, nextEq, nextVal⟩ := spec_imp_exists (UScalar.add_spec (x := index) (y := 1#u8) fits)
    rw [nextEq, bind_tc_ok]
    simp only [below', if_true]
    have nextVal' : next.val = index.val + 1 := by simpa using nextVal
    unfold order.denied_from deniedFrom
    split
    · rename_i more
      have more' : next.val < state.plan.denied_reads.val := by simpa using more
      simp [nextVal', order.go, go, decisionOf, stateOf, planOf, phaseOf, actionOf]
      omega
    · rename_i done
      have done' : ¬ next.val < state.plan.denied_reads.val := by simpa using done
      rw [nextVal'] at done'
      simp only [done', if_false]
      rcases mode with _ | _ | _
      all_goals
        simp [order.after_credentials, order.pre_entry_from, order.ceiling_from,
          order.after_reads, order.go, afterCredentials, preEntryFrom, ceilingFrom, afterReads, go,
          decisionOf, stateOf, planOf, phaseOf, actionOf, modeOf]
        repeat' split
        all_goals simp_all
  · rename_i above
    have above' : ¬ index.val < state.plan.denied_reads.val := by simpa using above
    simp [above', order.halt, order.stop, order.go, halt, stop, go, decisionOf, stateOf, planOf,
      phaseOf, actionOf, stopOf]


@[simp] theorem stateOf_phase (state : order.SubmitState) :
    (stateOf state).phase = phaseOf state.phase := rfl

@[simp] theorem stateOf_plan (state : order.SubmitState) :
    (stateOf state).plan = planOf state.plan := rfl

@[simp] theorem stateOf_argument (state : order.SubmitState) :
    (stateOf state).argument = state.argument.val := rfl

theorem after_denied_spec (state : order.SubmitState) (mode : order.Mode) (index : Std.U8)
    (result : order.DeniedResult) :
    order.after_denied state mode index result ⦃ decision =>
      decisionOf decision =
        afterDenied (stateOf state) (modeOf mode) index.val (deniedOf result) ⦄ := by
  match result with
  | .Refused => exact after_denied_refused_spec state mode index
  | .Answered | .Unavailable =>
      rcases mode with _ | _ | _ <;>
        simp [order.after_denied, order.lease_failed, order.not_entered, order.stop, order.go,
          afterDenied, leaseFailed, notEntered, stop, go, decisionOf, stateOf, phaseOf, actionOf,
          refusalCodeOf, stopOf, deniedOf, modeOf]

theorem after_ceiling_spec (state : order.SubmitState) (read : order.CeilingRead) :
    order.after_ceiling state read ⦃ decision =>
      decisionOf decision = afterCeiling (stateOf state) (ceilingOf read) ⦄ := by
  match read with
  | .Unavailable =>
      simp [order.after_ceiling, order.not_entered, order.go, afterCeiling, notEntered, go,
        decisionOf, stateOf, phaseOf, actionOf, refusalCodeOf, ceilingOf]
  | .Read basis bindsEqual =>
      simp only [order.after_ceiling, afterCeiling, ceilingOf, relative_ceiling_admits_eq,
        bind_tc_ok]
      rcases bindsEqual with _ | _
      all_goals
        simp [order.not_entered, order.after_reads, order.go, notEntered, afterReads, go,
          decisionOf, stateOf, planOf, phaseOf, actionOf, refusalCodeOf]
        repeat' split
        all_goals simp_all

/-- The translated step machine returns exactly the model's next state and
action for every state and event. -/
theorem translated_next_step_refines_model (state : order.SubmitState)
    (event : order.SubmitEvent) :
    order.next_step state event ⦃ decision =>
      decisionOf decision = nextStep (stateOf state) (eventOf event) ⦄ := by
  rcases state with ⟨plan, phase, argument⟩
  rcases phase with _ | _ | _ | _ | _ | _ | _ | _ | (_ | _ | _) | (_ | _ | _) | (_ | _ | _) |
      (_ | _ | _) | ⟨(_ | _ | _), _⟩ | _ | _ | _ | _ | _ | _ | _ | _ | _ | (_ | _ | _) | _ <;>
    rcases event with _ | _ | (_ | _) | _ | _ | _ | (_ | _ | _ | _) | _ | _ | _ | _ |
      (_ | _ | _) | _ | (_ | _ | _) | _ | _ | _ | (_ | _ | _) | (_ | _) <;>
    simp only [order.next_step, order.pre_claim_step, order.lease_step, order.entry_step,
      nextStep, preClaimStep, leaseStep, entryStep, stateOf_phase, phaseOf, eventOf, modeOf] <;>
    first
    | exact after_denied_spec _ _ _ _
    | exact after_ceiling_spec _ _
    | skip
  all_goals
    simp [order.go, order.stop, order.halt, order.not_entered, order.lease_failed,
      order.after_reads, order.ceiling_from, order.pre_entry_from, order.after_credentials,
      order.denied_from, order.after_prefix, order.after_admission, order.pre_claim,
      order.after_claim, order.after_account, order.after_pre_entry, order.after_write,
      order.after_response, order.after_read_back, go, stop, halt, notEntered, leaseFailed,
      afterReads, ceilingFrom, preEntryFrom, afterCredentials, deniedFrom, afterPrefix,
      afterAdmission, preClaim, afterClaim, afterAccount, afterPreEntry, afterWrite,
      afterResponse, afterReadBack, decisionOf, stateOf, planOf, phaseOf, actionOf, refusalCodeOf,
      stopOf, modeOf, verificationOf, claimOf, accountOf, preEntryOf, writeOf,
      responseOf] <;>
    (repeat' split) <;> simp_all

end Order

/-! ## Attempt-record transitions -/

section Transition

theorem byteList_inj {left right : List Std.U8} : byteList left = byteList right ↔ left = right := by
  constructor
  · intro equal
    induction left generalizing right with
    | nil => cases right <;> simp_all [byteList]
    | cons head tail induction =>
        cases right with
        | nil => simp [byteList] at equal
        | cons head' tail' =>
            simp only [byteList, List.map_cons, List.cons.injEq] at equal
            rw [(UScalar.eq_equiv _ _).mpr equal.1, induction equal.2]
  · intro equal
    rw [equal]

def stageOf : transition.Stage → Auths.Product.Recovery.Stage
  | .Attempting => .attempting
  | .NotEntered => .notEntered
  | .Unknown => .unknown
  | .ResponseRecorded => .responseRecorded
  | .Observed => .observed
  | .ObservedByProvider => .observedByProvider

def readingOf : transition.Reading → Auths.Product.Recovery.Reading
  | .None => .none
  | .Match => .matched
  | .Mismatch => .mismatched
  | .EchoMismatch => .echoMismatch

def storedLinkOf : transition.Link → Auths.Product.Recovery.Link
  | .None => .none
  | .Verified => .verified
  | .AfterResponse => .afterResponse

def viewOf (view : transition.AttemptView) : Auths.Product.Recovery.AttemptView where
  fixed := byteList view.fixed.val
  stage := stageOf view.stage
  refusal := view.refusal
  preEntry := byteList view.pre_entry.val
  response := byteList view.response.val
  locator := byteList view.locator.val
  reading := readingOf view.reading
  evidence := view.evidence
  observation := view.observation
  link := storedLinkOf view.link

theorem absent_eq (bytes : Slice Std.U8) :
    transition.absent bytes = ok (byteList bytes.val).isEmpty := by
  have zero : (Slice.len bytes = 0#usize) ↔ bytes.val = [] := by
    rw [UScalar.eq_equiv, Slice.len_val]
    simp
  simp only [transition.absent]
  congr 1
  cases equal : bytes.val with
  | nil => simp [byteList, zero.mpr equal]
  | cons head tail =>
      have nonzero : ¬ (Slice.len bytes = 0#usize) := by
        rw [zero, equal]
        simp
      simp [byteList, nonzero]

theorem same_bytes_from_spec (left right : Slice Std.U8)
    (sameLength : left.val.length = right.val.length) :
    transition.same_bytes_from left right ⦃ result => result = decide (left.val = right.val) ⦄ := by
  unfold transition.same_bytes_from transition.same_bytes_from_loop
  apply loop.spec_decr_nat
    (measure := fun index => left.val.length - index.val)
    (inv := fun index =>
      index.val ≤ left.val.length ∧ left.val.take index.val = right.val.take index.val)
  · rintro index ⟨bound, prefixEq⟩
    unfold transition.same_bytes_from_loop.body
    dsimp only
    split <;> rename_i withinLeft
    · have inLeft : index.val < left.val.length := by simpa using withinLeft
      have inRight : index.val < right.val.length := by omega
      have withinRight : index < Slice.len right := by
        simp only [UScalar.lt_equiv, Slice.len_val]
        exact inRight
      simp only [withinRight, if_true]
      step as ⟨leftByte, leftEq⟩
      step as ⟨rightByte, rightEq⟩
      split <;> rename_i differs
      · simp only [spec_ok]
        have unequal : leftByte ≠ rightByte := by simpa using differs
        symm
        rw [decide_eq_false_iff_not]
        intro same
        apply unequal
        rw [leftEq, rightEq]
        simp only [same]
      · have equalBytes : leftByte = rightByte :=
          (UScalar.eq_equiv _ _).mpr (by simpa using differs)
        step as ⟨next, nextEq⟩
        refine ⟨by omega, ?_, by omega⟩
        rw [nextEq, List.take_succ_eq_append_getElem inLeft,
          List.take_succ_eq_append_getElem inRight, prefixEq]
        congr 2
        rw [← leftEq, ← rightEq, equalBytes]
    · simp only [spec_ok]
      have atEnd : left.val.length ≤ index.val := by simpa using withinLeft
      have full : index.val = left.val.length := by omega
      rw [full, List.take_length, sameLength, List.take_length] at prefixEq
      simp [prefixEq]
  · exact ⟨by simp, by simp⟩

theorem same_bytes_eq (left right : Slice Std.U8) :
    transition.same_bytes left right = ok (decide (byteList left.val = byteList right.val)) := by
  unfold transition.same_bytes
  dsimp only
  split <;> rename_i lengths
  · have sameLength : left.val.length = right.val.length := by
      have := congrArg UScalar.val lengths
      simpa using this
    obtain ⟨result, resultEq, resultVal⟩ :=
      spec_imp_exists (same_bytes_from_spec left right sameLength)
    rw [resultEq, resultVal]
    simp [byteList_inj]
  · have differ : left.val.length ≠ right.val.length := by
      intro same
      apply lengths
      rw [UScalar.eq_equiv]
      simpa using same
    congr 1
    symm
    rw [decide_eq_false_iff_not]
    intro same
    apply differ
    have := congrArg List.length same
    simpa [byteList] using this

theorem consistent_eq (view : transition.AttemptView) :
    transition.consistent view = ok (Auths.Product.Recovery.consistent (viewOf view)) := by
  rcases view with ⟨fixed, stage, refusal, preEntry, response, locator, reading, evidence,
    observation, link⟩
  simp only [transition.consistent, absent_eq, bind_tc_ok, alloc.vec.Vec.deref,
    Auths.Product.Recovery.consistent, viewOf]
  rcases stage with _ | _ | _ | _ | _ | _ <;> rcases reading with _ | _ | _ | _ <;>
    rcases link with _ | _ | _ <;>
    simp [transition.refusal_stage, transition.requires_response, transition.permits_response,
      transition.observed_stage, transition.provider_stage, transition.has_reading,
      transition.has_link, transition.resolves_unknown, stageOf, readingOf, storedLinkOf,
      Auths.Product.Recovery.refusalStage, Auths.Product.Recovery.requiresResponse,
      Auths.Product.Recovery.permitsResponse, Auths.Product.Recovery.observedStage,
      Auths.Product.Recovery.providerStage, Auths.Product.Recovery.hasReading,
      Auths.Product.Recovery.hasLink, Auths.Product.Recovery.resolvesUnknown] <;>
    (repeat' split) <;> simp_all

/-- The translated transition rule returns exactly the model's decision for
every pair of records. -/
theorem translated_valid_transition_refines_model (old new : transition.AttemptView) :
    transition.valid_transition old new ⦃ valid =>
      valid = Auths.Product.Recovery.validTransition (viewOf old) (viewOf new) ⦄ := by
  rcases old with ⟨fixed, stage, refusal, preEntry, response, locator, reading, evidence,
    observation, link⟩
  rcases new with ⟨fixed', stage', refusal', preEntry', response', locator', reading', evidence',
    observation', link'⟩
  simp only [transition.valid_transition, transition.plan_kept, transition.checkpoint_valid,
    transition.pre_entry_kept, transition.response_kept, same_bytes_eq, absent_eq,
    consistent_eq, bind_tc_ok, alloc.vec.Vec.deref, Auths.Product.Recovery.validTransition,
    Auths.Product.Recovery.planKept, Auths.Product.Recovery.checkpointValid,
    Auths.Product.Recovery.preEntryKept, Auths.Product.Recovery.responseKept, viewOf]
  rcases stage with _ | _ | _ | _ | _ | _ <;> rcases stage' with _ | _ | _ | _ | _ | _ <;>
    rcases link with _ | _ | _ <;> rcases link' with _ | _ | _ <;>
    simp [transition.stage_transition_allowed, transition.adds_pre_entry,
      transition.adds_response, transition.link_equal, transition.resolves_unknown, stageOf,
      storedLinkOf, Auths.Product.Recovery.stageTransitionAllowed,
      Auths.Product.Recovery.addsPreEntry, Auths.Product.Recovery.addsResponse,
      Auths.Product.Recovery.resolvesUnknown, List.isEmpty_iff] <;>
    (repeat' split) <;> simp_all <;>
    (repeat' split) <;> simp_all

end Transition

end Auths.Product.Refinement.Gateway
