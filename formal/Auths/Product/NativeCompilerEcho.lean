import Auths.Product.NativeCompilerSchemaAtoms
import Auths.Product.NativeCompilerAstMeaning
import Auths.Product.EchoPointer

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeMemberError := AuthsNativeRecipe.auths_gateway_kernel.template_members.MemberError
abbrev NativeEcho := AuthsNativeRecipe.auths_gateway_kernel.template_ast.Echo
abbrev NativeEchoSource := AuthsNativeRecipe.recipe.source.EchoPlacement

def nativeMemberErrorMeaning : NativeMemberError → TemplateMembers.Error
  | .Members => .members
  | .EchoConflict => .echoConflict

def nativeTokenNames (tokens : NativeVec (NativeVec Std.U8)) : List (List Nat) := tokens.val.map bytes

def nativeTokenResult : core.result.Result (NativeVec (NativeVec Std.U8)) NativeMemberError →
    Except TemplateMembers.Error (List (List Nat))
  | .Ok tokens => .ok (nativeTokenNames tokens)
  | .Err error => .error (nativeMemberErrorMeaning error)

def nativeEchoMeaning : NativeEcho → TemplateAst.Echo
  | .Json tokens => .json (nativeTokenNames tokens)
  | .Form name => .form (bytes name)

def nativeEchoResult : core.result.Result NativeEcho AuthsNativeRecipe.recipe.GatewayRecipeError →
    Except AuthsNativeRecipe.recipe.GatewayRecipeError TemplateAst.Echo
  | .Ok echo => .ok (nativeEchoMeaning echo)
  | .Err error => .error error

def NativeEchoFits : NativeEchoSource → Prop
  | .JsonPointer pointer => TextFits pointer
  | .FormField name => TextFits name

def originalEcho : NativeEchoSource → Except AuthsNativeRecipe.recipe.GatewayRecipeError TemplateAst.Echo
  | .JsonPointer pointer =>
      ((EchoPointer.decode (textBytes pointer)).map TemplateAst.Echo.json).mapError (fun _ => .EchoConflict)
  | .FormField name => .ok (.form (textBytes name))

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

@[step] theorem native_echo_finish_exact (prefix : NativeVec (NativeVec Std.U8)) (token : NativeVec Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.finish_echo_token prefix token ⦃ actual =>
      nativeTokenResult actual = EchoPointer.finish (nativeTokenNames prefix) (bytes token) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.finish_echo_token
    AuthsNativeRecipe.auths_gateway_kernel.template_members.MAX_ECHO_POINTER_TOKENS
  by_cases full : 6 ≤ prefix.val.length
  · have nativeFull : AuthsNativeRecipe.alloc.vec.Vec.len prefix >= 6#usize := by scalar_tac
    simp [nativeFull, nativeTokenResult, nativeMemberErrorMeaning, EchoPointer.finish,
      nativeTokenNames, Nat.not_lt.mpr full]
  · have room : prefix.val.length < 6 := by omega
    have nativeRoom : ¬AuthsNativeRecipe.alloc.vec.Vec.len prefix >= 6#usize := by scalar_tac
    simp only [nativeRoom, ↓reduceIte]
    step with native_schema_token_exact (AuthsNativeRecipe.alloc.vec.Vec.deref token) 64#usize
      as ⟨valid, validMeaning⟩
    have tokenMeaning : valid = OperationIdentity.validToken (bytes token) 64 := by
      simpa only [schemaSliceBytes, bytes, native_deref_contents] using validMeaning
    cases valid with
    | false =>
        simp only [Bool.false_eq_true, ↓reduceIte, spec_ok, nativeTokenResult,
          nativeMemberErrorMeaning, EchoPointer.finish, nativeTokenNames, List.length_map,
          room, ← tokenMeaning, Bool.false_eq_true, and_false, ↓reduceIte]
    | true =>
        have capacity : prefix.val.length < Usize.max := by scalar_tac
        simp only [Bool.true_eq_true, ↓reduceIte]
        step with native_push_exact prefix token capacity as ⟨output, appended⟩
        simp only [spec_ok, nativeTokenResult, EchoPointer.finish, nativeTokenNames,
          List.length_map, room, ← tokenMeaning, and_true, ↓reduceIte, appended,
          List.map_append, List.map_singleton]

/- The private loop relation contains the complete unconsumed original suffix.
Its only bounds are the actual source cursor/token/count invariants; no chosen
tokenization, successful finish flag or truncating fuel is supplied. -/
private theorem native_echo_scan_suffix (pointer : Slice Std.U8)
    (prefix : NativeVec (NativeVec Std.U8)) (token : NativeVec Std.U8) (position : Std.Usize)
    (positionBound : position.val ≤ pointer.val.length)
    (tokenBound : token.val.length ≤ 64) (prefixBound : prefix.val.length ≤ 6) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.echo_pointer_tokens_loop
      pointer prefix token position ⦃ actual =>
      nativeTokenResult actual.1 = EchoPointer.scan (nativeTokenNames prefix) (bytes token)
        ((pointer.val.drop position.val).map (·.val)) ⦄ := by
  generalize remaining : pointer.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position prefix token with
  | h count ih =>
    unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.echo_pointer_tokens_loop
    by_cases finished : position.val = pointer.val.length
    · have nativeFinished : position = pointer.len := by scalar_tac
      simp only [nativeFinished, ↓reduceIte]
      step with native_echo_finish_exact prefix token as ⟨actual, exact⟩
      simpa only [spec_ok, finished, List.drop_length, List.map_nil, EchoPointer.scan] using exact
    · have inside : position.val < pointer.val.length := by omega
      have nativeUnfinished : position ≠ pointer.len := by scalar_tac
      simp only [nativeUnfinished, ↓reduceIte]
      step with Slice.index_usize_spec pointer position inside as ⟨byte, byteAt⟩
      have originalSuffix : (pointer.val.drop position.val).map (·.val) =
          byte.val :: (pointer.val.drop (position.val + 1)).map (·.val) := by
        simpa only [List.map_cons, byteAt] using
          congrArg (List.map (fun value : Std.U8 => value.val)) (List.drop_eq_getElem_cons inside)
      by_cases slash : byte = 47#u8
      · have delimiter : byte.val = 47 := by simpa using congrArg UScalar.val slash
        simp only [slash, ↓reduceIte, core.mem.replace]
        step with native_echo_finish_exact prefix token as ⟨committed, committedMeaning⟩
        cases committed with
        | Err error =>
            simp only [nativeTokenResult] at committedMeaning
            simp only [spec_ok, nativeTokenResult, originalSuffix, EchoPointer.scan,
              delimiter, ↓reduceIte, ← committedMeaning]
        | Ok committed =>
            have committedRun : EchoPointer.finish (nativeTokenNames prefix) (bytes token) =
                .ok (nativeTokenNames committed) := by
              simpa only [nativeTokenResult] using committedMeaning.symm
            have committedFacts := EchoPointer.finish_success _ _ _ committedRun
            have committedCount : committed.val.length ≤ 6 := by
              have length := congrArg List.length committedFacts.1
              simp only [nativeTokenNames, List.length_map, List.length_append, List.length_singleton] at length
              have before := committedFacts.2.1
              simp only [nativeTokenNames, List.length_map] at before
              omega
            step with native_vector_clone_exact
              (AuthsNativeRecipe.core.clone.CloneallocvecVec core.clone.CloneU8) committed
              (by
                intro value _
                exact native_vector_clone_result core.clone.CloneU8 value (by intro item _; rfl))
              as ⟨copied, sameCopy⟩
            step as ⟨next, nextValue⟩
            have nextBound : next.val ≤ pointer.val.length := by omega
            have nextCount : copied.val.length ≤ 6 := by simpa only [sameCopy] using committedCount
            have smaller : pointer.val.length - next.val < count := by omega
            apply spec_mono (ih _ smaller next copied (AuthsNativeRecipe.alloc.vec.Vec.new Std.U8)
              nextBound (by simp only [native_empty_contents, List.length_nil]; omega) nextCount rfl)
            intro actual exact
            simpa only [originalSuffix, EchoPointer.scan, delimiter, ↓reduceIte,
              committedRun, sameCopy, bytes, native_empty_contents, List.map_nil, nextValue] using exact
      · have different : byte.val ≠ 47 := by
          intro same
          exact slash (UScalar.eq_of_val_eq same)
        simp only [slash, Bool.false_eq_true, ↓reduceIte]
        by_cases full : 64 ≤ token.val.length
        · have nativeFull : AuthsNativeRecipe.alloc.vec.Vec.len token >= 64#usize := by scalar_tac
          have noRoom : ¬(bytes token).length < 64 := by
            simp only [bytes, List.length_map]
            omega
          simp only [nativeFull, ↓reduceIte, spec_ok, nativeTokenResult,
            nativeMemberErrorMeaning, originalSuffix, EchoPointer.scan, different, ↓reduceIte, noRoom]
        · have room : token.val.length < 64 := by omega
          have nativeRoom : ¬AuthsNativeRecipe.alloc.vec.Vec.len token >= 64#usize := by scalar_tac
          have capacity : token.val.length < Usize.max := by scalar_tac
          simp only [nativeRoom, ↓reduceIte]
          step with native_push_exact token byte capacity as ⟨updated, appended⟩
          have updatedBound : updated.val.length ≤ 64 := by
            simp only [appended, List.length_append, List.length_singleton]
            omega
          step as ⟨next, nextValue⟩
          have nextBound : next.val ≤ pointer.val.length := by omega
          have smaller : pointer.val.length - next.val < count := by omega
          apply spec_mono (ih _ smaller next prefix updated nextBound updatedBound prefixBound rfl)
          intro actual exact
          have tokenRoom : (bytes token).length < 64 := by simpa only [bytes, List.length_map] using room
          simpa only [originalSuffix, EchoPointer.scan, different, ↓reduceIte, tokenRoom,
            bytes, appended, List.map_append, List.map_singleton, nextValue] using exact

@[step] theorem native_echo_pointer_exact (pointer : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.echo_pointer_tokens pointer ⦃ actual =>
      nativeTokenResult actual = EchoPointer.decode (schemaSliceBytes pointer) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_members.echo_pointer_tokens
    AuthsNativeRecipe.auths_gateway_kernel.template_members.MAX_ECHO_POINTER_BYTES
  by_cases empty : pointer.val = []
  · simp [empty, core.slice.Slice.is_empty, EchoPointer.decode, schemaSliceBytes,
      nativeTokenResult, nativeMemberErrorMeaning]
  · simp only [core.slice.Slice.is_empty, List.isEmpty_eq_false.mpr empty, bind_tc_ok,
      Bool.false_eq_true, ↓reduceIte]
    by_cases large : 128 < pointer.val.length
    · have nativeLarge : pointer.len > 128#usize := by scalar_tac
      have refused : EchoPointer.decode (schemaSliceBytes pointer) = .error .echoConflict := by
        cases original : pointer.val with
        | nil => simp [original, schemaSliceBytes, EchoPointer.decode]
        | cons first rest =>
            by_cases slash : first.val = 47 <;>
              simp [schemaSliceBytes, original, EchoPointer.decode, slash, large]
      simp [nativeLarge, refused, nativeTokenResult, nativeMemberErrorMeaning]
    · have bounded : pointer.val.length ≤ 128 := by omega
      have nativeBound : ¬pointer.len > 128#usize := by scalar_tac
      simp only [nativeBound, ↓reduceIte]
      have inside : 0 < pointer.val.length := List.length_pos.mpr empty
      obtain ⟨originalFirst, originalRest, original⟩ := List.exists_cons_of_ne_nil empty
      step with Slice.index_usize_spec pointer 0#usize inside as ⟨first, firstAt⟩
      have firstSame : first = originalFirst := by simpa only [original] using firstAt
      by_cases slash : first = 47#u8
      · have delimiter : originalFirst.val = 47 := by
          simpa only [firstSame] using congrArg UScalar.val slash
        simp only [slash, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
        step with native_echo_scan_suffix pointer
          (AuthsNativeRecipe.alloc.vec.Vec.new (NativeVec Std.U8))
          (AuthsNativeRecipe.alloc.vec.Vec.new Std.U8) 1#usize
          (by omega) (by simp only [native_empty_contents, List.length_nil]; omega)
          (by simp only [native_empty_contents, List.length_nil]; omega) as ⟨actual, exact⟩
        have sourceBound : (47 :: originalRest.map (·.val)).length ≤ 128 := by
          simpa only [original, List.length_cons, List.length_map] using bounded
        cases control : actual.2 <;>
          simpa only [control, bind_tc_ok, spec_ok, nativeTokenNames, bytes,
            native_empty_contents, List.map_nil, schemaSliceBytes, original, List.map_cons,
            delimiter, List.drop_succ_cons, List.drop_zero, EchoPointer.decode, sourceBound,
            ↓reduceIte] using exact
      · have different : originalFirst.val ≠ 47 := by
          intro same
          apply slash
          exact UScalar.eq_of_val_eq (by simpa only [firstSame] using same)
        simp [slash, nativeTokenResult, nativeMemberErrorMeaning, schemaSliceBytes,
          original, EchoPointer.decode, different]

theorem native_echo_pointer_has_original_meaning (pointer : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.echo_pointer_tokens pointer ⦃ actual =>
      match actual with
      | .Ok tokens => EchoPointer.Meaning (schemaSliceBytes pointer) (nativeTokenNames tokens)
      | .Err error => error = .EchoConflict ∧ ¬∃ tokens, EchoPointer.Meaning (schemaSliceBytes pointer) tokens ⦄ := by
  apply spec_mono (native_echo_pointer_exact pointer)
  intro actual exact
  cases actual with
  | Ok tokens =>
      exact (EchoPointer.decode_exact _ _).mp (by simpa only [nativeTokenResult] using exact.symm)
  | Err error =>
      have refused : EchoPointer.decode (schemaSliceBytes pointer) = .error (nativeMemberErrorMeaning error) := by
        simpa only [nativeTokenResult] using exact.symm
      have kind := EchoPointer.decode_error_class _ _ refused
      have nativeKind : error = .EchoConflict := by cases error <;> simp_all [nativeMemberErrorMeaning]
      refine ⟨nativeKind, (EchoPointer.refusal_exact _).mp ?_⟩
      simpa only [nativeKind, nativeMemberErrorMeaning] using refused

theorem native_echo_pointer_invalid_refuses (pointer : Slice Std.U8)
    (invalid : ¬∃ tokens, EchoPointer.Meaning (schemaSliceBytes pointer) tokens) :
    AuthsNativeRecipe.auths_gateway_kernel.template_members.echo_pointer_tokens pointer ⦃ actual =>
      actual = .Err .EchoConflict ⦄ := by
  apply spec_mono (native_echo_pointer_has_original_meaning pointer)
  intro actual meaning
  cases actual with
  | Ok tokens => exact False.elim (invalid ⟨nativeTokenNames tokens, meaning⟩)
  | Err error => simp only [meaning.1]

@[step] theorem native_echo_input_exact (source : NativeEchoSource) (bounded : NativeEchoFits source) :
    AuthsNativeRecipe.recipe.lower.source_echo source ⦃ actual => nativeEchoResult actual = originalEcho source ⦄ := by
  cases source with
  | JsonPointer pointer =>
      unfold AuthsNativeRecipe.recipe.lower.source_echo
      step with borrow_text_exact pointer bounded as ⟨raw, rawMeaning⟩
      step with native_echo_pointer_exact raw as ⟨decoded, decodedMeaning⟩
      have originalBytes : schemaSliceBytes raw = textBytes pointer := rawMeaning
      cases decoded <;> simp_all [nativeEchoResult, nativeEchoMeaning, originalEcho,
        nativeTokenResult, Except.map, Except.mapError]
  | FormField name =>
      unfold AuthsNativeRecipe.recipe.lower.source_echo
      step with borrow_text_exact name bounded as ⟨raw, rawMeaning⟩
      step with copy_u8_exact raw as ⟨copied, copiedMeaning⟩
      simp only [spec_ok, nativeEchoResult, nativeEchoMeaning, originalEcho,
        copiedMeaning.trans rawMeaning]

theorem native_echo_json_has_useful_original_tokens (pointer : String) (bounded : TextFits pointer)
    (tokens : List (List Nat)) (meaning : EchoPointer.Meaning (textBytes pointer) tokens) :
    AuthsNativeRecipe.recipe.lower.source_echo (.JsonPointer pointer) ⦃ actual =>
      ∃ output : NativeVec (NativeVec Std.U8), actual = .Ok (.Json output) ∧
        nativeTokenNames output = tokens ∧ TemplateMembers.PointerDomain (nativeTokenNames output) ⦄ := by
  have decoded := EchoPointer.decode_complete (textBytes pointer) tokens meaning
  apply spec_mono (native_echo_input_exact (.JsonPointer pointer) bounded)
  intro actual exact
  cases actual with
  | Err error => simp [nativeEchoResult, originalEcho, decoded] at exact
  | Ok echo =>
      cases echo with
      | Form name => simp [nativeEchoResult, nativeEchoMeaning, originalEcho, decoded] at exact
      | Json output =>
          have same : nativeTokenNames output = tokens := by
            simpa only [nativeEchoResult, nativeEchoMeaning, originalEcho, decoded,
              Except.map, Except.mapError, Except.ok.injEq, TemplateAst.Echo.json.injEq] using exact
          exact ⟨output, rfl, same, by simpa only [same] using meaning.2⟩

end Auths.Product.NativeCompiler.Refinement
