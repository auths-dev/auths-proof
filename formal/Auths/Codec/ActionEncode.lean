import Auths.Codec.AttachmentEncode
open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.ActionEncode
open Refinement EncoderState ProtocolEncode ObjectEncode AttachmentEncode

structure StringsBounded (action : auths_codec.auths_model.CanonicalAction) : Prop where
  profile : action.profile.id.toByteArray.size ≤ U32.max
  media : action.media_type.toByteArray.size ≤ U32.max
  capability : action.permission.capability.toByteArray.size ≤ U32.max
  resource : action.permission.resource.toByteArray.size ≤ U32.max
  budget : optionalBudgetStringsBounded action.requested_budget

/-- An allocation envelope for every intermediate write, including headers.
It is independent of final encoded length and does not model physical OOM. -/
def actionCost (action : auths_codec.auths_model.CanonicalAction) : Nat :=
  180 + action.profile.id.toByteArray.size + action.media_type.toByteArray.size +
    action.body.val.length + action.permission.capability.toByteArray.size +
    action.permission.resource.toByteArray.size + optionalBudgetCost action.requested_budget +
    attachmentsCost action.detached_attachments.val

def actionEncoding (action : auths_codec.auths_model.CanonicalAction) : List Nat :=
  [166, 0] ++ profileEncoding (stringBytes action.profile.id) action.profile.version.val ++
  [1] ++ payloadEncoding 3 (stringBytes action.media_type) ++
  [2] ++ payloadEncoding 2 (byteList action.body.val) ++
  [3] ++ permissionEncoding (stringBytes action.permission.capability) (stringBytes action.permission.resource) ++
  [4] ++ optionalBudgetEncoding (action.requested_budget.map ObjectEncode.budgetView) ++
  [5] ++ encodeHead ⟨4, action.detached_attachments.val.length⟩ ++
  attachmentsEncoding action.detached_attachments.val

def resultView (result : core.result.Result (alloc.vec.Vec Std.U8) error.CodecError) :
    core.result.Result (List Nat) error.CodecError :=
  match result with | .Err error => .Err error | .Ok bytes => .Ok (byteList bytes.val)

theorem optional_budget_length_bound (value : Option auths_codec.auths_model.BudgetCeiling) :
    (optionalBudgetEncoding (value.map ObjectEncode.budgetView)).length ≤ optionalBudgetCost value := by
  cases value with
  | none => simp [optionalBudgetEncoding, optionalBudgetCost]
  | some value =>
    have bound := budget_length_bound (stringBytes value.algebra) value.value.val
    rw [stringBytes_length] at bound
    simp only [Option.map_some, ObjectEncode.budgetView, optionalBudgetEncoding, optionalBudgetCost]
    omega

theorem action_length_bound (action : auths_codec.auths_model.CanonicalAction) :
    (actionEncoding action).length ≤ actionCost action := by
  have profileBound := profile_length_bound (stringBytes action.profile.id) action.profile.version.val
  have mediaBound := payload_length_bound 3 (stringBytes action.media_type)
  have bodyBound := payload_length_bound 2 (byteList action.body.val)
  have permissionBound := permission_length_bound (stringBytes action.permission.capability) (stringBytes action.permission.resource)
  have budgetBound := optional_budget_length_bound action.requested_budget
  have arrayBound := encodeHead_length_le_nine ⟨4, action.detached_attachments.val.length⟩
  have attachmentBound := attachments_length_bound action.detached_attachments.val
  simp only [actionEncoding, actionCost, List.length_append, List.length_cons, List.length_nil,
    stringBytes_length, byteList, List.length_map] at *
  omega

@[step] theorem action_exact (action : auths_codec.auths_model.CanonicalAction)
    (stringsBounded : StringsBounded action) (space : actionCost action ≤ Usize.max) :
    encode.encode_canonical_action action ⦃ actual => resultView actual = .Ok (actionEncoding action) ⦄ := by
  unfold encode.encode_canonical_action
  simp only [cbor.Encoder.new, alloc.vec.Vec.new, bind_tc_ok]
  simp only [actionCost] at space
  step with ProtocolEncode.map_exact (cbor.Encoder.mk (alloc.vec.Vec.new Std.U8)) 6#u64 (by
    simp only [alloc.vec.Vec.new, alloc.vec.Vec.deref, Array.to_slice, Slice.len] at *
    omega)
    as ⟨r0, e0, ok0, bytes0⟩
  have len0 := output_length bytes0
  have bound0 := encodeHead_length_le_nine ⟨5, 6⟩
  simp only [stringBytes_length, byteList, List.length_map, alloc.vec.Vec.deref, Slice.len] at bound0 len0
  simp only [ok0, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncode.key_exact e0 0#u8 (by
    simp only [alloc.vec.Vec.new, alloc.vec.Vec.deref, Array.to_slice, Slice.len] at *
    omega)
    as ⟨r1, e1, ok1, bytes1⟩
  have len1 := output_length bytes1
  have bound1 := encodeHead_length_le_nine ⟨0, 0⟩
  simp only [stringBytes_length, byteList, List.length_map, alloc.vec.Vec.deref, Slice.len] at bound1 len1
  simp only [ok1, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.CanonicalAction.impl.profile, alloc.vec.Vec.deref, bind_tc_ok]
  step with ObjectEncode.profile_exact e1 action.profile stringsBounded.profile (by
    simp only [alloc.vec.Vec.new, alloc.vec.Vec.deref, Array.to_slice, Slice.len] at *
    omega)
    as ⟨r2, e2, ok2, bytes2⟩
  have len2 := output_length bytes2
  have bound2 := profile_length_bound (stringBytes action.profile.id) action.profile.version.val
  simp only [stringBytes_length, byteList, List.length_map, alloc.vec.Vec.deref, Slice.len] at bound2 len2
  simp only [ok2, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncode.key_exact e2 1#u8 (by
    simp only [alloc.vec.Vec.new, alloc.vec.Vec.deref, Array.to_slice, Slice.len] at *
    omega)
    as ⟨r3, e3, ok3, bytes3⟩
  have len3 := output_length bytes3
  have bound3 := encodeHead_length_le_nine ⟨0, 1⟩
  simp only [stringBytes_length, byteList, List.length_map, alloc.vec.Vec.deref, Slice.len] at bound3 len3
  simp only [ok3, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.CanonicalAction.impl.media_type, auths_model.MediaType.as_str, alloc.vec.Vec.deref, bind_tc_ok]
  rw [StringRefinement.string_borrow_exact action.media_type stringsBounded.media]
  simp only [bind_tc_ok]
  have mediaLength : (toStr action.media_type stringsBounded.media).val.length = action.media_type.toByteArray.size := by
    simp [toStr, ByteArray.length_toList]
  step with ProtocolEncode.text_exact e3 (toStr action.media_type stringsBounded.media) (by
    simp only [alloc.vec.Vec.new, alloc.vec.Vec.deref, Array.to_slice, Slice.len] at *
    omega)
    as ⟨r4, e4, ok4, bytes4⟩
  rw [borrowed_bytes] at bytes4
  have len4 := output_length bytes4
  have bound4 := payload_length_bound 3 (stringBytes action.media_type)
  simp only [stringBytes_length, byteList, List.length_map, alloc.vec.Vec.deref, Slice.len] at bound4 len4
  simp only [ok4, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncode.key_exact e4 2#u8 (by
    simp only [alloc.vec.Vec.new, alloc.vec.Vec.deref, Array.to_slice, Slice.len] at *
    omega)
    as ⟨r5, e5, ok5, bytes5⟩
  have len5 := output_length bytes5
  have bound5 := encodeHead_length_le_nine ⟨0, 2⟩
  simp only [stringBytes_length, byteList, List.length_map, alloc.vec.Vec.deref, Slice.len] at bound5 len5
  simp only [ok5, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.CanonicalAction.impl.body, alloc.vec.Vec.deref, bind_tc_ok]
  step with ProtocolEncode.bytes_exact e5 (alloc.vec.Vec.deref action.body) (by
    simp only [alloc.vec.Vec.new, alloc.vec.Vec.deref, Array.to_slice, Slice.len] at *
    omega)
    as ⟨r6, e6, ok6, bytes6⟩
  have len6 := output_length bytes6
  have bound6 := payload_length_bound 2 (byteList action.body.val)
  simp only [stringBytes_length, byteList, List.length_map, alloc.vec.Vec.deref, Slice.len] at bound6 len6
  simp only [ok6, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncode.key_exact e6 3#u8 (by
    simp only [alloc.vec.Vec.new, alloc.vec.Vec.deref, Array.to_slice, Slice.len] at *
    omega)
    as ⟨r7, e7, ok7, bytes7⟩
  have len7 := output_length bytes7
  have bound7 := encodeHead_length_le_nine ⟨0, 3⟩
  simp only [stringBytes_length, byteList, List.length_map, alloc.vec.Vec.deref, Slice.len] at bound7 len7
  simp only [ok7, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.CanonicalAction.impl.permission, alloc.vec.Vec.deref, bind_tc_ok]
  step with ObjectEncode.permission_exact e7 action.permission stringsBounded.capability stringsBounded.resource (by
    simp only [alloc.vec.Vec.new, alloc.vec.Vec.deref, Array.to_slice, Slice.len] at *
    omega)
    as ⟨r8, e8, ok8, bytes8⟩
  have len8 := output_length bytes8
  have bound8 := permission_length_bound (stringBytes action.permission.capability) (stringBytes action.permission.resource)
  simp only [stringBytes_length, byteList, List.length_map, alloc.vec.Vec.deref, Slice.len] at bound8 len8
  simp only [ok8, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncode.key_exact e8 4#u8 (by
    simp only [alloc.vec.Vec.new, alloc.vec.Vec.deref, Array.to_slice, Slice.len] at *
    omega)
    as ⟨r9, e9, ok9, bytes9⟩
  have len9 := output_length bytes9
  have bound9 := encodeHead_length_le_nine ⟨0, 4⟩
  simp only [stringBytes_length, byteList, List.length_map, alloc.vec.Vec.deref, Slice.len] at bound9 len9
  simp only [ok9, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.CanonicalAction.impl.requested_budget, core.option.Option.as_ref, alloc.vec.Vec.deref, bind_tc_ok]
  step with ObjectEncode.optional_budget_exact e9 action.requested_budget stringsBounded.budget (by
    simp only [alloc.vec.Vec.new, alloc.vec.Vec.deref, Array.to_slice, Slice.len] at *
    omega)
    as ⟨r10, e10, ok10, bytes10⟩
  have len10 := output_length bytes10
  have bound10 := optional_budget_length_bound action.requested_budget
  simp only [stringBytes_length, byteList, List.length_map, alloc.vec.Vec.deref, Slice.len] at bound10 len10
  simp only [ok10, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  step with ProtocolEncode.key_exact e10 5#u8 (by
    simp only [alloc.vec.Vec.new, alloc.vec.Vec.deref, Array.to_slice, Slice.len] at *
    omega)
    as ⟨r11, e11, ok11, bytes11⟩
  have len11 := output_length bytes11
  have bound11 := encodeHead_length_le_nine ⟨0, 5⟩
  simp only [stringBytes_length, byteList, List.length_map, alloc.vec.Vec.deref, Slice.len] at bound11 len11
  simp only [ok11, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [auths_model.CanonicalAction.impl.detached_attachments, alloc.vec.Vec.deref, bind_tc_ok]
  step with ProtocolEncode.array_exact e11 (Slice.len (alloc.vec.Vec.deref action.detached_attachments)) (by
    simp only [alloc.vec.Vec.new, alloc.vec.Vec.deref, Array.to_slice, Slice.len] at *
    omega)
    as ⟨r12, e12, ok12, bytes12⟩
  have len12 := output_length bytes12
  have bound12 := encodeHead_length_le_nine ⟨4, action.detached_attachments.val.length⟩
  simp only [stringBytes_length, byteList, List.length_map, alloc.vec.Vec.deref, Slice.len] at bound12 len12
  simp only [ok12, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
  simp only [SharedSlice.Insts.CoreIterTraitsCollectIntoIteratorSharedIter.into_iter, bind_tc_ok]
  step with AttachmentEncode.attachments_exact
    ⟨alloc.vec.Vec.deref action.detached_attachments, 0⟩ e12 (by
      simp only [alloc.vec.Vec.deref, List.drop_zero]
      omega) as ⟨state, meaning⟩
  cases state with
  | Err error => simp [encoderView] at meaning
  | Ok finalEncoder =>
    simp only [encoderView, Option.map_some, List.drop_zero, alloc.vec.Vec.deref,
      core.result.Result.Ok.injEq] at meaning
    simp [core.result.Result.Insts.CoreOpsTry.branch, cbor.Encoder.into_writer,
      resultView, meaning,
      bytes12, bytes11, bytes10, bytes9, bytes8, bytes7, bytes6, bytes5, bytes4, bytes3, bytes2, bytes1, bytes0,
      actionEncoding, List.append_assoc, alloc.vec.Vec.new, byteList,
      alloc.vec.Vec.deref, Slice.len, encodeHead, additionalTag, argumentWidth, bigEndian]

end Auths.Codec.ActionEncode
