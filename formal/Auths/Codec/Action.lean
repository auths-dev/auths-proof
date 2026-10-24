import qualification.aeneas.generated.codec.Funs
import Mathlib.Tactic.CasesM
open Aeneas Aeneas.Std Result
open auths_codec
set_option maxHeartbeats 2000000
set_option maxRecDepth 2048

namespace Auths.Codec.Action

theorem branch_ok_iff {T E : Type} (value : core.result.Result T E) (output : T) :
    core.result.Result.Insts.CoreOpsTry.branch value =
      ok (core.ops.control_flow.ControlFlow.Continue output) ↔ value = .Ok output := by
  cases value <;> simp [core.result.Result.Insts.CoreOpsTry.branch]

theorem bytes_ne_exact (left right : Slice Std.U8) :
    core.cmp.impls.PartialEqShared.ne
      (Slice.Insts.CoreCmpPartialEqSlice core.cmp.PartialEqU8) left right
      ⦃ result => result = decide (left ≠ right) ⦄ := by
  have eqSpec := core.slice.cmp.PartialEqSlice.eq_homo_spec
    core.cmp.PartialEqU8 left right (by
      intro x y
      simp [core.cmp.PartialEqU8])
  have neSpec := core.cmp.PartialEq.ne.trait_default.spec
    (Slice.Insts.CoreCmpPartialEqSlice core.cmp.PartialEqU8) left right eqSpec
  apply Aeneas.Std.WP.spec_mono neSpec
  intro result property
  cases result <;> simp_all

theorem decode_encode_exact (input : Slice Std.U8)
    (limits : auths_model.VerifierLimits) (action : auths_model.CanonicalAction)
    (accepted : decode.decode_canonical_action input limits = ok (.Ok action)) :
    ∃ bytes, encode.encode_canonical_action action = ok (.Ok bytes) ∧ bytes.val = input.val := by
  unfold decode.decode_canonical_action canonical.accept canonical.accept_with_error at accepted
  simp only [Bind.bind, Aeneas.Std.bind] at accepted
  repeat' first
    | casesm* _ × _
    | dsimp only at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [uncurry, Bind.bind, Aeneas.Std.bind, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, bind_tc_ok, bind_tc_fail, bind_tc_div,
        Result.ok.injEq, core.result.Result.Ok.injEq,
        reduceCtorEq] at accepted
    | contradiction
  all_goals subst action
  all_goals
    rename_i encodedCall encodedResult encodedEq branchCall control bytes branchEq
      borrowedCall borrowed borrowedEq compareCall different compared same
    have resultOk := (branch_ok_iff encodedResult bytes).mp branchEq
    rw [resultOk] at encodedEq
    refine ⟨bytes, encodedEq, ?_⟩
    have borrowEq : alloc.vec.Vec.deref bytes = borrowed := by
      simpa only [alloc.vec.Vec.as_slice, Result.ok.injEq] using borrowedEq
    have comparison := bytes_ne_exact borrowed input
    rw [compared] at comparison
    simp only [Aeneas.Std.WP.spec_ok] at comparison
    have sliceSame : borrowed = input := by
      cases different <;> simp_all
    exact congrArg Subtype.val (borrowEq.trans sliceSame)

end Auths.Codec.Action

namespace Auths.Codec.Action

/-- Equal decoded actions cannot have different accepted encodings. This is a
byte equality statement and makes no assertion about hash collisions. -/
theorem accepted_encoding_unique (left right : Slice Std.U8)
    (limits : auths_model.VerifierLimits) (action : auths_model.CanonicalAction)
    (leftAccepted : decode.decode_canonical_action left limits = ok (.Ok action))
    (rightAccepted : decode.decode_canonical_action right limits = ok (.Ok action)) :
    left.val = right.val := by
  obtain ⟨leftBytes, leftEncode, leftMeaning⟩ := decode_encode_exact left limits action leftAccepted
  obtain ⟨rightBytes, rightEncode, rightMeaning⟩ := decode_encode_exact right limits action rightAccepted
  rw [leftEncode] at rightEncode
  have sameBytes : leftBytes = rightBytes := by simpa using rightEncode
  exact leftMeaning.symm.trans ((congrArg Subtype.val sameBytes).trans rightMeaning)

end Auths.Codec.Action

namespace Auths.Codec.Action

/-- The sole `sort_by_key` call has a stateless, exact digest-key callback. -/
theorem attachment_key_stateless (attachment : auths_model.DetachedAttachment) :
    auths_model.CanonicalAction.with_detached_attachments.closure.Insts.CoreOpsFunctionFnMutTupleSharedDetachedAttachmentAttachmentDigest.call_mut
      () attachment = ok (attachment.digest, ()) := by
  rfl

end Auths.Codec.Action
