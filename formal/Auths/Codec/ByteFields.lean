import Auths.Codec.Action
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_codec
namespace Auths.Codec.Action

theorem cloned_bytes_exact (bytes : Slice Std.U8) :
    alloc.slice.Slice.to_vec core.clone.CloneU8 bytes = ok bytes := by
  change Slice.clone core.clone.CloneU8.clone bytes = ok bytes
  have contract := Slice.clone_spec (s := bytes) (clone := core.clone.CloneU8.clone) (by intro value _; rfl)
  obtain ⟨result, evaluates, meaning⟩ := spec_imp_exists contract
  simpa only [← meaning] using evaluates

theorem bounded_bytes_valid (decoder next : cbor.Decoder) (maximum : Std.Usize)
    (nonEmpty : Bool) (bytes : alloc.vec.Vec Std.U8)
    (accepted : decode.bounded_bytes decoder maximum nonEmpty = ok (.Ok bytes, next)) :
    bytes.val.length ≤ maximum.val ∧ (nonEmpty = true → 0 < bytes.val.length) := by
  unfold decode.bounded_bytes at accepted
  simp only [Bind.bind, Aeneas.Std.bind, cloned_bytes_exact, bind_tc_ok,
    core.slice.Slice.is_empty] at accepted
  repeat' first
    | casesm* _ × _
    | dsimp only at accepted
    | split at accepted
    | simp (failIfUnchanged := true) only [uncurry, Bind.bind, Aeneas.Std.bind,
        bind_tc_ok, Result.ok.injEq, core.result.Result.Ok.injEq,
        Prod.mk.injEq, reduceCtorEq] at accepted
    | contradiction
  all_goals simp_all [UScalar.lt_equiv, List.length_pos_iff]

end Auths.Codec.Action
