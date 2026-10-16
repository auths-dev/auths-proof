import Auths.Verifier.StatusSelection
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace Auths.StatusSelection
set_option maxHeartbeats 2000000

theorem byte_array_comparison {N : Std.Usize} (left right : Array Std.U8 N) :
    core.array.equality.PartialEqArray.eq core.cmp.PartialEqU8 left right = ok (left == right) := by
  have sameComputation : core.array.equality.PartialEqArray.eq core.cmp.PartialEqU8 left right =
      core.slice.cmp.PartialEqSlice.eq core.cmp.PartialEqU8 left.to_slice right.to_slice := by
    simp [core.array.equality.PartialEqArray.eq, core.slice.cmp.PartialEqSlice.eq,
      Array.to_slice, Array.length, Slice.length]
  have contract := core.slice.cmp.PartialEqSlice.eq_homo_spec core.cmp.PartialEqU8
    left.to_slice right.to_slice (by
      intro x y
      simp [liftFun2])
  obtain ⟨actual, equation, meaning⟩ := spec_imp_exists contract
  rw [sameComputation, equation]
  congr 1
  apply Bool.eq_iff_iff.mpr
  simpa [beq_iff_eq, Slice.eq_iff, Array.to_slice, Aeneas.Std.Array, Subtype.ext_iff] using meaning

theorem grant_eq (left right : AuthsStatusSelection.auths_model.GrantId) :
    AuthsStatusSelection.auths_model.GrantId.Insts.CoreCmpPartialEqGrantId.eq left right = ok (left == right) := by
  simp [AuthsStatusSelection.auths_model.GrantId.Insts.CoreCmpPartialEqGrantId.eq,
    AuthsStatusSelection.auths_model.Digest.Insts.CoreCmpPartialEqDigest.eq, byte_array_comparison]

def grantActive : AuthsStatusSelection.auths_model.GrantState → Bool
  | .Active => true
  | _ => false

def grantView (signed : AuthsStatusSelection.auths_model.SignedGrantStatus) :
    Model.Statement AuthsStatusSelection.auths_model.GrantId :=
  let row := signed.statement
  ⟨row.grant_id, row.method, row.issuer, row.sequence.val, row.observed_at.val,
    row.valid_until.val, grantActive row.state⟩

theorem grant_not_active (state : AuthsStatusSelection.auths_model.GrantState) :
    core.cmp.PartialEq.ne.trait_default AuthsStatusSelection.auths_model.GrantState.Insts.CoreCmpPartialEqGrantState
      state .Active = ok (!grantActive state) := by
  cases state <;> simp [core.cmp.PartialEq.ne.trait_default, core.cmp.PartialEq.ne.default,
    AuthsStatusSelection.auths_model.GrantState.Insts.CoreCmpPartialEqGrantState.eq,
    grantActive, AuthsStatusSelection.auths_model.GrantState.read_discriminant]
end Auths.StatusSelection
