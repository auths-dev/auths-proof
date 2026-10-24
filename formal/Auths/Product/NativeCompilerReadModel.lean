import Auths.Product.PathCompiler

/-!
Independent compilation of read plans. The error parameter is a fixed outer
error code, not a callback or supplied compiler outcome. Original path names
remain names until the independent path compiler resolves the shared layout.
-/
namespace Auths.Product.NativeCompiler.ReadModel
open RequestConstruction

def action {E : Type} (invalid : E) (origin : Bytes) (headers : HeaderPlan)
    (names : List Bytes) (source : List PathCompiler.SourceSegment) : Except E ReadPlan :=
  ((PathCompiler.lowerPath names source).mapError (fun _ => invalid)).map
    (fun path => ⟨origin, path, headers⟩)

def credential {E : Type} (invalid : E) (method : Method) (origin : Bytes)
    (versions : List Header) (source : List PathCompiler.SourceSegment) : Except E CredentialPlan :=
  ((PathCompiler.lowerFixedPath source).mapError (fun _ => invalid)).map
    (fun path => ⟨method, origin, path, versions⟩)

/-- A credential read does not acquire an account-scope header, even when
the shared action-header plan contains one. Only its fixed version column
is a parameter of this declaration. -/
theorem credential_success_columns {E : Type} (invalid : E) (method : Method) (origin : Bytes)
    (versions : List Header) (source : List PathCompiler.SourceSegment) (output : CredentialPlan)
    (compiled : credential invalid method origin versions source = .ok output) :
    output.method = method ∧ output.origin = origin ∧ output.versions = versions ∧
      PathCompiler.lowerFixedPath source = .ok output.path := by
  unfold credential at compiled
  cases pathAt : PathCompiler.lowerFixedPath source with
  | error error => simp [pathAt] at compiled
  | ok path =>
      have same : CredentialPlan.mk method origin path versions = output := by
        simpa only [pathAt, Except.mapError, Except.map] using compiled
      subst output
      exact ⟨rfl, rfl, rfl, pathAt⟩

theorem action_success_columns {E : Type} (invalid : E) (origin : Bytes) (headers : HeaderPlan)
    (names : List Bytes) (source : List PathCompiler.SourceSegment) (output : ReadPlan)
    (compiled : action invalid origin headers names source = .ok output) :
    output.origin = origin ∧ output.headers = headers ∧
      List.Forall₂ (PathCompiler.SegmentMeaning names) source output.path := by
  unfold action at compiled
  cases pathAt : PathCompiler.lowerPath names source with
  | error error => simp [pathAt] at compiled
  | ok path =>
      have same : ReadPlan.mk origin path headers = output := by
        simpa only [pathAt, Except.mapError, Except.map] using compiled
      subst output
      refine ⟨rfl, rfl, ?_⟩
      unfold PathCompiler.lowerPath at pathAt
      split at pathAt
      · exact PathCompiler.lower_list_sound _ _ _ pathAt
      · contradiction

end Auths.Product.NativeCompiler.ReadModel
