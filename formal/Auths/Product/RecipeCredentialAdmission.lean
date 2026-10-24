import Auths.Product.RecipeAdmissionAtoms
import Auths.Product.RecipePlanModel

/-!
Independent decoded-source credential/guard admission. Original path tags,
method bytes, probe literals, pointers, response bounds and status lists are
retained. No accepted-source flag, native result or selected request is input.
All failed guard rules have the same existing credential-guard error; this
module states their complete admitted domain, not physical execution costs.
-/
namespace Auths.Product.RecipeCredentialAdmission
open RequestConstruction RecipeAdmissionAtoms
abbrev Bytes := RequestConstruction.Bytes
abbrev Segment := RecipePlanModel.PathSegment
abbrev Path := List Segment
abbrev FixedPath := List Bytes

/-- The byte scan itself permits an empty sequence; the enclosing requirement
rejects empty names and checks the 64-byte limit before this scan. -/
def HeaderTokenBody : Bytes → Prop
  | [] => True
  | first :: rest => OperationIdentity.Alphanumeric first ∧
      ∀ byte ∈ rest, OperationIdentity.Alphanumeric byte ∨ byte = 45
instance (name : Bytes) : Decidable (HeaderTokenBody name) := by
  cases name <;> unfold HeaderTokenBody OperationIdentity.Alphanumeric <;> infer_instance

def CredentialHeaderToken : Bytes → Prop
  | [] => False
  | first :: rest => rest.length + 1 ≤ 64 ∧ OperationIdentity.Alphanumeric first ∧
      ∀ byte ∈ rest, OperationIdentity.Alphanumeric byte ∨ byte = 45
instance (name : Bytes) : Decidable (CredentialHeaderToken name) := by
  cases name <;> unfold CredentialHeaderToken OperationIdentity.Alphanumeric <;> infer_instance

/-- Exact existing transport/content/idempotency names, independent of native
catalog indices and native lowercased strings. -/
def transportHeaderNames : List Bytes := [
  [97,117,116,104,111,114,105,122,97,116,105,111,110],
  [104,111,115,116], [99,111,111,107,105,101],
  [115,101,116,45,99,111,111,107,105,101],
  [99,111,110,116,101,110,116,45,116,121,112,101],
  [99,111,110,116,101,110,116,45,108,101,110,103,116,104],
  [97,99,99,101,112,116], [99,111,110,110,101,99,116,105,111,110],
  [116,114,97,110,115,102,101,114,45,101,110,99,111,100,105,110,103],
  [105,100,101,109,112,111,116,101,110,99,121,45,107,101,121]
]

def CredentialHeaderAdmitted (name : Bytes) : Prop :=
  CredentialHeaderToken name ∧
    (∀ reserved ∈ transportHeaderNames, ¬HeaderCompiler.AsciiNameEqual name reserved) ∧
    ¬HeaderCompiler.RegisteredCredentialHeader name
instance (name : Bytes) : Decidable (CredentialHeaderAdmitted name) := by
  unfold CredentialHeaderAdmitted
  infer_instance

theorem credential_header_token_iff (name : Bytes) :
    CredentialHeaderToken name ↔ name ≠ [] ∧ name.length ≤ 64 ∧ HeaderTokenBody name := by
  cases name <;> simp [CredentialHeaderToken, HeaderTokenBody]

inductive Requirement where
  | bearer
  | headerApiKey (name : Bytes)
  deriving DecidableEq

def RequirementAdmitted : Requirement → Prop
  | .bearer => True
  | .headerApiKey name => CredentialHeaderAdmitted name
instance (requirement : Requirement) : Decidable (RequirementAdmitted requirement) := by
  cases requirement <;> unfold RequirementAdmitted <;> infer_instance

def validateRequirement {E : Type} (invalidCredential : E) (requirement : Requirement) : Except E Unit :=
  if RequirementAdmitted requirement then .ok () else .error invalidCredential

def fixedValues : Path → Option FixedPath
  | [] => some []
  | .fixed value :: rest => (fixedValues rest).map (value :: ·)
  | _ :: _ => none

def FixedPathAdmitted (path : Path) : Prop :=
  0 < path.length ∧ path.length ≤ 16 ∧
    ∃ values, fixedValues path = some values ∧ ∀ value ∈ values, PathCompiler.FixedValid value
instance (path : Path) : Decidable (FixedPathAdmitted path) := by
  unfold FixedPathAdmitted
  cases fixedValues path <;> simp <;> infer_instance

inductive Literal where
  | boolean (value : Bool)
  | text (value : Bytes)
  | integer (value : Int)
  | unsupported
  deriving DecidableEq

def ProbeLiteralAdmitted : Literal → Prop
  | .boolean _ => True
  | .text value => value.length ≤ 256
  | .integer value => value.natAbs ≤ 9007199254740991
  | .unsupported => False
instance (value : Literal) : Decidable (ProbeLiteralAdmitted value) := by
  cases value <;> unfold ProbeLiteralAdmitted <;> infer_instance

structure Read where
  path : Path
  pointer : Bytes
  maximumResponseBytes : Nat
  deriving DecidableEq

structure Probe extends Read where
  equals : Literal
  deriving DecidableEq

def ReadAdmitted (read : Read) : Prop :=
  FixedPathAdmitted read.path ∧ ResponsePointer read.pointer ∧ ReadBound read.maximumResponseBytes
instance (read : Read) : Decidable (ReadAdmitted read) := by unfold ReadAdmitted; infer_instance

def ProbeAdmitted (probe : Probe) : Prop :=
  FixedPathAdmitted probe.path ∧ ResponsePointer probe.pointer ∧
    ProbeLiteralAdmitted probe.equals ∧ ReadBound probe.maximumResponseBytes
instance (probe : Probe) : Decidable (ProbeAdmitted probe) := by unfold ProbeAdmitted; infer_instance

structure DeniedRead where
  method : Bytes
  path : Path
  refusedStatuses : List Nat
  deriving DecidableEq

def getMethod : Bytes := [71, 69, 84]
def headMethod : Bytes := [72, 69, 65, 68]

def DeniedReadAdmitted (read : DeniedRead) : Prop :=
  (read.method = getMethod ∨ read.method = headMethod) ∧
    FixedPathAdmitted read.path ∧ RefusedStatuses read.refusedStatuses
instance (read : DeniedRead) : Decidable (DeniedReadAdmitted read) := by
  unfold DeniedReadAdmitted
  infer_instance

def deniedPaths (reads : List DeniedRead) : Option (List FixedPath) :=
  reads.mapM (fun read => fixedValues read.path)

def DeniedReadsAdmitted (reads : List DeniedRead) (reserved : List FixedPath) : Prop :=
  0 < reads.length ∧ reads.length ≤ 4 ∧
    (∀ read ∈ reads, DeniedReadAdmitted read) ∧
    ∃ paths, deniedPaths reads = some paths ∧ paths.Nodup ∧ ∀ path ∈ paths, path ∉ reserved
instance (reads : List DeniedRead) (reserved : List FixedPath) :
    Decidable (DeniedReadsAdmitted reads reserved) := by
  unfold DeniedReadsAdmitted
  cases deniedPaths reads <;> simp <;> infer_instance

structure Guard where
  prefixes : List Bytes
  probe : Option Probe
  account : Option Read
  denied : Option (List DeniedRead)
  deriving DecidableEq

/-- The four source paths appear in the native guard's reservation order.
Only all-fixed columns participate; other path tags retain their meaning in
the enclosing source validator rather than becoming fixed strings here. -/
structure SourcePaths where
  write : Path
  observation : Option Path
  preEntry : Option Path
  relativeCeiling : Option Path
  deriving DecidableEq

def optionalFixedPath (path : Option Path) : List FixedPath :=
  (path.bind fixedValues).toList

def sourceReserved (source : SourcePaths) : List FixedPath :=
  (fixedValues source.write).toList ++ optionalFixedPath source.observation ++
    optionalFixedPath source.preEntry ++ optionalFixedPath source.relativeCeiling

def guardReserved (guard : Guard) (source : SourcePaths) : List FixedPath :=
  (guard.probe.bind (fun probe => fixedValues probe.path)).toList ++
    (guard.account.bind (fun account => fixedValues account.path)).toList ++ sourceReserved source

def OptionalAdmitted {T : Type} (admit : T → Prop) : Option T → Prop
  | none => True
  | some value => admit value
instance {T : Type} (admit : T → Prop) [DecidablePred admit] (value : Option T) :
    Decidable (OptionalAdmitted admit value) := by
  cases value <;> unfold OptionalAdmitted <;> infer_instance

def GuardAdmitted (guard : Guard) (source : SourcePaths) : Prop :=
  Prefixes guard.prefixes ∧ OptionalAdmitted ProbeAdmitted guard.probe ∧
    OptionalAdmitted ReadAdmitted guard.account ∧
    OptionalAdmitted (fun reads => DeniedReadsAdmitted reads (guardReserved guard source)) guard.denied
instance (guard : Guard) (source : SourcePaths) : Decidable (GuardAdmitted guard source) := by
  unfold GuardAdmitted
  infer_instance

def guardAdmitted (guard : Guard) (source : SourcePaths) : Bool := decide (GuardAdmitted guard source)

/-- The error parameter is the fixed native credential-guard error value,
not a validator callback or a supplied admission decision. -/
def validateGuard {E : Type} (invalidCredentialGuard : E) (guard : Guard) (source : SourcePaths) : Except E Unit :=
  if GuardAdmitted guard source then .ok () else .error invalidCredentialGuard

theorem credential_headers_exclude_transport_and_catalog (name : Bytes)
    (admitted : CredentialHeaderAdmitted name) :
    (∀ reserved ∈ transportHeaderNames, ¬HeaderCompiler.AsciiNameEqual name reserved) ∧
      ¬HeaderCompiler.RegisteredCredentialHeader name := admitted.2

theorem credential_header_bytes_exclude_transport_delimiters (name : Bytes)
    (admitted : CredentialHeaderAdmitted name) :
    name ≠ [] ∧ name.length ≤ 64 ∧
      ∀ byte ∈ name, byte ≠ 0 ∧ byte ≠ 10 ∧ byte ≠ 13 ∧ byte ≠ 58 := by
  cases name with
  | nil => exact False.elim admitted.1
  | cons first rest =>
      have token := admitted.1
      refine ⟨by simp, by simpa only [List.length_cons] using token.1, ?_⟩
      intro byte member
      rcases List.mem_cons.mp member with same | later
      · subst byte
        have alpha := token.2.1
        unfold OperationIdentity.Alphanumeric at alpha
        omega
      · have allowed := token.2.2 byte later
        unfold OperationIdentity.Alphanumeric at allowed
        omega

theorem fixed_values_preserve_all_original_segments (path : Path) (values : FixedPath)
    (selected : fixedValues path = some values) : path = values.map Segment.fixed := by
  induction path generalizing values with
  | nil =>
      have same : ([] : FixedPath) = values := Option.some.inj selected
      subst values
      rfl
  | cons first rest ih =>
      cases first with
      | fixed value =>
          cases remaining : fixedValues rest with
          | none => simp [fixedValues, remaining] at selected
          | some tail =>
              have same : value :: tail = values := by simpa [fixedValues, remaining] using selected
              subst values
              simp only [List.map_cons]
              exact congrArg (List.cons (.fixed value)) (ih tail remaining)
      | field name => simp [fixedValues] at selected
      | responseField pointer maximum => simp [fixedValues] at selected
      | echo => simp [fixedValues] at selected

theorem fixed_paths_earn_original_bounds (path : Path) (admitted : FixedPathAdmitted path) :
    ∃ values, path = values.map Segment.fixed ∧
      0 < values.length ∧ values.length ≤ 16 ∧ ∀ value ∈ values, PathCompiler.FixedValid value := by
  obtain ⟨minimum, maximum, values, selected, segments⟩ := admitted
  have original := fixed_values_preserve_all_original_segments path values selected
  refine ⟨values, original, ?_, ?_, segments⟩
  · simpa only [original, List.length_map] using minimum
  · simpa only [original, List.length_map] using maximum

theorem denied_reads_earn_non_aliasing (reads : List DeniedRead) (reserved : List FixedPath)
    (admitted : DeniedReadsAdmitted reads reserved) :
    ∃ paths, deniedPaths reads = some paths ∧ paths.Nodup ∧ ∀ path ∈ paths, path ∉ reserved :=
  admitted.2.2.2

theorem denied_read_methods_are_closed (reads : List DeniedRead) (reserved : List FixedPath)
    (admitted : DeniedReadsAdmitted reads reserved) :
    ∀ read ∈ reads, read.method = getMethod ∨ read.method = headMethod := by
  intro read member
  exact (admitted.2.2.1 read member).1

theorem accepted_guard_keeps_all_bounds (guard : Guard) (source : SourcePaths)
    (accepted : guardAdmitted guard source = true) :
    guard.prefixes.length ≤ 4 ∧
      OptionalAdmitted (fun reads => reads.length ≤ 4) guard.denied := by
  have admitted : GuardAdmitted guard source := by
    simpa only [guardAdmitted, decide_eq_true_eq] using accepted
  refine ⟨admitted.1.2.1, ?_⟩
  cases present : guard.denied with
  | none => trivial
  | some reads =>
      have denied : DeniedReadsAdmitted reads (guardReserved guard source) := by
        simpa only [present, OptionalAdmitted] using admitted.2.2.2
      exact denied.2.1

end Auths.Product.RecipeCredentialAdmission
