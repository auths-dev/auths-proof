import Auths.Product.RequestConstruction
import Mathlib.Tactic
namespace Auths.Product.SchemaIndex
open RequestConstruction
abbrev Name := Bytes

def position : List Name → Name → Option Nat
  | [], _ => none
  | field :: rest, wanted =>
    if field = wanted then some 0 else (position rest wanted).map Nat.succ

theorem position_points_to_name (fields : List Name) (wanted : Name) (index : Nat)
    (found : position fields wanted = some index) : fields[index]? = some wanted := by
  induction fields generalizing index with
  | nil => simp [position] at found
  | cons field rest ih =>
    by_cases same : field = wanted
    · simp [position, same] at found
      subst index
      simp [same]
    · simp only [position, same, ↓reduceIte] at found
      cases tail : position rest wanted with
      | none => simp [tail] at found
      | some next =>
        simp only [tail, Option.map_some, Option.some.injEq] at found
        subst index
        simpa using ih next tail

theorem absent_iff (fields : List Name) (wanted : Name) :
    position fields wanted = none ↔ wanted ∉ fields := by
  induction fields with
  | nil => simp [position]
  | cons field rest ih =>
    by_cases same : field = wanted
    · simp [position, same]
    · simp [position, same, ih, Ne.symm same]

theorem position_eq_first (fields : List Name) (wanted : Name) (index : Nat)
    (atIndex : fields[index]? = some wanted)
    (first : ∀ earlier, earlier < index → fields[earlier]? ≠ some wanted) :
    position fields wanted = some index := by
  induction fields generalizing index with
  | nil => simp at atIndex
  | cons field rest ih =>
    cases index with
    | zero =>
      have same : field = wanted := by simpa using atIndex
      simp [position, same]
    | succ index =>
      have different : field ≠ wanted := by
        intro same
        exact first 0 (by omega) (by simp [same])
      have tail : rest[index]? = some wanted := by simpa using atIndex
      have earliest : ∀ earlier, earlier < index → rest[earlier]? ≠ some wanted := by
        intro earlier before
        simpa using first (earlier + 1) (by omega)
      simp [position, different, ih index tail earliest]

/-- A named argument environment and its positional projection agree at every
    declared schema position. This relation is independent of lowered plans. -/
def Aligned (fields : List Name) (arguments : List Arg) (named : Name → Option Arg) : Prop :=
  fields.length = arguments.length ∧
    ∀ (index : Nat) (name : Name), fields[index]? = some name → arguments[index]? = named name

theorem indexed_argument_is_named (fields : List Name) (arguments : List Arg)
    (named : Name → Option Arg) (aligned : Aligned fields arguments named)
    (name : Name) (index : Nat) (lowered : position fields name = some index) :
    arguments[index]? = named name :=
  aligned.2 index name (position_points_to_name fields name index lowered)

inductive NamedSegment where
  | fixed (bytes : Bytes)
  | field (name : Name)
  deriving DecidableEq

def lowerSegment (fields : List Name) : NamedSegment → Option Segment
  | .fixed bytes => some (.fixed bytes)
  | .field name => (position fields name).map Segment.field

def namedSegmentBytes (named : Name → Option Arg) : NamedSegment → Option Bytes
  | .fixed bytes => some bytes
  | .field name =>
    match named name with
    | some (.text bytes) => some (pathEncode bytes)
    | _ => none

/-- Successful lowering cannot substitute a similarly named argument. -/
theorem lowered_field_uses_exact_name (fields : List Name) (arguments : List Arg)
    (named : Name → Option Arg) (aligned : Aligned fields arguments named)
    (name : Name) (index : Nat) (lowered : lowerSegment fields (.field name) = some (.field index)) :
    arguments[index]? = named name := by
  simp only [lowerSegment] at lowered
  have found : position fields name = some index := by
    cases candidate : position fields name <;> simp_all
  exact indexed_argument_is_named fields arguments named aligned name index found

/-- Naming an undeclared field cannot produce a positional field reference. -/
theorem undeclared_field_refused (fields : List Name) (name : Name) (absent : name ∉ fields) :
    lowerSegment fields (.field name) = none := by
  simp [lowerSegment, (absent_iff fields name).mpr absent]

/-- A reference to an exact field in the source has the same bytes after
    positional lowering, under the independently stated projection relation. -/
theorem field_rendering_preserved (fields : List Name) (arguments : List Arg)
    (named : Name → Option Arg) (aligned : Aligned fields arguments named)
    (name : Name) (index : Nat) (value : Bytes)
    (lowered : position fields name = some index) (provided : named name = some (.text value)) :
    segmentBytes arguments (.field index) = pathEncode value := by
  have same := indexed_argument_is_named fields arguments named aligned name index lowered
  simp [segmentBytes, same, provided]

end Auths.Product.SchemaIndex
