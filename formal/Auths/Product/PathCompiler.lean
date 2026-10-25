import Auths.Product.FieldProjection

namespace Auths.Product.PathCompiler
open RequestConstruction

def httpsPrefix : Bytes := [104, 116, 116, 112, 115, 58, 47, 47]
def OriginMatches (origin host : Bytes) : Prop :=
  0 < host.length ∧ host.length ≤ 253 ∧ origin = httpsPrefix ++ host
instance (origin host : Bytes) : Decidable (OriginMatches origin host) := by unfold OriginMatches; infer_instance

theorem origin_matches_bound (origin host : Bytes) (matched : OriginMatches origin host) : origin.length ≤ 261 := by
  rw [matched.2.2, List.length_append]
  have prefixLength : httpsPrefix.length = 8 := rfl
  omega

theorem origin_matches_unique_host (origin first second : Bytes)
    (firstMatch : OriginMatches origin first) (secondMatch : OriginMatches origin second) : first = second := by
  have framed : httpsPrefix ++ first = httpsPrefix ++ second := firstMatch.2.2.symm.trans secondMatch.2.2
  exact List.append_left_cancel framed

inductive SourceSegment where
  | fixed (bytes : Bytes)
  | field (name : Bytes)
  | unsupported
  deriving DecidableEq

def FixedValid (bytes : Bytes) : Prop :=
  0 < bytes.length ∧ bytes.length ≤ 128 ∧ bytes ≠ [46] ∧ bytes ≠ [46, 46] ∧
    ∀ byte ∈ bytes, pathLiteral byte = true
instance (bytes : Bytes) : Decidable (FixedValid bytes) := by unfold FixedValid; infer_instance

theorem fixed_iff_source_checks (bytes : Bytes) : FixedValid bytes ↔
    bytes.length ≤ 128 ∧ segmentValueValid bytes = true ∧ ∀ byte ∈ bytes, pathLiteral byte = true := by
  cases bytes with
  | nil => simp [FixedValid, segmentValueValid]
  | cons first rest =>
    simp only [FixedValid, segmentValueValid, List.isEmpty_cons, Bool.not_false, Bool.true_and,
      Bool.and_eq_true, decide_eq_true_eq, bne_iff_ne, maxSegmentValueBytes, List.length_cons]
    constructor
    · rintro ⟨positive, bounded, one, two, literal⟩
      exact ⟨bounded, ⟨by omega, one, two⟩, literal⟩
    · rintro ⟨bounded, ⟨within, one, two⟩, literal⟩
      exact ⟨by omega, bounded, one, two, literal⟩

def lowerField (names : List Bytes) (name : Bytes) : Except ConstructError Nat :=
  if names.length ≤ 32 ∧ OperationIdentity.validToken name 64 = true then
    match SchemaIndex.position names name with
    | none => .error .argumentMismatch
    | some index => .ok index
  else .error .argumentMismatch

def lowerOne (names : List Bytes) : SourceSegment → Except ConstructError Segment
  | .fixed bytes => if FixedValid bytes then .ok (.fixed bytes) else .error .unsafeSegment
  | .field name => (lowerField names name).map Segment.field
  | .unsupported => .error .argumentMismatch

def lowerList (names : List Bytes) : List SourceSegment → Except ConstructError (List Segment)
  | [] => .ok []
  | source :: rest => do
    let segment ← lowerOne names source
    let tail ← lowerList names rest
    pure (segment :: tail)

def lowerPath (names : List Bytes) (source : List SourceSegment) : Except ConstructError (List Segment) :=
  if 0 < source.length ∧ source.length ≤ 16 ∧ names.length ≤ 32 then lowerList names source
  else .error .argumentMismatch

def lowerFixedList : List SourceSegment → Except ConstructError (List Bytes)
  | [] => .ok []
  | .fixed bytes :: rest =>
    if FixedValid bytes then (lowerFixedList rest).map (bytes :: ·) else .error .unsafeSegment
  | _ => .error .argumentMismatch

def lowerFixedPath (source : List SourceSegment) : Except ConstructError (List Bytes) :=
  if 0 < source.length ∧ source.length ≤ 16 then lowerFixedList source else .error .argumentMismatch

def SegmentAdmissible (names : List Bytes) : SourceSegment → Prop
  | .fixed bytes => FixedValid bytes
  | .field name => names.length ≤ 32 ∧ OperationIdentity.validToken name 64 = true ∧ name ∈ names
  | .unsupported => False

def PathAdmissible (names : List Bytes) (source : List SourceSegment) : Prop :=
  names.length ≤ 32 ∧ 0 < source.length ∧ source.length ≤ 16 ∧
    ∀ segment ∈ source, SegmentAdmissible names segment

instance (names : List Bytes) (source : SourceSegment) : Decidable (SegmentAdmissible names source) := by
  cases source <;> unfold SegmentAdmissible <;> infer_instance
instance (names : List Bytes) (source : List SourceSegment) : Decidable (PathAdmissible names source) := by
  unfold PathAdmissible
  infer_instance

theorem lower_one_complete (names : List Bytes) (source : SourceSegment)
    (valid : SegmentAdmissible names source) : ∃ segment, lowerOne names source = .ok segment := by
  cases source with
  | fixed bytes => exact ⟨.fixed bytes, by simp [lowerOne, valid]⟩
  | unsupported => exact False.elim valid
  | field name =>
    cases found : SchemaIndex.position names name with
    | none => exact False.elim ((SchemaIndex.absent_iff names name).mp found valid.2.2)
    | some index =>
      exact ⟨.field index, by simp [lowerOne, lowerField, valid.1, valid.2.1, found]⟩

theorem lower_list_complete (names : List Bytes) (source : List SourceSegment)
    (valid : ∀ segment ∈ source, SegmentAdmissible names segment) :
    ∃ segments, lowerList names source = .ok segments := by
  induction source with
  | nil => exact ⟨[], rfl⟩
  | cons first rest ih =>
    obtain ⟨segment, firstRun⟩ := lower_one_complete names first (valid first (by simp))
    obtain ⟨tail, restRun⟩ := ih (fun value member => valid value (by simp [member]))
    exact ⟨segment :: tail, by simp [lowerList, firstRun, restRun]⟩

theorem lower_path_complete (names : List Bytes) (source : List SourceSegment)
    (valid : PathAdmissible names source) : ∃ segments, lowerPath names source = .ok segments := by
  obtain ⟨segments, run⟩ := lower_list_complete names source valid.2.2.2
  exact ⟨segments, by simp [lowerPath, valid.1, valid.2.1, valid.2.2.1, run]⟩

/-- Declarative mapping keeps the original name and exact literal in the
statement; a wrong computed index cannot satisfy this relation. -/
def SegmentMeaning (names : List Bytes) : SourceSegment → Segment → Prop
  | .fixed bytes, .fixed actual => FixedValid bytes ∧ actual = bytes
  | .field name, .field index => names.length ≤ 32 ∧ OperationIdentity.validToken name 64 = true ∧
      SchemaIndex.position names name = some index
  | _, _ => False

def namedBytes (environment : Bytes → Option Arg) : SourceSegment → Bytes
  | .fixed bytes => bytes
  | .field name =>
    match environment name with
    | some (.text bytes) => pathEncode bytes
    | _ => []
  | .unsupported => []

def namedError (environment : Bytes → Option Arg) : SourceSegment → Option ConstructError
  | .fixed _ => none
  | .field name =>
    match environment name with
    | some (.text bytes) => if segmentValueValid bytes then none else some .unsafeSegment
    | _ => some .argumentMismatch
  | .unsupported => some .argumentMismatch

def namedPath (environment : Bytes → Option Arg) (source : List SourceSegment) : Bytes :=
  source.flatMap (fun segment => 47 :: namedBytes environment segment)

def namedPathError (environment : Bytes → Option Arg) : List SourceSegment → Option ConstructError
  | [] => none
  | segment :: rest => (namedError environment segment).orElse (fun _ => namedPathError environment rest)

def namedUrl (origin : Bytes) (environment : Bytes → Option Arg) (source : List SourceSegment) :
    Except ConstructError Bytes :=
  match namedPathError environment source with
  | some error => .error error
  | none =>
    if maxPathBytes < (namedPath environment source).length then .error .pathTooLong
    else .ok (origin ++ namedPath environment source)

theorem path_encode_length (bytes : Bytes) : (pathEncode bytes).length ≤ 3 * bytes.length := by
  induction bytes with
  | nil => simp [pathEncode]
  | cons byte rest ih =>
    have one : (pathByte byte).length ≤ 3 := by
      unfold pathByte
      split <;> simp [percent]
    simp only [pathEncode, List.flatMap_cons, List.length_append, List.length_cons] at *
    omega

theorem lower_one_sound (names : List Bytes) (source : SourceSegment) (segment : Segment)
    (lowered : lowerOne names source = .ok segment) : SegmentMeaning names source segment := by
  cases source with
  | fixed bytes =>
    unfold lowerOne at lowered
    split at lowered
    · rename_i valid
      have same : Segment.fixed bytes = segment := by simpa using lowered
      subst segment
      exact ⟨valid, rfl⟩
    · contradiction
  | field name =>
    unfold lowerOne lowerField at lowered
    split at lowered
    · rename_i valid
      cases found : SchemaIndex.position names name with
      | none => simp [found] at lowered
      | some index =>
        have same : Segment.field index = segment := by simpa [found] using lowered
        subst segment
        exact ⟨valid.1, valid.2, found⟩
    · contradiction
  | unsupported => simp [lowerOne] at lowered

theorem lower_list_sound (names : List Bytes) (source : List SourceSegment) (segments : List Segment)
    (lowered : lowerList names source = .ok segments) : List.Forall₂ (SegmentMeaning names) source segments := by
  induction source generalizing segments with
  | nil =>
    have empty : segments = [] := by simpa [lowerList] using lowered.symm
    simp [empty]
  | cons head rest ih =>
    cases first : lowerOne names head with
    | error error => simp [lowerList, first] at lowered
    | ok segment =>
      cases remaining : lowerList names rest with
      | error error => simp [lowerList, first, remaining] at lowered
      | ok tail =>
        have same : segment :: tail = segments := by simpa [lowerList, first, remaining] using lowered
        subst segments
        exact List.Forall₂.cons (lower_one_sound _ _ _ first) (ih tail remaining)

theorem lowered_path_preserves_named_rendering (names : List Bytes) (values : List Arg)
    (environment : Bytes → Option Arg) (source : List SourceSegment) (segments : List Segment)
    (aligned : SchemaIndex.Aligned names values environment)
    (meaning : List.Forall₂ (SegmentMeaning names) source segments) :
    renderPath values segments = namedPath environment source ∧
      pathError values segments = namedPathError environment source := by
  induction meaning with
  | nil => simp [renderPath, namedPath, pathError, namedPathError]
  | @cons source segment sources segments one rest ih =>
    have bytes : segmentBytes values segment = namedBytes environment source := by
      cases source <;> cases segment <;> simp only [SegmentMeaning] at one
      all_goals try contradiction
      · simpa [one.2, segmentBytes, namedBytes]
      · have exactName := SchemaIndex.indexed_argument_is_named _ _ _ aligned _ _ one.2.2
        simp [segmentBytes, namedBytes, exactName]
    have error : segmentError values segment = namedError environment source := by
      cases source <;> cases segment <;> simp only [SegmentMeaning] at one
      all_goals try contradiction
      · rfl
      · have exactName := SchemaIndex.indexed_argument_is_named _ _ _ aligned _ _ one.2.2
        simp [segmentError, namedError, exactName]
    constructor
    · simp [renderPath, namedPath, bytes, ih.1]
    · simp only [pathError, namedPathError, error]
      cases namedError environment source <;> simp [ih.2]

theorem lower_fixed_list_literals (source : List SourceSegment) (bytes : List Bytes)
    (lowered : lowerFixedList source = .ok bytes) :
    List.Forall₂ (fun source bytes => source = .fixed bytes ∧ FixedValid bytes) source bytes := by
  induction source generalizing bytes with
  | nil =>
    have empty : bytes = [] := by simpa [lowerFixedList] using lowered.symm
    simp [empty]
  | cons segment rest ih =>
    cases segment with
    | field _ => simp [lowerFixedList] at lowered
    | unsupported => simp [lowerFixedList] at lowered
    | fixed literal =>
      unfold lowerFixedList at lowered
      split at lowered
      · rename_i valid
        cases remaining : lowerFixedList rest with
        | error error => simp [remaining] at lowered
        | ok tail =>
          have same : literal :: tail = bytes := by simpa [remaining] using lowered
          subst bytes
          exact List.Forall₂.cons ⟨rfl, valid⟩ (ih tail remaining)
      · contradiction

theorem lowered_path_length_bound (names : List Bytes) (values : List Arg)
    (source : List SourceSegment) (segments : List Segment)
    (valuesBound : ∀ value ∈ values, ScalarProjection.PayloadLength value ≤ 4096)
    (meaning : List.Forall₂ (SegmentMeaning names) source segments) :
    (renderPath values segments).length ≤ 12289 * source.length := by
  induction meaning with
  | nil => simp [renderPath]
  | @cons original segment sources segments one rest ih =>
    have segmentBound : (segmentBytes values segment).length ≤ 12288 := by
      cases original with
      | unsupported => cases segment <;> exact False.elim one
      | fixed bytes =>
        cases segment with
        | field index => exact False.elim one
        | fixed actual =>
          have fixedSize := one.1.2.1
          have small : bytes.length ≤ 12288 := by omega
          simpa [segmentBytes, one.2] using small
      | field name =>
        cases segment with
        | fixed bytes => exact False.elim one
        | field index =>
          cases found : values[index]? with
          | none => simp [segmentBytes, found]
          | some argument =>
            have member := List.mem_iff_getElem?.mpr ⟨index, found⟩
            have bounded := valuesBound argument member
            cases argument with
            | text bytes =>
              have small : 3 * bytes.length ≤ 12288 := by simp only [ScalarProjection.PayloadLength] at bounded; omega
              simpa [segmentBytes, found] using (path_encode_length bytes).trans small
            | integer bytes => simp [segmentBytes, found]
            | boolean value => simp [segmentBytes, found]
    simp only [renderPath, List.flatMap_cons, List.length_append, List.length_cons] at *
    omega

end Auths.Product.PathCompiler
