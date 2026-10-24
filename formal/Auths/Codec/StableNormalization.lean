import Mathlib.Data.List.Sort
import Mathlib.Data.Prod.Lex
import Mathlib.Tactic

namespace Auths.Codec.StableNormalization

/- Independent stable normalization. Keys may collide and records need not
have decidable equality. A normal form orders keys and retains the complete
sequence within every equal-key class; it never deduplicates those records.
No source encoder, decoder, successful result or cryptographic assumption is
part of the definitions below. -/

variable {Value Key : Type} [LinearOrder Key]

def before (key : Value → Key) (left right : Value) : Prop := key left ≤ key right

instance before_decidable (key : Value → Key) : DecidableRel (before key) :=
  fun _ _ => inferInstanceAs (Decidable (_ ≤ _))

instance before_total (key : Value → Key) : Std.Total (before key) :=
  ⟨fun _ _ => le_total _ _⟩

instance before_trans (key : Value → Key) : IsTrans Value (before key) :=
  ⟨fun _ _ _ left right => le_trans left right⟩

def sort (key : Value → Key) (values : List Value) : List Value :=
  values.insertionSort (before key)

def bucket (key : Value → Key) (target : Key) (values : List Value) : List Value :=
  values.filter (fun value => decide (key value = target))

theorem permutation (key : Value → Key) (values : List Value) :
    (sort key values).Perm values := List.perm_insertionSort _ _

theorem ordered (key : Value → Key) (values : List Value) :
    (sort key values).Pairwise (before key) := List.pairwise_insertionSort _ _

theorem fixed (key : Value → Key) (values : List Value)
    (normal : values.Pairwise (before key)) : sort key values = values :=
  List.Pairwise.insertionSort_eq normal

theorem idempotent (key : Value → Key) (values : List Value) :
    sort key (sort key values) = sort key values := fixed key _ (ordered key values)

theorem insert_congr_on (leftKey rightKey : Value → Key)
    (item : Value) (values : List Value)
    (itemSame : leftKey item = rightKey item)
    (keysSame : ∀ value ∈ values, leftKey value = rightKey value) :
    values.orderedInsert (before leftKey) item =
      values.orderedInsert (before rightKey) item := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    have firstSame := keysSame first (by simp)
    have restSame : ∀ value ∈ rest, leftKey value = rightKey value :=
      fun value member => keysSame value (by simp [member])
    by_cases next : rightKey item ≤ rightKey first
    · simp [List.orderedInsert_cons, before, itemSame, firstSame, next]
    · simp [List.orderedInsert_cons, before, itemSame, firstSame, next, ih restSame]

/-- Sorting only observes keys of members of this input. No global key
equality, record equality or key injectivity is required. -/
theorem sort_congr_on (leftKey rightKey : Value → Key) (values : List Value)
    (keysSame : ∀ value ∈ values, leftKey value = rightKey value) :
    sort leftKey values = sort rightKey values := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    have firstSame := keysSame first (by simp)
    have restSame : ∀ value ∈ rest, leftKey value = rightKey value :=
      fun value member => keysSame value (by simp [member])
    change (sort leftKey rest).orderedInsert (before leftKey) first =
      (sort rightKey rest).orderedInsert (before rightKey) first
    rw [ih restSame]
    apply insert_congr_on leftKey rightKey first _ firstSame
    intro value member
    exact restSame value ((permutation rightKey rest).mem_iff.mp member)

theorem map_insert {Output : Type} (project : Value → Output) (key : Output → Key)
    (item : Value) (values : List Value) :
    (values.orderedInsert (before (fun value => key (project value))) item).map project =
      (values.map project).orderedInsert (before key) (project item) := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    by_cases next : key (project item) ≤ key (project first)
    · simp [List.orderedInsert_cons, before, next]
    · simp [List.orderedInsert_cons, before, next, ih]

/-- Stable sorting commutes with a payload projection when comparisons use
the projected key. The projection may be many-to-one. -/
theorem map_sort {Output : Type} (project : Value → Output) (key : Output → Key)
    (values : List Value) :
    (sort (fun value => key (project value)) values).map project =
      sort key (values.map project) := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    change ((sort (fun value => key (project value)) rest).orderedInsert
      (before (fun value => key (project value))) first).map project =
        (sort key (rest.map project)).orderedInsert (before key) (project first)
    rw [map_insert, ih]

theorem before_some (key : Value → Key) :
    before (fun value => some (key value)) = before key := by
  funext left right
  simp [before]

theorem sort_some (key : Value → Key) (values : List Value) :
    sort (fun value => some (key value)) values = sort key values := by
  simp only [sort, before_some]

private theorem pairwise_from_members (relation : Value → Value → Prop)
    (values : List Value)
    (related : ∀ left ∈ values, ∀ right ∈ values, relation left right) :
    values.Pairwise relation := by
  revert related
  induction values with
  | nil => intro _; exact List.Pairwise.nil
  | cons first rest ih =>
    intro related
    apply List.pairwise_cons.mpr
    refine ⟨?_, ih ?_⟩
    · intro value member
      exact related first (by simp) value (by simp [member])
    · intro left leftMember right rightMember
      exact related left (by simp [leftMember]) right (by simp [rightMember])

/-- Sorting retains the complete selected subsequence whenever all selected
records are mutually comparable in the insertion relation. This includes
equal-key classes and joint-key classes refined by a coarser sorting key. -/
theorem filter_sort_eq (relation : Value → Value → Prop) [DecidableRel relation]
    (keep : Value → Bool)
    (tied : ∀ left right, keep left = true → keep right = true → relation left right)
    (values : List Value) :
    (values.insertionSort relation).filter keep = values.filter keep := by
  have selectedOrdered : (values.filter keep).Pairwise relation := by
    apply pairwise_from_members
    intro left leftMember right rightMember
    exact tied left right (List.mem_filter.mp leftMember).2 (List.mem_filter.mp rightMember).2
  have selectedBefore : values.filter keep <+ values.insertionSort relation :=
    List.sublist_insertionSort selectedOrdered (List.filter_sublist)
  have selectedAfter : values.filter keep <+ (values.insertionSort relation).filter keep := by
    simpa [List.filter_filter] using selectedBefore.filter keep
  have sameLength := ((List.perm_insertionSort relation values).filter keep).length_eq
  exact (selectedAfter.eq_of_length sameLength.symm).symm

theorem bucket_preserved (key : Value → Key) (target : Key) (values : List Value) :
    bucket key target (sort key values) = bucket key target values := by
  unfold bucket sort
  apply filter_sort_eq
  intro left right leftSelected rightSelected
  have leftKey : key left = target := of_decide_eq_true leftSelected
  have rightKey : key right = target := of_decide_eq_true rightSelected
  simp [before, leftKey, rightKey]

theorem refined_bucket_preserved {Refined : Type} [DecidableEq Refined]
    (key : Value → Key) (refined : Value → Refined)
    (refines : ∀ left right, refined left = refined right → key left = key right)
    (target : Refined) (values : List Value) :
    (sort key values).filter (fun value => decide (refined value = target)) =
      values.filter (fun value => decide (refined value = target)) := by
  unfold sort
  apply filter_sort_eq
  intro left right leftSelected rightSelected
  have leftKey : refined left = target := of_decide_eq_true leftSelected
  have rightKey : refined right = target := of_decide_eq_true rightSelected
  have same := refines left right (leftKey.trans rightKey.symm)
  simp [before, same]

private theorem head_le_member (key : Value → Key) (first : Value) (rest : List Value)
    (normal : (first :: rest).Pairwise (before key))
    (value : Value) (member : value ∈ first :: rest) : key first ≤ key value := by
  rcases List.mem_cons.mp member with same | member
  · subst value
    exact le_rfl
  · exact (List.pairwise_cons.mp normal).1 value member

/-- Ordered keys, a complete permutation and identical equal-key sequences
determine the exact record list. Antisymmetry is required only of keys;
distinct records with equal keys are permitted. -/
theorem eq_of_ordered_perm_buckets (key : Value → Key) (left right : List Value)
    (leftOrdered : left.Pairwise (before key))
    (rightOrdered : right.Pairwise (before key))
    (same : left.Perm right)
    (ties : ∀ target, bucket key target left = bucket key target right) : left = right := by
  revert leftOrdered rightOrdered same ties
  induction left generalizing right with
  | nil =>
    intro _ _ same _
    have length := same.length_eq
    have empty : right.length = 0 := by simpa using length.symm
    exact (List.length_eq_zero.mp empty).symm
  | cons first rest ih =>
    intro leftOrdered rightOrdered same ties
    cases right with
    | nil => have length := same.length_eq; simp at length
    | cons other remaining =>
      have otherMember : other ∈ first :: rest := same.mem_iff.mpr (by simp)
      have firstMember : first ∈ other :: remaining := same.mem_iff.mp (by simp)
      have keys : key first = key other := le_antisymm
        (head_le_member key first rest leftOrdered other otherMember)
        (head_le_member key other remaining rightOrdered first firstMember)
      have selected : first :: bucket key (key first) rest =
          other :: bucket key (key first) remaining := by
        simpa [bucket, keys.symm] using ties (key first)
      have heads : first = other := (List.cons.inj selected).1
      subst other
      congr 1
      apply ih (List.pairwise_cons.mp leftOrdered).2 (List.pairwise_cons.mp rightOrdered).2
        (List.Perm.cons_inv same)
      intro target
      have selected := ties target
      by_cases selectedHead : key first = target
      · have selected : first :: bucket key target rest = first :: bucket key target remaining := by
          simpa [bucket, selectedHead] using selected
        exact (List.cons.inj selected).2
      · simpa [bucket, selectedHead] using selected

section TwoKeys
variable {Primary Secondary : Type} [LinearOrder Primary] [LinearOrder Secondary]
variable (primary : Value → Primary) (secondary : Value → Secondary)

def jointKey (value : Value) : Primary ×ₗ Secondary := toLex (primary value, secondary value)

theorem joint_le (left right : Value) :
    before (jointKey primary secondary) left right ↔
      primary left < primary right ∨
        primary left = primary right ∧ secondary left ≤ secondary right :=
  Prod.Lex.toLex_le_toLex

theorem primary_le_of_joint {left right : Value}
    (related : before (jointKey primary secondary) left right) : primary left ≤ primary right := by
  rcases (joint_le primary secondary left right).mp related with strict | ⟨same, _⟩
  · exact le_of_lt strict
  · exact le_of_eq same

theorem joint_primary_eq (left right : Value)
    (same : jointKey primary secondary left = jointKey primary secondary right) :
    primary left = primary right := by
  exact congrArg (fun value : Primary ×ₗ Secondary => (ofLex value).1) same

theorem joint_secondary_eq (left right : Value)
    (same : jointKey primary secondary left = jointKey primary secondary right) :
    secondary left = secondary right := by
  exact congrArg (fun value : Primary ×ₗ Secondary => (ofLex value).2) same

private theorem insert_primary_ordered (item : Value) (values : List Value)
    (normal : values.Pairwise (before (jointKey primary secondary)))
    (secondaryLeast : ∀ value ∈ values, secondary item ≤ secondary value) :
    (values.orderedInsert (before primary) item).Pairwise (before (jointKey primary secondary)) := by
  revert normal secondaryLeast
  induction values with
  | nil => intro _ _; simp
  | cons first rest ih =>
    intro normal secondaryLeast
    obtain ⟨fromFirst, restNormal⟩ := List.pairwise_cons.mp normal
    by_cases position : primary item ≤ primary first
    · rw [List.orderedInsert_cons, if_pos position]
      apply List.pairwise_cons.mpr
      refine ⟨?_, normal⟩
      intro value member
      have headBound := head_le_member (jointKey primary secondary) first rest normal value member
      have primaryBound := le_trans position (primary_le_of_joint primary secondary headBound)
      apply (joint_le primary secondary item value).mpr
      rcases lt_or_eq_of_le primaryBound with strict | same
      · exact Or.inl strict
      · exact Or.inr ⟨same, secondaryLeast value member⟩
    · rw [List.orderedInsert_cons, if_neg position]
      apply List.pairwise_cons.mpr
      refine ⟨?_, ih restNormal (fun value member => secondaryLeast value (by simp [member]))⟩
      intro value member
      rcases (List.mem_orderedInsert (before primary)).mp member with same | member
      · subst value
        exact (joint_le primary secondary first item).mpr (Or.inl (lt_of_not_ge position))
      · exact fromFirst value member

theorem primary_sort_of_secondary_ordered (values : List Value)
    (secondaryOrdered : values.Pairwise (before secondary)) :
    (sort primary values).Pairwise (before (jointKey primary secondary)) := by
  revert secondaryOrdered
  induction values with
  | nil => intro _; simp [sort]
  | cons first rest ih =>
    intro secondaryOrdered
    obtain ⟨least, restOrdered⟩ := List.pairwise_cons.mp secondaryOrdered
    change ((sort primary rest).orderedInsert (before primary) first).Pairwise _
    apply insert_primary_ordered primary secondary first _ (ih restOrdered)
    intro value member
    exact least value ((permutation primary rest).mem_iff.mp member)

/-- A stable primary pass after a stable secondary pass is the single
independent lexicographic normalizer, including the exact order of records
whose complete keys tie. -/
theorem two_pass_eq (values : List Value) :
    sort primary (sort secondary values) = sort (jointKey primary secondary) values := by
  apply eq_of_ordered_perm_buckets (jointKey primary secondary)
  · exact primary_sort_of_secondary_ordered primary secondary _ (ordered secondary values)
  · exact ordered _ _
  · exact ((permutation primary _).trans (permutation secondary values)).trans
      (permutation (jointKey primary secondary) values).symm
  · intro target
    change (sort primary (sort secondary values)).filter _ =
      (sort (jointKey primary secondary) values).filter _
    rw [refined_bucket_preserved primary (jointKey primary secondary)
      (joint_primary_eq primary secondary)]
    rw [refined_bucket_preserved secondary (jointKey primary secondary)
      (joint_secondary_eq primary secondary)]
    exact (bucket_preserved (jointKey primary secondary) target values).symm

def storage (values : List Value) : List Value := sort primary (sort secondary values)

theorem storage_permutation (values : List Value) :
    (storage primary secondary values).Perm values :=
  (permutation primary _).trans (permutation secondary values)

theorem storage_ordered (values : List Value) :
    (storage primary secondary values).Pairwise (before (jointKey primary secondary)) :=
  primary_sort_of_secondary_ordered primary secondary _ (ordered secondary values)

theorem storage_fixed (values : List Value)
    (normal : values.Pairwise (before (jointKey primary secondary))) :
    storage primary secondary values = values := by
  rw [storage, two_pass_eq]
  exact fixed _ _ normal

theorem storage_normal_form_iff (values : List Value) :
    storage primary secondary values = values ↔
      values.Pairwise (before (jointKey primary secondary)) := by
  constructor
  · intro same
    simpa only [same] using storage_ordered primary secondary values
  · exact storage_fixed primary secondary values

theorem storage_idempotent (values : List Value) :
    storage primary secondary (storage primary secondary values) = storage primary secondary values :=
  storage_fixed primary secondary _ (storage_ordered primary secondary values)

theorem storage_length (values : List Value) :
    (storage primary secondary values).length = values.length :=
  (storage_permutation primary secondary values).length_eq

theorem storage_fields (field : Value → Prop) (values : List Value) :
    (∀ value ∈ storage primary secondary values, field value) ↔ ∀ value ∈ values, field value := by
  have same := storage_permutation primary secondary values
  constructor
  · intro valid value member
    exact valid value (same.mem_iff.mpr member)
  · intro valid value member
    exact valid value (same.mem_iff.mp member)

theorem storage_count [DecidableEq Value] (value : Value) (values : List Value) :
    (storage primary secondary values).count value = values.count value :=
  (storage_permutation primary secondary values).count_eq value

/-- A constructor-valid raw snapshot is already primary-ordered. Refining
its tied primary groups into ID order preserves the old ID-ordered wire
sequence exactly. This needs primary ordering, not hash injectivity. -/
theorem wire_preserved (values : List Value) (primaryOrdered : values.Pairwise (before primary)) :
    sort secondary (storage primary secondary values) = sort secondary values := by
  apply eq_of_ordered_perm_buckets (jointKey secondary primary)
  · apply primary_sort_of_secondary_ordered secondary primary
    exact (storage_ordered primary secondary values).imp
      (fun {_ _} related => primary_le_of_joint primary secondary related)
  · exact primary_sort_of_secondary_ordered secondary primary values primaryOrdered
  · exact ((permutation secondary _).trans (storage_permutation primary secondary values)).trans
      (permutation secondary values).symm
  · intro target
    unfold bucket storage
    simp only [refined_bucket_preserved secondary (jointKey secondary primary)
      (joint_primary_eq secondary primary),
      refined_bucket_preserved primary (jointKey secondary primary)
        (joint_secondary_eq secondary primary)]

end TwoKeys
end Auths.Codec.StableNormalization
