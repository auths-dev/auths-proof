import Aeneas
import Mathlib.Tactic.Tauto

namespace Auths.Codec.SnapshotUniqueness

/-- Independent duplicate semantics compares full unsigned statement keys.
Signature-envelope differences cannot make the same statement distinct. -/
def scan {Key : Type} [DecidableEq Key] : List Key → List Key → Bool
  | _, [] => false
  | seen, first :: rest =>
      if first ∈ seen then true else scan (seen ++ [first]) rest

def hasDuplicate {Key : Type} [DecidableEq Key] (keys : List Key) : Bool := scan [] keys

theorem scan_false_iff {Key : Type} [DecidableEq Key] (seen remaining : List Key) :
    scan seen remaining = false ↔ remaining.Nodup ∧ ∀ key ∈ remaining, key ∉ seen := by
  induction remaining generalizing seen with
  | nil => simp [scan]
  | cons first rest ih =>
    by_cases earlier : first ∈ seen
    · simp only [scan, earlier, ↓reduceIte, Bool.true_eq_false, false_iff]
      rintro ⟨_, fresh⟩
      exact fresh first (by simp) earlier
    · rw [scan, if_neg earlier, ih]
      constructor
      · rintro ⟨restUnique, fresh⟩
        have firstAbsent : first ∉ rest := by
          intro member
          exact fresh first member (by simp)
        refine ⟨List.nodup_cons.mpr ⟨firstAbsent, restUnique⟩, ?_⟩
        intro key member
        rcases List.mem_cons.mp member with rfl | member
        · exact earlier
        · intro before
          exact fresh key member (List.mem_append.mpr (Or.inl before))
      · rintro ⟨unique, fresh⟩
        obtain ⟨notFirst, restUnique⟩ := List.nodup_cons.mp unique
        refine ⟨restUnique, ?_⟩
        intro key member before
        rcases List.mem_append.mp before with before | before
        · exact fresh key (by simp [member]) before
        · have same : key = first := List.mem_singleton.mp before
          subst key
          exact notFirst member

theorem no_duplicate_iff {Key : Type} [DecidableEq Key] (keys : List Key) :
    hasDuplicate keys = false ↔ keys.Nodup := by
  simpa [hasDuplicate] using scan_false_iff ([] : List Key) keys

theorem duplicate_iff {Key : Type} [DecidableEq Key] (keys : List Key) :
    hasDuplicate keys = true ↔ ¬ keys.Nodup := by
  have clean := no_duplicate_iff keys
  cases result : hasDuplicate keys <;> simp_all

theorem permutation_preserves {Key : Type} [DecidableEq Key] {left right : List Key}
    (permutation : left.Perm right) : hasDuplicate left = hasDuplicate right := by
  apply Bool.eq_iff_iff.mpr
  rw [duplicate_iff, duplicate_iff, permutation.nodup_iff]

def before {Key : Type} [DecidableEq Key] (keys : List Key) (current : Nat) : Bool :=
  match keys[current]? with
  | none => false
  | some key => decide (key ∈ keys.take current)

def search {Key : Type} [DecidableEq Key] (keys : List Key) (target : Key) : Nat → Nat → Bool
  | _, 0 => false
  | position, count + 1 =>
      match keys[position]? with
      | none => false
      | some key => decide (key = target) || search keys target (position + 1) count

def from {Key : Type} [DecidableEq Key] (keys : List Key) : Nat → Nat → Bool
  | _, 0 => false
  | position, count + 1 => before keys position || from keys (position + 1) count

theorem take_next {Key : Type} (keys : List Key) (position : Nat) (key : Key)
    (present : keys[position]? = some key) :
    keys.take (position + 1) = keys.take position ++ [key] := by
  induction position generalizing keys with
  | zero =>
    cases keys with
    | nil => simp at present
    | cons first rest =>
      have same : first = key := by simpa using present
      subst first
      rfl
  | succ position ih =>
    cases keys with
    | nil => simp at present
    | cons first rest =>
      have tail : rest[position]? = some key := by simpa using present
      simpa only [List.take_succ_cons, List.cons_append] using congrArg (List.cons first) (ih rest tail)

theorem search_eq_membership {Key : Type} [DecidableEq Key]
    (keys : List Key) (target : Key) (position count : Nat)
    (within : position + count ≤ keys.length) :
    search keys target position count = decide (target ∈ (keys.drop position).take count) := by
  induction count generalizing position with
  | zero => simp [search]
  | succ count ih =>
    have present : position < keys.length := by omega
    have suffix : keys.drop position = keys[position] :: keys.drop (position + 1) := by
      simpa using List.drop_eq_getElem_cons present
    have indexed : keys[position]? = some keys[position] := List.getElem?_eq_getElem present
    simp only [search, indexed, suffix, List.take_succ_cons, List.mem_cons,
      decide_or, ih (position + 1) (by omega)]
    congr 1
    exact Bool.eq_iff_iff.mpr (by simp [eq_comm])

theorem search_initial {Key : Type} [DecidableEq Key]
    (keys : List Key) (position : Nat) (key : Key)
    (present : keys[position]? = some key) :
    search keys key 0 position = before keys position := by
  have within := (List.getElem?_eq_some_iff.mp present).1
  simpa [before, present] using search_eq_membership keys key 0 position (by omega)

theorem from_eq_scan {Key : Type} [DecidableEq Key] (keys remaining : List Key)
    (position : Nat) (suffix : keys.drop position = remaining) :
    from keys position remaining.length = scan (keys.take position) remaining := by
  induction remaining generalizing position with
  | nil => simp [from, scan]
  | cons first rest ih =>
    have present : keys[position]? = some first := by
      have inside : position < keys.length := by
        have size := congrArg List.length suffix
        simp only [List.length_drop, List.length_cons] at size
        omega
      have decomposition := List.drop_eq_getElem_cons inside
      rw [suffix] at decomposition
      have same := (List.cons.inj decomposition).1
      simpa only [List.getElem?_eq_getElem inside] using congrArg some same.symm
    have tail : keys.drop (position + 1) = rest := by
      have dropped := congrArg (List.drop 1) suffix
      simpa only [List.drop_drop, Nat.add_comm position 1, List.drop_succ_cons, List.drop_zero] using dropped
    have next := take_next keys position first present
    simp only [List.length_cons, from, before, present]
    by_cases seen : first ∈ keys.take position
    · simp [seen, scan]
    · simp only [seen, decide_false, Bool.false_or, scan, ↓reduceIte]
      simpa only [next] using ih (position + 1) tail

theorem complete_scan_exact {Key : Type} [DecidableEq Key] (keys : List Key) :
    from keys 0 keys.length = hasDuplicate keys := by
  simpa [hasDuplicate] using from_eq_scan keys keys 0 (by simp)

theorem complete_refusal_iff {Key : Type} [DecidableEq Key] (keys : List Key) :
    from keys 0 keys.length = true ↔ ¬ keys.Nodup := by
  rw [complete_scan_exact, duplicate_iff]

/-- Independent snapshot-carrier obligations earned by the statement checks.
The key is the whole unsigned statement; callers cannot substitute its partial
sorting key, a signature, or a collision-prone content identifier. -/
def WellFormed {Entry Key : Type} (key : Entry → Key)
    (observed valid : Entry → Nat) (starts ends maximum : Nat) (entries : List Entry) : Prop :=
  starts ≤ ends ∧ entries.length ≤ maximum ∧ (entries.map key).Nodup ∧
    ∀ entry ∈ entries, observed entry ≤ starts ∧ ends ≤ valid entry

/-- The worst-case number of statement comparisons in a complete prefix scan.
The cost of a comparison's fields/bytes remains a separate leaf charge. -/
def comparisonEnvelope : Nat → Nat
  | 0 => 0
  | count + 1 => comparisonEnvelope count + count

def searchProbes {Key : Type} [DecidableEq Key]
    (keys : List Key) (target : Key) : Nat → Nat → Nat
  | _, 0 => 0
  | position, count + 1 =>
      match keys[position]? with
      | none => 0
      | some key => if key = target then 1 else 1 + searchProbes keys target (position + 1) count

def probes {Key : Type} [DecidableEq Key] (keys : List Key) : Nat → Nat → Nat
  | _, 0 => 0
  | position, count + 1 =>
      let first := match keys[position]? with
        | none => 0
        | some key => searchProbes keys key 0 position
      if before keys position then first else first + probes keys (position + 1) count

theorem search_probe_bound {Key : Type} [DecidableEq Key]
    (keys : List Key) (target : Key) (position count : Nat) :
    searchProbes keys target position count ≤ count := by
  induction count generalizing position with
  | zero => simp [searchProbes]
  | succ count ih =>
    simp only [searchProbes]
    split
    · omega
    · split
      · omega
      · have tail := ih (position + 1)
        omega

theorem probe_bound {Key : Type} [DecidableEq Key]
    (keys : List Key) (position count : Nat) :
    probes keys position count ≤ count * position + comparisonEnvelope count := by
  induction count generalizing position with
  | zero => simp [probes, comparisonEnvelope]
  | succ count ih =>
    have first : (match keys[position]? with
        | none => 0
        | some key => searchProbes keys key 0 position) ≤ position := by
      split
      · omega
      · exact search_probe_bound _ _ _ _
    have tail := ih (position + 1)
    simp only [probes]
    split
    · simp only [Nat.succ_mul, comparisonEnvelope]
      omega
    · simp only [Nat.mul_succ] at tail
      simp only [Nat.succ_mul, comparisonEnvelope]
      omega

theorem envelope_monotone {smaller larger : Nat} (bound : smaller ≤ larger) :
    comparisonEnvelope smaller ≤ comparisonEnvelope larger := by
  induction larger generalizing smaller with
  | zero => have zero : smaller = 0 := by omega; simp [zero]
  | succ larger ih =>
    by_cases before : smaller ≤ larger
    · have previous := ih before
      simp only [comparisonEnvelope]
      omega
    · have same : smaller = larger + 1 := by omega
      simp [same]

/-- Model comparison-call bound at the actual constructor cardinality limit.
This is not a whole-constructor runtime theorem: concrete loop trace linkage,
sorting work, field-comparison byte costs and allocations must also compose. -/
theorem bounded_snapshot_comparisons {Key : Type} [DecidableEq Key]
    (keys : List Key) (bounded : keys.length ≤ 512) : probes keys 0 keys.length ≤ 130816 := by
  have counts := probe_bound keys 0 keys.length
  have envelope := envelope_monotone bounded
  have maximum : comparisonEnvelope 512 = 130816 := by decide
  simp only [Nat.mul_zero, Nat.zero_add] at counts
  omega

-- A/B/A has no adjacent equal full statements, while all three partial sort
-- keys coincide. This is the constructor gap addressed by the source scans.
private def separated : List (Nat × Nat) := [(0, 0), (0, 1), (0, 0)]

example : hasDuplicate separated = true := by decide
example : separated.Pairwise (fun left right => left.1 ≤ right.1) := by decide
example : (separated.zip separated.tail).all (fun pair => decide (pair.1 ≠ pair.2)) = true := by decide

end Auths.Codec.SnapshotUniqueness
