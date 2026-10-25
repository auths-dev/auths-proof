import Aeneas

namespace Auths.Codec.CollectionWork

/-- A reader's semantic step includes its failure cursor and a named abstract
work charge. The charge includes primitive parsing, validation and copying;
this model does not assign a wall-clock or allocator-time cost. -/
structure Step (Value Failure State : Type) where
  outcome : Except Failure Value
  next : State
  work : Nat

/-- `produced` records successful elements even when the final result is an
error and the temporary vector is discarded. `attempted` includes the failing
reader call. Source loop guards, branch/push bookkeeping and counter updates
are charged six abstract units per attempted element, plus two at completion. -/
structure Batch (Value Failure State : Type) where
  outcome : Except Failure (List Value)
  next : State
  produced : Nat
  attempted : Nat
  work : Nat

/-- Independent first-error collection semantics. The checked array length is
supplied by the schema parser. The element reader is fixed by each concrete
schema, not selected by an untrusted request. -/
def run {Value Failure State : Type}
    (read : State → Step Value Failure State) : Nat → State → Batch Value Failure State
  | 0, initial => ⟨.ok [], initial, 0, 0, 2⟩
  | count + 1, initial =>
      let first := read initial
      match first.outcome with
      | .error failure => ⟨.error failure, first.next, 0, 1, first.work + 6⟩
      | .ok value =>
          let tail := run read count first.next
          ⟨tail.outcome.map (value :: ·), tail.next, tail.produced + 1,
            tail.attempted + 1, first.work + 6 + tail.work⟩

/-- Semantic success transitions, retaining the actual reader state at every
edge. This relation never equates success with an implementation verdict. -/
inductive Successes {Value Failure State : Type}
    (read : State → Step Value Failure State) : List Value → State → State → Prop
  | nil (state : State) : Successes read [] state state
  | cons (initial : State) (value : Value) (remaining : List Value) (final : State)
      (first : (read initial).outcome = .ok value)
      (tail : Successes read remaining (read initial).next final) :
      Successes read (value :: remaining) initial final

/-- The whole collection terminates within its declared attempt and abstract
work envelopes, including errors. The element bound must hold for all reached
states; it cannot be restricted to already-successful reads. -/
theorem bounds {Value Failure State : Type}
    (read : State → Step Value Failure State) (maximum : Nat)
    (elementBound : ∀ state, (read state).work ≤ maximum)
    (count : Nat) (initial : State) :
    (run read count initial).produced ≤ (run read count initial).attempted ∧
      (run read count initial).attempted ≤ count ∧
      (run read count initial).work ≤ 2 + (maximum + 6) * count := by
  induction count generalizing initial with
  | zero => simp [run]
  | succ count ih =>
    have firstBound := elementBound initial
    cases first : (read initial).outcome with
    | error failure =>
      simp only [run, first]
      refine ⟨by omega, by omega, ?_⟩
      rw [Nat.mul_succ]
      omega
    | ok value =>
      have tail := ih (read initial).next
      simp only [run, first]
      refine ⟨by omega, by omega, ?_⟩
      rw [Nat.mul_succ]
      omega

/-- Every successful collection contains exactly the declared number of
constructor outputs. This excludes truncating a list while reporting success. -/
theorem successful_count {Value Failure State : Type}
    (read : State → Step Value Failure State) (count : Nat) (initial : State)
    (values : List Value) (accepted : (run read count initial).outcome = .ok values) :
    values.length = count ∧ (run read count initial).produced = count ∧
      (run read count initial).attempted = count := by
  induction count generalizing initial values with
  | zero =>
    have empty : values = [] := by simpa [run] using accepted.symm
    subst values
    simp [run]
  | succ count ih =>
    cases first : (read initial).outcome with
    | error failure => simp [run, first] at accepted
    | ok value =>
      cases rest : (run read count (read initial).next).outcome with
      | error failure => simp [run, first, rest] at accepted
      | ok tail =>
        have same : value :: tail = values := by simpa [run, first, rest] using accepted
        have tailCount := ih (read initial).next tail rest
        subst values
        simp only [List.length_cons, run, first]
        exact ⟨by omega, by omega, by omega⟩

/-- A failed traversal attempted precisely one more element than it produced.
There are no later reads after the first failure. -/
theorem failed_count {Value Failure State : Type}
    (read : State → Step Value Failure State) (count : Nat) (initial : State)
    (failure : Failure) (rejected : (run read count initial).outcome = .error failure) :
    (run read count initial).attempted = (run read count initial).produced + 1 ∧
      (run read count initial).produced < count := by
  induction count generalizing initial with
  | zero => simp [run] at rejected
  | succ count ih =>
    cases first : (read initial).outcome with
    | error error => simp [run, first]
    | ok value =>
      cases rest : (run read count (read initial).next).outcome with
      | ok tail => simp [run, first, rest] at rejected
      | error error =>
        have same : error = failure := by simpa [run, first, rest] using rejected
        subst error
        have tail := ih (read initial).next rest
        simp only [run, first]
        exact ⟨by omega, by omega⟩

/-- Success earns an exact chain of element-reader transitions. Mutable cursor
and writer-prefix facts can be transported along this chain, rather than
assumed at the final collection boundary. -/
theorem successful_trace {Value Failure State : Type}
    (read : State → Step Value Failure State) (count : Nat) (initial : State)
    (values : List Value) (accepted : (run read count initial).outcome = .ok values) :
    Successes read values initial (run read count initial).next := by
  induction count generalizing initial values with
  | zero =>
    have empty : values = [] := by simpa [run] using accepted.symm
    subst values
    exact .nil initial
  | succ count ih =>
    cases first : (read initial).outcome with
    | error failure => simp [run, first] at accepted
    | ok value =>
      cases rest : (run read count (read initial).next).outcome with
      | error failure => simp [run, first, rest] at accepted
      | ok tail =>
        have same : value :: tail = values := by simpa [run, first, rest] using accepted
        subst values
        simpa only [run, first] using Successes.cons initial value tail
          (run read count (read initial).next).next first
          (ih (read initial).next tail rest)

/-- Error provenance includes the exact successful prefix and the failing
reader's resulting state. An error cannot be replaced by a later reader's
error or accompanied by mutation after the failing step. -/
theorem failure_trace {Value Failure State : Type}
    (read : State → Step Value Failure State) (count : Nat) (initial : State)
    (failure : Failure) (rejected : (run read count initial).outcome = .error failure) :
    ∃ prefix before,
      Successes read prefix initial before ∧
      (read before).outcome = .error failure ∧
      (run read count initial).next = (read before).next ∧
      prefix.length = (run read count initial).produced ∧ prefix.length < count := by
  induction count generalizing initial with
  | zero => simp [run] at rejected
  | succ count ih =>
    cases first : (read initial).outcome with
    | error error =>
      have same : error = failure := by simpa [run, first] using rejected
      subst error
      refine ⟨[], initial, .nil initial, first, ?_⟩
      simp [run, first]
    | ok value =>
      cases rest : (run read count (read initial).next).outcome with
      | ok tail => simp [run, first, rest] at rejected
      | error error =>
        have same : error = failure := by simpa [run, first, rest] using rejected
        subst error
        obtain ⟨prefix, before, trace, fails, finalState, length, shorter⟩ :=
          ih (read initial).next rest
        refine ⟨value :: prefix, before,
          .cons initial value prefix before first trace, fails, ?_⟩
        simp only [run, first, List.length_cons]
        exact ⟨finalState, by omega, by omega⟩

/-- Any state invariant established by every successful element survives the
entire successful collection. No failing element is given that premise. -/
theorem success_invariant {Value Failure State : Type}
    (read : State → Step Value Failure State) (invariant : State → Prop)
    (stepPreserves : ∀ state value, invariant state →
      (read state).outcome = .ok value → invariant (read state).next)
    {values : List Value} {initial final : State}
    (trace : Successes read values initial final) (starts : invariant initial) : invariant final := by
  induction trace with
  | nil => exact starts
  | cons initial value remaining final first tail ih =>
    exact ih (stepPreserves initial value starts first)

/-- Explicit allocation accounting for a preallocated element vector: no
successful push can require capacity beyond the checked declared count. -/
theorem vector_allocation_bound {Value Failure State : Type}
    (read : State → Step Value Failure State) (maximum : Nat)
    (elementBound : ∀ state, (read state).work ≤ maximum)
    (count : Nat) (initial : State) :
    (run read count initial).produced ≤ count := by
  have bounded := bounds read maximum elementBound count initial
  omega

/-- A cursor/potential charge avoids multiplying the whole input byte bound by
the element count. A failing parse is included: any scan that does not advance
the cursor must be covered by the fixed per-element charge. -/
theorem amortized_bound {Value Failure State : Type}
    (read : State → Step Value Failure State) (measure : State → Nat)
    (fixed perUnit : Nat)
    (elementBound : ∀ state, measure state ≤ measure (read state).next ∧
      (read state).work ≤ fixed + perUnit * (measure (read state).next - measure state))
    (count : Nat) (initial : State) :
    measure initial ≤ measure (run read count initial).next ∧
      (run read count initial).work ≤ 2 + (fixed + 6) * count +
        perUnit * (measure (run read count initial).next - measure initial) := by
  induction count generalizing initial with
  | zero => simp [run]
  | succ count ih =>
    obtain ⟨firstProgress, firstWork⟩ := elementBound initial
    cases first : (read initial).outcome with
    | error failure =>
      simp only [run, first]
      refine ⟨firstProgress, ?_⟩
      rw [Nat.mul_succ]
      omega
    | ok value =>
      obtain ⟨tailProgress, tailWork⟩ := ih (read initial).next
      have telescopes :
          measure (run read count (read initial).next).next - measure initial =
            (measure (read initial).next - measure initial) +
              (measure (run read count (read initial).next).next - measure (read initial).next) := by
        omega
      simp only [run, first]
      refine ⟨by omega, ?_⟩
      rw [Nat.mul_succ, telescopes, Nat.mul_add]
      have sumBound := Nat.add_le_add firstWork tailWork
      omega

/-- Once the source parser earns cursor confinement, work is linear in the
checked count and total consumed input. This applies to refusals as well as
accepted collections, and includes an element reader's byte-copy charge. -/
theorem input_work_bound {Value Failure State : Type}
    (read : State → Step Value Failure State) (measure : State → Nat)
    (fixed perByte : Nat)
    (elementBound : ∀ state, measure state ≤ measure (read state).next ∧
      (read state).work ≤ fixed + perByte * (measure (read state).next - measure state))
    (count : Nat) (initial : State) (inputBytes : Nat)
    (confined : measure (run read count initial).next ≤ inputBytes) :
    (run read count initial).work ≤ 2 + (fixed + 6) * count + perByte * inputBytes := by
  have bounded := (amortized_bound read measure fixed perByte elementBound count initial).2
  have spanBound : measure (run read count initial).next - measure initial ≤ inputBytes := by
    omega
  have charged := Nat.mul_le_mul_left perByte spanBound
  omega

-- This module supplies independent model lemmas. Actual Rust loop refinements,
-- primitive cost contracts and enclosing schema bounds remain separate source
-- obligations; none of these lemmas alone is a whole-codec work theorem.

end Auths.Codec.CollectionWork
