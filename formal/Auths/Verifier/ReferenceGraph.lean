import Mathlib.Tactic

/-!
Independent semantics of the verifier's grant-reference walk. Keys are generic;
no signature, hash, context or authorization outcome is assumed here. A finite
graph names the records present in the proof, including parents which may be
missing or cyclic. A valid chain states every link and excludes repetition.

The executable model uses ghost fuel equal to the number of records. The
remaining-domain argument proves that exhaustion is unreachable: a scan finds
a root, a missing record or a cycle within that bound. The shipping Rust walk
has no fuel refusal; linking its cursor/visited/used state to this model remains
the source-refinement obligation, rather than an assumed outcome premise.
-/

namespace Auths.Verifier.ReferenceGraph

variable {Key : Type} [DecidableEq Key]

structure Graph (Key : Type) [DecidableEq Key] where
  domain : Finset Key
  parent : Key → Option (Option Key)
  known_iff : ∀ key, (∃ next, parent key = some next) ↔ key ∈ domain

inductive Failure where
  | cycle
  | missing
  | exhausted
  | unused
  deriving DecidableEq, Repr

/-- A complete path through exactly the named records to a root. -/
inductive Chain (graph : Graph Key) : Option Key → List Key → Prop
  | done : Chain graph none []
  | link {key : Key} {next : Option Key} {rest : List Key}
      (known : graph.parent key = some next)
      (tail : Chain graph next rest)
      (fresh : key ∉ rest) : Chain graph (some key) (key :: rest)

def walk (graph : Graph Key) (fuel : Nat) (seen : Finset Key) (cursor : Option Key) :
    Except Failure (List Key) :=
  match cursor with
  | none => .ok []
  | some key =>
    if key ∈ seen then .error .cycle
    else match graph.parent key with
      | none => .error .missing
      | some next => match fuel with
        | 0 => .error .exhausted
        | remaining + 1 =>
          match walk graph remaining (insert key seen) next with
          | .error failure => .error failure
          | .ok rest => .ok (key :: rest)
termination_by fuel

/-- Number of entered cursor steps, including the step which discovers a
missing record or cycle. This counts graph steps, not comparison-byte or hash
work, which belong to the source cost composition. -/
def calls (graph : Graph Key) (fuel : Nat) (seen : Finset Key) (cursor : Option Key) : Nat :=
  match cursor with
  | none => 0
  | some key =>
    if key ∈ seen then 1
    else match graph.parent key with
      | none => 1
      | some next => match fuel with
        | 0 => 1
        | remaining + 1 => 1 + calls graph remaining (insert key seen) next
termination_by fuel

theorem cursor_call_bound (graph : Graph Key) (fuel : Nat) (seen : Finset Key) (cursor : Option Key) :
    calls graph fuel seen cursor ≤ fuel + 1 := by
  induction fuel generalizing seen cursor with
  | zero =>
    cases cursor with
    | none => simp [calls]
    | some key =>
      by_cases visited : key ∈ seen
      · simp [calls, visited]
      · cases known : graph.parent key <;> simp [calls, visited, known]
  | succ fuel ih =>
    cases cursor with
    | none => simp [calls]
    | some key =>
      by_cases visited : key ∈ seen
      · simp [calls, visited]
      · cases known : graph.parent key with
        | none => simp [calls, visited, known]
        | some next =>
          have tail := ih (insert key seen) next
          rw [calls, if_neg visited, known]
          omega

theorem remaining_after_insert (domain seen : Finset Key) (key : Key) :
    domain \ insert key seen = (domain \ seen).erase key := by
  ext value
  simp only [Finset.mem_sdiff, Finset.mem_insert, Finset.mem_erase]
  tauto

/-- Fuel bounds the unvisited records, rather than trusting a requested chain
depth. Missing parents and cycles remain explicit typed failures. -/
theorem exhaustion_unreachable (graph : Graph Key) (fuel : Nat) (seen : Finset Key)
    (cursor : Option Key) (enough : (graph.domain \ seen).card ≤ fuel) :
    walk graph fuel seen cursor ≠ .error .exhausted := by
  induction fuel generalizing seen cursor with
  | zero =>
    cases cursor with
    | none => simp [walk]
    | some key =>
      by_cases visited : key ∈ seen
      · simp [walk, visited]
      · cases known : graph.parent key with
        | none => simp [walk, visited, known]
        | some next =>
          have present : key ∈ graph.domain := (graph.known_iff key).mp ⟨next, known⟩
          have member : key ∈ graph.domain \ seen := Finset.mem_sdiff.mpr ⟨present, visited⟩
          have positive : 0 < (graph.domain \ seen).card := Finset.card_pos.mpr ⟨key, member⟩
          omega
  | succ fuel ih =>
    cases cursor with
    | none => simp [walk]
    | some key =>
      by_cases visited : key ∈ seen
      · simp [walk, visited]
      · cases known : graph.parent key with
        | none => simp [walk, visited, known]
        | some next =>
          have present : key ∈ graph.domain := (graph.known_iff key).mp ⟨next, known⟩
          have member : key ∈ graph.domain \ seen := Finset.mem_sdiff.mpr ⟨present, visited⟩
          have remaining : (graph.domain \ insert key seen).card ≤ fuel := by
            rw [remaining_after_insert, Finset.card_erase_of_mem member]
            omega
          have tail := ih (insert key seen) next remaining
          rw [walk, if_neg visited, known]
          cases result : walk graph fuel (insert key seen) next with
          | ok rest => simp
          | error failure => cases failure <;> simp_all

/-- Acceptance earns the complete declarative path and excludes every record
already visited. This is stronger than merely returning a non-error flag. -/
theorem accepted_has_chain (graph : Graph Key) (fuel : Nat) (seen : Finset Key)
    (cursor : Option Key) (path : List Key)
    (accepted : walk graph fuel seen cursor = .ok path) :
    Chain graph cursor path ∧ ∀ key ∈ path, key ∉ seen := by
  induction fuel generalizing seen cursor path with
  | zero =>
    cases cursor with
    | none =>
      have same : path = [] := by simpa [walk] using accepted.symm
      subst path
      exact ⟨.done, by simp⟩
    | some key =>
      by_cases visited : key ∈ seen
      · simp [walk, visited] at accepted
      · cases known : graph.parent key <;> simp [walk, visited, known] at accepted
  | succ fuel ih =>
    cases cursor with
    | none =>
      have same : path = [] := by simpa [walk] using accepted.symm
      subst path
      exact ⟨.done, by simp⟩
    | some key =>
      by_cases visited : key ∈ seen
      · simp [walk, visited] at accepted
      · cases known : graph.parent key with
        | none => simp [walk, visited, known] at accepted
        | some next =>
          rw [walk, if_neg visited, known] at accepted
          cases result : walk graph fuel (insert key seen) next with
          | error failure => simp [result] at accepted
          | ok rest =>
            rw [result] at accepted
            have same : key :: rest = path := Except.ok.inj accepted
            subst path
            obtain ⟨tail, outside⟩ := ih (insert key seen) next rest result
            have fresh : key ∉ rest := by
              intro member
              exact outside key member (Finset.mem_insert_self key seen)
            refine ⟨.link known tail fresh, ?_⟩
            intro value member
            rcases List.mem_cons.mp member with same | inRest
            · subst value
              exact visited
            · intro inSeen
              exact outside value inRest (Finset.mem_insert_of_mem inSeen)

/-- Useful completeness: every independently valid finite path is accepted
when its records have not already been visited. -/
theorem chain_is_accepted {graph : Graph Key} {cursor : Option Key} {path : List Key}
    (chain : Chain graph cursor path) (seen : Finset Key) (fuel : Nat)
    (outside : ∀ key ∈ path, key ∉ seen) (enough : path.length ≤ fuel) :
    walk graph fuel seen cursor = .ok path := by
  induction chain generalizing seen fuel with
  | done => simp [walk]
  | @link key next rest known tail fresh ih =>
    cases fuel with
    | zero => simp at enough
    | succ fuel =>
      have unvisited : key ∉ seen := outside key (by simp)
      have remaining : rest.length ≤ fuel := by simpa using enough
      have outsideTail : ∀ value ∈ rest, value ∉ insert key seen := by
        intro value member inNew
        rcases Finset.mem_insert.mp inNew with same | inSeen
        · apply fresh
          simpa [same] using member
        · exact outside value (List.mem_cons_of_mem key member) inSeen
      have accepted := ih (insert key seen) fuel outsideTail remaining
      rw [walk, if_neg unvisited, known, accepted]

theorem chain_nodup {graph : Graph Key} {cursor : Option Key} {path : List Key}
    (chain : Chain graph cursor path) : path.Nodup := by
  induction chain with
  | done => simp
  | link _ _ fresh ih => exact List.nodup_cons.mpr ⟨fresh, ih⟩

theorem chain_members {graph : Graph Key} {cursor : Option Key} {path : List Key}
    (chain : Chain graph cursor path) : ∀ key ∈ path, key ∈ graph.domain := by
  induction chain with
  | done => simp
  | @link key next rest known tail fresh ih =>
    intro value member
    rcases List.mem_cons.mp member with same | inRest
    · subst value
      exact (graph.known_iff key).mp ⟨next, known⟩
    · exact ih value inRest

theorem chain_length_bound {graph : Graph Key} {cursor : Option Key} {path : List Key}
    (chain : Chain graph cursor path) : path.length ≤ graph.domain.card := by
  calc
    path.length = path.toFinset.card := (List.toFinset_card_of_nodup (chain_nodup chain)).symm
    _ ≤ graph.domain.card := Finset.card_le_card (by
      intro key member
      exact chain_members chain key (List.mem_toFinset.mp member))

/-- Exact initial acceptance, without an exhaustion assumption or a premise
stating what the implementation should return. -/
theorem initial_accepts_iff (graph : Graph Key) (cursor : Option Key) (path : List Key) :
    walk graph graph.domain.card ∅ cursor = .ok path ↔ Chain graph cursor path := by
  constructor
  · intro accepted
    exact (accepted_has_chain graph graph.domain.card ∅ cursor path accepted).1
  · intro chain
    exact chain_is_accepted chain ∅ graph.domain.card (by simp) (chain_length_bound chain)

def scan (graph : Graph Key) : List (Option Key) → Except Failure (List (List Key))
  | [] => .ok []
  | cursor :: rest =>
    match walk graph graph.domain.card ∅ cursor with
    | .error failure => .error failure
    | .ok path => match scan graph rest with
      | .error failure => .error failure
      | .ok paths => .ok (path :: paths)

theorem scan_has_chains (graph : Graph Key) (roots : List (Option Key)) (paths : List (List Key))
    (accepted : scan graph roots = .ok paths) : List.Forall₂ (Chain graph) roots paths := by
  induction roots generalizing paths with
  | nil =>
    have same : paths = [] := by simpa [scan] using accepted.symm
    subst paths
    exact .nil
  | cons cursor rest ih =>
    rw [scan] at accepted
    cases headResult : walk graph graph.domain.card ∅ cursor with
    | error failure => simp [headResult] at accepted
    | ok path =>
      rw [headResult] at accepted
      cases tailResult : scan graph rest with
      | error failure => simp [tailResult] at accepted
      | ok remaining =>
        rw [tailResult] at accepted
        have same : path :: remaining = paths := Except.ok.inj accepted
        subst paths
        exact .cons ((initial_accepts_iff graph cursor path).mp headResult) (ih remaining tailResult)

theorem chains_are_scanned {graph : Graph Key} {roots : List (Option Key)} {paths : List (List Key)}
    (paired : List.Forall₂ (Chain graph) roots paths) : scan graph roots = .ok paths := by
  induction roots generalizing paths with
  | nil => cases paired; rfl
  | cons cursor rest ih =>
    cases paths with
    | nil => cases paired
    | cons path remaining =>
      cases paired with
      | cons head tail =>
        have headResult := (initial_accepts_iff graph cursor path).mpr head
        have tailResult := ih tail
        rw [scan, headResult, tailResult]

theorem paired_members {graph : Graph Key} {roots : List (Option Key)} {paths : List (List Key)}
    (paired : List.Forall₂ (Chain graph) roots paths) :
    ∀ path ∈ paths, ∀ key ∈ path, key ∈ graph.domain := by
  induction paired with
  | nil => simp
  | cons head tail ih =>
    intro path member key inPath
    rcases List.mem_cons.mp member with same | inRemaining
    · subst path
      exact chain_members head key inPath
    · exact ih path inRemaining key inPath

theorem used_subset {graph : Graph Key} {roots : List (Option Key)} {paths : List (List Key)}
    (paired : List.Forall₂ (Chain graph) roots paths) : paths.flatten.toFinset ⊆ graph.domain := by
  intro key member
  simp only [List.mem_toFinset, List.mem_flatten] at member
  obtain ⟨path, inPaths, inPath⟩ := member
  exact paired_members paired path inPaths key inPath

/-- The reference stage's complete independent requirement: every root has
a valid path and every supplied grant belongs to at least one such path. -/
def Resolved (graph : Graph Key) (roots : List (Option Key)) (paths : List (List Key)) : Prop :=
  List.Forall₂ (Chain graph) roots paths ∧ paths.flatten.toFinset = graph.domain

def resolve (graph : Graph Key) (roots : List (Option Key)) : Except Failure (List (List Key)) :=
  match scan graph roots with
  | .error failure => .error failure
  | .ok paths =>
    if paths.flatten.toFinset.card = graph.domain.card then .ok paths else .error .unused

/-- Equal cardinality establishes complete coverage only because accepted
walks have already earned membership in the supplied graph. -/
theorem resolve_exact (graph : Graph Key) (roots : List (Option Key)) (paths : List (List Key)) :
    resolve graph roots = .ok paths ↔ Resolved graph roots paths := by
  constructor
  · intro accepted
    rw [resolve] at accepted
    cases scanned : scan graph roots with
    | error failure => simp [scanned] at accepted
    | ok candidates =>
      rw [scanned] at accepted
      by_cases complete : candidates.flatten.toFinset.card = graph.domain.card
      · rw [if_pos complete] at accepted
        have same : candidates = paths := Except.ok.inj accepted
        subst paths
        have paired := scan_has_chains graph roots candidates scanned
        refine ⟨paired, ?_⟩
        exact Finset.eq_of_subset_of_card_le (used_subset paired) (by omega)
      · rw [if_neg complete] at accepted
        cases accepted
  · rintro ⟨paired, complete⟩
    have scanned := chains_are_scanned paired
    rw [resolve, scanned]
    simp [complete]

private def exampleGraph : Graph Nat where
  domain := {1, 2}
  parent key := if key = 1 then some none else if key = 2 then some (some 1) else none
  known_iff := by
    intro key
    by_cases first : key = 1 <;> by_cases second : key = 2 <;> simp_all

example : walk exampleGraph 2 ∅ (some 2) = .ok [2, 1] := by decide
example : walk exampleGraph 2 ∅ (some 3) = .error .missing := by decide
example : walk exampleGraph 2 {1} (some 2) = .error .cycle := by decide
example : resolve exampleGraph [some 2] = .ok [[2, 1]] := by decide
example : resolve exampleGraph [some 1] = .error .unused := by decide
example : resolve exampleGraph [some 3] = .error .missing := by decide

end Auths.Verifier.ReferenceGraph
