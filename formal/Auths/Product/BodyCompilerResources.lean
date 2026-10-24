import Auths.Product.BodyCompiler

namespace Auths.Product.BodyCompiler.Resources

structure Usage where
  literalBytes : Nat
  dynamicPieces : Nat
  deriving DecidableEq

def zero : Usage := ⟨0, 0⟩
def plus (left right : Usage) : Usage :=
  ⟨left.literalBytes + right.literalBytes, left.dynamicPieces + right.dynamicPieces⟩
def Bounded (used : Usage) : Prop := used.literalBytes ≤ 524288 ∧ used.dynamicPieces ≤ 256
instance (used : Usage) : Decidable (Bounded used) := by unfold Bounded; infer_instance

def add (current extra : Usage) : Option Usage :=
  if Bounded current ∧ Bounded (plus current extra) then some (plus current extra) else none

theorem add_success_earns_bound (current extra next : Usage) (run : add current extra = some next) : Bounded next := by
  unfold add at run
  split at run
  · rename_i fit
    have same : next = plus current extra := by simpa using run.symm
    simpa [same] using fit.2
  · contradiction

def jsonQuantity (piece : NamedJson) : Usage := ⟨jsonLiteralSize piece, jsonDynamicSize piece⟩
def formQuantity (piece : NamedForm) : Usage := ⟨formLiteralSize piece, formDynamicSize piece⟩

def totals {α : Type} (quantity : α → Usage) (source : List α) : Usage :=
  ⟨(source.map (fun piece => (quantity piece).literalBytes)).sum,
    (source.map (fun piece => (quantity piece).dynamicPieces)).sum⟩

def scan {α : Type} (charge : Usage → α → Option Usage) (current : Usage) : List α → Option Usage
  | [] => some current
  | piece :: rest => match charge current piece with
    | none => none
    | some next => scan charge next rest

def jsonCharge (current : Usage) (piece : NamedJson) : Option Usage := add current (jsonQuantity piece)
def formCharge (current : Usage) (piece : NamedForm) : Option Usage :=
  if NestedCount piece then add current (formQuantity piece) else none

theorem form_charge_success_earns_bound (current : Usage) (piece : NamedForm) (next : Usage)
    (run : formCharge current piece = some next) : Bounded next := by
  unfold formCharge at run
  split at run
  · exact add_success_earns_bound _ _ _ run
  · contradiction

def jsonResources (source : List NamedJson) : Option Usage :=
  if source.length ≤ 256 then scan jsonCharge zero source else none
def formResources (source : List NamedForm) : Option Usage :=
  if source.length ≤ 256 then scan formCharge zero source else none

private theorem scan_exact {α : Type} (quantity : α → Usage) (guard : α → Prop)
    [DecidablePred guard] (charge : Usage → α → Option Usage)
    (chargeSpec : ∀ current piece, charge current piece = if guard piece then add current (quantity piece) else none)
    (source : List α) (current : Usage) (currentBound : Bounded current) :
    scan charge current source =
      if (∀ piece ∈ source, guard piece) ∧ Bounded (plus current (totals quantity source)) then
        some (plus current (totals quantity source)) else none := by
  induction source generalizing current with
  | nil => simp [scan, totals, plus, currentBound, Bounded] at *
  | cons first rest ih =>
    let next := plus current (quantity first)
    by_cases firstGuard : guard first
    · by_cases nextBound : Bounded next
      · have firstRun : charge current first = some next := by
          simp [chargeSpec, firstGuard, add, currentBound, nextBound, next]
        rw [scan, firstRun, ih next nextBound]
        have totalStep : plus current (totals quantity (first :: rest)) = plus next (totals quantity rest) := by
          apply Usage.ext <;> simp [totals, plus, next] <;> omega
        simp [totalStep, firstGuard]
      · have firstRun : charge current first = none := by
          simp [chargeSpec, firstGuard, add, currentBound, nextBound, next]
        rw [scan, firstRun]
        have totalBad : ¬Bounded (plus current (totals quantity (first :: rest))) := by
          intro full
          apply nextBound
          simp only [Bounded, plus, totals, List.map_cons, List.sum_cons] at full ⊢
          dsimp [next, Bounded, plus]
          constructor <;> omega
        simp [totalBad]
    · have firstRun : charge current first = none := by simp [chargeSpec, firstGuard]
      rw [scan, firstRun]
      have guardsBad : ¬∀ piece ∈ first :: rest, guard piece := by
        intro every
        exact firstGuard (every first (by simp))
      simp [guardsBad]

theorem json_resources_exact_totals (source : List NamedJson) :
    jsonResources source = if source.length ≤ 256 ∧ JsonResourceDomain source then
      some ⟨jsonLiterals source, jsonDynamics source⟩ else none := by
  unfold jsonResources
  by_cases count : source.length ≤ 256
  · rw [if_pos count, scan_exact jsonQuantity (fun _ => True) jsonCharge]
    · simp [count, totals, jsonQuantity, zero, plus, Bounded, JsonResourceDomain]
    · intro current piece
      simp [jsonCharge]
    · simp [zero, Bounded]
  · simp [count]

theorem form_resources_exact_totals (source : List NamedForm) :
    formResources source = if source.length ≤ 256 ∧ FormResourceDomain source then
      some ⟨formLiterals source, formDynamics source⟩ else none := by
  unfold formResources
  by_cases count : source.length ≤ 256
  · rw [if_pos count, scan_exact formQuantity NestedCount formCharge]
    · simp [count, totals, formQuantity, zero, plus, Bounded, FormResourceDomain, NestedCounts,
        and_assoc, and_left_comm, and_comm]
    · intro current piece
      rfl
    · simp [zero, Bounded]
  · simp [count]

theorem json_resources_success_earns_totals (source : List NamedJson) (used : Usage)
    (run : jsonResources source = some used) :
    used = ⟨jsonLiterals source, jsonDynamics source⟩ ∧ source.length ≤ 256 ∧ JsonResourceDomain source := by
  rw [json_resources_exact_totals] at run
  split at run
  · rename_i admitted
    exact ⟨by simpa using run.symm, admitted.1, admitted.2⟩
  · contradiction

theorem form_resources_success_earns_totals (source : List NamedForm) (used : Usage)
    (run : formResources source = some used) :
    used = ⟨formLiterals source, formDynamics source⟩ ∧ source.length ≤ 256 ∧ FormResourceDomain source := by
  rw [form_resources_exact_totals] at run
  split at run
  · rename_i admitted
    exact ⟨by simpa using run.symm, admitted.1, admitted.2⟩
  · contradiction

theorem form_json_cannot_reset_budget (current : Usage) (source : List NamedJson) (next : Usage)
    (run : formCharge current (.json source) = some next) :
    next.literalBytes = current.literalBytes + jsonLiterals source ∧
      next.dynamicPieces = current.dynamicPieces + jsonDynamics source ∧ Bounded next := by
  unfold formCharge NestedCount add at run
  split at run
  · split at run
    · rename_i bound
      have same : next = plus current (formQuantity (.json source)) := by simpa using run.symm
      subst next
      exact ⟨rfl, rfl, bound.2⟩
    · contradiction
  · contradiction

end Auths.Product.BodyCompiler.Resources
