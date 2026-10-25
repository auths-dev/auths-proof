import Auths.Product.TemplateAstAdmissionSelection

namespace Auths.Product.TemplateAst.AdmissionSupport
open RequestConstruction BodyCompiler

/- These generic budget lemmas are proof support, not source claims. Complete
compiler theorems instantiate every step with the closed actual model and
derive the step hypotheses from original-tree admission. -/
def JsonStep {α : Type} (step : JsonBuild → α → Except Error JsonBuild) (item : α) (demand : Demand) : Prop :=
  ∀ before, JsonRoom before demand → ∃ after, step before item = .ok after ∧ JsonSpend before after demand
def FormStep {α : Type} (step : FormBuild → α → Except Error FormBuild) (item : α) (demand : Demand) : Prop :=
  ∀ before, FormRoom before demand → ∃ after, step before item = .ok after ∧ FormSpend before after demand

theorem json_fold {α : Type} (step : JsonBuild → α → Except Error JsonBuild) (items : List α) (demands : List Demand)
    (paired : List.Forall₂ (JsonStep step) items demands) (before : JsonBuild) (room : JsonRoom before (Demand.sum demands)) :
    ∃ after, items.foldlM step before = .ok after ∧ JsonSpend before after (Demand.sum demands) := by
  induction paired generalizing before with
  | nil => exact ⟨before, rfl, JsonSpend.refl before room.1⟩
  | cons first remaining ih =>
    have headRoom := json_room_weaken before _ _ room (Demand.le_plus_left _ _)
    obtain ⟨middle, firstRun, firstSpend⟩ := first before headRoom
    have tailRoom := json_room_after room firstSpend
    obtain ⟨after, tailRun, tailSpend⟩ := ih middle tailRoom
    exact ⟨after, by simp [List.foldlM_cons, firstRun, tailRun], firstSpend.trans tailSpend⟩

theorem form_fold {α : Type} (step : FormBuild → α → Except Error FormBuild) (items : List α) (demands : List Demand)
    (paired : List.Forall₂ (FormStep step) items demands) (before : FormBuild) (room : FormRoom before (Demand.sum demands)) :
    ∃ after, items.foldlM step before = .ok after ∧ FormSpend before after (Demand.sum demands) := by
  induction paired generalizing before with
  | nil => exact ⟨before, rfl, FormSpend.refl before room.1⟩
  | cons first remaining ih =>
    have headRoom := form_room_weaken before _ _ room (Demand.le_plus_left _ _)
    obtain ⟨middle, firstRun, firstSpend⟩ := first before headRoom
    have tailRoom := form_room_after room firstSpend
    obtain ⟨after, tailRun, tailSpend⟩ := ih middle tailRoom
    exact ⟨after, by simp [List.foldlM_cons, firstRun, tailRun], firstSpend.trans tailSpend⟩

theorem indexed_pairs {α β : Type} (relation : α → β → Prop) (items : List α) (metadata : List β)
    (paired : List.Forall₂ relation items metadata) (cost : β × Nat → Demand)
    (property : α × Nat → Demand → Prop)
    (each : ∀ item data, relation item data → ∀ position, property (item, position) (cost (data, position))) (position : Nat) :
    List.Forall₂ property (items.zipIdx position) ((metadata.zipIdx position).map cost) := by
  induction paired generalizing position with
  | nil => exact .nil
  | cons associated remaining ih =>
    exact .cons (each _ _ associated position) (ih (position + 1))

theorem paired_members {α : Type} (items : List α) : List.Forall₂ (fun first second => first = second ∧ first ∈ items) items items := by
  induction items with
  | nil => exact .nil
  | cons item rest ih =>
    exact .cons ⟨rfl, by simp⟩ (ih.imp (fun _ _ related => ⟨related.1, List.mem_cons_of_mem _ related.2⟩))

theorem indexed_costs_constant {α : Type} (items : List α) (cost : α → Demand) (position : Nat) :
    (items.zipIdx position).map (fun item => cost item.1) = items.map cost := by
  induction items generalizing position with
  | nil => rfl
  | cons item rest ih => simp [List.zipIdx_cons, ih]

theorem paired_key_at {α : Type} (relation : (Bytes × α) → Demand → Prop)
    (row : (Bytes × α) → Demand → Demand) (fields : List (Bytes × α)) (demands : List Demand)
    (paired : List.Forall₂ relation fields demands) (index : Nat) (name : Bytes)
    (key : (fields.map Prod.fst)[index]? = some name) :
    ∃ value demand, fields[index]? = some (name, value) ∧ demands[index]? = some demand ∧ relation (name, value) demand ∧
      ((fields.zip demands).map (fun (field, cost) => row field cost))[index]? = some (row (name, value) demand) := by
  induction paired generalizing index with
  | nil => simp at key
  | @cons member cost fields demands admitted remaining ih =>
    obtain ⟨original, value⟩ := member
    cases index with
    | zero =>
      have same : original = name := by simpa using key
      subst original
      exact ⟨value, cost, rfl, rfl, admitted, rfl⟩
    | succ index =>
      obtain ⟨child, demand, atField, atCost, childAdmitted, atRow⟩ := ih index (by simpa using key)
      exact ⟨child, demand, by simpa using atField, by simpa using atCost, childAdmitted, by simpa using atRow⟩

def separatorDemand (position : Nat) : Demand := if 0 < position then Demand.literal [44] else Demand.zero

theorem separator_costs (demands : List Demand) (position : Nat) (positive : 0 < position) :
    Demand.sum ((demands.zipIdx position).map (fun item => Demand.plus (separatorDemand item.2) item.1)) =
      Demand.plus ⟨0, demands.length, demands.length, 0⟩ (Demand.sum demands) := by
  induction demands generalizing position with
  | nil => simp [Demand.sum]
  | cons first rest ih =>
    rw [List.zipIdx_cons, List.map_cons, Demand.sum, ih (position + 1) (by omega)]
    apply Demand.ext <;> simp [separatorDemand, positive, Demand.literal, Demand.plus, Demand.sum] <;> omega

theorem array_demand_decomposition (items : List Value) (demands : List Demand) (length : items.length = demands.length) :
    arrayDemand items demands = Demand.plus Demand.node (Demand.plus (Demand.literal [91]) (Demand.plus
      (Demand.sum ((demands.zipIdx 0).map (fun item => Demand.plus (separatorDemand item.2) item.1))) (Demand.literal [93]))) := by
  cases demands with
  | nil =>
    have empty : items = [] := List.length_eq_zero_iff.mp (by simpa using length)
    simp [empty, arrayDemand, Demand.sum, Demand.literal, Demand.plus, Demand.node]
  | cons first rest =>
    simp only [List.zipIdx_cons, List.map_cons, Demand.sum]
    rw [separator_costs rest 1 (by omega)]
    apply Demand.ext <;>
      simp [arrayDemand, Demand.plus, Demand.node, Demand.literal, separatorDemand, length, Demand.sum] <;> omega

end Auths.Product.TemplateAst.AdmissionSupport
