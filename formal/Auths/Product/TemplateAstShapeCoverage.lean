import Auths.Product.TemplateAstDemandBounds
import Auths.Product.TemplateAstBodyAdmission

namespace Auths.Product.TemplateAst
open RequestConstruction BodyCompiler
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

/- Total counts of every original child. Unlike a bounded traversal model,
these views have no fuel, depth truncation, compiler output or validity bit. -/
mutual
  def jsonNodes : Value → Nat
    | .array items => 1 + arrayNodes items
    | .object fields => 1 + memberNodes fields
    | .text _ | .integer _ | .boolean _ | .field _ | .authorEcho => 1
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf <;> omega

  def arrayNodes : List Value → Nat
    | [] => 0
    | value :: rest => jsonNodes value + arrayNodes rest
  termination_by items => sizeOf items
  decreasing_by all_goals simp_wf <;> omega

  def memberNodes : List (Bytes × Value) → Nat
    | [] => 0
    | (_, value) :: rest => jsonNodes value + memberNodes rest
  termination_by fields => sizeOf fields
  decreasing_by all_goals simp_wf <;> omega
end

def formValueNodes : FormValue → Nat
  | .json value => jsonNodes value
  | .text _ | .field _ | .authorEcho => 0
def bodyNodes : Body → Nat
  | .json value => jsonNodes value
  | .form fields => (fields.map (fun member => formValueNodes member.2)).sum

inductive JsonShape : Nat → Value → Option (List Bytes) → Prop
  | leaf (depth : Nat) (value : Value) (within : depth ≤ 6) (admitted : LeafAdmission value) : JsonShape depth value none
  | array (depth : Nat) (items : List Value) (within : depth ≤ 6) (count : 0 < items.length ∧ items.length ≤ 16)
      (children : ∀ child ∈ items, JsonShape (depth + 1) child none) : JsonShape depth (.array items) none
  | object (depth : Nat) (fields : List (Bytes × Value)) (echo : Option (List Bytes)) (route : NamedEchoRoute)
      (within : depth ≤ 6) (keys : TemplateMembers.KeyColumn (fields.map Prod.fst) .json)
      (routeMeaning : namedEchoRoute (fields.map Prod.fst) echo = .ok route)
      (children : ∀ member ∈ fields, JsonShape (depth + 1) member.2 (namedChildEcho route member.1)) :
      JsonShape depth (.object fields) echo

inductive FormShape : FormValue → Prop
  | text (bytes : Bytes) (bounded : bytes.length ≤ 1024) : FormShape (.text bytes)
  | field (name : Bytes) (allowed : RenderedField name) : FormShape (.field name)
  | json (value : Value) (allowed : FormJsonAllowed value) (shape : JsonShape 0 value none) : FormShape (.json value)

/-- Original source shape rules alone: no resource-demand witness, emitted
template, expected bytes, compiler result or selected argument/source index. -/
inductive BodyShape : Body → Option Echo → Prop
  | json (value : Value) (pointer : Option (List Bytes)) (shape : JsonShape 0 value pointer) :
      BodyShape (.json value) (pointer.map Echo.json)
  | form (fields : List (Bytes × FormValue)) (insertion : Option Bytes)
      (keys : TemplateMembers.KeyColumn (fields.map Prod.fst) .form)
      (echo : TemplateMembers.EchoAdmitted (fields.map Prod.fst) insertion .form)
      (children : ∀ member ∈ fields, FormShape member.2) : BodyShape (.form fields) (insertion.map Echo.form)

theorem json_shape_within_depth (depth : Nat) (value : Value) (echo : Option (List Bytes))
    (shape : JsonShape depth value echo) : depth ≤ 6 := by cases shape <;> assumption

private theorem array_nodes_sum (items : List Value) : arrayNodes items = (items.map jsonNodes).sum := by
  induction items <;> simp_all [arrayNodes]
private theorem member_nodes_sum (fields : List (Bytes × Value)) : memberNodes fields = (fields.map (fun member => jsonNodes member.2)).sum := by
  induction fields with
  | nil => rfl
  | cons member rest ih => cases member <;> simp [memberNodes, ih]

private theorem collect_demands {α : Type} (items : List α) (relation : α → Demand → Prop) (nodes : α → Nat)
    (each : ∀ item ∈ items, ∃ demand, relation item demand ∧ demand.nodes = nodes item) :
    ∃ demands, List.Forall₂ relation items demands ∧ (Demand.sum demands).nodes = (items.map nodes).sum := by
  induction items with
  | nil => exact ⟨[], .nil, rfl⟩
  | cons item rest ih =>
    obtain ⟨first, firstAdmitted, firstNodes⟩ := each item (by simp)
    obtain ⟨remaining, tailAdmitted, tailNodes⟩ := ih (fun value member => each value (List.mem_cons_of_mem _ member))
    exact ⟨first :: remaining, .cons firstAdmitted tailAdmitted, by simp [Demand.sum, Demand.plus, firstNodes, tailNodes]⟩

private theorem literal_row_nodes {α : Type} {R : α → Demand → Prop} (items : List α) (demands : List Demand)
    (paired : List.Forall₂ R items demands) (prefix : α → Bytes) :
    (Demand.sum ((items.zip demands).map (fun (item, demand) => Demand.plus (Demand.literal (prefix item)) demand))).nodes =
      (Demand.sum demands).nodes := by
  induction paired with
  | nil => rfl
  | cons head tail ih => simp [Demand.sum, Demand.plus, Demand.literal, ih]

private theorem object_demand_nodes {R : (Bytes × Value) → Demand → Prop}
    (fields : List (Bytes × Value)) (demands : List Demand) (paired : List.Forall₂ R fields demands) (insertion : Option Bytes) :
    (objectDemand fields demands insertion).nodes = 1 + (Demand.sum demands).nodes := by
  have rows := literal_row_nodes fields demands paired (fun member => jsonPrefix member.1 true)
  cases insertion <;> simpa [objectDemand, Demand.plus, Demand.node, echoDemand, Demand.zero, Demand.literal, Demand.dynamic] using congrArg (1 + ·) rows

private theorem form_demand_nodes (fields : List (Bytes × FormValue)) (demands : List Demand)
    (paired : List.Forall₂ (fun member demand => FormValueAdmission member.2 demand) fields demands) (insertion : Option Bytes) :
    (formDemand fields demands insertion).nodes = (Demand.sum demands).nodes := by
  have rows := literal_row_nodes fields demands paired (fun member => formPrefix member.1 true)
  cases insertion <;> simpa [formDemand, Demand.plus, formEchoDemand, Demand.zero, Demand.literal, Demand.dynamic] using rows

/-- Every shape earns its original-tree demand and exact untruncated node
count. Resource bounds are conclusions of the separate hard-node-limit proof. -/
theorem json_shape_earns_admission (depth : Nat) (value : Value) (echo : Option (List Bytes)) (shape : JsonShape depth value echo) :
    ∃ demand, JsonAdmission depth value echo demand ∧ demand.nodes = jsonNodes value := by
  generalize remainingEq : 7 - depth = remaining
  induction remaining using Nat.strong_induction_on generalizing depth value echo with
  | h remaining ih =>
    have within := json_shape_within_depth depth value echo shape
    have descend : ∀ child nested, JsonShape (depth + 1) child nested →
        ∃ demand, JsonAdmission (depth + 1) child nested demand ∧ demand.nodes = jsonNodes child := by
      intro child nested childShape
      exact ih (7 - (depth + 1)) (by omega) (depth + 1) child nested childShape rfl
    cases shape with
    | leaf depth value within admitted =>
      refine ⟨leafDemand value, JsonAdmission.leaf depth value within admitted, ?_⟩
      cases admitted <;> rfl
    | array depth items within count children =>
      obtain ⟨demands, paired, nodes⟩ := collect_demands items
        (fun child demand => JsonAdmission (depth + 1) child none demand) jsonNodes
        (fun child present => descend child none (children child present))
      refine ⟨arrayDemand items demands, JsonAdmission.array depth items demands within count paired, ?_⟩
      simp [arrayDemand, Demand.plus, Demand.node, jsonNodes, nodes, array_nodes_sum]
    | object depth fields echo route within keys routeMeaning children =>
      obtain ⟨demands, paired, nodes⟩ := collect_demands fields
        (fun member demand => JsonAdmission (depth + 1) member.2 (namedChildEcho route member.1) demand)
        (fun member => jsonNodes member.2)
        (fun member present => descend member.2 (namedChildEcho route member.1) (children member present))
      exact ⟨objectDemand fields demands route.insertion, JsonAdmission.object depth fields echo route demands within keys routeMeaning paired,
        by simp [object_demand_nodes fields demands paired route.insertion, nodes, jsonNodes, member_nodes_sum]⟩

theorem form_shape_earns_admission (value : FormValue) (shape : FormShape value) (nodes : formValueNodes value ≤ 64) :
    ∃ demand, FormValueAdmission value demand ∧ demand.nodes = formValueNodes value := by
  cases shape with
  | text bytes bounded => exact ⟨Demand.literal (formEncode bytes), FormValueAdmission.text bytes bounded, rfl⟩
  | field name allowed => exact ⟨Demand.dynamic, FormValueAdmission.field name allowed, rfl⟩
  | json value allowed shape =>
    obtain ⟨demand, admitted, exactNodes⟩ := json_shape_earns_admission 0 value none shape
    have count : demand.pieces ≤ 256 := by
      have bounded := json_node_limit_earns_bounded_demand 0 value none demand admitted (by simpa [exactNodes] using nodes)
      exact bounded.2.1
    exact ⟨⟨demand.nodes, 1, demand.literals, demand.dynamics⟩, FormValueAdmission.json value demand allowed admitted count,
      by simpa [formValueNodes] using exactNodes⟩

private theorem member_node_bound {α : Type} (items : List α) (nodes : α → Nat) (item : α) (present : item ∈ items) :
    nodes item ≤ (items.map nodes).sum := by
  induction items with
  | nil => simp at present
  | cons first rest ih =>
    rcases List.mem_cons.mp present with same | later
    · subst item; simp
    · have bound := ih later
      simp only [List.map_cons, List.sum_cons]
      omega

/-- The source shape rules and original 64-node limit earn every aggregate
resource condition, including nested JSON piece caps. Conservative separator
reserves therefore introduce no additional refusal for this entire shape
language. Native validation must establish the source-to-shape bridge. -/
theorem bounded_shape_is_admissible (body : Body) (echo : Option Echo) (shape : BodyShape body echo)
    (nodes : bodyNodes body ≤ 64) : BodyAdmissible body echo := by
  cases shape with
  | json value pointer shape =>
    obtain ⟨demand, admitted, exactNodes⟩ := json_shape_earns_admission 0 value pointer shape
    exact ⟨demand, BodyAdmission.json value pointer demand admitted,
      json_node_limit_earns_bounded_demand 0 value pointer demand admitted (by simpa [bodyNodes, exactNodes] using nodes)⟩
  | form fields insertion keys echo children =>
    have each : ∀ member ∈ fields, ∃ demand, FormValueAdmission member.2 demand ∧ demand.nodes = formValueNodes member.2 := by
      intro member present
      have localNodes := member_node_bound fields (fun member => formValueNodes member.2) member present
      have bounded : formValueNodes member.2 ≤ 64 := by simp only [bodyNodes] at nodes; omega
      exact form_shape_earns_admission member.2 (children member present) bounded
    obtain ⟨demands, paired, exactNodes⟩ := collect_demands fields
      (fun member demand => FormValueAdmission member.2 demand) (fun member => formValueNodes member.2) each
    have demandNodes : (formDemand fields demands insertion).nodes ≤ 64 := by
      simpa [bodyNodes, form_demand_nodes fields demands paired insertion, exactNodes] using nodes
    exact ⟨formDemand fields demands insertion, BodyAdmission.form fields insertion demands keys echo paired,
      form_node_limit_earns_bounded_demand fields insertion demands keys echo paired demandNodes⟩

theorem bounded_shape_compiles (body : Body) (echo : Option Echo) (shape : BodyShape body echo) (nodes : bodyNodes body ≤ 64) :
    ∃ output, compileBody body echo = .ok output :=
  admitted_body_compiles body echo (bounded_shape_is_admissible body echo shape nodes)

end Auths.Product.TemplateAst
