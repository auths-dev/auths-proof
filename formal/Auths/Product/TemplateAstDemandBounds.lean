import Auths.Product.TemplateAstAdmissionSelection

namespace Auths.Product.TemplateAst
open RequestConstruction BodyCompiler
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

def echoMark {α : Type} (echo : Option α) : Nat := if echo.isSome then 1 else 0

theorem echo_mark_bound {α : Type} (echo : Option α) : echoMark echo ≤ 1 := by cases echo <;> decide

private theorem unmarked_keys (keys : List Bytes) (name : Bytes) (absent : name ∉ keys) :
    (keys.map (fun key => if name = key then 1 else 0)).sum = 0 := by
  induction keys with
  | nil => rfl
  | cons key rest ih =>
    have separate : name ≠ key ∧ name ∉ rest := by simpa only [List.mem_cons, not_or] using absent
    simp [separate.1, ih separate.2]

private theorem one_marked_key (keys : List Bytes) (name : Bytes) (unique : keys.Nodup) (present : name ∈ keys) :
    (keys.map (fun key => if name = key then 1 else 0)).sum = 1 := by
  induction keys with
  | nil => simp at present
  | cons key rest ih =>
    obtain ⟨absent, tailUnique⟩ := List.nodup_cons.mp unique
    by_cases same : name = key
    · subst name
      simp [unmarked_keys rest key absent]
    · have later : name ∈ rest := by simpa [same] using present
      simp [same, ih tailUnique later]

/-- Original-name routing partitions one declared echo into either one final
insertion or exactly one recursive child. It cannot multiply down siblings. -/
theorem named_route_echo_partition (keys : List Bytes) (echo : Option (List Bytes)) (route : NamedEchoRoute)
    (column : TemplateMembers.KeyColumn keys .json) (meaning : namedEchoRoute keys echo = .ok route) :
    echoMark route.insertion + (keys.map (fun name => echoMark (namedChildEcho route name))).sum = echoMark echo := by
  cases echo with
  | none =>
    have same : route = ⟨none, none⟩ := by simpa [namedEchoRoute] using meaning.symm
    subst route
    induction keys <;> simp_all [namedChildEcho, echoMark]
  | some tokens =>
    unfold namedEchoRoute at meaning
    split at meaning
    · cases tokens with
      | nil => contradiction
      | cons parent tail =>
        cases tail with
        | nil =>
          split at meaning
          · have same : route = ⟨some parent, none⟩ := by simpa using meaning.symm
            subst route
            induction keys <;> simp_all [namedChildEcho, echoMark]
          · contradiction
        | cons next rest =>
          split at meaning
          · rename_i present
            have same : route = ⟨none, some (parent, next :: rest)⟩ := by simpa using meaning.symm
            subst route
            have child : ∀ name, echoMark (namedChildEcho ⟨none, some (parent, next :: rest)⟩ name) =
                if parent = name then 1 else 0 := by
              intro name
              by_cases equal : parent = name <;> simp [namedChildEcho, echoMark, equal]
            simp_rw [child]
            simpa [echoMark] using one_marked_key keys parent (admitted_keys_are_unique keys .json column) present
          · contradiction
    · contradiction

theorem json_key_prefix_bound (name : Bytes) (valid : OperationIdentity.validToken name 64 = true) :
    (jsonPrefix name true).length ≤ 388 := by
  have size := (TemplateMembers.token_shape_bounds name valid).2.1
  have quoted := BodyCompiler.json_string_length name
  simp only [jsonPrefix, List.length_append, List.length_singleton]
  omega

theorem form_key_prefix_bound (name : Bytes) (valid : OperationIdentity.validToken name 64 = true) :
    (formPrefix name true).length ≤ 194 := by
  have size := (TemplateMembers.token_shape_bounds name valid).2.1
  have encoded := BodyCompiler.form_encode_length name
  simp only [formPrefix, List.length_append, List.length_singleton]
  omega

private theorem json_echo_demand_bounds (keys : List Bytes) (insertion : Option Bytes)
    (admitted : TemplateMembers.EchoAdmitted keys insertion .json) :
    (echoDemand insertion).nodes = 0 ∧ (echoDemand insertion).pieces = 2 * echoMark insertion ∧
      (echoDemand insertion).literals ≤ 388 * echoMark insertion ∧ (echoDemand insertion).dynamics = echoMark insertion := by
  cases insertion with
  | none => simp [echoDemand, Demand.zero, echoMark]
  | some name =>
    have size := json_key_prefix_bound name admitted.1
    simpa [echoDemand, echoMark, Demand.plus, Demand.literal, Demand.dynamic] using size

def JsonDemandEnvelope (demand : Demand) (echo : Option (List Bytes)) : Prop :=
  demand.pieces + 1 ≤ 3 * demand.nodes + 2 * echoMark echo ∧
    demand.literals + 390 ≤ 6536 * demand.nodes + 390 * echoMark echo ∧
    demand.dynamics ≤ demand.nodes + echoMark echo

private theorem leaf_demand_envelope (value : Value) (admitted : LeafAdmission value) : JsonDemandEnvelope (leafDemand value) none := by
  cases admitted with
  | text bytes bounded =>
    have size := BodyCompiler.json_string_length bytes
    simp [JsonDemandEnvelope, leafDemand, leafPiece, Demand.plus, Demand.node, Demand.atom, jsonLiteralSize, jsonDynamicSize, echoMark]
    omega
  | integer value safe =>
    have size := admitted_integer_literal_length value safe
    simp [JsonDemandEnvelope, leafDemand, leafPiece, Demand.plus, Demand.node, Demand.atom, jsonLiteralSize, jsonDynamicSize, echoMark]
    omega
  | boolean value => cases value <;> decide
  | field name allowed => decide

private theorem summed_json_envelopes {α : Type} (items : List α) (demands : List Demand) (mark : α → Nat)
    (paired : List.Forall₂ (fun item demand =>
      demand.pieces + 1 ≤ 3 * demand.nodes + 2 * mark item ∧
      demand.literals + 390 ≤ 6536 * demand.nodes + 390 * mark item ∧
      demand.dynamics ≤ demand.nodes + mark item) items demands) :
    (Demand.sum demands).pieces + items.length ≤ 3 * (Demand.sum demands).nodes + 2 * (items.map mark).sum ∧
      (Demand.sum demands).literals + 390 * items.length ≤ 6536 * (Demand.sum demands).nodes + 390 * (items.map mark).sum ∧
      (Demand.sum demands).dynamics ≤ (Demand.sum demands).nodes + (items.map mark).sum := by
  induction paired with
  | nil => simp [Demand.sum, Demand.zero]
  | @cons item demand items demands head tail ih =>
    rcases head with ⟨hp, hl, hd⟩
    rcases ih with ⟨tp, tl, td⟩
    simp only [Demand.sum, Demand.plus, List.length_cons, List.map_cons, List.sum_cons]
    constructor
    · omega
    · constructor <;> omega

private theorem json_rows_bounds {R : (Bytes × Value) → Demand → Prop}
    (fields : List (Bytes × Value)) (demands : List Demand) (paired : List.Forall₂ R fields demands)
    (names : ∀ member ∈ fields, OperationIdentity.validToken member.1 64 = true) :
    let rows := Demand.sum ((fields.zip demands).map (fun (member, child) =>
      Demand.plus (Demand.literal (jsonPrefix member.1 true)) child))
    rows.nodes = (Demand.sum demands).nodes ∧ rows.pieces = fields.length + (Demand.sum demands).pieces ∧
      rows.literals ≤ 388 * fields.length + (Demand.sum demands).literals ∧ rows.dynamics = (Demand.sum demands).dynamics := by
  revert names
  induction paired with
  | nil => intro names; simp [Demand.sum, Demand.zero]
  | @cons member demand fields demands admitted tail ih =>
    intro names
    have prefix := json_key_prefix_bound member.1 (names member (by simp))
    obtain ⟨nodes, pieces, literals, dynamics⟩ := ih (fun value present => names value (List.mem_cons_of_mem _ present))
    simp only [List.zip_cons_cons, List.map_cons, Demand.sum, Demand.plus, Demand.literal, List.length_cons]
    constructor
    · omega
    · constructor
      · omega
      · constructor <;> omega

/-- Original shape bounds account for all conservative separators. The one
echo partition is earned from exact original-name routing, including nested
descent; no precomputed resource claim is assumed. -/
theorem json_demand_envelope (depth : Nat) (value : Value) (echo : Option (List Bytes)) (demand : Demand)
    (admitted : JsonAdmission depth value echo demand) : JsonDemandEnvelope demand echo := by
  generalize remainingEq : 7 - depth = remaining
  induction remaining using Nat.strong_induction_on generalizing depth value echo demand with
  | h remaining ih =>
    have within := (json_admission_positive_nodes depth value echo demand admitted).2
    have children : ∀ child nested cost, JsonAdmission (depth + 1) child nested cost → JsonDemandEnvelope cost nested := by
      intro child nested cost childAdmission
      exact ih (7 - (depth + 1)) (by omega) (depth + 1) child nested cost childAdmission rfl
    cases admitted with
    | leaf depth value within admitted => exact leaf_demand_envelope value admitted
    | array depth items costs within count paired =>
      have aggregate := summed_json_envelopes items costs (fun _ => 0)
        (paired.imp (fun child cost admitted => by simpa [JsonDemandEnvelope, echoMark] using children child none cost admitted))
      have zeros : (items.map (fun _ => (0 : Nat))).sum = 0 := by induction items <;> simp_all
      rw [zeros] at aggregate
      rcases aggregate with ⟨pieces, literals, dynamics⟩
      simp only [JsonDemandEnvelope, arrayDemand, Demand.plus, Demand.node, echoMark, Option.isSome_none,
        Bool.false_eq_true, ↓reduceIte, Nat.mul_zero, Nat.add_zero]
      have nonempty := count.1
      constructor
      · omega
      · constructor <;> omega
    | object depth fields echo route costs within keys routeMeaning paired =>
      have aggregate := summed_json_envelopes fields costs (fun member => echoMark (namedChildEcho route member.1))
        (paired.imp (fun member cost admitted => children member.2 (namedChildEcho route member.1) cost admitted))
      have partition := named_route_echo_partition (fields.map Prod.fst) echo route keys routeMeaning
      simp only [List.map_map, Function.comp_def] at partition
      have names : ∀ member ∈ fields, OperationIdentity.validToken member.1 64 = true := by
        intro member present
        exact keys.2.2.1 member.1 (List.mem_map.mpr ⟨member, present, rfl⟩)
      obtain ⟨rowNodes, rowPieces, rowLiterals, rowDynamics⟩ := json_rows_bounds fields costs paired names
      obtain ⟨echoNodes, echoPieces, echoLiterals, echoDynamics⟩ := json_echo_demand_bounds _ route.insertion
        (named_route_member_admission _ echo route keys routeMeaning).2
      rcases aggregate with ⟨pieces, literals, dynamics⟩
      simp only [JsonDemandEnvelope, objectDemand, Demand.plus, Demand.node]
      rw [rowNodes, rowPieces, rowDynamics, echoNodes, echoPieces, echoDynamics]
      constructor
      · omega
      · constructor <;> omega

theorem json_node_limit_earns_demand_bounds (depth : Nat) (value : Value) (echo : Option (List Bytes)) (demand : Demand)
    (admitted : JsonAdmission depth value echo demand) (nodes : demand.nodes ≤ 64) :
    demand.pieces ≤ 193 ∧ demand.literals ≤ 418304 ∧ demand.dynamics ≤ 65 := by
  obtain ⟨pieces, literals, dynamics⟩ := json_demand_envelope depth value echo demand admitted
  have mark := echo_mark_bound echo
  exact ⟨by omega, by omega, by omega⟩

theorem json_node_limit_earns_bounded_demand (depth : Nat) (value : Value) (echo : Option (List Bytes)) (demand : Demand)
    (admitted : JsonAdmission depth value echo demand) (nodes : demand.nodes ≤ 64) : Demand.Bounded demand := by
  obtain ⟨pieces, literals, dynamics⟩ := json_node_limit_earns_demand_bounds depth value echo demand admitted nodes
  exact ⟨nodes, by omega, by omega, by omega⟩

theorem form_value_demand_envelope (value : FormValue) (demand : Demand) (admitted : FormValueAdmission value demand) :
    demand.pieces = 1 ∧ demand.literals ≤ 6536 * demand.nodes + 3072 ∧ demand.dynamics ≤ demand.nodes + 1 := by
  cases admitted with
  | text bytes bounded =>
    have encoded := BodyCompiler.form_encode_length bytes
    simp only [Demand.literal]
    exact ⟨rfl, by omega, by omega⟩
  | field name allowed => decide
  | json value demand shape admitted count =>
    obtain ⟨pieces, literals, dynamics⟩ := json_demand_envelope 0 value none demand admitted
    simp only [echoMark, Option.isSome_none, Bool.false_eq_true, ↓reduceIte, Nat.mul_zero, Nat.add_zero] at literals dynamics
    exact ⟨rfl, by omega, by omega⟩

private theorem form_rows_bounds (fields : List (Bytes × FormValue)) (demands : List Demand)
    (paired : List.Forall₂ (fun member demand => FormValueAdmission member.2 demand) fields demands)
    (names : ∀ member ∈ fields, OperationIdentity.validToken member.1 64 = true) :
    let rows := Demand.sum ((fields.zip demands).map (fun (member, child) =>
      Demand.plus (Demand.literal (formPrefix member.1 true)) child))
    rows.nodes = (Demand.sum demands).nodes ∧ rows.pieces = 2 * fields.length ∧
      rows.literals ≤ 3266 * fields.length + 6536 * (Demand.sum demands).nodes ∧
      rows.dynamics ≤ (Demand.sum demands).nodes + fields.length := by
  revert names
  induction paired with
  | nil => intro names; simp [Demand.sum, Demand.zero]
  | @cons member demand fields demands admitted tail ih =>
    intro names
    have prefix := form_key_prefix_bound member.1 (names member (by simp))
    obtain ⟨childPieces, childLiterals, childDynamics⟩ := form_value_demand_envelope member.2 demand admitted
    obtain ⟨nodes, pieces, literals, dynamics⟩ := ih (fun value present => names value (List.mem_cons_of_mem _ present))
    simp only [List.zip_cons_cons, List.map_cons, Demand.sum, Demand.plus, Demand.literal, List.length_cons]
    constructor
    · omega
    · constructor
      · omega
      · constructor <;> omega

theorem form_echo_name_length (name : Bytes) (valid : TemplateMembers.EchoName .form name) : name.length ≤ 130 := by
  unfold TemplateMembers.EchoName TemplateMembers.formEchoValid at valid
  by_cases large : 130 < name.length
  · simp [large] at valid
  · omega

private theorem form_echo_demand_bounds (keys : List Bytes) (insertion : Option Bytes)
    (admitted : TemplateMembers.EchoAdmitted keys insertion .form) :
    (formEchoDemand insertion).nodes = 0 ∧ (formEchoDemand insertion).pieces = 2 * echoMark insertion ∧
      (formEchoDemand insertion).literals ≤ 392 * echoMark insertion ∧ (formEchoDemand insertion).dynamics = echoMark insertion := by
  cases insertion with
  | none => simp [formEchoDemand, Demand.zero, echoMark]
  | some name =>
    have size := form_echo_name_length name admitted.1
    have encoded := BodyCompiler.form_encode_length name
    have prefix : (formPrefix name true).length ≤ 392 := by
      simp only [formPrefix, List.length_append, List.length_singleton]
      omega
    simpa [formEchoDemand, echoMark, Demand.plus, Demand.literal, Demand.dynamic] using prefix

theorem form_node_limit_earns_bounded_demand (fields : List (Bytes × FormValue)) (insertion : Option Bytes) (demands : List Demand)
    (keys : TemplateMembers.KeyColumn (fields.map Prod.fst) .form)
    (echo : TemplateMembers.EchoAdmitted (fields.map Prod.fst) insertion .form)
    (paired : List.Forall₂ (fun member demand => FormValueAdmission member.2 demand) fields demands)
    (nodeLimit : (formDemand fields demands insertion).nodes ≤ 64) : Demand.Bounded (formDemand fields demands insertion) := by
  have names : ∀ member ∈ fields, OperationIdentity.validToken member.1 64 = true := by
    intro member present
    exact keys.2.2.1 member.1 (List.mem_map.mpr ⟨member, present, rfl⟩)
  obtain ⟨rowNodes, rowPieces, rowLiterals, rowDynamics⟩ := form_rows_bounds fields demands paired names
  obtain ⟨echoNodes, echoPieces, echoLiterals, echoDynamics⟩ := form_echo_demand_bounds _ insertion echo
  have members : fields.length + echoMark insertion ≤ 16 := by
    cases insertion with
    | none => simpa [TemplateMembers.maximum, echoMark] using keys.2.1
    | some name =>
      have spare : fields.length < 16 := by simpa [TemplateMembers.maximum] using echo.2.1
      have enough : fields.length + 1 ≤ 16 := by omega
      simpa [echoMark] using enough
  have marker := echo_mark_bound insertion
  have nodes : (Demand.sum demands).nodes ≤ 64 := by
    simpa [formDemand, Demand.plus, rowNodes, echoNodes] using nodeLimit
  refine ⟨nodeLimit, ?_, ?_, ?_⟩
  · simp only [formDemand, Demand.plus]
    rw [rowPieces, echoPieces]
    omega
  · simp only [formDemand, Demand.plus]
    omega
  · simp only [formDemand, Demand.plus]
    omega

/-- The existing global node limit earns every aggregate cap, including the
extra first-member separator reserves. Those reserves exclude no admitted
shape within 64 nodes. Native validation must still earn the shape relation. -/
theorem body_node_limit_earns_bounded_demand (body : Body) (echo : Option Echo) (demand : Demand)
    (admitted : BodyAdmission body echo demand) (nodes : demand.nodes ≤ 64) : Demand.Bounded demand := by
  cases admitted with
  | json value pointer demand admitted => exact json_node_limit_earns_bounded_demand 0 value pointer demand admitted nodes
  | form fields insertion demands keys echo admitted =>
    exact form_node_limit_earns_bounded_demand fields insertion demands keys echo admitted nodes

theorem node_bounded_body_admissible (body : Body) (echo : Option Echo) (demand : Demand)
    (admitted : BodyAdmission body echo demand) (nodes : demand.nodes ≤ 64) : BodyAdmissible body echo :=
  ⟨demand, admitted, body_node_limit_earns_bounded_demand body echo demand admitted nodes⟩

end Auths.Product.TemplateAst
