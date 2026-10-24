import Auths.Product.TemplateAstAdmissionFold

namespace Auths.Product.TemplateAst
open RequestConstruction BodyCompiler BodyCompiler.Resources AdmissionSupport
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

private theorem leaf_spend (depth : Nat) (value : Value) (admitted : LeafAdmission value)
    (within : depth ≤ 6) (before : JsonBuild) (room : JsonRoom before (leafDemand value)) :
    ∃ after, emitJson 7 value none depth before = .ok after ∧ JsonSpend before after (leafDemand value) := by
  obtain ⟨initial, charged, initialSame, initialSpend⟩ := json_node_admission depth before within
    (json_room_weaken before Demand.node _ room (Demand.le_plus_left _ _))
  have remaining := json_room_after room initialSpend
  obtain ⟨after, pushed, spent⟩ := json_atom_admission initial (leafPiece value) remaining
  refine ⟨after, ?_, initialSpend.trans spent⟩
  cases admitted <;> simpa [emit_json_dispatch_exact, dispatchJson, charged, initialSame, isObject, leafPiece, *] using pushed

private theorem array_item_spend (depth : Nat) (value : Value) (demand : Demand)
    (child : ∀ before, JsonRoom before demand → ∃ after,
      emitJson 7 value none (depth + 1) before = .ok after ∧ JsonSpend before after demand)
    (position : Nat) : JsonStep (fun before item => arrayItem item.1 depth item.2 before)
      (value, position) (Demand.plus (separatorDemand position) demand) := by
  intro before room
  have separator : ∃ separated,
      (if 0 < position then pushJson before (.raw [44]) else .ok before) = .ok separated ∧
      JsonSpend before separated (separatorDemand position) := by
    by_cases positive : 0 < position
    · have firstRoom : JsonRoom before (Demand.atom (.raw [44])) := by
        simpa [separatorDemand, positive, Demand.literal, Demand.atom, jsonLiteralSize, jsonDynamicSize] using
          json_room_weaken before _ _ room (Demand.le_plus_left _ _)
      obtain ⟨separated, run, spent⟩ := json_atom_admission before (.raw [44]) firstRoom
      exact ⟨separated, by simpa [positive] using run, by simpa [separatorDemand, positive] using spent⟩
    · exact ⟨before, by simp [positive], by simpa [separatorDemand, positive] using JsonSpend.refl before room.1⟩
  obtain ⟨separated, separatorRun, separatorSpend⟩ := separator
  obtain ⟨after, childRun, childSpend⟩ := child separated (json_room_after room separatorSpend)
  exact ⟨after, by simp [arrayItem, separatorRun, childRun], separatorSpend.trans childSpend⟩

private theorem array_spend (depth : Nat) (items : List Value) (demands : List Demand) (within : depth ≤ 6)
    (count : 0 < items.length ∧ items.length ≤ 16)
    (paired : List.Forall₂ (fun value demand => JsonAdmission (depth + 1) value none demand) items demands)
    (children : ∀ value demand, JsonAdmission (depth + 1) value none demand → ∀ before, JsonRoom before demand →
      ∃ after, emitJson 7 value none (depth + 1) before = .ok after ∧ JsonSpend before after demand)
    (before : JsonBuild) (room : JsonRoom before (arrayDemand items demands)) :
    ∃ after, emitJson 7 (.array items) none depth before = .ok after ∧ JsonSpend before after (arrayDemand items demands) := by
  let costs := (demands.zipIdx 0).map (fun item => Demand.plus (separatorDemand item.2) item.1)
  have decomposition := array_demand_decomposition items demands paired.length_eq
  rw [decomposition] at room
  obtain ⟨initial, charged, initialSame, initialSpend⟩ := json_node_admission depth before within
    (json_room_weaken before Demand.node _ room (Demand.le_plus_left _ _))
  have afterNode := json_room_after room initialSpend
  obtain ⟨opened, openRun, openSpend⟩ := json_atom_admission initial (.raw [91])
    (json_room_weaken initial _ _ afterNode (Demand.le_plus_left _ _))
  have afterOpen := json_room_after afterNode openSpend
  have steps := indexed_pairs _ items demands paired
    (fun item => Demand.plus (separatorDemand item.2) item.1)
    (JsonStep (fun current item => arrayItem item.1 depth item.2 current))
    (fun value demand admitted position => array_item_spend depth value demand (children value demand admitted) position) 0
  obtain ⟨folded, foldRun, foldSpend⟩ := json_fold (fun current item => arrayItem item.1 depth item.2 current)
    items.zipIdx costs steps opened (json_room_weaken opened _ _ afterOpen (Demand.le_plus_left _ _))
  obtain ⟨after, closeRun, closeSpend⟩ := json_atom_admission folded (.raw [93]) (json_room_after afterOpen foldSpend)
  have traversed : arrayFrom items depth 0 opened = .ok folded := by simpa [arrayFrom] using foldRun
  refine ⟨after, ?_, ?_⟩
  · simp [emit_json_dispatch_exact, dispatchJson, charged, initialSame, isObject, jsonArray, count, openRun, traversed, closeRun]
  · simpa [decomposition, costs] using initialSpend.trans (openSpend.trans (foldSpend.trans closeSpend))

private def jsonRowDemand (member : Bytes × Value) (demand : Demand) : Demand :=
  Demand.plus (Demand.literal (jsonPrefix member.1 true)) demand

private theorem object_item_spend (depth : Nat) (fields : List (Bytes × Value)) (demands : List Demand)
    (echo : Option (List Bytes)) (route : NamedEchoRoute) (target : Option TemplateMembers.Target)
    (paired : List.Forall₂ (fun member demand => JsonAdmission (depth + 1) member.2 (namedChildEcho route member.1) demand) fields demands)
    (children : ∀ value nested demand, JsonAdmission (depth + 1) value nested demand → ∀ before, JsonRoom before demand →
      ∃ after, emitJson 7 value nested (depth + 1) before = .ok after ∧ JsonSpend before after demand)
    (echoMeaning : ∀ index name, (fields.map Prod.fst)[index]? = some name →
      objectChildEcho target echo index = .ok (namedChildEcho route name))
    (choice : TemplateMembers.Choice)
    (safe : match choice with
      | .source index => ∃ name, (fields.map Prod.fst)[index]? = some name
      | .echo => ∃ name, route.insertion = some name)
    (position : Nat) :
    JsonStep (objectStep fields target echo route.insertion depth) (choice, position)
      (choiceDemand ((fields.zip demands).map (fun (member, demand) => jsonRowDemand member demand)) (echoDemand route.insertion) choice) := by
  intro before room
  cases choice with
  | source index =>
    obtain ⟨name, keyAt⟩ := safe
    obtain ⟨value, demand, atField, atDemand, admitted, atRow⟩ := paired_key_at _ jsonRowDemand fields demands paired index name keyAt
    have available : JsonRoom before (Demand.plus (Demand.literal (jsonPrefix name true)) demand) := by
      simpa [choiceDemand, atRow, jsonRowDemand] using room
    have prefixRoom := json_room_weaken before _ _ available (Demand.le_plus_left _ _)
    obtain ⟨prefixed, prefixRun, rawSpend⟩ := json_atom_admission before (.raw (jsonPrefix name (decide (0 < position))))
      (json_room_weaken before _ _ prefixRoom (json_prefix_demand name _))
    have prefixSpend := rawSpend.weaken (json_prefix_demand name _)
    obtain ⟨after, childRun, childSpend⟩ := children value (namedChildEcho route name) demand admitted prefixed
      (json_room_after available prefixSpend)
    refine ⟨after, ?_, ?_⟩
    · simp [objectStep, atField, prefixRun, echoMeaning index name keyAt, childRun]
    · simpa [choiceDemand, atRow, jsonRowDemand] using prefixSpend.trans childSpend
  | echo =>
    obtain ⟨name, insertion⟩ := safe
    have available : JsonRoom before (Demand.plus (Demand.literal (jsonPrefix name true)) Demand.dynamic) := by
      simpa [choiceDemand, echoDemand, insertion] using room
    have prefixRoom := json_room_weaken before _ _ available (Demand.le_plus_left _ _)
    obtain ⟨prefixed, prefixRun, rawSpend⟩ := json_atom_admission before (.raw (jsonPrefix name (decide (0 < position))))
      (json_room_weaken before _ _ prefixRoom (json_prefix_demand name _))
    have prefixSpend := rawSpend.weaken (json_prefix_demand name _)
    obtain ⟨after, echoRun, echoSpend⟩ := json_atom_admission prefixed .echo (json_room_after available prefixSpend)
    refine ⟨after, by simp [objectStep, insertion, prefixRun, echoRun], ?_⟩
    simpa [choiceDemand, echoDemand, insertion] using prefixSpend.trans echoSpend

private theorem object_spend (depth : Nat) (fields : List (Bytes × Value)) (echo : Option (List Bytes))
    (route : NamedEchoRoute) (demands : List Demand) (within : depth ≤ 6)
    (keys : TemplateMembers.KeyColumn (fields.map Prod.fst) .json)
    (routeMeaning : namedEchoRoute (fields.map Prod.fst) echo = .ok route)
    (paired : List.Forall₂ (fun member demand => JsonAdmission (depth + 1) member.2 (namedChildEcho route member.1) demand) fields demands)
    (children : ∀ value nested demand, JsonAdmission (depth + 1) value nested demand → ∀ before, JsonRoom before demand →
      ∃ after, emitJson 7 value nested (depth + 1) before = .ok after ∧ JsonSpend before after demand)
    (before : JsonBuild) (room : JsonRoom before (objectDemand fields demands route.insertion)) :
    ∃ after, emitJson 7 (.object fields) echo depth before = .ok after ∧ JsonSpend before after (objectDemand fields demands route.insertion) := by
  obtain ⟨target, targetRun, insertionRun, childEchoMeaning⟩ := named_route_compiles _ echo route keys routeMeaning
  obtain ⟨order, orderRun⟩ := TemplateMembers.canonical_useful_acceptance _ route.insertion .json
    (named_route_member_admission _ echo route keys routeMeaning)
  let rows := (fields.zip demands).map (fun (member, demand) => jsonRowDemand member demand)
  let inner := Demand.plus (Demand.sum rows) (echoDemand route.insertion)
  have length : rows.length = (fields.map Prod.fst).length := by
    simp [rows, List.length_zip, paired.length_eq]
  have total : Demand.sum (order.map (choiceDemand rows (echoDemand route.insertion))) = inner := by
    rw [canonical_choice_demand _ _ _ _ orderRun rows length]
    cases insertion : route.insertion <;> simp [inner, echoDemand, insertion]
  have decomposition : objectDemand fields demands route.insertion = Demand.plus Demand.node
      (Demand.plus (Demand.literal [123]) (Demand.plus inner (Demand.literal [125]))) := by
    apply Demand.ext <;> simp [objectDemand, inner, rows, jsonRowDemand, Demand.plus, Demand.literal, Demand.node]
    all_goals omega
  rw [decomposition] at room
  obtain ⟨initial, charged, initialSame, initialSpend⟩ := json_node_admission depth before within
    (json_room_weaken before Demand.node _ room (Demand.le_plus_left _ _))
  have afterNode := json_room_after room initialSpend
  obtain ⟨opened, openRun, openSpend⟩ := json_atom_admission initial (.raw [123])
    (json_room_weaken initial _ _ afterNode (Demand.le_plus_left _ _))
  have afterOpen := json_room_after afterNode openSpend
  have each : ∀ choice data, (choice = data ∧ choice ∈ order) → ∀ position,
      JsonStep (objectStep fields target echo route.insertion depth) (choice, position)
        (choiceDemand rows (echoDemand route.insertion) data) := by
    intro choice data related position
    subst data
    exact object_item_spend depth fields demands echo route target paired children childEchoMeaning choice
      (canonical_choices_safe _ _ _ order orderRun choice related.2) position
  have steps := indexed_pairs _ order order (paired_members order)
    (fun item => choiceDemand rows (echoDemand route.insertion) item.1)
    (JsonStep (objectStep fields target echo route.insertion depth)) each 0
  rw [indexed_costs_constant] at steps
  have foldRoom : JsonRoom opened (Demand.sum (order.map (choiceDemand rows (echoDemand route.insertion)))) := by
    rw [total]
    exact json_room_weaken opened _ _ afterOpen (Demand.le_plus_left _ _)
  obtain ⟨folded, foldRun, foldSpend⟩ := json_fold (objectStep fields target echo route.insertion depth)
    order.zipIdx _ steps opened foldRoom
  rw [total] at foldSpend
  obtain ⟨after, closeRun, closeSpend⟩ := json_atom_admission folded (.raw [125]) (json_room_after afterOpen foldSpend)
  have traversed : objectFrom fields order target echo route.insertion depth 0 opened = .ok folded := by
    simpa [objectFrom] using foldRun
  have count : 0 < fields.length ∧ fields.length ≤ 32 := by
    exact ⟨by simpa using keys.1, by simpa [TemplateMembers.maximum] using keys.2.1⟩
  refine ⟨after, ?_, ?_⟩
  · simp [emit_json_dispatch_exact, dispatchJson, charged, initialSame, isObject, jsonObject, count,
      targetRun, insertionRun, orderRun, Except.mapError, openRun, traversed, closeRun]
  · simpa [decomposition] using initialSpend.trans (openSpend.trans (foldSpend.trans closeSpend))

/-- Complete useful JSON acceptance from original-tree admission and an earned
resource frame. Every recursive child consumes its returned meter/resources;
object selection and echo descent are derived from original-name routes. -/
theorem json_admission_compiles (depth : Nat) (value : Value) (echo : Option (List Bytes)) (demand : Demand)
    (admitted : JsonAdmission depth value echo demand) (before : JsonBuild) (room : JsonRoom before demand) :
    ∃ after, emitJson 7 value echo depth before = .ok after ∧ JsonSpend before after demand := by
  generalize remainingEq : 7 - depth = remaining
  induction remaining using Nat.strong_induction_on generalizing depth value echo demand before with
  | h remaining ih =>
    have within := (json_admission_positive_nodes depth value echo demand admitted).2
    have children : ∀ child nested cost, JsonAdmission (depth + 1) child nested cost → ∀ current, JsonRoom current cost →
        ∃ after, emitJson 7 child nested (depth + 1) current = .ok after ∧ JsonSpend current after cost := by
      intro child nested cost childAdmission current childRoom
      exact ih (7 - (depth + 1)) (by omega) (depth + 1) child nested cost childAdmission current childRoom rfl
    cases admitted with
    | leaf depth value within admitted => exact leaf_spend depth value admitted within before room
    | array depth items costs within count paired =>
      exact array_spend depth items costs within count paired (fun value cost admitted => children value none cost admitted) before room
    | object depth fields echo route costs within keys routeMeaning paired =>
      exact object_spend depth fields echo route costs within keys routeMeaning paired children before room

end Auths.Product.TemplateAst
