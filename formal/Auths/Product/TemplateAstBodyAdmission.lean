import Auths.Product.TemplateAstJsonAdmission

namespace Auths.Product.TemplateAst
open RequestConstruction BodyCompiler BodyCompiler.Resources AdmissionSupport
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

theorem form_start_has_admission_room (demand : Demand) (bounded : Demand.Bounded demand) : FormRoom formStart demand := by
  exact ⟨form_start_invariant, by simpa [formStart] using bounded.1,
    by simpa [formStart] using bounded.2.1, by simpa [formStart, zero] using bounded.2.2.1,
    by simpa [formStart, zero] using bounded.2.2.2⟩

/-- Nested JSON pays its original-tree node/literal/dynamic demand in the
parent form. Its separate inner piece domain is retained before the one outer
piece is pushed; a fresh temporary JSON builder cannot reset parent resources. -/
theorem form_value_admission_compiles (value : FormValue) (demand : Demand) (admitted : FormValueAdmission value demand)
    (before : FormBuild) (room : FormRoom before demand) :
    ∃ after, emitFormValue value before = .ok after ∧ FormSpend before after demand := by
  cases admitted with
  | text bytes bounded =>
    obtain ⟨after, run, spent⟩ := form_atom_admission before (.raw (formEncode bytes)) (by trivial) room
    exact ⟨after, by simpa [emitFormValue, bounded] using run, spent⟩
  | field name allowed =>
    obtain ⟨after, run, spent⟩ := form_atom_admission before (.field name) (by trivial) room
    exact ⟨after, by simpa [emitFormValue, allowed] using run, spent⟩
  | json value demand shape admitted count =>
    rcases room with ⟨valid, nodes, pieces, literals, dynamics⟩
    have innerRoom : JsonRoom (jsonStart before.nodes) demand := by
      refine ⟨json_start_invariant before.nodes valid.1, ?_, ?_, ?_, ?_⟩
      · simpa [jsonStart] using nodes
      · simpa [jsonStart] using count
      · simp only [jsonStart, zero, zero_add]
        omega
      · simp only [jsonStart, zero, zero_add]
        omega
    obtain ⟨nested, nestedRun, nestedSpend⟩ := json_admission_compiles 0 value none demand admitted (jsonStart before.nodes) innerRoom
    have innerPieces : nested.pieces.length ≤ 256 := by
      have used := nestedSpend.pieces
      simp only [jsonStart, List.length_nil, zero_add] at used
      omega
    have literalExact : nested.resources.literalBytes = jsonLiterals nested.pieces := by
      simpa [totals, jsonQuantity, jsonLiterals] using congrArg Usage.literalBytes nestedSpend.frame.invariant.2.2.2
    have dynamicExact : nested.resources.dynamicPieces = jsonDynamics nested.pieces := by
      simpa [totals, jsonQuantity, jsonDynamics] using congrArg Usage.dynamicPieces nestedSpend.frame.invariant.2.2.2
    have innerLiterals : jsonLiterals nested.pieces ≤ demand.literals := by
      have used := nestedSpend.literals
      simpa [jsonStart, zero, literalExact] using used
    have innerDynamics : jsonDynamics nested.pieces ≤ demand.dynamics := by
      have used := nestedSpend.dynamics
      simpa [jsonStart, zero, dynamicExact] using used
    let rebased : FormBuild := { before with nodes := nested.nodes }
    have rebasedValid : FormInvariant rebased := ⟨nestedSpend.frame.invariant.1, valid.2⟩
    have rebasedFrame : FormFrame before rebased := ⟨rebasedValid,
      by simpa [rebased, jsonStart] using nestedSpend.frame.nodes, by simp [rebased]⟩
    have outerRoom : FormRoom rebased (formAtom (.json nested.pieces)) := by
      refine ⟨rebasedValid, ?_, ?_, ?_, ?_⟩
      · simpa [rebased, formAtom] using nestedSpend.frame.invariant.1
      · simpa [rebased, formAtom] using pieces
      · simp only [rebased, formAtom, formLiteralSize]
        omega
      · simp only [rebased, formAtom, formDynamicSize]
        omega
    obtain ⟨after, pushed, spent⟩ := form_atom_admission rebased (.json nested.pieces) innerPieces outerRoom
    refine ⟨after, by simp [emitFormValue, shape, nestedRun, rebased, pushed], ?_⟩
    refine ⟨rebasedFrame.trans spent.frame, ?_, ?_, ?_, ?_⟩
    · have nodeUse := nestedSpend.nodes
      have outerUse := spent.nodes
      simp only [jsonStart, rebased, formAtom] at nodeUse outerUse
      omega
    · have used := spent.pieces
      simpa [rebased, formAtom] using used
    · have used := spent.literals
      simp only [rebased, formAtom, formLiteralSize] at used
      omega
    · have used := spent.dynamics
      simp only [rebased, formAtom, formDynamicSize] at used
      omega

private def formRowDemand (member : Bytes × FormValue) (demand : Demand) : Demand :=
  Demand.plus (Demand.literal (formPrefix member.1 true)) demand

private theorem form_item_spend (fields : List (Bytes × FormValue)) (demands : List Demand) (insertion : Option Bytes)
    (paired : List.Forall₂ (fun member demand => FormValueAdmission member.2 demand) fields demands)
    (choice : TemplateMembers.Choice)
    (safe : match choice with
      | .source index => ∃ name, (fields.map Prod.fst)[index]? = some name
      | .echo => ∃ name, insertion = some name) (position : Nat) :
    FormStep (formStep fields insertion) (choice, position)
      (choiceDemand ((fields.zip demands).map (fun (member, demand) => formRowDemand member demand)) (formEchoDemand insertion) choice) := by
  intro before room
  cases choice with
  | source index =>
    obtain ⟨name, keyAt⟩ := safe
    obtain ⟨value, demand, atField, atDemand, admitted, atRow⟩ := paired_key_at _ formRowDemand fields demands paired index name keyAt
    have available : FormRoom before (Demand.plus (Demand.literal (formPrefix name true)) demand) := by
      simpa [choiceDemand, atRow, formRowDemand] using room
    have prefixRoom := form_room_weaken before _ _ available (Demand.le_plus_left _ _)
    obtain ⟨prefixed, prefixRun, rawSpend⟩ := form_atom_admission before (.raw (formPrefix name (decide (0 < position)))) (by trivial)
      (form_room_weaken before _ _ prefixRoom (form_prefix_demand name _))
    have prefixSpend := rawSpend.weaken (form_prefix_demand name _)
    obtain ⟨after, childRun, childSpend⟩ := form_value_admission_compiles value demand admitted prefixed (form_room_after available prefixSpend)
    refine ⟨after, by simp [formStep, atField, prefixRun, childRun], ?_⟩
    simpa [choiceDemand, atRow, formRowDemand] using prefixSpend.trans childSpend
  | echo =>
    obtain ⟨name, inserted⟩ := safe
    have available : FormRoom before (Demand.plus (Demand.literal (formPrefix name true)) Demand.dynamic) := by
      simpa [choiceDemand, formEchoDemand, inserted] using room
    have prefixRoom := form_room_weaken before _ _ available (Demand.le_plus_left _ _)
    obtain ⟨prefixed, prefixRun, rawSpend⟩ := form_atom_admission before (.raw (formPrefix name (decide (0 < position)))) (by trivial)
      (form_room_weaken before _ _ prefixRoom (form_prefix_demand name _))
    have prefixSpend := rawSpend.weaken (form_prefix_demand name _)
    obtain ⟨after, echoRun, echoSpend⟩ := form_atom_admission prefixed .echo (by trivial) (form_room_after available prefixSpend)
    refine ⟨after, by simp [formStep, inserted, prefixRun, echoRun], ?_⟩
    simpa [choiceDemand, formEchoDemand, inserted] using prefixSpend.trans echoSpend

private theorem form_body_spend (fields : List (Bytes × FormValue)) (insertion : Option Bytes) (demands : List Demand)
    (keys : TemplateMembers.KeyColumn (fields.map Prod.fst) .form)
    (echo : TemplateMembers.EchoAdmitted (fields.map Prod.fst) insertion .form)
    (paired : List.Forall₂ (fun member demand => FormValueAdmission member.2 demand) fields demands)
    (bounded : Demand.Bounded (formDemand fields demands insertion)) :
    ∃ output, compileBody (.form fields) (insertion.map Echo.form) = .ok output := by
  obtain ⟨order, orderRun⟩ := TemplateMembers.canonical_useful_acceptance _ insertion .form ⟨keys, echo⟩
  let rows := (fields.zip demands).map (fun (member, demand) => formRowDemand member demand)
  have length : rows.length = (fields.map Prod.fst).length := by simp [rows, List.length_zip, paired.length_eq]
  have total : Demand.sum (order.map (choiceDemand rows (formEchoDemand insertion))) = formDemand fields demands insertion := by
    rw [canonical_choice_demand _ _ _ _ orderRun rows length]
    cases insertion <;> simp [formDemand, rows, formRowDemand, formEchoDemand]
  have each : ∀ choice data, (choice = data ∧ choice ∈ order) → ∀ position,
      FormStep (formStep fields insertion) (choice, position) (choiceDemand rows (formEchoDemand insertion) data) := by
    intro choice data related position
    subst data
    exact form_item_spend fields demands insertion paired choice (canonical_choices_safe _ _ _ order orderRun choice related.2) position
  have steps := indexed_pairs _ order order (paired_members order)
    (fun item => choiceDemand rows (formEchoDemand insertion) item.1)
    (FormStep (formStep fields insertion)) each 0
  rw [indexed_costs_constant] at steps
  have room : FormRoom formStart (Demand.sum (order.map (choiceDemand rows (formEchoDemand insertion)))) := by
    rw [total]
    exact form_start_has_admission_room _ bounded
  obtain ⟨after, run, spent⟩ := form_fold (formStep fields insertion) order.zipIdx _ steps formStart room
  have count : 0 < fields.length ∧ fields.length ≤ 16 :=
    ⟨by simpa using keys.1, by simpa [TemplateMembers.maximum] using keys.2.1⟩
  refine ⟨.form after.pieces, ?_⟩
  have traversed : formMembers fields order insertion = .ok after := by simpa [formMembers, formFrom] using run
  cases insertion <;>
    simpa [compileBody, count, orderRun, Except.mapError, formMembers, formFrom, formStep] using
      congrArg (Except.map (fun output : FormBuild => NamedTemplate.form output.pieces)) traversed

/-- Complete useful body compilation follows from independent original-tree
admission. Desired output, compiler success, a selected source index and a
caller-supplied validity flag are absent. Coverage of every native-valid source
by this conservative demand predicate remains a separate required bridge. -/
theorem admitted_body_compiles (body : Body) (echo : Option Echo) (admissible : BodyAdmissible body echo) :
    ∃ output, compileBody body echo = .ok output := by
  obtain ⟨demand, admitted, bounded⟩ := admissible
  cases admitted with
  | json value pointer demand admitted =>
    obtain ⟨after, run, spent⟩ := json_admission_compiles 0 value pointer demand admitted (jsonStart 0) (json_start_has_admission_room demand bounded)
    refine ⟨.json after.pieces, ?_⟩
    cases pointer <;> simpa [compileBody] using congrArg (Except.map (fun output : JsonBuild => NamedTemplate.json output.pieces)) run
  | form fields insertion demands keys echo admitted =>
    exact form_body_spend fields insertion demands keys echo admitted bounded

end Auths.Product.TemplateAst
