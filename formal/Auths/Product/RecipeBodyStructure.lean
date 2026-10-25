import Auths.Product.RecipeRulePathAdmission
import Auths.Product.TemplateAstShapeCoverage

namespace Auths.Product.RecipeRuleAdmission
open RequestConstruction NativeCompiler RecipeConsumption

/-- Representation order of every original object map. Bounds, grammar,
field admission, depth and compiler success are deliberately absent. The
public parser/BTreeMap boundary must earn this property for actual source
maps; an arbitrary list used by a foreign representation does not imply it. -/
inductive JsonMemberOrder : TemplateAst.Value → Prop where
  | text (value : Bytes) : JsonMemberOrder (.text value)
  | integer (value : Int) : JsonMemberOrder (.integer value)
  | boolean (value : Bool) : JsonMemberOrder (.boolean value)
  | field (name : Bytes) : JsonMemberOrder (.field name)
  | authorEcho : JsonMemberOrder .authorEcho
  | array (values : List TemplateAst.Value)
      (children : ∀ value ∈ values, JsonMemberOrder value) : JsonMemberOrder (.array values)
  | object (members : List (Bytes × TemplateAst.Value))
      (ordered : (members.map Prod.fst).Pairwise (· < ·))
      (children : ∀ member ∈ members, JsonMemberOrder member.2) : JsonMemberOrder (.object members)

def FormMemberOrder : TemplateAst.FormValue → Prop
  | .json value => JsonMemberOrder value
  | .text _ | .field _ | .authorEcho => True

def BodyMemberOrder : TemplateAst.Body → Prop
  | .json value => JsonMemberOrder value
  | .form members => (members.map Prod.fst).Pairwise (· < ·) ∧
      ∀ member ∈ members, FormMemberOrder member.2

/-- Complete original field references, independent of the argument values,
selected schema indices, compiled pieces or rendered provider request. -/
inductive JsonFieldsWithin (names : List Bytes) : TemplateAst.Value → Prop where
  | text (value : Bytes) : JsonFieldsWithin names (.text value)
  | integer (value : Int) : JsonFieldsWithin names (.integer value)
  | boolean (value : Bool) : JsonFieldsWithin names (.boolean value)
  | field (name : Bytes) (present : name ∈ names) : JsonFieldsWithin names (.field name)
  | array (values : List TemplateAst.Value)
      (children : ∀ value ∈ values, JsonFieldsWithin names value) : JsonFieldsWithin names (.array values)
  | object (members : List (Bytes × TemplateAst.Value))
      (children : ∀ member ∈ members, JsonFieldsWithin names member.2) : JsonFieldsWithin names (.object members)

def FormFieldsWithin (names : List Bytes) : TemplateAst.FormValue → Prop
  | .text _ => True
  | .field name => name ∈ names
  | .json value => JsonFieldsWithin names value
  | .authorEcho => False

def BodyFieldsWithin (names : List Bytes) : TemplateAst.Body → Prop
  | .json value => JsonFieldsWithin names value
  | .form members => ∀ member ∈ members, FormFieldsWithin names member.2

theorem field_ref_success_earns_original_name (original : List FieldProjection.Field) (fields : Fields)
    (layout : FieldProjection.LayoutValid original) (meaning : Rules.Meaning original fields)
    (name : Bytes) (state : State) (admitted : (fieldRef fields name state).1 = .ok ()) :
    TemplateAst.RenderedField name ∧ name ∈ FieldProjection.names original := by
  unfold fieldRef at admitted
  cases decoded : Rules.decodeName name with
  | none => simp [decoded, refused] at admitted
  | some key =>
      simp only [decoded] at admitted
      split at admitted
      · rename_i allowed
        have lexical : TemplateAst.RenderedField name := by
          simpa only [decide_eq_true_eq] using (Bool.and_eq_true.mp allowed).2
        have known : fieldTest (fun _ => true) fields key = true := by
          have present := (Bool.and_eq_true.mp allowed).1
          cases atSchema : schemaFor key fields <;> simp_all [fieldTest]
        have named := (field_test_earns_original_plan_name original fields layout meaning (fun _ => true) key known).2
        have bytesAt := Rules.decoded_name_has_original_bytes name key decoded
        exact ⟨lexical, by simpa only [bytesAt] using named⟩
      · simp [refused] at admitted

theorem original_array_nodes_sum (values : List TemplateAst.Value) :
    TemplateAst.arrayNodes values = (values.map TemplateAst.jsonNodes).sum := by
  induction values <;> simp_all [TemplateAst.arrayNodes]

theorem original_member_nodes_sum (members : List (Bytes × TemplateAst.Value)) :
    TemplateAst.memberNodes members = (members.map (fun member => TemplateAst.jsonNodes member.2)).sum := by
  induction members with
  | nil => rfl
  | cons member rest ih => cases member; simp [TemplateAst.memberNodes, ih]

/-- A complete successful source fold earns each child on its actual earlier
counter/state, its untruncated aggregate cost and its final shared-node limit.
The step relation describes the fixed source visitor; it is discharged by the
body induction, not accepted as an external Auths decision. -/
theorem fold_nodes_success_earns_domain {T : Type} (visit : T → Nat → State → NodeOutcome)
    (items : List T) (property : T → Prop) (cost : T → Nat) (nodes : Nat) (state : State)
    (initial : nodes ≤ 64)
    (step : ∀ item ∈ items, ∀ count current, count ≤ 64 →
      (visit item count current).1.1 = .ok () →
        property item ∧ (visit item count current).2 = count + cost item ∧ (visit item count current).2 ≤ 64)
    (admitted : (foldNodes visit items nodes state).1.1 = .ok ()) :
    (∀ item ∈ items, property item) ∧ (foldNodes visit items nodes state).2 = nodes + (items.map cost).sum ∧
      (foldNodes visit items nodes state).2 ≤ 64 := by
  induction items generalizing nodes state with
  | nil => exact ⟨by simp, by rfl, initial⟩
  | cons item rest ih =>
      rcases headAt : visit item nodes state with ⟨⟨verdict, nextState⟩, nextNodes⟩
      cases verdict with
      | error error => simp [foldNodes, headAt] at admitted
      | ok unit =>
          cases unit
          have accepted : (visit item nodes state).1.1 = .ok () := by simp [headAt]
          obtain ⟨first, spent, bounded⟩ := step item (by simp) nodes state initial accepted
          have continued : foldNodes visit (item :: rest) nodes state = foldNodes visit rest nextNodes nextState := by
            simp [foldNodes, headAt]
          have tailAccepted : (foldNodes visit rest nextNodes nextState).1.1 = .ok () := by simpa [continued] using admitted
          have nextBound : nextNodes ≤ 64 := by simpa [headAt] using bounded
          obtain ⟨remaining, total, finalBound⟩ := ih nextNodes nextState nextBound
            (fun later member => step later (List.mem_cons_of_mem _ member)) tailAccepted
          refine ⟨?_, ?_, by simpa only [continued] using finalBound⟩
          · intro value member
            rcases List.mem_cons.mp member with rfl | later
            · exact first
            · exact remaining value later
          · have firstCost : nextNodes = nodes + cost item := by simpa [headAt] using spent
            simp only [continued, List.map_cons, List.sum_cons, total, firstCost, Nat.add_assoc]

end Auths.Product.RecipeRuleAdmission
