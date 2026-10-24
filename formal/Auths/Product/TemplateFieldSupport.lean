import Auths.Product.RecipeBodyStructure
import Auths.Product.TemplateAstResources

namespace Auths.Product.TemplateAst
open RequestConstruction BodyCompiler

def JsonPieceFields (names : List Bytes) : NamedJson → Prop
  | .raw _ | .echo => True
  | .field name => name ∈ names

def JsonFields (names : List Bytes) (pieces : List NamedJson) : Prop :=
  ∀ piece ∈ pieces, JsonPieceFields names piece

def FormPieceFields (names : List Bytes) : NamedForm → Prop
  | .raw _ | .echo => True
  | .field name => name ∈ names
  | .json pieces => JsonFields names pieces

def FormFields (names : List Bytes) (pieces : List NamedForm) : Prop :=
  ∀ piece ∈ pieces, FormPieceFields names piece

def TemplateFields (names : List Bytes) : NamedTemplate → Prop
  | .json pieces => JsonFields names pieces
  | .form pieces => FormFields names pieces

instance (names : List Bytes) (piece : NamedJson) : Decidable (JsonPieceFields names piece) := by
  cases piece <;> unfold JsonPieceFields <;> infer_instance

instance (names : List Bytes) (pieces : List NamedJson) : Decidable (JsonFields names pieces) := by
  unfold JsonFields
  infer_instance

instance (names : List Bytes) (piece : NamedForm) : Decidable (FormPieceFields names piece) := by
  cases piece <;> unfold FormPieceFields <;> infer_instance

instance (names : List Bytes) (pieces : List NamedForm) : Decidable (FormFields names pieces) := by
  unfold FormFields
  infer_instance

instance (names : List Bytes) (template : NamedTemplate) : Decidable (TemplateFields names template) := by
  cases template <;> unfold TemplateFields <;> infer_instance

namespace FieldSupport

theorem bind_success {A B : Type} (first : Except Error A) (next : A → Except Error B) (output : B)
    (completed : (first >>= next) = .ok output) :
    ∃ value, first = .ok value ∧ next value = .ok output := by
  cases first with
  | error error => simp [Bind.bind, Except.bind] at completed
  | ok value => exact ⟨value, rfl, by simpa [Bind.bind, Except.bind] using completed⟩

theorem fold_preserves {S T : Type} (property : S → Prop) (step : S → T → Except Error S)
    (items : List T) (before after : S) (initial : property before)
    (preserves : ∀ current item next, item ∈ items → property current → step current item = .ok next → property next)
    (completed : items.foldlM step before = .ok after) : property after := by
  induction items generalizing before with
  | nil => have same : before = after := by simpa using completed; simpa only [← same] using initial
  | cons item rest ih =>
      rw [List.foldlM_cons] at completed
      obtain ⟨middle, first, remaining⟩ := bind_success _ _ _ completed
      exact ih middle (preserves before item middle (by simp) initial first)
        (fun current later next member => preserves current later next (List.mem_cons_of_mem _ member)) remaining

end FieldSupport

theorem json_push_preserves_fields (names : List Bytes) (before after : JsonBuild) (piece : NamedJson)
    (initial : JsonFields names before.pieces) (known : JsonPieceFields names piece)
    (completed : pushJson before piece = .ok after) : JsonFields names after.pieces := by
  unfold pushJson at completed
  split at completed
  · cases charged : BodyCompiler.Resources.add before.resources (BodyCompiler.Resources.jsonQuantity piece) with
    | none => simp [charged] at completed
    | some resources =>
        have same : after = ⟨before.nodes, resources, before.pieces ++ [piece]⟩ := by simpa [charged] using completed.symm
        subst after
        intro item member
        rcases List.mem_append.mp member with previous | current
        · exact initial item previous
        · simpa only [List.mem_singleton.mp current] using known
  · contradiction

theorem form_push_preserves_fields (names : List Bytes) (before after : FormBuild) (piece : NamedForm)
    (initial : FormFields names before.pieces) (known : FormPieceFields names piece)
    (completed : pushForm before piece = .ok after) : FormFields names after.pieces := by
  unfold pushForm at completed
  split at completed
  · cases charged : BodyCompiler.Resources.formCharge before.resources piece with
    | none => simp [charged] at completed
    | some resources =>
        have same : after = ⟨before.nodes, resources, before.pieces ++ [piece]⟩ := by simpa [charged] using completed.symm
        subst after
        intro item member
        rcases List.mem_append.mp member with previous | current
        · exact initial item previous
        · simpa only [List.mem_singleton.mp current] using known
  · contradiction

theorem member_cost_le_sum {T : Type} (items : List T) (cost : T → Nat) (item : T) (member : item ∈ items) :
    cost item ≤ (items.map cost).sum := by
  induction items with
  | nil => simp at member
  | cons first rest ih =>
      rcases List.mem_cons.mp member with rfl | later
      · simp
      · have bounded := ih later
        simp only [List.map_cons, List.sum_cons]
        omega

theorem original_name_is_token (fields : List FieldProjection.Field) (layout : FieldProjection.LayoutValid fields)
    (name : Bytes) (member : name ∈ FieldProjection.names fields) : OperationIdentity.validToken name 64 = true := by
  obtain ⟨field, present, same⟩ := List.mem_map.mp member
  simpa only [same] using layout.2.2 field present

theorem json_fields_resources_earn_lowering (fields : List FieldProjection.Field)
    (layout : FieldProjection.LayoutValid fields) (pieces : List NamedJson)
    (count : pieces.length ≤ 256) (resources : JsonResourceDomain pieces)
    (known : JsonFields (FieldProjection.names fields) pieces) : JsonTemplateAdmissible (FieldProjection.names fields) pieces := by
  have namesBound : (FieldProjection.names fields).length ≤ 32 := by simpa [FieldProjection.names] using layout.1
  refine ⟨namesBound, count, ?_, resources⟩
  intro piece member
  cases piece with
  | raw bytes =>
      have contribution := member_cost_le_sum pieces jsonLiteralSize (.raw bytes) member
      change bytes.length ≤ 524288
      have bound := resources.1
      simp only [jsonLiteralSize] at contribution
      unfold jsonLiterals at bound
      omega
  | field name => exact ⟨namesBound, original_name_is_token fields layout name (known _ member), known _ member⟩
  | echo => trivial

theorem form_fields_resources_earn_lowering (fields : List FieldProjection.Field)
    (layout : FieldProjection.LayoutValid fields) (pieces : List NamedForm)
    (count : pieces.length ≤ 256) (resources : FormResourceDomain pieces)
    (known : FormFields (FieldProjection.names fields) pieces) : FormTemplateAdmissible (FieldProjection.names fields) pieces := by
  have namesBound : (FieldProjection.names fields).length ≤ 32 := by simpa [FieldProjection.names] using layout.1
  refine ⟨namesBound, count, ?_, resources⟩
  intro piece member
  cases piece with
  | raw bytes =>
      have contribution := member_cost_le_sum pieces formLiteralSize (.raw bytes) member
      change bytes.length ≤ 524288
      have bound := resources.1
      simp only [formLiteralSize] at contribution
      unfold formLiterals at bound
      omega
  | field name => exact ⟨namesBound, original_name_is_token fields layout name (known _ member), known _ member⟩
  | echo => trivial
  | json nested =>
      have literals := member_cost_le_sum pieces formLiteralSize (.json nested) member
      have dynamics := member_cost_le_sum pieces formDynamicSize (.json nested) member
      have nestedResources : JsonResourceDomain nested := by
        have literalBound := resources.1
        have dynamicBound := resources.2.1
        simp only [formLiteralSize, formDynamicSize] at literals dynamics
        unfold formLiterals at literalBound
        unfold formDynamics at dynamicBound
        exact ⟨by omega, by omega⟩
      exact json_fields_resources_earn_lowering fields layout nested (resources.2.2 _ member) nestedResources (known _ member)

/-- Complete emitted field support and the emitter's earned resource domain
give the actual named-piece lowerer's admission, including nested form JSON.
No successful lowerer or selected argument index is supplied. -/
theorem template_fields_resources_earn_body_lowering (fields : List FieldProjection.Field)
    (layout : FieldProjection.LayoutValid fields) (template : NamedTemplate)
    (resources : TemplateDomain template) (known : TemplateFields (FieldProjection.names fields) template) :
    RequestCompiler.BodyAdmissible (FieldProjection.names fields) (namedBody template) := by
  cases template with
  | json pieces => exact json_fields_resources_earn_lowering fields layout pieces resources.1 resources.2 known
  | form pieces => exact form_fields_resources_earn_lowering fields layout pieces resources.1 resources.2 known

end Auths.Product.TemplateAst
