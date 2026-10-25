import Auths.Product.RecipeSerdeBody
import Auths.Product.NativeSerdeUniqueness

/-!
Every object of the complete typed-body serialization has unique original
names. User map names come from full decoded carrier provenance; fixed serde
field/tag names are checked separately. Includes rejected author Echo and all
original children. This grants no recipe admission or native Serialize proof.
-/
namespace Auths.Product.RecipeSerde
open NativeCompiler NativeSerde

theorem ast_member_encoding_keeps_names {inputs : List (String × SourceAst)}
    {outputs : List (String × Json)} (encoded : AstMemberEncodings inputs outputs) :
    outputs.map Prod.fst = inputs.map Prod.fst := by
  induction encoded with
  | nil => rfl
  | cons head tail ih => simp only [List.map_cons, ih]

mutual
  theorem ast_encoding_has_unique_objects {input : SourceAst} {output : Json}
      (encoded : AstEncoding input output) (unique : CarrierUnique (.internal .value) input) :
      FullJsonValue.Unique output := by
    cases encoded with
    | text value => simp [tagged]
    | integer value => simp [tagged]
    | boolean value => simp [tagged]
    | field name => simp [tagged]
    | echo => simp [tagged]
    | object children =>
        have members := unique_variant_field unique (.map (.internal .value)) _ (by simp [variantSlots])
        cases members with
        | map value names each =>
            have objectUnique : FullJsonValue.Unique (.object _) :=
              (FullJsonValue.object_unique_iff _).mpr
                ⟨by rw [ast_member_encoding_keeps_names children]; exact names,
                  ast_members_encoding_has_unique_objects children each⟩
            simpa [tagged] using objectUnique
    | array children =>
        have values := unique_variant_field unique (.vector (.internal .value)) _ (by simp [variantSlots])
        cases values with
        | vector value each =>
            have arrayUnique : FullJsonValue.Unique (.array _) :=
              (FullJsonValue.array_unique_iff _).mpr (ast_values_encoding_has_unique_objects children each)
            simpa [tagged] using arrayUnique
  termination_by structural encoded

  theorem ast_values_encoding_has_unique_objects {inputs : List SourceAst} {outputs : List Json}
      (encoded : AstEncodings inputs outputs) (unique : ElementsUnique (.internal .value) inputs) :
      ∀ output ∈ outputs, FullJsonValue.Unique output := by
    cases encoded with
    | nil => simp
    | cons head tail =>
        cases unique with
        | cons first rest =>
            intro output present
            rcases List.mem_cons.mp present with rfl | later
            · exact ast_encoding_has_unique_objects head first
            · exact ast_values_encoding_has_unique_objects tail rest output later
  termination_by structural encoded

  theorem ast_members_encoding_has_unique_objects {inputs : List (String × SourceAst)}
      {outputs : List (String × Json)} (encoded : AstMemberEncodings inputs outputs)
      (unique : MembersUnique (.internal .value) inputs) :
      ∀ output ∈ outputs, FullJsonValue.Unique output.2 := by
    cases encoded with
    | nil => simp
    | cons head tail =>
        cases unique with
        | cons first rest =>
            intro output present
            rcases List.mem_cons.mp present with rfl | later
            · exact ast_encoding_has_unique_objects head first
            · exact ast_members_encoding_has_unique_objects tail rest output later
  termination_by structural encoded
end

theorem form_encoding_has_unique_objects {input : SourceForm} {output : Json}
    (encoded : FormEncoding input output) (unique : CarrierUnique (.internal .form) input) :
    FullJsonValue.Unique output := by
  cases encoded with
  | text value => simp [tagged]
  | field name => simp [tagged]
  | echo => simp [tagged]
  | json child =>
      have value := unique_variant_field unique (.internal .value) _ (by simp [variantSlots])
      have childUnique := ast_encoding_has_unique_objects child value
      simpa [tagged] using childUnique

theorem form_member_encoding_keeps_names {inputs : List (String × SourceForm)}
    {outputs : List (String × Json)} (encoded : List.Forall₂ FormMemberEncoding inputs outputs) :
    outputs.map Prod.fst = inputs.map Prod.fst := by
  induction encoded with
  | nil => rfl
  | cons head tail ih => simp only [List.map_cons, ← head.1, ih]

theorem form_members_encoding_has_unique_objects {inputs : List (String × SourceForm)}
    {outputs : List (String × Json)} (encoded : List.Forall₂ FormMemberEncoding inputs outputs)
    (unique : MembersUnique (.internal .form) inputs) :
    ∀ output ∈ outputs, FullJsonValue.Unique output.2 := by
  revert unique
  induction encoded with
  | nil => intro _; simp
  | cons head tail ih =>
      intro unique
      cases unique with
      | cons first rest =>
          intro output present
          rcases List.mem_cons.mp present with rfl | later
          · exact form_encoding_has_unique_objects head.2 first
          · exact ih rest output later

theorem body_encoding_has_unique_objects {input : SourceBody} {output : Json}
    (encoded : BodyEncoding input output) (unique : CarrierUnique (.internal .body) input) :
    FullJsonValue.Unique output := by
  cases encoded with
  | json child =>
      have value := unique_variant_field unique (.internal .value) _ (by simp [variantSlots])
      have childUnique := ast_encoding_has_unique_objects child value
      simpa [tagged] using childUnique
  | form fields =>
      have members := unique_variant_field unique (.map (.internal .form)) _ (by simp [variantSlots])
      cases members with
      | map value names each =>
          have objectUnique : FullJsonValue.Unique (.object _) :=
            (FullJsonValue.object_unique_iff _).mpr
              ⟨by rw [form_member_encoding_keeps_names fields]; exact names,
                form_members_encoding_has_unique_objects fields each⟩
          simpa [tagged] using objectUnique

end Auths.Product.RecipeSerde
