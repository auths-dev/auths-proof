import Auths.Product.RecipeBodyEchoAdmission
import Auths.Product.TemplateBodyFieldSupport

namespace Auths.Product.RecipeRuleAdmission
open RequestConstruction NativeCompiler RecipeConsumption TemplateAst

/-- Complete original rule admission earns a named body and its full typed
piece/index-lowering domain. Source field support crosses every emitted piece;
literal and nested resource limits come from the successful original emitter.
No chosen template or successful body lowerer is a caller premise. -/
theorem complete_rules_earn_typed_named_body {E : Type} (errors : RecipePlanModel.Errors E)
    (original : List FieldProjection.Field) (fields : Fields) (layout : FieldProjection.LayoutValid original)
    (meaning : Rules.Meaning original fields) (source : Source) (order : BodyMemberOrder source.body)
    (admitted : (validate fields source).1 = .ok ()) :
    ∃ named, RecipePlanModel.namedBody errors source.body (source.echo.map (·.write)) = .ok named ∧
      RequestCompiler.BodyAdmissible (FieldProjection.names original) (TemplateAst.namedBody named) := by
  obtain ⟨sourceFields, _, named, compiled, resources⟩ := complete_rules_earn_named_body errors original fields layout meaning source order admitted
  have emittedFields := named_body_preserves_original_fields errors (FieldProjection.names original) source.body
    (source.echo.map (·.write)) named sourceFields compiled
  exact ⟨named, compiled, template_fields_resources_earn_body_lowering original layout named resources emittedFields⟩

end Auths.Product.RecipeRuleAdmission
