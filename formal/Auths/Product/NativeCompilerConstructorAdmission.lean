import Auths.Product.NativeCompilerConstructorStages

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

set_option maxHeartbeats 30000000
set_option maxRecDepth 4096

private theorem projected_unit_error (actual : core.result.Result Unit NativeRecipeError) (error : NativeRecipeError)
    (meaning : nativeLockOutcome actual = .error error) : actual = .Err error := by
  cases actual <;> simp_all [nativeLockOutcome]

private theorem projected_unit_ok (actual : core.result.Result Unit NativeRecipeError)
    (meaning : nativeLockOutcome actual = .ok ()) : actual = .Ok () := by
  cases actual with
  | Err error => simp [nativeLockOutcome] at meaning
  | Ok unit => cases unit; rfl

private theorem native_ctor_from_map_exact (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (schema : ProfileSchema.Value)
    (specs : NativeVec NativeFieldSpec) (namespaceValue : AuthsNativeRecipe.recipe.OperatorNamespace)
    (fields : NativeRuleMap) (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (count : fields.entries.val.length ≤ 32)
    (names : ∀ entry ∈ fields.entries.val, TextFits entry.1) :
    nativeCtorFromMap source canonical specs namespaceValue fields ⦃ actual =>
      constructorOutcome actual = RecipeConstructorAdmission.finish constructorErrors
        (originalConstructorSource source body) (originalConstructorLock lock canonical schema)
        (constructorParsedOrigin source fits) (nativeFieldsMeaning specs) (textBytes namespaceValue)
        (nativeRuleMapMeaning fields) ∧ ConstructorFrame source canonical actual ⦄ := by
  unfold nativeCtorFromMap
  step with native_constructor_credential_exact source fits.credential as ⟨credential, credentialMeaning⟩
  cases credentialVerdict : RecipeCredentialAdmission.validateRequirement NativeRecipeError.InvalidCredential
      (nativeSourceCredentialRequirement source.credential) with
  | error error =>
      have refused : credential = .Err error := projected_unit_error credential error (by simpa [credentialVerdict] using credentialMeaning)
      simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, RecipeConstructorAdmission.finish,
        originalConstructorSource, constructorErrors, credentialVerdict, constructorOutcome, ConstructorFrame]
  | ok unit =>
      cases unit
      have accepted : credential = .Ok () := projected_unit_ok credential (by simpa [credentialVerdict] using credentialMeaning)
      simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      step with native_constructor_origin_exact source fits.origin as ⟨origin, originMeaning⟩
      cases originVerdict : RecipeOriginAdmission.validate NativeRecipeError.UnsafeOrigin (textBytes source.origin)
          (constructorParsedOrigin source fits) with
      | error error =>
          have refused : origin = .Err error := by cases origin <;> simp_all [nativeOriginOutcome, constructorParsedOrigin]
          simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from, RecipeConstructorAdmission.finish,
            originalConstructorSource, constructorErrors, credentialVerdict, originVerdict,
            constructorOutcome, ConstructorFrame]
      | ok originalHost =>
          cases origin with
          | Err error => simp [nativeOriginOutcome, constructorParsedOrigin, originVerdict] at originMeaning
          | Ok host =>
              have hostMeaning : textBytes host = originalHost := by
                simpa [nativeOriginOutcome, constructorParsedOrigin, originVerdict] using originMeaning
              simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
              step with native_source_rules_admission_exact source fields body bodyMeaning fits.rules count names
                as ⟨rules, ruleMeaning⟩
              cases ruleVerdict : (RecipeRuleAdmission.validate (nativeRuleMapMeaning fields) (ruleSource source body)).1 with
              | error error =>
                  have refused : rules = .Err (consumptionError error) := by simpa [ruleVerdict, consumptionVerdict] using ruleMeaning
                  simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
                    core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
                    core.convert.FromSame, core.convert.FromSame.from, RecipeConstructorAdmission.finish,
                    originalConstructorSource, constructorErrors, credentialVerdict, originVerdict,
                    ruleVerdict, constructorOutcome, ConstructorFrame]
              | ok unit =>
                  cases unit
                  have admitted : rules = .Ok () := by simpa [ruleVerdict, consumptionVerdict] using ruleMeaning
                  simp [admitted, core.result.Result.Insts.CoreOpsTry.branch, RecipeConstructorAdmission.finish,
                    originalConstructorSource, originalConstructorLock, constructorErrors, credentialVerdict,
                    originVerdict, ruleVerdict, constructorOutcome, constructorValue, hostMeaning, ConstructorFrame]

private theorem native_ctor_with_fields_exact (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (schema : ProfileSchema.Value)
    (specs : NativeVec NativeFieldSpec) (layout : FieldProjection.LayoutValid (nativeFieldsMeaning specs))
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body) (fits : ConstructorSourceFits source) :
    nativeCtorWithFields source canonical specs ⦃ actual =>
      constructorOutcome actual = RecipeConstructorAdmission.withFields constructorErrors
        (originalConstructorSource source body) (originalConstructorLock lock canonical schema)
        (constructorParsedOrigin source fits) (nativeFieldsMeaning specs) ∧ ConstructorFrame source canonical actual ⦄ := by
  unfold nativeCtorWithFields
  step with native_constructor_namespace_exact source fits.namespaceValue as ⟨namespaceResult, namespaceMeaning⟩
  by_cases namespaceValid : OperationIdentity.validToken (textBytes source.operator_namespace) 64 = true
  · cases namespaceResult with
    | Err error => simp [namespaceVerdict, namespaceValid, nativeNamespaceOutcome] at namespaceMeaning
    | Ok namespaceValue =>
        have bytesSame : textBytes namespaceValue = textBytes source.operator_namespace := by
          simpa [namespaceVerdict, namespaceValid, nativeNamespaceOutcome] using namespaceMeaning
        have namespaceSame : namespaceValue = source.operator_namespace := text_bytes_injective bytesSame
        subst namespaceValue
        simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
        step with native_validate_binding_fields_exact (AuthsNativeRecipe.alloc.vec.Vec.deref specs)
          source.operator_namespace fits.namespaceValue as ⟨binding, bindingMeaning⟩
        by_cases bindingValid : ProfileSchema.BindingFields (nativeFieldsMeaning specs) (textBytes source.operator_namespace)
        · have bound : binding = .Ok () := by
            simpa [nativeFieldColumn, nativeFieldsMeaning, native_deref_contents, bindingValid] using bindingMeaning
          simp only [bound, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          step with native_rule_fields_exact (AuthsNativeRecipe.alloc.vec.Vec.deref specs) as ⟨built, buildMeaning⟩
          cases tableAt : Rules.build [] (nativeFieldsMeaning specs) with
          | error unit =>
              cases unit
              have independentAdmission := Rules.layout_earns_rule_admission (nativeFieldsMeaning specs) layout
              have refused := (Rules.build_refusal_exact _).mp tableAt
              exact False.elim (refused independentAdmission)
          | ok table =>
              cases built with
              | Err error =>
                  simp [nativeRuleResult, sourceRuleVerdict, nativeFieldColumn, nativeFieldsMeaning,
                    native_deref_contents, tableAt] at buildMeaning
              | Ok fields =>
                  have tableMeaning : nativeRuleMapMeaning fields = table := by
                    simpa [nativeRuleResult, sourceRuleVerdict, nativeFieldColumn, nativeFieldsMeaning,
                      native_deref_contents, tableAt] using buildMeaning
                  have originalFields : Rules.Meaning (nativeFieldsMeaning specs) (nativeRuleMapMeaning fields) := by
                    rw [tableMeaning]
                    exact Rules.build_has_original_meaning _ _ tableAt
                  have count := original_rule_map_count _ fields layout originalFields
                  have names := original_rule_fields_earn_name_bounds _ fields layout originalFields
                  simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
                  apply spec_mono (native_ctor_from_map_exact source lock canonical schema specs source.operator_namespace fields
                    body bodyMeaning fits count (fun entry member => (names entry member).2))
                  rintro actual ⟨meaning, frame⟩
                  refine ⟨?_, frame⟩
                  simpa [RecipeConstructorAdmission.withFields, originalConstructorSource, constructorErrors,
                    namespaceValid, bindingValid, tableAt, tableMeaning] using meaning
        · have refused : binding = .Err .ProfileMismatch := by
            simpa [nativeFieldColumn, nativeFieldsMeaning, native_deref_contents, bindingValid] using bindingMeaning
          simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
            core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
            core.convert.FromSame, core.convert.FromSame.from, RecipeConstructorAdmission.withFields,
            originalConstructorSource, constructorErrors, namespaceValid, bindingValid, constructorOutcome, ConstructorFrame]
  · have refused : namespaceResult = .Err .InvalidNamespace := by
      cases namespaceResult <;> simp_all [namespaceVerdict, nativeNamespaceOutcome]
    simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame, core.convert.FromSame.from, RecipeConstructorAdmission.withFields,
      originalConstructorSource, constructorErrors, namespaceValid, constructorOutcome, ConstructorFrame]

private theorem native_ctor_with_profile_exact (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (schema : ProfileSchema.Value)
    (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body) (fits : ConstructorSourceFits source) :
    nativeCtorWithProfile source lock canonical ⦃ actual =>
      constructorOutcome actual = RecipeConstructorAdmission.withProfile constructorErrors
        (originalConstructorSource source body) (originalConstructorLock lock canonical schema)
        (constructorParsedOrigin source fits) ∧ ConstructorFrame source canonical actual ⦄ := by
  unfold nativeCtorWithProfile AuthsNativeRecipe.recipe.parse_root_fields
  step with native_profile_root_exact lock.command_schema schemaBounds schema schemaMeaning as ⟨parsed, meaning⟩
  cases schemaAt : ProfileSchema.parseRoot schema with
  | none =>
      have refused : parsed = .Err .InvalidProfileLock := by
        cases parsed <;> simp_all [nativeProfileResult, sourceProfileVerdict]
      simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, RecipeConstructorAdmission.withProfile,
        originalConstructorLock, constructorErrors, schemaAt, constructorOutcome, ConstructorFrame]
  | some originalFields =>
      have originalRoot := (ProfileSchema.root_parse_exact schema originalFields).mp schemaAt
      cases parsed with
      | Err error => simp [nativeProfileResult, sourceProfileVerdict, schemaAt] at meaning
      | Ok specs =>
          have fieldMeaning : nativeFieldsMeaning specs = originalFields := by
            simpa [nativeProfileResult, sourceProfileVerdict, schemaAt] using meaning
          have layout : FieldProjection.LayoutValid (nativeFieldsMeaning specs) := by
            rw [fieldMeaning]
            exact (ProfileSchema.root_meaning_earns_complete_valid_layout schema originalFields originalRoot).2.1
          simp only [core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
          apply spec_mono (native_ctor_with_fields_exact source lock canonical schema specs layout body bodyMeaning fits)
          rintro actual ⟨semantic, frame⟩
          refine ⟨?_, frame⟩
          simpa [RecipeConstructorAdmission.withProfile, originalConstructorLock, schemaAt, fieldMeaning] using semantic

private theorem native_ctor_after_lock_exact (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (schema : ProfileSchema.Value)
    (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock) :
    nativeCtorAfterLock source lock canonical ⦃ actual =>
      constructorOutcome actual = RecipeConstructorAdmission.afterLock constructorErrors
        (originalConstructorSource source body) (originalConstructorLock lock canonical schema)
        (constructorParsedOrigin source fits) ∧ ConstructorFrame source canonical actual ⦄ := by
  unfold nativeCtorAfterLock
  step with native_constructor_profile_binding_exact source lock fits.binding lockFits as ⟨matches, meaning⟩
  by_cases binding : RecipeBinding.SourceMatches (originalSourceBinding source) (originalLockMetadata lock).binding
  · have matched : matches = true := by simpa [binding] using meaning
    simp only [matched, Bool.true_eq_true, ↓reduceIte]
    apply spec_mono (native_ctor_with_profile_exact source lock canonical schema schemaBounds schemaMeaning body bodyMeaning fits)
    rintro actual ⟨semantic, frame⟩
    refine ⟨?_, frame⟩
    simpa [RecipeConstructorAdmission.afterLock, originalConstructorSource, originalConstructorLock, binding] using semantic
  · have mismatch : matches = false := by simpa [binding] using meaning
    simp [mismatch, RecipeConstructorAdmission.afterLock, originalConstructorSource, originalConstructorLock,
      binding, constructorErrors, constructorOutcome, ConstructorFrame]

private theorem native_ctor_after_tag_exact (hash : List Nat → List Nat) (library : NativeSha256LibraryContract hash)
    (source : NativeConstructorSource) (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock) (hashRoom : NativeCanonicalFits 0 canonical.schema) :
    nativeCtorAfterTag source lock canonical ⦃ actual =>
      constructorOutcome actual = RecipeConstructorAdmission.afterTag constructorErrors hash
        (originalConstructorSource source body) (originalConstructorLock lock canonical schema)
        (constructorParsedOrigin source fits) ∧ ConstructorFrame source canonical actual ⦄ := by
  unfold nativeCtorAfterTag
  step with native_validate_lock_exact hash library lock canonical.schema lockFits hashRoom as ⟨checked, meaning⟩
  cases verdict : RecipeLockAdmission.validateLock compilerLockErrors hash (originalLockMetadata lock)
      (nativeCanonicalOutcome canonical.schema) with
  | error error =>
      have refused : checked = .Err error := projected_unit_error checked error (by simpa [verdict] using meaning)
      simp [refused, core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from, RecipeConstructorAdmission.afterTag,
        originalConstructorLock, constructorErrors, compilerLockErrors, verdict, constructorOutcome, ConstructorFrame]
  | ok unit =>
      cases unit
      have accepted : checked = .Ok () := projected_unit_ok checked (by simpa [verdict] using meaning)
      simp only [accepted, core.result.Result.Insts.CoreOpsTry.branch, bind_tc_ok]
      apply spec_mono (native_ctor_after_lock_exact source lock canonical schema schemaBounds schemaMeaning body bodyMeaning fits lockFits)
      rintro actual ⟨semantic, frame⟩
      refine ⟨?_, frame⟩
      simpa [RecipeConstructorAdmission.afterTag, originalConstructorLock, constructorErrors, compilerLockErrors, verdict] using semantic

/-- All outcomes of the actual complete constructor, in original source order.
Original parsed fields, namespace, host and canonical-source outcome are retained;
the successful record also retains the exact source/reference frame. Hash and
URL library contracts remain explicit, and no Auths child success is assumed. -/
@[step] theorem native_constructor_admission_exact (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) (schema : ProfileSchema.Value)
    (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock) (hashRoom : NativeCanonicalFits 0 canonical.schema) :
    AuthsNativeRecipe.recipe.validate.validate_source source lock canonical ⦃ actual =>
      constructorOutcome actual = RecipeConstructorAdmission.validate constructorErrors hash
        (originalConstructorSource source body) (originalConstructorLock lock canonical schema)
        (constructorParsedOrigin source fits) ∧ ConstructorFrame source canonical actual ⦄ := by
  rw [native_constructor_uses_original_stages]
  unfold nativeCtorAllStages
  step with native_constructor_source_tag_exact source fits.schema as ⟨supported, meaning⟩
  by_cases tag : textBytes source.schema = RecipeBinding.sourceSchema
  · have accepted : supported = true := by simpa [tag] using meaning
    simp only [accepted, Bool.true_eq_true, ↓reduceIte]
    apply spec_mono (native_ctor_after_tag_exact hash library source lock canonical schema schemaBounds schemaMeaning
      body bodyMeaning fits lockFits hashRoom)
    rintro actual ⟨semantic, frame⟩
    refine ⟨?_, frame⟩
    simpa [RecipeConstructorAdmission.validate, originalConstructorSource, tag] using semantic
  · have refused : supported = false := by simpa [tag] using meaning
    simp [refused, RecipeConstructorAdmission.validate, originalConstructorSource, tag,
      constructorErrors, constructorOutcome, ConstructorFrame]

theorem native_constructor_useful (hash : List Nat → List Nat) (library : NativeSha256LibraryContract hash)
    (source : NativeConstructorSource) (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock) (hashRoom : NativeCanonicalFits 0 canonical.schema)
    (value : RecipeConstructorAdmission.Value)
    (admitted : RecipeConstructorAdmission.validate constructorErrors hash (originalConstructorSource source body)
      (originalConstructorLock lock canonical schema) (constructorParsedOrigin source fits) = .ok value) :
    AuthsNativeRecipe.recipe.validate.validate_source source lock canonical ⦃ actual =>
      ∃ checked, actual = .Ok checked ∧ constructorValue checked = value ∧
        checked.source = source ∧ checked.canonical_source = canonical.source ⦄ := by
  apply spec_mono (native_constructor_admission_exact hash library source lock canonical schema schemaBounds schemaMeaning
    body bodyMeaning fits lockFits hashRoom)
  rintro actual ⟨semantic, frame⟩
  cases actual with
  | Err error => simp [constructorOutcome, admitted] at semantic
  | Ok checked =>
      have original : constructorValue checked = value := by simpa [constructorOutcome, admitted] using semantic
      exact ⟨checked, rfl, original, frame checked rfl⟩

theorem native_constructor_refusal (hash : List Nat → List Nat) (library : NativeSha256LibraryContract hash)
    (source : NativeConstructorSource) (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) (schemaBounds : JsonBounds lock.command_schema) (schemaMeaning : JsonMeaning lock.command_schema schema)
    (body : TemplateAst.Body) (bodyMeaning : BodySourceMeaning source.write.body body)
    (fits : ConstructorSourceFits source) (lockFits : NativeProfileLockFits lock) (hashRoom : NativeCanonicalFits 0 canonical.schema)
    (error : NativeRecipeError)
    (refused : RecipeConstructorAdmission.validate constructorErrors hash (originalConstructorSource source body)
      (originalConstructorLock lock canonical schema) (constructorParsedOrigin source fits) = .error error) :
    AuthsNativeRecipe.recipe.validate.validate_source source lock canonical ⦃ actual => actual = .Err error ⦄ := by
  apply spec_mono (native_constructor_admission_exact hash library source lock canonical schema schemaBounds schemaMeaning
    body bodyMeaning fits lockFits hashRoom)
  rintro actual ⟨semantic, frame⟩
  cases actual <;> simp_all [constructorOutcome]

end Auths.Product.NativeCompiler.Refinement
