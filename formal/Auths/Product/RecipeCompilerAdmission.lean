import Auths.Product.RecipeConstructorAdmission
import Auths.Product.RecipePlanProperties

/-!
Independent decoded compiler, including constructor, digest and lowering in
shipping order. Both source views are original-data projections; the native
adapter must tie them to the same complete source and body. Hashing and parsed
URL outcomes remain named library inputs. No native function is imported here.
-/
namespace Auths.Product.RecipeCompilerAdmission
open RequestConstruction

def fieldsOfPairs (pairs : List (Bytes × ScalarProjection.Schema)) : List FieldProjection.Field :=
  pairs.map (fun pair => ⟨pair.1, pair.2⟩)

theorem original_fields_roundtrip (fields : List FieldProjection.Field) :
    fieldsOfPairs (RecipeConstructorAdmission.fieldPairs fields) = fields := by
  induction fields with
  | nil => rfl
  | cons field rest ih =>
      change field :: fieldsOfPairs (RecipeConstructorAdmission.fieldPairs rest) = field :: rest
      exact congrArg (List.cons field) ih

theorem original_pairs_roundtrip (pairs : List (Bytes × ScalarProjection.Schema)) :
    RecipeConstructorAdmission.fieldPairs (fieldsOfPairs pairs) = pairs := by
  simp [fieldsOfPairs, RecipeConstructorAdmission.fieldPairs, List.map_map, Function.comp_def]

structure Value where
  namespaceBytes : Bytes
  digest : Bytes
  plans : RecipePlanModel.Plans

def afterDigest {E : Type} (errors : RecipePlanModel.Errors E) (source : RecipePlanModel.Source)
    (admitted : RecipeConstructorAdmission.Value) (digest : Bytes) : Except E Value := do
  let plans ← RecipePlanModel.compile errors (fieldsOfPairs admitted.fields) admitted.host source
  .ok ⟨admitted.namespaceBytes, digest, plans⟩

def afterConstructor {E : Type} (digestErrors : RecipeLockAdmission.Errors E)
    (planErrors : RecipePlanModel.Errors E) (hash : Bytes → Bytes) (source : RecipePlanModel.Source)
    (admitted : RecipeConstructorAdmission.Value) : Except E Value := do
  let digest ← RecipeLockAdmission.recipeDigest digestErrors hash admitted.canonicalSource
  afterDigest planErrors source admitted digest

def compile {E : Type} (constructorErrors : RecipeConstructorAdmission.Errors E)
    (digestErrors : RecipeLockAdmission.Errors E) (planErrors : RecipePlanModel.Errors E)
    (hash : Bytes → Bytes) (source : RecipeConstructorAdmission.Source) (lock : RecipeConstructorAdmission.Lock)
    (parsed : Except Unit RecipeOriginAdmission.Parsed) (lowering : RecipePlanModel.Source) : Except E Value := do
  let admitted ← RecipeConstructorAdmission.validate constructorErrors hash source lock parsed
  afterConstructor digestErrors planErrors hash lowering admitted

theorem constructor_refusal_is_first {E : Type} (constructorErrors : RecipeConstructorAdmission.Errors E)
    (digestErrors : RecipeLockAdmission.Errors E) (planErrors : RecipePlanModel.Errors E)
    (hash : Bytes → Bytes) (source : RecipeConstructorAdmission.Source) (lock : RecipeConstructorAdmission.Lock)
    (parsed : Except Unit RecipeOriginAdmission.Parsed) (lowering : RecipePlanModel.Source) (error : E)
    (refused : RecipeConstructorAdmission.validate constructorErrors hash source lock parsed = .error error) :
    compile constructorErrors digestErrors planErrors hash source lock parsed lowering = .error error := by
  simp [compile, refused]

theorem failed_canonical_source_refuses_before_plans {E : Type} (digestErrors : RecipeLockAdmission.Errors E)
    (planErrors : RecipePlanModel.Errors E) (hash : Bytes → Bytes) (source : RecipePlanModel.Source)
    (admitted : RecipeConstructorAdmission.Value) (failed : admitted.canonicalSource = .error ()) :
    afterConstructor digestErrors planErrors hash source admitted = .error digestErrors.invalidSource := by
  simp [afterConstructor, RecipeLockAdmission.recipeDigest, failed]

/-- Useful composition starts with independent source admission and independent
plan compilation. Neither an actual constructor nor native lowering success is
assumed. Actual library non-vacuity remains an outer qualification obligation. -/
theorem independently_admitted_source_and_plans_compile {E : Type}
    (constructorErrors : RecipeConstructorAdmission.Errors E) (digestErrors : RecipeLockAdmission.Errors E)
    (planErrors : RecipePlanModel.Errors E) (hash : Bytes → Bytes)
    (source : RecipeConstructorAdmission.Source) (lock : RecipeConstructorAdmission.Lock)
    (parsed : Except Unit RecipeOriginAdmission.Parsed) (lowering : RecipePlanModel.Source)
    (admitted : RecipeConstructorAdmission.Value) (canonical : Bytes) (plans : RecipePlanModel.Plans)
    (sourceAt : RecipeConstructorAdmission.validate constructorErrors hash source lock parsed = .ok admitted)
    (canonicalAt : admitted.canonicalSource = .ok canonical)
    (plansAt : RecipePlanModel.compile planErrors (fieldsOfPairs admitted.fields) admitted.host lowering = .ok plans) :
    compile constructorErrors digestErrors planErrors hash source lock parsed lowering =
      .ok ⟨admitted.namespaceBytes, hash (RecipeBinding.digestPreimage canonical), plans⟩ := by
  simp [compile, sourceAt, afterConstructor, RecipeLockAdmission.recipeDigest, canonicalAt, afterDigest, plansAt]

def Meaning {E : Type} (constructorErrors : RecipeConstructorAdmission.Errors E)
    (digestErrors : RecipeLockAdmission.Errors E) (planErrors : RecipePlanModel.Errors E)
    (hash : Bytes → Bytes) (source : RecipeConstructorAdmission.Source) (lock : RecipeConstructorAdmission.Lock)
    (parsed : Except Unit RecipeOriginAdmission.Parsed) (lowering : RecipePlanModel.Source) (output : Value) : Prop :=
    ∃ admitted canonical body write,
      RecipeConstructorAdmission.validate constructorErrors hash source lock parsed = .ok admitted ∧
      admitted.canonicalSource = .ok canonical ∧ output.namespaceBytes = admitted.namespaceBytes ∧
      output.digest = hash (RecipeBinding.digestPreimage canonical) ∧
      RecipePlanModel.namedBody planErrors lowering.body lowering.echo = .ok body ∧
      RequestCompiler.compile (fieldsOfPairs admitted.fields)
        (RecipePlanModel.writeSource lowering admitted.host body) = .ok write ∧
      RequestCompiler.CompilationMeaning (fieldsOfPairs admitted.fields)
        (RecipePlanModel.writeSource lowering admitted.host body) write ∧
      RecipePlanModel.remainingPlans planErrors (fieldsOfPairs admitted.fields) lowering write = .ok output.plans ∧
      output.plans.fields = fieldsOfPairs admitted.fields ∧ output.plans.write = write.plan

/-- A successful complete independent compiler earns constructor admission,
canonical-source success, the exact domain-separated digest and all original
plan components. The field layout is recovered losslessly, including order. -/
theorem success_has_original_components {E : Type} (constructorErrors : RecipeConstructorAdmission.Errors E)
    (digestErrors : RecipeLockAdmission.Errors E) (planErrors : RecipePlanModel.Errors E)
    (hash : Bytes → Bytes) (source : RecipeConstructorAdmission.Source) (lock : RecipeConstructorAdmission.Lock)
    (parsed : Except Unit RecipeOriginAdmission.Parsed) (lowering : RecipePlanModel.Source) (output : Value)
    (completed : compile constructorErrors digestErrors planErrors hash source lock parsed lowering = .ok output) :
    Meaning constructorErrors digestErrors planErrors hash source lock parsed lowering output := by
  unfold Meaning
  unfold compile at completed
  cases sourceAt : RecipeConstructorAdmission.validate constructorErrors hash source lock parsed with
  | error error => simp [sourceAt] at completed
  | ok admitted =>
      cases canonicalAt : admitted.canonicalSource with
      | error unit =>
          cases unit
          simp [sourceAt, afterConstructor, RecipeLockAdmission.recipeDigest, canonicalAt] at completed
      | ok canonical =>
          cases plansAt : RecipePlanModel.compile planErrors (fieldsOfPairs admitted.fields) admitted.host lowering with
          | error error =>
              simp [sourceAt, afterConstructor, RecipeLockAdmission.recipeDigest, canonicalAt, afterDigest, plansAt] at completed
          | ok plans =>
              have same : (⟨admitted.namespaceBytes, hash (RecipeBinding.digestPreimage canonical), plans⟩ : Value) = output := by
                simpa [sourceAt, afterConstructor, RecipeLockAdmission.recipeDigest, canonicalAt, afterDigest, plansAt] using completed
              subst output
              obtain ⟨body, write, named, compiled, meaning, remaining, fields, keptWrite⟩ :=
                RecipePlanModel.compile_success_components planErrors (fieldsOfPairs admitted.fields) admitted.host lowering plans plansAt
              exact ⟨admitted, canonical, body, write, sourceAt, canonicalAt, rfl, rfl,
                named, compiled, meaning, remaining, fields, keptWrite⟩

end Auths.Product.RecipeCompilerAdmission
