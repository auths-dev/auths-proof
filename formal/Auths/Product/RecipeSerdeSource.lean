import Auths.Product.RecipeSerdeBody

/-!
Complete independent serialization specification for the typed recipe source.
Every struct field and enum tag is represented from the ORIGINAL native typed
source, including fields that a later admission rule will reject. Optional
None fields are omitted; Some empty collections are retained. Only the
preconditions.verified default-empty vector is omitted when empty.

This specifies the Auths serde derives; it does not prove their implementation,
raw-byte decoding, JCS sorting/number formatting or canonicalizer adequacy.
Typed signed integers describe serialize_i64 inputs, not a claim that parsing
the resulting positive numeral would produce serde_json's NegInt carrier.
-/
namespace Auths.Product.RecipeSerde
open NativeCompiler
open AuthsNativeRecipe.recipe

abbrev Source := source.RecipeSource
abbrev Credential := source.CredentialSource

def optional {T : Type} (name : String) (encode : T → Json) : Option T → List (String × Json)
  | none => []
  | some value => [(name, encode value)]

def vector {T : Type} (encode : T → Json) (values : NativeVec T) : Json :=
  .array (values.val.map encode)

def unsigned (value : Aeneas.Std.U64) : Json := .number (.unsigned value.val)

def pathSegment : source.PathSegment → Json
  | .Fixed value => tagged "fixed" [("value", .text value)]
  | .Field name => tagged "field" [("name", .text name)]
  | .ResponseField pointer maximum =>
      tagged "response-field" [("pointer", .text pointer), ("max_bytes", unsigned maximum)]
  | .Echo => tagged "echo" []

def accountRead (input : source.AccountReadSource) : Json := .object [
  ("path", vector pathSegment input.path),
  ("json_pointer", .text input.json_pointer),
  ("maximum_response_bytes", unsigned input.maximum_response_bytes)]

def deniedRead (input : source.DeniedReadSource) : Json := .object [
  ("method", .text input.method),
  ("path", vector pathSegment input.path),
  ("refused_status", vector unsigned input.refused_status)]

def probe (input : source.ProbeSource) (literal : Json) : Json := .object [
  ("path", vector pathSegment input.path),
  ("json_pointer", .text input.json_pointer),
  ("equals", literal),
  ("maximum_response_bytes", unsigned input.maximum_response_bytes)]

def guardValue (input : source.GuardSource) (literal : Json) : Json :=
  .object ([("prefixes", vector .text input.prefixes)] ++
    optional "probe" (fun value => probe value literal) input.probe ++
    optional "account" accountRead input.account ++
    optional "denied_reads" (vector deniedRead) input.denied_reads)

def guardOf : Credential → Option source.GuardSource
  | .Bearer guard | .HeaderApiKey _ guard => guard

def originalProbe (credential : Credential) : Option source.ProbeSource :=
  (guardOf credential).bind (fun guard => guard.probe)

/-- The only generic JSON literal in a typed recipe lives at this exact
credential guard/probe slot. An absent slot consumes no supplied literal. -/
def ProbeLiteralMeaning (credential : Credential) (literal : Json) : Prop :=
  ∀ actual, originalProbe credential = some actual → FullJsonMeaning actual.equals literal

def ProbeBounded (credential : Credential) : Prop :=
  ∀ actual, originalProbe credential = some actual → JsonBounds actual.equals

def guardMembers (credential : Credential) (literal : Json) : List (String × Json) :=
  optional "guard" (fun guard => guardValue guard literal) (guardOf credential)

def credentialValue (input : Credential) (literal : Json) : Json :=
  match input with
  | .Bearer _ => tagged "bearer" (guardMembers input literal)
  | .HeaderApiKey header _ => tagged "header-api-key" (("header", .text header) :: guardMembers input literal)

def accountScope (input : source.AccountScopeSource) : Json :=
  .object [("header", .text input.header), ("field", .text input.field)]

def sumBound (input : source.SumBoundSource) : Json :=
  .object ([("argument", .text input.argument)] ++ optional "partition" .text input.partition)

def bounds (input : source.BoundsSource) : Json :=
  .object (optional "sum" sumBound input.sum)

def bindValue (input : source.BindSource) : Json :=
  .object [("pointer", .text input.pointer), ("field", .text input.field)]

def relativeCeiling (input : source.RelativeCeilingSource) : Json :=
  .object ([("argument", .text input.argument),
    ("basis_points", unsigned input.basis_points),
    ("path", vector pathSegment input.path),
    ("json_pointer", .text input.json_pointer)] ++
    optional "subtract_pointer" .text input.subtract_pointer ++
    optional "bind" (vector bindValue) input.bind ++
    [("maximum_response_bytes", unsigned input.maximum_response_bytes)])

def idempotencyLocation (input : source.IdempotencyLocation) : Json :=
  .object (optional "json_pointer" .text input.json_pointer ++
    optional "form_field" .text input.form_field ++
    optional "pointer" .text input.pointer)

def idempotency : source.IdempotencySource → Json
  | .DerivedHeader retention => tagged "derived-header" [("retention_seconds", unsigned retention)]
  | .OperationIdField location retention => tagged "operation-id-field" [
      ("location", idempotencyLocation location), ("retention_seconds", unsigned retention)]

def writeMethod : WriteMethod → Json
  | .Post => .text "POST"
  | .Put => .text "PUT"
  | .Patch => .text "PATCH"
  | .Delete => .text "DELETE"

def writeValue (input : source.WriteSource) (body : Json) : Json :=
  .object ([("method", writeMethod input.method),
    ("path", vector pathSegment input.path), ("body", body)] ++
    optional "idempotency" idempotency input.idempotency)

def observation (input : source.ObservationSource) : Json := .object [
  ("path", vector pathSegment input.path), ("json_pointer", .text input.json_pointer),
  ("expected_field", .text input.expected_field),
  ("maximum_response_bytes", .number (.unsigned input.maximum_response_bytes.val))]

def echoPlacement : source.EchoPlacement → Json
  | .JsonPointer pointer => tagged "json-pointer" [("pointer", .text pointer)]
  | .FormField name => tagged "form-field" [("name", .text name)]

def echoValue (input : source.EchoSource) : Json :=
  .object [("write", echoPlacement input.write), ("observe", .text input.observe)]

def preEntry (input : source.PreEntrySource) : Json := .object [
  ("path", vector pathSegment input.path), ("pointers", vector .text input.pointers),
  ("maximum_response_bytes", unsigned input.maximum_response_bytes)]

def preconditions (input : source.PreconditionSource) : Json :=
  .object (optional "read_back_subject" .text input.read_back_subject ++
    if input.verified.val.isEmpty then [] else [("verified", vector .text input.verified)])

def providerHeaders (input : SourceMap String) : Json :=
  .object (input.entries.val.map (fun pair => (pair.1, .text pair.2)))

def sourceMembers (input : Source) (body literal : Json) : List (String × Json) :=
  [("schema", .text input.schema),
    ("profile_schema_digest", .text input.profile_schema_digest),
    ("service", .text input.service), ("tool", .text input.tool),
    ("operator_namespace", .text input.operator_namespace),
    ("credential", credentialValue input.credential literal), ("origin", .text input.origin)] ++
    optional "provider_headers" providerHeaders input.provider_headers ++
    optional "account_scope" accountScope input.account_scope ++
    optional "bounds" bounds input.bounds ++
    optional "relative_ceiling" relativeCeiling input.relative_ceiling ++
    [("write", writeValue input.write body)] ++
    optional "observation" observation input.observation ++
    optional "echo" echoValue input.echo ++
    optional "pre_entry" preEntry input.pre_entry ++
    optional "preconditions" preconditions input.preconditions

def sourceValue (input : Source) (body literal : Json) : Json :=
  .object (sourceMembers input body literal)

inductive SourceEncoding : Source → Json → Prop where
  | original {input : Source} {body literal : Json}
      (bodyOriginal : BodyEncoding input.write.body body)
      (literalOriginal : ProbeLiteralMeaning input.credential literal) :
      SourceEncoding input (sourceValue input body literal)

theorem probe_literal_exists (credential : Credential) (bounded : ProbeBounded credential) :
    ∃ literal, ProbeLiteralMeaning credential literal := by
  cases selected : originalProbe credential with
  | none => exact ⟨.null, by simp [ProbeLiteralMeaning, selected]⟩
  | some actual =>
      obtain ⟨literal, original⟩ := full_json_meaning_exists actual.equals (bounded actual selected)
      refine ⟨literal, ?_⟩
      intro other otherAt
      have same : actual = other := Option.some.inj (selected.symm.trans otherAt)
      cases same
      exact original

/-- Every represented source has a complete independent serialization. The
premises are body/string and literal representation bounds, not validation,
canonicalization success, a target byte sequence or a compiled plan. -/
theorem source_encoding_exists (input : Source) (body : BodyBounds input.write.body)
    (literal : ProbeBounded input.credential) : ∃ output, SourceEncoding input output := by
  obtain ⟨bodyValue, bodyOriginal⟩ := body_encoding_exists input.write.body body
  obtain ⟨literalValue, literalOriginal⟩ := probe_literal_exists input.credential literal
  exact ⟨_, .original bodyOriginal literalOriginal⟩

private theorem guard_members_agree (credential : Credential) (first second : Json)
    (left : ProbeLiteralMeaning credential first) (right : ProbeLiteralMeaning credential second) :
    guardMembers credential first = guardMembers credential second := by
  cases guarded : guardOf credential with
  | none => simp [guardMembers, guarded, optional]
  | some guard =>
      cases selected : guard.probe with
      | none => simp [guardMembers, guarded, optional, guardValue, selected]
      | some actual =>
          have original : originalProbe credential = some actual := by simp [originalProbe, guarded, selected]
          rw [full_json_meaning_unique (left actual original) (right actual original)]

theorem credential_value_agrees (credential : Credential) (first second : Json)
    (left : ProbeLiteralMeaning credential first) (right : ProbeLiteralMeaning credential second) :
    credentialValue credential first = credentialValue credential second := by
  have same := guard_members_agree credential first second left right
  cases credential <;> simp only [credentialValue] <;> rw [same]

theorem source_encoding_unique {input : Source} {first second : Json}
    (left : SourceEncoding input first) (right : SourceEncoding input second) : first = second := by
  cases left with
  | original leftBody leftLiteral =>
      cases right with
      | original rightBody rightLiteral =>
          have bodySame := body_encoding_unique leftBody rightBody
          have literalSame := credential_value_agrees input.credential _ _ leftLiteral rightLiteral
          unfold sourceValue sourceMembers
          rw [bodySame, literalSame]

def requiredSourceKeys : List String :=
  ["schema", "profile_schema_digest", "service", "tool", "operator_namespace", "credential", "origin", "write"]

theorem source_retains_required_keys (input : Source) (body literal : Json) :
    ∀ name ∈ requiredSourceKeys, name ∈ (sourceMembers input body literal).map Prod.fst := by
  intro name required
  simp only [requiredSourceKeys, List.mem_cons, List.mem_singleton] at required
  rcases required with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> simp [sourceMembers]

end Auths.Product.RecipeSerde
