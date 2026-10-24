import Auths.Product.PathCompiler

namespace Auths.Product.HeaderCompiler
open RequestConstruction

def stripeVersionName : Bytes := [83,116,114,105,112,101,45,86,101,114,115,105,111,110]
def githubVersionName : Bytes := [88,45,71,105,116,72,117,98,45,65,112,105,45,86,101,114,115,105,111,110]
def stripeAccountName : Bytes := [83,116,114,105,112,101,45,65,99,99,111,117,110,116]

/-- HTTP credential-header collision comparison folds ASCII letters only.
Canonical source/header-plan lookup below continues to retain exact bytes. -/
def asciiLower (byte : Nat) : Nat :=
  if 65 ≤ byte ∧ byte ≤ 90 then byte + 32 else byte

def AsciiNameEqual (left right : Bytes) : Prop :=
  left.map asciiLower = right.map asciiLower
instance (left right : Bytes) : Decidable (AsciiNameEqual left right) := by
  unfold AsciiNameEqual
  infer_instance

def RegisteredCredentialHeader (name : Bytes) : Prop :=
  AsciiNameEqual name stripeVersionName ∨ AsciiNameEqual name githubVersionName ∨
    AsciiNameEqual name stripeAccountName
instance (name : Bytes) : Decidable (RegisteredCredentialHeader name) := by
  unfold RegisteredCredentialHeader
  infer_instance

theorem ascii_lower_idempotent (byte : Nat) : asciiLower (asciiLower byte) = asciiLower byte := by
  unfold asciiLower
  split_ifs <;> omega

theorem ascii_name_equality_is_original_byte_alignment (left right : Bytes) :
    AsciiNameEqual left right ↔ List.Forall₂ (fun first second => asciiLower first = asciiLower second) left right := by
  unfold AsciiNameEqual
  induction left generalizing right with
  | nil => cases right <;> simp
  | cons first rest ih => cases right <;> simp_all

theorem ascii_name_equality_keeps_length (left right : Bytes) (same : AsciiNameEqual left right) :
    left.length = right.length := by
  simpa only [List.length_map] using congrArg List.length same

theorem ascii_lower_keeps_non_ascii (byte : Nat) (nonAscii : 127 ≤ byte) : asciiLower byte = byte := by
  simp [asciiLower, show ¬(65 ≤ byte ∧ byte ≤ 90) by omega]

def headerIndex (name : Bytes) : Option Nat :=
  if name = stripeVersionName then some 0
  else if name = githubVersionName then some 1
  else if name = stripeAccountName then some 2
  else none

def Digit (byte : Nat) : Prop := 48 ≤ byte ∧ byte ≤ 57
def VersionByte (byte : Nat) : Prop := alphanumeric byte = true ∨ byte = 46 ∨ byte = 45
def DateByte (index byte : Nat) : Prop :=
  if index = 4 ∨ index = 7 then byte = 45 else Digit byte
instance (byte : Nat) : Decidable (Digit byte) := by unfold Digit; infer_instance
instance (byte : Nat) : Decidable (VersionByte byte) := by unfold VersionByte; infer_instance
instance (index byte : Nat) : Decidable (DateByte index byte) := by unfold DateByte; infer_instance

def StripeVersionValid (value : Bytes) : Prop :=
  10 ≤ value.length ∧ value.length ≤ 64 ∧ Digit (value.headD 0) ∧ ∀ byte ∈ value, VersionByte byte
def IsoDateValid (value : Bytes) : Prop :=
  value.length = 10 ∧ ∀ index ∈ List.range value.length, DateByte index (value[index]?.getD 0)
instance (value : Bytes) : Decidable (StripeVersionValid value) := by unfold StripeVersionValid; infer_instance
instance (value : Bytes) : Decidable (IsoDateValid value) := by unfold IsoDateValid; infer_instance

def VersionValid (name value : Bytes) : Prop :=
  (name = stripeVersionName ∧ StripeVersionValid value) ∨
    (name = githubVersionName ∧ IsoDateValid value)
instance (name value : Bytes) : Decidable (VersionValid name value) := by unfold VersionValid; infer_instance

theorem header_index_zero_iff (name : Bytes) : headerIndex name = some 0 ↔ name = stripeVersionName := by
  unfold headerIndex
  split_ifs <;> simp_all
theorem header_index_one_iff (name : Bytes) : headerIndex name = some 1 ↔ name = githubVersionName := by
  unfold headerIndex
  split_ifs <;> simp_all [stripeVersionName, githubVersionName, stripeAccountName]
theorem header_index_two_iff (name : Bytes) : headerIndex name = some 2 ↔ name = stripeAccountName := by
  unfold headerIndex
  split_ifs <;> simp_all [stripeVersionName, githubVersionName, stripeAccountName]

theorem version_valid_by_index (name value : Bytes) : VersionValid name value ↔
    (match headerIndex name with
      | some 0 => StripeVersionValid value
      | some 1 => IsoDateValid value
      | _ => False) := by
  unfold headerIndex VersionValid
  split_ifs <;> simp_all [stripeVersionName, githubVersionName, stripeAccountName]

abbrev Versions := List (Bytes × Bytes)
def VersionsValid (headers : Versions) : Prop :=
  0 < headers.length ∧ headers.length ≤ 2 ∧ (headers.map Prod.fst).Nodup ∧
    ∀ entry ∈ headers, VersionValid entry.1 entry.2
instance (headers : Versions) : Decidable (VersionsValid headers) := by unfold VersionsValid; infer_instance

def SmallDistinct : Versions → Prop
  | [first, second] => first.1 ≠ second.1
  | _ => True

theorem small_distinct_iff (source : Versions) (bound : source.length ≤ 2) :
    SmallDistinct source ↔ (source.map Prod.fst).Nodup := by
  cases source with
  | nil => simp [SmallDistinct]
  | cons first rest =>
    cases rest with
    | nil => simp [SmallDistinct]
    | cons second tail =>
      cases tail with
      | nil => simp [SmallDistinct, ne_comm]
      | cons third later => simp at bound

inductive CompileError where
  | providerHeader
  | accountScope
  deriving DecidableEq

structure ScopeSource where
  name : Bytes
  field : Bytes
  deriving DecidableEq

def literalHeaders (source : Versions) : List Header := source.map (fun entry => ⟨entry.1, entry.2⟩)
def lowerVersions (source : Versions) : Except CompileError (List Header) :=
  if VersionsValid source then .ok (literalHeaders source) else .error .providerHeader

def lowerScope (names : List Bytes) (source : ScopeSource) : Except CompileError ScopePlan :=
  if source.name = stripeAccountName then
    match PathCompiler.lowerField names source.field with
    | .ok index => .ok ⟨source.name, index⟩
    | .error _ => .error .accountScope
  else .error .accountScope

def lowerHeaders (names : List Bytes) (versions : Option Versions) (scope : Option ScopeSource) :
    Except CompileError HeaderPlan := do
  let fixed ← match versions with
    | none => .ok []
    | some source => lowerVersions source
  let account ← match scope with
    | none => .ok none
    | some source => (lowerScope names source).map some
  pure ⟨fixed, account⟩

def ScopeAdmissible (names : List Bytes) (source : ScopeSource) : Prop :=
  source.name = stripeAccountName ∧ names.length ≤ 32 ∧
    OperationIdentity.validToken source.field 64 = true ∧ source.field ∈ names
def ScopeMeaning (names : List Bytes) (source : ScopeSource) (plan : ScopePlan) : Prop :=
  source.name = stripeAccountName ∧ plan.name = source.name ∧ names.length ≤ 32 ∧
    OperationIdentity.validToken source.field 64 = true ∧ SchemaIndex.position names source.field = some plan.field

def HeaderAdmissible (names : List Bytes) (versions : Option Versions) (scope : Option ScopeSource) : Prop :=
  (match versions with | none => True | some headers => VersionsValid headers) ∧
    (match scope with | none => True | some source => ScopeAdmissible names source)

instance (names : List Bytes) (source : ScopeSource) : Decidable (ScopeAdmissible names source) := by
  unfold ScopeAdmissible; infer_instance
instance (names : List Bytes) (versions : Option Versions) (scope : Option ScopeSource) :
    Decidable (HeaderAdmissible names versions scope) := by
  unfold HeaderAdmissible
  cases versions <;> cases scope <;> infer_instance

theorem valid_version_bounds (name value : Bytes) (valid : VersionValid name value) :
    name.length ≤ 20 ∧ value.length ≤ 64 := by
  rcases valid with ⟨nameSame, stripe⟩ | ⟨nameSame, date⟩
  · simp only [nameSame, stripeVersionName]
    exact ⟨by decide, stripe.2.1⟩
  · simp only [nameSame, githubVersionName]
    exact ⟨by decide, by have size := date.1; omega⟩

theorem version_name_excludes_account_scope (name value : Bytes) (valid : VersionValid name value) :
    name ≠ stripeAccountName := by
  intro same
  rcases valid with stripe | github
  · have wrong : stripeVersionName = stripeAccountName := stripe.1.symm.trans same
    exact (show stripeVersionName ≠ stripeAccountName by decide) wrong
  · have wrong : githubVersionName = stripeAccountName := github.1.symm.trans same
    exact (show githubVersionName ≠ stripeAccountName by decide) wrong

theorem version_bytes_are_safe (name value : Bytes) (valid : VersionValid name value) :
    ∀ byte ∈ value, byte < 128 ∧ byte ≠ 0 ∧ byte ≠ 10 ∧ byte ≠ 13 := by
  rcases valid with stripe | date
  · intro byte member
    have admitted := stripe.2.2.2.2 byte member
    unfold VersionByte alphanumeric at admitted
    simp only [Bool.or_eq_true, Bool.and_eq_true, decide_eq_true_eq] at admitted
    omega
  · intro byte member
    obtain ⟨index, atIndex⟩ := List.mem_iff_getElem?.mp member
    have inside : index < value.length := by
      by_contra outside
      simp [List.getElem?_eq_none (by omega)] at atIndex
    have admitted := date.2.2 index (List.mem_range.mpr inside)
    rw [atIndex] at admitted
    simp only [Option.getD_some] at admitted
    unfold DateByte Digit at admitted
    split at admitted <;> omega

theorem versions_refuse_empty : lowerVersions [] = .error .providerHeader := by
  simp [lowerVersions, VersionsValid]

theorem lower_scope_sound (names : List Bytes) (source : ScopeSource) (plan : ScopePlan)
    (run : lowerScope names source = .ok plan) : ScopeMeaning names source plan := by
  unfold lowerScope at run
  split at run
  · rename_i nameSame
    cases field : PathCompiler.lowerField names source.field with
    | error error => simp [field] at run
    | ok index =>
      have planSame : ScopePlan.mk source.name index = plan := by simpa [field] using run
      subst plan
      unfold PathCompiler.lowerField at field
      split at field
      · rename_i admitted
        cases found : SchemaIndex.position names source.field with
        | none => simp [found] at field
        | some actual =>
          have indexSame : actual = index := by simpa [found] using field
          exact ⟨nameSame, rfl, admitted.1, admitted.2, by simpa [indexSame] using found⟩
      · contradiction
  · contradiction

theorem lower_scope_complete (names : List Bytes) (source : ScopeSource)
    (admitted : ScopeAdmissible names source) : ∃ plan, lowerScope names source = .ok plan := by
  cases found : SchemaIndex.position names source.field with
  | none => exact False.elim ((SchemaIndex.absent_iff names source.field).mp found admitted.2.2.2)
  | some index =>
    exact ⟨⟨source.name, index⟩, by simp [lowerScope, admitted.1, PathCompiler.lowerField,
      admitted.2.1, admitted.2.2.1, found]⟩

theorem lower_headers_complete (names : List Bytes) (versions : Option Versions) (scope : Option ScopeSource)
    (admitted : HeaderAdmissible names versions scope) : ∃ plan, lowerHeaders names versions scope = .ok plan := by
  cases scope with
  | none =>
    cases versions with
    | none => exact ⟨⟨[], none⟩, rfl⟩
    | some headers => exact ⟨⟨literalHeaders headers, none⟩, by simp [lowerHeaders, lowerVersions, admitted.1]⟩
  | some source =>
    obtain ⟨account, accountRun⟩ := lower_scope_complete names source admitted.2
    cases versions with
    | none => exact ⟨⟨[], some account⟩, by simp [lowerHeaders, accountRun]⟩
    | some headers => exact ⟨⟨literalHeaders headers, some account⟩,
        by simp [lowerHeaders, lowerVersions, admitted.1, accountRun]⟩

def namedScopeHeader (environment : Bytes → Option Arg) (source : ScopeSource) : Except ConstructError Header :=
  match environment source.field with
  | some (.text value) =>
    if scopeValueValid value then .ok ⟨source.name, value⟩ else .error .headerValue
  | _ => .error .argumentMismatch

def namedHeaders (environment : Bytes → Option Arg) (versions : Option Versions) (scope : Option ScopeSource) :
    Except ConstructError (List Header) :=
  let fixed := literalHeaders (versions.getD [])
  match scope with
  | none => .ok fixed
  | some source => (namedScopeHeader environment source).map (fixed ++ ·)

theorem lowered_scope_uses_named_value (names : List Bytes) (values : List Arg) (environment : Bytes → Option Arg)
    (aligned : SchemaIndex.Aligned names values environment) (source : ScopeSource) (plan : ScopePlan)
    (meaning : ScopeMeaning names source plan) : scopeHeader plan values = namedScopeHeader environment source := by
  have exactName := SchemaIndex.indexed_argument_is_named _ _ _ aligned _ _ meaning.2.2.2.2
  simp [scopeHeader, namedScopeHeader, exactName, meaning.2.1]

theorem lower_headers_fixed_column (names : List Bytes) (versions : Option Versions) (scope : Option ScopeSource)
    (plan : HeaderPlan) (run : lowerHeaders names versions scope = .ok plan) :
    plan.versions = literalHeaders (versions.getD []) := by
  cases versions with
  | none =>
    cases scope with
    | none =>
      have same : HeaderPlan.mk [] none = plan := by simpa [lowerHeaders] using run
      simp [← same, literalHeaders]
    | some source =>
      cases accountRun : lowerScope names source with
      | error error => simp [lowerHeaders, accountRun] at run
      | ok compiledAccount =>
        have same : HeaderPlan.mk [] (some compiledAccount) = plan := by simpa [lowerHeaders, accountRun] using run
        simp [← same, literalHeaders]
  | some headers =>
    cases fixedRun : lowerVersions headers with
    | error error => simp [lowerHeaders, fixedRun] at run
    | ok fixedHeaders =>
      have fixedSame : fixedHeaders = literalHeaders headers := by
        unfold lowerVersions at fixedRun
        split at fixedRun
        · simpa using fixedRun.symm
        · contradiction
      cases scope with
      | none =>
        have same : HeaderPlan.mk fixedHeaders none = plan := by simpa [lowerHeaders, fixedRun] using run
        simp [← same, fixedSame]
      | some source =>
        cases accountRun : lowerScope names source with
        | error error => simp [lowerHeaders, fixedRun, accountRun] at run
        | ok compiledAccount =>
          have same : HeaderPlan.mk fixedHeaders (some compiledAccount) = plan := by simpa [lowerHeaders, fixedRun, accountRun] using run
          simp [← same, fixedSame]

theorem lower_headers_versions_admitted (names : List Bytes) (versions : Option Versions) (scope : Option ScopeSource)
    (plan : HeaderPlan) (run : lowerHeaders names versions scope = .ok plan) :
    match versions with | none => True | some source => VersionsValid source := by
  cases versions with
  | none => trivial
  | some source =>
    cases fixedRun : lowerVersions source with
    | error error => simp [lowerHeaders, fixedRun] at run
    | ok fixed =>
      unfold lowerVersions at fixedRun
      split at fixedRun
      · assumption
      · contradiction

theorem lower_headers_scope_column (names : List Bytes) (versions : Option Versions) (scope : Option ScopeSource)
    (plan : HeaderPlan) (run : lowerHeaders names versions scope = .ok plan) :
    match scope with
    | none => plan.scope = none
    | some source => ∃ compiled, plan.scope = some compiled ∧ lowerScope names source = .ok compiled := by
  cases versions with
  | none =>
    cases scope with
    | none =>
      have same : HeaderPlan.mk [] none = plan := by simpa [lowerHeaders] using run
      simp [← same]
    | some source =>
      cases made : lowerScope names source with
      | error error => simp [lowerHeaders, made] at run
      | ok compiled =>
        have same : HeaderPlan.mk [] (some compiled) = plan := by simpa [lowerHeaders, made] using run
        exact ⟨compiled, by simp [← same], made⟩
  | some fixedSource =>
    cases madeFixed : lowerVersions fixedSource with
    | error error => simp [lowerHeaders, madeFixed] at run
    | ok fixed =>
      cases scope with
      | none =>
        have same : HeaderPlan.mk fixed none = plan := by simpa [lowerHeaders, madeFixed] using run
        simp [← same]
      | some source =>
        cases made : lowerScope names source with
        | error error => simp [lowerHeaders, madeFixed, made] at run
        | ok compiled =>
          have same : HeaderPlan.mk fixed (some compiled) = plan := by simpa [lowerHeaders, madeFixed, made] using run
          exact ⟨compiled, by simp [← same], made⟩

theorem lower_headers_earns_bounds (names : List Bytes) (versions : Option Versions) (scope : Option ScopeSource)
    (plan : HeaderPlan) (run : lowerHeaders names versions scope = .ok plan) :
    plan.versions.length ≤ 2 ∧
      (∀ header ∈ plan.versions, header.name.length ≤ 20 ∧ header.value.length ≤ 64) ∧
      (∀ account, plan.scope = some account → account.name.length = 14) := by
  have fixed := lower_headers_fixed_column _ _ _ _ run
  have admitted := lower_headers_versions_admitted _ _ _ _ run
  have count : plan.versions.length ≤ 2 := by
    rw [fixed]
    cases versions with
    | none => simp [literalHeaders]
    | some source => simpa [literalHeaders] using admitted.2.1
  have rows : ∀ header ∈ plan.versions, header.name.length ≤ 20 ∧ header.value.length ≤ 64 := by
    intro header member
    rw [fixed] at member
    cases versions with
    | none => simp [literalHeaders] at member
    | some source =>
      obtain ⟨entry, member, same⟩ := List.mem_map.mp member
      subst header
      exact valid_version_bounds _ _ (admitted.2.2.2 entry member)
  refine ⟨count, rows, ?_⟩
  intro account present
  have column := lower_headers_scope_column _ _ _ _ run
  cases scope with
  | none => simp [column] at present
  | some source =>
    obtain ⟨compiled, compiledAt, compiledRun⟩ := column
    have same : compiled = account := Option.some.inj (compiledAt.symm.trans present)
    subst account
    have meaning := lower_scope_sound _ _ _ compiledRun
    rw [meaning.2.1, meaning.1]
    decide

theorem lower_headers_earns_admissibility (names : List Bytes) (versions : Option Versions) (scope : Option ScopeSource)
    (plan : HeaderPlan) (run : lowerHeaders names versions scope = .ok plan) :
    HeaderAdmissible names versions scope := by
  refine ⟨lower_headers_versions_admitted _ _ _ _ run, ?_⟩
  have column := lower_headers_scope_column _ _ _ _ run
  cases scope with
  | none => trivial
  | some source =>
    obtain ⟨compiled, _, compiledRun⟩ := column
    obtain ⟨sameName, _, count, lexical, found⟩ := lower_scope_sound _ _ _ compiledRun
    exact ⟨sameName, count, lexical, List.mem_iff_getElem?.mpr
      ⟨compiled.field, SchemaIndex.position_points_to_name _ _ _ found⟩⟩

theorem lowered_headers_preserve_named_rendering (names : List Bytes) (values : List Arg)
    (environment : Bytes → Option Arg) (aligned : SchemaIndex.Aligned names values environment)
    (versions : Option Versions) (scope : Option ScopeSource) (plan : HeaderPlan)
    (run : lowerHeaders names versions scope = .ok plan) :
    actionHeaders plan values = namedHeaders environment versions scope := by
  have fixed := lower_headers_fixed_column _ _ _ _ run
  cases scope with
  | none =>
    have noScope : plan.scope = none := by
      cases versions with
      | none =>
        have same : HeaderPlan.mk [] none = plan := by simpa [lowerHeaders] using run
        simp [← same]
      | some headers =>
        cases produced : lowerVersions headers with
        | error error => simp [lowerHeaders, produced] at run
        | ok fixedHeaders =>
          have same : HeaderPlan.mk fixedHeaders none = plan := by simpa [lowerHeaders, produced] using run
          simp [← same]
    simp [actionHeaders, namedHeaders, noScope, fixed]
  | some source =>
    have account : ∃ compiled, plan.scope = some compiled ∧ lowerScope names source = .ok compiled := by
      cases versions with
      | none =>
        cases made : lowerScope names source with
        | error error => simp [lowerHeaders, made] at run
        | ok compiled =>
          have same : HeaderPlan.mk [] (some compiled) = plan := by simpa [lowerHeaders, made] using run
          exact ⟨compiled, by simp [← same], made⟩
      | some headers =>
        cases madeFixed : lowerVersions headers with
        | error error => simp [lowerHeaders, madeFixed] at run
        | ok fixedHeaders =>
          cases made : lowerScope names source with
          | error error => simp [lowerHeaders, madeFixed, made] at run
          | ok compiled =>
            have same : HeaderPlan.mk fixedHeaders (some compiled) = plan := by
              simpa [lowerHeaders, madeFixed, made] using run
            exact ⟨compiled, by simp [← same], made⟩
    obtain ⟨compiled, present, compiledRun⟩ := account
    have exactScope := lowered_scope_uses_named_value _ _ _ aligned _ _ (lower_scope_sound _ _ _ compiledRun)
    simp [actionHeaders, namedHeaders, present, fixed, exactScope]
    cases namedScopeHeader environment source <;> rfl

end Auths.Product.HeaderCompiler
