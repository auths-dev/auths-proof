import Auths.Generated.Algebra
import Auths.Rich.Semantics

open Auths

def truthCode : Generated.Truth → String
  | .denied => "denied"
  | .indeterminate => "indeterminate"
  | .authorized => "authorized"

def boolCode (value : Bool) : String :=
  if value then "true" else "false"

def thresholdVector (required authorized indeterminate : Nat) : String :=
  let outcome := Generated.thresholdCounts required authorized indeterminate
  "{" ++
    s!"\"required\":{required},\"authorized\":{authorized},\"indeterminate\":{indeterminate},\"expected\":\"{truthCode outcome}\"" ++
    "}"

def thresholdVectors : List String :=
  (List.range Generated.exhaustiveThresholdBound).flatMap fun requiredIndex =>
    let required := requiredIndex + 1
    (List.range (Generated.exhaustiveThresholdBound + 1)).flatMap fun authorized =>
      (List.range (Generated.exhaustiveThresholdBound + 1 - authorized)).map fun indeterminate =>
        thresholdVector required authorized indeterminate

def boolVectors : Nat → List (List Bool)
  | 0 => [[]]
  | count + 1 =>
      (boolVectors count).flatMap fun tail =>
        [false :: tail, true :: tail]

def attenuationProjection (values : List Bool) : Generated.AttenuationProjection where
  rootPreserved := values.getD 0 false
  depthDecreases := values.getD 1 false
  profileAttenuates := values.getD 2 false
  permissionsAttenuate := values.getD 3 false
  validityAttenuates := values.getD 4 false
  audiencesAttenuate := values.getD 5 false
  actionConstraintAttenuates := values.getD 6 false
  budgetAttenuates := values.getD 7 false
  statusAttenuates := values.getD 8 false
  assuranceAttenuates := values.getD 9 false
  extensionsAttenuate := values.getD 10 false

def attenuationVector (values : List Bool) : String :=
  let projection := attenuationProjection values
  let fields := String.intercalate "," (values.map boolCode)
  let accepted := boolCode (Generated.attenuationAccepts projection)
  "{" ++ s!"\"checks\":[{fields}],\"accepted\":{accepted}" ++ "}"

def attenuationVectors : List String :=
  (boolVectors 11).map attenuationVector

def natVocabulary : Rich.Vocabulary where
  PrincipalCarrier := Nat
  ProfileCarrier := Nat
  PermissionCarrier := Nat
  AudienceCarrier := Nat
  DigestCarrier := Nat
  BudgetAlgebraCarrier := Nat
  StatusMethodCarrier := Nat
  AssuranceCarrier := Nat
  GrantIdCarrier := Nat
  principalDecidableEq := inferInstance
  profileDecidableEq := inferInstance
  permissionDecidableEq := inferInstance
  audienceDecidableEq := inferInstance
  digestDecidableEq := inferInstance
  budgetAlgebraDecidableEq := inferInstance
  statusMethodDecidableEq := inferInstance
  assuranceDecidableEq := inferInstance
  grantIdDecidableEq := inferInstance

def natArrayCode (values : List Nat) : String :=
  "[" ++ String.intercalate "," (values.map toString) ++ "]"

def richVector
    (id kind : String) (args child parent : List Nat) (expected : Bool) :
    String :=
  "{" ++
    s!"\"id\":\"{id}\",\"kind\":\"{kind}\",\"args\":{natArrayCode args}," ++
    s!"\"child\":{natArrayCode child},\"parent\":{natArrayCode parent}," ++
    s!"\"expected\":{boolCode expected}" ++
    "}"

def richWindow (start finish : Nat) (wellFormed : start ≤ finish) :
    Rich.InclusiveWindow :=
  ⟨start, finish, wellFormed⟩

def richBudget (algebra value : Nat) :
    Rich.BudgetCeiling natVocabulary :=
  ⟨⟨algebra⟩, value⟩

def richFreshness (seconds : Nat) (positive : 0 < seconds) :
    Rich.FreshnessLimit :=
  ⟨seconds, positive⟩

def richStatusMethod (value : Nat) :
    Rich.StatusMethod natVocabulary :=
  ⟨value⟩

def richDigest (value : Nat) :
    Rich.Digest natVocabulary :=
  ⟨value⟩

def richAuthorityVectors : List String :=
  [
    richVector "window-inner" "window" [10, 20, 11, 19] [] []
      (decide <| Rich.windowContained
        (richWindow 11 19 (by decide)) (richWindow 10 20 (by decide))),
    richVector "window-inclusive-boundary" "window" [10, 20, 10, 20] [] []
      (decide <| Rich.windowContained
        (richWindow 10 20 (by decide)) (richWindow 10 20 (by decide))),
    richVector "window-expanded-start" "window" [10, 20, 9, 19] [] []
      (decide <| Rich.windowContained
        (richWindow 9 19 (by decide)) (richWindow 10 20 (by decide))),
    richVector "finite-set-subset" "finite-set-subset" [] [1] [1, 2]
      (decide <| ({1} : Rich.FiniteSet Nat) ⊆ {1, 2}),
    richVector "finite-set-widening" "finite-set-subset" [] [1, 2] [1]
      (decide <| ({1, 2} : Rich.FiniteSet Nat) ⊆ {1}),
    richVector "finite-set-member" "finite-set-member" [2] [] [1, 2]
      (decide <| 2 ∈ ({1, 2} : Rich.FiniteSet Nat)),
    richVector "finite-set-missing" "finite-set-member" [3] [] [1, 2]
      (decide <| 3 ∈ ({1, 2} : Rich.FiniteSet Nat)),
    richVector "budget-lower" "budget" [1, 5, 1, 10] [] []
      (decide <| Rich.budgetLe
        (some (richBudget 1 5)) (some (richBudget 1 10))),
    richVector "budget-higher" "budget" [1, 11, 1, 10] [] []
      (decide <| Rich.budgetLe
        (some (richBudget 1 11)) (some (richBudget 1 10))),
    richVector "budget-algebra-mismatch" "budget" [1, 5, 2, 10] [] []
      (decide <| Rich.budgetLe
        (some (richBudget 1 5)) (some (richBudget 2 10))),
    richVector "budget-unbounded-parent" "optional-budget" [1, 0] [] []
      (decide <| Rich.budgetLe
        (some (richBudget 1 5)) (none : Option (Rich.BudgetCeiling natVocabulary))),
    richVector "budget-unbounded-child" "optional-budget" [0, 1] [] []
      (decide <| Rich.budgetLe
        (none : Option (Rich.BudgetCeiling natVocabulary))
        (some (richBudget 1 10))),
    richVector "budget-cover-no-request" "budget-covers"
      [1, 1, 10, 0, 0, 0] [] []
      (decide <| Rich.budgetCovers
        (some (richBudget 1 10))
        (none : Option (Rich.BudgetCeiling natVocabulary))),
    richVector "budget-cover-within-ceiling" "budget-covers"
      [1, 1, 10, 1, 1, 5] [] []
      (decide <| Rich.budgetCovers
        (some (richBudget 1 10)) (some (richBudget 1 5))),
    richVector "budget-cover-over-ceiling" "budget-covers"
      [1, 1, 10, 1, 1, 11] [] []
      (decide <| Rich.budgetCovers
        (some (richBudget 1 10)) (some (richBudget 1 11))),
    richVector "budget-cover-unbounded-ceiling" "budget-covers"
      [0, 0, 0, 1, 1, 500] [] []
      (decide <| Rich.budgetCovers
        (none : Option (Rich.BudgetCeiling natVocabulary))
        (some (richBudget 1 500))),
    richVector "status-fresher" "status" [1, 5, 1, 10] [] []
      (decide <| Rich.statusLe
        (.snapshotRequired (richStatusMethod 1) (richFreshness 5 (by decide)))
        (.snapshotRequired (richStatusMethod 1) (richFreshness 10 (by decide)))),
    richVector "status-weaker" "status" [1, 11, 1, 10] [] []
      (decide <| Rich.statusLe
        (.snapshotRequired (richStatusMethod 1) (richFreshness 11 (by decide)))
        (.snapshotRequired (richStatusMethod 1) (richFreshness 10 (by decide)))),
    richVector "status-method-mismatch" "status" [1, 5, 2, 10] [] []
      (decide <| Rich.statusLe
        (.snapshotRequired (richStatusMethod 1) (richFreshness 5 (by decide)))
        (.snapshotRequired (richStatusMethod 2) (richFreshness 10 (by decide)))),
    richVector "action-exact-match" "action-allows-exact" [1, 1] [] []
      (decide <| Rich.actionConstraintAllows
        (.exactBodyDigest (richDigest 1)) (richDigest 1)),
    richVector "action-exact-mismatch" "action-allows-exact" [1, 2] [] []
      (decide <| Rich.actionConstraintAllows
        (.exactBodyDigest (richDigest 1)) (richDigest 2)),
    richVector "action-set-attenuation" "action-set-attenuation" [] [1] [1, 2]
      (decide <| Rich.actionConstraintLe
        (.allowedBodyDigests {richDigest 1})
        (.allowedBodyDigests {richDigest 1, richDigest 2} :
          Rich.ActionConstraint natVocabulary)),
    richVector "action-set-widening" "action-set-attenuation" [] [1, 2] [1]
      (decide <| Rich.actionConstraintLe
        (.allowedBodyDigests {richDigest 1, richDigest 2})
        (.allowedBodyDigests {richDigest 1} :
          Rich.ActionConstraint natVocabulary))
  ]

def main (arguments : List String) : IO Unit := do
  match arguments with
  | ["threshold"] =>
      IO.println <| "{" ++
        s!"\"schema\":\"auths-proof-threshold-vectors/v1\",\"exhaustive_bound\":{Generated.exhaustiveThresholdBound},\"cases\":[{String.intercalate "," thresholdVectors}]" ++
        "}"
  | ["attenuation"] =>
      IO.println <| "{" ++
        s!"\"schema\":\"auths-proof-attenuation-vectors/v1\",\"dimensions\":11,\"cases\":[{String.intercalate "," attenuationVectors}]" ++
        "}"
  | ["rich-authority"] =>
      IO.println <| "{" ++
        s!"\"schema\":\"auths-proof-rich-authority-vectors/v1\",\"cases\":[{String.intercalate "," richAuthorityVectors}]" ++
        "}"
  | _ =>
      throw <| IO.userError
        "usage: auths-vector-export <threshold|attenuation|rich-authority>"
