import Auths

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

def attenuationVector (values : List Bool) : String :=
  let projection := attenuationProjection values
  let fields := String.intercalate "," (values.map boolCode)
  let accepted := boolCode (Generated.attenuationAccepts projection)
  "{" ++ s!"\"checks\":[{fields}],\"accepted\":{accepted}" ++ "}"

def attenuationVectors : List String :=
  (boolVectors 10).map attenuationVector

def main (arguments : List String) : IO Unit := do
  match arguments with
  | ["threshold"] =>
      IO.println <| "{" ++
        s!"\"schema\":\"auths-proof-threshold-vectors/v1\",\"exhaustive_bound\":{Generated.exhaustiveThresholdBound},\"cases\":[{String.intercalate "," thresholdVectors}]" ++
        "}"
  | ["attenuation"] =>
      IO.println <| "{" ++
        s!"\"schema\":\"auths-proof-attenuation-vectors/v1\",\"dimensions\":10,\"cases\":[{String.intercalate "," attenuationVectors}]" ++
        "}"
  | _ =>
      throw <| IO.userError "usage: auths-vector-export <threshold|attenuation>"
