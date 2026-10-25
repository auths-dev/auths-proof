import Auths.Support.NativeBindingWiring
import qualification.aeneas.cases.NativeProjectorLevels
import qualification.aeneas.cases.NativeCaptureClosures
/- Native registry names and immediate expressions drive this complete Pure bundle.
   Unelaborated/unqualified. Full original environment/dispatch/permission adequacy remains open. -/
namespace Auths.Qualification.NativeBindingClosures
open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection
open Auths.Support.NativePurePayload Auths.Support.NativePureExpressions
open Auths.Qualification.NativePureExpressions
open Auths.Qualification.BorrowProjection.Candidate3400
universe u
def branch0Names : List Auths.Support.NativeBindingWiring.Pair := [{ native := { identity := 3, type := .literal 0 }, lowered := { identity := 0, type := .literal 0 } }, { native := { identity := 2, type := .literal 0 }, lowered := { identity := 1, type := .literal 0 } }, { native := { identity := 4, type := .literal 0 }, lowered := { identity := 3, type := .literal 0 } }, { native := { identity := 5, type := .error }, lowered := { identity := 2, type := .error } }]
def branch0Uses : List Auths.Support.NativeBindingWiring.Use := [{ native := .variable ({ identity := 3, type := .literal 0 }), lowered := .variable ({ identity := 0, type := .literal 0 }) }, { native := .variable ({ identity := 2, type := .literal 0 }), lowered := .variable ({ identity := 1, type := .literal 0 }) }]
theorem branch0_all_native_references_map_to_same_typed_lowered_variables : Auths.Support.NativeBindingWiring.usesValid branch0Names branch0Uses = true := by decide
def branch0 : Term := .lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.literal 0) (.result (.literal 0))))) (.bound (.literal 0) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.literal 0) (.result (.literal 0)))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.literal 0) (.result (.literal 0))) (.bound (.literal 0) (none)) (.binding (.result (.literal 0)) (.bound (.literal 0) (none)) (.bound (.literal 0) 0 0) (.switch (.result (.literal 0)) (.application (.result (.literal 0)) (.constructor (.arrow (.literal 0) (.result (.literal 0))) (.result) (some 0) [.literal 0]) (.bound (.literal 0) 0 0)) [(.constructor (.result (.literal 0)) (some 0) [.bound (.literal 0) (none)], .application (.result (.literal 0)) (.constructor (.arrow (.literal 0) (.result (.literal 0))) (.result) (some 0) [.literal 0]) (.bound (.literal 0) 0 0)), (.constructor (.result (.literal 0)) (some 1) [.bound (.error) (none)], .application (.result (.literal 0)) (.constructor (.arrow (.error) (.result (.literal 0))) (.result) (some 1) [.literal 0]) (.bound (.error) 0 0))]))))
def branch0Fuel : Nat := 152
theorem branch0_well_typed : check builtins schemas branch0Fuel [] branch0 = true := by decide
def branch0Run (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : Option (Dynamic Atom) :=
  executePacked builtins schemas branch0Fuel branch0 [pack branch0Fuel counter, pack branch0Fuel writer, pack branch0Fuel incoming0]
theorem branch0_native_registry_program_matches_selected_view_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) :
    branch0Run Atom counter writer incoming0 = Auths.Qualification.NativeCurrentWiring.branch0Run Atom counter writer incoming0 := by
  unfold branch0Run Auths.Qualification.NativeCurrentWiring.branch0Run
  rw [checked_packed_runs_body builtins schemas branch0Fuel branch0 branch0_well_typed]
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeCurrentWiring.branch0Fuel Auths.Qualification.NativeCurrentWiring.branch0 Auths.Qualification.NativeCurrentWiring.branch0_well_typed]
  cases counter with
  | atom v0 =>
    cases writer with
    | named v1 =>
      cases v1 with
      | left v2 =>
        cases v2 with
        | named v4 =>
          cases v4 with
          | product v5 v6 =>
            cases v5 with
            | named v7 =>
              cases v7 with
              | atom v8 =>
                cases v6 with
                | unit =>
                  cases incoming0 with
                  | atom v9 =>
                    rfl
      | right v3 =>
        cases v3 with
        | left v10 =>
          cases v10 with
          | named v12 =>
            cases v12 with
            | product v13 v14 =>
              cases v13 with
              | named v15 =>
                cases v15 with
                | atom v16 =>
                  cases v14 with
                  | unit =>
                    cases incoming0 with
                    | atom v17 =>
                      rfl
        | right v11 =>
          cases v11
def branch1Names : List Auths.Support.NativeBindingWiring.Pair := [{ native := { identity := 0, type := .literal 0 }, lowered := { identity := 1, type := .literal 0 } }, { native := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 2, type := .literal 0 }, lowered := { identity := 2, type := .literal 0 } }, { native := { identity := 5, type := .literal 0 }, lowered := { identity := 3, type := .literal 0 } }, { native := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 7, type := .error }, lowered := { identity := 5, type := .error } }]
def branch1Uses : List Auths.Support.NativeBindingWiring.Use := [{ native := .variable ({ identity := 0, type := .literal 0 }), lowered := .variable ({ identity := 1, type := .literal 0 }) }, { native := .variable ({ identity := 2, type := .literal 0 }), lowered := .variable ({ identity := 2, type := .literal 0 }) }, { native := .variable ({ identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }), lowered := .variable ({ identity := 0, type := .nominal 507 [.nominal 5 [.literal 1]] }) }, { native := .variable ({ identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }), lowered := .variable ({ identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }) }]
theorem branch1_all_native_references_map_to_same_typed_lowered_variables : Auths.Support.NativeBindingWiring.usesValid branch1Names branch1Uses = true := by decide
def branch1 : Term := .lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))))) (.bound (.literal 0) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (none)) (.bound (.literal 0) 2 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (none)) (.bound (.literal 0) 0 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0)) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0)), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.error) 0 0))]))))))
def branch1Fuel : Nat := 168
theorem branch1_well_typed : check builtins schemas branch1Fuel [] branch1 = true := by decide
def branch1Run (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : Option (Dynamic Atom) :=
  executePacked builtins schemas branch1Fuel branch1 [pack branch1Fuel counter, pack branch1Fuel writer, pack branch1Fuel incoming0]
theorem branch1_native_registry_program_matches_selected_view_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) :
    branch1Run Atom counter writer incoming0 = Auths.Qualification.NativeCurrentWiring.branch1Run Atom counter writer incoming0 := by
  unfold branch1Run Auths.Qualification.NativeCurrentWiring.branch1Run
  rw [checked_packed_runs_body builtins schemas branch1Fuel branch1 branch1_well_typed]
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeCurrentWiring.branch1Fuel Auths.Qualification.NativeCurrentWiring.branch1 Auths.Qualification.NativeCurrentWiring.branch1_well_typed]
  cases counter with
  | atom v18 =>
    cases writer with
    | named v19 =>
      cases v19 with
      | left v20 =>
        cases v20 with
        | named v22 =>
          cases v22 with
          | product v23 v24 =>
            cases v23 with
            | named v25 =>
              cases v25 with
              | atom v26 =>
                cases v24 with
                | unit =>
                  cases incoming0 with
                  | named v27 =>
                    cases v27 with
                    | left v28 =>
                      cases v28 with
                      | named v30 =>
                        cases v30 with
                        | product v31 v32 =>
                          cases v31 with
                          | named v33 =>
                            cases v33 with
                            | atom v34 =>
                              cases v32 with
                              | unit =>
                                rfl
                    | right v29 =>
                      cases v29 with
                      | left v35 =>
                        cases v35 with
                        | named v37 =>
                          cases v37 with
                          | product v38 v39 =>
                            cases v38 with
                            | named v40 =>
                              cases v40 with
                              | atom v41 =>
                                cases v39 with
                                | unit =>
                                  rfl
                      | right v36 =>
                        cases v36
      | right v21 =>
        cases v21 with
        | left v42 =>
          cases v42 with
          | named v44 =>
            cases v44 with
            | product v45 v46 =>
              cases v45 with
              | named v47 =>
                cases v47 with
                | atom v48 =>
                  cases v46 with
                  | unit =>
                    cases incoming0 with
                    | named v49 =>
                      cases v49 with
                      | left v50 =>
                        cases v50 with
                        | named v52 =>
                          cases v52 with
                          | product v53 v54 =>
                            cases v53 with
                            | named v55 =>
                              cases v55 with
                              | atom v56 =>
                                cases v54 with
                                | unit =>
                                  rfl
                      | right v51 =>
                        cases v51 with
                        | left v57 =>
                          cases v57 with
                          | named v59 =>
                            cases v59 with
                            | product v60 v61 =>
                              cases v60 with
                              | named v62 =>
                                cases v62 with
                                | atom v63 =>
                                  cases v61 with
                                  | unit =>
                                    rfl
                        | right v58 =>
                          cases v58
        | right v43 =>
          cases v43
def branch2Names : List Auths.Support.NativeBindingWiring.Pair := [{ native := { identity := 0, type := .literal 0 }, lowered := { identity := 1, type := .literal 0 } }, { native := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 2, type := .literal 0 }, lowered := { identity := 2, type := .literal 0 } }, { native := { identity := 5, type := .literal 0 }, lowered := { identity := 3, type := .literal 0 } }, { native := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 7, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 7, type := .error }, lowered := { identity := 6, type := .error } }]
def branch2Uses : List Auths.Support.NativeBindingWiring.Use := [{ native := .variable ({ identity := 0, type := .literal 0 }), lowered := .variable ({ identity := 1, type := .literal 0 }) }, { native := .variable ({ identity := 2, type := .literal 0 }), lowered := .variable ({ identity := 2, type := .literal 0 }) }, { native := .variable ({ identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }), lowered := .variable ({ identity := 0, type := .nominal 507 [.nominal 5 [.literal 1]] }) }, { native := .variable ({ identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }), lowered := .variable ({ identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }) }, { native := .variable ({ identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), lowered := .variable ({ identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] }) }]
theorem branch2_all_native_references_map_to_same_typed_lowered_variables : Auths.Support.NativeBindingWiring.usesValid branch2Names branch2Uses = true := by decide
def branch2 : Term := .lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))))) (.bound (.literal 0) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (none)) (.bound (.literal 0) 2 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (none)) (.bound (.literal 0) 0 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 4 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0)))])]) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0)), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.error) 0 0))]))))))
def branch2Fuel : Nat := 192
theorem branch2_well_typed : check builtins schemas branch2Fuel [] branch2 = true := by decide
def branch2Run (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Option (Dynamic Atom) :=
  executePacked builtins schemas branch2Fuel branch2 [pack branch2Fuel counter, pack branch2Fuel writer, pack branch2Fuel incoming0]
theorem branch2_native_registry_program_matches_selected_view_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    branch2Run Atom counter writer incoming0 = Auths.Qualification.NativeCurrentWiring.branch2Run Atom counter writer incoming0 := by
  unfold branch2Run Auths.Qualification.NativeCurrentWiring.branch2Run
  rw [checked_packed_runs_body builtins schemas branch2Fuel branch2 branch2_well_typed]
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeCurrentWiring.branch2Fuel Auths.Qualification.NativeCurrentWiring.branch2 Auths.Qualification.NativeCurrentWiring.branch2_well_typed]
  cases counter with
  | atom v64 =>
    cases writer with
    | named v65 =>
      cases v65 with
      | left v66 =>
        cases v66 with
        | named v68 =>
          cases v68 with
          | product v69 v70 =>
            cases v69 with
            | named v71 =>
              cases v71 with
              | atom v72 =>
                cases v70 with
                | unit =>
                  cases incoming0 with
                  | named v73 =>
                    cases v73 with
                    | left v74 =>
                      cases v74 with
                      | named v76 =>
                        cases v76 with
                        | product v77 v78 =>
                          cases v77 with
                          | named v79 =>
                            cases v79 with
                            | atom v80 =>
                              cases v78 with
                              | unit =>
                                rfl
                    | right v75 =>
                      cases v75 with
                      | left v81 =>
                        cases v81 with
                        | named v83 =>
                          cases v83 with
                          | product v84 v85 =>
                            cases v84 with
                            | named v86 =>
                              cases v86 with
                              | atom v87 =>
                                cases v85 with
                                | unit =>
                                  rfl
                      | right v82 =>
                        cases v82
      | right v67 =>
        cases v67 with
        | left v88 =>
          cases v88 with
          | named v90 =>
            cases v90 with
            | product v91 v92 =>
              cases v91 with
              | named v93 =>
                cases v93 with
                | atom v94 =>
                  cases v92 with
                  | unit =>
                    cases incoming0 with
                    | named v95 =>
                      cases v95 with
                      | left v96 =>
                        cases v96 with
                        | named v98 =>
                          cases v98 with
                          | product v99 v100 =>
                            cases v99 with
                            | named v101 =>
                              cases v101 with
                              | atom v102 =>
                                cases v100 with
                                | unit =>
                                  rfl
                      | right v97 =>
                        cases v97 with
                        | left v103 =>
                          cases v103 with
                          | named v105 =>
                            cases v105 with
                            | product v106 v107 =>
                              cases v106 with
                              | named v108 =>
                                cases v108 with
                                | atom v109 =>
                                  cases v107 with
                                  | unit =>
                                    rfl
                        | right v104 =>
                          cases v104
        | right v89 =>
          cases v89
def branch3Names : List Auths.Support.NativeBindingWiring.Pair := [{ native := { identity := 0, type := .literal 0 }, lowered := { identity := 2, type := .literal 0 } }, { native := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 0, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 7, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 2, type := .literal 0 }, lowered := { identity := 3, type := .literal 0 } }, { native := { identity := 8, type := .literal 0 }, lowered := { identity := 4, type := .literal 0 } }, { native := { identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 9, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 7, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 8, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 10, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 10, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 11, type := .error }, lowered := { identity := 9, type := .error } }, { native := { identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 11, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 12, type := .nominal 507 [.nominal 5 [.literal 1]] }, lowered := { identity := 13, type := .nominal 507 [.nominal 5 [.literal 1]] } }, { native := { identity := 13, type := .error }, lowered := { identity := 12, type := .error } }]
def branch3Uses : List Auths.Support.NativeBindingWiring.Use := [{ native := .variable ({ identity := 0, type := .literal 0 }), lowered := .variable ({ identity := 2, type := .literal 0 }) }, { native := .variable ({ identity := 2, type := .literal 0 }), lowered := .variable ({ identity := 3, type := .literal 0 }) }, { native := .variable ({ identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), lowered := .variable ({ identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] }) }, { native := .variable ({ identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }), lowered := .variable ({ identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }) }, { native := .variable ({ identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }), lowered := .variable ({ identity := 0, type := .nominal 507 [.nominal 5 [.literal 1]] }) }, { native := .variable ({ identity := 4, type := .nominal 507 [.nominal 5 [.literal 1]] }), lowered := .variable ({ identity := 8, type := .nominal 507 [.nominal 5 [.literal 1]] }) }, { native := .variable ({ identity := 3, type := .nominal 507 [.nominal 5 [.literal 1]] }), lowered := .variable ({ identity := 6, type := .nominal 507 [.nominal 5 [.literal 1]] }) }, { native := .variable ({ identity := 7, type := .nominal 507 [.nominal 5 [.literal 1]] }), lowered := .variable ({ identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }) }, { native := .variable ({ identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] }), lowered := .variable ({ identity := 11, type := .nominal 507 [.nominal 5 [.literal 1]] }) }, { native := .variable ({ identity := 1, type := .nominal 507 [.nominal 5 [.literal 1]] }), lowered := .variable ({ identity := 5, type := .nominal 507 [.nominal 5 [.literal 1]] }) }]
theorem branch3_all_native_references_map_to_same_typed_lowered_variables : Auths.Support.NativeBindingWiring.usesValid branch3Names branch3Uses = true := by decide
def branch3 : Term := .lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))))) (.bound (.literal 0) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.literal 0) (none)) (.bound (.literal 0) 3 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.literal 0) (none)) (.bound (.literal 0) 0 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 4 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 5 0) (.switch (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 1 0)))])]) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)], .binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 6 0) (.switch (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 9 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 1 0)))])]) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)], .application (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.result) (some 0) [.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]]) (.application (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.tuple) (none) [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0))), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (none)], .application (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.error) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.result) (some 1) [.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]]) (.bound (.error) 0 0))])), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (none)], .application (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.error) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.result) (some 1) [.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]]) (.bound (.error) 0 0))])))))))))
def branch3Fuel : Nat := 232
theorem branch3_well_typed : check builtins schemas branch3Fuel [] branch3 = true := by decide
def branch3Run (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) : Option (Dynamic Atom) :=
  executePacked builtins schemas branch3Fuel branch3 [pack branch3Fuel counter, pack branch3Fuel writer, pack branch3Fuel incoming0, pack branch3Fuel incoming1]
theorem branch3_native_registry_program_matches_selected_view_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) :
    branch3Run Atom counter writer incoming0 incoming1 = Auths.Qualification.NativeCurrentWiring.branch3Run Atom counter writer incoming0 incoming1 := by
  unfold branch3Run Auths.Qualification.NativeCurrentWiring.branch3Run
  rw [checked_packed_runs_body builtins schemas branch3Fuel branch3 branch3_well_typed]
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeCurrentWiring.branch3Fuel Auths.Qualification.NativeCurrentWiring.branch3 Auths.Qualification.NativeCurrentWiring.branch3_well_typed]
  cases counter with
  | atom v110 =>
    cases writer with
    | named v111 =>
      cases v111 with
      | left v112 =>
        cases v112 with
        | named v114 =>
          cases v114 with
          | product v115 v116 =>
            cases v115 with
            | named v117 =>
              cases v117 with
              | atom v118 =>
                cases v116 with
                | unit =>
                  cases incoming0 with
                  | named v119 =>
                    cases v119 with
                    | left v120 =>
                      cases v120 with
                      | named v122 =>
                        cases v122 with
                        | product v123 v124 =>
                          cases v123 with
                          | named v125 =>
                            cases v125 with
                            | atom v126 =>
                              cases v124 with
                              | unit =>
                                cases incoming1 with
                                | named v127 =>
                                  cases v127 with
                                  | left v128 =>
                                    cases v128 with
                                    | named v130 =>
                                      cases v130 with
                                      | product v131 v132 =>
                                        cases v131 with
                                        | named v133 =>
                                          cases v133 with
                                          | atom v134 =>
                                            cases v132 with
                                            | unit =>
                                              rfl
                                  | right v129 =>
                                    cases v129 with
                                    | left v135 =>
                                      cases v135 with
                                      | named v137 =>
                                        cases v137 with
                                        | product v138 v139 =>
                                          cases v138 with
                                          | named v140 =>
                                            cases v140 with
                                            | atom v141 =>
                                              cases v139 with
                                              | unit =>
                                                rfl
                                    | right v136 =>
                                      cases v136
                    | right v121 =>
                      cases v121 with
                      | left v142 =>
                        cases v142 with
                        | named v144 =>
                          cases v144 with
                          | product v145 v146 =>
                            cases v145 with
                            | named v147 =>
                              cases v147 with
                              | atom v148 =>
                                cases v146 with
                                | unit =>
                                  cases incoming1 with
                                  | named v149 =>
                                    cases v149 with
                                    | left v150 =>
                                      cases v150 with
                                      | named v152 =>
                                        cases v152 with
                                        | product v153 v154 =>
                                          cases v153 with
                                          | named v155 =>
                                            cases v155 with
                                            | atom v156 =>
                                              cases v154 with
                                              | unit =>
                                                rfl
                                    | right v151 =>
                                      cases v151 with
                                      | left v157 =>
                                        cases v157 with
                                        | named v159 =>
                                          cases v159 with
                                          | product v160 v161 =>
                                            cases v160 with
                                            | named v162 =>
                                              cases v162 with
                                              | atom v163 =>
                                                cases v161 with
                                                | unit =>
                                                  rfl
                                      | right v158 =>
                                        cases v158
                      | right v143 =>
                        cases v143
      | right v113 =>
        cases v113 with
        | left v164 =>
          cases v164 with
          | named v166 =>
            cases v166 with
            | product v167 v168 =>
              cases v167 with
              | named v169 =>
                cases v169 with
                | atom v170 =>
                  cases v168 with
                  | unit =>
                    cases incoming0 with
                    | named v171 =>
                      cases v171 with
                      | left v172 =>
                        cases v172 with
                        | named v174 =>
                          cases v174 with
                          | product v175 v176 =>
                            cases v175 with
                            | named v177 =>
                              cases v177 with
                              | atom v178 =>
                                cases v176 with
                                | unit =>
                                  cases incoming1 with
                                  | named v179 =>
                                    cases v179 with
                                    | left v180 =>
                                      cases v180 with
                                      | named v182 =>
                                        cases v182 with
                                        | product v183 v184 =>
                                          cases v183 with
                                          | named v185 =>
                                            cases v185 with
                                            | atom v186 =>
                                              cases v184 with
                                              | unit =>
                                                rfl
                                    | right v181 =>
                                      cases v181 with
                                      | left v187 =>
                                        cases v187 with
                                        | named v189 =>
                                          cases v189 with
                                          | product v190 v191 =>
                                            cases v190 with
                                            | named v192 =>
                                              cases v192 with
                                              | atom v193 =>
                                                cases v191 with
                                                | unit =>
                                                  rfl
                                      | right v188 =>
                                        cases v188
                      | right v173 =>
                        cases v173 with
                        | left v194 =>
                          cases v194 with
                          | named v196 =>
                            cases v196 with
                            | product v197 v198 =>
                              cases v197 with
                              | named v199 =>
                                cases v199 with
                                | atom v200 =>
                                  cases v198 with
                                  | unit =>
                                    cases incoming1 with
                                    | named v201 =>
                                      cases v201 with
                                      | left v202 =>
                                        cases v202 with
                                        | named v204 =>
                                          cases v204 with
                                          | product v205 v206 =>
                                            cases v205 with
                                            | named v207 =>
                                              cases v207 with
                                              | atom v208 =>
                                                cases v206 with
                                                | unit =>
                                                  rfl
                                      | right v203 =>
                                        cases v203 with
                                        | left v209 =>
                                          cases v209 with
                                          | named v211 =>
                                            cases v211 with
                                            | product v212 v213 =>
                                              cases v212 with
                                              | named v214 =>
                                                cases v214 with
                                                | atom v215 =>
                                                  cases v213 with
                                                  | unit =>
                                                    rfl
                                        | right v210 =>
                                          cases v210
                        | right v195 =>
                          cases v195
        | right v165 =>
          cases v165
def bundle : Term := .lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.tuple [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))]))) (.bound (.literal 0) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.tuple [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.application (.tuple [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))]) (.application (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))) (.tuple [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))])) (.application (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))) (.tuple [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))]))) (.application (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))) (.tuple [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))])))) (.constructor (.arrow (.arrow (.literal 0) (.result (.literal 0))) (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))) (.tuple [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))]))))) (.tuple) (none) [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))]) (.application (.arrow (.literal 0) (.result (.literal 0))) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.literal 0) (.result (.literal 0)))) (.lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.literal 0) (.result (.literal 0))))) (.bound (.literal 0) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.literal 0) (.result (.literal 0)))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.literal 0) (.result (.literal 0))) (.bound (.literal 0) (none)) (.binding (.result (.literal 0)) (.bound (.literal 0) (none)) (.bound (.literal 0) 0 0) (.switch (.result (.literal 0)) (.application (.result (.literal 0)) (.constructor (.arrow (.literal 0) (.result (.literal 0))) (.result) (some 0) [.literal 0]) (.bound (.literal 0) 0 0)) [(.constructor (.result (.literal 0)) (some 0) [.bound (.literal 0) (none)], .application (.result (.literal 0)) (.constructor (.arrow (.literal 0) (.result (.literal 0))) (.result) (some 0) [.literal 0]) (.bound (.literal 0) 0 0)), (.constructor (.result (.literal 0)) (some 1) [.bound (.error) (none)], .application (.result (.literal 0)) (.constructor (.arrow (.error) (.result (.literal 0))) (.result) (some 1) [.literal 0]) (.bound (.error) 0 0))]))))) (.bound (.literal 0) 1 0)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0))) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))))) (.bound (.literal 0) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (none)) (.bound (.literal 0) 2 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (none)) (.bound (.literal 0) 0 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0)) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0)), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.error) 0 0))]))))))) (.bound (.literal 0) 1 0)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0))) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))))) (.bound (.literal 0) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (none)) (.bound (.literal 0) 2 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (none)) (.bound (.literal 0) 0 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 4 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0)))])]) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0)), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.error) 0 0))]))))))) (.bound (.literal 0) 1 0)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0))) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))))) (.lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))))) (.bound (.literal 0) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.literal 0) (none)) (.bound (.literal 0) 3 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.literal 0) (none)) (.bound (.literal 0) 0 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 4 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 5 0) (.switch (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 1 0)))])]) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)], .binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 6 0) (.switch (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 9 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 1 0)))])]) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)], .application (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.result) (some 0) [.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]]) (.application (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.tuple) (none) [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0))), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (none)], .application (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.error) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.result) (some 1) [.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]]) (.bound (.error) 0 0))])), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (none)], .application (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.error) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.result) (some 1) [.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]]) (.bound (.error) 0 0))])))))))))) (.bound (.literal 0) 1 0)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0))))
def fuel : Nat := 392
theorem bundle_well_typed : check builtins schemas fuel [] bundle = true := by decide
def build (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Option (Dynamic Atom) :=
  Auths.Support.NativePureClosures.execute builtins schemas fuel bundle [pack fuel counter, pack fuel writer]
def memberTypes : List Ty := [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))]
theorem build_has_exact_member_types (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    (build Atom counter writer).map Dynamic.type = some (.tuple memberTypes) := by
  unfold build
  rw [Auths.Support.NativePureClosures.checked_runs_body builtins schemas fuel bundle bundle_well_typed]
  cases counter with
  | atom v216 =>
    cases writer with
    | named v217 =>
      cases v217 with
      | left v218 =>
        cases v218 with
        | named v220 =>
          cases v220 with
          | product v221 v222 =>
            cases v221 with
            | named v223 =>
              cases v223 with
              | atom v224 =>
                cases v222 with
                | unit =>
                  rfl
      | right v219 =>
        cases v219 with
        | left v225 =>
          cases v225 with
          | named v227 =>
            cases v227 with
            | product v228 v229 =>
              cases v228 with
              | named v230 =>
                cases v230 with
                | atom v231 =>
                  cases v229 with
                  | unit =>
                    rfl
        | right v226 =>
          cases v226
theorem build_produces_bundle (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : ∃ functions, build Atom counter writer = some functions := by
  cases result : build Atom counter writer with
  | none =>
    have accepted := build_has_exact_member_types Atom counter writer
    simp [result] at accepted
  | some functions => exact ⟨functions, by simp [result]⟩
def branch0Invoke (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← build Atom counter writer
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured 0 [pack fuel incoming0]
theorem branch0_bundle_uses_its_exact_registry_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) :
    branch0Invoke Atom counter writer incoming0 = branch0Run Atom counter writer incoming0 := by
  unfold branch0Invoke build branch0Run
  rw [Auths.Support.NativePureClosures.checked_runs_body builtins schemas fuel bundle bundle_well_typed]
  rw [checked_packed_runs_body builtins schemas branch0Fuel branch0 branch0_well_typed]
  cases counter with
  | atom v232 =>
    cases writer with
    | named v233 =>
      cases v233 with
      | left v234 =>
        cases v234 with
        | named v236 =>
          cases v236 with
          | product v237 v238 =>
            cases v237 with
            | named v239 =>
              cases v239 with
              | atom v240 =>
                cases v238 with
                | unit =>
                  cases incoming0 with
                  | atom v241 =>
                    rfl
      | right v235 =>
        cases v235 with
        | left v242 =>
          cases v242 with
          | named v244 =>
            cases v244 with
            | product v245 v246 =>
              cases v245 with
              | named v247 =>
                cases v247 with
                | atom v248 =>
                  cases v246 with
                  | unit =>
                    cases incoming0 with
                    | atom v249 =>
                      rfl
        | right v243 =>
          cases v243
theorem branch0_bundle_matches_selected_view_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) :
    branch0Invoke Atom counter writer incoming0 = Auths.Qualification.NativeCurrentWiring.branch0Run Atom counter writer incoming0 := by
  rw [branch0_bundle_uses_its_exact_registry_program, branch0_native_registry_program_matches_selected_view_program]
def branch1Invoke (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← build Atom counter writer
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured 1 [pack fuel incoming0]
theorem branch1_bundle_uses_its_exact_registry_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) :
    branch1Invoke Atom counter writer incoming0 = branch1Run Atom counter writer incoming0 := by
  unfold branch1Invoke build branch1Run
  rw [Auths.Support.NativePureClosures.checked_runs_body builtins schemas fuel bundle bundle_well_typed]
  rw [checked_packed_runs_body builtins schemas branch1Fuel branch1 branch1_well_typed]
  cases counter with
  | atom v250 =>
    cases writer with
    | named v251 =>
      cases v251 with
      | left v252 =>
        cases v252 with
        | named v254 =>
          cases v254 with
          | product v255 v256 =>
            cases v255 with
            | named v257 =>
              cases v257 with
              | atom v258 =>
                cases v256 with
                | unit =>
                  cases incoming0 with
                  | named v259 =>
                    cases v259 with
                    | left v260 =>
                      cases v260 with
                      | named v262 =>
                        cases v262 with
                        | product v263 v264 =>
                          cases v263 with
                          | named v265 =>
                            cases v265 with
                            | atom v266 =>
                              cases v264 with
                              | unit =>
                                rfl
                    | right v261 =>
                      cases v261 with
                      | left v267 =>
                        cases v267 with
                        | named v269 =>
                          cases v269 with
                          | product v270 v271 =>
                            cases v270 with
                            | named v272 =>
                              cases v272 with
                              | atom v273 =>
                                cases v271 with
                                | unit =>
                                  rfl
                      | right v268 =>
                        cases v268
      | right v253 =>
        cases v253 with
        | left v274 =>
          cases v274 with
          | named v276 =>
            cases v276 with
            | product v277 v278 =>
              cases v277 with
              | named v279 =>
                cases v279 with
                | atom v280 =>
                  cases v278 with
                  | unit =>
                    cases incoming0 with
                    | named v281 =>
                      cases v281 with
                      | left v282 =>
                        cases v282 with
                        | named v284 =>
                          cases v284 with
                          | product v285 v286 =>
                            cases v285 with
                            | named v287 =>
                              cases v287 with
                              | atom v288 =>
                                cases v286 with
                                | unit =>
                                  rfl
                      | right v283 =>
                        cases v283 with
                        | left v289 =>
                          cases v289 with
                          | named v291 =>
                            cases v291 with
                            | product v292 v293 =>
                              cases v292 with
                              | named v294 =>
                                cases v294 with
                                | atom v295 =>
                                  cases v293 with
                                  | unit =>
                                    rfl
                        | right v290 =>
                          cases v290
        | right v275 =>
          cases v275
theorem branch1_bundle_matches_selected_view_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) :
    branch1Invoke Atom counter writer incoming0 = Auths.Qualification.NativeCurrentWiring.branch1Run Atom counter writer incoming0 := by
  rw [branch1_bundle_uses_its_exact_registry_program, branch1_native_registry_program_matches_selected_view_program]
def branch2Invoke (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← build Atom counter writer
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured 2 [pack fuel incoming0]
theorem branch2_bundle_uses_its_exact_registry_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    branch2Invoke Atom counter writer incoming0 = branch2Run Atom counter writer incoming0 := by
  unfold branch2Invoke build branch2Run
  rw [Auths.Support.NativePureClosures.checked_runs_body builtins schemas fuel bundle bundle_well_typed]
  rw [checked_packed_runs_body builtins schemas branch2Fuel branch2 branch2_well_typed]
  cases counter with
  | atom v296 =>
    cases writer with
    | named v297 =>
      cases v297 with
      | left v298 =>
        cases v298 with
        | named v300 =>
          cases v300 with
          | product v301 v302 =>
            cases v301 with
            | named v303 =>
              cases v303 with
              | atom v304 =>
                cases v302 with
                | unit =>
                  cases incoming0 with
                  | named v305 =>
                    cases v305 with
                    | left v306 =>
                      cases v306 with
                      | named v308 =>
                        cases v308 with
                        | product v309 v310 =>
                          cases v309 with
                          | named v311 =>
                            cases v311 with
                            | atom v312 =>
                              cases v310 with
                              | unit =>
                                rfl
                    | right v307 =>
                      cases v307 with
                      | left v313 =>
                        cases v313 with
                        | named v315 =>
                          cases v315 with
                          | product v316 v317 =>
                            cases v316 with
                            | named v318 =>
                              cases v318 with
                              | atom v319 =>
                                cases v317 with
                                | unit =>
                                  rfl
                      | right v314 =>
                        cases v314
      | right v299 =>
        cases v299 with
        | left v320 =>
          cases v320 with
          | named v322 =>
            cases v322 with
            | product v323 v324 =>
              cases v323 with
              | named v325 =>
                cases v325 with
                | atom v326 =>
                  cases v324 with
                  | unit =>
                    cases incoming0 with
                    | named v327 =>
                      cases v327 with
                      | left v328 =>
                        cases v328 with
                        | named v330 =>
                          cases v330 with
                          | product v331 v332 =>
                            cases v331 with
                            | named v333 =>
                              cases v333 with
                              | atom v334 =>
                                cases v332 with
                                | unit =>
                                  rfl
                      | right v329 =>
                        cases v329 with
                        | left v335 =>
                          cases v335 with
                          | named v337 =>
                            cases v337 with
                            | product v338 v339 =>
                              cases v338 with
                              | named v340 =>
                                cases v340 with
                                | atom v341 =>
                                  cases v339 with
                                  | unit =>
                                    rfl
                        | right v336 =>
                          cases v336
        | right v321 =>
          cases v321
theorem branch2_bundle_matches_selected_view_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    branch2Invoke Atom counter writer incoming0 = Auths.Qualification.NativeCurrentWiring.branch2Run Atom counter writer incoming0 := by
  rw [branch2_bundle_uses_its_exact_registry_program, branch2_native_registry_program_matches_selected_view_program]
def branch3Invoke (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) : Option (Dynamic Atom) := do
  let captured ← build Atom counter writer
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured 3 [pack fuel incoming0, pack fuel incoming1]
theorem branch3_bundle_uses_its_exact_registry_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) :
    branch3Invoke Atom counter writer incoming0 incoming1 = branch3Run Atom counter writer incoming0 incoming1 := by
  unfold branch3Invoke build branch3Run
  rw [Auths.Support.NativePureClosures.checked_runs_body builtins schemas fuel bundle bundle_well_typed]
  rw [checked_packed_runs_body builtins schemas branch3Fuel branch3 branch3_well_typed]
  cases counter with
  | atom v342 =>
    cases writer with
    | named v343 =>
      cases v343 with
      | left v344 =>
        cases v344 with
        | named v346 =>
          cases v346 with
          | product v347 v348 =>
            cases v347 with
            | named v349 =>
              cases v349 with
              | atom v350 =>
                cases v348 with
                | unit =>
                  cases incoming0 with
                  | named v351 =>
                    cases v351 with
                    | left v352 =>
                      cases v352 with
                      | named v354 =>
                        cases v354 with
                        | product v355 v356 =>
                          cases v355 with
                          | named v357 =>
                            cases v357 with
                            | atom v358 =>
                              cases v356 with
                              | unit =>
                                cases incoming1 with
                                | named v359 =>
                                  cases v359 with
                                  | left v360 =>
                                    cases v360 with
                                    | named v362 =>
                                      cases v362 with
                                      | product v363 v364 =>
                                        cases v363 with
                                        | named v365 =>
                                          cases v365 with
                                          | atom v366 =>
                                            cases v364 with
                                            | unit =>
                                              rfl
                                  | right v361 =>
                                    cases v361 with
                                    | left v367 =>
                                      cases v367 with
                                      | named v369 =>
                                        cases v369 with
                                        | product v370 v371 =>
                                          cases v370 with
                                          | named v372 =>
                                            cases v372 with
                                            | atom v373 =>
                                              cases v371 with
                                              | unit =>
                                                rfl
                                    | right v368 =>
                                      cases v368
                    | right v353 =>
                      cases v353 with
                      | left v374 =>
                        cases v374 with
                        | named v376 =>
                          cases v376 with
                          | product v377 v378 =>
                            cases v377 with
                            | named v379 =>
                              cases v379 with
                              | atom v380 =>
                                cases v378 with
                                | unit =>
                                  cases incoming1 with
                                  | named v381 =>
                                    cases v381 with
                                    | left v382 =>
                                      cases v382 with
                                      | named v384 =>
                                        cases v384 with
                                        | product v385 v386 =>
                                          cases v385 with
                                          | named v387 =>
                                            cases v387 with
                                            | atom v388 =>
                                              cases v386 with
                                              | unit =>
                                                rfl
                                    | right v383 =>
                                      cases v383 with
                                      | left v389 =>
                                        cases v389 with
                                        | named v391 =>
                                          cases v391 with
                                          | product v392 v393 =>
                                            cases v392 with
                                            | named v394 =>
                                              cases v394 with
                                              | atom v395 =>
                                                cases v393 with
                                                | unit =>
                                                  rfl
                                      | right v390 =>
                                        cases v390
                      | right v375 =>
                        cases v375
      | right v345 =>
        cases v345 with
        | left v396 =>
          cases v396 with
          | named v398 =>
            cases v398 with
            | product v399 v400 =>
              cases v399 with
              | named v401 =>
                cases v401 with
                | atom v402 =>
                  cases v400 with
                  | unit =>
                    cases incoming0 with
                    | named v403 =>
                      cases v403 with
                      | left v404 =>
                        cases v404 with
                        | named v406 =>
                          cases v406 with
                          | product v407 v408 =>
                            cases v407 with
                            | named v409 =>
                              cases v409 with
                              | atom v410 =>
                                cases v408 with
                                | unit =>
                                  cases incoming1 with
                                  | named v411 =>
                                    cases v411 with
                                    | left v412 =>
                                      cases v412 with
                                      | named v414 =>
                                        cases v414 with
                                        | product v415 v416 =>
                                          cases v415 with
                                          | named v417 =>
                                            cases v417 with
                                            | atom v418 =>
                                              cases v416 with
                                              | unit =>
                                                rfl
                                    | right v413 =>
                                      cases v413 with
                                      | left v419 =>
                                        cases v419 with
                                        | named v421 =>
                                          cases v421 with
                                          | product v422 v423 =>
                                            cases v422 with
                                            | named v424 =>
                                              cases v424 with
                                              | atom v425 =>
                                                cases v423 with
                                                | unit =>
                                                  rfl
                                      | right v420 =>
                                        cases v420
                      | right v405 =>
                        cases v405 with
                        | left v426 =>
                          cases v426 with
                          | named v428 =>
                            cases v428 with
                            | product v429 v430 =>
                              cases v429 with
                              | named v431 =>
                                cases v431 with
                                | atom v432 =>
                                  cases v430 with
                                  | unit =>
                                    cases incoming1 with
                                    | named v433 =>
                                      cases v433 with
                                      | left v434 =>
                                        cases v434 with
                                        | named v436 =>
                                          cases v436 with
                                          | product v437 v438 =>
                                            cases v437 with
                                            | named v439 =>
                                              cases v439 with
                                              | atom v440 =>
                                                cases v438 with
                                                | unit =>
                                                  rfl
                                      | right v435 =>
                                        cases v435 with
                                        | left v441 =>
                                          cases v441 with
                                          | named v443 =>
                                            cases v443 with
                                            | product v444 v445 =>
                                              cases v444 with
                                              | named v446 =>
                                                cases v446 with
                                                | atom v447 =>
                                                  cases v445 with
                                                  | unit =>
                                                    rfl
                                        | right v442 =>
                                          cases v442
                        | right v427 =>
                          cases v427
        | right v397 =>
          cases v397
theorem branch3_bundle_matches_selected_view_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) :
    branch3Invoke Atom counter writer incoming0 incoming1 = Auths.Qualification.NativeCurrentWiring.branch3Run Atom counter writer incoming0 incoming1 := by
  rw [branch3_bundle_uses_its_exact_registry_program, branch3_native_registry_program_matches_selected_view_program]
structure Captured (Atom : Ty → Type u) where
  value : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) outputShape
  backwards : Dynamic Atom
def capture (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Option (Captured Atom) := do
  let prepared ← Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1
  let backwards ← build Atom prepared.current0 prepared.current1
  pure { value := prepared.value, backwards }
theorem capture_keeps_prepared_value (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) :
    (capture Atom input0 input1).map Captured.value = (Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1).map Auths.Qualification.NativeCurrentSeeds.Prepared.value := by
  unfold capture
  cases prepared : Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1 with
  | none => simp [prepared]
  | some value =>
    obtain ⟨functions, found⟩ := build_produces_bundle Atom value.current0 value.current1
    simp [prepared, found]
theorem capture_keeps_original_source_value (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) :
    (capture Atom input0 input1).map Captured.value = some (construct (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0 input1) := by
  rw [capture_keeps_prepared_value]
  exact Auths.Qualification.NativeCurrentSeeds.prepared_value_is_original_source_capture Atom input0 input1
def branch0FromCapture (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← capture Atom input0 input1
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured.backwards 0 [pack fuel incoming0]
theorem branch0_captures_its_own_forward_current (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) :
    branch0FromCapture Atom input0 input1 incoming0 = Auths.Qualification.NativeCurrentSeeds.branch0FromForward Atom input0 input1 incoming0 := by
  unfold branch0FromCapture capture Auths.Qualification.NativeCurrentSeeds.branch0FromForward
  cases prepared : Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1 with
  | none => simp [prepared]
  | some value =>
    simp only [prepared, Option.bind_some]
    simpa [branch0Invoke, Option.bind_assoc] using branch0_bundle_matches_selected_view_program Atom value.current0 value.current1 incoming0
def branch1FromCapture (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← capture Atom input0 input1
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured.backwards 1 [pack fuel incoming0]
theorem branch1_captures_its_own_forward_current (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) :
    branch1FromCapture Atom input0 input1 incoming0 = Auths.Qualification.NativeCurrentSeeds.branch1FromForward Atom input0 input1 incoming0 := by
  unfold branch1FromCapture capture Auths.Qualification.NativeCurrentSeeds.branch1FromForward
  cases prepared : Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1 with
  | none => simp [prepared]
  | some value =>
    simp only [prepared, Option.bind_some]
    simpa [branch1Invoke, Option.bind_assoc] using branch1_bundle_matches_selected_view_program Atom value.current0 value.current1 incoming0
def branch2FromCapture (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← capture Atom input0 input1
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured.backwards 2 [pack fuel incoming0]
theorem branch2_captures_its_own_forward_current (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    branch2FromCapture Atom input0 input1 incoming0 = Auths.Qualification.NativeCurrentSeeds.branch2FromForward Atom input0 input1 incoming0 := by
  unfold branch2FromCapture capture Auths.Qualification.NativeCurrentSeeds.branch2FromForward
  cases prepared : Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1 with
  | none => simp [prepared]
  | some value =>
    simp only [prepared, Option.bind_some]
    simpa [branch2Invoke, Option.bind_assoc] using branch2_bundle_matches_selected_view_program Atom value.current0 value.current1 incoming0
def branch3FromCapture (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) : Option (Dynamic Atom) := do
  let captured ← capture Atom input0 input1
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured.backwards 3 [pack fuel incoming0, pack fuel incoming1]
theorem branch3_captures_its_own_forward_current (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) :
    branch3FromCapture Atom input0 input1 incoming0 incoming1 = Auths.Qualification.NativeCurrentSeeds.branch3FromForward Atom input0 input1 incoming0 incoming1 := by
  unfold branch3FromCapture capture Auths.Qualification.NativeCurrentSeeds.branch3FromForward
  cases prepared : Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1 with
  | none => simp [prepared]
  | some value =>
    simp only [prepared, Option.bind_some]
    simpa [branch3Invoke, Option.bind_assoc] using branch3_bundle_matches_selected_view_program Atom value.current0 value.current1 incoming0 incoming1
end Auths.Qualification.NativeBindingClosures
