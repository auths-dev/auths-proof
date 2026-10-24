import Auths.Support.NativePureExpressions
import qualification.aeneas.cases.NativePurePayload
/- Actual closed native Pure helper expressions. Unelaborated/unqualified.
   These helpers do not replace the original functions or prove current/default/loan adequacy. -/
namespace Auths.Qualification.NativePureExpressions
open Auths.Support.NativePurePayload Auths.Support.NativePureExpressions
universe u
def builtins : Builtins := { resultOk := 0, resultFail := 1, errorFailure := 0, errorOutOfFuel := 1 }
theorem actual_builtin_tags_are_distinct : builtins.resultOk ≠ builtins.resultFail ∧ builtins.errorFailure ≠ builtins.errorOutOfFuel := by decide
def schemas : List Schema := [
  { type := .nominal 507 [.nominal 5 [.literal 1]], variants := [(some 0, [.nominal 5 [.literal 1]]), (some 1, [.nominal 5 [.literal 1]])] }
]
def branch0Channel0 : Term := .lambda (.arrow (.literal 0) (.result (.literal 0))) (.bound (.literal 0) (none)) (.application (.result (.literal 0)) (.constructor (.arrow (.literal 0) (.result (.literal 0))) (.result) (some 0) [.literal 0]) (.bound (.literal 0) 0 0))
def branch0Channel0Fuel : Nat := 44
theorem branch0Channel0_well_typed : check builtins schemas branch0Channel0Fuel [] branch0Channel0 = true := by decide
def branch0Channel0Escaped : Term := .lambda (.arrow (.literal 0) (.result (.literal 0))) (.bound (.literal 0) (none)) (.bound (.result (.literal 0)) 999 0)
theorem branch0Channel0_escaped_scope_refused : check builtins schemas branch0Channel0Fuel [] branch0Channel0Escaped = false := by decide
theorem branch0Channel0_evaluates_as_selected_adapter (Atom : Ty → Type u)
    (current incoming : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) :
    execute builtins schemas branch0Channel0Fuel branch0Channel0 current incoming =
      expected builtins branch0Channel0Fuel (.literal 0) (Auths.Qualification.NativePurePayload.branch0Channel0Native Atom current incoming) := by
  rw [checked_runs_body builtins schemas branch0Channel0Fuel branch0Channel0 branch0Channel0_well_typed]
  cases current with
  | atom v0 =>
    cases incoming with
    | atom v1 =>
      rfl
def branch1Channel0 : Term := .lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0))
def branch1Channel0Fuel : Nat := 44
theorem branch1Channel0_well_typed : check builtins schemas branch1Channel0Fuel [] branch1Channel0 = true := by decide
def branch1Channel0Escaped : Term := .lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.result (.nominal 507 [.nominal 5 [.literal 1]])) 999 0)
theorem branch1Channel0_escaped_scope_refused : check builtins schemas branch1Channel0Fuel [] branch1Channel0Escaped = false := by decide
theorem branch1Channel0_evaluates_as_selected_adapter (Atom : Ty → Type u)
    (current incoming : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) :
    execute builtins schemas branch1Channel0Fuel branch1Channel0 current incoming =
      expected builtins branch1Channel0Fuel (.nominal 507 [.nominal 5 [.literal 1]]) (Auths.Qualification.NativePurePayload.branch1Channel0Native Atom current incoming) := by
  rw [checked_runs_body builtins schemas branch1Channel0Fuel branch1Channel0 branch1Channel0_well_typed]
  cases current with
  | named v2 =>
    cases v2 with
    | left v3 =>
      cases v3 with
      | named v5 =>
        cases v5 with
        | product v6 v7 =>
          cases v6 with
          | named v8 =>
            cases v8 with
            | atom v9 =>
              cases v7 with
              | unit =>
                cases incoming with
                | named v10 =>
                  cases v10 with
                  | left v11 =>
                    cases v11 with
                    | named v13 =>
                      cases v13 with
                      | product v14 v15 =>
                        cases v14 with
                        | named v16 =>
                          cases v16 with
                          | atom v17 =>
                            cases v15 with
                            | unit =>
                              rfl
                  | right v12 =>
                    cases v12 with
                    | left v18 =>
                      cases v18 with
                      | named v20 =>
                        cases v20 with
                        | product v21 v22 =>
                          cases v21 with
                          | named v23 =>
                            cases v23 with
                            | atom v24 =>
                              cases v22 with
                              | unit =>
                                rfl
                    | right v19 =>
                      cases v19
    | right v4 =>
      cases v4 with
      | left v25 =>
        cases v25 with
        | named v27 =>
          cases v27 with
          | product v28 v29 =>
            cases v28 with
            | named v30 =>
              cases v30 with
              | atom v31 =>
                cases v29 with
                | unit =>
                  cases incoming with
                  | named v32 =>
                    cases v32 with
                    | left v33 =>
                      cases v33 with
                      | named v35 =>
                        cases v35 with
                        | product v36 v37 =>
                          cases v36 with
                          | named v38 =>
                            cases v38 with
                            | atom v39 =>
                              cases v37 with
                              | unit =>
                                rfl
                    | right v34 =>
                      cases v34 with
                      | left v40 =>
                        cases v40 with
                        | named v42 =>
                          cases v42 with
                          | product v43 v44 =>
                            cases v43 with
                            | named v45 =>
                              cases v45 with
                              | atom v46 =>
                                cases v44 with
                                | unit =>
                                  rfl
                      | right v41 =>
                        cases v41
      | right v26 =>
        cases v26
def branch2Channel0 : Term := .lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0)))])]))
def branch2Channel0Fuel : Nat := 60
theorem branch2Channel0_well_typed : check builtins schemas branch2Channel0Fuel [] branch2Channel0 = true := by decide
def branch2Channel0Escaped : Term := .lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.result (.nominal 507 [.nominal 5 [.literal 1]])) 999 0))
theorem branch2Channel0_escaped_scope_refused : check builtins schemas branch2Channel0Fuel [] branch2Channel0Escaped = false := by decide
def branch2Channel0MissingVariant : Term := .lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0)))])]))
theorem branch2Channel0_missing_variant_refused : check builtins schemas branch2Channel0Fuel [] branch2Channel0MissingVariant = false := by decide
theorem branch2Channel0_evaluates_as_selected_adapter (Atom : Ty → Type u)
    (current incoming : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    execute builtins schemas branch2Channel0Fuel branch2Channel0 current incoming =
      expected builtins branch2Channel0Fuel (.nominal 507 [.nominal 5 [.literal 1]]) (Auths.Qualification.NativePurePayload.branch2Channel0Native Atom current incoming) := by
  rw [checked_runs_body builtins schemas branch2Channel0Fuel branch2Channel0 branch2Channel0_well_typed]
  cases current with
  | named v47 =>
    cases v47 with
    | left v48 =>
      cases v48 with
      | named v50 =>
        cases v50 with
        | product v51 v52 =>
          cases v51 with
          | named v53 =>
            cases v53 with
            | atom v54 =>
              cases v52 with
              | unit =>
                cases incoming with
                | named v55 =>
                  cases v55 with
                  | left v56 =>
                    cases v56 with
                    | named v58 =>
                      cases v58 with
                      | product v59 v60 =>
                        cases v59 with
                        | named v61 =>
                          cases v61 with
                          | atom v62 =>
                            cases v60 with
                            | unit =>
                              rfl
                  | right v57 =>
                    cases v57 with
                    | left v63 =>
                      cases v63 with
                      | named v65 =>
                        cases v65 with
                        | product v66 v67 =>
                          cases v66 with
                          | named v68 =>
                            cases v68 with
                            | atom v69 =>
                              cases v67 with
                              | unit =>
                                rfl
                    | right v64 =>
                      cases v64
    | right v49 =>
      cases v49 with
      | left v70 =>
        cases v70 with
        | named v72 =>
          cases v72 with
          | product v73 v74 =>
            cases v73 with
            | named v75 =>
              cases v75 with
              | atom v76 =>
                cases v74 with
                | unit =>
                  cases incoming with
                  | named v77 =>
                    cases v77 with
                    | left v78 =>
                      cases v78 with
                      | named v80 =>
                        cases v80 with
                        | product v81 v82 =>
                          cases v81 with
                          | named v83 =>
                            cases v83 with
                            | atom v84 =>
                              cases v82 with
                              | unit =>
                                rfl
                    | right v79 =>
                      cases v79 with
                      | left v85 =>
                        cases v85 with
                        | named v87 =>
                          cases v87 with
                          | product v88 v89 =>
                            cases v88 with
                            | named v90 =>
                              cases v90 with
                              | atom v91 =>
                                cases v89 with
                                | unit =>
                                  rfl
                      | right v86 =>
                        cases v86
      | right v71 =>
        cases v71
def branch3Channel0 : Term := .lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 1 0)))])]))
def branch3Channel0Fuel : Nat := 60
theorem branch3Channel0_well_typed : check builtins schemas branch3Channel0Fuel [] branch3Channel0 = true := by decide
def branch3Channel0Escaped : Term := .lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.result (.nominal 507 [.nominal 5 [.literal 1]])) 999 0))
theorem branch3Channel0_escaped_scope_refused : check builtins schemas branch3Channel0Fuel [] branch3Channel0Escaped = false := by decide
def branch3Channel0MissingVariant : Term := .lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 1 0)))])]))
theorem branch3Channel0_missing_variant_refused : check builtins schemas branch3Channel0Fuel [] branch3Channel0MissingVariant = false := by decide
theorem branch3Channel0_evaluates_as_selected_adapter (Atom : Ty → Type u)
    (current incoming : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) :
    execute builtins schemas branch3Channel0Fuel branch3Channel0 current incoming =
      expected builtins branch3Channel0Fuel (.nominal 507 [.nominal 5 [.literal 1]]) (Auths.Qualification.NativePurePayload.branch3Channel0Native Atom current incoming) := by
  rw [checked_runs_body builtins schemas branch3Channel0Fuel branch3Channel0 branch3Channel0_well_typed]
  cases current with
  | named v92 =>
    cases v92 with
    | left v93 =>
      cases v93 with
      | named v95 =>
        cases v95 with
        | product v96 v97 =>
          cases v96 with
          | named v98 =>
            cases v98 with
            | atom v99 =>
              cases v97 with
              | unit =>
                cases incoming with
                | named v100 =>
                  cases v100 with
                  | left v101 =>
                    cases v101 with
                    | named v103 =>
                      cases v103 with
                      | product v104 v105 =>
                        cases v104 with
                        | named v106 =>
                          cases v106 with
                          | atom v107 =>
                            cases v105 with
                            | unit =>
                              rfl
                  | right v102 =>
                    cases v102 with
                    | left v108 =>
                      cases v108 with
                      | named v110 =>
                        cases v110 with
                        | product v111 v112 =>
                          cases v111 with
                          | named v113 =>
                            cases v113 with
                            | atom v114 =>
                              cases v112 with
                              | unit =>
                                rfl
                    | right v109 =>
                      cases v109
    | right v94 =>
      cases v94 with
      | left v115 =>
        cases v115 with
        | named v117 =>
          cases v117 with
          | product v118 v119 =>
            cases v118 with
            | named v120 =>
              cases v120 with
              | atom v121 =>
                cases v119 with
                | unit =>
                  cases incoming with
                  | named v122 =>
                    cases v122 with
                    | left v123 =>
                      cases v123 with
                      | named v125 =>
                        cases v125 with
                        | product v126 v127 =>
                          cases v126 with
                          | named v128 =>
                            cases v128 with
                            | atom v129 =>
                              cases v127 with
                              | unit =>
                                rfl
                    | right v124 =>
                      cases v124 with
                      | left v130 =>
                        cases v130 with
                        | named v132 =>
                          cases v132 with
                          | product v133 v134 =>
                            cases v133 with
                            | named v135 =>
                              cases v135 with
                              | atom v136 =>
                                cases v134 with
                                | unit =>
                                  rfl
                      | right v131 =>
                        cases v131
      | right v116 =>
        cases v116
def branch3Channel1 : Term := .lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 1 0)))])]))
def branch3Channel1Fuel : Nat := 60
theorem branch3Channel1_well_typed : check builtins schemas branch3Channel1Fuel [] branch3Channel1 = true := by decide
def branch3Channel1Escaped : Term := .lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.bound (.result (.nominal 507 [.nominal 5 [.literal 1]])) 999 0))
theorem branch3Channel1_escaped_scope_refused : check builtins schemas branch3Channel1Fuel [] branch3Channel1Escaped = false := by decide
def branch3Channel1MissingVariant : Term := .lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (none)) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 1 0)))])]))
theorem branch3Channel1_missing_variant_refused : check builtins schemas branch3Channel1Fuel [] branch3Channel1MissingVariant = false := by decide
theorem branch3Channel1_evaluates_as_selected_adapter (Atom : Ty → Type u)
    (current incoming : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) :
    execute builtins schemas branch3Channel1Fuel branch3Channel1 current incoming =
      expected builtins branch3Channel1Fuel (.nominal 507 [.nominal 5 [.literal 1]]) (Auths.Qualification.NativePurePayload.branch3Channel1Native Atom current incoming) := by
  rw [checked_runs_body builtins schemas branch3Channel1Fuel branch3Channel1 branch3Channel1_well_typed]
  cases current with
  | named v137 =>
    cases v137 with
    | left v138 =>
      cases v138 with
      | named v140 =>
        cases v140 with
        | product v141 v142 =>
          cases v141 with
          | named v143 =>
            cases v143 with
            | atom v144 =>
              cases v142 with
              | unit =>
                cases incoming with
                | named v145 =>
                  cases v145 with
                  | left v146 =>
                    cases v146 with
                    | named v148 =>
                      cases v148 with
                      | product v149 v150 =>
                        cases v149 with
                        | named v151 =>
                          cases v151 with
                          | atom v152 =>
                            cases v150 with
                            | unit =>
                              rfl
                  | right v147 =>
                    cases v147 with
                    | left v153 =>
                      cases v153 with
                      | named v155 =>
                        cases v155 with
                        | product v156 v157 =>
                          cases v156 with
                          | named v158 =>
                            cases v158 with
                            | atom v159 =>
                              cases v157 with
                              | unit =>
                                rfl
                    | right v154 =>
                      cases v154
    | right v139 =>
      cases v139 with
      | left v160 =>
        cases v160 with
        | named v162 =>
          cases v162 with
          | product v163 v164 =>
            cases v163 with
            | named v165 =>
              cases v165 with
              | atom v166 =>
                cases v164 with
                | unit =>
                  cases incoming with
                  | named v167 =>
                    cases v167 with
                    | left v168 =>
                      cases v168 with
                      | named v170 =>
                        cases v170 with
                        | product v171 v172 =>
                          cases v171 with
                          | named v173 =>
                            cases v173 with
                            | atom v174 =>
                              cases v172 with
                              | unit =>
                                rfl
                    | right v169 =>
                      cases v169 with
                      | left v175 =>
                        cases v175 with
                        | named v177 =>
                          cases v177 with
                          | product v178 v179 =>
                            cases v178 with
                            | named v180 =>
                              cases v180 with
                              | atom v181 =>
                                cases v179 with
                                | unit =>
                                  rfl
                      | right v176 =>
                        cases v176
      | right v161 =>
        cases v161
end Auths.Qualification.NativePureExpressions
