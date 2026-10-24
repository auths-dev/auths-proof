import qualification.aeneas.cases.NativePureExpressions
/- Native SSA lowering of the explicit ending model. Unelaborated/unqualified.
   Foreign-default selection is proposed; original native environment/continuation/heap adequacy remains open. -/
namespace Auths.Qualification.NativeCurrentWiring
open Auths.Support.NativePurePayload Auths.Support.NativePureExpressions
open Auths.Qualification.NativePureExpressions
universe u
def branch0 : Term := .lambda (.arrow (.literal 0) (.result (.literal 0))) (.bound (.literal 0) (some [105, 110, 99, 111, 109, 105, 110, 103, 95, 55])) (.binding (.result (.literal 0)) (.bound (.literal 0) (some [114, 101, 99, 101, 105, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 55])) (.bound (.literal 0) 0 0) (.switch (.result (.literal 0)) (.application (.result (.literal 0)) (.constructor (.arrow (.literal 0) (.result (.literal 0))) (.result) (some 0) [.literal 0]) (.bound (.literal 0) 0 0)) [(.constructor (.result (.literal 0)) (some 0) [.bound (.literal 0) (some [111, 117, 116, 112, 117, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 55])], .application (.result (.literal 0)) (.constructor (.arrow (.literal 0) (.result (.literal 0))) (.result) (some 0) [.literal 0]) (.bound (.literal 0) 0 0)), (.constructor (.result (.literal 0)) (some 1) [.bound (.error) (some [101, 114, 114, 111, 114, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 55])], .application (.result (.literal 0)) (.constructor (.arrow (.error) (.result (.literal 0))) (.result) (some 1) [.literal 0]) (.bound (.error) 0 0))]))
def branch0Fuel : Nat := 94
theorem branch0_well_typed : check builtins schemas branch0Fuel [] branch0 = true := by decide
def branch0Run (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : Option (Dynamic Atom) :=
  executePacked builtins schemas branch0Fuel branch0 [pack branch0Fuel incoming0]
def branch0Expected (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : Option (Dynamic Atom) :=
  expectedMany builtins [.literal 0] (do
    let outputs ← Auths.Qualification.NativeBorrowFullABI.branch0FullFromEndingState
      (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) (decode Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec counter) (decode Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec writer)
      (decode Auths.Qualification.NativePurePayload.branch0Channel0IncomingCodec incoming0)
    pure [pack branch0Fuel (encode Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec outputs)])
theorem branch0_executes_explicit_ending_model (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) :
    branch0Run Atom counter writer incoming0 = branch0Expected Atom counter writer incoming0 := by
  unfold branch0Run
  rw [checked_packed_runs_body builtins schemas branch0Fuel branch0 branch0_well_typed]
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
def branch1 : Term := .lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.literal 0) (some [105, 110, 105, 116, 105, 97, 108, 95, 98, 111, 114, 114, 111, 119, 95, 48])) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [105, 110, 99, 111, 109, 105, 110, 103, 95, 57])) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (some [100, 101, 102, 97, 117, 108, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 56])) (.bound (.literal 0) 1 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (some [111, 98, 115, 101, 114, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 56])) (.bound (.literal 0) 0 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [114, 101, 99, 101, 105, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 57])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0)) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [111, 117, 116, 112, 117, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 57])], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0)), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (some [101, 114, 114, 111, 114, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 57])], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.error) 0 0))])))))
def branch1Fuel : Nat := 112
theorem branch1_well_typed : check builtins schemas branch1Fuel [] branch1 = true := by decide
def branch1Run (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : Option (Dynamic Atom) :=
  executePacked builtins schemas branch1Fuel branch1 [pack branch1Fuel counter, pack branch1Fuel incoming0]
def branch1Expected (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : Option (Dynamic Atom) :=
  expectedMany builtins [.nominal 507 [.nominal 5 [.literal 1]]] (do
    let outputs ← Auths.Qualification.NativeBorrowFullABI.branch1FullFromEndingState
      (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) (decode Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec counter) (decode Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec writer)
      (decode Auths.Qualification.NativePurePayload.branch1Channel0IncomingCodec incoming0)
    pure [pack branch1Fuel (encode Auths.Qualification.NativePurePayload.branch1Channel0OutgoingCodec outputs)])
theorem branch1_executes_explicit_ending_model (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) :
    branch1Run Atom counter writer incoming0 = branch1Expected Atom counter writer incoming0 := by
  unfold branch1Run
  rw [checked_packed_runs_body builtins schemas branch1Fuel branch1 branch1_well_typed]
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
def branch2 : Term := .lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))))) (.bound (.literal 0) (some [105, 110, 105, 116, 105, 97, 108, 95, 98, 111, 114, 114, 111, 119, 95, 48])) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [105, 110, 105, 116, 105, 97, 108, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 54])) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [105, 110, 99, 111, 109, 105, 110, 103, 95, 49, 49])) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (some [100, 101, 102, 97, 117, 108, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 48])) (.bound (.literal 0) 2 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (some [111, 98, 115, 101, 114, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 48])) (.bound (.literal 0) 0 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [114, 101, 99, 101, 105, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 49])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 4 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0)))])]) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [111, 117, 116, 112, 117, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 49])], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0)), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (some [101, 114, 114, 111, 114, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 49])], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.error) 0 0))]))))))
def branch2Fuel : Nat := 136
theorem branch2_well_typed : check builtins schemas branch2Fuel [] branch2 = true := by decide
def branch2Run (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Option (Dynamic Atom) :=
  executePacked builtins schemas branch2Fuel branch2 [pack branch2Fuel counter, pack branch2Fuel writer, pack branch2Fuel incoming0]
def branch2Expected (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Option (Dynamic Atom) :=
  expectedMany builtins [.nominal 507 [.nominal 5 [.literal 1]]] (do
    let outputs ← Auths.Qualification.NativeBorrowFullABI.branch2FullFromEndingState
      (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) (decode Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec counter) (decode Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec writer)
      (decode Auths.Qualification.NativePurePayload.branch2Channel0IncomingCodec incoming0)
    pure [pack branch2Fuel (encode Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec outputs)])
theorem branch2_executes_explicit_ending_model (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    branch2Run Atom counter writer incoming0 = branch2Expected Atom counter writer incoming0 := by
  unfold branch2Run
  rw [checked_packed_runs_body builtins schemas branch2Fuel branch2 branch2_well_typed]
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
def branch3 : Term := .lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))))) (.bound (.literal 0) (some [105, 110, 105, 116, 105, 97, 108, 95, 98, 111, 114, 114, 111, 119, 95, 48])) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [105, 110, 105, 116, 105, 97, 108, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 54])) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [105, 110, 99, 111, 109, 105, 110, 103, 95, 49, 52])) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [105, 110, 99, 111, 109, 105, 110, 103, 95, 49, 53])) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.literal 0) (some [100, 101, 102, 97, 117, 108, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 50])) (.bound (.literal 0) 3 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.literal 0) (some [111, 98, 115, 101, 114, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 50])) (.bound (.literal 0) 0 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [100, 101, 102, 97, 117, 108, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 51])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 4 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [111, 98, 115, 101, 114, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 51])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [114, 101, 99, 101, 105, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 52])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 5 0) (.switch (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 1 0)))])]) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [111, 117, 116, 112, 117, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 52])], .binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [114, 101, 99, 101, 105, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 53])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 6 0) (.switch (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 9 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 1 0)))])]) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [111, 117, 116, 112, 117, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 53])], .application (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.result) (some 0) [.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]]) (.application (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.tuple) (none) [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0))), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (some [101, 114, 114, 111, 114, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 53])], .application (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.error) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.result) (some 1) [.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]]) (.bound (.error) 0 0))])), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (some [101, 114, 114, 111, 114, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 52])], .application (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.error) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.result) (some 1) [.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]]) (.bound (.error) 0 0))])))))))))
def branch3Fuel : Nat := 166
theorem branch3_well_typed : check builtins schemas branch3Fuel [] branch3 = true := by decide
def branch3Run (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) : Option (Dynamic Atom) :=
  executePacked builtins schemas branch3Fuel branch3 [pack branch3Fuel counter, pack branch3Fuel writer, pack branch3Fuel incoming0, pack branch3Fuel incoming1]
def branch3Expected (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) : Option (Dynamic Atom) :=
  expectedMany builtins [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]] (do
    let outputs ← Auths.Qualification.NativeBorrowFullABI.branch3FullFromEndingState
      (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) (decode Auths.Qualification.NativePurePayload.branch0Channel0OutgoingCodec counter) (decode Auths.Qualification.NativePurePayload.branch2Channel0OutgoingCodec writer)
      (decode Auths.Qualification.NativePurePayload.branch3Channel0IncomingCodec incoming0) (decode Auths.Qualification.NativePurePayload.branch3Channel1IncomingCodec incoming1)
    pure [pack branch3Fuel (encode Auths.Qualification.NativePurePayload.branch3Channel0OutgoingCodec outputs.1), pack branch3Fuel (encode Auths.Qualification.NativePurePayload.branch3Channel1OutgoingCodec outputs.2)])
theorem branch3_executes_explicit_ending_model (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) :
    branch3Run Atom counter writer incoming0 incoming1 = branch3Expected Atom counter writer incoming0 incoming1 := by
  unfold branch3Run
  rw [checked_packed_runs_body builtins schemas branch3Fuel branch3 branch3_well_typed]
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
end Auths.Qualification.NativeCurrentWiring
