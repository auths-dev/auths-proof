import Auths.Product.AdmissionOwnership
namespace Auths.Product.AdmissionHistory.Examples

def policy : Policy :=
  {capacity := fun counter => if counter = 0 then 2 else 0, expires := fun _ => 100}
def first : Request := ⟨("operator", "payment-1"), 1, [⟨0, 1⟩]⟩
def second : Request := ⟨("operator", "payment-2"), 2, [⟨0, 1⟩]⟩
def third : Request := ⟨("operator", "payment-3"), 3, [⟨0, 1⟩]⟩

theorem available_capacity_admits :
    (run policy empty [.admission first true]).handles first.operation = some 1 := by
  simp [run, step, admit, empty, first, policy, fits, charge, Function.update]

theorem lost_acknowledgement_preserves_claim :
    (run policy empty [.admission first false]).claims first.operation = some 1 := by
  simp [run, step, admit, empty, first, policy, fits, charge, Function.update]

theorem lost_acknowledgement_cannot_enter :
    (run policy empty [.admission first false, .writeEntry first.operation 1]).entries = [] := by
  simp [run, step, admit, enter, empty, first, policy, fits, charge, Function.update]

theorem replay_cannot_change_owner :
    (run policy empty [.admission first true,
      .admission {first with worker := 2, debits := []} true]).claims first.operation = some 1 := by
  simp [run, step, admit, empty, first, policy, fits, charge, Function.update]

theorem two_entries_consume_shared_capacity :
    (run policy empty [.admission first true, .writeEntry first.operation 1,
      .admission second true, .writeEntry second.operation 2, .admission third true]).historical 0 = 2 := by
  simp [run, step, admit, enter, empty, first, second, third, policy, fits, charge, Function.update]

theorem crash_cannot_refund_capacity :
    (run policy empty [.admission first true, .processCrash 1]).historical 0 = 1 := by
  simp [run, step, admit, crash, empty, first, policy, fits, charge, Function.update]

theorem collected_window_cannot_reopen :
    (run policy empty [.admission first true, .collection 100, .collection 0,
      .admission second true]).claims second.operation = none := by
  simp [run, step, admit, collect, empty, first, second, policy, fits, charge, Function.update]

theorem write_handle_is_one_use :
    (run policy empty [.admission first true, .writeEntry first.operation 1,
      .writeEntry first.operation 1]).entries = [(first.operation, 1)] := by
  simp [run, step, admit, enter, empty, first, policy, fits, charge, Function.update]

theorem failure_before_commit_can_retry :
    (run policy empty [.failedBeforeCommit, .admission first true]).handles first.operation = some 1 := by
  simp [run, step, admit, empty, first, policy, fits, charge, Function.update]

theorem terminal_refusal_retains_claim_without_capacity :
    (run policy empty [.terminalRefusal first.operation 1]).claims first.operation = some 1 ∧
      (run policy empty [.terminalRefusal first.operation 1]).historical 0 = 0 := by
  simp [run, step, admit, empty, first, policy, fits, charge, Function.update]

end Auths.Product.AdmissionHistory.Examples
