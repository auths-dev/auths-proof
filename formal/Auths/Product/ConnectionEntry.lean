import Auths.Product.SchemaIndex
import Mathlib.Tactic
namespace Auths.Product.ConnectionEntry
inductive State where | active | disabled | revoked
  deriving DecidableEq
structure Profile where
  id : List Nat
  version : Nat
  deriving DecidableEq

def valid (state : State) (workloads : List (List Nat)) (profiles : List Profile)
    (workload : List Nat) (profile : Profile) : Prop :=
  state = .active ∧ workload ∈ workloads ∧ profile ∈ profiles
instance (state : State) (workloads : List (List Nat)) (profiles : List Profile)
    (workload : List Nat) (profile : Profile) : Decidable (valid state workloads profiles workload profile) := by
  unfold valid
  infer_instance

def allows (state : State) (workloads : List (List Nat)) (profiles : List Profile)
    (workload : List Nat) (profile : Profile) : Bool := decide (valid state workloads profiles workload profile)

theorem admitted_binds_all (state : State) (workloads : List (List Nat)) (profiles : List Profile)
    (workload : List Nat) (profile : Profile) (accepted : allows state workloads profiles workload profile = true) :
    state = .active ∧ workload ∈ workloads ∧ profile ∈ profiles := by
  simpa [allows, valid] using accepted
end Auths.Product.ConnectionEntry
