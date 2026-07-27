import Lean.Elab.Tactic.Omega
import Auths.Base

namespace Auths

structure EffectiveAuthority where
  root : Nat
  subject : Nat
  permissions : Nat
  validity : Nat
  audiences : Nat
  actionConstraint : Nat
  budget : Nat
  status : Nat
  depth : Nat
  deriving DecidableEq, Repr

structure Action where
  permissions : Nat
  validity : Nat
  audiences : Nat
  actionConstraint : Nat
  budget : Nat
  deriving DecidableEq, Repr

def attenuates (child parent : EffectiveAuthority) : Prop :=
  child.root = parent.root ∧
  child.permissions ≤ parent.permissions ∧
  child.validity ≤ parent.validity ∧
  child.audiences ≤ parent.audiences ∧
  child.actionConstraint ≤ parent.actionConstraint ∧
  child.budget ≤ parent.budget ∧
  child.status ≤ parent.status ∧
  child.depth ≤ parent.depth

def delegates (parent child : EffectiveAuthority) : Prop :=
  attenuates child parent ∧ child.depth < parent.depth

def covers (authority : EffectiveAuthority) (action : Action) : Prop :=
  action.permissions ≤ authority.permissions ∧
  action.validity ≤ authority.validity ∧
  action.audiences ≤ authority.audiences ∧
  action.actionConstraint ≤ authority.actionConstraint ∧
  action.budget ≤ authority.budget

end Auths
