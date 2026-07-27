import Lean.Elab.Tactic.Omega
import Auths.Base

namespace Auths

structure EffectiveAuthority where
  root : Nat
  subject : Nat
  profile : Nat
  permissions : Nat
  validity : Nat
  audiences : Nat
  actionConstraint : Nat
  budget : Nat
  status : Nat
  assurance : Nat
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
  child.profile ≤ parent.profile ∧
  child.permissions ≤ parent.permissions ∧
  child.validity ≤ parent.validity ∧
  child.audiences ≤ parent.audiences ∧
  child.actionConstraint ≤ parent.actionConstraint ∧
  child.budget ≤ parent.budget ∧
  child.status ≤ parent.status ∧
  child.assurance ≤ parent.assurance ∧
  child.depth ≤ parent.depth

def delegates (parent child : EffectiveAuthority) : Prop :=
  attenuates child parent ∧ child.depth < parent.depth

def delegationProjection
    (parent child : EffectiveAuthority) : Generated.AttenuationProjection where
  rootPreserved := decide (child.root = parent.root)
  depthDecreases := decide (child.depth < parent.depth)
  profileAttenuates := decide (child.profile ≤ parent.profile)
  permissionsAttenuate := decide (child.permissions ≤ parent.permissions)
  validityAttenuates := decide (child.validity ≤ parent.validity)
  audiencesAttenuate := decide (child.audiences ≤ parent.audiences)
  actionConstraintAttenuates :=
    decide (child.actionConstraint ≤ parent.actionConstraint)
  budgetAttenuates := decide (child.budget ≤ parent.budget)
  statusAttenuates := decide (child.status ≤ parent.status)
  assuranceAttenuates := decide (child.assurance ≤ parent.assurance)

def delegateTo
    (parent : EffectiveAuthority) (subject : Nat) : EffectiveAuthority :=
  { parent with subject := subject, depth := parent.depth - 1 }

def covers (authority : EffectiveAuthority) (action : Action) : Prop :=
  action.permissions ≤ authority.permissions ∧
  action.validity ≤ authority.validity ∧
  action.audiences ≤ authority.audiences ∧
  action.actionConstraint ≤ authority.actionConstraint ∧
  action.budget ≤ authority.budget

end Auths
