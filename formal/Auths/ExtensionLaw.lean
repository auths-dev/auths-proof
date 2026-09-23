import Mathlib.Tactic

/-!
# Critical-extension attenuation laws

Every critical-extension handler declares an attenuation law over an optional
child payload and an optional parent payload (`none` is an absent
extension). The authority kernel judges each identifier by its law. Delegation
never widens authority when every law is a preorder that narrows; this module
states that premise over decoded payloads, and each handler discharges it for
its own law.
-/

namespace Auths

universe u w

/-- One handler's attenuation law over decoded payloads, and the worlds each
payload admits. -/
structure NarrowingLaw (Body : Type u) (World : Type w) where
  attenuates : Option Body → Option Body → Prop
  admits : Body → World → Prop

/-- The law is a preorder that narrows: reflexive, transitive, and accepting a
child payload only when it admits no world its parent payload refuses. -/
structure NarrowingLaw.Lawful {Body : Type u} {World : Type w}
    (law : NarrowingLaw Body World) : Prop where
  refl : ∀ body, law.attenuates (some body) (some body)
  trans : ∀ child middle (parent : Option Body),
    law.attenuates (some child) (some middle) →
    law.attenuates (some middle) parent →
    law.attenuates (some child) parent
  narrows : ∀ child parent, law.attenuates (some child) (some parent) →
    ∀ world, law.admits child world → law.admits parent world

/-- The `exact-marker-v1` law: byte equality, and adding the marker is
refused. The marker admits every world, so it changes no authority. -/
def exactMarkerLaw (Body : Type u) (World : Type w) : NarrowingLaw Body World where
  attenuates child parent :=
    match child, parent with
    | some child, some parent => child = parent
    | _, _ => False
  admits _ _ := True

theorem exact_marker_law_lawful (Body : Type u) (World : Type w) :
    (exactMarkerLaw Body World).Lawful where
  refl _ := rfl
  trans child middle parent childMiddle middleParent := by
    cases parent with
    | none => exact absurd middleParent id
    | some parent =>
        exact (show child = middle from childMiddle).trans middleParent
  narrows _ _ _ _ _ := trivial

theorem exact_marker_law_refuses_addition (Body : Type u) (World : Type w)
    (body : Body) : ¬ (exactMarkerLaw Body World).attenuates (some body) none :=
  id

end Auths
