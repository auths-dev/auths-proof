import Auths.Authority

namespace Auths

theorem attenuation_refl (authority : EffectiveAuthority) :
    attenuates authority authority := by
  simp [attenuates]

theorem attenuation_trans {a b c : EffectiveAuthority}
    (hab : attenuates a b) (hbc : attenuates b c) : attenuates a c := by
  simp only [attenuates] at *
  obtain ⟨r₁, p₁, pe₁, v₁, a₁, c₁, b₁, s₁, as₁, d₁⟩ := hab
  obtain ⟨r₂, p₂, pe₂, v₂, a₂, c₂, b₂, s₂, as₂, d₂⟩ := hbc
  constructor
  · exact r₁.trans r₂
  · omega

theorem attenuation_antisymm {a b : EffectiveAuthority}
    (hab : attenuates a b) (hba : attenuates b a)
    (subjects : a.subject = b.subject) : a = b := by
  simp only [attenuates] at hab hba
  obtain ⟨root, p₁, v₁, a₁, c₁, b₁, s₁, d₁⟩ := hab
  obtain ⟨_, p₂, v₂, a₂, c₂, b₂, s₂, d₂⟩ := hba
  cases a
  cases b
  simp_all
  omega

theorem coverage_downward_closed {child parent : EffectiveAuthority} {action : Action}
    (order : attenuates child parent) (covered : covers child action) :
    covers parent action := by
  simp only [attenuates] at order
  simp only [covers] at covered ⊢
  omega

theorem delegate_preserves_root {parent child : EffectiveAuthority}
    (accepted : delegates parent child) : child.root = parent.root :=
  accepted.1.1

theorem delegate_updates_subject (parent : EffectiveAuthority) (subject : Nat) :
    (delegateTo parent subject).subject = subject := rfl

theorem attenuation_kernel_refines (parent child : EffectiveAuthority) :
    Generated.attenuationAccepts (delegationProjection parent child) = true ↔
      delegates parent child := by
  simp [Generated.attenuationAccepts, delegationProjection, delegates, attenuates]
  omega

theorem delegate_strict_depth {parent child : EffectiveAuthority}
    (accepted : delegates parent child) : child.depth < parent.depth :=
  accepted.2

theorem delegate_never_widens {parent child : EffectiveAuthority}
    (accepted : delegates parent child) : attenuates child parent :=
  accepted.1

theorem chain_transitive_attenuation {root middle terminal : EffectiveAuthority}
    (first : delegates root middle) (second : delegates middle terminal) :
    attenuates terminal root :=
  attenuation_trans second.1 first.1

theorem authorized_action_covered
    {parent child : EffectiveAuthority} {action : Action}
    (accepted : delegates parent child) (authorized : covers child action) :
    covers parent action :=
  coverage_downward_closed accepted.1 authorized

end Auths
