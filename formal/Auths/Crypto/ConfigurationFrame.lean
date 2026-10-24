import Auths.Crypto.Framing

open Auths.Codec
namespace Auths.Crypto.ConfigurationFrame

/-- Adapter configuration uses its existing V1 prefix. It is a different
frame from signing, object identifiers and application commitments. -/
def prefix : List Nat :=
  "auths-proof-adapter-configuration-v1".toUTF8.toList.map UInt8.toNat

structure Frame where
  domain : List Nat
  components : List (List Nat)
  deriving DecidableEq

def component (bytes : List Nat) : List Nat := bigEndian 8 bytes.length ++ bytes

def encodeComponents : List (List Nat) → List Nat
  | [] => []
  | head :: tail => component head ++ encodeComponents tail

def encode (frame : Frame) : List Nat :=
  prefix ++ component frame.domain ++ encodeComponents frame.components

def Frame.Valid (frame : Frame) : Prop :=
  frame.domain.length < 2 ^ 64 ∧
  ∀ bytes ∈ frame.components, bytes.length < 2 ^ 64

theorem component_length (bytes : List Nat) :
    (component bytes).length = 8 + bytes.length := by
  simp [component, bigEndian_length]

theorem components_length (values : List (List Nat)) :
    (encodeComponents values).length = 8 * values.length + (values.map List.length).sum := by
  induction values with
  | nil => simp [encodeComponents]
  | cons head tail ih => simp [encodeComponents, component_length, ih]; omega

theorem frame_length (frame : Frame) :
    (encode frame).length = prefix.length + 8 + frame.domain.length +
      8 * frame.components.length + (frame.components.map List.length).sum := by
  simp [encode, component_length, components_length]
  omega

theorem component_unambiguous (left right afterLeft afterRight : List Nat)
    (leftFits : left.length < 2 ^ 64) (rightFits : right.length < 2 ^ 64)
    (same : component left ++ afterLeft = component right ++ afterRight) :
    left = right ∧ afterLeft = afterRight := by
  have normalized : bigEndian 8 left.length ++ (left ++ afterLeft) =
      bigEndian 8 right.length ++ (right ++ afterRight) := by
    simpa only [component, List.append_assoc] using same
  obtain ⟨lengthBytes, content⟩ := List.append_inj normalized (by simp [bigEndian_length])
  have lengths : left.length = right.length :=
    Framing.endian_injective 8 _ _ (by simpa using leftFits) (by simpa using rightFits) lengthBytes
  exact List.append_inj content lengths

theorem components_unambiguous (left right : List (List Nat))
    (leftFits : ∀ bytes ∈ left, bytes.length < 2 ^ 64)
    (rightFits : ∀ bytes ∈ right, bytes.length < 2 ^ 64)
    (same : encodeComponents left = encodeComponents right) : left = right := by
  revert leftFits rightFits same
  induction left generalizing right with
  | nil =>
    intro leftFits rightFits same
    cases right with
    | nil => rfl
    | cons head tail =>
      have lengths := congrArg List.length same
      simp only [encodeComponents, List.length_nil, List.length_append, component_length] at lengths
      omega
  | cons head tail ih =>
    intro leftFits rightFits same
    cases right with
    | nil =>
      have lengths := congrArg List.length same
      simp only [encodeComponents, List.length_nil, List.length_append, component_length] at lengths
      omega
    | cons rightHead rightTail =>
      have headFit : head.length < 2 ^ 64 := leftFits head (by simp)
      have rightHeadFit : rightHead.length < 2 ^ 64 := rightFits rightHead (by simp)
      obtain ⟨heads, tails⟩ := component_unambiguous head rightHead
        (encodeComponents tail) (encodeComponents rightTail) headFit rightHeadFit same
      have tailFits : ∀ bytes ∈ tail, bytes.length < 2 ^ 64 :=
        fun bytes member => leftFits bytes (by simp [member])
      have rightTailFits : ∀ bytes ∈ rightTail, bytes.length < 2 ^ 64 :=
        fun bytes member => rightFits bytes (by simp [member])
      exact List.cons.inj.mpr ⟨heads, ih rightTail tailFits rightTailFits tails⟩

/-- The ordered domain/components are determined by the preimage. Empty
components remain distinct from no components. No hash assumption is needed. -/
theorem unambiguous (left right : Frame) (leftValid : left.Valid) (rightValid : right.Valid)
    (same : encode left = encode right) : left = right := by
  have rest : component left.domain ++ encodeComponents left.components =
      component right.domain ++ encodeComponents right.components := by
    exact List.append_left_cancel (by simpa only [encode, List.append_assoc] using same)
  obtain ⟨domains, components⟩ := component_unambiguous left.domain right.domain
    (encodeComponents left.components) (encodeComponents right.components)
    leftValid.1 rightValid.1 rest
  have componentsSame := components_unambiguous left.components right.components
    leftValid.2 rightValid.2 components
  cases left; cases right
  simp_all

theorem no_component_differs_from_empty_component (domain : List Nat) :
    encode ⟨domain, []⟩ ≠ encode ⟨domain, [[]]⟩ := by
  intro same
  have lengths := congrArg List.length same
  simp only [frame_length, List.length_nil, List.length_cons, List.map_cons,
    List.map_nil, List.sum_cons, List.sum_nil] at lengths
  omega

theorem different_domains_separate (left right : Frame)
    (leftValid : left.Valid) (rightValid : right.Valid) (different : left.domain ≠ right.domain) :
    encode left ≠ encode right := by
  intro same
  exact different (congrArg Frame.domain (unambiguous left right leftValid rightValid same))

end Auths.Crypto.ConfigurationFrame
