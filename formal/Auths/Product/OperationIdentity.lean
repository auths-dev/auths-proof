import Mathlib.Tactic
namespace Auths.Product.OperationIdentity
abbrev Bytes := List Nat

def Alphanumeric (byte : Nat) : Prop :=
  (48 ≤ byte ∧ byte ≤ 57) ∨ (65 ≤ byte ∧ byte ≤ 90) ∨ (97 ≤ byte ∧ byte ≤ 122)
def TailByte (byte : Nat) : Prop := Alphanumeric byte ∨ byte = 46 ∨ byte = 95 ∨ byte = 45
local instance (byte : Nat) : Decidable (Alphanumeric byte) := inferInstanceAs (Decidable (_ ∨ _))
local instance (byte : Nat) : Decidable (TailByte byte) := inferInstanceAs (Decidable (_ ∨ _))

def validToken (bytes : Bytes) (maximum : Nat) : Bool :=
  match bytes with
  | [] => false
  | first :: rest => decide (bytes.length ≤ maximum ∧ Alphanumeric first) &&
      rest.all (fun byte => decide (TailByte byte))

def NulFree (bytes : Bytes) : Prop := ∀ byte ∈ bytes, byte ≠ 0

theorem alphanumeric_nonzero (byte : Nat) (valid : Alphanumeric byte) : byte ≠ 0 := by
  unfold Alphanumeric at valid
  omega

theorem tail_nonzero (byte : Nat) (valid : TailByte byte) : byte ≠ 0 := by
  rcases valid with alpha | dot | underscore | hyphen
  · exact alphanumeric_nonzero byte alpha
  · omega
  · omega
  · omega

theorem token_nul_free (bytes : Bytes) (maximum : Nat) (valid : validToken bytes maximum = true) :
    NulFree bytes := by
  cases bytes with
  | nil => simp [validToken] at valid
  | cons first rest =>
    simp only [validToken, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true] at valid
    intro byte member
    rcases List.mem_cons.mp member with same | tail
    · subst byte; exact alphanumeric_nonzero first valid.1.2
    · exact tail_nonzero byte (by simpa using valid.2 byte tail)

/-- UTF-8 bytes of `auths.gateway-logical-operation/1` followed by NUL. -/
def domain : Bytes := [97,117,116,104,115,46,103,97,116,101,119,97,121,45,108,111,103,
  105,99,97,108,45,111,112,101,114,97,116,105,111,110,47,49,0]

structure Identity where
  namespaceBytes : Bytes
  operation : Bytes
  deriving DecidableEq

def preimage (identity : Identity) : Bytes :=
  domain ++ (identity.namespaceBytes ++ 0 :: identity.operation)

theorem before_separator (namespaceBytes operation : Bytes) (valid : NulFree namespaceBytes) :
    (namespaceBytes ++ 0 :: operation).takeWhile (fun byte => byte != 0) = namespaceBytes := by
  induction namespaceBytes with
  | nil => simp
  | cons first rest ih =>
    have firstNonzero := valid first (by simp)
    have restFree : NulFree rest := fun byte member => valid byte (by simp [member])
    simp [firstNonzero, ih restFree]

/-- Framing is injective on validated namespaceBytes carriers. This theorem is
    about exact bytes and assumes no collision-free hash. -/
theorem preimage_injective (left right : Identity)
    (leftValid : NulFree left.namespaceBytes) (rightValid : NulFree right.namespaceBytes)
    (same : preimage left = preimage right) : left = right := by
  have framed : left.namespaceBytes ++ 0 :: left.operation = right.namespaceBytes ++ 0 :: right.operation := by
    obtain ⟨_, rest⟩ := List.append_inj same (show domain.length = domain.length from rfl)
    exact rest
  have namespaces := congrArg (List.takeWhile (fun byte => byte != 0)) framed
  rw [before_separator _ _ leftValid, before_separator _ _ rightValid] at namespaces
  obtain ⟨_, tails⟩ := List.append_inj framed (congrArg List.length namespaces)
  have operations := (List.cons.inj tails).2
  cases left; cases right
  simp_all

theorem valid_tokens_bind_identity (left right : Identity)
    (leftValid : validToken left.namespaceBytes 64 = true)
    (rightValid : validToken right.namespaceBytes 64 = true)
    (same : preimage left = preimage right) : left = right :=
  preimage_injective left right (token_nul_free _ _ leftValid) (token_nul_free _ _ rightValid) same

end Auths.Product.OperationIdentity
