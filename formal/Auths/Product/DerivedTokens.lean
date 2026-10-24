import Auths.Product.OperationIdentity
import Auths.Product.RequestConstruction

namespace Auths.Product.DerivedTokens
open RequestConstruction

inductive Kind where
  | echo
  | idempotency
  deriving DecidableEq

def echoDomain : Bytes := [97,117,116,104,115,46,103,97,116,101,119,97,121,45,101,99,104,111,47,49,0]
def idempotencyDomain : Bytes := [97,117,116,104,115,46,103,97,116,101,119,97,121,45,105,100,101,109,112,111,116,101,110,99,121,45,107,101,121,47,49,0]
def echoPrefix : Bytes := [97,117,116,104,115,45,101,49,45]
def idempotencyPrefix : Bytes := [97,117,116,104,115,45,105,49,45]

def echoPreimage (namespaceBytes operation commitment : Bytes) : Bytes :=
  echoDomain ++ namespaceBytes ++ [0] ++ operation ++ [0] ++ commitment
def idempotencyPreimage (namespaceBytes operation : Bytes) : Bytes :=
  idempotencyDomain ++ namespaceBytes ++ [0] ++ operation

def prefix : Kind → Bytes
  | .echo => echoPrefix
  | .idempotency => idempotencyPrefix
def hexByte (byte : Nat) : Bytes := [hexLower (byte / 16), hexLower (byte % 16)]
def hexDigest (digest : Bytes) : Bytes := digest.flatMap hexByte
def token (kind : Kind) (digest : Bytes) : Bytes := prefix kind ++ hexDigest digest
def HexDigit (digit : Nat) : Prop := (48 ≤ digit ∧ digit ≤ 57) ∨ (97 ≤ digit ∧ digit ≤ 102)
instance (digit : Nat) : Decidable (HexDigit digit) := by unfold HexDigit; infer_instance

theorem prefix_length (kind : Kind) : (prefix kind).length = 9 := by cases kind <;> rfl
theorem hex_digest_length (digest : Bytes) : (hexDigest digest).length = 2 * digest.length := by
  induction digest with
  | nil => simp [hexDigest]
  | cons byte rest ih => simp [hexDigest, hexByte, ih]; omega

theorem token_length (kind : Kind) (digest : Bytes) (size : digest.length = 32) :
    (token kind digest).length = 73 := by
  simp [token, prefix_length, hex_digest_length, size]

theorem lower_hex_digit (nibble : Nat) (bounded : nibble < 16) : HexDigit (hexLower nibble) := by
  unfold hexLower HexDigit
  split <;> omega

theorem hex_digest_digits (digest : Bytes) (bounded : ∀ byte ∈ digest, byte < 256) :
    ∀ digit ∈ hexDigest digest, HexDigit digit := by
  intro digit member
  obtain ⟨byte, member, atByte⟩ := List.mem_flatMap.mp member
  have range := bounded byte member
  have high : byte / 16 < 16 := by omega
  have low : byte % 16 < 16 := by omega
  simp only [hexByte, List.mem_cons, List.mem_singleton] at atByte
  rcases atByte with same | same
  · subst digit; exact lower_hex_digit _ high
  · subst digit; exact lower_hex_digit _ low

theorem token_ascii (kind : Kind) (digest : Bytes) (bounded : ∀ byte ∈ digest, byte < 256) :
    ∀ byte ∈ token kind digest, byte < 128 := by
  intro byte member
  rcases List.mem_append.mp member with atPrefix | atHex
  · cases kind <;> simp [prefix, echoPrefix, idempotencyPrefix] at atPrefix <;> omega
  · have digit := hex_digest_digits digest bounded byte atHex
    unfold HexDigit at digit
    omega

def unhex (digit : Nat) : Nat := if digit < 58 then digit - 48 else digit - 87
private theorem unhex_lower (nibble : Nat) (bounded : nibble < 16) : unhex (hexLower nibble) = nibble := by
  unfold unhex hexLower
  split <;> split <;> omega

def unhexByte (bytes : Bytes) : Nat :=
  16 * unhex (bytes.headD 0) + unhex ((bytes.drop 1).headD 0)

private theorem unhex_byte (byte : Nat) (bounded : byte < 256) : unhexByte (hexByte byte) = byte := by
  have high : byte / 16 < 16 := by omega
  have low : byte % 16 < 16 := by omega
  simp only [unhexByte, hexByte, List.headD_cons, List.drop_succ_cons, List.drop_zero]
  rw [unhex_lower _ high, unhex_lower _ low]
  omega

theorem hex_byte_injective (left right : Nat) (leftBound : left < 256) (rightBound : right < 256)
    (same : hexByte left = hexByte right) : left = right := by
  have decoded := congrArg unhexByte same
  simpa [unhex_byte _ leftBound, unhex_byte _ rightBound] using decoded

theorem hex_digest_injective (left right : Bytes)
    (leftBound : ∀ byte ∈ left, byte < 256) (rightBound : ∀ byte ∈ right, byte < 256)
    (same : hexDigest left = hexDigest right) : left = right := by
  induction left generalizing right with
  | nil =>
    have sizes := congrArg List.length same
    rw [hex_digest_length, hex_digest_length] at sizes
    have empty : right = [] := List.eq_nil_of_length_eq_zero (by simp at sizes; omega)
    simp [empty]
  | cons first rest ih =>
    cases right with
    | nil =>
      have sizes := congrArg List.length same
      rw [hex_digest_length, hex_digest_length] at sizes
      simp at sizes
    | cons other tail =>
      have heads : hexByte first = hexByte other := by
        simpa [hexDigest, hexByte] using congrArg (List.take 2) same
      have tails : hexDigest rest = hexDigest tail := by
        simpa [hexDigest, hexByte] using congrArg (List.drop 2) same
      have headSame := hex_byte_injective first other (leftBound _ (by simp)) (rightBound _ (by simp)) heads
      have tailSame := ih tail (fun byte member => leftBound byte (by simp [member]))
        (fun byte member => rightBound byte (by simp [member])) tails
      simp [headSame, tailSame]

theorem token_injective (kind : Kind) (left right : Bytes)
    (leftBound : ∀ byte ∈ left, byte < 256) (rightBound : ∀ byte ∈ right, byte < 256)
    (same : token kind left = token kind right) : left = right := by
  have sameHex : hexDigest left = hexDigest right := List.append_left_cancel same
  exact hex_digest_injective left right leftBound rightBound sameHex

theorem token_kinds_separate (left right : Bytes) : token .echo left ≠ token .idempotency right := by
  intro same
  have tag := congrArg (fun bytes : Bytes => bytes[6]?) same
  simp [token, prefix, echoPrefix, idempotencyPrefix, List.getElem?_append] at tag

private theorem separator_injective (leftNamespace rightNamespace leftRest rightRest : Bytes)
    (leftFree : OperationIdentity.NulFree leftNamespace) (rightFree : OperationIdentity.NulFree rightNamespace)
    (same : leftNamespace ++ 0 :: leftRest = rightNamespace ++ 0 :: rightRest) :
    leftNamespace = rightNamespace ∧ leftRest = rightRest := by
  have names := congrArg (List.takeWhile (fun byte => byte != 0)) same
  rw [OperationIdentity.before_separator _ _ leftFree, OperationIdentity.before_separator _ _ rightFree] at names
  obtain ⟨_, tail⟩ := List.append_inj same (congrArg List.length names)
  exact ⟨names, (List.cons.inj tail).2⟩

theorem echo_preimage_injective (leftNamespace rightNamespace leftOperation rightOperation leftCommitment rightCommitment : Bytes)
    (leftNamespaceFree : OperationIdentity.NulFree leftNamespace) (rightNamespaceFree : OperationIdentity.NulFree rightNamespace)
    (leftOperationFree : OperationIdentity.NulFree leftOperation) (rightOperationFree : OperationIdentity.NulFree rightOperation)
    (same : echoPreimage leftNamespace leftOperation leftCommitment =
      echoPreimage rightNamespace rightOperation rightCommitment) :
    leftNamespace = rightNamespace ∧ leftOperation = rightOperation ∧ leftCommitment = rightCommitment := by
  have framed : leftNamespace ++ 0 :: (leftOperation ++ 0 :: leftCommitment) =
      rightNamespace ++ 0 :: (rightOperation ++ 0 :: rightCommitment) := by
    apply List.append_left_cancel (l₁ := echoDomain)
    simpa [echoPreimage, List.append_assoc] using same
  obtain ⟨names, remainder⟩ := separator_injective _ _ _ _ leftNamespaceFree rightNamespaceFree framed
  obtain ⟨operations, commitments⟩ := separator_injective _ _ _ _ leftOperationFree rightOperationFree remainder
  exact ⟨names, operations, commitments⟩

theorem idempotency_preimage_injective (leftNamespace rightNamespace leftOperation rightOperation : Bytes)
    (leftFree : OperationIdentity.NulFree leftNamespace) (rightFree : OperationIdentity.NulFree rightNamespace)
    (same : idempotencyPreimage leftNamespace leftOperation = idempotencyPreimage rightNamespace rightOperation) :
    leftNamespace = rightNamespace ∧ leftOperation = rightOperation := by
  have framed : leftNamespace ++ 0 :: leftOperation = rightNamespace ++ 0 :: rightOperation := by
    apply List.append_left_cancel (l₁ := idempotencyDomain)
    simpa [idempotencyPreimage, List.append_assoc] using same
  exact separator_injective _ _ _ _ leftFree rightFree framed

theorem preimage_domains_separate (firstNamespace firstOperation commitment secondNamespace secondOperation : Bytes) :
    echoPreimage firstNamespace firstOperation commitment ≠ idempotencyPreimage secondNamespace secondOperation := by
  intro same
  have tag := congrArg (fun bytes : Bytes => bytes[14]?) same
  simp [echoPreimage, idempotencyPreimage, echoDomain, idempotencyDomain, List.getElem?_append] at tag

end Auths.Product.DerivedTokens

