import Auths.Crypto.Strict.SuiteRefinement
open Aeneas Aeneas.Std Result
open Auths.Crypto.Strict.SuiteModel Auths.Crypto.Strict.SuiteRefinement
namespace Auths.Crypto.Strict.Acceptance

def EdForm (bytes : List Std.U8) : Prop :=
  ∃ encoded : Encoding.Encoded.Input, encoded.val = bytes ∧ Encoding.Encoded.Encoding encoded

def EdAccepts {K : Type} (decode : List Std.U8 → Option K)
    (equation : K → List Std.U8 → List Std.U8 → Bool)
    (key message signature : List Std.U8) : Prop :=
  ∃ encoded : Encoding.Encoded.Input, ∃ signed : RContract.Input,
    encoded.val = key ∧ signed.val = signature ∧ Encoding.Encoded.Encoding encoded ∧
    ¬ WeakContract.WeakCoordinate (Encoding.Encoded.ordinate encoded) ∧ RContract.Allowed signed ∧
    ∃ point, decode key = some point ∧ equation point message signature = true

def P256Accepts {K S : Type} (decode : List Std.U8 → Option K) (parse : List Std.U8 → Option S)
    (equation : K → List Std.U8 → S → Bool) (key message signature : List Std.U8) : Prop :=
  Encoding.P256.Encoding (key.map UScalar.val) ∧ signature.length = 64 ∧
    ByteLex.value (signature.drop 32) ≤ LowContract.order / 2 ∧
    ∃ point parsed, decode key = some point ∧ parse signature = some parsed ∧ equation point message parsed = true

theorem fixed_exact (N : Std.Usize) (array : Array Std.U8 N) : fixed N array.val = some array := by
  unfold fixed
  have sized : array.val.length = N.val := array.property
  simp only [sized, _root_.dite_true]
  congr 1

theorem key_encoding_accepts_iff (bytes : List Std.U8) (encoded : Encoding.Encoded.Input) :
    keyEncoding bytes = .ok encoded ↔ encoded.val = bytes ∧ Encoding.Encoded.Encoding encoded := by
  constructor
  · intro accepted
    refine ⟨key_encoding_value bytes encoded accepted, ?_⟩
    unfold keyEncoding at accepted
    cases sized : fixedKey bytes with
    | none => simp [sized] at accepted
    | some raw =>
      simp only [sized] at accepted
      split at accepted
      · rename_i canonical
        simp only [Except.ok.injEq] at accepted
        simpa [accepted] using canonical
      · contradiction
  · rintro ⟨exactBytes, canonical⟩
    have sized := fixed_exact 32#usize encoded
    rw [exactBytes] at sized
    simp [keyEncoding, fixedKey, sized, canonical]

theorem p256_key_accepts_iff {K : Type} (decode : List Std.U8 → Option K)
    (bytes : List Std.U8) (point : K) :
    p256Key decode bytes = .ok point ↔ Encoding.P256.Encoding (bytes.map UScalar.val) ∧ decode bytes = some point := by
  by_cases canonical : Encoding.P256.Encoding (bytes.map UScalar.val)
  · cases decoded : decode bytes <;> simp [p256Key, canonical, decoded, eq_comm]
  · simp [p256Key, canonical]

theorem ed_accepts_iff {K : Type} (decode : List Std.U8 → Option K)
    (equation : K → List Std.U8 → List Std.U8 → Bool)
    (key message signature : List Std.U8) :
    edVerify decode equation key message signature = .ok () ↔ EdAccepts decode equation key message signature := by
  cases encoded : keyEncoding key with
  | error reason =>
    have refused : ¬ EdAccepts decode equation key message signature := by
      rintro ⟨raw, _, exactKey, _, canonical, _⟩
      have accepted := (key_encoding_accepts_iff key raw).mpr ⟨exactKey, canonical⟩
      rw [encoded] at accepted
      contradiction
    simp [edVerify, encoded, refused, Except.bind, Bind.bind, Except.instMonad]
  | ok raw =>
    obtain ⟨exactKey, canonical⟩ := (key_encoding_accepts_iff key raw).mp encoded
    cases decoded : decode key with
    | none => simp [edVerify, encoded, decoded, EdAccepts, Except.bind, Bind.bind, Except.instMonad]
    | some point =>
      cases sized : fixedSignature signature with
      | none =>
        have refused : ¬ EdAccepts decode equation key message signature := by
          rintro ⟨_, signed, _, exactSignature, _⟩
          have accepted := fixed_exact 64#usize signed
          rw [exactSignature] at accepted
          change fixedSignature signature = some signed at accepted
          rw [sized] at accepted
          contradiction
        simp [edVerify, encoded, decoded, sized, refused, Except.bind, Bind.bind, Except.instMonad]
      | some signed =>
        have exactSignature : signed.val = signature := fixed_value 64#usize signature signed sized
        have relation : EdAccepts decode equation key message signature ↔
            ¬ WeakContract.WeakCoordinate (Encoding.Encoded.ordinate raw) ∧
            RContract.Allowed signed ∧ equation point message signature = true := by
          constructor
          · rintro ⟨other, otherSignature, otherKey, otherBytes, _, notWeak, allowed, otherPoint, samePoint, verifies⟩
            have sameKey : other = raw := Subtype.ext (otherKey.trans exactKey.symm)
            have sameSignature : otherSignature = signed := Subtype.ext (otherBytes.trans exactSignature.symm)
            have same : otherPoint = point := by simpa only [decoded, Option.some.injEq, eq_comm] using samePoint
            simpa only [sameKey, sameSignature, same] using And.intro notWeak (And.intro allowed verifies)
          · rintro ⟨notWeak, allowed, verifies⟩
            exact ⟨raw, signed, exactKey, exactSignature, canonical, notWeak, allowed, point, decoded, verifies⟩
        rw [relation]
        by_cases weak : WeakContract.WeakCoordinate (Encoding.Encoded.ordinate raw) <;>
          by_cases allowed : RContract.Allowed signed <;> cases verified : equation point message signature <;>
          simp [edVerify, encoded, decoded, sized, weak, allowed, exactSignature, verified,
            Except.bind, Bind.bind, Except.instMonad]

theorem p256_accepts_iff {K S : Type} (decode : List Std.U8 → Option K) (parse : List Std.U8 → Option S)
    (equation : K → List Std.U8 → S → Bool) (key message signature : List Std.U8) :
    p256Verify decode parse equation key message signature = .ok () ↔
      P256Accepts decode parse equation key message signature := by
  cases decoded : p256Key decode key with
  | error reason =>
    have refused : ¬ P256Accepts decode parse equation key message signature := by
      rintro ⟨form, _, _, point, parsed, pointBytes, _⟩
      have accepted := (p256_key_accepts_iff decode key point).mpr ⟨form, pointBytes⟩
      rw [decoded] at accepted
      contradiction
    simp [p256Verify, decoded, refused, Except.bind, Bind.bind, Except.instMonad]
  | ok point =>
    obtain ⟨form, exactKey⟩ := (p256_key_accepts_iff decode key point).mp decoded
    cases sized : fixedSignature signature with
    | none =>
      have wrong : signature.length ≠ 64 := by
        intro exactLength
        unfold fixedSignature fixed at sized
        simp only [show signature.length = (64#usize).val from by simpa using exactLength, _root_.dite_true] at sized
        contradiction
      simp [p256Verify, decoded, sized, P256Accepts, wrong, Except.bind, Bind.bind, Except.instMonad]
    | some signed =>
      have exactSignature : signed.val = signature := fixed_value 64#usize signature signed sized
      have length : signature.length = 64 := by
        rw [← exactSignature]
        have size := signed.property
        scalar_tac
      cases parsed : parse signature with
      | none => simp [p256Verify, decoded, sized, P256Accepts, form, exactKey, exactSignature, parsed,
          Except.bind, Bind.bind, Except.instMonad]
      | some scalar =>
        by_cases low : ByteLex.value (signature.drop 32) ≤ LowContract.order / 2 <;>
          cases verified : equation point message scalar <;>
          simp [p256Verify, decoded, sized, P256Accepts, form, exactKey, exactSignature, parsed,
            length, low, verified, Except.bind, Bind.bind, Except.instMonad]

end Auths.Crypto.Strict.Acceptance
