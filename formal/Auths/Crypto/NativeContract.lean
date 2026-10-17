import Auths.Crypto.Strict.Examples

open Aeneas Aeneas.Std Result
open auths_signature_core

namespace Auths.Crypto.Native

def decoded {K E : Type} : core.result.Result K E → Option K
  | .Ok key => some key
  | .Err _ => none

def authenticated {E : Type} : core.result.Result Unit E → Bool
  | .Ok _ => true
  | .Err _ => false

/-- Contracts for foreign calls only. Auths' key/R forms, widths and weak-point
guards are proved source decisions, outside these premises. -/
structure Ed25519Contract [P : Ed25519Primitives]
    (decode : List Std.U8 → Option P.Key)
    (signatureValue : List Std.U8 → P.Signature)
    (equation : P.Key → List Std.U8 → List Std.U8 → Bool) : Prop where
  decode_exact : ∀ bytes, ∃ output,
    P.decode bytes = ok output ∧ decoded output = decode bytes.val
  signature_exact : ∀ bytes, P.signatureFromBytes bytes = ok (signatureValue bytes.val)
  equation_exact : ∀ (key : P.Key) (message : Slice Std.U8) (bytes : Array Std.U8 64#usize), ∃ output,
    P.verifyStrict key message (signatureValue bytes.val) = ok output ∧
      authenticated output = equation key message.val bytes.val

theorem decode_leaf_refines [P : Ed25519Primitives]
    (decode : List Std.U8 → Option P.Key)
    (signatureValue : List Std.U8 → P.Signature)
    (equation : P.Key → List Std.U8 → List Std.U8 → Bool)
    (contract : Ed25519Contract decode signatureValue equation)
    (bytes : Array Std.U8 32#usize) :
    decode_ed25519_point bytes = ok (decode bytes.val) := by
  obtain ⟨output, exactCall, exactValue⟩ := contract.decode_exact bytes
  simp only [decode_ed25519_point, ed25519_dalek.verifying.VerifyingKey.from_bytes, exactCall,
    bind_tc_ok, core.result.Result.ok]
  exact congrArg Result.ok exactValue

theorem equation_leaf_refines [P : Ed25519Primitives]
    (decode : List Std.U8 → Option P.Key)
    (signatureValue : List Std.U8 → P.Signature)
    (equation : P.Key → List Std.U8 → List Std.U8 → Bool)
    (contract : Ed25519Contract decode signatureValue equation)
    (key : P.Key) (message : Slice Std.U8) (bytes : Array Std.U8 64#usize) :
    verify_ed25519_equation key message bytes = ok (equation key message.val bytes.val) := by
  obtain ⟨output, exactCall, exactValue⟩ := contract.equation_exact key message bytes
  simp only [verify_ed25519_equation, ed25519.Signature.from_bytes, contract.signature_exact,
    bind_tc_ok, ed25519_dalek.verifying.VerifyingKey.verify_strict, exactCall]
  cases output <;> simp_all [authenticated, core.result.Result.is_ok]

theorem public_verify_accepts_iff [P : Ed25519Primitives]
    (decode : List Std.U8 → Option P.Key)
    (signatureValue : List Std.U8 → P.Signature)
    (equation : P.Key → List Std.U8 → List Std.U8 → Bool)
    (contract : Ed25519Contract decode signatureValue equation)
    (bytes message signature : Slice Std.U8) :
    verify_ed25519 bytes message signature = ok (.Ok ()) ↔
      Strict.Acceptance.EdAccepts decode equation bytes.val message.val signature.val := by
  have decodeCall : ∀ array,
      verify_ed25519.closure.Insts.CoreOpsFunctionFnOnceTupleSharedArrayU832OptionVerifyingKey.call_once () array =
      ok (decode array.val) := by
    intro array
    exact decode_leaf_refines decode signatureValue equation contract array
  have verifyCall : ∀ key message signature,
      verify_ed25519.closure_1.Insts.CoreOpsFunctionFnOnceTupleSharedVerifyingKeySharedSliceU8SharedArrayU864Bool.call_once
        () (key, message, signature) = ok (equation key message.val signature.val) := by
    intro key message signature
    exact equation_leaf_refines decode signatureValue equation contract key message signature
  exact Strict.SourceAcceptance.ed_source_accepts_iff
    verify_ed25519.closure.Insts.CoreOpsFunctionFnOnceTupleSharedArrayU832OptionVerifyingKey
    verify_ed25519.closure_1.Insts.CoreOpsFunctionFnOnceTupleSharedVerifyingKeySharedSliceU8SharedArrayU864Bool
    () () decode equation decodeCall verifyCall bytes message signature

theorem public_verify_refines [P : Ed25519Primitives]
    (decode : List Std.U8 → Option P.Key)
    (signatureValue : List Std.U8 → P.Signature)
    (equation : P.Key → List Std.U8 → List Std.U8 → Bool)
    (contract : Ed25519Contract decode signatureValue equation)
    (bytes message signature : Slice Std.U8) :
    verify_ed25519 bytes message signature =
      ok (Strict.SuiteModel.sourceEd (Strict.SuiteModel.edVerify decode equation
        bytes.val message.val signature.val)) := by
  exact Strict.SuiteRefinement.verify_ed25519_refines
    verify_ed25519.closure.Insts.CoreOpsFunctionFnOnceTupleSharedArrayU832OptionVerifyingKey
    verify_ed25519.closure_1.Insts.CoreOpsFunctionFnOnceTupleSharedVerifyingKeySharedSliceU8SharedArrayU864Bool
    () () decode equation
    (decode_leaf_refines decode signatureValue equation contract)
    (equation_leaf_refines decode signatureValue equation contract)
    bytes message signature

theorem public_validate_refines [P : Ed25519Primitives]
    (decode : List Std.U8 → Option P.Key)
    (signatureValue : List Std.U8 → P.Signature)
    (equation : P.Key → List Std.U8 → List Std.U8 → Bool)
    (contract : Ed25519Contract decode signatureValue equation)
    (bytes : Slice Std.U8) :
    validate_ed25519_key bytes =
      ok (Strict.SuiteModel.sourceEd ((Strict.SuiteModel.edKey decode bytes.val).map (fun _ => ()))) := by
  have decodeCall : ∀ array,
      decode_ed25519_key.closure.Insts.CoreOpsFunctionFnOnceTupleSharedArrayU832OptionVerifyingKey.call_once
        () array = ok (decode array.val) := by
    intro array
    exact decode_leaf_refines decode signatureValue equation contract array
  have keyExact := Strict.SuiteRefinement.decode_ed25519_refines
    decode_ed25519_key.closure.Insts.CoreOpsFunctionFnOnceTupleSharedArrayU832OptionVerifyingKey
    () decode decodeCall bytes
  change (do let key ← decode_ed25519_key bytes
             core.result.Result.map
               validate_ed25519_key.closure.Insts.CoreOpsFunctionFnOnceTupleVerifyingKeyTuple key ()) = _
  change decode_ed25519_key bytes = _ at keyExact
  rw [keyExact]
  cases keyResult : Strict.SuiteModel.edKey decode bytes.val <;>
    simp [Strict.SuiteModel.sourceEd, Except.map, core.result.Result.map,
      validate_ed25519_key.closure.Insts.CoreOpsFunctionFnOnceTupleVerifyingKeyTuple,
      validate_ed25519_key.closure.Insts.CoreOpsFunctionFnOnceTupleVerifyingKeyTuple.call_once]

end Auths.Crypto.Native
