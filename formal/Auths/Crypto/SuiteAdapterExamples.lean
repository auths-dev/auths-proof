import Auths.Crypto.SuiteAdapters
import Auths.Crypto.NativeExamples
import Auths.Crypto.P256Examples
import Lean.Elab.Tactic.Cbv
open Aeneas Aeneas.Std Result
open AuthsSuiteAdapters
set_option cbv.warning false
set_option maxRecDepth 4096
set_option maxHeartbeats 2000000
namespace Auths.Crypto.SuiteAdapterExamples

-- Literal private-ID carriers match the constructors' installed identifiers.
-- These witnesses do not claim constructor or registry-selection refinement.
def edSuite : Ed25519Suite := ⟨⟨[101#u8,100#u8,50#u8,53#u8,53#u8,49#u8,57#u8,45#u8,118#u8,49#u8], by scalar_tac⟩⟩
def p256Suite : P256Sha256Suite := ⟨⟨[112#u8,50#u8,53#u8,54#u8,45#u8,115#u8,104#u8,97#u8,50#u8,53#u8,54#u8,45#u8,118#u8,49#u8], by scalar_tac⟩⟩

def edInput : auths_ports.SignatureInput :=
  ⟨NativeExamples.key, NativeExamples.message, NativeExamples.signature⟩
def edChanged : auths_ports.SignatureInput :=
  ⟨NativeExamples.key, NativeExamples.changedMessage, NativeExamples.signature⟩
def p256Input : auths_ports.SignatureInput :=
  ⟨P256Examples.key, P256Examples.message, P256Examples.signature⟩
def p256Changed : auths_ports.SignatureInput :=
  ⟨P256Examples.key, P256Examples.changedMessage, P256Examples.signature⟩

theorem ed_exact_fields_admitted :
    Ed25519Suite.Insts.Auths_portsSignatureSuite.verify
      (edPrimitive := NativeExamples.forwardingPrimitive) edSuite edInput = ok (.Ok ()) := by
  rw [SuiteAdapters.ed_public_refines (P := NativeExamples.forwardingPrimitive)
    (fun _ => some ()) id NativeExamples.equation NativeExamples.forwarding_contract]
  cbv

theorem ed_changed_message_refused :
    Ed25519Suite.Insts.Auths_portsSignatureSuite.verify
      (edPrimitive := NativeExamples.forwardingPrimitive) edSuite edChanged = ok (.Err .InvalidSignature) := by
  rw [SuiteAdapters.ed_public_refines (P := NativeExamples.forwardingPrimitive)
    (fun _ => some ()) id NativeExamples.equation NativeExamples.forwarding_contract]
  cbv

theorem p256_exact_fields_admitted :
    P256Sha256Suite.Insts.Auths_portsSignatureSuite.verify
      (p256Primitive := P256Examples.forwardingPrimitive) p256Suite p256Input = ok (.Ok ()) := by
  rw [SuiteAdapters.p256_public_refines (P := P256Examples.forwardingPrimitive)
    (fun bytes => some bytes) (fun bytes => some bytes) P256Examples.equation P256Examples.forwarding_contract]
  cbv

theorem p256_changed_message_refused :
    P256Sha256Suite.Insts.Auths_portsSignatureSuite.verify
      (p256Primitive := P256Examples.forwardingPrimitive) p256Suite p256Changed = ok (.Err .InvalidSignature) := by
  rw [SuiteAdapters.p256_public_refines (P := P256Examples.forwardingPrimitive)
    (fun bytes => some bytes) (fun bytes => some bytes) P256Examples.equation P256Examples.forwarding_contract]
  cbv

end Auths.Crypto.SuiteAdapterExamples
