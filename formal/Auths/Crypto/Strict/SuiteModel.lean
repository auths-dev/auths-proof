import Auths.Crypto.Strict.RContract
import Auths.Crypto.Strict.LowContract
import Auths.Crypto.Encoding.P256
open Aeneas Aeneas.Std Result
namespace Auths.Crypto.Strict.SuiteModel

def fixed (N : Std.Usize) (bytes : List Std.U8) : Option (Array Std.U8 N) :=
  if h : bytes.length = N.val then some ⟨bytes, h⟩ else none

def fixedKey (bytes : List Std.U8) : Option Encoding.Encoded.Input := fixed 32#usize bytes

def fixedSignature (bytes : List Std.U8) : Option RContract.Input := fixed 64#usize bytes

inductive Failure where | key | shape | equation

def keyEncoding (bytes : List Std.U8) : Except Failure Encoding.Encoded.Input :=
  match fixedKey bytes with
  | none => .error .key
  | some encoded => if decide (Encoding.Encoded.Encoding encoded) then .ok encoded else .error .key

def edKey {K : Type} (decode : List Std.U8 → Option K) (bytes : List Std.U8) : Except Failure K := do
  let _ ← keyEncoding bytes
  match decode bytes with | none => .error .key | some key => .ok key

def edVerify {K : Type} (decode : List Std.U8 → Option K)
    (equation : K → List Std.U8 → List Std.U8 → Bool)
    (key message signature : List Std.U8) : Except Failure Unit := do
  let encoded ← keyEncoding key
  let point ← match decode key with | none => .error .key | some point => .ok point
  match fixedSignature signature with
  | none => .error .shape
  | some signature =>
    if decide (WeakContract.WeakCoordinate (Encoding.Encoded.ordinate encoded)) ||
        !decide (RContract.Allowed signature) then .error .equation
    else if equation point message signature.val then .ok () else .error .equation

def p256Key {K : Type} (decode : List Std.U8 → Option K) (bytes : List Std.U8) : Except Failure K :=
  if decide (Encoding.P256.Encoding (bytes.map UScalar.val)) then
    match decode bytes with | none => .error .key | some key => .ok key
  else .error .key

def p256Verify {K S : Type} (decode : List Std.U8 → Option K) (parse : List Std.U8 → Option S)
    (equation : K → List Std.U8 → S → Bool)
    (key message signature : List Std.U8) : Except Failure Unit := do
  let point ← p256Key decode key
  match fixedSignature signature with
  | none => .error .shape
  | some signature =>
    match parse signature.val with
    | none => .error .shape
    | some parsed =>
      if decide (ByteLex.value (signature.val.drop 32) ≤ LowContract.order / 2) &&
          equation point message parsed then .ok () else .error .equation

def sourceEdFailure : Failure → auths_signature_core.Ed25519Error
  | .key => .InvalidKey | .shape => .InvalidSignatureEncoding | .equation => .VerificationFailed

def sourceP256Failure : Failure → auths_signature_core.P256Error
  | .key => .InvalidKey | .shape => .InvalidSignatureEncoding | .equation => .VerificationFailed

def sourceEd {A : Type} : Except Failure A → core.result.Result A auths_signature_core.Ed25519Error
  | .error error => .Err (sourceEdFailure error) | .ok value => .Ok value

def sourceP256 {A : Type} : Except Failure A → core.result.Result A auths_signature_core.P256Error
  | .error error => .Err (sourceP256Failure error) | .ok value => .Ok value

end Auths.Crypto.Strict.SuiteModel
