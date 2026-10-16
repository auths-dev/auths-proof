-- REVIEWED TRANSPARENT STANDARD MATCHES AND EXPLICIT FOREIGN PROJECTIONS.
import qualification.aeneas.generated.p256.Types
open Aeneas Aeneas.Std Result
namespace AuthsNativeP256
variable [P : Auths.Crypto.P256Primitives]

def SharedSliceU8.Insts.CoreConvertTryIntoArrayU864.try_into (bytes : Slice Std.U8) :
    Result core.qualified_p256_type_decls_9 :=
  if sized : bytes.val.length = 64 then
    ok (.Ok ⟨bytes.val, by scalar_tac⟩)
  else ok (.Err ())

def core.qualified_p256_fun_decls_27 (value : core.qualified_p256_type_decls_16) : Result Bool :=
  ok (match value with | .Ok _ => true | .Err _ => false)

def core.qualified_p256_fun_decls_30 (value : core.qualified_p256_type_decls_17) :
    Result core.qualified_p256_type_decls_13 :=
  ok (match value with | .Ok key => .Some key | .Err _ => .None)

def core.qualified_p256_fun_decls_24 (value : core.qualified_p256_type_decls_14) :
    Result core.qualified_p256_type_decls_12 :=
  ok (match value with | .Ok signature => .Some signature | .Err _ => .None)


def core.qualified_p256_type_decls_3.Insts.CoreOpsTry_traitTry.branch
    (value : core.qualified_p256_type_decls_3) : Result core.qualified_p256_type_decls_6 :=
  ok (match value with | .Ok key => .Continue key | .Err reason => .Break (.Err reason))

def core.qualified_p256_type_decls_0.Insts.CoreOpsTry_traitFromResidualqualified_p256_type_decls_7.from_residual
    (residual : core.qualified_p256_type_decls_7) : Result core.qualified_p256_type_decls_0 :=
  match residual with
  | .Ok impossible => nomatch impossible
  | .Err reason => ok (.Err reason)

def core.qualified_p256_fun_decls_20 (bytes : Slice Std.U8) : Result Std.Usize := ok (Slice.len bytes)

def ecdsa.qualified_p256_fun_decls_23 (bytes : Slice Std.U8) :
    Result core.qualified_p256_type_decls_14 := do
  let value ← P.parse bytes
  ok (match value with | .Ok signature => .Ok signature | .Err reason => .Err reason)

def ecdsa.qualified_p256_fun_decls_29 (bytes : Slice Std.U8) :
    Result core.qualified_p256_type_decls_17 := do
  let value ← P.decode bytes
  ok (match value with | .Ok key => .Ok key | .Err reason => .Err reason)

def ecdsa.qualified_p256_type_decls_4.Insts.SignatureVerifierVerifierqualified_p256_type_decls_11.verify
    (key : ecdsa.qualified_p256_type_decls_4) (message : Slice Std.U8)
    (signature : ecdsa.qualified_p256_type_decls_11) : Result core.qualified_p256_type_decls_16 := do
  let value ← P.verify key message signature
  ok (match value with | .Ok valueUnit => .Ok valueUnit | .Err reason => .Err reason)

end AuthsNativeP256
