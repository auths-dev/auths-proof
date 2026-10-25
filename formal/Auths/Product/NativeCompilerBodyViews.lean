import Auths.Product.NativeCompilerConstruction
import Auths.Product.BodyCompilerResources
import Auths.Product.RequestCompiler

open Aeneas Aeneas.Std

namespace Auths.Product.NativeCompiler

abbrev NativeNamedJson := AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedJsonPiece
abbrev NativeNamedForm := AuthsNativeRecipe.auths_gateway_kernel.body_compiler.NamedFormPiece
abbrev NativeJsonPiece := AuthsNativeRecipe.auths_gateway_kernel.construct.JsonPiece
abbrev NativeFormPiece := AuthsNativeRecipe.auths_gateway_kernel.construct.FormPiece
abbrev NativeBodyPlan := AuthsNativeRecipe.auths_gateway_kernel.construct.BodyPlan
abbrev NativeUsage := AuthsNativeRecipe.auths_gateway_kernel.body_compiler.ResourceUse
abbrev NativeNamedBody := AuthsNativeRecipe.auths_gateway_kernel.request_compiler.NamedBody
abbrev NativeNamedTemplate := AuthsNativeRecipe.auths_gateway_kernel.template_ast.NamedTemplate

def nativeNamedJson : NativeNamedJson → BodyCompiler.NamedJson
  | .Raw value => .raw (bytes value)
  | .Field name => .field (bytes name)
  | .Echo => .echo

def nativeNamedForm : NativeNamedForm → BodyCompiler.NamedForm
  | .Raw value => .raw (bytes value)
  | .Field name => .field (bytes name)
  | .Json pieces => .json (pieces.val.map nativeNamedJson)
  | .Echo => .echo

def nativeJsonSource (source : Slice NativeNamedJson) : List BodyCompiler.NamedJson :=
  source.val.map nativeNamedJson
def nativeFormSource (source : Slice NativeNamedForm) : List BodyCompiler.NamedForm :=
  source.val.map nativeNamedForm

def nativeJsonPiece : NativeJsonPiece → RequestConstruction.JsonPiece
  | .Raw value => .raw (bytes value)
  | .Field index => .field index.val
  | .Echo => .echo

def nativeFormPiece : NativeFormPiece → RequestConstruction.FormPiece
  | .Raw value => .raw (bytes value)
  | .Field index => .field index.val
  | .Json pieces => .json (pieces.val.map nativeJsonPiece)
  | .Echo => .echo

def nativeBodyPlan : NativeBodyPlan → RequestConstruction.BodyPlan
  | .Json pieces => .json (pieces.val.map nativeJsonPiece)
  | .Form pieces => .form (pieces.val.map nativeFormPiece)

def nativeUsage (used : NativeUsage) : BodyCompiler.Resources.Usage :=
  ⟨used.literal_bytes.val, used.dynamic_pieces.val⟩

def nativeNamedBody : NativeNamedBody → RequestCompiler.SourceBody
  | .Json pieces => .json (nativeJsonSource pieces)
  | .Form pieces => .form (nativeFormSource pieces)

def nativeNamedTemplate : NativeNamedTemplate → RequestCompiler.SourceBody
  | .Json pieces => .json (pieces.val.map nativeNamedJson)
  | .Form pieces => .form (pieces.val.map nativeNamedForm)

end Auths.Product.NativeCompiler
