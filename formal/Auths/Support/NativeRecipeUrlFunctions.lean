import qualification.aeneas.generated.native_recipe.Types
import Auths.Support.NativeRecipeUrlTypes

/-!
Explicit foreign URL parsing; all other selected methods are ordinary getters.
The primitive supplies complete parsed components and typed parse failures,
never an Auths-approved origin or validation result. A published origin claim
must retain the pinned URL parser/normalization/totality contract relating this
projection to the original input. This module does not prove WHATWG parsing,
DNS, TLS, proxy, redirect or transport behavior. No global instance is supplied.
-/
open Aeneas Aeneas.Std Result

namespace Auths.Product.NativeCompiler

class UrlPrimitives where
  parse : Str → Except AuthsNativeRecipe.url.parser.ParseError AuthsNativeRecipe.NativeModel.UrlProjection

end Auths.Product.NativeCompiler

namespace AuthsNativeRecipe

def NativeModel.parsedHost (host : NativeModel.ParsedHost) : url.host.Host Str :=
  match host with
  | .domain text => .Domain text.val
  | .ipv4 address => .Ipv4 address
  | .ipv6 address => .Ipv6 address

def url.Url.parse [primitive : Auths.Product.NativeCompiler.UrlPrimitives] (original : Str) :
    Result (core.result.Result url.Url url.parser.ParseError) :=
  ok (match primitive.parse original with
    | .error reason => .Err reason
    | .ok projection => .Ok ⟨original, projection⟩)

def url.Url.scheme (input : url.Url) : Result Str := ok input.projection.scheme.val
def url.Url.username (input : url.Url) : Result Str := ok input.projection.username.val
def url.Url.password (input : url.Url) : Result (Option Str) := ok (input.projection.password.map Subtype.val)
def url.Url.host (input : url.Url) : Result (Option (url.host.Host Str)) :=
  ok (input.projection.host.map NativeModel.parsedHost)
def url.Url.port (input : url.Url) : Result (Option Std.U16) := ok input.projection.port
def url.Url.path (input : url.Url) : Result Str := ok input.projection.path.val
def url.Url.query (input : url.Url) : Result (Option Str) := ok (input.projection.query.map Subtype.val)
def url.Url.fragment (input : url.Url) : Result (Option Str) := ok (input.projection.fragment.map Subtype.val)

end AuthsNativeRecipe
