import Auths.Support.NativeRecipeTypes

/-!
Complete observable URL components for the pinned foreign `url` interface.
No safe-origin/admission bit is stored. The original input is attached by the
parse wrapper, and getters project this same immutable parsed value. IP hosts
remain distinct from domains. Their octets are retained even though the Auths
origin validator refuses both IP constructors.
-/
open Aeneas Aeneas.Std

namespace AuthsNativeRecipe.core.net.ip_addr
structure Ipv4Addr where
  octets : Array Std.U8 4#usize

structure Ipv6Addr where
  octets : Array Std.U8 16#usize
end AuthsNativeRecipe.core.net.ip_addr

namespace AuthsNativeRecipe.NativeModel

def rawByteArray (bytes : Str) : ByteArray :=
  (bytes.val.map (fun byte => UInt8.ofNat byte.val)).toByteArray

/-- Foreign Rust `str` projections are valid UTF-8 byte slices. This is a
representation invariant, not an Auths host, path or header validity rule. -/
abbrev Utf8Str := { bytes : Str // (_root_.String.fromUTF8? (rawByteArray bytes)).isSome = true }

inductive ParsedHost where
  | domain (text : Utf8Str)
  | ipv4 (address : core.net.ip_addr.Ipv4Addr)
  | ipv6 (address : core.net.ip_addr.Ipv6Addr)

structure UrlProjection where
  scheme : Utf8Str
  username : Utf8Str
  password : Option Utf8Str
  host : Option ParsedHost
  port : Option Std.U16
  path : Utf8Str
  query : Option Utf8Str
  fragment : Option Utf8Str

end AuthsNativeRecipe.NativeModel

namespace AuthsNativeRecipe.url
structure Url where
  original : Str
  projection : NativeModel.UrlProjection
end AuthsNativeRecipe.url
