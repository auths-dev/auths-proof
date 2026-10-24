import qualification.aeneas.generated.codec.TypesExternal
import Auths.Support.ProtocolVec

/-!
Foreign carriers for the actual shipping native-compiler extraction. These
definitions contain no Auths validation or request-construction algorithm.
Map/iterator contents preserve complete original pairs. Native construction
and parsing must supply lawful map ordering and the declared input bounds.
The positive vector is the existing proved isomorphism to the standard model.
-/
open Aeneas Aeneas.Std

namespace AuthsNativeRecipe.alloc.vec
abbrev Vec := AuthsProtocolCodec.alloc.vec.Vec
abbrev Vec.val := @AuthsProtocolCodec.alloc.vec.Vec.val
abbrev Vec.property := @AuthsProtocolCodec.alloc.vec.Vec.property
abbrev Vec.toBase := @AuthsProtocolCodec.alloc.vec.Vec.toBase
abbrev Vec.ofBase := @AuthsProtocolCodec.alloc.vec.Vec.ofBase
abbrev Vec.deref := @AuthsProtocolCodec.alloc.vec.Vec.deref
abbrev Vec.new := AuthsProtocolCodec.alloc.vec.Vec.new
abbrev Vec.len := @AuthsProtocolCodec.alloc.vec.Vec.len
abbrev Vec.push := @AuthsProtocolCodec.alloc.vec.Vec.push
abbrev CloneVec.clone := @AuthsProtocolCodec.alloc.vec.CloneVec.clone
end AuthsNativeRecipe.alloc.vec

namespace AuthsNativeRecipe

namespace alloc.collections.btree.map
structure BTreeMap (K V A : Type) where
  entries : alloc.vec.Vec (K × V)

/-- Remaining immutable pairs of a borrowing iterator, in their original order.
The monomorphic JSON iterator is defined after the generated JSON Value type;
it is this same carrier specialized to String and that exact Value type. -/
abbrev Iter (K V : Type) := alloc.vec.Vec (K × V)
end alloc.collections.btree.map

namespace alloc.collections.btree.set
/-- Original ordered elements. Native construction/default/insert establish
the sorted, duplicate-free representation; membership does not invent it. -/
structure BTreeSet (T A : Type) where
  elements : alloc.vec.Vec T
end alloc.collections.btree.set

namespace serde_json.map
/-- The actual extracted dependency graph enables preserve_order. JSON object
iteration therefore retains insertion order; it must not inherit the native
rule map's sorted-key invariant merely because the payload shape is similar. -/
structure Map (K V : Type) where
  entries : alloc.vec.Vec (K × V)
end serde_json.map

namespace serde_json.number
/-- The pinned serde_json Number's three represented cases. A Float's bits
are deliberately uninterpreted: both integer projections refuse that case.
Finite-float and negative-NegInt representation validity belongs to the
explicit foreign JSON construction/parser contract, not Auths validation. -/
inductive Number where
  | PosInt (value : Std.U64)
  | NegInt (value : Std.I64)
  | Float (bits : Std.U64)
end serde_json.number

namespace alloc.string
/-- Original bytes and the shared standard UTF-8 error projection. The native
adapter observes only success/failure; it never reads UTF-8 error positions. -/
structure FromUtf8Error where
  bytes : alloc.vec.Vec Std.U8
  error : core.str.error.Utf8Error
end alloc.string

abbrev core.clone.CloneallocvecVec := @AuthsProtocolCodec.core.clone.CloneallocvecVec

namespace alloc.slice
def Slice.to_vec {T : Type} (clone : core.clone.Clone T) (input : Slice T) :
    Result (alloc.vec.Vec T) := do
  let copied ← Aeneas.Std.alloc.slice.Slice.to_vec clone input
  ok (alloc.vec.Vec.ofBase copied)
end alloc.slice

end AuthsNativeRecipe
