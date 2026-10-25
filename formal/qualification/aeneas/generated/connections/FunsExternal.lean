-- Reuse the reviewed exact String ordering/UTF-8 models; all Auths bodies remain translated.
import qualification.aeneas.generated.connections.Types
import qualification.aeneas.generated.model.FunsExternal
open Aeneas Aeneas.Std Result
namespace auths_connections
@[trait_default]
def core.cmp.PartialOrd.lt.default {Self Rhs : Type}
    (implementation : Aeneas.Std.core.cmp.PartialOrd Self Rhs)
    (left : Self) (right : Rhs) : Result Bool :=
  Aeneas.Std.core.cmp.PartialOrd.lt.default implementation.partial_cmp left right
abbrev alloc.string.String.Insts.CoreCmpPartialEqString.eq :=
  _root_.alloc.string.String.Insts.CoreCmpPartialEqString.eq
abbrev alloc.string.String.Insts.CoreCmpPartialOrdString.partial_cmp :=
  _root_.alloc.string.String.Insts.CoreCmpPartialOrdString.partial_cmp
abbrev alloc.string.String.Insts.CoreCmpEq.assert_fields_are_eq :=
  _root_.alloc.string.String.Insts.CoreCmpEq.assert_fields_are_eq
abbrev alloc.string.String.Insts.CoreCmpOrd.cmp :=
  _root_.alloc.string.String.Insts.CoreCmpOrd.cmp
abbrev alloc.string.String.as_bytes := _root_.alloc.string.String.as_bytes
end auths_connections
