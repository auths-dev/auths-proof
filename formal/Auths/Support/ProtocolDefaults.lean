import Auths.Support.ProtocolVec

open Aeneas Aeneas.Std Result
namespace AuthsProtocolCodec

-- The backend passes a trait dictionary at these default-method interfaces;
-- the official library's equivalent operations take its projected method.
-- These are transparent interface adapters, not new comparison assumptions.
@[trait_default] def core.cmp.PartialOrd.lt.default {Self Rhs : Type}
    (order : Aeneas.Std.core.cmp.PartialOrd Self Rhs) (left : Self) (right : Rhs) : Result Bool :=
  Aeneas.Std.core.cmp.PartialOrd.lt.default order.partial_cmp left right
@[trait_default] def core.cmp.PartialOrd.le.default {Self Rhs : Type}
    (order : Aeneas.Std.core.cmp.PartialOrd Self Rhs) (left : Self) (right : Rhs) : Result Bool :=
  Aeneas.Std.core.cmp.PartialOrd.le.default order.partial_cmp left right
@[trait_default] def core.cmp.PartialOrd.gt.default {Self Rhs : Type}
    (order : Aeneas.Std.core.cmp.PartialOrd Self Rhs) (left : Self) (right : Rhs) : Result Bool :=
  Aeneas.Std.core.cmp.PartialOrd.gt.default order.partial_cmp left right
@[trait_default] def core.cmp.PartialOrd.ge.default {Self Rhs : Type}
    (order : Aeneas.Std.core.cmp.PartialOrd Self Rhs) (left : Self) (right : Rhs) : Result Bool :=
  Aeneas.Std.core.cmp.PartialOrd.ge.default order.partial_cmp left right

@[trait_default] def core.cmp.Ord.max.default {T : Type}
    (order : Aeneas.Std.core.cmp.Ord T) (left right : T) : Result T :=
  Aeneas.Std.core.cmp.Ord.max.default order.partialOrdInst.lt left right
@[trait_default] def core.cmp.Ord.min.default {T : Type}
    (order : Aeneas.Std.core.cmp.Ord T) (left right : T) : Result T :=
  Aeneas.Std.core.cmp.Ord.min.default order.partialOrdInst.lt left right

theorem max_delegates {T : Type} (order : Aeneas.Std.core.cmp.Ord T) (left right : T) :
    core.cmp.Ord.max.default order left right =
      Aeneas.Std.core.cmp.Ord.max.default order.partialOrdInst.lt left right := rfl
theorem min_delegates {T : Type} (order : Aeneas.Std.core.cmp.Ord T) (left right : T) :
    core.cmp.Ord.min.default order left right =
      Aeneas.Std.core.cmp.Ord.min.default order.partialOrdInst.lt left right := rfl
end AuthsProtocolCodec
