-- REVIEWED: bounded ordered-set and consuming-iterator carriers.
-- Only Global allocation and the translated fixed-width ProofRef order are used.
import Aeneas
import Auths.Support.Discriminant
import Auths.Support.PositiveVec
open Aeneas Aeneas.Std
namespace alloc.collections.btree.set
structure BTreeSet (T A : Type) where
  values : List T
  bound : values.length ≤ Usize.max
structure IntoIter (T A : Type) where
  values : List T
  bound : values.length ≤ Usize.max
end alloc.collections.btree.set
