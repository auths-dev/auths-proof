import Auths.Product.Refinement.CollectionFence

open Aeneas Aeneas.Std Result
open auths_stores

namespace qualification.aeneas.cases

example : gateway_fence.gateway_window_open 100#u64 none = ok true := rfl

example : gateway_fence.gateway_window_open 100#u64 (some 100#u64) = ok false := rfl

example : gateway_fence.gateway_window_open 101#u64 (some 100#u64) = ok true := rfl

example : gateway_fence.advance_gateway_collection (some 100#u64) 1#u64 = ok 100#u64 := rfl

end qualification.aeneas.cases
