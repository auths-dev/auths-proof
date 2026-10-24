(* Authored positive-source reconstruction regressions; final validation only. *)
open Charon.Types
open Charon.Values

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let empty = Charon.TypesUtils.empty_generic_args
let free id = RVar (Free (RegionId.of_int id))
let owner regions types = TAdt { id = TAdtId (TypeDeclId.of_int 17);
  generics = { empty with regions; types } }
let parameters : generic_params = { Charon.TypesUtils.empty_generic_params with
  regions = [{ index = RegionId.of_int 0; name = None; variance = Invariant; mutability = LtShared }] }

let () =
  let arguments = { empty with regions = [RErased] } in
  let template = owner [free 0] [] in
  let source = owner [free 7] [] in
  let witness = Impl_regions.recover parameters template arguments source in
  require "a missing lifetime must come from the actual declared associated value"
    (witness.reconstructed_arguments.regions = [free 7] && witness.reconstructed_self = source);
  require "the independent replay must retain the complete original witness"
    (Impl_regions.replay parameters template witness);
  require "a modified reconstructed argument must not replay"
    (not (Impl_regions.replay parameters template { witness with reconstructed_arguments =
      { witness.reconstructed_arguments with regions = [free 8] } }));
  require "extra inferred arguments must not replay"
    (not (Impl_regions.replay parameters template { witness with inferred =
      (RegionId.of_int 10, free 7) :: witness.inferred }));
  let known = { arguments with regions = [free 2] } in
  require "known implementation arguments must never be changed to fit another value"
    (refuses (fun () -> ignore (Impl_regions.recover parameters template known source)));
  require "a missing region absent from Self must remain unresolved"
    (refuses (fun () -> ignore (Impl_regions.recover parameters (owner [] []) arguments (owner [] []))));
  let unjustified : Impl_regions.witness = {
    original_arguments = arguments; reconstructed_arguments = { arguments with regions = [free 7] };
    source_self = owner [] []; reconstructed_self = owner [] [];
    inferred = [RegionId.of_int 0, free 7] } in
  require "replay must reject a fabricated witness for an unused lifetime"
    (not (Impl_regions.replay parameters (owner [] []) unjustified));
  require "erased declared values cannot justify reconstruction"
    (refuses (fun () -> ignore (Impl_regions.recover parameters template arguments (owner [RErased] []))));
  require "static provenance must not be guessed"
    (refuses (fun () -> ignore (Impl_regions.recover parameters template arguments (owner [RStatic] []))));
  require "quantified lifetimes must not escape"
    (refuses (fun () -> ignore (Impl_regions.recover parameters template arguments
      (owner [RVar (Bound (0, RegionId.of_int 0))] [])))));
  require "repeated source occurrences must agree"
    (refuses (fun () -> ignore (Impl_regions.recover parameters (owner [free 0; free 0] []) arguments
      (owner [free 7; free 8] [])))));
  let with_type : generic_params = { parameters with types = [{
    index = TypeVarId.of_int 0; name = "T"; variance = Invariant }] } in
  let unrelated = TRef (free 0, TLiteral TBool, RShared) in
  let typed_arguments = { arguments with types = [unrelated] } in
  let typed = Impl_regions.recover with_type (owner [free 0] [TVar (Free (TypeVarId.of_int 0))])
    typed_arguments (owner [free 7] [unrelated]) in
  require "provided type-argument lifetimes must not collide with matching metavariables"
    (typed.reconstructed_arguments.types = [unrelated] && typed.reconstructed_arguments.regions = [free 7]);
  let predicate region : trait_decl_ref = { id = TraitDeclId.of_int 41;
    generics = { empty with regions = [region]; types = [owner [] []] } } in
  let complete = Impl_regions.recover_predicate parameters (predicate (free 0)) arguments (predicate (free 7)) in
  require "a trait lifetime outside Self must come from the complete declared bound"
    (complete.reconstructed_arguments.regions = [free 7] &&
      Impl_regions.replay_predicate parameters (predicate (free 0)) complete);
  require "reconstruction must preserve the trait identity" (refuses (fun () ->
    ignore (Impl_regions.recover_predicate parameters (predicate (free 0)) arguments
      { (predicate (free 7)) with id = TraitDeclId.of_int 42 })));
  let corrupted = { complete with reconstructed_predicate = predicate (free 8) } in
  require "a corrupted whole-predicate witness must not replay"
    (not (Impl_regions.replay_predicate parameters (predicate (free 0)) corrupted));
  require "known trait lifetime arguments must stay rigid" (refuses (fun () ->
    ignore (Impl_regions.recover_predicate parameters (predicate (free 0))
      { arguments with regions = [free 8] } (predicate (free 7)))))
