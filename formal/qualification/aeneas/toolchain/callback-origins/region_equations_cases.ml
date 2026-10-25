(* Authored source-body region regressions; deferred to final validation. *)
open Charon.Types
open Charon.Values

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let body id = RBody (RegionId.of_int id)
let free id = RVar (Free (RegionId.of_int id))
let bound id = RVar (Bound (0, RegionId.of_int id))
let predicate regions : trait_decl_ref region_binder = {
  binder_regions = [];
  binder_value = { id = TraitDeclId.of_int 0;
    generics = { Charon.TypesUtils.empty_generic_args with regions } } }

let () =
  let state = Region_equations.add_all Region_equations.empty
    [body 4, body 8; body 8, free 2; body 12, body 4] in
  require "every aliased body region must resolve to the same rigid parameter"
    (List.for_all (fun region -> Region_equations.resolve state region = free 2)
      [body 4; body 8; body 12]);
  require "the exact equality certificate must replay" (Region_equations.replay state);
  require "unrelated body regions must stay independent"
    (Region_equations.resolve state (body 99) = body 99);
  require "distinct signature parameters must never be merged" (refuses (fun () ->
    ignore (Region_equations.add state (body 4) (free 3))));
  require "body regions cannot become static through inference" (refuses (fun () ->
    ignore (Region_equations.add Region_equations.empty (body 0) RStatic)));
  require "matching static provenance must remain static"
    (Region_equations.resolve (Region_equations.add Region_equations.empty RStatic RStatic) RStatic = RStatic);
  require "a body variable must not capture a higher-ranked variable" (refuses (fun () ->
    ignore (Region_equations.add Region_equations.empty (body 0) (bound 0))));
  require "even two erased labels do not prove a lifetime equation" (refuses (fun () ->
    ignore (Region_equations.add Region_equations.empty RErased RErased)));
  let corrupted = { state with Region_equations.bindings =
    RegionId.Map.add (RegionId.of_int 4) (free 3) state.bindings } in
  require "a modified solution must not replay" (not (Region_equations.replay corrupted));
  let extra = { state with Region_equations.bindings =
    RegionId.Map.add (RegionId.of_int 100) (free 2) state.bindings } in
  require "unjustified extra region bindings must not replay" (not (Region_equations.replay extra));
  let predicates = Region_equations.add_predicate Region_equations.empty_predicates
    (predicate [body 1; body 1]) (predicate [free 0; free 0]) in
  require "complete original predicates must agree after replay"
    (Region_equations.replay_predicates predicates);
  require "predicate replay must not accept a detached equation certificate"
    (not (Region_equations.replay_predicates { predicates with originals = [] }));
  require "alias conflicts in one predicate must be refused" (refuses (fun () ->
    ignore (Region_equations.add_predicate Region_equations.empty_predicates
      (predicate [body 1; body 1]) (predicate [free 0; free 1]))));
  require "a later call must not contradict an earlier call's region solution" (refuses (fun () ->
    ignore (Region_equations.add_predicate predicates
      (predicate [body 1]) (predicate [free 1]))));
  let other = { (predicate [free 0]) with binder_value = {
    (predicate [free 0]).binder_value with id = TraitDeclId.of_int 1 } } in
  require "trait identity cannot be unified away" (refuses (fun () ->
    ignore (Region_equations.add_predicate Region_equations.empty_predicates
      (predicate [body 1]) other)));
  let quantified = { (predicate [bound 0]) with binder_regions = [
    { index = RegionId.of_int 0; name = None; variance = Invariant; mutability = LtShared }] } in
  require "a universal predicate cannot become a monomorphic one by equality inference"
    (refuses (fun () -> ignore (Region_equations.add_predicate
      Region_equations.empty_predicates (predicate [body 1]) quantified)));
  let reference region kind ty = TRef (region, ty, kind) in
  let typed = Region_equations.add_type Region_equations.empty_predicates
    (reference (body 7) RShared (TLiteral TBool))
    (reference (free 2) RShared (TLiteral TBool)) in
  require "full associated type equalities must replay" (Region_equations.replay_predicates typed);
  require "reference mutability cannot be erased to solve an associated equality" (refuses (fun () ->
    ignore (Region_equations.add_type Region_equations.empty_predicates
      (reference (body 7) RMut (TLiteral TBool))
      (reference (free 2) RShared (TLiteral TBool)))));
  require "pointee types cannot change during lifetime solving" (refuses (fun () ->
    ignore (Region_equations.add_type Region_equations.empty_predicates
      (reference (body 7) RShared (TLiteral (TUInt U8)))
      (reference (free 2) RShared (TLiteral TBool)))))

let () =
  let parameter : region_param = { index = RegionId.of_int 0; name = Some "'a";
    variance = Invariant; mutability = LtShared } in
  let wrap ty = { binder_regions = [parameter]; binder_value = ty } in
  let typed region = TRef (region, TLiteral TBool, RShared) in
  let solved = Region_equations.add_quantified_type Region_equations.empty_predicates
    (wrap (typed (body 7))) (wrap (typed (free 2))) in
  require "an outer body equality can replay under an unchanged universal binder"
    (Region_equations.replay_predicates solved &&
      Region_equations.resolve solved.solution (body 7) = free 2);
  require "a universal local lifetime must not escape into a body variable"
    (refuses (fun () -> ignore (Region_equations.add_quantified_type
      Region_equations.empty_predicates (wrap (typed (body 7))) (wrap (typed (bound 0))))));
  require "different quantified local lifetimes must remain distinct"
    (refuses (fun () -> ignore (Region_equations.add_quantified_type
      Region_equations.empty_predicates (wrap (typed (bound 0))) (wrap (typed (bound 1))))));
  require "the complete universal binder must not be discarded"
    (refuses (fun () -> ignore (Region_equations.add_quantified_type
      Region_equations.empty_predicates (wrap (typed (bound 0)))
      { binder_regions = []; binder_value = typed (bound 0) }))));
  require "a detached quantified equality certificate must not replay"
    (not (Region_equations.replay_predicates { solved with originals = [] }))

let () =
  let arguments first second : generic_args = {
    Charon.TypesUtils.empty_generic_args with regions = [first];
    types = [TRef (second, TLiteral TBool, RShared)];
    trait_refs = [{ kind = Clause (Free (TraitClauseId.of_int 0));
      trait_decl_ref = predicate [first] }] } in
  let source = arguments (body 8) (body 9) in
  let actual = arguments (free 2) (free 3) in
  let solved = Region_equations.add_arguments Region_equations.empty_predicates source actual in
  require "the entire source argument environment, including repeated dictionary labels, must replay"
    (Region_equations.replay_predicates solved &&
     Region_equations.resolve solved.solution (body 8) = free 2 &&
     Region_equations.resolve solved.solution (body 9) = free 3);
  require "changing a nested dictionary identity cannot be explained by lifetime equalities"
    (refuses (fun () -> ignore (Region_equations.add_arguments Region_equations.empty_predicates source
      { actual with trait_refs = [{ (List.hd actual.trait_refs) with kind = Clause (Free (TraitClauseId.of_int 1)) }] }))));
  require "alias conflicts inside captured dictionaries must fail closed"
    (refuses (fun () -> ignore (Region_equations.add_arguments Region_equations.empty_predicates source
      { actual with trait_refs = [{ (List.hd actual.trait_refs) with trait_decl_ref = predicate [free 4] }] }))));
  require "captured non-region argument types cannot change"
    (refuses (fun () -> ignore (Region_equations.add_arguments Region_equations.empty_predicates source
      { actual with types = [TRef (free 3, TLiteral (TUInt U8), RShared)] }))));
  require "argument reconstruction cannot manufacture a static lifetime"
    (refuses (fun () -> ignore (Region_equations.add_arguments Region_equations.empty_predicates source
      (arguments RStatic (free 3)))));
  require "a detached complete argument certificate cannot replay"
    (not (Region_equations.replay_predicates { solved with originals = [] }))
