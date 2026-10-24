(* Universal dictionary source-family regressions. Run at final validation. *)
open Charon.Types

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let empty = Charon.TypesUtils.empty_generic_args
let free id = RVar (Free (RegionId.of_int id))
let parameter : region_param = {
  index = RegionId.of_int 0; name = Some "'de"; variance = Invariant; mutability = LtShared }
let parameters = { Charon.TypesUtils.empty_generic_params with regions = [parameter] }
let predicate region : trait_decl_ref = {
  id = TraitDeclId.of_int 8; generics = { empty with regions = [region] } }
let universal = { binder_regions = [parameter];
  binder_value = predicate (RVar (Bound (0, parameter.index))) }

let () =
  let representative = { empty with regions = [free 17] } in
  let family = Quantified_dictionary.recover parameters (predicate (free 0)) representative universal in
  require "a universal family must retain its original known representative arguments"
    (family.representative_arguments = representative);
  require "the entire source universal binder must replay"
    (Quantified_dictionary.replay parameters (predicate (free 0)) family);
  let concrete = { binder_regions = []; binder_value = predicate (free 3) } in
  let instance = Quantified_dictionary.instantiate parameters (predicate (free 0)) family concrete in
  require "a universal source family may instantiate its lifetime at the actual call"
    (instance.reconstructed_arguments.regions = [free 3] && instance.reconstructed_predicate = concrete.binder_value);
  require "a changed universal trait identity must not replay"
    (not (Quantified_dictionary.replay parameters (predicate (free 0))
      { family with expected = { universal with binder_value =
        { universal.binder_value with id = TraitDeclId.of_int 9 } } }));
  require "a corrupted opened universal predicate must not replay"
    (not (Quantified_dictionary.replay parameters (predicate (free 0))
      { family with opened = predicate (free 400) }));
  require "a source implementation restricted to static cannot establish for-all"
    (refuses (fun () -> ignore (Quantified_dictionary.recover
      Charon.TypesUtils.empty_generic_params (predicate RStatic) empty universal)));
  let constrained = { parameters with regions_outlive = [
    { binder_regions = []; binder_value = free 0, RStatic }] } in
  require "a conditional implementation cannot masquerade as an unconditional universal family"
    (refuses (fun () -> ignore (Quantified_dictionary.recover constrained
      (predicate (free 0)) representative universal)));
  require "universal-to-universal instantiation requires explicit binder composition"
    (refuses (fun () -> ignore (Quantified_dictionary.instantiate parameters
      (predicate (free 0)) family universal)));
  let typed_parameters = { parameters with types = [{ index = TypeVarId.of_int 0;
    name = "T"; variance = Invariant }] } in
  let fixed_type = TRef (free 31, TLiteral Charon.Values.TBool, RShared) in
  let template = { (predicate (free 0)) with generics = {
    (predicate (free 0)).generics with types = [TVar (Free (TypeVarId.of_int 0))] } } in
  let changing_self = { universal with binder_value = {
    universal.binder_value with generics = { universal.binder_value.generics with types = [
      TRef (RVar (Bound (0, parameter.index)), TLiteral Charon.Values.TBool, RShared)] } } } in
  require "a fixed borrowed Self argument must not be generalized with the implementation lifetime"
    (refuses (fun () -> ignore (Quantified_dictionary.recover typed_parameters template
      { representative with types = [fixed_type] } changing_self)))

let () =
  let with_unused = { parameters with regions = [
    { parameter with index = RegionId.of_int 1 }; parameter] } in
  let representative = { empty with regions = [free 41; free 17] } in
  let family = Quantified_dictionary.recover with_unused (predicate (free 0)) representative universal in
  require "an unused implementation lifetime must retain its exact known representative"
    (List.hd family.family.reconstructed_arguments.regions = free 41);
  let concrete = { binder_regions = []; binder_value = predicate (free 3) } in
  let instance = Quantified_dictionary.instantiate with_unused (predicate (free 0)) family concrete in
  require "universal instantiation must not vary an unused fixed implementation argument"
    (instance.reconstructed_arguments.regions = [free 41; free 3]);
  require "a missing unused source argument must still be refused"
    (refuses (fun () -> ignore (Quantified_dictionary.recover with_unused (predicate (free 0))
      { representative with regions = [RErased; free 17] } universal)))

let () =
  let condition ty : trait_decl_ref region_binder = { binder_regions = [];
    binder_value = { id = TraitDeclId.of_int 60; generics = { empty with types = [ty] } } } in
  let variable = TVar (Free (TypeVarId.of_int 0)) in
  let clause : trait_param = { clause_id = TraitClauseId.of_int 7; span = None;
    origin = WhereClauseOnFn; trait = condition variable } in
  let constrained = { parameters with types = [{ index = TypeVarId.of_int 0;
    name = "F"; variance = Invariant }]; trait_clauses = [clause] } in
  let bool_type = TLiteral Charon.Values.TBool in
  let evidence : trait_ref = { kind = TraitImpl { id = TraitImplId.of_int 90; generics = empty };
    trait_decl_ref = condition bool_type } in
  let representative = { empty with regions = [free 17]; types = [bool_type]; trait_refs = [evidence] } in
  let template = { (predicate (free 0)) with generics = {
    (predicate (free 0)).generics with types = [variable] } } in
  let expected = { universal with binder_value = { universal.binder_value with generics = {
    universal.binder_value.generics with types = [bool_type] } } } in
  let family = Quantified_dictionary.recover constrained template representative expected in
  require "an invariant concrete source prerequisite must remain an explicit family premise"
    (match family.invariant_prerequisites with
     | [(declared, actual)] -> declared.trait = evidence.trait_decl_ref && actual = evidence
     | _ -> false);
  require "the full conditional-family structure must replay"
    (Quantified_dictionary.replay constrained template family);
  require "unknown evidence cannot stand in for a concrete source prerequisite"
    (refuses (fun () -> ignore (Quantified_dictionary.recover constrained template
      { representative with trait_refs = [{ evidence with kind = Unknown "fixture" }] } expected)));
  let varying = { clause with trait = { clause.trait with binder_value = {
    clause.trait.binder_value with generics = {
      clause.trait.binder_value.generics with regions = [free 0] } } } } in
  require "a condition depending on the varying lifetime needs a separate universal proof"
    (refuses (fun () -> ignore (Quantified_dictionary.recover
      { constrained with trait_clauses = [varying] } template representative expected)));
  let two = { parameters with regions = [parameter; { parameter with index = RegionId.of_int 1 }] } in
  let predicate left right = { (predicate left) with generics = { empty with regions = [left; right] } } in
  let fixed_expected = { universal with binder_value = predicate (RVar (Bound (0, parameter.index))) (free 8) } in
  let fixed_family = Quantified_dictionary.recover two (predicate (free 0) (free 1))
    { empty with regions = [free 17; free 9] } fixed_expected in
  require "a universal family must retain disagreement in a known fixed argument"
    (fixed_family.fixed_actual <> fixed_family.expected);
  require "strict instantiation must not change a known fixed argument to fit the caller"
    (refuses (fun () -> ignore (Quantified_dictionary.instantiate two (predicate (free 0) (free 1))
      fixed_family { binder_regions = []; binder_value = predicate (free 3) (free 8) })));
  require "a fabricated fixed-argument match must fail replay"
    (not (Quantified_dictionary.replay two (predicate (free 0) (free 1))
      { fixed_family with fixed_actual = fixed_family.expected }))
