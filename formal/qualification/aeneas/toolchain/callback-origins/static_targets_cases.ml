(* Authored regressions for specialization metadata. Not part of construction
   builds; execute with the final validation batch. *)
open Charon.Types
open Charon.Values

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let empty = Charon.TypesUtils.empty_generic_args
let region id = RBody (RegionId.of_int id)
let reference id args : trait_ref = {
  kind = TraitImpl { id = TraitImplId.of_int id; generics = args };
  trait_decl_ref = { binder_regions = []; binder_value = {
    id = TraitDeclId.of_int id; generics = args } } }
let clause id (reference : trait_ref) : trait_param = {
  clause_id = TraitClauseId.of_int id; span = None;
  origin = WhereClauseOnFn; trait = reference.trait_decl_ref }

let () =
  Function_frame.require_body_region 2 (region 1);
  Function_frame.require_body_region 0 RStatic;
  require "the exclusive body-region bound must be enforced" (refuses (fun () ->
    Function_frame.require_body_region 2 (region 2)));
  require "a negative body-region scope must be refused" (refuses (fun () ->
    Function_frame.require_body_region (-1) RStatic));
  Static_targets.require_argument_arity Charon.TypesUtils.empty_generic_params empty;
  require "source preconditions must refuse surplus region arguments" (refuses (fun () ->
    Static_targets.require_argument_arity Charon.TypesUtils.empty_generic_params
      { empty with regions = [region 1] }));
  require "source preconditions must refuse missing dictionaries" (refuses (fun () ->
    Static_targets.require_argument_arity { Charon.TypesUtils.empty_generic_params with
      trait_clauses = [clause 8 (reference 0 empty)] } empty));
  Static_targets.require_no_associated_arguments Charon.TypesUtils.empty_generic_params;
  require "generic associated lifetimes must not be discarded" (refuses (fun () ->
    Static_targets.require_no_associated_arguments { Charon.TypesUtils.empty_generic_params with
      regions = [{ index = RegionId.of_int 0; name = None;
        variance = Invariant; mutability = LtShared }] }));
  let requirements = { Charon.TypesUtils.empty_generic_params with
    regions_outlive = [{ binder_regions = []; binder_value = RStatic, RStatic }] } in
  let preserved = Static_targets.unbind_associated_requirements
    Charon.Substitute.empty_subst requirements in
  require "associated predicates without explicit parameters must still be preserved"
    (preserved = requirements);
  let first = reference 0 empty in
  let last = reference 1 empty in
  require "a source Self dictionary must match the complete declared predicate"
    (Static_targets.source_self_evidence first.trait_decl_ref [last; first] = first);
  require "duplicate identical source evidence must not create an arbitrary choice"
    (Static_targets.source_self_evidence first.trait_decl_ref [first; first] = first);
  require "missing source Self evidence must be refused" (refuses (fun () ->
    ignore (Static_targets.source_self_evidence first.trait_decl_ref [last])));
  require "distinct implementations for the same predicate must remain ambiguous"
    (refuses (fun () -> ignore (Static_targets.source_self_evidence first.trait_decl_ref
      [first; { first with kind = last.kind }])));
  let sparse = [clause 3 first; clause 90 last] in
  require "sparse parent IDs must not be treated as list indices"
    (Static_targets.select_parent sparse [first; last] (TraitClauseId.of_int 90) = last);
  require "an absent parent must be refused" (refuses (fun () ->
    ignore (Static_targets.select_parent sparse [first; last] (TraitClauseId.of_int 1))));
  require "incomplete parent evidence must be refused" (refuses (fun () ->
    ignore (Static_targets.select_parent sparse [first] (TraitClauseId.of_int 3))));
  require "duplicate parent IDs must be refused" (refuses (fun () ->
    ignore (Static_targets.select_parent [clause 3 first; clause 3 last]
      [first; last] (TraitClauseId.of_int 3))));
  let shared = { empty with regions = [region 12] } in
  let self = reference 0 shared in
  let factored, args, evidence = Instance_view.factor_context shared (Some self) in
  require "Self and call argument lifetimes must retain their alias"
    (List.length factored.parameters = 1 && args.regions = [RVar (Free (RegionId.of_int 0))]);
  require "Self dictionary must remain concrete" (match evidence with
    | Some { kind = TraitImpl target; _ } -> target.generics.regions = args.regions
    | _ -> false);
  let distinct, _, _ = Instance_view.factor_context shared
    (Some (reference 0 { empty with regions = [region 13] })) in
  require "distinct Self and argument lifetimes must not alias"
    (List.length distinct.parameters = 2);
  let global_arguments = { shared with trait_refs = [self] } in
  let global_factor = Region_shape.factor global_arguments in
  require "source-global Self must follow the exact argument factorization"
    (Global_view.factored_self global_arguments global_factor.pattern self =
      List.hd global_factor.pattern.trait_refs);
  let other, _, _ = Instance_view.factor_context shared (Some (reference 1 shared)) in
  require "different default-method dictionaries must have different instance keys"
    (factored.pattern <> other.pattern);
  require "factoring Self evidence must retain the exact original complete context"
    (Region_shape.instantiate factored = { shared with trait_refs = [self] });
  require "erased regions present only in Self evidence must still be refused"
    (refuses (fun () -> ignore (Instance_view.factor_context shared
      (Some (reference 0 { empty with regions = [RErased] })))));
  let owner : trait_impl_ref = { id = TraitImplId.of_int 0; generics = empty } in
  let trait : trait_decl_ref = { id = TraitDeclId.of_int 0; generics = empty } in
  let method_id = TraitMethodId.of_int 3 in
  let own source = Static_targets.method_self_evidence ~default_lookup:false
    owner.id trait.id method_id self source in
  let source = TraitImplItem (owner, trait, AssocIdMethod method_id, false) in
  require "actual implementation must reconstruct its own Self" (own source = None);
  let default = TraitDeclItem (trait, AssocIdMethod method_id) in
  require "default method must retain exact dispatch Self evidence" (own default = Some self);
  require "a method in the same implementation must not stand in for another method"
    (refuses (fun () -> ignore (own (TraitImplItem
      (owner, trait, AssocIdMethod (TraitMethodId.of_int 4), false)))));
  require "a different implementation must not supply an actual method"
    (refuses (fun () -> ignore (own (TraitImplItem
      ({ owner with id = TraitImplId.of_int 1 }, trait, AssocIdMethod method_id, false)))));
  require "a default method from another trait must be refused"
    (refuses (fun () -> ignore (own (TraitDeclItem
      ({ trait with id = TraitDeclId.of_int 1 }, AssocIdMethod method_id)))));
  require "default lookup must not select an implementation body as its default"
    (refuses (fun () -> ignore (Static_targets.method_self_evidence ~default_lookup:true
      owner.id trait.id method_id self source)));
  let ranked : trait_decl_ref region_binder = {
    binder_regions = [{ index = RegionId.of_int 0; name = None;
      variance = Invariant; mutability = LtShared }];
    binder_value = self.trait_decl_ref.binder_value } in
  require "higher-ranked evidence needs explicit instantiation" (refuses (fun () ->
    ignore (Static_targets.without_region_binder
      Charon.Substitute.st_substitute_visitor#visit_trait_decl_ref ranked)));
  let predicate region = (reference 0 { empty with regions = [region] }).trait_decl_ref in
  let expected = predicate (region 5) in
  let actual = predicate RStatic in
  require "strict resolution must not silently unify different regions" (refuses (fun () ->
    ignore (Static_targets.compare_predicates ~candidate_only:false "test" expected actual)));
  require "candidate traversal must retain the entire unresolved regional obligation"
    (match Static_targets.compare_predicates ~candidate_only:true "test" expected actual with
     | Some obligation -> obligation.expected = expected && obligation.actual = actual
     | None -> false);
  require "exact predicates require no residual obligation"
    (Static_targets.compare_predicates ~candidate_only:false "test" expected expected = None);
  let type_parameter index : type_param = { index = TypeVarId.of_int index;
    name = "T" ^ string_of_int index; variance = Invariant } in
  let parent_parameters = { Charon.TypesUtils.empty_generic_params with types = [type_parameter 0; type_parameter 1] } in
  let variable index = TVar (Free (TypeVarId.of_int index)) in
  let universal_argument = TRef (RVar (Bound (0, RegionId.of_int 0)), TLiteral TBool, RShared) in
  let source_parent = { ranked with binder_value = { id = TraitDeclId.of_int 70;
    generics = { empty with types = [TLiteral TBool; universal_argument] } } } in
  let parent_clause : trait_param = { clause_id = TraitClauseId.of_int 8; span = None;
    origin = WhereClauseOnFn; trait = { binder_regions = []; binder_value = {
      id = TraitDeclId.of_int 71; generics = { empty with types = [variable 0; variable 1] } } } } in
  let inherited = Static_targets.quantified_parent_predicate parent_parameters source_parent parent_clause in
  require "a universal family must inherit the complete source parent under the same binder"
    (inherited.binder_regions = source_parent.binder_regions &&
      inherited.binder_value.id = TraitDeclId.of_int 71 &&
      inherited.binder_value.generics.types = [TLiteral TBool; universal_argument]);
  require "an additional parent binder must require explicit composition"
    (refuses (fun () -> ignore (Static_targets.quantified_parent_predicate parent_parameters source_parent
      { parent_clause with trait = { parent_clause.trait with binder_regions = ranked.binder_regions } })));
  let iterator region element = TAdt { id = TAdtId (TypeDeclId.of_int 16);
    generics = { empty with regions = [region]; types = [element] } } in
  let parent_source = { binder_regions = []; binder_value = {
    id = TraitDeclId.of_int 19; generics = { empty with types = [iterator (region 31) (TLiteral (TUInt U64))] } } } in
  let parent_parameters = { Charon.TypesUtils.empty_generic_params with types = [type_parameter 0] } in
  let iterator_clause = { parent_clause with trait = { binder_regions = []; binder_value = {
    id = TraitDeclId.of_int 11; generics = { empty with types = [variable 0] } } } } in
  let declared = Static_targets.quantified_parent_predicate parent_parameters parent_source iterator_clause in
  let parameters = { Charon.TypesUtils.empty_generic_params with regions = [{
    index = RegionId.of_int 0; name = None; variance = Invariant; mutability = LtShared }];
    types = [type_parameter 0] } in
  let template = { id = TraitDeclId.of_int 11;
    generics = { empty with types = [iterator (RVar (Free (RegionId.of_int 0))) (variable 0)] } } in
  let arguments = { empty with regions = [RErased]; types = [TLiteral (TUInt U64)] } in
  let recovered = Impl_regions.recover_predicate parameters template arguments declared.binder_value in
  require "a missing parent implementation lifetime must come from the complete actual declared parent"
    (recovered.reconstructed_arguments.regions = [region 31] &&
      Impl_regions.replay_predicate parameters template recovered);
  require "parent reconstruction must preserve every known implementation argument" (refuses (fun () ->
    ignore (Impl_regions.recover_predicate parameters template
      { arguments with regions = [region 32] } declared.binder_value)));
  let typed ty = (reference 0 { empty with types = [ty] }).trait_decl_ref in
  require "candidate traversal must not hide a type discrepancy" (refuses (fun () ->
    ignore (Static_targets.compare_predicates ~candidate_only:true "test"
      (typed (TLiteral TBool)) (typed (TLiteral (TUInt U8))))));
  let erased = predicate RErased in
  require "candidate traversal must retain erased metadata as unresolved"
    (match Static_targets.compare_predicates ~candidate_only:true "test" expected erased with
     | Some obligation -> obligation.actual = erased
     | None -> false);
  let partial = (reference 0 { empty with regions = [RErased; region 7] }).trait_decl_ref in
  let source = (reference 0 { empty with regions = [region 4; region 8] }).trait_decl_ref in
  let metadata = Predicate_metadata.recover partial source in
  require "omitted informative regions must come from the selected source"
    (metadata.completed.binder_value.generics.regions = [region 4; region 7]);
  require "known informative labels must not be silently overwritten"
    (metadata.completed <> source);
  require "remaining known discrepancies must remain complete obligations"
    (match Static_targets.compare_predicates ~candidate_only:true "known metadata"
      metadata.completed source with Some _ -> true | None -> false);
  require "informative metadata reconstruction must replay"
    (Predicate_metadata.replay metadata);
  require "a forged witness replacing a known label must fail replay"
    (not (Predicate_metadata.replay { metadata with completed = source }));
  require "an erased selected source is not reconstruction evidence" (refuses (fun () ->
    ignore (Predicate_metadata.recover partial partial)));
  require "source trait identity must not be substituted for another trait"
    (refuses (fun () -> ignore (Predicate_metadata.recover partial
      { source with binder_value = { source.binder_value with id = TraitDeclId.of_int 19 } }))));
  require "informative completion must preserve higher-ranked binders"
    (refuses (fun () -> ignore (Predicate_metadata.recover partial ranked)))
