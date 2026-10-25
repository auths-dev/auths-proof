(* A universally quantified dictionary is a family of source implementations,
   not equality with the single lifetime used in Charon's representative
   TraitImpl arguments. Construct the family from an actual generic source
   impl. The representative arguments remain unchanged and recorded.
   Invariant concrete dictionary prerequisites remain explicit premises.
   Varying conditions and outlives/type equalities need further family proofs. *)
open Charon
open Types

type witness = {
  representative_arguments : generic_args;
  expected : trait_decl_ref region_binder;
  opened : trait_decl_ref;
  fresh_arguments : region list;
  family : Region_match.witness;
  invariant_prerequisites : (trait_param * trait_ref) list;
  fixed_actual : trait_decl_ref region_binder;
}

let open_predicate fresh (expected : trait_decl_ref region_binder) =
  let binder = {
    binder_params = { TypesUtils.empty_generic_params with regions = expected.binder_regions };
    binder_value = expected.binder_value } in
  Substitute.apply_args_to_binder
    { TypesUtils.empty_generic_args with regions = fresh }
    Substitute.st_substitute_visitor#visit_trait_decl_ref binder

let invariant_prerequisites (parameters : generic_params) representative family_arguments =
  if parameters.regions_outlive <> [] || parameters.types_outlive <> [] ||
     parameters.trait_type_constraints <> [] then
    invalid_arg "a universal implementation family needs explicit outlives/type-equality premises";
  let instantiate arguments =
    Substitute.predicates_substitute
      (Substitute.make_subst_from_generics parameters arguments Self) parameters in
  let original = instantiate representative in
  let generalized = instantiate family_arguments in
  if original.trait_clauses <> generalized.trait_clauses then
    invalid_arg "implementation dictionary conditions vary with a universal lifetime";
  if List.length original.trait_clauses <> List.length representative.trait_refs then
    invalid_arg "universal dictionary prerequisites have incomplete source evidence";
  let premises = List.combine original.trait_clauses representative.trait_refs in
  List.iter (fun ((clause : trait_param), (evidence : trait_ref)) ->
    (match evidence.kind with TraitImpl _ -> () | _ ->
      invalid_arg "an invariant universal prerequisite needs its concrete source implementation");
    if clause.trait <> evidence.trait_decl_ref then
      invalid_arg "an invariant universal prerequisite differs from its complete declared predicate") premises;
  premises

let family_pattern (parameters : generic_params) template (representative : generic_args) =
  let occurrences = Region_match.occurrences (Region_match.Trait_predicate template) in
  if List.length parameters.regions <> List.length representative.regions then
    invalid_arg "universal source family region arity differs from its representative";
  { representative with regions = List.map2 (fun (parameter : region_param) original ->
    if List.mem (RVar (Free parameter.index)) occurrences then RErased else original)
    parameters.regions representative.regions }

let fresh_regions template representative expected =
  let values = ref [] in
  let visitor = object
    inherit [_] iter_ty
    method! visit_region _ region = values := region :: !values
  end in
  visitor#visit_generic_args () representative;
  visitor#visit_trait_decl_ref () template;
  visitor#visit_region_binder visitor#visit_trait_decl_ref () expected;
  let largest = List.fold_left (fun largest -> function
    | RVar (Free id) -> max largest (RegionId.to_int id)
    | _ -> largest) (-1) !values in
  if largest >= max_int - List.length expected.binder_regions - 1 then
    invalid_arg "quantified dictionary parameters exceed the construction identifier space";
  List.mapi (fun index _ -> RVar (Free (RegionId.of_int (largest + index + 1)))) expected.binder_regions

let close_predicate expected fresh opened =
  let pairs = List.combine fresh (List.map (fun (parameter : region_param) ->
    RVar (Bound (0, parameter.index))) expected.binder_regions) in
  let under = Substitute.st_substitute_visitor#visit_trait_decl_ref
    Substitute.move_under_binder_subst opened in
  let substitution = { Substitute.empty_subst with r_subst = (fun variable ->
    let region = RVar variable in
    match List.assoc_opt region pairs with Some bound -> bound | None -> region) } in
  { binder_regions = expected.binder_regions;
    binder_value = Substitute.trait_decl_ref_substitute substitution under }

let fixed_actual parameters template (representative : generic_args) expected fresh (family_arguments : generic_args) =
  (* Generalize only the universally variable positions in the representative.
     Fixed positions retain their original known arguments. The caller must
     establish this complete quantified predicate against [expected]; recording
     the old representative alone is not evidence that its fixed slots match. *)
  let arguments = { representative with regions = List.map2 (fun original generalized ->
    if List.mem generalized fresh then generalized else original)
    representative.regions family_arguments.regions } in
  let actual = Region_match.instantiate parameters arguments (Region_match.Trait_predicate template) in
  match actual with
  | Region_match.Trait_predicate actual -> close_predicate expected fresh actual
  | _ -> invalid_arg "universal fixed-argument validation changed its subject kind"

let replay parameters template witness =
  try
    let representative = witness.representative_arguments in
    let fresh = fresh_regions template representative witness.expected in
    let opened = open_predicate fresh witness.expected in
    let pattern = family_pattern parameters template representative in
    witness.expected.binder_regions <> [] &&
    witness.fresh_arguments = fresh && witness.opened = opened &&
    witness.family.original_arguments = pattern &&
    witness.family.source = Region_match.Trait_predicate opened &&
    Region_match.replay parameters (Region_match.Trait_predicate template) witness.family &&
    witness.invariant_prerequisites = invariant_prerequisites parameters representative
      witness.family.reconstructed_arguments &&
    witness.fixed_actual = fixed_actual parameters template representative witness.expected fresh
      witness.family.reconstructed_arguments &&
    close_predicate witness.expected fresh opened = witness.expected
  with Invalid_argument _ | Not_found -> false

let recover parameters template representative_arguments expected =
  if expected.binder_regions = [] then invalid_arg "a quantified dictionary family needs its explicit universal binder";
  let fresh_arguments = fresh_regions template representative_arguments expected in
  let opened = open_predicate fresh_arguments expected in
  (* These holes parameterize a new universal source family. They do not
     replace or reinterpret any known representative call argument. *)
  let pattern = family_pattern parameters template representative_arguments in
  let family = Region_match.recover parameters (Region_match.Trait_predicate template)
    pattern (Region_match.Trait_predicate opened) in
  let invariant_prerequisites = invariant_prerequisites parameters representative_arguments family.reconstructed_arguments in
  let fixed_actual = fixed_actual parameters template representative_arguments expected fresh_arguments family.reconstructed_arguments in
  let witness = { representative_arguments; expected; opened; fresh_arguments; family; invariant_prerequisites; fixed_actual } in
  if not (replay parameters template witness) then
    invalid_arg "quantified source implementation family did not reconstruct the entire original binder";
  witness

let instantiate ?(candidate_only = false) parameters template witness expected =
  if not (replay parameters template witness) then
    invalid_arg "a universal dictionary instance needs its replayable source family";
  if not candidate_only && witness.fixed_actual <> witness.expected then
    invalid_arg "a universal dictionary's known fixed arguments require their complete source predicate proof";
  if expected.binder_regions <> [] then
    invalid_arg "instantiating one universal dictionary into another needs explicit binder composition";
  let concrete = Substitute.extract_from_binder
    Substitute.st_substitute_visitor#visit_trait_decl_ref expected in
  let family_arguments = witness.family.reconstructed_arguments in
  let pattern = { family_arguments with regions = List.map (fun region ->
    if List.mem region witness.fresh_arguments then RErased else region) family_arguments.regions } in
  (* Only parameters proved universally variable by the family may vary.
     Fixed regions and every type/const/evidence argument stay unchanged. *)
  Impl_regions.recover_predicate parameters template pattern concrete
