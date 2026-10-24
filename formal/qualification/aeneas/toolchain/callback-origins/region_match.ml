(* Mechanical source matching on complete Charon ASTs. The subject is either
   an implementation Self carrier or its whole trait predicate. No business
   evaluator or caller-supplied semantic matching function is involved. *)
open Charon
open Types

type subject = Self_type of ty | Trait_predicate of trait_decl_ref

type witness = {
  original_arguments : generic_args;
  reconstructed_arguments : generic_args;
  source : subject;
  reconstructed : subject;
  inferred : (region_id * region) list;
}

let occurrences = function
  | Self_type ty -> Region_equations.type_occurrences ty
  | Trait_predicate predicate ->
      let values = ref [] in
      let visitor = object
        inherit [_] iter_ty
        method! visit_region _ region = values := region :: !values
      end in
      visitor#visit_trait_decl_ref () predicate;
      List.rev !values

let shape subject =
  let visitor = object
    inherit [_] map_ty
    method! visit_region _ _ = RErased
  end in
  match subject with
  | Self_type ty -> Self_type (visitor#visit_ty () ty)
  | Trait_predicate predicate -> Trait_predicate (visitor#visit_trait_decl_ref () predicate)

let instantiate parameters arguments template =
  let subst = Substitute.make_subst_from_generics parameters arguments Self in
  match template with
  | Self_type ty -> Self_type (Substitute.ty_substitute subst ty)
  | Trait_predicate predicate -> Trait_predicate (Substitute.trait_decl_ref_substitute subst predicate)

let replay (parameters : generic_params) template witness =
  try
    let original = witness.original_arguments in
    let recovered = witness.reconstructed_arguments in
    let template_regions = occurrences template in
    let bindings = List.combine parameters.regions (List.combine original.regions recovered.regions) in
    let inferred = List.filter_map (fun ((parameter : region_param), (before, after)) ->
      match before with
      | RErased ->
          if not (List.mem (RVar (Free parameter.index)) template_regions) then
            invalid_arg "an unused implementation lifetime has no declared-source witness";
          (match after with
           | RBody _ | RVar (Free _) -> Some (parameter.index, after)
           | _ -> invalid_arg "reconstruction has no admissible declared-source lifetime")
      | _ when before = after -> None
      | _ -> invalid_arg "reconstruction changed a known argument") bindings in
    let actual = instantiate parameters recovered template in
    original.types = recovered.types && original.const_generics = recovered.const_generics &&
    original.trait_refs = recovered.trait_refs &&
    List.sort compare inferred = List.sort compare witness.inferred &&
    actual = witness.reconstructed && actual = witness.source &&
    not (List.mem RErased (occurrences witness.source))
  with Invalid_argument _ | Not_found -> false

let recover (parameters : generic_params) template (arguments : generic_args) source =
  let same_count label expected actual =
    if expected <> actual then invalid_arg ("implementation " ^ label ^ " argument arity disagrees with source") in
  same_count "region" (List.length parameters.regions) (List.length arguments.regions);
  same_count "type" (List.length parameters.types) (List.length arguments.types);
  same_count "const" (List.length parameters.const_generics) (List.length arguments.const_generics);
  same_count "trait" (List.length parameters.trait_clauses) (List.length arguments.trait_refs);
  let source_regions = occurrences source in
  if List.mem RErased source_regions then invalid_arg "declared source must supply complete lifetime evidence";
  let argument_regions =
    let values = ref [] in
    let visitor = object
      inherit [_] iter_ty
      method! visit_region _ region = values := region :: !values
    end in
    visitor#visit_generic_args () arguments;
    !values in
  let largest = List.fold_left (fun largest -> function
    | RVar (Free id) ->
        let id = RegionId.to_int id in
        if id < 0 then invalid_arg "source contains a negative free-region identifier";
        max largest id
    | _ -> largest) (-1) (argument_regions @ source_regions @ occurrences template) in
  if largest >= max_int - List.length parameters.regions - 1 then
    invalid_arg "implementation matching metavariables exceed the construction identifier space";
  let next = ref (largest + 1) in
  let unknown = ref [] in
  let pattern_regions = List.map2 (fun (parameter : region_param) region ->
    match region with
    | RErased ->
        let marker = RegionId.of_int !next in
        incr next;
        unknown := (marker, parameter.index) :: !unknown;
        RVar (Free marker)
    | region -> region) parameters.regions arguments.regions in
  let pattern = instantiate parameters { arguments with regions = pattern_regions } template in
  if shape pattern <> shape source then invalid_arg "selected implementation shape differs from the complete source subject";
  let pattern_regions = occurrences pattern in
  if List.length pattern_regions <> List.length source_regions then
    invalid_arg "implementation/source region traversal arities disagree";
  let inferred = ref RegionId.Map.empty in
  List.iter2 (fun pattern source -> match pattern with
    | RVar (Free marker) when List.mem_assoc marker !unknown ->
        (match source with
         | RBody _ | RVar (Free _) -> ()
         | RStatic -> invalid_arg "missing implementation regions need separate static provenance"
         | RVar (Bound _) -> invalid_arg "implementation matching must not capture a quantified lifetime"
         | RErased -> invalid_arg "an erased source label is not lifetime evidence");
        (match RegionId.Map.find_opt marker !inferred with
         | None -> inferred := RegionId.Map.add marker source !inferred
         | Some previous when previous = source -> ()
         | Some _ -> invalid_arg "one implementation lifetime has conflicting declared-source occurrences")
    | _ -> ()) pattern_regions source_regions;
  let inferred = List.map (fun (marker, parameter) ->
    match RegionId.Map.find_opt marker !inferred with
    | Some source -> parameter, source
    | None -> invalid_arg "a missing implementation lifetime is not determined by its complete declared source subject") !unknown in
  let regions = List.map2 (fun (parameter : region_param) original ->
    match original with RErased -> List.assoc parameter.index inferred | region -> region)
    parameters.regions arguments.regions in
  let reconstructed_arguments = { arguments with regions } in
  let reconstructed = instantiate parameters reconstructed_arguments template in
  if reconstructed <> source then invalid_arg "reconstructed implementation does not exactly match its complete source subject";
  let witness = { original_arguments = arguments; reconstructed_arguments; source; reconstructed; inferred } in
  if not (replay parameters template witness) then invalid_arg "implementation-region witness did not replay";
  witness
