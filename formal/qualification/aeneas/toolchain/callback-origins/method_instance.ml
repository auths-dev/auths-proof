(* Instantiate only a source method's own lifetime binder. Caller/owner
   substitution happens before entry; fixed regions and every type/const/
   dictionary argument remain rigid. This is a complete source-pointer
   routing witness, not a method ABI, where-condition or execution proof. *)
open Charon
open Types

type t = {
  source : fun_decl_ref binder;
  actual : fn_ptr;
  own_arguments : region list;
  reconstructed : fn_ptr;
}

let pointer (reference : fun_decl_ref) : fn_ptr = {
  kind = FunId (FRegular reference.id); generics = reference.generics }

let regions pointer =
  let regions = ref [] in
  let scan = object
    inherit [_] iter_ty
    method! visit_region _ region = regions := region :: !regions
  end in
  scan#visit_fn_ptr () pointer;
  List.rev !regions

let erase_regions pointer =
  let erase = object inherit [_] map_ty method! visit_region _ _ = RErased end in
  erase#visit_fn_ptr () pointer

let open_source arguments source =
  Substitute.apply_args_to_binder { TypesUtils.empty_generic_args with regions = arguments }
    Substitute.st_substitute_visitor#visit_fun_decl_ref source |> pointer

let derive source actual =
  let parameters = source.binder_params in
  if parameters.types <> [] || parameters.const_generics <> [] || parameters.trait_clauses <> [] then
    invalid_arg "a source dyn-method route cannot guess type/const/dictionary method parameters";
  Region_scope.require_parameters parameters.regions;
  let all = regions actual @ regions (pointer source.binder_value) in
  if List.mem RErased all then
    invalid_arg "source method routing needs complete captured and actual lifetime provenance";
  let largest = List.fold_left (fun largest -> function
    | RVar (Free id) -> Stdlib.max largest (RegionId.to_int id)
    | _ -> largest) (-1) all in
  if largest >= Int.max_int - List.length parameters.regions - 1 then
    invalid_arg "source method matching parameters exceed the construction identifier space";
  let markers = List.mapi (fun index _ -> RVar (Free (RegionId.of_int (largest + index + 1)))) parameters.regions in
  let pattern = open_source markers source in
  if erase_regions pattern <> erase_regions actual then
    invalid_arg "source method route differs in its complete function/type/const/dictionary/binder structure";
  let left, right = regions pattern, regions actual in
  if List.length left <> List.length right then invalid_arg "source method route region traversal arities disagree";
  let inferred = ref [] in
  List.iter2 (fun expected supplied ->
    if List.mem expected markers then (
      (match supplied with
       | RStatic -> ()
       | RBody id | RVar (Free id) when RegionId.to_int id >= 0 -> ()
       | _ -> invalid_arg "a source method binder cannot capture an erased or unopened caller quantifier");
      match List.assoc_opt expected !inferred with
      | None -> inferred := (expected, supplied) :: !inferred
      | Some previous when previous = supplied -> ()
      | Some _ -> invalid_arg "one source method lifetime routes to incompatible actual arguments"
    )) left right;
  let own_arguments = List.map (fun marker -> match List.assoc_opt marker !inferred with
    | Some actual -> actual
    | None -> invalid_arg "a source method lifetime cannot be determined from the complete actual pointer") markers in
  let reconstructed = open_source own_arguments source in
  if reconstructed <> actual then
    invalid_arg "source method routing changed a fixed argument or did not reconstruct the complete actual pointer";
  { source; actual; own_arguments; reconstructed }

let replay witness =
  try derive witness.source witness.actual = witness with Invalid_argument _ -> false

let create source actual =
  let witness = derive source actual in
  if not (replay witness) then invalid_arg "the complete source method routing witness did not replay";
  witness

let report witness =
  let open Diagnostic in
  `Assoc ["source_method_id", `Int (FunDeclId.to_int witness.source.binder_value.id);
    "source_method_parameters", `String (show_generic_params witness.source.binder_params);
    "source_method_arguments", `String (show_generic_args witness.source.binder_value.generics);
    "actual_source_call", `String (show_fn_ptr witness.actual);
    "own_lifetime_arguments", `List (List.map (fun region -> `String (show_region region)) witness.own_arguments);
    "complete_reconstructed_pointer", `String (show_fn_ptr witness.reconstructed);
    "source_argument_routing_replays", `Bool (replay witness);
    "method_where_abi_borrow_and_execution_adequacy_discharged", `Bool false]
