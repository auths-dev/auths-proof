(* Instantiate an original function-pointer lifetime binder from the complete
   actual inputs/output. Fixed/captured regions and nested binders stay rigid.
   This is source-signature reconstruction, not a borrow or invocation proof. *)
open Charon
open Types

type t = {
  source : fun_sig region_binder;
  actual : fun_sig;
  arguments : region list;
  reconstructed : fun_sig;
}

let regions signature =
  let result = ref [] in
  let scan = object inherit [_] iter_ty
    method! visit_region _ region = result := region :: !result
  end in
  scan#visit_fun_sig () signature;
  List.rev !result

let shape signature =
  let erase = object inherit [_] map_ty
    method! visit_region _ _ = RErased
  end in
  erase#visit_fun_sig () signature

let instantiate source arguments =
  Callable_instance.open_binder Substitute.st_substitute_visitor#visit_fun_sig arguments source

let derive source actual =
  Region_scope.require_parameters source.binder_regions;
  let all = regions source.binder_value @ regions actual in
  if List.mem RErased all then invalid_arg "a function-pointer invocation needs complete source lifetime provenance";
  let largest = List.fold_left (fun current -> function
    | RVar (Free id) -> Stdlib.max current (RegionId.to_int id)
    | _ -> current) (-1) all in
  if largest >= Int.max_int - List.length source.binder_regions - 1 then
    invalid_arg "function-pointer matching parameters exceed the construction identifier space";
  let markers = List.mapi (fun index _ -> RVar (Free (RegionId.of_int (largest + index + 1)))) source.binder_regions in
  let pattern = instantiate source markers in
  if shape pattern <> shape actual then
    invalid_arg "the actual function-pointer call differs in complete input/result/ABI/quantifier structure";
  let left, right = regions pattern, regions actual in
  if List.length left <> List.length right then invalid_arg "function-pointer signature region traversal arities disagree";
  let inferred = ref [] in
  List.iter2 (fun expected supplied ->
    if List.mem expected markers then (
      (match supplied with
       | RStatic -> ()
       | RBody id | RVar (Free id) when RegionId.to_int id >= 0 -> ()
       | _ -> invalid_arg "a function-pointer binder cannot capture an erased or nested local lifetime");
      match List.assoc_opt expected !inferred with
      | None -> inferred := (expected, supplied) :: !inferred
      | Some earlier when earlier = supplied -> ()
      | Some _ -> invalid_arg "one function-pointer lifetime has inconsistent actual occurrences"
    )) left right;
  let arguments = List.map (fun marker -> match List.assoc_opt marker !inferred with
    | Some region -> region
    | None -> invalid_arg "a function-pointer lifetime is not determined by the complete actual call") markers in
  let reconstructed = instantiate source arguments in
  if reconstructed <> actual then
    invalid_arg "function-pointer instantiation changed a fixed lifetime or failed complete signature reconstruction";
  { source; actual; arguments; reconstructed }

let replay witness = try derive witness.source witness.actual = witness with Invalid_argument _ -> false

let create source actual =
  let witness = derive source actual in
  if not (replay witness) then invalid_arg "the complete function-pointer invocation witness did not replay";
  witness

let report witness =
  let open Diagnostic in
  `Assoc ["original_source_signature", `String (show_ty (TFnPtr witness.source));
    "actual_call_signature", `String (show_fun_sig witness.actual);
    "original_binder_arguments", `List (List.map (fun region -> `String (show_region region)) witness.arguments);
    "complete_reconstructed_signature", `String (show_fun_sig witness.reconstructed);
    "complete_signature_replays", `Bool (replay witness);
    "source_type_borrow_abi_and_invocation_adequacy_proved", `Bool false]
