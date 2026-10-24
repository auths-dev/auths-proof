(* Equality constraints for existential regions belonging to one source body.
   Free/signature and higher-ranked regions are rigid. No erased region is
   recovered, no signature parameter is merged and no static lifetime is
   synthesized. A replayable certificate contains every original equation. *)
open Charon.Types

type t = {
  bindings : region RegionId.Map.t;
  equations : (region * region) list;
}

let empty = { bindings = RegionId.Map.empty; equations = [] }

let resolve state region =
  let rec follow seen = function
    | RBody id as region ->
        if RegionId.Set.mem id seen then invalid_arg "cyclic body-region certificate";
        (match RegionId.Map.find_opt id state.bindings with
         | None -> region
         | Some target -> follow (RegionId.Set.add id seen) target)
    | region -> region in
  follow RegionId.Set.empty region

let add state left right =
  let original = left, right in
  let left = resolve state left in
  let right = resolve state right in
  let bind id target =
    { state with bindings = RegionId.Map.add id target state.bindings } in
  let state = match left, right with
    | RErased, _ | _, RErased -> invalid_arg "erased regions require source evidence, not unification"
    | _ when left = right -> state
    | RBody left, RBody right ->
        if RegionId.to_int left < RegionId.to_int right then bind right (RBody left)
        else bind left (RBody right)
    | RBody id, (RVar (Free _) as target)
    | (RVar (Free _) as target), RBody id -> bind id target
    | RBody _, RStatic | RStatic, RBody _ ->
        invalid_arg "a body-to-static equation requires separate static provenance"
    | RBody _, RVar (Bound _) | RVar (Bound _), RBody _ ->
        invalid_arg "a body region cannot capture a quantified lifetime"
    | _ -> invalid_arg "rigid signature or quantified regions disagree" in
  { state with equations = original :: state.equations }

let add_all state equations = List.fold_left (fun state (left, right) -> add state left right) state equations

let replay state =
  try
    let rebuilt = add_all empty (List.rev state.equations) in
    RegionId.Map.equal equal_region rebuilt.bindings state.bindings &&
    List.for_all (fun (left, right) -> resolve state left = resolve state right) state.equations
  with Invalid_argument _ -> false

class ['self] apply state = object (_self : 'self)
  inherit [_] map_ty
  method! visit_region _ region = resolve state region
end

(* Full predicates must have the same non-region structure and binders. The
   final witness rechecks their entire ASTs, not just the extracted equations. *)
type premise =
  | Predicate of trait_decl_ref region_binder * trait_decl_ref region_binder
  | Type of ty * ty
  | QuantifiedType of ty region_binder * ty region_binder
  | Arguments of generic_args * generic_args

type predicates = {
  solution : t;
  originals : premise list;
}

let empty_predicates = { solution = empty; originals = [] }

let occurrences predicate =
  let values = ref [] in
  let visitor = object
    inherit [_] iter_ty
    method! visit_region _ region = values := region :: !values
  end in
  visitor#visit_region_binder visitor#visit_trait_decl_ref () predicate;
  List.rev !values

let shape predicate =
  let visitor = object
    inherit [_] map_ty
    method! visit_region _ _ = RErased
  end in
  visitor#visit_region_binder visitor#visit_trait_decl_ref () predicate

let apply_predicate solution predicate =
  let visitor = new apply solution in
  visitor#visit_region_binder visitor#visit_trait_decl_ref () predicate

let type_occurrences ty =
  let values = ref [] in
  let visitor = object
    inherit [_] iter_ty
    method! visit_region _ region = values := region :: !values
  end in
  visitor#visit_ty () ty;
  List.rev !values

let type_shape ty =
  let visitor = object
    inherit [_] map_ty
    method! visit_region _ _ = RErased
  end in
  visitor#visit_ty () ty

let quantified_type_occurrences value =
  let values = ref [] in
  let visitor = object
    inherit [_] iter_ty
    method! visit_region _ region = values := region :: !values
  end in
  visitor#visit_region_binder visitor#visit_ty () value;
  List.rev !values

let quantified_type_shape value =
  let visitor = object
    inherit [_] map_ty
    method! visit_region _ _ = RErased
  end in
  visitor#visit_region_binder visitor#visit_ty () value

let argument_occurrences arguments =
  let values = ref [] in
  let visitor = object inherit [_] iter_ty
    method! visit_region _ region = values := region :: !values
  end in
  visitor#visit_generic_args () arguments;
  List.rev !values

let argument_shape arguments =
  let visitor = object inherit [_] map_ty
    method! visit_region _ _ = RErased
  end in
  visitor#visit_generic_args () arguments

let premise_holds solution = function
  | Predicate (expected, actual) -> apply_predicate solution expected = apply_predicate solution actual
  | Type (expected, actual) ->
      let visitor = new apply solution in
      visitor#visit_ty () expected = visitor#visit_ty () actual
  | QuantifiedType (expected, actual) ->
      let visitor = new apply solution in
      visitor#visit_region_binder visitor#visit_ty () expected =
        visitor#visit_region_binder visitor#visit_ty () actual
  | Arguments (expected, actual) ->
      let visitor = new apply solution in
      visitor#visit_generic_args () expected = visitor#visit_generic_args () actual

let add_premise state original =
  let expected_regions, actual_regions = match original with
    | Predicate (expected, actual) ->
        if shape expected <> shape actual then
          invalid_arg "predicate structures or quantifiers require separate source instantiation";
        occurrences expected, occurrences actual
    | Type (expected, actual) ->
        if type_shape expected <> type_shape actual then
          invalid_arg "associated type structures require separate source evidence";
        type_occurrences expected, type_occurrences actual
    | QuantifiedType (expected, actual) ->
        if quantified_type_shape expected <> quantified_type_shape actual then
          invalid_arg "quantified type structures or complete binders disagree";
        quantified_type_occurrences expected, quantified_type_occurrences actual
    | Arguments (expected, actual) ->
        if argument_shape expected <> argument_shape actual then
          invalid_arg "complete source argument structures, dictionaries or quantifiers disagree";
        argument_occurrences expected, argument_occurrences actual in
  if List.length expected_regions <> List.length actual_regions then
    invalid_arg "predicate region traversal arities disagree";
  let solution = add_all state.solution (List.combine expected_regions actual_regions) in
  let originals = original :: state.originals in
  if not (List.for_all (premise_holds solution) originals) then
    invalid_arg "body-region solution does not reconstruct every original full predicate";
  { solution; originals }

let add_predicate state expected actual = add_premise state (Predicate (expected, actual))
let add_type state expected actual = add_premise state (Type (expected, actual))
let add_quantified_type state expected actual = add_premise state (QuantifiedType (expected, actual))
let add_arguments state expected actual = add_premise state (Arguments (expected, actual))

let replay_predicates state =
  try
    let rebuilt = List.fold_left add_premise empty_predicates (List.rev state.originals) in
    replay state.solution && rebuilt.solution.equations = state.solution.equations &&
    RegionId.Map.equal equal_region rebuilt.solution.bindings state.solution.bindings &&
    List.for_all (premise_holds state.solution) state.originals
  with Invalid_argument _ -> false
