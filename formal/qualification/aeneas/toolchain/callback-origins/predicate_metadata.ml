(* Informative dictionary predicates may omit lifetime labels even when the
   selected implementation arguments retain them. Fill only those omitted
   labels from that actual source predicate. Known labels are immutable;
   disagreement remains a separate, complete predicate obligation. *)
open Charon.Types

type witness = {
  original : trait_decl_ref region_binder;
  source : trait_decl_ref region_binder;
  completed : trait_decl_ref region_binder;
}

let complete original source =
  if Region_equations.shape original <> Region_equations.shape source then
    invalid_arg "informative dictionary metadata differs from its selected source structure";
  let regions = Region_equations.occurrences source in
  if List.mem RErased regions then
    invalid_arg "a selected source predicate with erased regions cannot complete metadata";
  let remaining = ref regions in
  let visitor = object
    inherit [_] map_ty
    method! visit_region _ before =
      match !remaining with
      | actual :: rest ->
          remaining := rest;
          if before = RErased then actual else before
      | [] -> invalid_arg "informative predicate region traversal exceeds its source"
  end in
  let completed = visitor#visit_region_binder visitor#visit_trait_decl_ref () original in
  if !remaining <> [] then invalid_arg "informative predicate omits source region positions";
  completed

let replay witness =
  try complete witness.original witness.source = witness.completed
  with Invalid_argument _ -> false

let recover original source =
  let completed = complete original source in
  let witness = { original; source; completed } in
  if not (replay witness) then invalid_arg "informative dictionary reconstruction did not replay";
  witness
