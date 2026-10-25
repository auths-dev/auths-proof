(* Planning-only factorization for function specialization on the original
   polymorphic LLBC. It does not rewrite a program or erase lifetime labels.
   Instantiating the pattern with the captured arguments must recover the exact
   original generic argument tree, including higher-ranked binders. *)
open Charon.Types

module Regions = Map.Make (struct type t = region let compare = compare_region end)

type factorization = {
  pattern : generic_args;
  parameters : region_param list;
  arguments : region list;
}

let outside depth = function
  | RVar (Bound (binder, id)) when binder >= depth -> RVar (Bound (binder - depth, id))
  | region -> region

let under depth = function
  | RVar (Bound (binder, id)) -> RVar (Bound (binder + depth, id))
  | region -> region

class ['self] binder_map = object (self : 'self)
  inherit [_] map_ty

  method! visit_binder visit_value depth binder =
    let depth = depth + 1 in
    { binder_params = self#visit_generic_params depth binder.binder_params;
      binder_value = visit_value depth binder.binder_value }

  method! visit_region_binder visit_value depth binder =
    let depth = depth + 1 in
    { binder_regions = binder.binder_regions;
      binder_value = visit_value depth binder.binder_value }
end

let instantiate (factor : factorization) : generic_args =
  let arguments = Array.of_list factor.arguments in
  let visitor = object
    inherit [_] binder_map
    method! visit_region depth = function
      | RVar (Free id) ->
          let index = RegionId.to_int id in
          if index < 0 || index >= Array.length arguments then
            invalid_arg "region pattern contains an unbound specialization parameter";
          under depth arguments.(index)
      | region -> region
  end in
  visitor#visit_generic_args 0 factor.pattern

let factor (original : generic_args) : factorization =
  let indices = ref Regions.empty in
  let arguments = ref [] in
  let next = ref 0 in
  let parameter region =
    match Regions.find_opt region !indices with
    | Some id -> RVar (Free id)
    | None ->
        let id = RegionId.of_int !next in
        incr next;
        indices := Regions.add region id !indices;
        arguments := region :: !arguments;
        RVar (Free id)
  in
  let visitor = object
    inherit [_] binder_map
    method! visit_region depth = function
      | RErased -> invalid_arg "cannot recover an erased lifetime for specialization"
      | RStatic -> RStatic
      | RVar (Bound (binder, _)) as region when binder < depth -> region
      | region -> parameter (outside depth region)
  end in
  let pattern = visitor#visit_generic_args 0 original in
  let arguments = List.rev !arguments in
  let parameters = List.mapi (fun index _ -> {
    index = RegionId.of_int index;
    name = Some ("auths_specialized_region_" ^ string_of_int index);
    variance = Invariant;
    mutability = LtUnknown;
  }) arguments in
  let result = { pattern; parameters; arguments } in
  if instantiate result <> original then
    invalid_arg "lifetime specialization factorization does not round-trip";
  result
