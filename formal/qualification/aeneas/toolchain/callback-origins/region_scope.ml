(* Check region provenance after complete source normalization. Empty binders
   still count towards de Bruijn depth. This checks naming/scope only, not
   outlives, aliasing, loans, layout or execution semantics. *)
open Charon.Types

let require_parameters parameters =
  let ids = List.map (fun (parameter : region_param) -> parameter.index) parameters in
  if List.exists (fun id -> RegionId.to_int id < 0) ids ||
     List.length ids <> List.length (List.sort_uniq RegionId.compare_id ids) then
    invalid_arg "source region parameters have duplicate or negative identifiers"

class ['self] check ?body_regions parameters = object (self : 'self)
  inherit [_] iter_ty
  initializer
    require_parameters parameters;
    (match body_regions with Some count when count < 0 ->
      invalid_arg "source region scope has a negative body-region bound" | _ -> ())

  method! visit_binder visit_value scopes binder =
    require_parameters binder.binder_params.regions;
    let scopes = binder.binder_params.regions :: scopes in
    self#visit_generic_params scopes binder.binder_params;
    visit_value scopes binder.binder_value

  method! visit_region_binder visit_value scopes binder =
    require_parameters binder.binder_regions;
    visit_value (binder.binder_regions :: scopes) binder.binder_value

  method! visit_region scopes = function
    | RStatic -> ()
    | RErased -> invalid_arg "normalized source region provenance remains erased"
    | RBody id ->
        (match body_regions with
         | Some count when RegionId.to_int id >= 0 && RegionId.to_int id < count -> ()
         | _ -> invalid_arg "normalized source region escapes its actual body binder")
    | RVar (Free id) ->
        if not (List.exists (fun (parameter : region_param) -> parameter.index = id) parameters) then
          invalid_arg "normalized source region is absent from the complete specialization parameters"
    | RVar (Bound (depth, id)) ->
        let rec lookup depth = function
          | [] -> None
          | scope :: _ when depth = 0 -> Some scope
          | _ :: rest -> lookup (depth - 1) rest in
        if depth < 0 then invalid_arg "normalized source region has a negative binder depth";
        (match lookup depth scopes with
         | Some scope when List.exists (fun (parameter : region_param) -> parameter.index = id) scope -> ()
         | _ -> invalid_arg "normalized source region escapes its exact local quantifier")
end

class ['self] statement_check ?body_regions parameters = object (_self : 'self)
  inherit [_] Charon.LlbcAst.iter_statement
  inherit! [_] check ?body_regions parameters
end

class ['self] declaration_check parameters = object (_self : 'self)
  inherit [_] iter_type_decl
  inherit! [_] check parameters
end
