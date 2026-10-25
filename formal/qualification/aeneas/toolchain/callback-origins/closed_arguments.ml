(* Closure of non-region capture variables. Local quantified type/constant/
   dictionary variables remain bound in their exact original scopes. Caller
   type/const/dictionary placeholders, unbound Self and opaque constants are
   not native instances. This is scope/closure evidence, not semantic proof. *)
open Charon
open Types

let rec scope depth = function
  | _ when depth < 0 -> invalid_arg "a closed capture has a negative binder depth"
  | [] -> invalid_arg "a closed capture escapes its original quantifier"
  | first :: _ when depth = 0 -> first
  | _ :: rest -> scope (depth - 1) rest

let require_binder (parameters : generic_params) =
  Region_scope.require_parameters parameters.regions;
  let unique ids =
    if List.exists (fun id -> id < 0) ids || List.length (List.sort_uniq Int.compare ids) <> List.length ids then
      invalid_arg "a closed capture quantifier has duplicate or negative parameter IDs" in
  unique (List.map (fun (parameter : type_param) -> TypeVarId.to_int parameter.index) parameters.types);
  unique (List.map (fun (parameter : const_generic_param) -> ConstGenericVarId.to_int parameter.index) parameters.const_generics);
  unique (List.map (fun (parameter : trait_param) -> TraitClauseId.to_int parameter.clause_id) parameters.trait_clauses)

class ['self] check ?body_regions parameters = object (self : 'self)
  inherit [_] iter_ty as super

  method! visit_binder visit scopes binder =
    require_binder binder.binder_params;
    let scopes = binder.binder_params :: scopes in
    self#visit_generic_params scopes binder.binder_params;
    visit scopes binder.binder_value

  method! visit_region_binder visit scopes binder =
    Region_scope.require_parameters binder.binder_regions;
    visit ({ TypesUtils.empty_generic_params with regions = binder.binder_regions } :: scopes) binder.binder_value

  method! visit_region scopes region =
    let region_scope = new Region_scope.check ?body_regions parameters in
    region_scope#visit_region (List.map (fun (parameters : generic_params) -> parameters.regions) scopes) region

  method! visit_ty scopes ty =
    (match ty with
     | TVar (Free _) -> invalid_arg "a native capture still contains a free source type parameter"
     | TVar (Bound (depth, id)) ->
         if not (List.exists (fun (parameter : type_param) -> parameter.index = id) (scope depth scopes).types) then
           invalid_arg "a native capture type variable escapes its exact local binder"
     | _ -> ());
    super#visit_ty scopes ty

  method! visit_constant_expr scopes value =
    (match value.kind with
     | CVar (Free _) -> invalid_arg "a native capture still contains a free source const parameter"
     | CVar (Bound (depth, id)) ->
         if not (List.exists (fun (parameter : const_generic_param) -> parameter.index = id) (scope depth scopes).const_generics) then
           invalid_arg "a native capture const variable escapes its exact local binder"
     | COpaque _ -> invalid_arg "an opaque source constant cannot supply a native capture value"
     | _ -> ());
    super#visit_constant_expr scopes value

  method! visit_trait_ref scopes reference =
    (match reference.kind with
     | Clause (Free _) -> invalid_arg "a native capture still contains a caller dictionary placeholder"
     | Clause (Bound (depth, id)) ->
         if not (List.exists (fun (parameter : trait_param) -> parameter.clause_id = id) (scope depth scopes).trait_clauses) then
           invalid_arg "a native capture dictionary escapes its exact local binder"
     | Self -> invalid_arg "a native capture has an unbound source Self dictionary"
     | _ -> ());
    super#visit_trait_ref scopes reference
end

class ['self] statement_check ?body_regions parameters = object (_self : 'self)
  inherit [_] Charon.LlbcAst.iter_statement
  inherit! [_] check ?body_regions parameters
end

let require ~parameters arguments =
  Region_scope.require_parameters parameters;
  (new check parameters)#visit_generic_args [] arguments
