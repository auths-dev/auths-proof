(* Construction-only instantiation of an original LLBC function. Uses the
   pinned substitution library and preserves all region/outlives requirements.
   This is a view, not a new function declaration or an active codegen pass. *)
open Charon
open Types
open LlbcAst

module Subst = Substitute

type t = {
  original_id : fun_decl_id;
  arguments : Region_shape.factorization;
  call_arguments : generic_args;
  self_evidence : trait_ref option;
  signature : fun_sig;
  locals_and_body : (local list * block) option;
  source_body : expr_body option;
  inherited_requirements : generic_params;
}

let is_auths name = match name with
  | PeIdent (text, _) :: _ -> String.starts_with ~prefix:"auths_" text
  | _ -> false

(* Factor dispatch evidence together with call arguments. Otherwise a lifetime
   shared by Self and an argument could incorrectly become two parameters, or
   two default-method instances could collide in a worklist key. *)
let factor_context arguments self_evidence =
  let packed = match self_evidence with
    | None -> arguments
    | Some reference -> { arguments with trait_refs = arguments.trait_refs @ [reference] } in
  let factor = Region_shape.factor packed in
  let pattern, self_evidence = match self_evidence with
    | None -> factor.pattern, None
    | Some _ ->
        (match List.rev factor.pattern.trait_refs with
         | self :: rest -> { factor.pattern with trait_refs = List.rev rest }, Some self
         | [] -> invalid_arg "static Self evidence disappeared during region factorization") in
  factor, pattern, self_evidence

let create ?self_evidence (declaration : fun_decl) (arguments : generic_args) : t =
  let arguments, call_arguments, self_evidence = factor_context arguments self_evidence in
  let require_arity label expected actual =
    if expected <> actual then invalid_arg (Printf.sprintf
      "original function %d %s argument count: expected %d, got %d"
      (FunDeclId.to_int declaration.def_id) label expected actual) in
  require_arity "region" (List.length declaration.generics.regions) (List.length call_arguments.regions);
  require_arity "type" (List.length declaration.generics.types) (List.length call_arguments.types);
  require_arity "const" (List.length declaration.generics.const_generics) (List.length call_arguments.const_generics);
  require_arity "trait" (List.length declaration.generics.trait_clauses) (List.length call_arguments.trait_refs);
  let preliminary = Subst.make_subst_from_generics declaration.generics call_arguments Self in
  let self = match self_evidence with
    | Some reference -> reference.kind
    | None -> match declaration.src with
      | TraitImplItem (implementation, _, _, _) ->
          TraitImpl (Subst.st_substitute_visitor#visit_trait_impl_ref preliminary implementation)
      | _ -> Self
  in
  let substitution = { preliminary with tr_self = self } in
  let signature = Subst.st_substitute_visitor#visit_fun_sig substitution declaration.signature in
  let source_body = match declaration.body with
    | StructuredBody body -> Some body
    | _ when is_auths declaration.item_meta.name ->
        invalid_arg "an Auths instance requires its actual structured source body"
    | _ -> None
  in
  let locals_and_body = Option.map (Subst.expr_body_substitute substitution) source_body in
  let inherited_requirements = Subst.predicates_substitute substitution declaration.generics in
  { original_id = declaration.def_id; arguments; call_arguments; self_evidence; signature;
    locals_and_body; source_body; inherited_requirements }

(* Recover the original complete argument/Self context before recreating the
   actual source view. Replaying only the already factored arguments would
   lose their original caller region labels. *)
let replay (declaration : fun_decl) (view : t) =
  try
    let packed = Region_shape.instantiate view.arguments in
    let arguments, self_evidence = match view.self_evidence with
      | None -> packed, None
      | Some _ -> (match List.rev packed.trait_refs with
          | self :: rest -> { packed with trait_refs = List.rev rest }, Some self
          | [] -> invalid_arg "a source instance lost its original complete Self context") in
    create ?self_evidence declaration arguments = view
  with Invalid_argument _ | Not_found -> false
