(* Isolated actual-source constructor input for the pinned native interpreter.
   This never rewrites a public root/caller or replaces an original declaration.
   The original erased-interface/source/loan refinement remains mandatory. *)
open Charon
open Types
open LlbcAst

type t = {
  source_node : Source_closure.node;
  frame : Function_frame.t;
  source_return : Return_signature.t;
  writer_runtime : Writer_runtime.t option;
  source_generic_arguments : generic_args;
  candidate_generic_arguments : generic_args;
  specialized_region_parameters : region_param list;
  specialized_type_parameters : type_param list;
  specialized_const_parameters : const_generic_param list;
  candidate : fun_decl;
  (* The native interpreter analyzes value representations. Physical pointer
     metadata is preserved separately, with no representation proof supplied. *)
  required_types : TypeDeclId.Set.t;
  metadata_obligations : (type_decl_id * ptr_metadata) list;
  component_declarations : declaration_group list;
}

let members = function NonRecGroup id -> [id] | RecGroup ids -> ids

let derive ?writer_runtime crate ~(node : Source_closure.node) ~candidate_id =
  if FunDeclId.to_int candidate_id < 0 || FunDeclId.Map.mem candidate_id crate.fun_decls then
    invalid_arg "a native constructor candidate needs a fresh declaration identity";
  let frame = match node.frame with Some frame -> frame
    | None -> invalid_arg "the actual source constructor frame is absent" in
  if Function_frame.prepare crate node.view <> frame then
    invalid_arg "the complete actual constructor frame did not replay";
  let source_return = match frame.return_signature with Some candidate -> candidate
    | None -> invalid_arg "the actual source constructor has no erased-return witness" in
  if not (Return_signature.replay crate source_return) then
    invalid_arg "the original source closure-return witness did not replay";
  if node.declaration.src <> TopLevelItem || node.declaration.is_global_initializer <> None then
    invalid_arg "this isolated native constructor cannot reclassify a method, closure body or global initializer";
  if frame.bindings <> [] || frame.global_bindings <> [] || frame.preserved_drops <> [] ||
      frame.primitive_contracts <> [] || frame.callable_calls <> [] || frame.dynamic_calls <> [] then
    invalid_arg "a native closure constructor with calls/globals/drops needs its complete native dependency emission";
  let requirements = frame.inherited_requirements in
  if node.view.self_evidence <> None then
    invalid_arg "a native constructor with a separate Self argument needs its complete original argument unpacking";
  let source_generic_arguments = Region_shape.instantiate node.view.arguments in
  let candidate_generic_arguments = node.view.arguments.pattern in
  Static_targets.require_argument_arity node.declaration.generics source_generic_arguments;
  Static_targets.require_argument_arity node.declaration.generics candidate_generic_arguments;
  (* The original arguments retain the caller's body/outer labels. Only the
     factored pattern lives in this candidate's parameter scope. Instance_view
     and Region_shape retain/replay their complete exact reconstruction. *)
  if not (Instance_view.replay node.declaration node.view) then
    invalid_arg "native constructor argument scopes lost their original source reconstruction";
  Closed_arguments.require ~parameters:node.view.arguments.parameters candidate_generic_arguments;
  (* predicates_substitute retains the original declaration-only type/const
     parameter lists after specializing their uses. Remove those declarations
     only under the full original argument binding and an escape check over
     every resulting predicate, signature, local and body instruction. Every
     semantic predicate, including closed trait requirements, is retained. *)
  let generics = { requirements with regions = node.view.arguments.parameters; types = []; const_generics = [] } in
  let source_body = frame.source_body in
  if source_body.locals.arg_count <> List.length frame.signature.inputs then
    invalid_arg "the native constructor cannot change its source input arity";
  let body = { source_body with locals = { source_body.locals with locals = frame.locals }; body = frame.body } in
  let closed = new Closed_arguments.statement_check
    ~body_regions:body.bound_body_regions node.view.arguments.parameters in
  closed#visit_generic_params [] generics;
  closed#visit_fun_sig [] frame.signature;
  List.iter (closed#visit_local []) frame.locals;
  closed#visit_block [] frame.body;
  let candidate = { node.declaration with def_id = candidate_id; generics; signature = frame.signature;
    item_meta = { node.declaration.item_meta with name = node.declaration.item_meta.name @
      [PeIdent ("__auths_source_capture_candidate_" ^ string_of_int node.index, Disambiguator.of_int 0)] };
    body = StructuredBody body } in
  let native = match writer_runtime with None -> crate | Some witness -> Writer_runtime.native_view crate witness in
  let needed = ref TypeDeclId.Set.empty in
  let metadata_obligations = ref [] in
  let pending = ref [] in
  let add id = if not (TypeDeclId.Set.mem id !needed) then (
    needed := TypeDeclId.Set.add id !needed; pending := id :: !pending) in
  let collect = object inherit [_] iter_statement as super
    method! visit_type_decl_ref env reference =
      (match reference.id with TAdtId id -> add id | _ -> ());
      super#visit_type_decl_ref env reference
    method! visit_ty env ty =
      (match ty with
       | TDynTrait _ -> invalid_arg "the isolated native constructor still requires dynamic value/loan semantics; the pinned type-analysis dyn shortcut is not usable"
       | TFnPtr _ | TFnDef _ -> invalid_arg "the isolated native constructor still requires actual native function-value semantics"
       | TError _ -> invalid_arg "the isolated native constructor contains a source type error"
       | _ -> ());
      super#visit_ty env ty
  end in
  collect#visit_generic_params () generics;
  collect#visit_fun_sig () candidate.signature;
  List.iter (collect#visit_local ()) frame.locals;
  collect#visit_block () frame.body;
  let scanned = ref TypeDeclId.Set.empty in
  let rec close () =
    (match !pending with
     | id :: rest ->
         pending := rest;
         if not (TypeDeclId.Set.mem id !scanned) then (
           scanned := TypeDeclId.Set.add id !scanned;
           let declaration = match TypeDeclId.Map.find_opt id native.type_decls with Some declaration -> declaration
             | None -> invalid_arg "a required actual constructor type declaration is absent" in
           (try
              let source_scope = new Region_scope.declaration_check declaration.generics.regions in
              source_scope#visit_generic_params [] declaration.generics;
              source_scope#visit_type_decl_kind [] declaration.kind;
              source_scope#visit_ptr_metadata [] declaration.ptr_metadata;
              collect#visit_generic_params () declaration.generics;
              collect#visit_type_decl_kind () declaration.kind
            with Invalid_argument message -> invalid_arg ("required native value type " ^
              string_of_int (TypeDeclId.to_int id) ^ ": " ^ message));
           (* Aeneas TypesAnalysis follows the value kind, not physical
              pointer metadata. Keep this complete source boundary as an
              undischarged obligation rather than treating a vtable layout as
              a value field or invoking the backend's dyn shortcut. The
              original declaration/map and metadata are never rewritten. *)
           metadata_obligations := (id, declaration.ptr_metadata) :: !metadata_obligations);
         close ()
     | [] ->
         (* Preserve complete source SCCs, never split recursive type groups. *)
         List.iter (function
           | TypeGroup group when List.exists (fun id -> TypeDeclId.Set.mem id !needed) (members group) -> List.iter add (members group)
           | MixedGroup group when List.exists (function IdType id -> TypeDeclId.Set.mem id !needed | _ -> false) (members group) ->
               invalid_arg "the native constructor type closure needs an original mixed declaration group"
           | _ -> ()) native.declarations;
         if !pending <> [] then close ()) in
  close ();
  let covered = ref TypeDeclId.Set.empty in
  let type_groups = List.filter_map (function
    | TypeGroup group as original when List.exists (fun id -> TypeDeclId.Set.mem id !needed) (members group) ->
        List.iter (fun id -> covered := TypeDeclId.Set.add id !covered) (members group); Some original
    | _ -> None) native.declarations in
  if not (TypeDeclId.Set.equal !covered !needed) then
    invalid_arg "the native constructor cannot omit a required type absent from its original declaration groups";
  let scope = new Region_scope.statement_check ~body_regions:body.bound_body_regions generics.regions in
  scope#visit_generic_params [] generics;
  scope#visit_fun_sig [] candidate.signature;
  List.iter (scope#visit_local []) frame.locals;
  scope#visit_block [] frame.body;
  { source_node = node; frame; source_return; writer_runtime; source_generic_arguments;
    candidate_generic_arguments; specialized_region_parameters = requirements.regions;
    specialized_type_parameters = requirements.types;
    specialized_const_parameters = requirements.const_generics;
    candidate; required_types = !needed; metadata_obligations = List.rev !metadata_obligations;
    component_declarations = type_groups @ [FunGroup (NonRecGroup candidate_id)] }

let replay crate witness =
  try derive ?writer_runtime:witness.writer_runtime crate ~node:witness.source_node ~candidate_id:witness.candidate.def_id = witness
  with Invalid_argument _ | Not_found -> false

let create ?writer_runtime crate ~node ~candidate_id =
  let witness = derive ?writer_runtime crate ~node ~candidate_id in
  if not (replay crate witness) then invalid_arg "the complete isolated native constructor did not replay";
  witness

let component_crate crate witness =
  if not (replay crate witness) then invalid_arg "the native component lost its source constructor before interpretation";
  let native = match witness.writer_runtime with None -> crate | Some runtime -> Writer_runtime.native_view crate runtime in
  { native with declarations = witness.component_declarations;
    fun_decls = FunDeclId.Map.add witness.candidate.def_id witness.candidate crate.fun_decls;
    item_names = (IdFun witness.candidate.def_id, witness.candidate.item_meta.name) :: native.item_names;
    short_names = (IdFun witness.candidate.def_id, witness.candidate.item_meta.name) :: native.short_names }
