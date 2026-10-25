(* Actual prepared frames, not speculative targets from unresolved bodies.
   Each callee is factored only after its caller's complete region equations
   replay and strict declared-bound checks. No declarations are emitted here;
   globals/types, primitive contracts and preserved drops remain explicit. *)
open Charon
open Types
open LlbcAst

module Key = Map.Make (struct
  type t = fun_decl_id * generic_args
  let compare (left, args) (right, other) =
    let ids = FunDeclId.compare_id left right in
    if ids <> 0 then ids else compare_generic_args args other
end)
module GlobalKey = Map.Make (struct
  type t = global_decl_id * generic_args
  let compare (left, args) (right, other) =
    let ids = GlobalDeclId.compare_id left right in
    if ids <> 0 then ids else compare_generic_args args other
end)
module TypeKey = Map.Make (struct
  type t = type_decl_id * generic_args
  let compare (left, args) (right, other) =
    let ids = TypeDeclId.compare_id left right in
    if ids <> 0 then ids else compare_generic_args args other
end)

type target =
  | Instance of int
  | Builtin of builtin_fun_id
  | NoopDestruct of fn_ptr
  | CallableAdapter of Callable_instance.t * target
  | VirtualMethod of Dynamic_method.t
type edge = {
  binding : Function_frame.call_binding;
  target : target;
}
type node = {
  index : int;
  declaration : fun_decl;
  view : Instance_view.t;
  frame : Function_frame.t option;
  callees : edge list;
  globals : int list;
  types : int list;
}
type global_node = {
  global_index : int;
  view : Global_view.t;
  globals : int list;
  initializer_references : (Static_targets.resolved * target) list;
  types : int list;
}
type type_node = {
  type_index : int;
  view : Type_view.t;
  types : int list;
  globals : int list;
  function_references : (Static_targets.resolved * target) list;
}
type type_failure = {
  owner : string;
  reference : type_decl_ref;
  message : string;
}
type global_failure = {
  owner : string;
  reference : global_decl_ref;
  message : string;
}
type failure = {
  instance : int option;
  pointer : fn_ptr;
  message : string;
}
type t = {
  roots : target list;
  adapter_dependencies : target list;
  nodes : node list;
  failures : failure list;
  scheduled : int;
  global_nodes : global_node list;
  global_failures : global_failure list;
  scheduled_globals : int;
  type_nodes : type_node list;
  type_failures : type_failure list;
  scheduled_types : int;
}

let build ?(additional_roots = []) ?(on_view = fun (_ : fun_decl) (_ : Instance_view.t) -> ()) crate pointers =
  let known = ref Key.empty in
  let pending = Queue.create () in
  let next = ref 0 in
  let global_known = ref GlobalKey.empty in
  let global_pending = Queue.create () in
  let next_global = ref 0 in
  let type_known = ref TypeKey.empty in
  let type_pending = Queue.create () in
  let next_type = ref 0 in
  let type_nodes = ref [] in
  let type_failures = ref [] in
  let global_nodes = ref [] in
  let global_failures = ref [] in
  let nodes = ref [] in
  let failures = ref [] in
  let fail instance (pointer : fn_ptr) message =
    failures := { instance; pointer; message } :: !failures;
    let label = match pointer.kind with
      | FunId (FRegular id) -> (match FunDeclId.Map.find_opt id crate.fun_decls with
          | Some declaration -> Print.name_to_string (Print.crate_to_fmt_env crate) declaration.item_meta.name
          | None -> "absent source declaration")
      | _ -> "non-source target" in
    let first_line = match String.split_on_char '\n' message with line :: _ -> line | [] -> message in
    Printf.eprintf "Source closure failure %s at %s: %s\n%s\n%!"
      (match instance with None -> "root" | Some index -> string_of_int index) label first_line message in
  let schedule (pointer : fn_ptr) self_evidence = match pointer.kind with
    | TraitMethod _ -> invalid_arg "an ordinary closure edge must select a source function"
    | FunId (FBuiltin builtin) -> Builtin builtin
    | FunId (FRegular id) ->
        let factor, _, _ = Instance_view.factor_context pointer.generics self_evidence in
        let key = id, factor.pattern in
        let index = match Key.find_opt key !known with
          | Some index -> index
          | None ->
              if !next >= 50000 then invalid_arg "prepared source closure exceeds its construction resource limit";
              let index = !next in
              incr next;
              known := Key.add key index !known;
              Queue.add (index, pointer, self_evidence) pending;
              index in
        Instance index in
  let schedule_dispatch pointer dispatch self_evidence =
    match dispatch with
    | Static_targets.DynamicMethod plan ->
        if not (Dynamic_method.replay crate plan) then
          invalid_arg "a virtual source-closure edge has invalid original interface evidence";
        VirtualMethod plan
    | Static_targets.NoopDestruct -> NoopDestruct pointer
    | Static_targets.FnDefCall plan ->
        if not (Callable_instance.replay crate plan) then
          invalid_arg "a callable source-closure edge has invalid source instantiation evidence";
        let source = Static_targets.resolve crate plan.target in
        (* Keep the original tuple ABI on the edge and schedule the actual
           source definition behind an explicit, still unproved adapter. *)
        CallableAdapter (plan, schedule source.pointer source.self_evidence)
    | _ -> schedule pointer self_evidence in
  let schedule_resolved (resolved : Static_targets.resolved) =
    schedule_dispatch resolved.pointer resolved.dispatch resolved.self_evidence in
  let schedule_global (reference : global_decl_ref) =
    let resolution = Static_targets.resolve_global crate reference in
    let reference = resolution.global_reference in
    let factor = Region_shape.factor reference.generics in
    let key = reference.id, factor.pattern in
    match GlobalKey.find_opt key !global_known with
    | Some index -> index
    | None ->
        if !next_global >= 50000 then invalid_arg "global source closure exceeds its construction resource limit";
        let index = !next_global in
        incr next_global;
        global_known := GlobalKey.add key index !global_known;
        Queue.add (index, resolution) global_pending;
        index in
  let fail_global owner (reference : global_decl_ref) message =
    global_failures := ({ owner; reference; message } : global_failure) :: !global_failures;
    Printf.eprintf "Source global failure from %s: %s\n%!" owner
      (match String.split_on_char '\n' message with first :: _ -> first | [] -> message) in
  let schedule_type (reference : type_decl_ref) =
    let resolution = Type_view.resolve crate reference in
    let id = resolution.declaration.def_id in
    let factor, _, _ = Instance_view.factor_context resolution.reference.generics resolution.self_evidence in
    let key = id, factor.pattern in
    match TypeKey.find_opt key !type_known with
    | Some index -> index
    | None ->
        if !next_type >= 50000 then invalid_arg "source type closure exceeds its construction resource limit";
        let index = !next_type in
        incr next_type;
        type_known := TypeKey.add key index !type_known;
        Queue.add (index, resolution) type_pending;
        index in
  let fail_type owner (reference : type_decl_ref) message =
    type_failures := ({ owner; reference; message } : type_failure) :: !type_failures;
    Printf.eprintf "Source type failure from %s: %s\n%!" owner
      (match String.split_on_char '\n' message with first :: _ -> first | [] -> message) in
  let global_collector owner dependencies types = object
    inherit [_] iter_statement as super
    method! visit_global_decl_ref env reference =
      (try dependencies := schedule_global reference :: !dependencies
       with Invalid_argument message -> fail_global owner reference message);
      super#visit_global_decl_ref env reference
    method! visit_type_decl_ref env reference =
      (match reference.id with
       | TAdtId _ ->
           (try types := schedule_type reference :: !types
            with Invalid_argument message -> fail_type owner reference message)
       | _ -> ());
      super#visit_type_decl_ref env reference
  end in
  let prepare_global () =
    let global_index, resolution = Queue.take global_pending in
    let reference = resolution.Static_targets.global_reference in
    let owner = "global:" ^ string_of_int global_index in
    try
      let view = Global_view.create crate resolution in
      let globals = ref [] in
      let types = ref [] in
      let dependencies = global_collector owner globals types in
      dependencies#visit_ty () view.ty;
      dependencies#visit_constant_expr () view.value;
      dependencies#visit_generic_params () view.inherited_requirements;
      let initializer_references = ref [] in
      let functions = object
        inherit [_] iter_statement as super
        method! visit_fn_ptr env pointer =
          (try
            let resolved = Static_targets.resolve crate pointer in
            let target = schedule_resolved resolved in
            initializer_references := (resolved, target) :: !initializer_references
          with Invalid_argument message -> fail None pointer (owner ^ ": " ^ message));
          super#visit_fn_ptr env pointer
      end in
      functions#visit_ty () view.ty;
      functions#visit_constant_expr () view.value;
      global_nodes := { global_index; view; globals = List.sort_uniq Int.compare !globals;
        types = List.sort_uniq Int.compare !types;
        initializer_references = List.rev !initializer_references } :: !global_nodes
    with Invalid_argument message -> fail_global owner reference message in
  let prepare_type () =
    let type_index, resolution = Queue.take type_pending in
    let reference = resolution.Type_view.reference in
    let owner = "type:" ^ string_of_int type_index in
    try
      let view = Type_view.create crate resolution in
      let globals = ref [] in
      let types = ref [] in
      let dependencies = global_collector owner globals types in
      let function_references = ref [] in
      let functions = object
        inherit [_] iter_statement as super
        method! visit_fn_ptr env pointer =
          (try
            let resolved = Static_targets.resolve crate pointer in
            function_references := (resolved, schedule_resolved resolved) :: !function_references
           with Invalid_argument message -> fail None pointer (owner ^ ": " ^ message));
          super#visit_fn_ptr env pointer
      end in
      let fields = object
        inherit [_] iter_type_decl
        method! visit_ty _ ty =
          dependencies#visit_ty () ty;
          functions#visit_ty () ty
      end in
      fields#visit_type_decl_kind () view.kind;
      (match view.ptr_metadata with
       | NoMetadata | Length -> ()
       | VTable reference ->
           dependencies#visit_type_decl_ref () reference;
           functions#visit_type_decl_ref () reference
       | InheritFrom ty -> dependencies#visit_ty () ty; functions#visit_ty () ty);
      dependencies#visit_generic_params () view.inherited_requirements;
      functions#visit_generic_params () view.inherited_requirements;
      type_nodes := { type_index; view; globals = List.sort_uniq Int.compare !globals;
        types = List.sort_uniq Int.compare !types;
        function_references = List.rev !function_references } :: !type_nodes
    with Invalid_argument message -> fail_type owner reference message in
  let roots = List.filter_map (fun pointer ->
    try
      let resolved = Static_targets.resolve crate pointer in
      Some (schedule_resolved resolved)
    with Invalid_argument message -> fail None pointer message; None) pointers in
  let adapter_dependencies = List.filter_map (fun (source : Static_targets.resolved) ->
    try
      let replay = Static_targets.resolve crate source.pointer in
      if replay.obligations <> [] || replay.self_evidence <> source.self_evidence then
        invalid_arg "an adapter dependency does not replay its exact source Self/where context";
      let factor, _, _ = Instance_view.factor_context replay.pointer.generics replay.self_evidence in
      Closed_arguments.require ~parameters:factor.parameters factor.pattern;
      Some (schedule_resolved replay)
    with Invalid_argument message -> fail None source.pointer ("adapter dependency: " ^ message); None) additional_roots in
  while not (Queue.is_empty pending && Queue.is_empty global_pending && Queue.is_empty type_pending) do
    if Queue.is_empty pending then (
      if not (Queue.is_empty global_pending) then prepare_global () else prepare_type ()
    ) else (
    let index, pointer, self_evidence = Queue.take pending in
    if index mod 128 = 0 then
      Printf.printf "Preparing source instance %d; queued=%d failures=%d\n%!"
        index (Queue.length pending) (List.length !failures);
    try
      let id = match pointer.kind with
        | FunId (FRegular id) -> id
        | _ -> invalid_arg "prepared source queue contains a non-source target" in
      let declaration = match FunDeclId.Map.find_opt id crate.fun_decls with
        | Some declaration -> declaration
        | None -> invalid_arg "prepared source declaration is absent" in
      let view = Instance_view.create ?self_evidence declaration pointer.generics in
      on_view declaration view;
      let frame = match view.locals_and_body with
        | None -> None
        | Some _ -> Some (Function_frame.prepare crate view) in
      let globals = ref [] in
      let types = ref [] in
      let dependencies = global_collector ("function:" ^ string_of_int index) globals types in
      (match frame with
       | None ->
           dependencies#visit_fun_sig () view.signature;
           dependencies#visit_generic_params () view.inherited_requirements
       | Some frame ->
           dependencies#visit_fun_sig () frame.signature;
           dependencies#visit_generic_params () frame.inherited_requirements;
           List.iter (dependencies#visit_local ()) frame.locals;
           dependencies#visit_block () frame.body);
      let callees = match frame with
        | None -> []
        | Some frame -> List.filter_map (fun (binding : Function_frame.call_binding) ->
            try
              let target = schedule_dispatch binding.direct binding.dispatch binding.self_evidence in
              Some { binding; target }
            with Invalid_argument message ->
              fail (Some index) binding.direct message; None) frame.bindings in
      nodes := { index; declaration; view; frame; callees;
        globals = List.sort_uniq Int.compare !globals;
        types = List.sort_uniq Int.compare !types } :: !nodes
    with Invalid_argument message -> fail (Some index) pointer message)
  done;
  { roots; adapter_dependencies; nodes = List.rev !nodes; failures = List.rev !failures; scheduled = !next;
    global_nodes = List.rev !global_nodes; global_failures = List.rev !global_failures;
    scheduled_globals = !next_global;
    type_nodes = List.rev !type_nodes; type_failures = List.rev !type_failures;
    scheduled_types = !next_type }
