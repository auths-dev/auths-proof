(* Read-only construction view of selected actual source declarations through
   the pinned parser. This emits no transformed program or proof evidence. *)
open Charon
open Types
open LlbcAst
open Diagnostic

let contains text part =
  let rec search offset =
    offset + String.length part <= String.length text &&
    (String.sub text offset (String.length part) = part || search (offset + 1)) in
  search 0

let () =
  if Array.length Sys.argv <> 5 then
    failwith "usage: source_slice SOURCE.llbc function|implementation|type|global|vtable-injections|indirect-calls NAME-SUBSTRING-or-#ID OUTPUT.json";
  let crate = match OfJson.crate_of_json_file Sys.argv.(1) with
    | Ok crate -> crate | Error message -> failwith message in
  let fmt = Print.crate_to_fmt_env crate in
  let next_candidate = ref (match FunDeclId.Map.max_binding_opt crate.fun_decls with
    | Some (id, _) -> FunDeclId.to_int id | None -> -1) in
  let fresh_candidate () =
    if !next_candidate >= Int.max_int then invalid_arg "candidate function IDs exceed the construction identifier space";
    incr next_candidate; FunDeclId.of_int !next_candidate in
  let text value = `String value in
  let selected name = contains (Print.name_to_string fmt name) Sys.argv.(3) in
  let selected_id id name = selected name || Sys.argv.(3) = "#" ^ string_of_int id in
  let values = match Sys.argv.(2) with
    | "indirect-calls" -> FunDeclId.Map.bindings crate.fun_decls |> List.filter_map (fun (id, (declaration : fun_decl)) ->
        if Sys.argv.(3) <> "*" && not (selected_id (FunDeclId.to_int id) declaration.item_meta.name) then None else
        match declaration.body with
        | StructuredBody body ->
            let calls = ref [] in
            let collect = object
              inherit [_] iter_statement as super
              method! visit_statement env (statement : statement) =
                (match statement.kind with
                 | Call (({ func = FnOpDynamic _; _ } as call), _) ->
                     calls := `Assoc ["statement_id", `Int (StatementId.to_int statement.statement_id);
                       "call", text (show_call call);
                       "source_vtable_dispatch", (try
                         let dispatch = Vtable_dispatch.create crate ~caller:declaration statement in
                         `Assoc ["lineage", Vtable_dispatch.report crate dispatch;
                           "concrete_caller_shim_families", `List (List.map (fun branch ->
                             let caller_id = fresh_candidate () in
                             let shim_id = fresh_candidate () in
                             try Vtable_specialization.report crate
                               (Vtable_specialization.create crate ~dispatch ~branch ~caller_id ~shim_id)
                             with Invalid_argument message -> `Assoc ["error", text message;
                               "qualified", `Bool false; "program_emitted", `Bool false]) dispatch.available_source_branches)]
                         with Invalid_argument message -> `Assoc ["error", text message;
                           "qualified", `Bool false; "program_emitted", `Bool false])] :: !calls
                 | _ -> ());
                super#visit_statement env statement
            end in
            collect#visit_block () body.body;
            if !calls = [] then None else Some (`Assoc ["id", `Int (FunDeclId.to_int id);
              "name", text (Print.name_to_string fmt declaration.item_meta.name);
              "source", text (show_item_source declaration.src);
              "parameters", text (show_generic_params declaration.generics);
              "signature", text (show_fun_sig declaration.signature);
              "body_regions", `Int body.bound_body_regions;
              "locals", `List (List.map (fun local -> text (show_local local)) body.locals.locals);
              "body", text (show_block body.body);
              "calls", `List (List.rev !calls)])
        | _ -> None)
    | "vtable-injections" -> FunDeclId.Map.bindings crate.fun_decls |> List.filter_map (fun (id, (declaration : fun_decl)) ->
        if Sys.argv.(3) <> "*" && not (selected_id (FunDeclId.to_int id) declaration.item_meta.name) then None else
        match declaration.body with
        | StructuredBody body ->
            let injections = ref [] in
            let collect = object
              inherit [_] iter_statement as super
              method! visit_statement env (statement : statement) =
                (match statement.kind with
                 | Assign (destination, Expressions.UnaryOp (Expressions.Cast
                     (Expressions.CastUnsize (from_ty, into_ty, (MetaVTable _ as metadata))), operand)) ->
                     injections := `Assoc ["statement_id", `Int (StatementId.to_int statement.statement_id);
                       "destination", text (show_place destination);
                       "from", text (show_ty from_ty); "into", text (show_ty into_ty);
                       "metadata", text (show_unsizing_metadata metadata);
                       "operand", text (show_operand operand);
                       "source_injection_binding", (try Vtable_injection.report crate
                         (Vtable_injection.create crate ~caller:declaration statement)
                         with Invalid_argument message -> `Assoc ["error", text message;
                           "qualified", `Bool false; "program_emitted", `Bool false])] :: !injections
                 | _ -> ());
                super#visit_statement env statement
            end in
            collect#visit_block () body.body;
            if !injections = [] then None else Some (`Assoc ["id", `Int (FunDeclId.to_int id);
              "name", text (Print.name_to_string fmt declaration.item_meta.name);
              "parameters", text (show_generic_params declaration.generics);
              "signature", text (show_fun_sig declaration.signature);
              "body_regions", `Int body.bound_body_regions;
              "injections", `List (List.rev !injections)])
        | _ -> None)
    | "function" -> FunDeclId.Map.bindings crate.fun_decls |> List.filter_map (fun (id, (declaration : fun_decl)) ->
        if not (selected_id (FunDeclId.to_int id) declaration.item_meta.name) then None else
        Some (`Assoc ["id", `Int (FunDeclId.to_int id);
          "name", text (Print.name_to_string fmt declaration.item_meta.name);
          "source", text (show_item_source declaration.src);
          "parameters", text (show_generic_params declaration.generics);
          "signature", text (show_fun_sig declaration.signature);
          "locals", (match declaration.body with StructuredBody body ->
            `List (List.map (fun local -> text (show_local local)) body.locals.locals) | _ -> `Null);
          "pretty_body", (match declaration.body with StructuredBody body ->
            text (Print.Llbc.block_to_string fmt "" "  " body.body) | _ -> `Null);
          "body", (match declaration.body with
            | StructuredBody body -> text (show_block body.body)
            | _ -> `Null)]))
    | "implementation" -> TraitImplId.Map.bindings crate.trait_impls |> List.filter_map (fun (id, (declaration : trait_impl)) ->
        if not (selected_id (TraitImplId.to_int id) declaration.item_meta.name) then None else
        Some (`Assoc ["id", `Int (TraitImplId.to_int id);
          "name", text (Print.name_to_string fmt declaration.item_meta.name);
          "parameters", text (show_generic_params declaration.generics);
          "predicate", text (show_trait_decl_ref declaration.impl_trait);
          "methods", `List (TraitMethodId.Map.bindings declaration.methods |> List.map (fun (id, method_) ->
            `Assoc ["id", `Int (TraitMethodId.to_int id); "parameters", text (show_generic_params method_.binder_params);
              "source_pointer", text (show_fun_decl_ref method_.binder_value)]));
          "associated_types", `List (AssocTypeId.Map.bindings declaration.types |> List.map (fun (id, body) ->
            `Assoc ["id", `Int (AssocTypeId.to_int id);
              "parameters", text (show_generic_params body.binder_params);
              "value", text (show_trait_assoc_ty_impl body.binder_value)]));
          "parents", `List (List.map (fun value -> text (show_trait_ref value)) declaration.implied_trait_refs)]))
    | "type" -> TypeDeclId.Map.bindings crate.type_decls |> List.filter_map (fun (id, (declaration : type_decl)) ->
        if not (selected_id (TypeDeclId.to_int id) declaration.item_meta.name) then None else
        Some (`Assoc ["id", `Int (TypeDeclId.to_int id);
          "name", text (Print.name_to_string fmt declaration.item_meta.name);
          "source", text (show_item_source declaration.src);
          "parameters", text (show_generic_params declaration.generics);
          "kind", text (show_type_decl_kind declaration.kind);
          "generated_vtable_representation", (match declaration.src with
            | VTableTyItem _ ->
                (try Vtable_shape.report (Vtable_shape.create crate declaration)
                 with Invalid_argument message -> `Assoc ["error", text message;
                   "source_provenance_gate_relaxed", `Bool false; "qualified", `Bool false])
            | _ -> `Null);
          "pointer_metadata", text (show_ptr_metadata declaration.ptr_metadata)]))
    | "global" -> GlobalDeclId.Map.bindings crate.global_decls |> List.filter_map (fun (id, (declaration : global_decl)) ->
        if not (selected_id (GlobalDeclId.to_int id) declaration.item_meta.name) then None else
        Some (`Assoc ["id", `Int (GlobalDeclId.to_int id);
          "name", text (Print.name_to_string fmt declaration.item_meta.name);
          "source", text (show_item_source declaration.src);
          "parameters", text (show_generic_params declaration.generics);
          "type", text (show_ty declaration.ty);
          "generated_vtable_initializer", (match declaration.src with
            | VTableInstanceItem _ ->
                (try Vtable_initializer.report (Vtable_initializer.create crate declaration)
                 with Invalid_argument message -> `Assoc ["error", text message;
                   "qualified", `Bool false; "source_program_emitted", `Bool false])
            | _ -> `Null);
          "value", text (show_constant_expr declaration.value)]))
    | _ -> invalid_arg "unsupported source declaration kind" in
  let fields = ["schema", text "auths-proof-source-declaration-slice/v1";
    "input", text Sys.argv.(1); "selector", text Sys.argv.(3);
    "qualified", `Bool false; "program_emitted", `Bool false;
    "declarations", `List values] in
  let report = `Assoc (fields @ ["source_file_table", source_files_json ()]) in
  let output = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 Sys.argv.(4) in
  Fun.protect ~finally:(fun () -> close_out output) (fun () -> Yojson.Basic.pretty_to_channel output report)
