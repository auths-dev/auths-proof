(* Construct instance candidates from actual raw injection seeds. Prepared
   source graphs can supply further Global_view instances to Vtable_instance.
   Unclosed seeds and unmatched traits remain explicit; this is not a closed
   whole-program, reachability, ownership, source-simulation or proof gate. *)
open Charon
open Types
open LlbcAst
open Diagnostic

let () =
  if Array.length Sys.argv <> 3 then failwith "usage: vtable_instances_plan SOURCE.llbc OUTPUT.json";
  let crate = match OfJson.crate_of_json_file Sys.argv.(1) with
    | Ok crate -> crate | Error message -> failwith message in
  if crate.name <> "auths_gateway" then failwith "vtable instance construction requires the actual shipping gateway crate";
  let next = ref (match FunDeclId.Map.max_binding_opt crate.fun_decls with Some (id, _) -> FunDeclId.to_int id | None -> -1) in
  let fresh () = if !next >= Int.max_int then invalid_arg "candidate declaration IDs exceed construction space";
    incr next; FunDeclId.of_int !next in
  let injections = ref [] and dispatches = ref [] and failures = ref [] in
  let error kind function_id statement_id message = `Assoc ["kind", `String kind;
    "function", `Int (FunDeclId.to_int function_id); "statement", `Int (StatementId.to_int statement_id);
    "error", `String message; "qualified", `Bool false] in
  FunDeclId.Map.iter (fun id (declaration : fun_decl) -> match declaration.body with
    | StructuredBody body ->
        let collect = object inherit [_] iter_statement as super
          method! visit_statement env (statement : statement) =
            (match statement.kind with
             | Assign (_, Expressions.UnaryOp (Expressions.Cast (Expressions.CastUnsize (_, _, MetaVTable _)), _)) ->
                 (try injections := Vtable_injection.create crate ~caller:declaration statement :: !injections
                  with Invalid_argument message -> failures := error "injection" id statement.statement_id message :: !failures)
             | Call ({ func = FnOpDynamic _; _ }, _) ->
                 (try dispatches := Vtable_dispatch.create crate ~caller:declaration statement :: !dispatches
                  with Invalid_argument message -> failures := error "dispatch" id statement.statement_id message :: !failures)
             | _ -> ());
            super#visit_statement env statement
        end in collect#visit_block () body.body
    | _ -> ()) crate.fun_decls;
  let injections = List.rev !injections and dispatches = List.rev !dispatches in
  let instances = ref [] and applications = ref [] and pending = ref [] and matched = ref [] in
  List.iter (fun (dispatch : Vtable_dispatch.t) -> List.iter (fun (branch : Vtable_dispatch.branch) ->
    let caller_id = fresh () in let shim_id = fresh () in
    try
      let family = Vtable_specialization.create crate ~dispatch ~branch ~caller_id ~shim_id in
      let known = ref Source_closure.GlobalKey.empty in
      List.iter (fun (injection : Vtable_injection.t) ->
        if injection.global_reference.id = branch.source_vtable.global.def_id then (
          matched := (injection.caller.def_id, injection.source_statement.statement_id) :: !matched;
          let boundary = ref "non_region_capture_closure" in
          try
            let factor = Region_shape.factor injection.global_reference.generics in
            Closed_arguments.require ~parameters:factor.parameters factor.pattern;
            boundary := "strict_actual_global";
            let resolution = Static_targets.resolve_global crate injection.global_reference in
            let source_global = Global_view.create crate resolution in
            let key = source_global.declaration.def_id, source_global.call_arguments in
            boundary := "captured_native_instance";
            let caller_id, shim_id = match Source_closure.GlobalKey.find_opt key !known with
              | Some pair -> pair
              | None ->
                  let caller_id = fresh () in let shim_id = fresh () in
                  let instance = Vtable_instance.create crate ~family ~source_global ~caller_id ~shim_id in
                  known := Source_closure.GlobalKey.add key (caller_id, shim_id) !known;
                  instances := Vtable_instance.report crate instance :: !instances;
                  caller_id, shim_id in
            applications := `Assoc ["source_function", `Int (FunDeclId.to_int injection.caller.def_id);
              "source_statement", `Int (StatementId.to_int injection.source_statement.statement_id);
              "actual_source_global", `String (show_generic_args injection.global_reference.generics);
              "normalized_source_global", `String (show_generic_args source_global.call_arguments);
              "source_capture_arguments", `List (List.map (fun region -> `String (show_region region)) source_global.arguments.arguments);
              "caller_candidate", `Int (FunDeclId.to_int caller_id); "shim_candidate", `Int (FunDeclId.to_int shim_id);
              "payload_value_and_region_application_simulation_proved", `Bool false] :: !applications
          with Invalid_argument message -> pending := `Assoc ["boundary", `String !boundary;
            "global", `Int (GlobalDeclId.to_int injection.global_reference.id);
            "source", error "capture" injection.caller.def_id injection.source_statement.statement_id message;
            "requires_prepared_source_instance_or_explicit_boundary_work", `Bool true] :: !pending
        )) injections
    with Invalid_argument message -> failures := error "family" dispatch.caller.def_id dispatch.source_statement.statement_id message :: !failures
  ) dispatch.available_source_branches) dispatches;
  let unmatched = List.filter (fun (injection : Vtable_injection.t) ->
    not (List.mem (injection.caller.def_id, injection.source_statement.statement_id) !matched)) injections in
  let report = `Assoc ["schema", `String "auths-proof-vtable-source-instance-construction/v1";
    "input", `String Sys.argv.(1); "qualified", `Bool false; "program_emitted", `Bool false; "tests_run", `Bool false;
    "scope", `String "raw actual injection seeds; prepared graph and whole native execution remain required";
    "source_injections", `Int (List.length injections); "source_dispatches", `Int (List.length dispatches);
    "closed_capture_instances", `List (List.rev !instances); "source_applications", `List (List.rev !applications);
    "pending_captures", `List (List.rev !pending);
    "unmatched_source_traits", `List (List.map (fun (injection : Vtable_injection.t) -> `Assoc [
      "source_function", `Int (FunDeclId.to_int injection.caller.def_id);
      "source_statement", `Int (StatementId.to_int injection.source_statement.statement_id);
      "source_global", `Int (GlobalDeclId.to_int injection.global_reference.id);
      "source_carrier", `String (show_ty injection.into_type);
      "actual_dispatch_or_ordinary_interface_binding_required", `Bool true]) unmatched);
    "construction_failures", `List (List.rev !failures); "source_file_table", source_files_json ()] in
  let output = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 Sys.argv.(2) in
  Fun.protect ~finally:(fun () -> close_out output) (fun () -> Yojson.Basic.pretty_to_channel output report);
  Printf.printf "Source instance construction: injections=%d dispatches=%d instances=%d applications=%d pending=%d unmatched=%d failures=%d; unqualified\n%!"
    (List.length injections) (List.length dispatches) (List.length !instances) (List.length !applications)
    (List.length !pending) (List.length unmatched) (List.length !failures)
