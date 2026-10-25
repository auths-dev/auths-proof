(* Read-only argument planning on original, polymorphic LLBC. No function body,
   method dispatch, trait definition or lifetime is rewritten. *)
open Charon
open Types
open LlbcAst

let labels name = List.filter_map (function PeIdent (text, _) -> Some text | _ -> None) name

let () =
  if Array.length Sys.argv <> 3 then failwith "usage: argument_shapes ORIGINAL.llbc OUTPUT.json";
  let crate = match OfJson.crate_of_json_file Sys.argv.(1) with
    | Ok crate -> crate | Error message -> failwith message in
  if crate.name <> "auths_gateway" then failwith "argument planning requires the shipping library";
  let root = FunDeclId.Map.bindings crate.fun_decls |> List.find_opt (fun (_, f) ->
    labels f.item_meta.name = ["auths_gateway"; "recipe"; "compile_source_bytes"] && f.item_meta.is_local) in
  let _, root = match root with Some root -> root | None -> failwith "public compiler root absent" in
  let body = match root.body with StructuredBody body -> body | _ -> failwith "public compiler body absent" in
  let fmt = Print.crate_to_fmt_env crate in
  let entries = ref [] in
  let errors = ref [] in
  let visitor = object
    inherit [_] iter_statement
    method! visit_fn_operand _ operand =
      match operand with
      | FnOpDynamic _ -> errors := `String "dynamic function operand requires explicit target resolution" :: !errors
      | FnOpRegular pointer ->
          let target = Print.fn_ptr_to_string fmt pointer in
          try
            let factor = Region_shape.factor pointer.generics in
            let instance = match pointer.kind with
              | FunId (FRegular id) ->
                  let declaration = FunDeclId.Map.find id crate.fun_decls in
                  let view = Instance_view.create declaration pointer.generics in
                  `Assoc [
                    "original_function_id", `Int (FunDeclId.to_int view.original_id);
                    "signature", `String (show_fun_sig view.signature);
                    "structured_body_preserved", `Bool (Option.is_some view.locals_and_body);
                    "inherited_requirements", `String (show_generic_params view.inherited_requirements);
                    "declaration_emitted", `Bool false ]
              | _ -> `Null
            in
            entries := `Assoc [
              "target", `String target;
              "original_arguments", `String (show_generic_args pointer.generics);
              "pattern", `String (show_generic_args factor.pattern);
              "region_arguments", `List (List.map (fun region -> `String (show_region region)) factor.arguments);
              "region_parameter_count", `Int (List.length factor.parameters);
              "exact_round_trip", `Bool true;
              "instance_view", instance ] :: !entries
          with Invalid_argument message ->
            errors := `Assoc ["target", `String target; "error", `String message] :: !errors
  end in
  visitor#visit_block () body.body;
  let report = `Assoc [
    "schema", `String "auths-proof-region-argument-plan/v1";
    "qualified", `Bool false;
    "scope", `String "public-root argument/instance views only; no emitted specialization, trait resolution or program transformation";
    "input", `String Sys.argv.(1);
    "calls", `List (List.rev !entries); "errors", `List (List.rev !errors) ] in
  Yojson.Basic.to_file Sys.argv.(2) report;
  Printf.printf "Public-root argument planning: calls=%d unsupported=%d; unqualified\n%!"
    (List.length !entries) (List.length !errors);
  if !entries = [] || !errors <> [] then exit 2
