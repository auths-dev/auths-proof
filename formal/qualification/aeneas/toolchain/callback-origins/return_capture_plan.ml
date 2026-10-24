(* Actual source constructor -> Lean command data and ordinary-kernel proofs.
   This emits a component certificate, never a native function/program or a
   qualification result. The native opaque-interface/loan gates remain. *)
open Charon
open Types
open Expressions
open LlbcAst

let numbers values = "[" ^ String.concat ", " (List.map string_of_int values) ^ "]"
let commands (candidate : Return_signature.t) =
  let body = match candidate.view.locals_and_body with Some (_, body) -> body
    | None -> invalid_arg "the actual source capture body is absent" in
  List.map (fun (statement : statement) ->
    let command = match statement.kind with
      | StorageLive id when LocalId.to_int id = 0 -> ".openReturn"
      | Assign ({ kind = PlaceLocal id; _ }, Aggregate (AggregatedAdt (_, None, None), operands))
          when LocalId.to_int id = 0 && statement = candidate.source_aggregate ->
          let indices = List.map (function Move { kind = PlaceLocal id; _ } when LocalId.to_int id > 0 -> LocalId.to_int id - 1
            | _ -> invalid_arg "a source capture certificate cannot replace a moved parameter") operands in
          ".capture " ^ numbers indices
      | StorageDead id when LocalId.to_int id > 0 -> ".endInput " ^ string_of_int (LocalId.to_int id - 1)
      | Return when statement = candidate.source_return -> ".finish"
      | Nop -> ".nop"
      | _ -> invalid_arg "the actual source capture contains a command outside the proved local-move subset" in
    statement.statement_id, command) body.statements

(* Emit the original local numbers, nominal identity and move operands too.
   Lean checks the source-to-command lowering; command text is not the sole
   representation of the source operation in the certificate. *)
let source_syntax (candidate : Return_signature.t) =
  let body = match candidate.view.locals_and_body with Some (_, body) -> body
    | None -> invalid_arg "the original closure capture source is absent" in
  let nominal = match candidate.original_output.id with TAdtId id -> TypeDeclId.to_int id
    | _ -> invalid_arg "a source capture certificate needs its actual nominal closure identity" in
  let instructions = List.map (fun (statement : statement) ->
    let instruction = match statement.kind with
      | StorageLive id -> ".storageLive " ^ string_of_int (LocalId.to_int id)
      | StorageDead id -> ".storageDead " ^ string_of_int (LocalId.to_int id)
      | Assign ({ kind = PlaceLocal destination; _ }, Aggregate (AggregatedAdt ({ id = TAdtId actual; _ }, None, None), fields))
          when statement = candidate.source_aggregate ->
          let operands = List.map (function Move { kind = PlaceLocal id; _ } ->
              ".move (.local " ^ string_of_int (LocalId.to_int id) ^ ")"
            | _ -> invalid_arg "the source syntax certificate cannot replace an actual whole-local move") fields in
          ".assignClosure (.local " ^ string_of_int (LocalId.to_int destination) ^ ") " ^
            string_of_int (TypeDeclId.to_int actual) ^ " [" ^ String.concat ", " operands ^ "]"
      | Return when statement = candidate.source_return -> ".returnValue"
      | Nop -> ".nop"
      | _ -> invalid_arg "the original constructor has a source instruction outside the restricted certificate syntax" in
    "⟨" ^ string_of_int (StatementId.to_int statement.statement_id) ^ ", " ^ instruction ^ "⟩"
  ) body.statements in
  nominal, instructions

let () =
  if Array.length Sys.argv <> 4 then invalid_arg "usage: return_capture_plan SOURCE.llbc ROOT-ARGUMENTS.json OUTPUT.lean";
  let crate = match OfJson.crate_of_json_file Sys.argv.(1) with Ok crate -> crate | Error message -> invalid_arg message in
  let names = Yojson.Basic.from_file Sys.argv.(2) |> Yojson.Basic.Util.member "roots" |> Yojson.Basic.Util.to_list
    |> List.map Yojson.Basic.Util.to_string in
  let graph, _, _ = Vtable_graph.close_source_dependencies crate (Source_roots.pointers crate names) in
  let candidates = List.filter_map (fun (node : Source_closure.node) -> match node.frame with
    | Some frame -> Option.map (fun candidate -> node.index, candidate) frame.return_signature
    | None -> None) graph.nodes in
  if candidates = [] then invalid_arg "the complete actual source graph has no matched erased-return capture constructor";
  (* Construct every checked witness and the entire certificate before creating
     the output. A refused later witness must not leave a plausible partial
     certificate available for a subsequent build. *)
  let buffer = Buffer.create 8192 in
  let line text = Buffer.add_string buffer (text ^ "\n") in
    line "import Auths.Support.SourceClosureSyntax";
    line "import Auths.Support.SourceClosureRegions";
    line "";
    line "/- Generated from actual complete-source Return_signature witnesses. Construction only.";
    line "   Native LLBC/subset/typed-reference/opaque-signature/loan refinement remains required.";
    line "   No Lean elaboration, tests or qualification are run by this emitter. -/";
    line "namespace Auths.Qualification.SourceClosureCapture";
    line "open Auths.Support.SourceClosureCapture";
    line "open Auths.Support.SourceClosureSyntax";
    line "open Auths.Support.SourceClosureRegions";
    line "universe u";
    List.iteri (fun ordinal (node, (candidate : Return_signature.t)) ->
      if not (Return_signature.replay crate candidate) then invalid_arg "the actual source capture witness changed before certificate emission";
      let instructions = commands candidate in
      let nominal, syntax = source_syntax candidate in
      let regions = Return_region_certificate.derive crate candidate in
      let arity = List.length candidate.original.inputs in
      let mapping = List.map (fun (capture : Return_signature.capture) -> capture.parameter_index) candidate.captures in
      let scope = "Constructor" ^ string_of_int ordinal in
      let values = List.init arity (fun index -> "input" ^ string_of_int index) in
      let arguments = String.concat " " values in
      let value_list indices = "[" ^ String.concat ", " (List.map (List.nth values) indices) ^ "]" in
      let source_values indices = "[" ^ String.concat ", " (List.map (fun index -> ".input " ^ List.nth values index) indices) ^ "]" in
      line ""; line ("namespace " ^ scope);
      line ("-- Input-local source function " ^ string_of_int (FunDeclId.to_int candidate.view.original_id) ^
        ", prepared node " ^ string_of_int node ^ "; original statement identities below.");
      line ("def sourceStatements : List Nat := " ^ numbers (List.map (fun (id, _) -> StatementId.to_int id) instructions));
      line ("def inputArity : Nat := " ^ string_of_int arity);
      line ("def capturedParameters : List Nat := " ^ numbers mapping);
      line ("def sourceProgram : List Command := [" ^ String.concat ", " (List.map snd instructions) ^ "]");
      line ("def nominalClosure : Nat := " ^ string_of_int nominal);
      line ("def sourceSyntax : List Statement := [" ^ String.concat ", " syntax ^ "]");
      line "theorem source_statement_identities_exact : sourceSyntax.map Statement.identity = sourceStatements := by decide";
      line "theorem source_statement_identities_unique : (sourceSyntax.map Statement.identity).Nodup := by decide";
      line "theorem source_lowering_exact : lower inputArity nominalClosure sourceSyntax = some sourceProgram := by decide";
      line "theorem captured_parameters_cover_inputs : capturedParameters.Perm (List.range inputArity) := by decide";
      line "theorem source_typed_parameter_pairing :";
      line "    sourceProgram.filterMap (fun command => match command with";
      line "      | .capture parameters => some parameters | _ => none) = [capturedParameters] := by decide";
      line ("def publicRegionParameters : List Nat := " ^ numbers regions.public_parameters);
      line ("def originalReturnRegions : List Region := " ^ Return_region_certificate.regions regions.original_regions);
      line ("def reconstructedReturnRegions : List Region := " ^ Return_region_certificate.regions regions.reconstructed_regions);
      line ("def sourceDeclaredInputTypes : List Expr := " ^ Return_region_certificate.expressions regions.declared_inputs);
      line ("def sourceFieldTypePatterns : List Expr := " ^ Return_region_certificate.expressions regions.field_patterns);
      line ("def originalReturnType : Expr := " ^ Return_region_certificate.lean regions.original_output);
      line ("def reconstructedReturnType : Expr := " ^ Return_region_certificate.lean regions.reconstructed_output);
      line "theorem original_return_regions_exact : outputRegions originalReturnType = some originalReturnRegions := by decide";
      line "theorem output_lifetimes_derived_from_moved_inputs :";
      line "    reconstruct publicRegionParameters originalReturnRegions sourceFieldTypePatterns";
      line "      sourceDeclaredInputTypes capturedParameters = some reconstructedReturnRegions := by decide";
      line "theorem complete_return_type_reconstruction_exact :";
      line "    reconstructOutput publicRegionParameters originalReturnType sourceFieldTypePatterns";
      line "      sourceDeclaredInputTypes capturedParameters = some reconstructedReturnType := by decide";
      List.iter (fun (completion : Return_signature.completion) ->
        let wrong = if completion.actual = RStatic then ".body 0" else ".literalStatic" in
        line ("theorem guessed_output_slot_" ^ string_of_int completion.output_region_index ^ "_refused :");
        line "    reconstructOutput publicRegionParameters originalReturnType sourceFieldTypePatterns";
        line "      sourceDeclaredInputTypes capturedParameters ≠";
        line ("      completeOutput originalReturnType (reconstructedReturnRegions.set " ^
          string_of_int completion.output_region_index ^ " (" ^ wrong ^ ")) := by");
        line "  rw [complete_return_type_reconstruction_exact]";
        line "  decide"
      ) candidate.completions;
      line "theorem source_field_order_exact {Value : Type u}";
      line ("    (" ^ arguments ^ " : Value) : returnedFields sourceProgram " ^ value_list (List.init arity Fun.id) ^ " =");
      line ("      some " ^ value_list mapping ^ " := by");
      line "  simp [returnedFields, run, step, moveInputs, clearInput, initial, sourceProgram]";
      line "theorem original_source_return_exact {Value : Type u}";
      line ("    (" ^ arguments ^ " : Value) : sourceResult sourceSyntax " ^ value_list (List.init arity Fun.id) ^ " =");
      line ("      some (.closure nominalClosure " ^ source_values mapping ^ ") := by");
      line "  simp [sourceResult, sourceRun, sourceStep, moveFields, writeLocal, initialState, sourceSyntax, nominalClosure]";
      line "theorem original_source_and_commands_agree {Value : Type u}";
      line ("    (" ^ arguments ^ " : Value) :");
      line ("    (sourceResult sourceSyntax " ^ value_list (List.init arity Fun.id) ^ ").bind (observedFields nominalClosure) =");
      line ("      returnedFields sourceProgram " ^ value_list (List.init arity Fun.id) ^ " := by");
      line ("  rw [original_source_return_exact " ^ arguments ^ ", source_field_order_exact " ^ arguments ^ "]");
      line "  simp [observedFields, inputFields]";
      List.iter (fun index ->
        line ("theorem source_input_" ^ string_of_int index ^ "_consumed {Value : Type u} (" ^ arguments ^ " : Value) :");
        line ("    (run sourceProgram (initial " ^ value_list (List.init arity Fun.id) ^ ")).map");
        line ("      (fun after => after.inputs " ^ string_of_int index ^ ") = some none := by");
        line "  simp [run, step, moveInputs, clearInput, initial, sourceProgram]";
        line ("theorem original_input_" ^ string_of_int index ^ "_consumed {Value : Type u} (" ^ arguments ^ " : Value) :");
        line ("    (sourceRun sourceSyntax (initialState " ^ value_list (List.init arity Fun.id) ^ ")).map");
        line ("      (fun after => after.locals " ^ string_of_int (index + 1) ^ ") = some none := by");
        line "  simp [sourceRun, sourceStep, moveFields, writeLocal, initialState, sourceSyntax]";
        line ("theorem original_input_" ^ string_of_int index ^ "_storage_ended {Value : Type u} (" ^ arguments ^ " : Value) :");
        line ("    (sourceRun sourceSyntax (initialState " ^ value_list (List.init arity Fun.id) ^ ")).map");
        line ("      (fun after => after.live " ^ string_of_int (index + 1) ^ ") = some false := by");
        line "  simp [sourceRun, sourceStep, moveFields, writeLocal, initialState, sourceSyntax]"
      ) (List.init arity Fun.id);
      line ("end " ^ scope)
    ) candidates;
    line "end Auths.Qualification.SourceClosureCapture";
  let output = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 Sys.argv.(3) in
  (try output_string output (Buffer.contents buffer); close_out output with error ->
     close_out_noerr output;
     (try Sys.remove Sys.argv.(3) with Sys_error _ -> ());
     raise error);
  Printf.printf "Actual source capture command certificates written: %d; unelaborated/unqualified, no native program\n%!" (List.length candidates)
