(* Exact source getter signatures and actual complete-graph calls. The
   reflected component concerns reference-input liveness only. It neither
   supplies source values nor proves capture reachability/native ownership. *)
open Charon
open Types
open LlbcAst

module P = Return_region_certificate

type signature_view = {
  parameters : region_param list;
  body_regions : int;
  signature : fun_sig;
  writer_index : int;
  writer_type : ty;
  object_predicate : dyn_predicate;
  object_region : region;
  inputs : P.expr list;
  reflected_writer : P.expr;
}

type producer = {
  source_case : int;
  injection : Prepared_injection.t;
  original : signature_view;
  prepared : signature_view;
}

type callsite = {
  source_call : Source_call.t;
  instantiated : signature_view;
}

type capture = {
  source_capture : Closure_capture.t;
  origin : Value_flow.edge;
  returned : Capture_callsite.t;
  getter_call_index : int;
  parent_writer : ty;
  object_region : region;
  constraints : Region_equations.predicates;
  input_bound : signature_view;
}

type t = {
  runtime : Writer_runtime.t;
  producers : producer list;
  getter_nodes : int list;
  calls : callsite list;
  captures : capture list;
}

let object_output owner = function
  | TAdt { id = TBuiltin TBox; generics = {
      regions = []; types = [TDynTrait predicate]; const_generics = []; trait_refs = [] } } ->
      let region = Vtable_shape.object_annotation owner predicate in
      if region = RErased then invalid_arg "a writer input bound cannot infer an erased output object lifetime";
      predicate, region
  | _ -> invalid_arg "a source writer getter must retain its complete original dynamic Box output"

let signature_view ~owner ~parameters ~body_regions ~writer_index ~writer_type signature =
  if body_regions < 0 then invalid_arg "a writer input bound has a negative source body-region scope";
  let object_predicate, object_region = object_output owner signature.output in
  let scope = new Region_scope.check ~body_regions parameters in
  scope#visit_fun_sig [] signature;
  let input = match List.nth_opt signature.inputs writer_index with Some input -> input
    | None -> invalid_arg "the source getter lost its exact parent writer input position" in
  if input <> TRef (object_region, writer_type, RMut) then
    invalid_arg "the source getter writer input does not supply the exact output object's lifetime";
  let inputs = List.map (P.reflect_type ~holes:[]) signature.inputs in
  let reflected_writer = P.reflect_type ~holes:[] writer_type in
  { parameters; body_regions; signature; writer_index; writer_type; object_predicate; object_region;
    inputs; reflected_writer }

let original_writer (declaration : fun_decl) =
  let parameter = match declaration.generics.types, declaration.generics.const_generics with
    | [parameter], [] -> parameter
    | _ -> invalid_arg "the original getter needs its actual single parent writer parameter" in
  let writer_type = TVar (Free parameter.index) in
  let positions = List.mapi (fun index ty -> index, ty) declaration.signature.inputs
    |> List.filter_map (function index, TRef (_, inner, RMut) when inner = writer_type -> Some index | _ -> None) in
  let index = match positions with [index] -> index
    | _ -> invalid_arg "the original getter has no unique exclusive parent writer parameter input" in
  parameter, index, writer_type

let derive crate (runtime : Writer_runtime.t) =
  if not (Writer_runtime.replay crate runtime) then
    invalid_arg "a writer input bound requires the complete original writer family replay";
  let producers = List.concat_map (fun (case : Writer_runtime.case) ->
    List.map (fun (injection : Prepared_injection.t) ->
      if not (Prepared_injection.replay crate injection) ||
          Function_frame.prepare crate injection.view <> injection.frame then
        invalid_arg "a writer input bound changed its complete prepared Box producer frame";
      let declaration = injection.original.caller in
      if not (Instance_view.replay declaration injection.view) then
        invalid_arg "a writer input bound changed the original getter's complete source instantiation";
      let parameter, writer_index, writer_type = original_writer declaration in
      let owner = injection.original.source_vtable.shape.source_predicate in
      let original = signature_view ~owner ~parameters:declaration.generics.regions ~body_regions:0
        ~writer_index ~writer_type declaration.signature in
      let substitution = Substitute.make_subst_from_generics declaration.generics injection.view.call_arguments Self in
      let writer_type = Substitute.ty_substitute substitution (TVar (Free parameter.index)) in
      let regions = Function_frame.region_mapper injection.frame.region_certificate.solution in
      let writer_type = regions#visit_ty () writer_type in
      let prepared = signature_view ~owner ~parameters:injection.view.arguments.parameters ~body_regions:0
        ~writer_index ~writer_type injection.frame.signature in
      { source_case = case.source_global_index; injection; original; prepared }
    ) case.producers
  ) runtime.cases in
  if producers = [] then invalid_arg "the writer input bound omitted every actual Box producer";
  let getter_ids = List.map (fun producer -> producer.injection.original.caller.def_id) producers
    |> List.sort_uniq FunDeclId.compare_id in
  let getters = List.filter (fun (node : Source_closure.node) -> List.mem node.declaration.def_id getter_ids)
    runtime.source.nodes in
  if getters = [] then invalid_arg "the writer input bound has no actual source getter nodes";
  List.iter (fun (node : Source_closure.node) ->
    if not (List.exists (fun producer -> producer.injection.view = node.view &&
      Some producer.injection.frame = node.frame) producers) then
      invalid_arg "an actual source getter instance has no retained complete writer Box producer"
  ) getters;
  let calls = List.concat_map (fun (caller : Source_closure.node) -> match caller.frame with
    | None -> []
    | Some frame ->
        let found = ref [] in
        let collect = object inherit [_] iter_statement as super
          method! visit_statement env statement =
            (match statement.kind with
             | Call ({ func = FnOpRegular { kind = FunId (FRegular id); _ }; _ }, _)
                 when List.mem id getter_ids ->
                 let matches = List.filter (fun (callee : Source_closure.node) ->
                   callee.declaration.def_id = id && List.exists (fun (edge : Source_closure.edge) ->
                     edge.target = Source_closure.Instance callee.index) caller.callees) getters in
                 let call = List.filter_map (fun callee ->
                   try Some (Source_call.derive crate ~caller ~callee statement.statement_id)
                   with Invalid_argument _ -> None) matches in
                 let source_call = match call with [call] -> call
                   | _ -> invalid_arg "an actual writer getter call lacks one exact complete source edge/ABI replay" in
                 let _, writer_index, _ = original_writer source_call.callee.declaration in
                 let owner = (List.find (fun producer ->
                   producer.injection.original.caller.def_id = id) producers).injection.original.source_vtable.shape.source_predicate in
                 let regions = Function_frame.region_mapper source_call.constraints.solution in
                 let signature = regions#visit_fun_sig () source_call.instantiated_signature in
                 let writer_type = match List.nth_opt signature.inputs writer_index with
                   | Some (TRef (_, writer_type, RMut)) -> writer_type
                   | _ -> invalid_arg "a writer getter call lost its exclusive input ABI" in
                 let instantiated = signature_view ~owner ~parameters:caller.view.arguments.parameters
                   ~body_regions:frame.source_body.bound_body_regions ~writer_index ~writer_type signature in
                 found := { source_call; instantiated } :: !found
             | _ -> ());
            super#visit_statement env statement
        end in
        collect#visit_block () frame.body;
        List.rev !found
  ) runtime.source.nodes in
  if calls = [] then invalid_arg "the complete source graph has no actual calls to its writer getter";
  List.iter (fun (callee : Source_closure.node) ->
    if not (List.exists (fun call -> call.source_call.callee.index = callee.index) calls) then
      invalid_arg "a writer getter instance has no retained actual incoming source call"
  ) getters;
  let captures = List.filter_map (fun (_, (source_capture : Closure_capture.t), _) ->
    if source_capture.source_type.def_id <> runtime.owner.def_id then None else (
      if not (Closure_capture.replay crate source_capture) then
        invalid_arg "the writer input bound lost its complete actual captured owner";
      let origin = match List.filter (fun (edge : Value_flow.edge) ->
        edge.destination = Value_flow.CapturedField (source_capture, runtime.field_index)) runtime.adapters.value_flow.edges with
        | [edge] when Value_flow.replay_edge crate ~context:runtime.adapters.value_flow.context edge -> edge
        | _ -> invalid_arg "the captured writer needs one exact actual source field/value-origin edge" in
      let rec getter_result = function
        | Value_origin.SourceMove (_, source) | Value_origin.SourceBorrow (_, source)
        | Value_origin.SourceProjection (_, _, source) | Value_origin.ShallowAddressAccess (_, source) ->
            getter_result source
        | Value_origin.ActualBoxResult returned -> returned
        | Value_origin.ParameterSlot _ | Value_origin.CapturedAggregate _ | Value_origin.ActualClosureResult _ ->
            invalid_arg "a captured writer lifetime needs its actual getter result path, not a type-based origin guess" in
      let returned = getter_result origin.origin.expression in
      if not (Capture_callsite.replay crate returned) then
        invalid_arg "the captured writer's exact source getter return cases did not replay";
      let getter_call_index, getter_call = match List.mapi (fun index call -> index, call) calls
        |> List.filter (fun (_, call) -> call.source_call = returned.binding) with
        | [call] -> call
        | _ -> invalid_arg "the actual captured Box is not one exact retained writer getter call" in
      List.iter (fun (case : Capture_callsite.case) ->
        if not (Capture_scope.replay case.environment) ||
            not (List.exists (fun producer -> producer.injection = case.returned.paired.producer) producers) then
          invalid_arg "the captured writer lost an actual return producer or its distinct callee/caller lifetime scope"
      ) returned.cases;
      let substitution = Type_view.source_substitution source_capture.source_type
        source_capture.reference.generics source_capture.type_resolution.self_evidence in
      let parent_writer = Substitute.ty_substitute substitution (TVar (Free runtime.parent_writer.index)) in
      let object_region = Substitute.st_substitute_visitor#visit_region substitution runtime.object_region in
      let constraints = List.fold_left Region_equations.add_premise origin.origin.constraints
        (List.rev source_capture.constraints.originals @ List.rev returned.binding.constraints.originals) in
      let regions = Function_frame.region_mapper constraints.solution in
      let parent_writer = regions#visit_ty () parent_writer in
      let object_region = regions#visit_region () object_region in
      (* Only exact annotation replay is admitted here. A future source cast
         would need its original narrowing interface and semantic inclusion;
         this route cannot equate two labels merely to obtain a bound. *)
      let signature = regions#visit_fun_sig () getter_call.instantiated.signature in
      let owner = (List.hd producers).injection.original.source_vtable.shape.source_predicate in
      let input_bound = signature_view ~owner ~parameters:source_capture.caller.view.arguments.parameters
        ~body_regions:(Source_call.frame source_capture.caller).source_body.bound_body_regions
        ~writer_index:getter_call.instantiated.writer_index ~writer_type:parent_writer signature in
      if input_bound.object_region <> object_region ||
          regions#visit_ty () getter_call.instantiated.writer_type <> parent_writer ||
          not (Region_equations.replay_predicates constraints) then
        invalid_arg "the captured owner writer/object lifetime is not the exact actual getter input interface";
      Some { source_capture; origin; returned; getter_call_index; parent_writer; object_region;
        constraints; input_bound }
    )) runtime.adapters.closure_captures in
  if captures = [] then invalid_arg "the writer input bound omitted its actual source closure capture";
  { runtime; producers; getter_nodes = List.map (fun (node : Source_closure.node) -> node.index) getters; calls; captures }

let replay crate witness =
  try derive crate witness.runtime = witness with Invalid_argument _ | Not_found -> false

let create crate runtime =
  let witness = derive crate runtime in
  if not (replay crate witness) then invalid_arg "the exact writer input lifetime source interface did not replay";
  witness

let signature_report view = `Assoc [
  "complete_source_signature", `String (show_fun_sig view.signature);
  "exact_output_dynamic_predicate", `String (show_dyn_predicate view.object_predicate);
  "source_region_parameters", `List (List.map (fun (parameter : region_param) -> `Int (RegionId.to_int parameter.index)) view.parameters);
  "source_body_region_count", `Int view.body_regions;
  "writer_input_index", `Int view.writer_index;
  "exact_writer_type", `String (show_ty view.writer_type);
  "exact_output_object_region", `String (show_region view.object_region);
  "full_dynamic_output_independently_reflected", `Bool false]

let report crate witness = `Assoc [
  "schema", `String "actual-source-writer-input-lifetime/v1";
  "complete_source_family_replays", `Bool (replay crate witness);
  "source_owner", `Int (TypeDeclId.to_int witness.runtime.owner.def_id);
  "all_getter_nodes", `List (List.map (fun index -> `Int index) witness.getter_nodes);
  "actual_producers", `List (List.map (fun producer -> `Assoc [
    "source_case", `Int producer.source_case;
    "source_getter", `Int (FunDeclId.to_int producer.injection.original.caller.def_id);
    "source_statement", `Int (StatementId.to_int producer.injection.statement.statement_id);
    "original", signature_report producer.original;
    "prepared", signature_report producer.prepared]) witness.producers);
  "actual_calls", `List (List.map (fun call -> `Assoc [
    "source_caller_node", `Int call.source_call.caller.index;
    "source_getter_node", `Int call.source_call.callee.index;
    "source_statement", `Int (StatementId.to_int call.source_call.source_statement.statement_id);
    "complete_input_and_result_requirements", `List (List.map (fun (expected, actual) ->
      `Assoc ["expected", `String (show_ty expected); "actual", `String (show_ty actual)]) call.source_call.requirements);
    "instantiated", signature_report call.instantiated]) witness.calls);
  "actual_capture_routes", `List (List.map (fun capture -> `Assoc [
    "source_caller_node", `Int capture.source_capture.caller.index;
    "source_capture_statement", `Int (StatementId.to_int capture.source_capture.statement.statement_id);
    "source_field_index", `Int witness.runtime.field_index;
    "getter_call_index", `Int capture.getter_call_index;
    "exact_captured_parent_writer", `String (show_ty capture.parent_writer);
    "exact_captured_object_region", `String (show_region capture.object_region);
    "source_value_origin", Value_origin.report crate ~context:witness.runtime.adapters.value_flow.context capture.origin.origin;
    "actual_source_getter_returns", Capture_callsite.report crate capture.returned;
    "input_bound_at_capture_scope", signature_report capture.input_bound;
    "intervening_effect_and_native_value_preservation_proved", `Bool false]) witness.captures);
  "source_reference_input_lifetime_premise_required", `Bool true;
  "getter_return_to_actual_capture_value_refinement_proved", `Bool false;
  "all_source_reachable_inputs_satisfy_native_parent_writer_bound_proved", `Bool false;
  "native_heap_loan_layout_and_alias_refinement_proved", `Bool false;
  "whole_program_emitted", `Bool false; "lean_elaboration_run", `Bool false;
  "tests_run", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let output = Buffer.create 16384 in
  let line text = Buffer.add_string output (text ^ "\n") in
  line "import Auths.Support.WriterInputBound";
  line "/- Actual source getter and call input signatures. Dynamic output predicates are";
  line "   checked by the construction AST replay, not independently reflected here.";
  line "   Source input WF, capture reachability and native adequacy remain required.";
  line "   All scripts are unelaborated; this file is not qualification evidence. -/";
  line "namespace Auths.Qualification.WriterInputBound";
  line "open Auths.Support.SourceClosureRegions Auths.Support.WriterInputBound";
  line ("def sourceOwner : Nat := " ^ string_of_int (TypeDeclId.to_int witness.runtime.owner.def_id));
  line ("def getterNodes : List Nat := " ^ P.numbers witness.getter_nodes);
  let emit name view =
    line ("def " ^ name ^ " : SignatureView := {");
    line ("  regionParameters := " ^ P.numbers (List.map (fun (p : region_param) -> RegionId.to_int p.index) view.parameters));
    line ("  bodyRegions := " ^ string_of_int view.body_regions);
    line ("  inputs := " ^ P.expressions view.inputs);
    line ("  writerIndex := " ^ string_of_int view.writer_index);
    line ("  writerType := " ^ P.lean view.reflected_writer);
    line ("  outputObjectRegion := " ^ P.lean_region view.object_region ^ " }");
    line ("theorem " ^ name ^ "_exact_input : check " ^ name ^ " = true := by decide");
    line ("theorem " ^ name ^ "_source_input_supplies_bound {Point : Type u}");
    line "    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)";
    line "    (input : Expr)";
    line ("    (actual : " ^ name ^ ".inputs[" ^ name ^ ".writerIndex]? = some input)");
    line "    (typed : ReferenceLifetimeWF regions typeLive input) :";
    line ("    TypeOutlives regions typeLive " ^ name ^ ".writerType " ^ name ^ ".outputObjectRegion :=");
    line ("  source_getter_input_supplies_object_bound " ^ name ^ " regions typeLive " ^ name ^ "_exact_input input actual typed")
  in
  line "universe u";
  List.iteri (fun index producer ->
    let prefix = "producer" ^ string_of_int index in
    line ("def " ^ prefix ^ "Case : Nat := " ^ string_of_int producer.source_case);
    line ("def " ^ prefix ^ "Statement : Nat := " ^ string_of_int (StatementId.to_int producer.injection.statement.statement_id));
    emit (prefix ^ "Original") producer.original;
    emit (prefix ^ "Prepared") producer.prepared
  ) witness.producers;
  List.iteri (fun index call ->
    let prefix = "call" ^ string_of_int index in
    line ("def " ^ prefix ^ "Caller : Nat := " ^ string_of_int call.source_call.caller.index);
    line ("def " ^ prefix ^ "Statement : Nat := " ^ string_of_int (StatementId.to_int call.source_call.source_statement.statement_id));
    emit prefix call.instantiated
  ) witness.calls;
  List.iteri (fun index capture ->
    let prefix = "capture" ^ string_of_int index in
    line ("def " ^ prefix ^ "Caller : Nat := " ^ string_of_int capture.source_capture.caller.index);
    line ("def " ^ prefix ^ "Statement : Nat := " ^ string_of_int (StatementId.to_int capture.source_capture.statement.statement_id));
    line ("def " ^ prefix ^ "GetterCall : Nat := " ^ string_of_int capture.getter_call_index);
    line ("def " ^ prefix ^ "ParentWriter : Expr := " ^ P.lean (P.reflect_type ~holes:[] capture.parent_writer));
    line ("def " ^ prefix ^ "ObjectRegion : Region := " ^ P.lean_region capture.object_region);
    emit (prefix ^ "Input") capture.input_bound;
    line ("theorem " ^ prefix ^ "_exact_source_interface :");
    line ("    " ^ prefix ^ "Input.writerType = " ^ prefix ^ "ParentWriter ∧");
    line ("    " ^ prefix ^ "Input.outputObjectRegion = " ^ prefix ^ "ObjectRegion := by decide");
    line ("theorem " ^ prefix ^ "_source_reference_input_supplies_captured_bound {Point : Type u}");
    line "    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop) (input : Expr)";
    line ("    (actual : " ^ prefix ^ "Input.inputs[" ^ prefix ^ "Input.writerIndex]? = some input)");
    line "    (typed : ReferenceLifetimeWF regions typeLive input) :";
    line ("    TypeOutlives regions typeLive " ^ prefix ^ "ParentWriter " ^ prefix ^ "ObjectRegion :=");
    line ("  " ^ prefix ^ "Input_source_input_supplies_bound regions typeLive input actual typed")
  ) witness.captures;
  line "end Auths.Qualification.WriterInputBound";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
