(* Actual-source capture mutation regressions, deferred to the final batch.
   Complete source construction is intentionally required; successful cases
   do not qualify the unresolved source functions/types or native execution. *)
open Charon
open Types
open Expressions
open LlbcAst

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true

let () =
  if Array.length Sys.argv <> 3 then failwith "usage: prepared_source_cases SOURCE.llbc ROOT-ARGUMENTS.json";
  let crate = match OfJson.crate_of_json_file Sys.argv.(1) with Ok crate -> crate | Error message -> failwith message in
  let names = Yojson.Basic.from_file Sys.argv.(2) |> Yojson.Basic.Util.member "roots"
    |> Yojson.Basic.Util.to_list |> List.map Yojson.Basic.Util.to_string in
  let source, adapters, _ = Vtable_graph.close_source_dependencies crate (Source_roots.pointers crate names) in
  (* This source corpus contains the JCS writer-capturing closure at nominal
     type 315. Its complete source family must replay before a conditional
     native overlay is usable; no assertion below discharges source reachability,
     exclusive-loan semantics or the overlay's extra outlives requirement. *)
  let maximum_type = match TypeDeclId.Map.max_binding_opt crate.type_decls with
    | Some (id, _) -> TypeDeclId.to_int id | None -> -1 in
  if maximum_type >= Int.max_int then failwith "writer runtime mutant identities exceed the identifier space";
  let writer_runtime = Writer_runtime.create crate ~source ~adapters
    ~owner_id:(TypeDeclId.of_int 315) ~enum_id:(TypeDeclId.of_int (maximum_type + 1)) in
  require "the complete actual source writer family must replay"
    (Writer_runtime.replay crate writer_runtime);
  require "the original source dynamic Box field must reconstruct every binder, predicate and metadata field"
    (Return_region_certificate.replays_type ~holes:[] writer_runtime.source_field.field_ty writer_runtime.source_field_tree);
  require "a source dynamic Box field cannot become an opaque or omitted type token"
    (not (Writer_runtime.replay crate { writer_runtime with source_field_tree = Return_region_certificate.Natural 0 }));
  let change_object change = match writer_runtime.source_field.field_ty with
    | TRef (borrow, TAdt ({ id = TBuiltin TBox; generics = { types = [TDynTrait object_type]; _ }; _ } as box), kind) ->
        TRef (borrow, TAdt { box with generics = { box.generics with types = [TDynTrait (change object_type)] } }, kind)
    | _ -> failwith "the actual writer reflection mutant lost its source dynamic Box field" in
  let no_object_bound = change_object (fun object_type -> { binder = { object_type.binder with
    binder_params = { object_type.binder.binder_params with types_outlive = [] } } }) in
  require "the complete source dynamic reflection cannot omit the existential self outlives bound"
    (not (Return_region_certificate.replays_type ~holes:[] no_object_bound writer_runtime.source_field_tree));
  let renamed_self = change_object (fun object_type -> { binder = { object_type.binder with
    binder_params = { object_type.binder.binder_params with types = List.map
      (fun (parameter : type_param) -> { parameter with name = parameter.name ^ "_mutated" })
      object_type.binder.binder_params.types } } }) in
  require "dynamic source reflection retains actual type parameter metadata"
    (not (Return_region_certificate.replays_type ~holes:[] renamed_self writer_runtime.source_field_tree));
  let without_spans = change_object (fun object_type -> { binder = { object_type.binder with
    binder_params = { object_type.binder.binder_params with trait_clauses = List.map
      (fun (clause : trait_param) -> { clause with span = None }) object_type.binder.binder_params.trait_clauses } } }) in
  if without_spans <> writer_runtime.source_field.field_ty then
    require "dynamic source reflection cannot silently discard predicate source spans"
      (not (Return_region_certificate.replays_type ~holes:[] without_spans writer_runtime.source_field_tree));
  require "an actual source writer case cannot disappear"
    (not (Writer_runtime.replay crate { writer_runtime with cases = List.tl writer_runtime.cases }));
  List.iter (fun (case : Writer_runtime.case) ->
    let replace changed = { writer_runtime with cases = List.map (fun (original : Writer_runtime.case) ->
      if original.role = case.role then changed else original) writer_runtime.cases } in
    require "a writer runtime case must keep its actual Box producers"
      (not (Writer_runtime.replay crate (replace { case with producers = [] })));
    require "a writer runtime cannot turn an exclusive borrowed payload into an owned pointee"
      (not (Writer_runtime.replay crate (replace { case with native_payload = case.original_inner_type })));
    require "a shared global declaration cannot replace the complete source runtime case identity"
      (not (Writer_runtime.replay crate (replace { case with source_global_index =
        GlobalDeclId.to_int case.source_case.source_global.declaration.def_id })));
    require "the source invariant inner reference cannot be replaced by a guessed static borrow"
      (not (Writer_runtime.replay crate (replace { case with original_inner_type =
        TRef (RStatic, case.original_inner_type, RMut) })))
  ) writer_runtime.cases;
  require "the conditional native wellformedness bound cannot silently disappear"
    (not (Writer_runtime.replay crate { writer_runtime with enum_declaration = {
      writer_runtime.enum_declaration with generics = {
        writer_runtime.enum_declaration.generics with types_outlive = [] } } }));
  require "the nested object-to-Box-borrow region edge cannot silently disappear"
    (not (Writer_runtime.replay crate { writer_runtime with lifted_owner = {
      writer_runtime.lifted_owner with generics = {
        writer_runtime.lifted_owner.generics with regions_outlive =
          List.filter ((<>) writer_runtime.object_borrow_bound)
            writer_runtime.lifted_owner.generics.regions_outlive } } }));
  require "the object-to-Box-borrow edge cannot reverse its actual source regions"
    (not (Writer_runtime.replay crate { writer_runtime with object_borrow_bound = {
      writer_runtime.object_borrow_bound with binder_value =
        snd writer_runtime.object_borrow_bound.binder_value,
        fst writer_runtime.object_borrow_bound.binder_value } }));
  require "the native overlay cannot claim the original dynamic closure is already lifted"
    (not (Writer_runtime.replay crate { writer_runtime with lifted_owner = writer_runtime.owner }));
  require "source capture construction cannot hide an unsupported producer or receiver" (adapters.failures = []);
  require "the actual source suite must exercise concrete-to-dynamic production" (adapters.injections <> []);
  require "the actual source suite must exercise normal dynamic Box return routes" (adapters.capture_returns <> []);
  require "the actual source suite must exercise caller/result/capture binding" (adapters.return_calls <> []);
  require "the actual source suite must exercise returned Box receiver provenance" (adapters.box_receiver_calls <> []);
  require "the actual source suite must exercise captured Box closure metadata" (adapters.closure_captures <> []);
  List.iter (fun (injection : Vtable_graph.injection) ->
    let producer = injection.producer in
    require "the actual full source producer must replay" (Prepared_injection.replay crate producer);
    require "the original source dictionary cannot be replaced by a different implementation"
      (not (Prepared_injection.replay crate { producer with implementation = {
        producer.implementation with id = TraitImplId.of_int (TraitImplId.to_int producer.implementation.id + 1) } }));
    require "the source value cannot be replaced while retaining only a metadata tag"
      (not (Prepared_injection.replay crate { producer with concrete_self = TRef (RStatic, producer.concrete_self, RShared) }));
    require "another static cannot supply the recorded source receiver"
      (not (Prepared_injection.replay crate { producer with global_reference = { producer.global_reference with
        id = GlobalDeclId.of_int (GlobalDeclId.to_int producer.global_reference.id + 1) } }));
    if producer.capture_environment <> [] then (
      require "an erased captured lifetime cannot fill a concrete source environment"
        (not (Prepared_injection.replay crate { producer with capture_environment =
          RErased :: List.tl producer.capture_environment }));
      require "a captured lifetime cannot be guessed static"
        (not (Prepared_injection.replay crate { producer with capture_environment =
          RStatic :: List.tl producer.capture_environment })));
    List.iter (fun (_, _, global, candidate, _) -> if global = injection.source_global_index then (
      ignore (Prepared_injection.virtual_self ~candidate producer);
      require "a candidate cannot open a source environment with one parameter missing"
        (refuses (fun () -> ignore (Prepared_injection.open_capture
          ~parameters:(candidate.Virtual_shim.capture_parameters @ [{ index = RegionId.of_int 1000000;
            name = None; variance = Invariant; mutability = LtUnknown }]) ~source_global:candidate.source_global producer)));
      require "a virtual branch cannot substitute another concrete receiver type"
        (refuses (fun () -> ignore (Prepared_injection.virtual_self
          ~candidate:{ candidate with concrete_self = TRef (RStatic, candidate.concrete_self, RShared) } producer)));
      List.iter (fun (_, _, other_global, other, _) ->
        if other_global <> global then require "the static ID alone cannot select another prepared source capture"
          (refuses (fun () -> ignore (Prepared_injection.open_capture ~parameters:other.Virtual_shim.capture_parameters
            ~source_global:other.source_global producer)))) adapters.virtual_instances
    )) adapters.virtual_instances
  ) adapters.injections;
  List.iter (fun (_, (routes : Capture_return.t)) ->
    require "all actual normal Box return routes must replay" (Capture_return.replay crate routes);
    require "discarding a normal return cannot leave a valid source route witness"
      (not (Capture_return.replay crate { routes with returns = [] }));
    let first = List.hd routes.returns in
    require "discarding the accumulated original source typing premises cannot replay"
      (not (Capture_return.replay crate { routes with returns = { first with paired = {
        first.paired with constraints = Region_equations.empty_predicates } } :: List.tl routes.returns }));
    require "a producer branch cannot disappear from the complete source function"
      (refuses (fun () -> ignore (Capture_return.derive crate ~view:routes.view ~frame:routes.frame
        ~producers:(List.tl routes.producers))));
    let incomplete = object inherit [_] map_statement as super
      method! visit_statement env statement =
        let statement = super#visit_statement env statement in
        match statement.kind with
        | Switch (Match (place, _ :: branches, None)) -> { statement with kind = Switch (Match (place, branches, None)) }
        | _ -> statement
    end in
    let frame = { routes.frame with body = incomplete#visit_block () routes.frame.body } in
    let producers = List.map (fun (producer : Prepared_injection.t) -> { producer with frame }) routes.producers in
    require "an absent source enum branch cannot be assumed unreachable"
      (refuses (fun () -> ignore (Capture_return.derive crate ~view:routes.view ~frame ~producers)));
    let copying = object inherit [_] map_statement as super
      method! visit_statement env statement =
        let statement = super#visit_statement env statement in
        match statement.kind with
        | Assign (destination, Charon.Expressions.UnaryOp (Cast (CastUnsize (from, into, MetaVTableUpcast [])), Move source)) ->
            { statement with kind = Assign (destination, UnaryOp (Cast (CastUnsize (from, into, MetaVTableUpcast [])), Copy source)) }
        | _ -> statement
    end in
    let frame = { routes.frame with body = copying#visit_block () routes.frame.body } in
    let producers = List.map (fun (producer : Prepared_injection.t) -> { producer with frame }) routes.producers in
    require "a paired owned Box cannot be copied across an object-lifetime cast"
      (refuses (fun () -> ignore (Capture_return.derive crate ~view:routes.view ~frame ~producers)))
  ) adapters.capture_returns;
  List.iter (fun (site : Capture_callsite.t) ->
    let source = site.binding in
    require "the actual original caller view must replay its complete pre-factorization context"
      (Instance_view.replay source.caller.declaration source.caller.view);
    require "the actual source call, full ABI and capture scopes must replay" (Capture_callsite.replay crate site);
    require "a forged full source callee ABI cannot replay"
      (not (Capture_callsite.replay crate { site with binding = { source with instantiated_signature = {
        source.instantiated_signature with is_unsafe = not source.instantiated_signature.is_unsafe } } }));
    require "an omitted returned capture case cannot replay"
      (not (Capture_callsite.replay crate { site with cases = [] }));
    require "a different result place type cannot acquire the actual source call's captures"
      (not (Capture_callsite.replay crate { site with binding = { source with call = { source.call with dest = {
        source.call.dest with ty = TRef (RStatic, source.call.dest.ty, RShared) } } } }));
    require "an absent actual lifetime argument cannot instantiate the source return view"
      (not (Capture_callsite.replay crate { site with binding = { source with arguments = { source.arguments with arguments = [] } } }));
    require "the full caller input/result typing certificate cannot be discarded"
      (not (Capture_callsite.replay crate { site with binding = { source with constraints = Region_equations.empty_predicates } }));
    (match source.caller.view.arguments.arguments with
     | _ :: rest -> require "source-view replay cannot erase an original caller lifetime"
         (not (Instance_view.replay source.caller.declaration { source.caller.view with arguments = {
           source.caller.view.arguments with arguments = RErased :: rest } }))
     | [] -> ())
  ) adapters.return_calls;
  List.iter (fun (route : Box_receiver_call.t) ->
    require "the same actual returned source Box must reach the receiver argument" (Box_receiver_call.replay crate route);
    require "a different original owner cannot keep the actual source receiver route"
      (not (Box_receiver_call.replay crate { route with owner_place = { route.owner_place with
        ty = TRef (RStatic, route.owner_place.ty, RShared) } }));
    require "the actual tracked carrier steps cannot be omitted"
      (not (Box_receiver_call.replay crate { route with receiver_steps = [] }));
    require "the combined caller typing premises cannot be omitted"
      (not (Box_receiver_call.replay crate { route with constraints = Region_equations.empty_predicates }));
    require "receiver provenance cannot substitute the other source argument"
      (not (Box_receiver_call.replay crate { route with receiver = { route.receiver with receiver_origin = {
        route.receiver.receiver_origin with argument = LocalId.of_int
          (LocalId.to_int route.receiver.receiver_origin.argument + 1) } } }))
  ) adapters.box_receiver_calls;
  List.iter (fun (_, (capture : Closure_capture.t), methods) ->
    require "the actual source closure fields and method families must replay" (Closure_capture.replay crate capture);
    require "a source capture operand cannot be omitted"
      (not (Closure_capture.replay crate { capture with source_operands = [] }));
    require "source callable method families cannot disappear behind opaque metadata"
      (not (Closure_capture.replay crate { capture with members = [] }));
    require "a captured Box field cannot be relabelled as untracked"
      (not (Closure_capture.replay crate { capture with box_fields = [] }));
    require "the original full closure typing premises cannot be discarded"
      (not (Closure_capture.replay crate { capture with constraints = Region_equations.empty_predicates }));
    require "every actual closure method family must enter the complete source graph"
      (List.for_all (fun (_, node) -> Option.is_some node) methods);
    List.iter (fun (member : Closure_capture.member) ->
      require "every actual captured method keeps its original own lifetime routing"
        (Method_instance.replay member.routing);
      require "a callback family cannot substitute a different source function"
        (not (Method_instance.replay { member.routing with actual = { member.routing.actual with
          kind = FunId (FRegular (FunDeclId.of_int 0)) } }))
    ) capture.members
  ) adapters.closure_captures;
  require "the actual source suite must exercise captured closure invocation binding" (adapters.closure_invocations <> []);
  List.iter (fun (invocation : Closure_invocation.t) ->
    require "the actual callback receiver, dictionary and own-lifetime routing must replay"
      (Closure_invocation.replay crate invocation);
    require "the actual callback receiver cannot be replaced with another argument"
      (not (Closure_invocation.replay crate { invocation with actual_receiver = Constant {
        ty = Vtable_shape.unit; kind = CAdt (None, []) } }));
    require "the actual callback role cannot be relabelled"
      (not (Closure_invocation.replay crate { invocation with role =
        (match invocation.role with FnOnce -> FnMut | FnMut | Fn -> FnOnce) }));
    require "a callback source dictionary cannot be substituted"
      (not (Closure_invocation.replay crate { invocation with owner = { invocation.owner with
        id = TraitImplId.of_int (TraitImplId.to_int invocation.owner.id + 1) } }))
  ) adapters.closure_invocations;
  require "the actual source suite must exercise captured-field Box accessors" (adapters.closure_receivers <> []);
  List.iter (fun (accessor : Closure_receiver.t) ->
    require "the exact actual callback field/address/reborrow/consumer accessor must replay"
      (Closure_receiver.replay crate accessor);
    require "the actual conditional source prefix cannot be discarded"
      (not (Closure_receiver.replay crate { accessor with conditional_prefix = [] }));
    require "the source captured field cannot be substituted with its local address load destination"
      (not (Closure_receiver.replay crate { accessor with captured_place = accessor.closure_argument }));
    require "the original source reborrow cannot be replaced by its shallow address load"
      (not (Closure_receiver.replay crate { accessor with reborrow = accessor.address_load }))
  ) adapters.closure_receivers;
  require "the actual source suite must bind an original closure aggregate to its real iterator argument"
    (adapters.closure_arguments <> []);
  List.iter (fun (argument : Closure_argument.t) ->
    require "the complete actual capture-to-argument route must replay" (Closure_argument.replay crate argument);
    require "an actual captured argument cannot change its source operand to a copy"
      (not (Closure_argument.replay crate { argument with actual_argument =
        (match argument.actual_argument with Move place -> Copy place | source -> source) }));
    require "the actual iterator argument cannot be replaced with another position"
      (not (Closure_argument.replay crate { argument with argument_index = argument.argument_index + 1 }));
    require "the complete actual aggregate-to-argument typing premises cannot be dropped"
      (not (Closure_argument.replay crate { argument with constraints = Region_equations.empty_predicates }))
  ) adapters.closure_arguments;
  require "the actual source suite must retain the callback/iterator carrier footprint closure"
    (adapters.carrier_effects.nodes <> []);
  require "the final source suite cannot discard unsupported carrier effects"
    (adapters.carrier_effects.failures = []);
  require "the actual iterator source must exercise an inductive loop obligation"
    (List.exists (fun (footprint : Carrier_effect.t) -> footprint.loops <> []) adapters.carrier_effects.nodes);
  require "the actual iterator move must retain its source MIR retag"
    (List.exists (fun (footprint : Carrier_effect.t) -> footprint.retags <> []) adapters.carrier_effects.nodes);
  require "the actual enumeration callback must retain its disjoint counter write obligation"
    (List.exists (fun (footprint : Carrier_effect.t) -> footprint.projected_data_writes <> []) adapters.carrier_effects.nodes);
  let receivers = List.map (fun (_, _, receiver) -> receiver) adapters.virtual_receivers in
  List.iter (fun (footprint : Carrier_effect.t) ->
    let replay = Carrier_effect.replay crate ~source ~receivers ~accessors:adapters.closure_receivers
      ~returned_closures:adapters.closure_return_calls in
    require "the complete actual callback body footprint must replay" (replay footprint);
    require "the complete source body statement inventory cannot be dropped"
      (not (replay { footprint with statements = [] }));
    if footprint.calls <> [] then require "ordinary and carrier-bearing callback calls cannot disappear"
      (not (replay { footprint with calls = [] }));
    if footprint.drops <> [] then require "callback cleanup cannot disappear behind a preservation claim"
      (not (replay { footprint with drops = [] }));
    if footprint.loops <> [] then require "an actual iterator loop cannot lose its inductive invariant obligation"
      (not (replay { footprint with loops = [] }));
    if footprint.switches <> [] then require "source callback branches cannot be erased"
      (not (replay { footprint with switches = [] }));
    if footprint.retags <> [] then require "an actual iterator move cannot lose its native retag/loan obligation"
      (not (replay { footprint with retags = [] }));
    if footprint.projected_data_writes <> [] then require "counter/data writes cannot lose their native disjointness obligation"
      (not (replay { footprint with projected_data_writes = [] }))
  ) adapters.carrier_effects.nodes;
  require "the actual source suite must retain a real helper closure return" (adapters.closure_returns <> []);
  require "the actual source suite must bind that closure return to its real caller" (adapters.closure_return_calls <> []);
  List.iter (fun (returned : Closure_return.t) ->
    require "the complete actual helper aggregate/return paths must replay" (Closure_return.replay crate returned);
    require "an actual helper cannot omit its normal return paths"
      (not (Closure_return.replay crate { returned with returns = [] }));
    List.iter (fun (route : Closure_return.returned) ->
      require "the exact actual returned closure value path must replay" (Closure_value_path.replay crate route.value_path);
      require "a return value cannot be replaced with a capture operand's different source place"
        (not (Closure_value_path.replay crate { route.value_path with destination = {
          route.value_path.destination with kind = PlaceLocal (LocalId.of_int 1) } }))
    ) returned.returns
  ) adapters.closure_returns;
  List.iter (fun (returned : Closure_return_call.t) ->
    require "the actual source returned closure/caller/capture scope link must replay"
      (Closure_return_call.replay crate returned);
    require "private/caller capture lifetime bindings cannot disappear from a returned closure"
      (not (Closure_return_call.replay crate { returned with environments = [] }))
  ) adapters.closure_return_calls;
  let reconstructed_returns = List.filter_map (fun (node : Source_closure.node) ->
    match node.frame with Some frame -> frame.return_signature | None -> None) source.nodes in
  require "the actual source suite must exercise the erased helper output capture boundary"
    (reconstructed_returns <> []);
  List.iter (fun (candidate : Return_signature.t) ->
    require "the actual whole-input capture source reconstruction must replay" (Return_signature.replay crate candidate);
    let region_certificate = Return_region_certificate.derive crate candidate in
    require "the actual full source type/region reflection must replay"
      (Return_region_certificate.replay crate candidate region_certificate);
    require "an omitted actual field schema cannot earn a structural lifetime certificate"
      (not (Return_region_certificate.replay crate candidate { region_certificate with field_patterns = [] }));
    List.iter2 (fun source reflected ->
      require "every reflected actual input type must reconstruct the original complete Charon AST"
        (Return_region_certificate.replays_type ~holes:[] source reflected);
      require "an opaque numeric token cannot replace a complete source input type/dictionary"
        (not (Return_region_certificate.replays_type ~holes:[] source (Return_region_certificate.Natural 0)))
    ) candidate.original.inputs region_certificate.declared_inputs;
    require "the original erased signature cannot be overwritten with its candidate"
      (not (Return_signature.replay crate { candidate with original = candidate.reconstructed }));
    require "a recovered output capture must retain its actual source input provenance"
      (not (Return_signature.replay crate { candidate with captures = [] }));
    require "an erased output slot cannot be filled without a recorded completion"
      (not (Return_signature.replay crate { candidate with completions = [] }));
    require "original source parameter/capture/return type premises cannot be omitted"
      (not (Return_signature.replay crate { candidate with constraints = Region_equations.empty_predicates }));
    List.iter (fun (completion : Return_signature.completion) ->
      let substitute = if completion.actual = RStatic then completion.marker else RStatic in
      let completions = List.map (fun (actual : Return_signature.completion) ->
        if actual.output_region_index = completion.output_region_index then { actual with actual = substitute } else actual) candidate.completions in
      require "an output capture cannot substitute a guessed static or fresh lifetime for its real moved parameter"
        (not (Return_signature.replay crate { candidate with completions }))
    ) candidate.completions;
    let definition = FunDeclId.Map.find candidate.view.original_id crate.fun_decls in
    let original_body = match definition.body with StructuredBody body -> body
      | _ -> failwith "the actual return capture source body disappeared" in
    let mutated = ref false in
    let copy_capture = object inherit [_] map_statement as super
      method! visit_statement env statement =
        if statement.statement_id = candidate.source_aggregate.statement_id then (
          match statement.kind with
          | Assign (destination, Aggregate (kind, Move place :: rest)) ->
              mutated := true; { statement with kind = Assign (destination, Aggregate (kind, Copy place :: rest)) }
          | _ -> failwith "the actual original helper aggregate no longer has its moved source input")
        else super#visit_statement env statement
    end in
    let definition = { definition with body = StructuredBody { original_body with body = copy_capture#visit_block () original_body.body } } in
    require "the capture-copy source mutant must alter the actual aggregate" !mutated;
    let mutant_crate = { crate with fun_decls = FunDeclId.Map.add definition.def_id definition crate.fun_decls } in
    let packed = Region_shape.instantiate candidate.view.arguments in
    let arguments, self_evidence = match candidate.view.self_evidence with
      | None -> packed, None
      | Some _ -> (match List.rev packed.trait_refs with self :: rest -> { packed with trait_refs = List.rev rest }, Some self
          | [] -> failwith "the actual source mutation lost complete Self dispatch evidence") in
    let mutant_view = Instance_view.create ?self_evidence definition arguments in
    require "a copied actual source input cannot earn an erased output capture completion"
      (refuses (fun () -> ignore (Return_signature.create mutant_crate mutant_view)));
    let duplicate_capture = object inherit [_] map_statement as super
      method! visit_statement env statement =
        if statement.statement_id = candidate.source_aggregate.statement_id then (
          match statement.kind with
          | Assign (destination, Aggregate (kind, first :: _second :: rest)) ->
              { statement with kind = Assign (destination, Aggregate (kind, first :: first :: rest)) }
          | _ -> failwith "the actual source helper no longer has two original captured inputs")
        else super#visit_statement env statement
    end in
    let original_definition = FunDeclId.Map.find candidate.view.original_id crate.fun_decls in
    let duplicate_definition = { original_definition with body = StructuredBody {
      original_body with body = duplicate_capture#visit_block () original_body.body } } in
    let duplicate_crate = { crate with fun_decls = FunDeclId.Map.add duplicate_definition.def_id duplicate_definition crate.fun_decls } in
    let duplicate_view = Instance_view.create ?self_evidence duplicate_definition arguments in
    require "one actual source input cannot be moved into two independent output captures"
      (refuses (fun () -> ignore (Return_signature.create duplicate_crate duplicate_view)));
    let duplicated_statement_body = match original_body.body.statements with
      | first :: rest -> { original_body.body with statements = first :: { first with kind = Nop } :: rest }
      | [] -> failwith "the original source return constructor has no statement identity to mutate" in
    let duplicated_statement_definition = { original_definition with body = StructuredBody {
      original_body with body = duplicated_statement_body } } in
    let duplicated_statement_crate = { crate with fun_decls = FunDeclId.Map.add
      duplicated_statement_definition.def_id duplicated_statement_definition crate.fun_decls } in
    let duplicated_statement_view = Instance_view.create ?self_evidence duplicated_statement_definition arguments in
    require "a repeated original identity cannot attach a return certificate to an ambiguous source body"
      (refuses (fun () -> ignore (Return_signature.create duplicated_statement_crate duplicated_statement_view)))
  ) reconstructed_returns;
  let maximum_function = match FunDeclId.Map.max_binding_opt crate.fun_decls with
    | Some (id, _) -> FunDeclId.to_int id | None -> -1 in
  if maximum_function >= Int.max_int then failwith "native source mutant identities exceed the identifier space";
  List.iter (fun (node : Source_closure.node) -> match node.frame with
    | Some frame when Option.is_some frame.return_signature ->
        let candidate = Native_capture_candidate.create ~writer_runtime crate ~node ~candidate_id:(FunDeclId.of_int (maximum_function + 1)) in
        require "the complete actual native constructor candidate must replay"
          (Native_capture_candidate.replay crate candidate);
        require "a native constructor cannot reuse an original source function identity"
          (refuses (fun () -> ignore (Native_capture_candidate.create ~writer_runtime crate ~node ~candidate_id:node.declaration.def_id)));
        require "native constructor emission cannot substitute a different output ABI"
          (not (Native_capture_candidate.replay crate { candidate with candidate = {
            candidate.candidate with signature = { candidate.candidate.signature with output = Vtable_shape.unit } } }));
        require "native constructor emission cannot omit its required source declaration groups"
          (not (Native_capture_candidate.replay crate { candidate with component_declarations = [] }));
        require "native constructor emission cannot discharge source layout by dropping pointer metadata"
          (not (Native_capture_candidate.replay crate { candidate with metadata_obligations = [] }));
        require "native parameter specialization cannot omit its complete original generic argument binding"
          (not (Native_capture_candidate.replay crate { candidate with source_generic_arguments = TypesUtils.empty_generic_args }));
        require "native parameter specialization cannot omit its factored candidate argument scope"
          (not (Native_capture_candidate.replay crate { candidate with candidate_generic_arguments = TypesUtils.empty_generic_args }));
        if candidate.source_generic_arguments <> candidate.candidate_generic_arguments then
          require "original caller body labels cannot be substituted for native candidate parameter labels"
            (not (Native_capture_candidate.replay crate { candidate with candidate_generic_arguments = candidate.source_generic_arguments }));
        if candidate.specialized_region_parameters <> [] then
          require "native parameter specialization must retain the original region declaration evidence"
            (not (Native_capture_candidate.replay crate { candidate with specialized_region_parameters = [] }));
        if candidate.specialized_type_parameters <> [] then
          require "native parameter specialization must retain the source declaration parameters it discharges"
            (not (Native_capture_candidate.replay crate { candidate with specialized_type_parameters = [] }));
        let component = Native_capture_candidate.component_crate crate candidate in
        require "an isolated native constructor must retain every original function body unchanged"
          (FunDeclId.Map.for_all (fun id original -> FunDeclId.Map.find_opt id component.fun_decls = Some original) crate.fun_decls);
        ignore (Source_roots.pointers component Source_roots.names)
    | _ -> ()) source.nodes;
  require "the actual source suite must connect source value origins to real fields/parameters"
    (adapters.value_flow.edges <> []);
  require "the final suite cannot omit unsupported actual carrier value origins"
    (adapters.value_flow.failures = []);
  let value_context = adapters.value_flow.context in
  List.iter (fun (edge : Value_flow.edge) ->
    require "the full actual definition/access-to-destination edge must replay"
      (Value_flow.replay_edge crate ~context:value_context edge);
    require "the real source operand cannot be replaced by a copied carrier"
      (not (Value_flow.replay_edge crate ~context:value_context { edge with origin = {
        edge.origin with operand = (match edge.origin.operand with Move place -> Copy place | operand -> operand) } }));
    if edge.origin.prefix <> [] then require "preceding native effects cannot be discarded from a value origin"
      (not (Value_flow.replay_edge crate ~context:value_context { edge with origin = { edge.origin with prefix = [] } }));
    if Iteration_path.loops edge.origin.prefix <> [] then (
      let prefix = List.filter (function Iteration_path.Iteration _ -> false | _ -> true) edge.origin.prefix in
      require "a source value trace cannot erase its loop-head value invariant"
        (not (Value_flow.replay_edge crate ~context:value_context { edge with origin = { edge.origin with prefix } })));
    let destination = match edge.destination with
      | Value_flow.CapturedField (capture, index) -> Value_flow.CapturedField (capture, index + 1)
      | Value_flow.CalleeParameter (binding, index) -> Value_flow.CalleeParameter (binding, index + 1) in
    require "source type similarity cannot substitute another actual captured field or callee parameter"
      (not (Value_flow.replay_edge crate ~context:value_context { edge with destination }))
  ) adapters.value_flow.edges;
  let actual_carrier_calls = List.concat_map (fun (footprint : Carrier_effect.t) ->
    List.filter_map (fun (call : Carrier_effect.call_effect) -> call.binding) footprint.calls) adapters.carrier_effects.nodes in
  require "the actual carrier source suite must exercise original default-method Self evidence"
    (List.exists (fun (binding : Source_call.t) -> Option.is_some binding.edge.binding.self_evidence) actual_carrier_calls);
  List.iter (fun (binding : Source_call.t) ->
    let resolution, actual = Source_call.site_resolution crate ~caller:binding.caller binding.source_statement.statement_id in
    require "the actual call site must retain its exact original pointer/Self/frame binding"
      (actual = binding.edge.binding && resolution.self_evidence = actual.self_evidence);
    if Option.is_some actual.self_evidence then require "default-method context cannot be removed from a normalized function call"
      (not (Source_call.replay crate { binding with edge = { binding.edge with binding = { actual with self_evidence = None } } }))
  ) actual_carrier_calls;
  Printf.printf "Actual-source prepared capture mutations completed; no native source/loan qualification\n%!"
