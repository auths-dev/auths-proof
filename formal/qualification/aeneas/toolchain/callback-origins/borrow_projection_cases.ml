(* Actual-source projection mutations, authored for the final batch only.
   This suite does not qualify the conditional native carrier or whole graph. *)
open Charon
open Types
open LlbcAst
module V = Aeneas.Values

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true

let () =
  if Array.length Sys.argv <> 3 then invalid_arg "usage: borrow_projection_cases SOURCE.llbc ROOT-ARGUMENTS.json";
  Aeneas.Config.set_backend "lean";
  Aeneas.Config.fail_hard := true;
  Aeneas.Config.warnings_as_errors := true;
  Aeneas.Config.sanity_checks := true;
  let crate = match OfJson.crate_of_json_file Sys.argv.(1) with
    | Ok crate -> crate | Error message -> invalid_arg message in
  let names = Yojson.Basic.from_file Sys.argv.(2) |> Yojson.Basic.Util.member "roots"
    |> Yojson.Basic.Util.to_list |> List.map Yojson.Basic.Util.to_string in
  let source, adapters, _ = Vtable_graph.close_source_dependencies crate (Source_roots.pointers crate names) in
  let largest_type = match TypeDeclId.Map.max_binding_opt crate.type_decls with
    | Some (id, _) -> TypeDeclId.to_int id | None -> -1 in
  let largest_function = match FunDeclId.Map.max_binding_opt crate.fun_decls with
    | Some (id, _) -> FunDeclId.to_int id | None -> -1 in
  if largest_type >= Int.max_int || largest_function >= Int.max_int then
    invalid_arg "projection mutation identities exceed the source identifier space";
  let writer_runtime = Writer_runtime.create crate ~source ~adapters ~owner_id:(TypeDeclId.of_int 315)
    ~enum_id:(TypeDeclId.of_int (largest_type + 1)) in
  let writer_bound = Writer_input_bound.create crate writer_runtime in
  require "writer input lifetime interface must retain every actual producer and call"
    (Writer_input_bound.replay crate writer_bound);
  require "writer input lifetime evidence cannot omit a Box producer"
    (not (Writer_input_bound.replay crate { writer_bound with producers = List.tl writer_bound.producers }));
  require "writer input lifetime evidence cannot omit an actual call"
    (not (Writer_input_bound.replay crate { writer_bound with calls = List.tl writer_bound.calls }));
  require "writer input lifetime evidence cannot omit its actual captured-owner route"
    (not (Writer_input_bound.replay crate { writer_bound with captures = [] }));
  List.iter (fun (capture : Writer_input_bound.capture) ->
    require "a source capture cannot be bound to another getter call by similar type"
      (not (Writer_input_bound.replay crate { writer_bound with captures = List.map (fun (actual : Writer_input_bound.capture) ->
        if actual = capture then { actual with getter_call_index = List.length writer_bound.calls } else actual) writer_bound.captures }));
    require "an exact captured writer lifetime cannot be promoted to static"
      (not (Writer_input_bound.replay crate { writer_bound with captures = List.map (fun (actual : Writer_input_bound.capture) ->
        if actual = capture then { actual with object_region = RStatic } else actual) writer_bound.captures }))
  ) writer_bound.captures;
  List.iter (fun (producer : Writer_input_bound.producer) ->
    let view = producer.original in
    require "a mismatched source writer input position cannot establish the object bound"
      (refuses (fun () -> ignore (Writer_input_bound.signature_view
        ~owner:producer.injection.original.source_vtable.shape.source_predicate
        ~parameters:view.parameters ~body_regions:view.body_regions
        ~writer_index:(List.length view.signature.inputs) ~writer_type:view.writer_type view.signature)));
    require "a changed parent writer type cannot establish the source object bound"
      (refuses (fun () -> ignore (Writer_input_bound.signature_view
        ~owner:producer.injection.original.source_vtable.shape.source_predicate
        ~parameters:view.parameters ~body_regions:view.body_regions
        ~writer_index:view.writer_index ~writer_type:TNever view.signature)));
    let wrong_input = TRef (RStatic, view.writer_type, RMut) in
    if wrong_input <> List.nth view.signature.inputs view.writer_index then
      require "a different input lifetime cannot license the original output object lifetime"
        (refuses (fun () -> ignore (Writer_input_bound.signature_view
          ~owner:producer.injection.original.source_vtable.shape.source_predicate
          ~parameters:view.parameters ~body_regions:view.body_regions
          ~writer_index:view.writer_index ~writer_type:view.writer_type
          { view.signature with inputs = List.mapi (fun index original ->
            if index = view.writer_index then wrong_input else original) view.signature.inputs })))
  ) writer_bound.producers;
  let checked = ref 0 in
  List.iter (fun (node : Source_closure.node) -> match node.frame with
    | Some frame when Option.is_some frame.return_signature ->
        let native = Native_capture_candidate.create ~writer_runtime crate ~node
          ~candidate_id:(FunDeclId.of_int (largest_function + 1)) in
        let original_component = Native_capture_candidate.component_crate crate native in
        let candidate = Aeneas.PrePasses.erase_body_regions original_component native.candidate in
        let component = { original_component with fun_decls = FunDeclId.Map.add candidate.def_id candidate original_component.fun_decls } in
        let witness = Borrow_projection.create component candidate in
        let context = Aeneas.Interp.compute_contexts component in
        let module S = Aeneas.SymbolicToPureTypes in
        let module Q = Aeneas.Pure in
        TypeDeclId.Map.iter (fun _ (declaration : type_decl) ->
          let span = declaration.item_meta.span in
          if Aeneas.TypesUtils.type_decl_has_nested_mut_borrows (Some span)
              context.type_ctx.type_infos declaration then (
            let translated = S.translate_type_decl context declaration in
            require "nested forward declarations retain complete original generic requirements"
              (translated.llbc_generics = declaration.generics);
            let parameters, predicates = S.translate_generic_params (Some span) declaration.generics in
            require "nested forward declarations retain translated parameters and associated predicates"
              (translated.generics = parameters && translated.preds = predicates);
            require "every actual nested forward field and variant has an independent exact certificate"
              (S.complete_nested_forward_kind context span declaration.kind translated.kind);
            require "an opaque declaration cannot stand in for nested forward fields"
              (not (S.complete_nested_forward_kind context span declaration.kind Q.Opaque));
            let original_rows = match declaration.kind with
              | Struct fields -> [fields]
              | Enum variants -> List.map (fun (variant : variant) -> variant.fields) variants
              | _ -> [] in
            let native_rows = match translated.kind with
              | Q.Struct fields -> [fields]
              | Q.Enum variants -> List.map (fun (variant : Q.variant) -> variant.fields) variants
              | Q.Opaque -> [] in
            List.iter2 (List.iter2 (fun (source : field) (native : Q.field) ->
              let mutate_arguments label transform =
                let touched = ref false in
                let visitor = object inherit [_] Q.map_ty as super
                  method! visit_generic_args env (arguments : Q.generic_args) =
                    let arguments = super#visit_generic_args env arguments in
                    match transform arguments with
                    | None -> arguments
                    | Some changed -> touched := true; changed
                end in
                let changed = visitor#visit_ty () native.field_ty in
                if !touched then require label
                  (not (S.complete_forward_type_matches context (Some span) source.field_ty changed)) in
              mutate_arguments "nested forward nominal type arguments cannot be omitted"
                (fun (arguments : Q.generic_args) -> match arguments.types with
                  | [] -> None | _ :: rest -> Some { arguments with types = rest });
              mutate_arguments "nested forward constant arguments cannot be omitted"
                (fun (arguments : Q.generic_args) -> match arguments.const_generics with
                  | [] -> None | _ :: rest -> Some { arguments with const_generics = rest });
              mutate_arguments "nested forward dictionary arguments cannot be omitted"
                (fun (arguments : Q.generic_args) -> match arguments.trait_refs with
                  | [] -> None | _ :: rest -> Some { arguments with trait_refs = rest })
            )) original_rows native_rows;
            let alter_first transform = function
              | Q.Struct (field :: rest) -> Some (Q.Struct (transform field :: rest))
              | Q.Enum (({ fields = field :: rest; _ } as variant) :: variants) ->
                  Some (Q.Enum ({ variant with fields = transform field :: rest } :: variants))
              | _ -> None in
            List.iter (fun (label, transform) ->
              match alter_first transform translated.kind with
              | None -> ()
              | Some changed -> require label
                  (not (S.complete_nested_forward_kind context span declaration.kind changed))
            ) ["a nested forward field cannot become a type-error placeholder",
                 (fun (field : Q.field) -> { field with field_ty = Q.TError });
               "a nested forward field name cannot be lost or changed",
                 (fun (field : Q.field) -> { field with field_name = Some "__changed_nested_forward_field__" })];
            let omitted = match translated.kind with
              | Q.Struct (_ :: rest) -> Some (Q.Struct rest)
              | Q.Enum (_ :: rest) -> Some (Q.Enum rest)
              | _ -> None in
            Option.iter (fun changed -> require "nested forward declarations cannot omit an original field or variant"
              (not (S.complete_nested_forward_kind context span declaration.kind changed))) omitted;
            (match translated.kind with
             | Q.Enum (variant :: rest) ->
                 let changed = Q.Enum ({ variant with discriminant = variant.discriminant + 1 } :: rest) in
                 require "nested forward enum discriminants remain exact"
                   (not (S.complete_nested_forward_kind context span declaration.kind changed))
             | _ -> ())
          )) context.type_ctx.to_extract;
        let native_inputs, expression = match Aeneas.Translate.translate_function_to_symbolics context
            Aeneas.ContextsBase.empty_marked_ids candidate with
          | Some value -> value | None -> failwith "the actual native constructor has no symbolic body" in
        let forward = Native_capture_value.create component witness native_inputs expression in
        let protocol = Native_borrow_protocol.create component witness native_inputs expression forward in
        let ignored_headers = ref 0 in
        let level_queries (abs : Aeneas.Values.abs) =
          let _, active = Native_borrow_protocol.active_levels abs in
          let maximum = List.fold_left max (-1) active in
          for minimum = 0 to maximum + 1 do
            let expected = List.exists (fun level -> level >= minimum) active in
            let actual = Aeneas.InterpBorrowsCore.abs_has_non_ended_eborrows abs minimum ||
              Aeneas.InterpBorrowsCore.abs_has_non_ended_eloans abs minimum in
            require "native live-loan queries agree with complete independent continuation levels, including nested borrow reprojections"
              (actual = expected)
          done in
        let source_headers = object
          inherit [_] Aeneas.SymbolicAst.iter_expr as super
          method! visit_expr env source =
            (match source with
             | Aeneas.SymbolicAst.EndAbs (_, abs, _, _) ->
                 level_queries abs;
                 let changed = ref false in
                 let mutate = object
                   inherit [_] Aeneas.Values.map_tavalue
                   method! visit_aended_ignored_mut_borrow _ (ended : Aeneas.Values.aended_ignored_mut_borrow) =
                     changed := true;
                     { ended with given_back_meta = { ended.given_back_meta with sv_ty = TNever } }
                 end in
                 let avalues = List.map (mutate#visit_tavalue ()) abs.avalues in
                 if !changed then (
                   incr ignored_headers;
                   require "ended-ignored borrow metadata must retain its exact AV/EV producer and type"
                     (refuses (fun () -> ignore (Native_borrow_protocol.observations { abs with avalues }))))
             | Aeneas.SymbolicAst.Return (context, _) ->
                 Aeneas.Values.AbsId.Map.iter (fun _ abs -> level_queries abs)
                   (Aeneas.Contexts.ctx_get_abs context)
             | _ -> ());
            super#visit_expr env source
        end in
        source_headers#visit_expr () expression;
        require "the complete source suite exercises actual ended-ignored mutable-borrow origins" (!ignored_headers > 0);
        let wiring = Native_borrow_wiring.create component witness native_inputs expression forward protocol in
        let projector_kinds = Native_projector_kinds.create component witness native_inputs expression forward protocol wiring in
        let kinds_replay = Native_projector_kinds.replay component witness native_inputs expression forward protocol wiring in
        require "actual per-level classification retains every original mutable source port" (kinds_replay projector_kinds);
        List.iter (fun (branch : Native_projector_kinds.branch) ->
          List.iteri (fun event (ending : Native_projector_kinds.ending) ->
            List.iter (fun (value : Native_projector_kinds.value) ->
              let replace changed = { projector_kinds with branches = List.map (fun (actual : Native_projector_kinds.branch) ->
                if actual.target <> branch.target then actual else { actual with endings = List.mapi (fun index current ->
                  if index <> event then current else { current with values = List.map (fun (original : Native_projector_kinds.value) ->
                    if original.index = value.index then changed else original) current.values }) actual.endings }) projector_kinds.branches } in
              if value.observations <> [] then (
                let first = List.hd value.observations in
                let changed = { first with projector_level = first.projector_level + 1 } in
                require "a reprojection header cannot inherit a different source level"
                  (not (kinds_replay (replace { value with observations = changed :: List.tl value.observations })));
                let changed = { first with projector_source_type = TNever } in
                require "a reprojection cannot inherit an erased or different parent annotation"
                  (not (kinds_replay (replace { value with observations = changed :: List.tl value.observations })));
                let changed = { first with projector_classification_type = TNever } in
                require "fresh given-back classification must retain its actual current source type"
                  (not (kinds_replay (replace { value with observations = changed :: List.tl value.observations }))));
              List.iteri (fun index (selection : Native_projector_kinds.selection) ->
                let replace_selection changed = replace {value with selections = List.mapi
                  (fun actual original -> if actual = index then changed else original) value.selections} in
                require "selected projector patterns retain the independent source identity/type roster" selection.agrees;
                (match selection.selected with
                 | [] -> ()
                 | (edge_type, meta) :: remaining ->
                     require "a selected fresh projector header cannot disappear"
                       (not (kinds_replay (replace_selection {selection with selected = remaining})));
                     let another_identity = Aeneas.Values.SymbolicValueId.of_int
                       (Aeneas.Values.SymbolicValueId.to_int meta.given_back.sv_id + 1) in
                     let changed = {meta with given_back = {meta.given_back with sv_id = another_identity}} in
                     require "equal current types cannot substitute a different fresh source version"
                       (not (kinds_replay (replace_selection {selection with selected = (edge_type, changed) :: remaining})));
                     let another_default = Aeneas.Values.SymbolicValueId.of_int
                       (Aeneas.Values.SymbolicValueId.to_int meta.consumed + 1) in
                     let changed = {meta with consumed = another_default} in
                     require "a fresh header cannot redirect its original lazy-default identity"
                       (not (kinds_replay (replace_selection {selection with selected = (edge_type, changed) :: remaining})));
                     let changed = {meta with given_back = {meta.given_back with sv_ty = TNever}} in
                     require "a selected fresh projector header cannot change its current type"
                       (not (kinds_replay (replace_selection {selection with selected = (edge_type, changed) :: remaining})));
                     require "a selected projector cannot replace its immediate source edge type"
                       (not (kinds_replay (replace_selection {selection with selected = (TNever, meta) :: remaining}))));
                require "a source projector cannot move to a different ending level"
                  (not (kinds_replay (replace_selection {selection with current_level = selection.current_level + 1})));
                (match selection.projector with
                 | Aeneas.Values.AEndedProjBorrows node when node.loans <> [] ->
                   require "selecting an outer fresh value must retain the source's nested loan tree"
                     (not (kinds_replay (replace_selection {selection with projector =
                       Aeneas.Values.AEndedProjBorrows {node with loans = []}})))
                 | _ -> ());
                require "source-coordinate selection cannot lose its exact projector path"
                  (not (kinds_replay (replace_selection {selection with path = selection.path @ [Native_borrow_wiring.Child]})))
              ) value.selections;
              if value.ports <> [] then
                require "classification evidence cannot omit an actual selected source port"
                  (not (kinds_replay (replace { value with ports = List.tl value.ports })))
            ) ending.values
          ) branch.endings
        ) projector_kinds.branches;
        let consumed_coverage = Native_consumed_coverage.analyze component witness native_inputs expression forward protocol wiring in
        let coverage_replay = Native_consumed_coverage.replay component witness native_inputs expression forward protocol wiring in
        require "every real consumed receipt retains its actual origin and complete type shape"
          (Native_consumed_coverage.admitted consumed_coverage && coverage_replay consumed_coverage);
        List.iter (fun (branch : Native_consumed_coverage.branch) ->
          List.iteri (fun event (ending : Native_consumed_coverage.ending) ->
            List.iteri (fun index (update : Native_consumed_coverage.update) ->
              let replace changed = {consumed_coverage with branches = List.map
                (fun (actual : Native_consumed_coverage.branch) -> if actual.target <> branch.target then actual else
                  {actual with endings = List.mapi (fun ending_index current -> if ending_index <> event then current else
                    {current with updates = List.mapi (fun update_index original ->
                      if update_index = index then changed else original) current.updates}) actual.endings}) consumed_coverage.branches} in
              let received = update.edge.received in
              let changed = {received with incoming_id = Aeneas.Values.SymbolicValueId.of_int
                (Aeneas.Values.SymbolicValueId.to_int received.incoming_id + 1)} in
              require "a consumed update cannot claim a different incoming source version"
                (not (coverage_replay (replace {update with edge = {update.edge with received = changed}})));
              let changed = {received with incoming_projection_type = TNever} in
              require "a consumed update cannot lose its actual incoming projection type"
                (not (coverage_replay (replace {update with edge = {update.edge with received = changed}})));
              let changed = {received with actual_given_type = TNever} in
              require "a consumed update cannot change its actual fresh value type"
                (not (coverage_replay (replace {update with edge = {update.edge with received = changed}})));
              if received.ended_regions <> [] then (
                let changed = {received with ended_regions = []} in
                require "coverage must retain the source operation's real ended region set"
                  (not (coverage_replay (replace {update with edge = {update.edge with received = changed}}))));
              require "a supplied total-coverage bit cannot replace the actual native comparison"
                (not (coverage_replay (replace {update with native_covers = not update.native_covers})))
            ) ending.updates
          ) branch.endings
        ) consumed_coverage.branches;
        let consumed_reconstruction = Native_consumed_reconstruction.analyze component witness consumed_coverage in
        let reconstruction_replay = Native_consumed_reconstruction.replay component witness consumed_coverage in
        require "consumed reconstruction retains the actual library code and independently expanded complete source codec"
          (reconstruction_replay consumed_reconstruction);
        if consumed_reconstruction.helpers <> [] then (
          require "consumed reconstruction cannot omit an original consumed receipt"
            (not (reconstruction_replay {consumed_reconstruction with helpers = List.tl consumed_reconstruction.helpers}));
          List.iteri (fun index (helper : Native_consumed_reconstruction.helper) ->
            let replace changed = {consumed_reconstruction with helpers = List.mapi
              (fun actual original -> if actual = index then changed else original) consumed_reconstruction.helpers} in
            require "consumed reconstruction cannot replace the exact receiver region scope"
              (not (reconstruction_replay (replace {helper with update = {helper.update with receiver_regions = []}})));
            require "consumed reconstruction cannot present another source ending as its producer"
              (not (reconstruction_replay (replace {helper with event = helper.event + 1})));
            require "consumed reconstruction cannot change the independently selected source view"
              (not (reconstruction_replay (replace {helper with selected = Native_borrow_defaults.Skip})))
          ) consumed_reconstruction.helpers
        );
        List.iter (fun (branch : Native_borrow_wiring.branch) ->
          List.iter (fun (link : Native_borrow_wiring.internal) ->
            let replace changed = { branch with internal = List.map (fun actual ->
              if actual = link then changed else actual) branch.internal } in
            require "an internal channel cannot lose its actual producer/consumer link"
              (refuses (fun () -> Native_borrow_wiring.validate { branch with internal =
                List.filter ((<>) link) branch.internal }));
            require "an internal channel cannot consume a different symbolic identity"
              (refuses (fun () -> Native_borrow_wiring.validate (replace { link with consumer =
                { link.consumer with value = { link.consumer.value with sv_id =
                  V.SymbolicValueId.of_int (V.SymbolicValueId.to_int link.consumer.value.sv_id + 1000000) } } })));
            require "an internal channel cannot change its consuming level"
              (refuses (fun () -> Native_borrow_wiring.validate (replace { link with consumer =
                { link.consumer with level = link.consumer.level + 1 } })));
            require "an internal channel cannot be consumed before it is produced"
              (refuses (fun () -> Native_borrow_wiring.validate (replace { link with
                producer_event = link.consumer_event; consumer_event = link.producer_event })))
          ) branch.internal;
          match branch.inputs with
          | first :: rest ->
              require "the source event roster prevents omitting an externally routed channel"
                (refuses (fun () -> Native_borrow_wiring.validate { branch with inputs = rest }));
              require "the source event roster prevents promoting an internal producer into a caller argument"
                (List.for_all (fun (link : Native_borrow_wiring.internal) ->
                  refuses (fun () -> Native_borrow_wiring.validate {
                    branch with inputs = link.producer :: first :: rest })) branch.internal)
          | [] -> ()
        ) wiring.branches;
        let borrow_levels = Native_borrow_levels.create component witness native_inputs expression forward protocol wiring in
        let levels_replay = Native_borrow_levels.replay component witness native_inputs expression forward protocol wiring in
        require "native borrowed type levels retain all complete source roots and region groups" (levels_replay borrow_levels);
        require "native borrowed type levels cannot omit a source root"
          (not (levels_replay { borrow_levels with roots = List.tl borrow_levels.roots }));
        require "native borrowed type levels cannot omit a source group"
          (not (levels_replay { borrow_levels with counts = List.tl borrow_levels.counts }));
        List.iter (fun (count : Native_borrow_levels.count) ->
          let replace changed = { borrow_levels with counts = List.map (fun (actual : Native_borrow_levels.count) ->
            if actual.group = count.group then changed else actual) borrow_levels.counts } in
          require "native borrowed type levels cannot replace the real signature maximum with a desired count"
            (not (levels_replay (replace { count with maximum = count.maximum + 1 })));
          require "native borrowed type levels cannot erase the observed actual symbolic port comparison"
            (not (levels_replay (replace { count with owned_levels = [] })))
        ) borrow_levels.counts;
        let backward_types = Native_backward_types.create component witness native_inputs expression forward protocol wiring borrow_levels in
        let types_replay = Native_backward_types.replay component witness native_inputs expression forward protocol wiring borrow_levels in
        require "complete native backward type/signature API witness retains every source root" (types_replay backward_types);
        require "native backward types cannot discard the actual complete forward-type table"
          (not (types_replay { backward_types with forward = [] }));
        require "native backward types cannot omit an actual root/level selection"
          (not (types_replay { backward_types with selections = List.tl backward_types.selections }));
        require "a selected event-leaf interface cannot replace the original native signature"
          (not (types_replay { backward_types with signature = { backward_types.signature with ty = Aeneas.PureUtils.mk_unit_ty } }));
        let native_type = Native_type_syntax.reflect backward_types.signature.ty in
        require "native full type syntax reconstructs the actual original signature, including dictionaries"
          (Aeneas.Pure.compare_ty (Native_type_syntax.decode native_type) backward_types.signature.ty = 0);
        let rec strip_dictionaries = function
          | Native_type_syntax.Node ("arguments", [types; constants; Native_type_syntax.Node ("traits", _ :: _)]) ->
              Native_type_syntax.Node ("arguments", [types; constants; Native_type_syntax.Node ("traits", [])])
          | Native_type_syntax.Node (tag, values) -> Native_type_syntax.Node (tag, List.map strip_dictionaries values)
          | value -> value in
        let stripped = strip_dictionaries native_type in
        require "the actual signature fixture exercises dictionary-bearing native types" (stripped <> native_type);
        require "removing a native dictionary cannot preserve the original complete signature"
          (Aeneas.Pure.compare_ty (Native_type_syntax.decode stripped) backward_types.signature.ty <> 0);
        let bound_type = Aeneas.Pure.TVar (Bound (2, TypeVarId.of_int 0)) in
        require "native type-variable binder depths survive complete reflection"
          (Aeneas.Pure.compare_ty (Native_type_syntax.decode (Native_type_syntax.reflect bound_type)) bound_type = 0);
        require "native generic fields cannot be replaced by an incomplete syntax node"
          (refuses (fun () -> ignore (Native_type_syntax.decode
            (Native_type_syntax.Node ("adt", [Native_type_syntax.Node ("tuple", []);
              Native_type_syntax.Node ("arguments", [Native_type_syntax.Node ("types", [])])])))));
        let root_origins = Native_root_origins.create component witness native_inputs expression forward protocol wiring borrow_levels backward_types in
        let origins_replay = Native_root_origins.replay component witness native_inputs expression forward protocol wiring borrow_levels backward_types in
        require "complete native root origins replay every actual source binding and ending port" (origins_replay root_origins);
        require "root origins cannot omit a source expansion binding" (not (origins_replay { root_origins with aliases = List.tl root_origins.aliases }));
        List.iter (fun (branch : Native_root_origins.branch) ->
          let replace changed = { root_origins with branches = List.map (fun (actual : Native_root_origins.branch) ->
            if actual.target = branch.target then changed else actual) root_origins.branches } in
          require "root origins cannot omit any original owned or foreign ending port"
            (not (origins_replay (replace { branch with ports = List.tl branch.ports })));
          List.iter (fun (port : Native_root_origins.port) ->
            let changed = { port with alias = { port.alias with input = port.alias.input + 1000 } } in
            require "native parent/internal values cannot be moved to a fabricated source parameter"
              (not (origins_replay (replace { branch with ports = List.map (fun actual -> if actual = port then changed else actual) branch.ports })))
          ) branch.ports
        ) root_origins.branches;
        let root_payload = Native_root_payload.create component witness native_inputs expression forward protocol wiring borrow_levels backward_types root_origins in
        let payload_replay = Native_root_payload.replay component witness native_inputs expression forward protocol wiring borrow_levels backward_types root_origins in
        require "whole native root codecs retain every original source field/schema and signature slot" (payload_replay root_payload);
        require "whole native root codecs cannot omit an original source root" (not (payload_replay { root_payload with roots = List.tl root_payload.roots }));
        require "whole native root codecs cannot omit a required native signature slot" (not (payload_replay { root_payload with slots = List.tl root_payload.slots }));
        require "whole native field schemas cannot omit source predicates" (not (payload_replay { root_payload with environment = { root_payload.environment with constraints = [] } }));
        let views = Native_borrow_view.create component witness native_inputs expression forward protocol wiring in
        let transport = Native_borrow_transport.create component witness native_inputs expression forward protocol wiring views in
        let rec atoms = function
          | Borrow_projection.Atom sort -> [sort]
          | Borrow_projection.Product (left, right) | Borrow_projection.Sum (left, right) -> atoms left @ atoms right
          | Borrow_projection.Named (_, contents) | Borrow_projection.Borrow (_, _, contents) -> atoms contents
          | Borrow_projection.Empty | Borrow_projection.Unit -> [] in
        let current = Current_borrow_carrier.create component witness native_inputs expression forward protocol wiring views transport in
        require "actual current-carrier reconstruction must replay against the complete native trace"
          (Current_borrow_carrier.replay component witness native_inputs expression forward protocol wiring views transport current);
        List.iter (fun (branch : Current_borrow_carrier.branch) ->
          List.iter (fun (port : Current_borrow_carrier.port) ->
            require "each actual current-carrier focus must retain its complete candidate port shape"
              (Current_borrow_carrier.target current.output port.focus = port.transport.source_shape);
            require "a missing returned origin cannot be replaced by the whole carrier"
              (not (Current_borrow_carrier.replay component witness native_inputs expression forward protocol wiring views transport
                { current with branches = List.map (fun (original : Current_borrow_carrier.branch) ->
                  if original.target = branch.target then { original with ports = List.map (fun (actual : Current_borrow_carrier.port) ->
                    if actual = port then { actual with focus = Current_borrow_carrier.Here } else actual) original.ports }
                  else original) current.branches }))
          ) branch.ports
        ) current.branches;
        require "an absent current payload cannot be expanded into a whole value"
          (refuses (fun () -> ignore (Native_borrow_defaults.restrict Native_borrow_defaults.Skip Native_borrow_defaults.Keep)));
        require "a skipped current value cannot invent an enum tag even when both alternatives have no payload"
          (refuses (fun () -> ignore (Native_borrow_defaults.restrict Native_borrow_defaults.Skip
            (Native_borrow_defaults.Sum (Native_borrow_defaults.Skip, Native_borrow_defaults.Skip)))));
        let defaults = Native_borrow_defaults.create component witness native_inputs expression forward protocol wiring in
        require "actual native default expressions must retain every immediate current version"
          (Native_borrow_defaults.replay component witness native_inputs expression forward protocol wiring defaults);
        List.iter (fun (branch : Native_borrow_defaults.branch) ->
          List.iter (fun (value : Native_borrow_defaults.default) ->
            match value.origin with
            | Native_borrow_protocol.Borrow _ -> ()
            | Native_borrow_protocol.Symbolic immediate ->
                (match List.filter (fun (parent : Native_borrow_defaults.default) -> parent.value.sv_id = immediate) branch.defaults with
                 | [parent] when parent.origin <> value.origin ->
                     require "a reprojection default cannot be flattened to its parent's earlier default source"
                       (not (Native_borrow_defaults.replay component witness native_inputs expression forward protocol wiring {
                         defaults with branches = List.map (fun (actual : Native_borrow_defaults.branch) ->
                           if actual.target = branch.target then { actual with defaults = List.map (fun (actual : Native_borrow_defaults.default) ->
                             if actual.value.sv_id = value.value.sv_id then { actual with origin = parent.origin } else actual) actual.defaults }
                           else actual) defaults.branches }))
                 | _ -> ())
          ) branch.defaults
        ) defaults.branches;
        let root_bindings = Native_root_bindings.create component witness native_inputs expression forward protocol wiring borrow_levels backward_types root_origins root_payload defaults in
        let binding_replay = Native_root_bindings.replay component witness native_inputs expression forward protocol wiring borrow_levels backward_types root_origins root_payload defaults in
        require "whole native bindings retain every owned and foreign original port" (binding_replay root_bindings);
        List.iter (fun (branch : Native_root_bindings.branch) ->
          let replace changed = { root_bindings with branches = List.map (fun (actual : Native_root_bindings.branch) ->
            if actual.target = branch.target then changed else actual) root_bindings.branches } in
          require "whole native bindings cannot discard a foreign/consumed port"
            (not (binding_replay (replace { branch with actions = List.tl branch.actions })));
          require "source-version correspondence cannot discard the original ending contexts"
            (not (binding_replay (replace { branch with endings = [] })));
          List.iteri (fun index (ending : Native_root_bindings.ending) ->
            let replace_ending changed = replace { branch with endings = List.mapi (fun actual original ->
              if actual = index then changed else original) branch.endings } in
            if ending.nested_returns <> [] then
              require "an outer given-back value cannot discard an actual nested return dependency"
                (not (binding_replay (replace_ending { ending with nested_returns = [] })));
            List.iter (fun (receipt : Native_root_bindings.nested_return) ->
              let changed = { receipt with prior_event = index } in
              require "a nested return must have been consumed at its exact earlier ending"
                (not (binding_replay (replace_ending { ending with nested_returns = List.map (fun actual ->
                  if actual = receipt then changed else actual) ending.nested_returns })))
            ) ending.nested_returns
          ) branch.endings;
          if branch.overlaps <> [] then
            require "an overlapping argument cannot silently discard distinct source-version obligations"
              (not (binding_replay (replace { branch with overlaps = [] })));
          List.iter (fun (overlap : Native_root_bindings.overlap) ->
            require "overlapping versions retain their distinct fresh identities"
              (overlap.first.port.original.value.sv_id <> overlap.second.port.original.value.sv_id);
            let merged = { overlap with second = { overlap.second with
              port = { overlap.second.port with original = { overlap.second.port.original with
                value = overlap.first.port.original.value } }; producer = overlap.first.producer } } in
            require "common storage coordinates cannot merge immediate current producers"
              (not (binding_replay (replace { branch with overlaps = List.map (fun actual ->
                if actual = overlap then merged else actual) branch.overlaps })))
          ) branch.overlaps;
          List.iter (function Native_root_bindings.Bind binding ->
            let changed = Native_root_bindings.Bind { binding with slot = { binding.slot with position = binding.slot.position + 1 } } in
            require "an internal view cannot be supplied by an extra invented native argument slot"
              (not (binding_replay (replace { branch with actions = List.map (fun original -> if original = Native_root_bindings.Bind binding then changed else original) branch.actions })));
            let changed = Native_root_bindings.Bind { binding with projection = { binding.projection with
              term = Native_root_expressions.Bound (binding.projection.native_type, 0, 0) } } in
            require "native argument projection cannot replace its closed field path with an unbound caller result"
              (not (binding_replay (replace { branch with actions = List.map (fun original -> if original = Native_root_bindings.Bind binding then changed else original) branch.actions })))
            | _ -> ()) branch.actions
        ) root_bindings.branches;
        let reconstruction = Native_nested_reconstruction.create component witness native_inputs expression forward protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings in
        let reconstruction_replay = Native_nested_reconstruction.replay component witness native_inputs expression forward protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings in
        require "native nested reconstruction retains every actual dependency and complete expression"
          (reconstruction_replay reconstruction);
        List.iter (fun (helper : Native_nested_reconstruction.helper) ->
          let replace changed = { reconstruction with helpers = List.map (fun actual ->
            if actual = helper then changed else actual) reconstruction.helpers } in
          require "closed native reconstruction retains full generic/type/scope syntax"
            (Aeneas.Pure.compare_texpr (Native_root_expressions.decode helper.term) helper.native = 0);
          if helper.captured_defaults <> [] then
            require "a nonmatching variant cannot lose its actual captured current defaults"
              (not (reconstruction_replay (replace { helper with captured_defaults = [] })));
          (match helper.strategy with
           | Native_pure_expressions.Enumeration (_ :: rows) ->
               require "native reconstruction cannot omit an original enum branch"
                 (not (reconstruction_replay (replace { helper with strategy = Native_pure_expressions.Enumeration rows })))
           | _ -> ());
          let changed = { helper with receipt = { helper.receipt with prior_event = helper.event } } in
          require "a reconstruction cannot replace its nested return with an unconsumed current version"
            (not (reconstruction_replay (replace changed)))
        ) reconstruction.helpers;
        let scoped = Native_scoped_defaults.create component witness native_inputs expression forward protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction in
        let scoped_replay = Native_scoped_defaults.replay component witness native_inputs expression forward protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction in
        require "full-type native lazy defaults retain original scopes, versions and fresh result bindings" (scoped_replay scoped);
        List.iter (fun (branch : Native_scoped_defaults.branch) ->
          List.iter (fun (registration : Native_scoped_defaults.registration) ->
            require "registering a lazy default cannot rebind the independent fresh source symbol"
              (registration.before.symbols = registration.after.symbols);
            require "registering a lazy default cannot mutate current declarations"
              (registration.before.variables = registration.after.variables && registration.before.types = registration.after.types);
            if registration.nested then (
              let replace changed = { scoped with branches = List.map (fun (actual : Native_scoped_defaults.branch) ->
                if actual.target = branch.target then { branch with registrations = List.map (fun original ->
                  if original = registration then changed else original) branch.registrations } else actual) scoped.branches } in
              require "a nested lazy default cannot discard its exact current and nested return captures"
                (not (scoped_replay (replace { registration with entry = { registration.entry with captures = [] } })));
              let module K = Aeneas.SymbolicToPureBindings in
              let module Q = Aeneas.Pure in
              let actual : K.t = { span = witness.candidate.item_meta.span;
                sv_to_var = List.fold_left (fun values (key, value) -> Aeneas.Values.SymbolicValueId.Map.add key value values)
                  Aeneas.Values.SymbolicValueId.Map.empty registration.before.symbols;
                fvars = List.fold_left (fun values (key, value) -> Q.FVarId.Map.add key value values) Q.FVarId.Map.empty registration.before.variables;
                fvars_tys = List.fold_left (fun values (key, value) -> Q.FVarId.Map.add key value values) Q.FVarId.Map.empty registration.before.types;
                fresh_fvar_id = (fun () -> invalid_arg "lazy registration must not allocate a fresh result");
                mut_borrow_to_consumed = Aeneas.Values.BorrowId.Map.empty; var_id_to_default = Q.FVarId.Map.empty } in
              let self = Aeneas.PureUtils.mk_texpr_from_fvar registration.entry.variable in
              require "checked native default registration rejects capture of its own fresh result"
                (try ignore (K.register_checked_default_expression registration.entry.variable.id self actual); false with Invalid_argument _ -> true);
              let absent : Q.fvar = { registration.entry.variable with id = Q.FVarId.of_int (List.length registration.before.variables + 1000) } in
              require "checked native defaults reject missing current variables instead of manufacturing fallback values"
                (try ignore (K.register_checked_default_expression registration.entry.variable.id (Aeneas.PureUtils.mk_texpr_from_fvar absent) actual); false with Invalid_argument _ -> true)
            )
          ) branch.registrations
        ) scoped.branches;
        let foreign = Native_foreign_defaults.create component witness native_inputs expression forward protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction scoped in
        let foreign_replay = Native_foreign_defaults.replay component witness native_inputs expression forward protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction scoped in
        require "foreign default activation retains every original given and consumed ancestor port" (foreign_replay foreign);
        List.iter (fun (branch : Native_foreign_defaults.branch) ->
          let replace changed = { foreign with branches = List.map (fun (actual : Native_foreign_defaults.branch) ->
            if actual.target = branch.target then changed else actual) foreign.branches } in
          if branch.ports <> [] then (
            require "foreign consumed or given ports cannot be dropped from the source roster"
              (not (foreign_replay (replace { branch with ports = List.tl branch.ports })));
            require "foreign source events cannot omit activation or immediate consumption"
              (not (foreign_replay (replace { branch with operations = List.tl branch.operations }))));
          if branch.parents <> [] then
            require "foreign activation must retain complete transitive source ancestry"
              (not (foreign_replay (replace { branch with parents = [] })))
        ) foreign.branches;
        (* Synthetic registry-only negative cases; these are not source events,
           original caller arguments, or runtime value witnesses. *)
        (match List.concat_map (fun (branch : Native_scoped_defaults.branch) -> branch.registrations) scoped.branches with
         | [] -> ()
         | registration :: _ ->
             let module K = Aeneas.SymbolicToPureBindings in
             let module Q = Aeneas.Pure in
             let module U = Aeneas.PureUtils in
             let first = registration.entry.variable in
             let next = List.fold_left (fun maximum (identity, _) -> max maximum (Q.FVarId.to_int identity + 1))
               0 registration.after.variables in
             let second : Q.fvar = { first with id = Q.FVarId.of_int next } in
             let current : Q.fvar = { first with id = Q.FVarId.of_int (next + 1) } in
             let base = Native_foreign_defaults.query_state witness.candidate.item_meta.span registration.after in
             let state = { base with
               fvars = List.fold_left (fun values (variable : Q.fvar) -> Q.FVarId.Map.add variable.id variable values)
                 base.fvars [first; second; current];
               fvars_tys = List.fold_left (fun values (variable : Q.fvar) -> Q.FVarId.Map.add variable.id variable.ty values)
                 base.fvars_tys [first; second; current];
               var_id_to_default = Q.FVarId.Map.empty } in
             let pattern variable = U.mk_tpat_from_fvar None variable in
             require "a missing native current default cannot be replaced by an ordinary result"
               (refuses (fun () -> ignore (K.materialize_pattern_defaults [pattern first] state)));
             let state = K.register_checked_default_expression second.id (U.mk_texpr_from_fvar current) state in
             let state = K.register_checked_default_expression first.id (U.mk_texpr_from_fvar second) state in
             let requested = [pattern first; pattern second] in
             require "native foreign lets must order a dependency before the original requesting binder"
               (List.map (fun ((pattern : Q.tpat), _) -> pattern) (K.materialize_pattern_defaults requested state)
                 = [pattern second; pattern first]);
             require "native foreign lets cannot bind the same fresh variable twice"
               (refuses (fun () -> ignore (K.materialize_pattern_defaults [pattern first; pattern first] state)));
             let cyclic = K.register_checked_default_expression second.id (U.mk_texpr_from_fvar first) state in
             require "mutually recursive lazy defaults must refuse instead of inventing an initial runtime value"
               (refuses (fun () -> ignore (K.materialize_pattern_defaults requested cyclic))));
        let owned = Native_owned_bindings.create component witness native_inputs expression forward protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction scoped in
        let owned_replay = Native_owned_bindings.replay component witness native_inputs expression forward protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction scoped in
        require "native given assignments retain the original whole argument roster and source-version declarations" (owned_replay owned);
        List.iter (fun (branch : Native_owned_bindings.branch) ->
          let replace changed = { owned with branches = List.map (fun (actual : Native_owned_bindings.branch) ->
            if actual.target = branch.target then changed else actual) owned.branches } in
          if branch.arguments <> [] then (
            require "native owned assignments cannot omit an original whole backward argument"
              (not (owned_replay (replace { branch with arguments = List.tl branch.arguments })));
            require "native owned assignments cannot add an independent caller parameter for each port"
              (not (owned_replay (replace { branch with arguments = List.hd branch.arguments :: branch.arguments }))));
          if branch.assignments <> [] then (
            let assignment = List.hd branch.assignments in
            require "native given-back lets cannot omit their original fresh source symbol"
              (not (owned_replay (replace { branch with assignments = List.tl branch.assignments })));
            let changed = { assignment with result = assignment.argument.variable } in
            require "an owned let cannot overwrite its original whole argument instead of binding its fresh given value"
              (not (owned_replay (replace { branch with assignments = changed :: List.tl branch.assignments }))));
          require "materialization cannot alter the source symbolic/default registry"
            (not (owned_replay (replace { branch with declarations = { branch.declarations with symbols = [] } })))
        ) owned.branches;
        let whole = Native_root_programs.create component witness native_inputs expression forward protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction scoped foreign owned in
        let whole_replay = Native_root_programs.replay component witness native_inputs expression forward protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction scoped foreign owned in
        require "whole-root trace retains every original current value, ending port and complete backward output" (whole_replay whole);
        require "a complete capture function cannot replace its returned closure tuple by an unrelated unbound value"
          (not (whole_replay { whole with code = Native_root_expressions.Bound (whole.function_type, 0, 0) }));
        require "the original conservative forward failure effect cannot be removed from the candidate function"
          (not (whole_replay { whole with may_fail = not whole.may_fail }));
        List.iter (fun (branch : Native_root_programs.branch) ->
          let replace changed = { whole with branches = List.map (fun (actual : Native_root_programs.branch) ->
            if actual.target = branch.target then changed else actual) whole.branches } in
          require "a whole-root trace cannot omit an actual ending, even when it has no visible output"
            (not (whole_replay (replace { branch with endings = List.tl branch.endings })));
          require "a whole-root trace cannot drop an original full forward or backward input"
            (not (whole_replay (replace { branch with inputs = List.tl branch.inputs })));
          require "a whole-root trace cannot lose an original full backward output"
            (not (whole_replay (replace { branch with outputs = List.tl branch.outputs })));
          if List.length branch.outputs > 1 then
            require "type-compatible whole backward outputs cannot be silently reordered"
              (not (whole_replay (replace { branch with outputs = List.rev branch.outputs })));
          if branch.initialization <> [] then
            let first = List.hd branch.initialization in
            if first.captures <> [] then
              require "an SSA initializer cannot manufacture an unavailable capture or drop its current operand"
                (not (whole_replay (replace { branch with initialization = { first with captures = [] } :: List.tl branch.initialization })))
        ) whole.branches;
        let execution = Native_borrow_execution.create component witness native_inputs expression forward protocol wiring defaults in
        require "every actual selected-level ending must have a concrete value operation"
          (Native_borrow_execution.replay component witness native_inputs expression forward protocol wiring defaults execution);
        List.iter (fun (branch : Native_borrow_execution.branch) ->
          require "parent ending events cannot disappear just because their values are absent from the final output tuple"
            (not (Native_borrow_execution.replay component witness native_inputs expression forward protocol wiring defaults
              { execution with branches = List.map (fun (actual : Native_borrow_execution.branch) ->
                if actual.target = branch.target then { actual with endings = [] } else actual) execution.branches }));
          List.iter (fun (ending : Native_borrow_execution.ending) ->
            List.iter (fun (operation : Native_borrow_execution.operation) ->
              match operation.kind with
              | Native_borrow_execution.Receive ->
                  require "an incoming higher-level binder cannot be replaced by a default candidate"
                    (not (Native_borrow_execution.replay component witness native_inputs expression forward protocol wiring defaults {
                      execution with branches = List.map (fun (actual : Native_borrow_execution.branch) ->
                        if actual.target = branch.target then { actual with endings = List.map (fun (actual : Native_borrow_execution.ending) ->
                          if actual.event = ending.event then { actual with operations = List.map (fun (actual : Native_borrow_execution.operation) ->
                            if actual = operation then { actual with kind = Native_borrow_execution.Default } else actual) actual.operations }
                          else actual) actual.endings } else actual) execution.branches }))
              | _ -> ()) ending.operations
          ) branch.endings
        ) execution.branches;
        require "an impossible enum tail must remain uninhabited under region selection"
          (Native_borrow_defaults.select [] Borrow_projection.Empty = Native_borrow_defaults.Empty);
        require "a skipped view cannot invent an inhabitant for an impossible enum tail"
          (refuses (fun () -> ignore (Native_borrow_defaults.restrict Native_borrow_defaults.Skip Native_borrow_defaults.Empty)));
        require "an unavailable vector atom cannot be invented while materializing a current carrier"
          (refuses (fun () -> ignore (Native_borrow_full_abi.rebuild (Borrow_projection.Atom (TLiteral (TUInt U8))) Native_borrow_defaults.Skip)));
        let full_abi = Native_borrow_full_abi.create component witness native_inputs expression forward protocol wiring defaults execution in
        require "full native field adapters must retain the actual source/interface channel mapping"
          (Native_borrow_full_abi.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi);
        let pure_payload = Native_pure_payload.create component witness native_inputs expression forward protocol wiring defaults execution full_abi in
        require "native pure payloads must retain all exact field and channel schemas"
          (Native_pure_payload.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload);
        let pure_expressions = Native_pure_expressions.create component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload in
        require "native expression helpers must retain every exact source channel and ownership plan"
          (Native_pure_expressions.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions);
        require "a native expression component cannot omit an actual helper"
          (not (Native_pure_expressions.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload
            { pure_expressions with helpers = List.tl pure_expressions.helpers }));
        List.iter (fun (helper : Native_pure_expressions.helper) ->
          require "a native helper cannot replace source field ownership with a whole current/input return"
            (not (Native_pure_expressions.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload
              { pure_expressions with helpers = List.map (fun (actual : Native_pure_expressions.helper) ->
                if actual = helper then { actual with strategy = (match actual.strategy with
                  | Native_pure_expressions.Current -> Native_pure_expressions.Incoming | _ -> Native_pure_expressions.Current) }
                else actual) pure_expressions.helpers }));
          require "native helper reflection cannot conceal an expression-error placeholder"
            (refuses (fun () -> ignore (Native_pure_expressions.reflect Aeneas.Pure.{ e = EError (None, "source mutation"); ty = helper.native.ty })));
          require "native helper reflection cannot conceal a free variable in a closed interface"
            (refuses (fun () -> ignore (Native_pure_expressions.reflect Aeneas.Pure.{ e = FVar (FVarId.of_int 0); ty = helper.native.ty })))
        ) pure_expressions.helpers;
        let current_wiring = Native_current_wiring.create component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions in
        let current_replays = Native_current_wiring.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions in
        require "native SSA programs must retain all exact source ending operations" (current_replays current_wiring);
        require "native SSA programs cannot omit a branch" (not (current_replays { current_wiring with branches = List.tl current_wiring.branches }));
        List.iter (fun (branch : Native_current_wiring.branch) ->
          let replace changed = { current_wiring with branches = List.map (fun (actual : Native_current_wiring.branch) ->
            if actual.source.target = branch.source.target then changed else actual) current_wiring.branches } in
          require "native SSA programs cannot omit a required post-forward current seed"
            (branch.seeds = [] || not (current_replays (replace { branch with seeds = List.tl branch.seeds })));
          require "native SSA programs cannot omit an actual observation or ending"
            (not (current_replays (replace { branch with operations = List.tl branch.operations })));
          require "native SSA programs cannot change actual higher-level-first input binders"
            (not (current_replays (replace { branch with inputs = List.tl branch.inputs })));
          List.iteri (fun index (operation : Native_current_wiring.operation) -> match operation.action with
            | Native_current_wiring.Output (helper, Some current, incoming, output, error) ->
                let changed = { current with key = Native_borrow_protocol.Symbolic (Aeneas.Values.SymbolicValueId.of_int 999999) } in
                let operations = List.mapi (fun actual (value : Native_current_wiring.operation) ->
                  if actual = index then { value with action = Native_current_wiring.Output (helper, Some changed, incoming, output, error) }
                  else value) branch.operations in
                require "partial native SSA output cannot read a missing current version"
                  (not (current_replays (replace { branch with operations })));
                if current.key = Native_borrow_protocol.Symbolic (Aeneas.Values.SymbolicValueId.of_int 13) then (
                  let changed = { current with key = Native_borrow_protocol.Symbolic (Aeneas.Values.SymbolicValueId.of_int 6) } in
                  let operations = List.mapi (fun actual (value : Native_current_wiring.operation) ->
                    if actual = index then { value with action = Native_current_wiring.Output (helper, Some changed, incoming, output, error) }
                    else value) branch.operations in
                  require "partial native SSA output cannot chase immediate version 13 back to original version 6"
                    (not (current_replays (replace { branch with operations }))))
            | _ -> ()) branch.operations
        ) current_wiring.branches;
        let current_seeds = Native_current_seeds.create component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions current_wiring in
        let seeds_replay = Native_current_seeds.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions current_wiring in
        require "initial native current seeds must come from the same actual forward capture" (seeds_replay current_seeds);
        require "a composed forward/backward component cannot omit a required current seed"
          (not (seeds_replay { current_seeds with seeds = List.tl current_seeds.seeds }));
        List.iter (fun (seed : Native_current_seeds.seed) ->
          let replace changed = { current_seeds with seeds = List.map (fun (actual : Native_current_seeds.seed) ->
            if actual.key = seed.key then changed else actual) current_seeds.seeds } in
          require "a current seed cannot project an absent field from the native returned capture"
            (not (seeds_replay (replace { seed with path = Native_current_seeds.Field 999999 :: seed.path })));
          require "a current seed cannot substitute another symbolic identity with the same erased type"
            (not (seeds_replay (replace { seed with binding = { seed.binding with native =
              { seed.binding.native with sv_id = Aeneas.Values.SymbolicValueId.of_int 999999 } } })));
          let rec wrong_borrow = function
            | [] -> None
            | Native_current_seeds.MutableBorrow _ :: rest -> Some (Native_current_seeds.MutableBorrow (Aeneas.Values.BorrowId.of_int 999999) :: rest)
            | step :: rest -> Option.map (fun rest -> step :: rest) (wrong_borrow rest) in
          Option.iter (fun path -> require "a current seed path must preserve its actual native exclusive borrow identity"
            (not (seeds_replay (replace { seed with path })))) (wrong_borrow seed.path)
        ) current_seeds.seeds;
        let capture_closures = Native_capture_closures.create component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions current_wiring current_seeds in
        let closures_replay = Native_capture_closures.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions current_wiring current_seeds in
        require "native closure bundle must retain all actual source/current/seed/member interfaces" (closures_replay capture_closures);
        require "native closure bundle cannot omit an original region-group member"
          (not (closures_replay { capture_closures with members = List.tl capture_closures.members }));
        require "native closure bundle cannot reorder original region-group members"
          (not (closures_replay { capture_closures with members = List.rev capture_closures.members }));
        List.iter (fun (member : Native_capture_closures.member) ->
          let replace changed = { capture_closures with members = List.map (fun (actual : Native_capture_closures.member) ->
            if actual.index = member.index then changed else actual) capture_closures.members } in
          require "native closure bundle cannot change a member index to another source group"
            (not (closures_replay (replace { member with index = List.length capture_closures.members })));
          require "native adapter Result effect cannot masquerade as the original infallible backward effect"
            (not (closures_replay (replace { member with original_effect = { member.original_effect with can_fail = not member.original_effect.can_fail } })))
        ) capture_closures.members;
        let default_bindings = Native_default_bindings.create component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions current_wiring current_seeds capture_closures in
        let bindings_replay = Native_default_bindings.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions current_wiring current_seeds capture_closures in
        require "shared native registry primitives must retain every actual selected AV/EV leaf" (bindings_replay default_bindings);
        require "shared native registry primitives cannot omit a branch"
          (not (bindings_replay { default_bindings with branches = List.tl default_bindings.branches }));
        require "shared native consumed-borrow context cannot omit an actual forward alias"
          (not (bindings_replay { default_bindings with aliases = List.tl default_bindings.aliases }));
        List.iter (fun (branch : Native_default_bindings.branch) ->
          let replace changed = { default_bindings with branches = List.map (fun (actual : Native_default_bindings.branch) ->
            if actual.target = branch.target then changed else actual) default_bindings.branches } in
          require "shared native registry trace cannot omit a selected given-back registration"
            (not (bindings_replay (replace { branch with registrations = List.tl branch.registrations })));
          require "shared native registry trace cannot supply a different default map"
            (not (bindings_replay (replace { branch with registrations = List.map (fun (registration : Native_default_bindings.registration) ->
              { registration with after = { registration.after with defaults = [] } }) branch.registrations })))
        ) default_bindings.branches;
        let projector_levels = Native_projector_levels.create component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions current_wiring current_seeds capture_closures default_bindings in
        let projector_replay = Native_projector_levels.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions current_wiring current_seeds capture_closures default_bindings in
        require "nested projector consumption must retain exact actual AV/EV types, paths and native reads" (projector_replay projector_levels);
        require "nested projector consumption cannot omit a branch"
          (not (projector_replay { projector_levels with branches = List.tl projector_levels.branches }));
        List.iter (fun (branch : Native_projector_levels.branch) ->
          let replace endings = { projector_levels with branches = List.map (fun (actual : Native_projector_levels.branch) ->
            if actual.target = branch.target then { actual with endings } else actual) projector_levels.branches } in
          require "nested projector consumption cannot omit an actual ending"
            (not (projector_replay (replace (List.tl branch.endings))));
          List.iteri (fun index (ending : Native_projector_levels.ending) ->
            let replace_ending changed = replace (List.mapi (fun actual original -> if actual = index then changed else original) branch.endings) in
            if ending.roots <> [] then (
              require "the complete actual projector forest cannot disappear"
                (not (projector_replay (replace_ending { ending with roots = [] })));
              List.iteri (fun root_index (root : Native_projector_levels.selected_root) ->
                let replace_root changed = replace_ending { ending with roots = List.mapi (fun actual original ->
                  if actual = root_index then changed else original) ending.roots } in
                require "a nested projector cannot be moved to a different sub-abstraction level"
                  (not (projector_replay (replace_root { root with abstract = { root.abstract with level = root.abstract.level + 1 } })));
                match root.abstract.tree.node with
                | Native_projector_levels.Borrow (original, given, _ :: _) ->
                  require "the inner loan of an ended outer borrow cannot be erased"
                    (not (projector_replay (replace_root { root with abstract = { root.abstract with tree =
                      { root.abstract.tree with node = Native_projector_levels.Borrow (original, given, []) } } })))
                | _ -> ()
              ) ending.roots);
            if ending.trace.reads <> [] then
              require "native consumption cannot replace the actual immediate-symbol read with a default chain"
                (not (projector_replay (replace_ending { ending with trace = { ending.trace with reads = [] } })))
          ) branch.endings
        ) projector_levels.branches;
        let binding_closures = Native_binding_closures.create component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions current_wiring current_seeds capture_closures default_bindings projector_levels in
        let binding_closures_replay = Native_binding_closures.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions current_wiring current_seeds capture_closures default_bindings projector_levels in
        require "registry-driven native closures must retain the complete actual source/name/expression relation" (binding_closures_replay binding_closures);
        require "registry-driven native closures cannot omit a backward branch"
          (not (binding_closures_replay { binding_closures with branches = List.tl binding_closures.branches }));
        List.iter (fun (branch : Native_binding_closures.branch) ->
          let replace changed = { binding_closures with branches = List.map (fun (actual : Native_binding_closures.branch) ->
            if actual.source.source.target = branch.source.source.target then changed else actual) binding_closures.branches } in
          require "registry-driven native closures cannot omit typed native/lowered names"
            (not (binding_closures_replay (replace { branch with pairs = [] })));
          require "registry-driven native closures cannot omit actual immediate expression uses"
            (not (binding_closures_replay (replace { branch with uses = [] })));
          require "registry-driven native closures cannot omit a native ending operation"
            (not (binding_closures_replay (replace { branch with operations = List.tl branch.operations })));
          require "registry-driven native closures cannot replace a complete native function with an unrelated unit"
            (not (binding_closures_replay (replace { branch with native = Aeneas.PureUtils.mk_unit_texpr })))
        ) binding_closures.branches;
        let compatible_programs = Native_compatible_programs.create component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions current_wiring current_seeds capture_closures default_bindings projector_levels binding_closures in
        let compatible_replay = Native_compatible_programs.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi pure_payload pure_expressions current_wiring current_seeds capture_closures default_bindings projector_levels binding_closures in
        require "native compatible-input conditions retain every actual helper and value-reference trace" (compatible_replay compatible_programs);
        require "native compatible-input conditions cannot omit an actual helper"
          (not (compatible_replay { compatible_programs with helpers = List.tl compatible_programs.helpers }));
        require "native compatible-input conditions cannot omit an actual branch"
          (not (compatible_replay { compatible_programs with branches = List.tl compatible_programs.branches }));
        List.iter (fun (branch : Native_compatible_programs.branch) ->
          let replace changed = { compatible_programs with branches = List.map (fun (actual : Native_compatible_programs.branch) ->
            if actual.source.source.source.target = branch.source.source.source.target then changed else actual) compatible_programs.branches } in
          require "native compatible-input conditions cannot erase an emitted partial-value obligation"
            (not (compatible_replay (replace { branch with conditions = List.tl branch.conditions })));
          require "native value origins cannot omit an actual earlier let or consumed read"
            (not (compatible_replay (replace { branch with operations = List.tl branch.operations })));
          List.iteri (fun index (condition : Native_compatible_programs.condition) ->
            let replace_condition changed = replace { branch with conditions = List.mapi (fun actual original ->
              if actual = index then changed else original) branch.conditions } in
            require "a native current cannot silently become a different forward/input origin"
              (not (compatible_replay (replace_condition { condition with current = { condition.current with source =
                { condition.current.source with index = condition.current.source.index + 1 } } })));
            if condition.current.aliases <> [] then
              require "a current value derived through an actual let cannot erase that path or chase default metadata"
                (not (compatible_replay (replace_condition { condition with current = { condition.current with aliases = [] } })))
          ) branch.conditions
        ) compatible_programs.branches;
        require "native pure payload schemas cannot omit an actual atom type"
          (not (Native_pure_payload.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi
            { pure_payload with atoms = [] }));
        require "native pure payload schemas cannot omit a complete borrowed nominal"
          (not (Native_pure_payload.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi
            { pure_payload with schemas = [] }));
        List.iter (fun (branch : Native_pure_payload.branch) ->
          require "native pure payload interfaces cannot replace the actual curried argument types"
            (not (Native_pure_payload.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi
              { pure_payload with branches = List.map (fun (actual : Native_pure_payload.branch) ->
                  if actual.target = branch.target then { actual with native_arrow = Aeneas.Pure.TNever } else actual) pure_payload.branches }));
          List.iter (fun (channel : Native_pure_payload.channel) ->
            if channel.incoming.layout <> Native_pure_payload.Atom channel.incoming.native_type then
            require "native pure payloads cannot flatten a nominal/variant field schema to an atom"
              (not (Native_pure_payload.replay component witness native_inputs expression forward protocol wiring defaults execution full_abi
                { pure_payload with branches = List.map (fun (actual : Native_pure_payload.branch) ->
                    if actual.target = branch.target then { actual with channels = List.map (fun (original : Native_pure_payload.channel) ->
                      if original = channel then { original with incoming = { original.incoming with layout = Native_pure_payload.Atom original.incoming.native_type } }
                      else original) actual.channels } else actual) pure_payload.branches }))
          ) branch.channels
        ) pure_payload.branches;
        List.iter (fun (branch : Native_borrow_full_abi.branch) ->
          List.iter (fun (channel : Native_borrow_full_abi.channel) ->
            if not channel.whole then require "a partial borrow cannot acquire whole-pointee ownership"
              (not (Native_borrow_full_abi.replay component witness native_inputs expression forward protocol wiring defaults execution {
                full_abi with branches = List.map (fun (actual : Native_borrow_full_abi.branch) ->
                  if actual.target = branch.target then { actual with channels = List.map (fun (actual : Native_borrow_full_abi.channel) ->
                    if actual = channel then { actual with whole = true } else actual) actual.channels } else actual) full_abi.branches }))
          ) branch.channels
        ) full_abi.branches;
        List.iter (fun (branch : Native_borrow_defaults.branch) ->
          List.iter (fun (value : Native_borrow_defaults.default) ->
            match value.origin with
            | Native_borrow_protocol.Symbolic parent when List.exists (fun (earlier : Native_borrow_defaults.default) -> earlier.value.sv_id = parent) branch.defaults ->
                require "an available parent view must account for every current native field"
                  (not (refuses (fun () -> ignore (Native_borrow_full_abi.rebuild value.candidate_shape
                    (Native_borrow_defaults.selection_plan value.candidate_shape value.available)))));
                require "the selected child view cannot fabricate the parent's skipped atom"
                  (refuses (fun () -> ignore (Native_borrow_full_abi.rebuild value.candidate_shape
                    (Native_borrow_defaults.selection_plan value.candidate_shape value.selected))))
            | _ -> ()
          ) branch.defaults
        ) defaults.branches;
        let atom_types = List.concat_map (fun (branch : Native_borrow_transport.branch) ->
          List.concat_map (fun (port : Native_borrow_transport.port) -> atoms port.source_shape) branch.ports) transport.branches
          |> List.sort_uniq compare in
        (match atom_types with first :: second :: _ ->
          require "native value transport cannot create a cast between different actual opaque atom types"
            (refuses (fun () -> ignore (Native_borrow_transport.change (Borrow_projection.Atom first) (Borrow_projection.Atom second))))
         | _ -> failwith "the actual transport fixture needs both counter and buffer atom types");
        require "native declaration-backed field/value transports must replay"
          (Native_borrow_transport.replay component witness native_inputs expression forward protocol wiring views transport);
        List.iter (fun (branch : Native_borrow_transport.branch) ->
          let view_branch = List.find (fun (original : Native_borrow_view.branch) -> original.target = branch.target) views.branches in
          List.iter (fun (port : Native_borrow_transport.port) ->
            let schema = List.nth view_branch.schemas port.candidate.schema in
            if port.native_shape <> port.source_shape then
              require "native private field names cannot silently become candidate field names"
                (refuses (fun () -> Native_borrow_transport.validate schema { port with native_shape = port.source_shape }));
            require "a transport cannot invent a field/sum/atom representation"
              (refuses (fun () -> Native_borrow_transport.validate schema { port with native_shape = Borrow_projection.Unit }))
          ) branch.ports
        ) transport.branches;
        require "candidate-regionful native view families must replay against all actual origins"
          (Native_borrow_view.replay component witness native_inputs expression forward protocol wiring views);
        require "native candidate binding evidence cannot disappear after forward execution"
          (not (Native_capture_value.replay component witness native_inputs expression { forward with source_bindings = [] }));
        List.iter (fun (branch : Native_borrow_view.branch) ->
          List.iter (fun (port : Native_borrow_view.port) ->
            match port.type_instance.native_arguments with
            | first :: _ :: _ ->
                let visitor = object inherit [_] map_ty
                  method! visit_region _ region =
                    if List.mem region port.type_instance.native_arguments then first else region
                end in
                let native = visitor#visit_ty () port.native.value.sv_ty in
                let schema = List.nth branch.schemas port.schema in
                require "native payload alpha instantiation cannot merge two candidate region names"
                  (refuses (fun () -> ignore (Native_borrow_view.type_instance schema.candidate_type native)))
            | _ -> ()
          ) (branch.inputs @ branch.outputs);
          let changed = { branch with schemas = [] } in
          let changed = { views with branches = List.map (fun (original : Native_borrow_view.branch) ->
            if original.target = branch.target then changed else original) views.branches } in
          require "a routed concrete native port cannot lose its candidate view schema"
            (not (Native_borrow_view.replay component witness native_inputs expression forward protocol wiring changed));
          List.iteri (fun index (schema : Native_borrow_view.schema) ->
            let changed = { schema with shape = Borrow_projection.Atom schema.candidate_type } in
            if changed <> schema then (
              let changed = { branch with schemas = List.mapi (fun position original -> if position = index then changed else original) branch.schemas } in
              let changed = { views with branches = List.map (fun (original : Native_borrow_view.branch) ->
                if original.target = branch.target then changed else original) views.branches } in
              require "a borrowed candidate carrier cannot silently become an opaque payload atom"
                (not (Native_borrow_view.replay component witness native_inputs expression forward protocol wiring changed))
            )
          ) branch.schemas
        ) views.branches;
        require "actual native level-aware payload wiring must replay"
          (Native_borrow_wiring.replay component witness native_inputs expression forward protocol wiring);
        List.iter (fun (branch : Native_borrow_wiring.branch) ->
          require "native payload routes cannot omit a boundary channel"
            (refuses (fun () -> Native_borrow_wiring.validate { branch with routes = [] }));
          require "native payload routes cannot point outside the actual inputs"
            (refuses (fun () -> Native_borrow_wiring.validate { branch with routes =
              List.map (fun _ -> List.length branch.inputs) branch.routes }));
          if List.length branch.inputs > 1 then (
            require "same-typed payloads at different native channels cannot be swapped"
              (refuses (fun () -> Native_borrow_wiring.validate { branch with routes = List.rev branch.routes }));
            require "native channels cannot duplicate a payload and drop another"
              (refuses (fun () -> Native_borrow_wiring.validate { branch with routes = List.map (fun _ -> 0) branch.routes }))
          );
          match branch.outputs with first :: rest ->
            let changed = { first with Native_borrow_wiring.level = first.level + 1 } in
            require "a native payload cannot be routed through a different sub-abstraction level"
              (refuses (fun () -> Native_borrow_wiring.validate { branch with outputs = changed :: rest }))
          | [] -> failwith "the actual native fixture needs a nonempty boundary"
        ) wiring.branches;
        require "the complete actual native backward scope protocol must replay"
          (Native_borrow_protocol.replay component witness native_inputs expression forward protocol);
        List.iter (fun (branch : Native_borrow_protocol.branch) ->
          (match branch.terminal with
           | first :: rest ->
               require "native terminal receipts retain every actual remaining row, including empty or unselected abstractions"
                 (not (Native_borrow_protocol.replay component witness native_inputs expression forward
                   { protocol with branches = List.map (fun (actual : Native_borrow_protocol.branch) ->
                     if actual.target = branch.target then { actual with terminal = rest } else actual) protocol.branches }));
               let live_target = { first with terminal_group = branch.target; terminal_has_live_loans = true } in
               require "completed ending events cannot hide a live target loan in the actual terminal scope"
                 (refuses (fun () -> Native_borrow_protocol.validate protocol { branch with terminal = live_target :: rest }))
           | [] -> ());
          List.iter (fun (event : Native_borrow_protocol.event) ->
            let replace changed = { protocol with branches = List.map (fun (actual : Native_borrow_protocol.branch) ->
              if actual.target = branch.target then { actual with events = List.map (fun (current : Native_borrow_protocol.event) ->
                if current = event then changed else current) actual.events } else actual) protocol.branches } in
            require "native level gap receipts cannot forge the original live-loan query"
              (not (Native_borrow_protocol.replay component witness native_inputs expression forward
                (replace { event with native_no_live_above = not event.native_no_live_above })));
            require "native level gap receipts retain the complete AV active-level scan"
              (not (Native_borrow_protocol.replay component witness native_inputs expression forward
                (replace { event with active_abstract_levels = event.level + 1 :: event.active_abstract_levels })));
            require "native level gap receipts retain the complete EV active-level scan"
              (not (Native_borrow_protocol.replay component witness native_inputs expression forward
                (replace { event with active_continuation_levels = event.level + 1 :: event.active_continuation_levels })))
          ) branch.events;
          require "native backward consumers cannot precede their actual producer events"
            (refuses (fun () -> Native_borrow_protocol.validate protocol { branch with events = List.rev branch.events }));
          require "native backward completion cannot omit all input/output endings"
            (refuses (fun () -> Native_borrow_protocol.validate protocol { branch with events = [] }));
          match branch.events with
          | first :: rest ->
              let changed = { first with Native_borrow_protocol.abstract_values = [] } in
              require "abstraction and continuation producers must agree independently"
                (refuses (fun () -> Native_borrow_protocol.validate protocol { branch with events = changed :: rest }));
              let changed = { first with Native_borrow_protocol.level = first.level + 1 } in
              require "an unfinished abstraction level cannot count as native completion"
                (refuses (fun () -> Native_borrow_protocol.validate protocol { branch with events = changed :: rest }))
          | [] -> failwith "the actual native branch must contain ending events"
        ) protocol.branches;
        require "the actual native forward value trace must replay"
          (Native_capture_value.replay component witness native_inputs expression forward);
        require "native forward steps cannot disappear from the lowering certificate"
          (not (Native_capture_value.replay component witness native_inputs expression { forward with steps = [] }));
        require "native backward branch identities must remain explicitly undischarged"
          (not (Native_capture_value.replay component witness native_inputs expression { forward with backward_groups = [] }));
        require "a native panic cannot acquire a successful forward-value translation"
          (refuses (fun () -> ignore (Native_capture_value.create component witness native_inputs Aeneas.SymbolicAst.Panic)));
        require "the native input list must contain every actual parameter"
          (refuses (fun () -> ignore (Native_capture_value.create component witness [] expression)));
        (match native_inputs with first :: second :: _ ->
          let duplicated = List.map (fun (input : Aeneas.Values.symbolic_value) ->
            if input.sv_id = second.sv_id then { input with sv_id = first.sv_id } else input) native_inputs in
          require "native inputs cannot share one symbolic identity"
            (refuses (fun () -> ignore (Native_capture_value.create component witness duplicated expression)))
         | _ -> failwith "the actual source mutation fixture needs both captured inputs");
        incr checked;
        require "the complete actual source projection schema must replay"
          (Borrow_projection.replay component witness);
        require "a lifetime group cannot disappear from the actual projection interface"
          (not (Borrow_projection.replay component { witness with hierarchy = [] }));
        require "a projected output cannot silently become an unrelated unit type"
          (not (Borrow_projection.replay component { witness with output = {
            witness.output with shape = Borrow_projection.Unit } }));
        require "borrowed nominal definitions and their source conditions cannot disappear"
          (not (Borrow_projection.replay component { witness with nominals = [] }));
        if List.rev witness.capture.moved_inputs <> witness.capture.moved_inputs then
          require "the actual source capture order cannot be replaced by another permutation"
            (not (Borrow_projection.replay component { witness with capture = {
              witness.capture with moved_inputs = List.rev witness.capture.moved_inputs } }));
        require "a captured source input cannot be silently omitted"
          (not (Borrow_projection.replay component { witness with inputs = List.tl witness.inputs }));
        List.iter (fun (input : Borrow_projection.root) ->
          match input.shape with Borrow_projection.Atom _ -> () | _ ->
            require "a borrowed input cannot be hidden behind an opaque source-type atom"
              (not (Borrow_projection.replay component { witness with inputs = List.map
                (fun (original : Borrow_projection.root) -> if original.index = input.index then
                  { original with shape = Borrow_projection.Atom original.source_type } else original) witness.inputs }))
        ) witness.inputs;
        let constrained = List.filter (fun (nominal : Borrow_projection.nominal) ->
          nominal.inherited_requirements.types_outlive <> []) witness.nominals in
        require "the actual native carrier's additional wellformedness conditions must stay visible" (constrained <> []);
        List.iter (fun (nominal : Borrow_projection.nominal) ->
          let changed = { nominal with inherited_requirements = {
            nominal.inherited_requirements with types_outlive = [] } } in
          require "source/native outlives conditions cannot be dropped from the projection evidence"
            (not (Borrow_projection.replay component { witness with nominals =
              List.map (fun original -> if original = nominal then changed else original) witness.nominals }))
        ) constrained;
        let body = match candidate.body with StructuredBody body -> body
          | _ -> failwith "the actual native constructor has no body" in
        let mutate = object inherit [_] map_statement as super
          method! visit_statement env statement =
            let statement = super#visit_statement env statement in
            match statement.kind with
            | Assign (destination, Aggregate (constructor, first :: _ :: rest)) ->
                { statement with kind = Assign (destination, Aggregate (constructor, first :: first :: rest)) }
            | _ -> statement
        end in
        let duplicated = { candidate with body = StructuredBody {
          body with body = mutate#visit_block () body.body } } in
        let mutated = { component with fun_decls = FunDeclId.Map.add duplicated.def_id duplicated component.fun_decls } in
        require "a projected source aggregate cannot consume the same original input twice"
          (refuses (fun () -> ignore (Borrow_projection.create mutated duplicated)))
    | _ -> ()) source.nodes;
  require "the actual full-root corpus must exercise a projected capture constructor" (!checked > 0)
