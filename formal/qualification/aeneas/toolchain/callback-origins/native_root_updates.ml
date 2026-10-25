(* Full native carrier updates preserve all unselected current fields. The
   source focus and selected plan are supplied by the exact source witness. *)
module Q = Aeneas.Pure
module U = Aeneas.PureUtils
module C = Native_root_payload
module R = Native_root_bindings
module G = Current_borrow_carrier
module H = Native_payload_layout
module D = Native_borrow_defaults
module E = Native_pure_expressions
module N = Native_nested_reconstruction
module X = Native_root_expressions

type t = { root : C.root; focus : G.focus; producer : D.default;
  native_type : Q.ty; layout : H.layout; codec : H.codec; strategy : E.strategy;
  native : Q.texpr; code : X.term }
let compile span environment root native_type focus merge =
  let generator, fresh_fvar_id = Q.FVarId.fresh_stateful_generator () in
  let fresh ty : Q.fvar = { id = fresh_fvar_id (); basename = None; ty } in
  let current = fresh root.C.native_type and incoming = fresh native_type in
  let value = U.mk_texpr_from_fvar in
  let rec update native codec focus current = match codec, focus with
    | _, G.Here ->
        if native <> native_type then invalid_arg "a native root update changed its selected leaf's complete type";
        U.mk_apps __FILE__ __LINE__ span merge [current; value incoming]
    | H.CBorrow (_, _, body), G.Borrow next | H.CBoxed body, G.Named next -> update native body next current
    | H.CNominal (_, owner, body), G.Named next when owner = native ->
        let index, child, next = R.projection_field body next in
        let fields = R.structure_fields environment native in
        if index < 0 || index >= List.length fields then invalid_arg "a native root update has no original declared field";
        let variables = List.map (fun (field : Q.field) -> fresh field.field_ty) fields in
        let pattern = U.mk_adt_pat native None (List.map (U.mk_tpat_from_fvar None) variables) in
        let changed = update (List.nth fields index).field_ty child next (value (List.nth variables index)) in
        let reconstructed = U.mk_adt_texpr span native None (List.mapi (fun position variable ->
          if position = index then changed else value variable) variables) in
        U.mk_closed_let span false pattern current reconstructed
    | _ -> invalid_arg "a native root update cannot erase a source wrapper, field or variant" in
  let body = update root.native_type root.codec focus (value current) in
  let native = U.mk_closed_lambdas span (List.map (U.mk_tpat_from_fvar None) [current; incoming]) body in
  ignore generator;
  if native.ty <> U.mk_arrows [root.native_type; native_type] root.native_type then
    invalid_arg "a root update changed its full current/incoming interface";
  native, X.reflect native
let create context span environment root focus (producer : D.default) =
  if G.target root.C.source.shape focus <> producer.candidate_shape then
    invalid_arg "a root update focus differs from its complete source candidate shape";
  let native_type = Aeneas.SymbolicToPureTypes.translate_fwd_ty (Some span) context producer.candidate_type in
  let layout = H.expand environment [] native_type in
  let codec = H.codec context span environment producer.candidate_shape layout in
  let selected = D.selection_plan producer.candidate_shape producer.selected in
  let strategy = E.strategy layout (E.erase_plan codec selected) in
  let merge, _ = N.compile span environment native_type strategy in
  let native, code = compile span environment root native_type focus merge in
  { root; focus; producer; native_type; layout; codec; strategy; native; code }
