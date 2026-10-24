(* Actual pinned Pure.ty payloads and independently instantiated native field
   schemas. This is a field component, not a replacement for translate_type_decl
   or its nested-mutable guard. Expression/default/heap adequacy remains open. *)
open Charon
open Types
module Q = Aeneas.Pure
module U = Aeneas.PureUtils
module S = Aeneas.SymbolicToPureTypes
module P = Borrow_projection
module E = Native_borrow_execution
module A = Native_borrow_full_abi
module H = Native_payload_layout

type pure_type = Nominal of int * pure_type list | Tuple of pure_type list
  | Literal of int | Never | Arrow of pure_type * pure_type | Result of pure_type | Error

let literal = function
  | Q.TPureNat -> 18 | Q.TPureInt -> 19
  | Q.TUInt kind -> Return_region_certificate.literal (Values.TUInt kind)
  | Q.TInt kind -> Return_region_certificate.literal (Values.TInt kind)
  | Q.TFloat kind -> Return_region_certificate.literal (Values.TFloat kind)
  | Q.TBool -> 16 | Q.TChar -> 17

let native_literal = function
  | 0 -> Q.TUInt Values.Usize | 1 -> Q.TUInt Values.U8 | 2 -> Q.TUInt Values.U16
  | 3 -> Q.TUInt Values.U32 | 4 -> Q.TUInt Values.U64 | 5 -> Q.TUInt Values.U128
  | 6 -> Q.TInt Values.Isize | 7 -> Q.TInt Values.I8 | 8 -> Q.TInt Values.I16
  | 9 -> Q.TInt Values.I32 | 10 -> Q.TInt Values.I64 | 11 -> Q.TInt Values.I128
  | 12 -> Q.TFloat Values.F16 | 13 -> Q.TFloat Values.F32
  | 14 -> Q.TFloat Values.F64 | 15 -> Q.TFloat Values.F128
  | 16 -> Q.TBool | 17 -> Q.TChar | 18 -> Q.TPureNat | 19 -> Q.TPureInt
  | _ -> invalid_arg "an invalid literal code cannot stand for a complete native Pure.ty"

let rec reflect_unchecked = function
  | Q.TAdt (id, arguments) ->
      if arguments.const_generics <> [] || arguments.trait_refs <> [] then
        invalid_arg "native payload reflection must retain constants/dictionaries explicitly; they cannot be dropped";
      let types = List.map reflect_unchecked arguments.types in
      (match id with Q.TAdtId id -> Nominal (TypeDeclId.to_int id, types)
       | Q.TTuple -> Tuple types
       | Q.TBuiltin Q.TResult -> (match types with [output] -> Result output
           | _ -> invalid_arg "the native result type lost its exact output argument")
       | Q.TBuiltin Q.TError when types = [] -> Error
       | Q.TBuiltin _ -> invalid_arg "this native payload needs an explicit builtin type representation")
  | Q.TLiteral kind -> Literal (literal kind)
  | Q.TNever -> Never
  | Q.TArrow (input, output) -> Arrow (reflect_unchecked input, reflect_unchecked output)
  | _ -> invalid_arg "this native payload needs an explicit variable/trait/dynamic/error type representation"

let rec decode = function
  | Nominal (id, arguments) when id >= 0 ->
      Q.TAdt (Q.TAdtId (TypeDeclId.of_int id), { U.empty_generic_args with types = List.map decode arguments })
  | Tuple arguments -> Q.TAdt (Q.TTuple, { U.empty_generic_args with types = List.map decode arguments })
  | Literal kind -> Q.TLiteral (native_literal kind)
  | Never -> Q.TNever
  | Arrow (input, output) -> Q.TArrow (decode input, decode output)
  | Result output -> U.mk_result_ty (decode output)
  | Error -> U.mk_error_ty
  | _ -> invalid_arg "a negative nominal identity cannot stand for a native payload type"

let reflect source =
  let view = reflect_unchecked source in
  if Q.compare_ty (decode view) source <> 0 then
    invalid_arg "native pure payload reflection did not reconstruct its complete original Pure.ty";
  view

let rec lean_type = function
  | Nominal (id, arguments) -> ".nominal " ^ string_of_int id ^ " [" ^ String.concat ", " (List.map lean_type arguments) ^ "]"
  | Tuple arguments -> ".tuple [" ^ String.concat ", " (List.map lean_type arguments) ^ "]"
  | Literal kind -> ".literal " ^ string_of_int kind
  | Never -> ".never"
  | Arrow (input, output) -> ".arrow (" ^ lean_type input ^ ") (" ^ lean_type output ^ ")"
  | Result output -> ".result (" ^ lean_type output ^ ")"
  | Error -> ".error"
let pure ty = lean_type (reflect ty)

type label = H.label = NativeNominal of Q.ty | NativeVariant of int | NativeField of int * string option
type layout = H.layout = Atom of Q.ty | Empty | Unit | Product of layout * layout | Sum of layout * layout | Named of label * layout
type codec = H.codec = CAtom of ty * Q.ty | CEmpty | CUnit | CProduct of codec * codec | CSum of codec * codec
  | CNominal of type_decl_ref * Q.ty * codec | CVariant of variant_id * codec
  | CField of int * string option * codec | CBoxed of codec | CBorrow of ref_kind * region * codec
type schema = H.schema = { source : P.nominal; native_type : Q.ty; native_kind : Q.type_decl_kind }
type endpoint = { access : E.access; native_type : Q.ty; layout : layout; codec : codec }
type channel = { source : A.channel; incoming : endpoint; outgoing : endpoint }
type branch = { target : region_group_id; channels : channel list; native_arrow : Q.ty }
type t = { atoms : (ty * Q.ty) list; schemas : schema list; branches : branch list }

let source_atoms = H.source_atoms
let instantiate_native_kind = H.instantiate_native_kind

let derive component projection inputs expression forward protocol wiring defaults execution (full_abi : A.t) =
  if not (A.replay component projection inputs expression forward protocol wiring defaults execution full_abi) then
    invalid_arg "native pure payloads require every exact actual full-field ABI channel";
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native pure payload context contains unresolved errors";
  let translate = S.translate_fwd_ty (Some projection.P.candidate.item_meta.span) context in
  let accesses = List.concat_map (fun (branch : A.branch) -> List.concat_map
    (fun (channel : A.channel) -> [channel.incoming; channel.outgoing]) branch.channels) full_abi.branches in
  let environment = H.create context projection.P.candidate.item_meta.span
    ~validate:(fun ty -> ignore (reflect ty))
    (List.map (fun (access : E.access) -> access.native_shape) accesses)
    (List.concat_map (fun (access : E.access) -> access.nominals) accesses) in
  let atoms = environment.atoms and schemas = environment.schemas in
  if atoms = [] then invalid_arg "the actual native field payloads have no retained atomic source values";
  if List.exists (fun (constraints : H.constraints) -> constraints.declared.trait_type_constraints <> []) environment.constraints then
    invalid_arg "native field schemas need explicit associated-type predicate correspondence";
  let expand = H.expand environment in
  let codec = H.codec context projection.candidate.item_meta.span environment in
  let endpoint (access : E.access) =
    let native_type = translate access.port.value.sv_ty in
    let layout = expand [] native_type in
    { access; native_type; layout; codec = codec access.native_shape layout } in
  let branches = List.map (fun (branch : A.branch) ->
    let channels = List.map (fun (source : A.channel) ->
      let incoming = endpoint source.incoming and outgoing = endpoint source.outgoing in
      if incoming.native_type <> outgoing.native_type || incoming.layout <> outgoing.layout then
        invalid_arg "an actual native full-payload channel changes its complete pure type or field schema";
      { source; incoming; outgoing }) branch.channels in
    (* Retain the actual higher-level-first binder order. This payload arrow
       alone is not the original complete translated function signature. *)
    let grouped ~incoming =
      let endpoint channel = if incoming then channel.incoming else channel.outgoing in
      let position channel = if incoming then channel.source.input_index else channel.source.output_index in
      let ordered = List.stable_sort (fun left right -> Int.compare (position left) (position right)) channels in
      let rec collect = function
        | [] -> []
        | first :: rest ->
            let level = (endpoint first).access.port.level in
            let rec same values = function
              | next :: rest when (endpoint next).access.port.level = level -> same (next :: values) rest
              | rest -> List.rev values, rest in
            let values, rest = same [first] rest in
            if List.exists (fun next -> (endpoint next).access.port.level >= level) rest then
              invalid_arg "actual native ABI port levels are not in the original higher-level-first order";
            U.mk_simpl_tuple_ty (List.map (fun channel -> (endpoint channel).native_type) values) :: collect rest in
      collect ordered in
    let native_arrow = U.mk_arrows (grouped ~incoming:true) (U.mk_simpl_tuple_ty (grouped ~incoming:false)) in
    ignore (reflect native_arrow);
    { target = branch.target; channels; native_arrow }) full_abi.branches in
  { atoms; schemas; branches }

let replay component projection inputs expression forward protocol wiring defaults execution full_abi witness =
  try derive component projection inputs expression forward protocol wiring defaults execution full_abi = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs expression forward protocol wiring defaults execution full_abi =
  let witness = derive component projection inputs expression forward protocol wiring defaults execution full_abi in
  if not (replay component projection inputs expression forward protocol wiring defaults execution full_abi witness) then
    invalid_arg "the actual native Pure.ty field component did not replay";
  witness

let name = function None -> "none" | Some text -> "some " ^ Return_region_certificate.numbers (List.init (String.length text) (fun i -> Char.code text.[i]))
let rec lean_layout = function
  | Atom ty -> ".atom (" ^ pure ty ^ ")" | Empty -> ".empty" | Unit -> ".unit"
  | Product (left, right) -> ".product (" ^ lean_layout left ^ ") (" ^ lean_layout right ^ ")"
  | Sum (left, right) -> ".sum (" ^ lean_layout left ^ ") (" ^ lean_layout right ^ ")"
  | Named (label, body) ->
      let label = match label with NativeNominal ty -> ".nominal (" ^ pure ty ^ ")"
        | NativeVariant id -> ".variant " ^ string_of_int id
        | NativeField (index, field_name) -> ".field " ^ string_of_int index ^ " (" ^ name field_name ^ ")" in
      ".named (" ^ label ^ ") (" ^ lean_layout body ^ ")"
let rec lean_codec = function
  | CAtom (source, native) -> ".atom (" ^ P.reflect source ^ ") (" ^ pure native ^ ") (by decide)"
  | CEmpty -> ".empty" | CUnit -> ".unit"
  | CProduct (left, right) -> ".product (" ^ lean_codec left ^ ") (" ^ lean_codec right ^ ")"
  | CSum (left, right) -> ".sum (" ^ lean_codec left ^ ") (" ^ lean_codec right ^ ")"
  | CNominal (reference, ty, body) -> ".nominal (" ^ P.reflect (TAdt reference) ^ ") (" ^ pure ty ^ ") (" ^ lean_codec body ^ ")"
  | CVariant (id, body) -> ".variant " ^ string_of_int (VariantId.to_int id) ^ " (" ^ lean_codec body ^ ")"
  | CField (index, field_name, body) -> ".field " ^ string_of_int index ^ " (" ^ name field_name ^ ") (" ^ lean_codec body ^ ")"
  | CBoxed body -> ".boxed (" ^ lean_codec body ^ ")"
  | CBorrow (kind, region, body) -> ".borrow " ^ (match kind with RMut -> "true" | RShared -> "false") ^
      " (" ^ Return_region_certificate.lean_region region ^ ") (" ^ lean_codec body ^ ")"

let report component projection inputs expression forward protocol wiring defaults execution full_abi witness =
  if not (replay component projection inputs expression forward protocol wiring defaults execution full_abi witness) then
    invalid_arg "native pure payload report lost its complete source/type/schema witness";
  `Assoc [
  "schema", `String "actual-native-pure-type-field-payloads/v1";
  "native_type_reflection_roundtrips_complete_supported_ast", `Bool true;
  "native_field_schema_instantiation_commutes", `Bool true;
  "atom_types", `List (List.map (fun (source, native) -> `Assoc ["source", `String (P.reflect source); "native", `String (Q.show_ty native)]) witness.atoms);
  "native_instantiated_schemas", `List (List.map (fun (schema : schema) -> `Assoc [
    "source_reference", `String (show_type_decl_ref schema.source.reference);
    "native_type", `String (Q.show_ty schema.native_type);
    "complete_native_kind", `String (Q.show_type_decl_kind schema.native_kind)]) witness.schemas);
  "branches", `List (List.map (fun branch -> `Assoc ["group", `Int (RegionGroupId.to_int branch.target);
    "actual_port_payload_arrow", `String (Q.show_ty branch.native_arrow);
    "channels", `List (List.map (fun channel -> `Assoc [
      "symbol", `Int (Aeneas.Values.SymbolicValueId.to_int channel.incoming.access.port.value.sv_id);
      "level", `Int channel.incoming.access.port.level;
      "complete_incoming_native_type", `String (Q.show_ty channel.incoming.native_type);
      "complete_outgoing_native_type", `String (Q.show_ty channel.outgoing.native_type);
      "native_field_layout", `String (lean_layout channel.incoming.layout)]) branch.channels)]) witness.branches);
  "native_expression_default_and_continuation_adequacy_proved", `Bool false;
  "original_complete_native_signature_constructed", `Bool false;
  "original_rust_heap_loan_layout_and_ownership_refinement_proved", `Bool false;
  "pinned_nested_mutable_adt_guard_removed", `Bool false;
  "native_program_emitted", `Bool false; "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let buffer = Buffer.create 16384 in
  let line text = Buffer.add_string buffer (text ^ "\n") in
  line "import Auths.Support.NativePurePayload";
  line "import qualification.aeneas.cases.NativeBorrowFullABI";
  line "/- Exact pinned native Pure.ty payload/field schemas; unelaborated/unqualified.";
  line "   Complete signature/expression/default/continuation and source/native heap adequacy remain required. -/";
  line "namespace Auths.Qualification.NativePurePayload";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.NativePurePayload";
  line "universe u";
  line "def atomTyping : AtomTyping := fun source =>";
  List.iter (fun (source, native) -> line ("  if source = " ^ P.reflect source ^ " then some (" ^ pure native ^ ") else")) witness.atoms;
  line "  none";
  List.iter (fun branch ->
    let prefix = "branch" ^ string_of_int (RegionGroupId.to_int branch.target) in
    line ("def " ^ prefix ^ "PayloadArrow : Ty := " ^ pure branch.native_arrow);
    List.iteri (fun index channel ->
      let base = prefix ^ "Channel" ^ string_of_int index in
      line ("def " ^ base ^ "Layout : Layout := " ^ lean_layout channel.incoming.layout);
      List.iter (fun (suffix, endpoint) ->
        let name = base ^ suffix in
        line ("def " ^ name ^ "Shape : Shape := " ^ P.lean endpoint.access.native_shape);
        line ("def " ^ name ^ "Codec : Codec atomTyping " ^ name ^ "Shape " ^ base ^ "Layout := " ^ lean_codec endpoint.codec);
        line ("theorem " ^ name ^ "_source_roundtrip (Atom : Ty → Type u)");
        line ("    (value : Data (SourceAtom atomTyping Atom) " ^ name ^ "Shape) :");
        line ("    decode " ^ name ^ "Codec (encode " ^ name ^ "Codec value) = value := decode_encode _ _");
        line ("theorem " ^ name ^ "_native_field_roundtrip (Atom : Ty → Type u)");
        line ("    (value : Value Atom " ^ base ^ "Layout) :");
        line ("    encode " ^ name ^ "Codec (decode " ^ name ^ "Codec value) = value := encode_decode _ _")
      ) ["Incoming", channel.incoming; "Outgoing", channel.outgoing];
      let actual = "Auths.Qualification.NativeBorrowFullABI." ^ base in
      line ("def " ^ base ^ "Native (Atom : Ty → Type u) (current incoming : Value Atom " ^ base ^ "Layout) :");
      line ("    Option (Value Atom " ^ base ^ "Layout) := adaptNative " ^ actual ^ " " ^ base ^ "IncomingCodec " ^ base ^ "OutgoingCodec current incoming");
      line ("theorem " ^ base ^ "_matching_native_input_is_accepted (Atom : Ty → Type u) (current : Value Atom " ^ base ^ "Layout) :");
      line ("    " ^ base ^ "Native Atom current (matchingNativeInput " ^ actual ^ " " ^ base ^ "IncomingCodec " ^ base ^ "OutgoingCodec current) = some current :=");
      line ("  matching_native_input_is_accepted " ^ actual ^ " " ^ base ^ "IncomingCodec " ^ base ^ "OutgoingCodec current");
      line ("theorem " ^ base ^ "_native_current_frame_preserved (Atom : Ty → Type u)");
      line ("    (current after incoming : Value Atom " ^ base ^ "Layout) (accepted : " ^ base ^ "Native Atom current incoming = some after) :");
      line ("    get (Auths.Support.CurrentBorrowCarrier.complement " ^ actual ^ ".outgoingPlan) (decode " ^ base ^ "OutgoingCodec after) =");
      line ("      get (Auths.Support.CurrentBorrowCarrier.complement " ^ actual ^ ".outgoingPlan) (decode " ^ base ^ "OutgoingCodec current) :=");
      line ("  accepted_native_preserves_current_frame " ^ actual ^ " " ^ base ^ "IncomingCodec " ^ base ^ "OutgoingCodec current after incoming accepted")
    ) branch.channels
  ) witness.branches;
  line "end Auths.Qualification.NativePurePayload";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
