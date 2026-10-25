(* Codecs for the actual complete native signature carriers. They retain full
   dictionary-bearing native types and all instantiated fields. Logical data
   conversion does not supply a callee result, heap or continuation semantics. *)
open Charon
open Types
module Q = Aeneas.Pure
module S = Aeneas.SymbolicToPureTypes
module P = Borrow_projection
module B = Native_borrow_protocol
module L = Native_borrow_levels
module N = Native_backward_types
module R = Native_root_origins
module H = Native_payload_layout
module T = Native_type_syntax

type root = { source : L.root; native_type : Q.ty; layout : H.layout; codec : H.codec }
type slot = { group : region_group_id; level : int; input : bool; position : int; root : root }
type t = { origins : R.t; environment : H.t; roots : root list; slots : slot list }

let derive component (projection : P.t) inputs symbolic forward protocol wiring levels signature origins =
  if not (R.replay component projection inputs symbolic forward protocol wiring levels signature origins) then
    invalid_arg "whole native payloads require the complete actual source origins and original signature";
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "whole native payload context has unresolved errors";
  let span = projection.candidate.item_meta.span in
  let validate ty =
    let visitor = object inherit [_] Q.iter_ty as super
      method! visit_ty env ty =
        if ty = Q.TError then invalid_arg "a native type-error placeholder cannot supply a whole payload";
        super#visit_ty env ty
      method! visit_UnknownTrait _ _ = invalid_arg "an unresolved native dictionary cannot supply a whole payload"
    end in
    visitor#visit_ty () ty; ignore (T.reflect ty) in
  let environment = H.create context span ~validate
    (List.map (fun (root : L.root) -> root.shape) signature.N.levels.roots) projection.nominals in
  let roots = List.map (fun (source : L.root) ->
    let native_type = S.translate_fwd_ty (Some span) context source.source in
    ignore (T.reflect native_type);
    let layout = H.expand environment [] native_type in
    let codec = H.codec context span environment source.shape layout in
    { source; native_type; layout; codec }) signature.levels.roots in
  let get_group region = match List.assoc_opt region signature.levels.mapping with
    | Some group -> group | None -> invalid_arg "whole native row codecs cannot guess a source region group" in
  let slots = List.concat_map (fun (group, (info : Q.back_sg_info)) ->
    let rows input actual = List.concat_map (fun (level, fields) ->
      let selected = List.filter_map (fun root ->
        let from_input = Option.is_some root.source.index in
        let included = if from_input then input || level = 0 else not input || level = 0 in
        if not included then None else
          let native = if input then S.translate_back_input_ty (Some span) context get_group group level ~from_input root.source.source
            else S.translate_back_output_ty (Some span) context get_group group level ~from_input root.source.source in
          Option.map (fun native -> root, native) native) roots in
      if List.length selected <> List.length fields then invalid_arg "whole native row codecs omitted an original signature field";
      List.mapi (fun position ((root, selected), (_, actual)) ->
        if selected <> actual then invalid_arg "whole native row codecs changed an actual complete signature field type";
        if root.native_type <> selected then
          invalid_arg "a selected native root needs an explicit structural projection; no whole-root forward type may be assumed";
        { group; level; input; position; root }) (List.combine selected fields)) actual in
    rows true info.inputs @ rows false info.outputs) (RegionGroupId.Map.bindings signature.signature.dsg.fun_ty.back_sg) in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "whole native payload construction produced unresolved native diagnostics";
  { origins; environment; roots; slots }

let replay component projection inputs symbolic forward protocol wiring levels signature origins witness =
  try derive component projection inputs symbolic forward protocol wiring levels signature origins = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs symbolic forward protocol wiring levels signature origins =
  let witness = derive component projection inputs symbolic forward protocol wiring levels signature origins in
  if not (replay component projection inputs symbolic forward protocol wiring levels signature origins witness) then
    invalid_arg "actual complete native whole-root field codecs did not replay";
  witness

let rec lean_layout = function
  | H.Atom ty -> ".atom (" ^ T.pure ty ^ ")" | H.Empty -> ".empty" | H.Unit -> ".unit"
  | H.Product (left, right) -> ".product (" ^ lean_layout left ^ ") (" ^ lean_layout right ^ ")"
  | H.Sum (left, right) -> ".sum (" ^ lean_layout left ^ ") (" ^ lean_layout right ^ ")"
  | H.Named (label, body) ->
      let label = match label with H.NativeNominal ty -> ".nominal (" ^ T.pure ty ^ ")"
        | H.NativeVariant index -> ".variant " ^ B.nat index
        | H.NativeField (index, name) -> ".field " ^ B.nat index ^ " (" ^ Native_pure_expressions.text name ^ ")" in
      ".named (" ^ label ^ ") (" ^ lean_layout body ^ ")"
let rec lean_codec = function
  | H.CAtom (source, native) -> ".atom (" ^ P.reflect source ^ ") (" ^ T.pure native ^ ") (by rfl)"
  | H.CEmpty -> ".empty" | H.CUnit -> ".unit"
  | H.CProduct (left, right) -> ".product (" ^ lean_codec left ^ ") (" ^ lean_codec right ^ ")"
  | H.CSum (left, right) -> ".sum (" ^ lean_codec left ^ ") (" ^ lean_codec right ^ ")"
  | H.CNominal (source, native, body) -> ".nominal (" ^ P.reflect (TAdt source) ^ ") (" ^ T.pure native ^ ") (" ^ lean_codec body ^ ")"
  | H.CVariant (variant, body) -> ".variant " ^ B.nat (VariantId.to_int variant) ^ " (" ^ lean_codec body ^ ")"
  | H.CField (index, name, body) -> ".field " ^ B.nat index ^ " (" ^ Native_pure_expressions.text name ^ ") (" ^ lean_codec body ^ ")"
  | H.CBoxed body -> ".boxed (" ^ lean_codec body ^ ")"
  | H.CBorrow (kind, region, body) -> ".borrow " ^ B.bool (kind = RMut) ^ " (" ^ Return_region_certificate.lean_region region ^ ") (" ^ lean_codec body ^ ")"
let rec depth = function
  | H.Atom ty -> 1 + T.depth (T.reflect ty) | H.Empty | H.Unit -> 1
  | H.Product (left, right) | H.Sum (left, right) -> 1 + max (depth left) (depth right)
  | H.Named (label, body) -> 1 + max (depth body) (match label with H.NativeNominal ty -> T.depth (T.reflect ty) | _ -> 1)
let fuel witness = 32 + 4 * List.fold_left (fun size root -> max size (depth root.layout)) 0 witness.roots
let root_name root = L.root_name root.source
let lean_schema (schema : H.schema) =
  let fields fields = B.list (fun (field : Q.field) -> "{ name := " ^ Native_pure_expressions.text field.field_name ^
    ", type := " ^ T.pure field.field_ty ^ " }") fields in
  let rows = match schema.native_kind with Q.Struct values -> [None, values]
    | Q.Enum variants -> List.mapi (fun index (variant : Q.variant) -> Some index, variant.fields) variants
    | Q.Opaque -> invalid_arg "an opaque native schema cannot provide borrowed whole-root fields" in
  "{ type := " ^ T.pure schema.native_type ^ ", rows := " ^ B.list (fun (variant, values) ->
    "(" ^ (match variant with None -> "none" | Some index -> "some " ^ B.nat index) ^ ", " ^ fields values ^ ")") rows ^ " }"

let report component projection inputs symbolic forward protocol wiring levels signature origins witness =
  if not (replay component projection inputs symbolic forward protocol wiring levels signature origins witness) then
    invalid_arg "whole native codec report lost an original root, native type, declaration or predicate";
  `Assoc ["schema", `String "actual-native-whole-signature-payload-codecs/v1";
    "metadata_fuel", `Int (fuel witness);
    "roots", `List (List.map (fun root -> `Assoc ["root", `String (root_name root);
      "complete_native_type", `String (Q.show_ty root.native_type); "complete_native_layout", `String (lean_layout root.layout);
      "source_shape", `String (P.lean root.source.shape)]) witness.roots);
    "actual_signature_slots", `List (List.map (fun slot -> `Assoc ["group", `Int (RegionGroupId.to_int slot.group);
      "level", `Int slot.level; "input", `Bool slot.input; "position", `Int slot.position;
      "root", `String (root_name slot.root)]) witness.slots);
    "complete_native_field_declarations", `List (List.map (fun (schema : H.schema) -> `Assoc [
      "complete_source_reference", `String (show_type_decl_ref schema.source.reference);
      "complete_native_type", `String (Q.show_ty schema.native_type);
      "complete_native_kind", `String (Q.show_type_decl_kind schema.native_kind)]) witness.environment.schemas);
    "complete_declaration_predicates", `List (List.map (fun (constraint_ : H.constraints) -> `Assoc [
      "complete_source_requirements", `String (show_generic_params constraint_.source.inherited_requirements);
      "native_parameters", `String (Q.show_generic_params constraint_.parameters);
      "native_declared_predicates", `String (Q.show_predicates constraint_.declared);
      "native_instantiated_predicates", `String (Q.show_predicates constraint_.instantiated);
      "native_source_first_predicates", `String (Q.show_predicates constraint_.source_first)]) witness.environment.constraints);
    "complete_field_and_predicate_instantiation_commutes", `Bool true;
    "actual_original_full_signature_field_types_retained", `Bool true;
    "signature_API_uses_candidate_nested_nominal_backtype_extension", `Bool true;
    "whole_root_can_represent_all_current_version_channels_proved", `Bool false;
    "event_ports_replaced_original_root_arguments", `Bool false;
    "native_forward_declaration_expression_ending_heap_loan_adequacy_proved", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let buffer = Buffer.create 262144 in
  let line value = Buffer.add_string buffer (value ^ "\n") in
  line "import Auths.Support.NativeRootPayload";
  line "import qualification.aeneas.cases.NativeRootOrigins";
  line "/- Complete actual native signature carriers/fields; unelaborated/unqualified.";
  line "   Logical codecs do not establish runtime expression/ending or source heap/loan adequacy. -/";
  line "namespace Auths.Qualification.NativeRootPayload";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.NativeRootPayload";
  line "universe u";
  line ("def fuel : Nat := " ^ B.nat (fuel witness));
  line ("def atomTypes : List NativeType := " ^ B.list T.pure (List.map snd witness.environment.atoms));
  line ("def schemas : List Schema := " ^ B.list lean_schema witness.environment.schemas);
  line "def atomTyping : AtomTyping := fun source =>";
  List.iter (fun (source, native) -> line ("  if source = " ^ P.reflect source ^ " then some (" ^ T.pure native ^ ") else")) witness.environment.atoms;
  line "  none";
  List.iter (fun root ->
    let name = root_name root in
    line ("def " ^ name ^ "Shape : Shape := " ^ P.lean root.source.shape);
    line ("def " ^ name ^ "NativeType : NativeType := " ^ T.pure root.native_type);
    line ("def " ^ name ^ "Layout : Layout := " ^ lean_layout root.layout);
    line ("def " ^ name ^ "Codec : Codec atomTyping " ^ name ^ "Shape " ^ name ^ "Layout := " ^ lean_codec root.codec);
    line ("theorem " ^ name ^ "_has_every_actual_native_field : check fuel atomTypes schemas " ^ name ^ "NativeType " ^ name ^ "Layout = true := by decide");
    line ("theorem " ^ name ^ "_source_roundtrip (Atom : NativeType → Type u) (value : Data (SourceAtom atomTyping Atom) " ^ name ^ "Shape) :");
    line ("    decode " ^ name ^ "Codec (encode " ^ name ^ "Codec value) = value := decode_encode _ _");
    line ("theorem " ^ name ^ "_native_roundtrip (Atom : NativeType → Type u) (value : Value Atom " ^ name ^ "Layout) :");
    line ("    encode " ^ name ^ "Codec (decode " ^ name ^ "Codec value) = value := encode_decode _ _")
  ) witness.roots;
  List.iter (fun slot ->
    let name = "group" ^ B.gid slot.group ^ "Level" ^ B.nat slot.level ^ (if slot.input then "Input" else "Output") ^ B.nat slot.position in
    let rows = "Auths.Qualification.NativeBackwardTypes.group" ^ B.gid slot.group ^ (if slot.input then "Inputs" else "Outputs") in
    line ("theorem " ^ name ^ "_is_the_original_native_signature_type :");
    line ("    ((" ^ rows ^ ".find? (fun row => row.1 == " ^ B.nat slot.level ^ ")).bind (fun row => row.2[" ^ B.nat slot.position ^ "]?)) =");
    line ("      some " ^ root_name slot.root ^ "NativeType := by rfl")
  ) witness.slots;
  line "end Auths.Qualification.NativeRootPayload";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
