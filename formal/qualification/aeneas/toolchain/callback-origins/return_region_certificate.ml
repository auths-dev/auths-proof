(* Exact structural data for the actual closure-return lifetime certificate.
   No pretty-printed type, hash, arbitrary ordinary result or native lifetime
   is used as a stand-in for a source type/dictionary. Unsupported constructors
   refuse this component reflection; the full native-emission gates remain. *)
open Charon
open Types

type expr = Natural of int | Bytes of int list | Region of region
  | OutputSlot of int | Node of string * expr list | Binder of int list * expr

type t = {
  public_parameters : int list;
  original_regions : region list;
  reconstructed_regions : region list;
  declared_inputs : expr list;
  field_patterns : expr list;
  original_output : expr;
  reconstructed_output : expr;
}

let natural value = if value < 0 then invalid_arg "a structural source certificate cannot encode a negative identifier" else Natural value
let list tag values = Node (tag, values)
let bytes value = Bytes (List.init (String.length value) (fun index -> Char.code value.[index]))
let name = function None -> Node ("noName", []) | Some value -> Node ("someName", [bytes value])
let variance = function Covariant -> 0 | Invariant -> 1 | Contravariant -> 2 | Bivariant -> 3 | VaUnknown -> 4
let mutability = function LtMutable -> 0 | LtShared -> 1 | LtUnknown -> 2
let parameter (value : region_param) = Node ("regionParameter", [natural (RegionId.to_int value.index);
  name value.name; natural (variance value.variance); natural (mutability value.mutability)])

let option encode = function None -> Node ("noneValue", []) | Some value -> Node ("someValue", [encode value])
let source_location (value : Meta.loc) = Node ("sourceLocation", [natural value.line; natural value.col])
let source_file (value : Meta.file) =
  let filename = match value.name with
    | Meta.Local path -> Node ("localFile", [bytes path])
    | Meta.Virtual path -> Node ("virtualFile", [bytes path])
    | Meta.NotReal path -> Node ("notRealFile", [bytes path]) in
  Node ("sourceFile", [filename; bytes value.crate_name; option bytes value.contents])
let source_span_data (value : Meta.span_data) = Node ("sourceSpanData",
  [source_file value.file; source_location value.beg_loc; source_location value.end_loc])
let source_span (value : Meta.span) = Node ("sourceSpan",
  [source_span_data value.data; option source_span_data value.generated_from_span])
let type_parameter (value : type_param) = Node ("typeParameter",
  [natural (TypeVarId.to_int value.index); bytes value.name; natural (variance value.variance)])
let predicate_origin = function
  | WhereClauseOnFn -> Node ("predicateOrigin", [natural 0])
  | WhereClauseOnType -> Node ("predicateOrigin", [natural 1])
  | WhereClauseOnImpl -> Node ("predicateOrigin", [natural 2])
  | TraitSelf -> Node ("predicateOrigin", [natural 3])
  | WhereClauseOnTrait -> Node ("predicateOrigin", [natural 4])
  | TraitItem id -> Node ("predicateOrigin", [natural 5; natural (AssocTypeId.to_int id)])
  | OriginDyn -> Node ("predicateOrigin", [natural 6])
let reflect_binder encode (value : 'a region_binder) =
  Region_scope.require_parameters value.binder_regions;
  let ids = List.map (fun (region : region_param) -> RegionId.to_int region.index) value.binder_regions in
  Binder (ids, Node ("predicateBinder", [list "regionParameters" (List.map parameter value.binder_regions); encode value.binder_value]))

let literal = function
  | Values.TUInt Values.Usize -> 0 | Values.TUInt Values.U8 -> 1 | Values.TUInt Values.U16 -> 2
  | Values.TUInt Values.U32 -> 3 | Values.TUInt Values.U64 -> 4 | Values.TUInt Values.U128 -> 5
  | Values.TInt Values.Isize -> 6 | Values.TInt Values.I8 -> 7 | Values.TInt Values.I16 -> 8
  | Values.TInt Values.I32 -> 9 | Values.TInt Values.I64 -> 10 | Values.TInt Values.I128 -> 11
  | Values.TFloat Values.F16 -> 12 | Values.TFloat Values.F32 -> 13
  | Values.TFloat Values.F64 -> 14 | Values.TFloat Values.F128 -> 15
  | Values.TBool -> 16 | Values.TChar -> 17

let builtin = function
  | BuiltinAuto -> 0 | BuiltinSized -> 1 | BuiltinMetaSized -> 2 | BuiltinPointeeSized -> 3
  | BuiltinCopy -> 4 | BuiltinClone -> 5 | BuiltinTuple -> 6 | BuiltinTransmute -> 7
  | BuiltinUnsize -> 8 | BuiltinPointee -> 9 | BuiltinDiscriminantKind -> 10 | BuiltinFn -> 11
  | BuiltinFnMut -> 12 | BuiltinFnOnce -> 13 | BuiltinFnPtr -> 14 | BuiltinAsyncFn -> 15
  | BuiltinAsyncFnMut -> 16 | BuiltinAsyncFnOnce -> 17 | BuiltinCoroutine -> 18
  | BuiltinFuture -> 19 | BuiltinNoopDestruct -> 20 | BuiltinUntrackedDestruct -> 21
  | BuiltinRemovedAdtClause -> 22

let reflect_unchecked_type ~holes =
  let region value = match List.find_opt (fun (_, marker) -> marker = value) holes with
    | Some (slot, _) -> OutputSlot slot
    | None -> Region value in
  let rec ty = function
    | TAdt reference ->
        let arguments = args reference.generics in
        (match reference.id with
         | TAdtId id -> Node ("adt", [natural (TypeDeclId.to_int id); arguments])
         | TTuple -> Node ("tuple", [arguments])
         | TBuiltin TBox -> Node ("boxType", [arguments])
         | TBuiltin TStr -> Node ("strType", [arguments]))
    | TRef (lifetime, inner, kind) -> Node ((match kind with RMut -> "mutRef" | RShared -> "sharedRef"), [region lifetime; ty inner])
    | TRawPtr (inner, kind) -> Node ((match kind with RMut -> "mutPtr" | RShared -> "sharedPtr"), [ty inner])
    | TVar (Free index) -> Node ("typeFree", [natural (TypeVarId.to_int index)])
    | TVar (Bound (depth, index)) -> Node ("typeBound", [natural depth; natural (TypeVarId.to_int index)])
    | TLiteral kind -> Node ("literal", [natural (literal kind)])
    | TNever -> Node ("neverType", [])
    | TDynTrait predicate ->
        let binder = predicate.binder in
        Region_scope.require_parameters binder.binder_params.regions;
        let ids = List.map (fun (region : region_param) -> RegionId.to_int region.index) binder.binder_params.regions in
        Binder (ids, Node ("dynamicType", [parameters binder.binder_params; ty binder.binder_value]))
    | _ -> invalid_arg "the actual return-region certificate contains an unsupported source type constructor; native type semantics cannot be replaced by an opaque token"
  and args (arguments : generic_args) =
    if arguments.const_generics <> [] then
      invalid_arg "the actual return-region certificate needs explicit constant-expression reflection, not omitted source const arguments";
    Node ("arguments", [list "regions" (List.map region arguments.regions);
      list "types" (List.map ty arguments.types); list "constants" [];
      list "traits" (List.map trait arguments.trait_refs)])
  and parameters (value : generic_params) =
    if value.const_generics <> [] || value.trait_type_constraints <> [] then
      invalid_arg "dynamic source reflection requires explicit const/associated-constraint syntax; these predicates cannot be omitted";
    let clause (value : trait_param) =
      let declaration (value : trait_decl_ref) = Node ("traitDeclaration", [natural (TraitDeclId.to_int value.id); args value.generics]) in
      Node ("traitParameter", [natural (TraitClauseId.to_int value.clause_id); option source_span value.span;
        predicate_origin value.origin; reflect_binder declaration value.trait]) in
    let region_edge (long, short) = Node ("regionOutlives", [region long; region short]) in
    let type_edge (source, lifetime) = Node ("typeOutlives", [ty source; region lifetime]) in
    Node ("genericParameters", [list "regionParameters" (List.map parameter value.regions);
      list "typeParameters" (List.map type_parameter value.types); list "constantParameters" [];
      list "traitParameters" (List.map clause value.trait_clauses);
      list "regionPredicates" (List.map (reflect_binder region_edge) value.regions_outlive);
      list "typePredicates" (List.map (reflect_binder type_edge) value.types_outlive);
      list "associatedConstraints" []])
  and trait (reference : trait_ref) =
    let implementation = match reference.kind with
      | TraitImpl value -> Node ("traitImplementation", [natural (TraitImplId.to_int value.id); args value.generics])
      | Clause (Free index) -> Node ("clauseFree", [natural (TraitClauseId.to_int index)])
      | Clause (Bound (depth, index)) -> Node ("clauseBound", [natural depth; natural (TraitClauseId.to_int index)])
      | ParentClause (parent, index) -> Node ("parentClause", [trait parent; natural (TraitClauseId.to_int index)])
      | ItemClause (parent, item, index) -> Node ("itemClause", [trait parent; natural (AssocTypeId.to_int item); natural (TraitClauseId.to_int index)])
      | Self -> Node ("selfClause", [])
      | Dyn -> Node ("dynamicClause", [])
      | BuiltinOrAuto (kind, parents, associated) ->
          let fields = AssocTypeId.Map.bindings associated |> List.map (fun (id, (value : trait_assoc_ty_impl)) ->
            Node ("associatedType", [natural (AssocTypeId.to_int id); ty value.value;
              list "traits" (List.map trait value.implied_trait_refs)])) in
          Node ("builtinClause", [natural (builtin kind); list "traits" (List.map trait parents); list "associatedTypes" fields])
      | UnknownTrait _ -> invalid_arg "an unresolved trait cannot be reflected as an ordinary structural source dictionary" in
    let binder = reference.trait_decl_ref in
    let declaration = binder.binder_value in
    let ids = List.map (fun (value : region_param) -> RegionId.to_int value.index) binder.binder_regions in
    Region_scope.require_parameters binder.binder_regions;
    let payload = Node ("regionBinder", [list "regionParameters" (List.map parameter binder.binder_regions);
      Node ("traitDeclaration", [natural (TraitDeclId.to_int declaration.id); args declaration.generics])]) in
    Node ("traitReference", [implementation; Binder (ids, payload)])
  in ty

(* Reconstruct the actual Charon AST as a construction invariant. This catches
   an omitted field, wrong tag/identifier or lost binder/metadata component.
   It is not a substitute for the deferred independent source/native proof. *)
let decode_type ~holes =
  let malformed () = invalid_arg "the structural return-region tree does not reconstruct its complete original Charon AST" in
  let integer = function Natural value when value >= 0 -> value | _ -> malformed () in
  let list tag = function Node (actual, values) when actual = tag -> values | _ -> malformed () in
  let text = function Bytes values ->
      String.of_seq (Seq.map (fun value -> if value < 0 || value > 255 then malformed () else Char.chr value) (List.to_seq values))
    | _ -> malformed () in
  let name = function Node ("noName", []) -> None | Node ("someName", [value]) -> Some (text value)
    | _ -> malformed () in
  let variance = function 0 -> Covariant | 1 -> Invariant | 2 -> Contravariant | 3 -> Bivariant | 4 -> VaUnknown | _ -> malformed () in
  let mutability = function 0 -> LtMutable | 1 -> LtShared | 2 -> LtUnknown | _ -> malformed () in
  let parameter = function Node ("regionParameter", [id; parameter_name; variation; mutation]) ->
      { index = RegionId.of_int (integer id); name = name parameter_name;
        variance = variance (integer variation); mutability = mutability (integer mutation) }
    | _ -> malformed () in
  let region = function Region region -> region
    | OutputSlot slot -> (match List.assoc_opt slot holes with Some original -> original | None -> malformed ())
    | _ -> malformed () in
  let option decode = function Node ("noneValue", []) -> None | Node ("someValue", [value]) -> Some (decode value) | _ -> malformed () in
  let location = function Node ("sourceLocation", [line; col]) ->
      { Meta.line = integer line; col = integer col } | _ -> malformed () in
  let file = function Node ("sourceFile", [filename; crate_name; contents]) ->
      let name = match filename with
        | Node ("localFile", [path]) -> Meta.Local (text path)
        | Node ("virtualFile", [path]) -> Meta.Virtual (text path)
        | Node ("notRealFile", [path]) -> Meta.NotReal (text path)
        | _ -> malformed () in
      { Meta.name; crate_name = text crate_name; contents = option text contents }
    | _ -> malformed () in
  let span_data = function Node ("sourceSpanData", [source; first; last]) ->
      { Meta.file = file source; beg_loc = location first; end_loc = location last } | _ -> malformed () in
  let span = function Node ("sourceSpan", [data; generated]) ->
      { Meta.data = span_data data; generated_from_span = option span_data generated } | _ -> malformed () in
  let type_parameter = function Node ("typeParameter", [id; name; variation]) ->
      { index = TypeVarId.of_int (integer id); name = text name; variance = variance (integer variation) }
    | _ -> malformed () in
  let origin = function
    | Node ("predicateOrigin", [Natural 0]) -> WhereClauseOnFn
    | Node ("predicateOrigin", [Natural 1]) -> WhereClauseOnType
    | Node ("predicateOrigin", [Natural 2]) -> WhereClauseOnImpl
    | Node ("predicateOrigin", [Natural 3]) -> TraitSelf
    | Node ("predicateOrigin", [Natural 4]) -> WhereClauseOnTrait
    | Node ("predicateOrigin", [Natural 5; id]) -> TraitItem (AssocTypeId.of_int (integer id))
    | Node ("predicateOrigin", [Natural 6]) -> OriginDyn
    | _ -> malformed () in
  let binder decode = function
    | Binder (ids, Node ("predicateBinder", [parameters; value])) ->
        let binder_regions = List.map parameter (list "regionParameters" parameters) in
        if List.map (fun (value : region_param) -> RegionId.to_int value.index) binder_regions <> ids then malformed ();
        { binder_regions; binder_value = decode value }
    | _ -> malformed () in
  let literal = function
    | 0 -> Values.TUInt Values.Usize | 1 -> Values.TUInt Values.U8 | 2 -> Values.TUInt Values.U16
    | 3 -> Values.TUInt Values.U32 | 4 -> Values.TUInt Values.U64 | 5 -> Values.TUInt Values.U128
    | 6 -> Values.TInt Values.Isize | 7 -> Values.TInt Values.I8 | 8 -> Values.TInt Values.I16
    | 9 -> Values.TInt Values.I32 | 10 -> Values.TInt Values.I64 | 11 -> Values.TInt Values.I128
    | 12 -> Values.TFloat Values.F16 | 13 -> Values.TFloat Values.F32
    | 14 -> Values.TFloat Values.F64 | 15 -> Values.TFloat Values.F128
    | 16 -> Values.TBool | 17 -> Values.TChar | _ -> malformed () in
  let builtin = function
    | 0 -> BuiltinAuto | 1 -> BuiltinSized | 2 -> BuiltinMetaSized | 3 -> BuiltinPointeeSized
    | 4 -> BuiltinCopy | 5 -> BuiltinClone | 6 -> BuiltinTuple | 7 -> BuiltinTransmute
    | 8 -> BuiltinUnsize | 9 -> BuiltinPointee | 10 -> BuiltinDiscriminantKind | 11 -> BuiltinFn
    | 12 -> BuiltinFnMut | 13 -> BuiltinFnOnce | 14 -> BuiltinFnPtr | 15 -> BuiltinAsyncFn
    | 16 -> BuiltinAsyncFnMut | 17 -> BuiltinAsyncFnOnce | 18 -> BuiltinCoroutine
    | 19 -> BuiltinFuture | 20 -> BuiltinNoopDestruct | 21 -> BuiltinUntrackedDestruct
    | 22 -> BuiltinRemovedAdtClause | _ -> malformed () in
  let rec ty = function
    | Node ("adt", [id; arguments]) -> TAdt { id = TAdtId (TypeDeclId.of_int (integer id)); generics = args arguments }
    | Node ("tuple", [arguments]) -> TAdt { id = TTuple; generics = args arguments }
    | Node ("boxType", [arguments]) -> TAdt { id = TBuiltin TBox; generics = args arguments }
    | Node ("strType", [arguments]) -> TAdt { id = TBuiltin TStr; generics = args arguments }
    | Node ("mutRef", [lifetime; inner]) -> TRef (region lifetime, ty inner, RMut)
    | Node ("sharedRef", [lifetime; inner]) -> TRef (region lifetime, ty inner, RShared)
    | Node ("mutPtr", [inner]) -> TRawPtr (ty inner, RMut)
    | Node ("sharedPtr", [inner]) -> TRawPtr (ty inner, RShared)
    | Node ("typeFree", [id]) -> TVar (Free (TypeVarId.of_int (integer id)))
    | Node ("typeBound", [depth; id]) -> TVar (Bound (integer depth, TypeVarId.of_int (integer id)))
    | Node ("literal", [kind]) -> TLiteral (literal (integer kind))
    | Node ("neverType", []) -> TNever
    | Binder (ids, Node ("dynamicType", [params; value])) ->
        let binder_params : generic_params = parameters params in
        if List.map (fun (value : region_param) -> RegionId.to_int value.index) binder_params.regions <> ids then malformed ();
        TDynTrait { binder = { binder_params; binder_value = ty value } }
    | _ -> malformed ()
  and args = function
    | Node ("arguments", [lifetimes; types; Node ("constants", []); traits]) ->
        { regions = List.map region (list "regions" lifetimes); types = List.map ty (list "types" types);
          const_generics = []; trait_refs = List.map trait (list "traits" traits) }
    | _ -> malformed ()
  and parameters (source : expr) : generic_params = match source with
    | Node ("genericParameters", [regions; types; Node ("constantParameters", []); clauses; region_edges; type_edges; Node ("associatedConstraints", [])]) ->
        let declaration (source : expr) : trait_decl_ref = match source with Node ("traitDeclaration", [id; arguments]) ->
            { id = TraitDeclId.of_int (integer id); generics = args arguments } | _ -> malformed () in
        let clause = function Node ("traitParameter", [id; source; provenance; reference]) ->
            { clause_id = TraitClauseId.of_int (integer id); span = option span source;
              origin = origin provenance; trait = binder declaration reference } | _ -> malformed () in
        let region_edge = function Node ("regionOutlives", [long; short]) -> region long, region short | _ -> malformed () in
        let type_edge = function Node ("typeOutlives", [source; lifetime]) -> ty source, region lifetime | _ -> malformed () in
        { regions = List.map parameter (list "regionParameters" regions);
          types = List.map type_parameter (list "typeParameters" types); const_generics = [];
          trait_clauses = List.map clause (list "traitParameters" clauses);
          regions_outlive = List.map (binder region_edge) (list "regionPredicates" region_edges);
          types_outlive = List.map (binder type_edge) (list "typePredicates" type_edges);
          trait_type_constraints = [] }
    | _ -> malformed ()
  and trait = function
    | Node ("traitReference", [implementation;
        Binder (ids, Node ("regionBinder", [parameters; Node ("traitDeclaration", [id; arguments])]))]) ->
        let binder_regions = List.map parameter (list "regionParameters" parameters) in
        if List.map (fun (value : region_param) -> RegionId.to_int value.index) binder_regions <> ids then malformed ();
        let kind = match implementation with
          | Node ("traitImplementation", [id; arguments]) -> TraitImpl { id = TraitImplId.of_int (integer id); generics = args arguments }
          | Node ("clauseFree", [id]) -> Clause (Free (TraitClauseId.of_int (integer id)))
          | Node ("clauseBound", [depth; id]) -> Clause (Bound (integer depth, TraitClauseId.of_int (integer id)))
          | Node ("parentClause", [parent; id]) -> ParentClause (trait parent, TraitClauseId.of_int (integer id))
          | Node ("itemClause", [parent; item; id]) -> ItemClause (trait parent, AssocTypeId.of_int (integer item), TraitClauseId.of_int (integer id))
          | Node ("selfClause", []) -> Self
          | Node ("dynamicClause", []) -> Dyn
          | Node ("builtinClause", [kind; parents; associated]) ->
              let fields = List.fold_left (fun fields -> function
                | Node ("associatedType", [id; value; implied]) ->
                    let id = AssocTypeId.of_int (integer id) in
                    if AssocTypeId.Map.mem id fields then malformed ();
                    AssocTypeId.Map.add id { value = ty value; implied_trait_refs = List.map trait (list "traits" implied) } fields
                | _ -> malformed ()) AssocTypeId.Map.empty (list "associatedTypes" associated) in
              BuiltinOrAuto (builtin (integer kind), List.map trait (list "traits" parents), fields)
          | _ -> malformed () in
        { kind; trait_decl_ref = { binder_regions;
            binder_value = { id = TraitDeclId.of_int (integer id); generics = args arguments } } }
    | _ -> malformed ()
  in ty

let reflect_type ~holes source =
  let reflected = reflect_unchecked_type ~holes source in
  if decode_type ~holes reflected <> source then
    invalid_arg "structural return-region reflection lost an original source type/argument/dictionary/binder component";
  reflected

let replays_type ~holes source reflected =
  try decode_type ~holes reflected = source && reflect_unchecked_type ~holes source = reflected
  with Invalid_argument _ | Not_found -> false

let derive crate (candidate : Return_signature.t) =
  if not (Return_signature.replay crate candidate) then invalid_arg "a return-region certificate requires its complete original source witness";
  let holes = List.map (fun (completion : Return_signature.completion) -> completion.output_region_index, completion.marker) candidate.completions in
  let plain = reflect_type ~holes:[] and pattern = reflect_type ~holes in
  let reconstructed_regions = match candidate.reconstructed.output with
    | TAdt reference -> reference.generics.regions
    | _ -> invalid_arg "the actual source closure reconstruction changed its nominal output shape" in
  { public_parameters = List.map (fun (parameter : region_param) -> RegionId.to_int parameter.index) candidate.view.arguments.parameters;
    original_regions = candidate.original_output.generics.regions;
    reconstructed_regions;
    declared_inputs = List.map plain candidate.original.inputs;
    field_patterns = List.map (fun (capture : Return_signature.capture) -> pattern capture.field_pattern) candidate.captures;
    original_output = plain candidate.original.output;
    reconstructed_output = plain candidate.reconstructed.output }

let replay crate candidate certificate =
  try derive crate candidate = certificate with Invalid_argument _ | Not_found -> false

let numbers values = "[" ^ String.concat ", " (List.map string_of_int values) ^ "]"
let lean_region = function
  | RStatic -> ".literalStatic"
  | RErased -> ".erased"
  | RBody id -> ".body " ^ string_of_int (RegionId.to_int id)
  | RVar (Free id) -> ".parameter " ^ string_of_int (RegionId.to_int id)
  | RVar (Bound (depth, id)) -> ".bound " ^ string_of_int depth ^ " " ^ string_of_int (RegionId.to_int id)

let rec lean = function
  | Natural value -> ".natural " ^ string_of_int value
  | Bytes values -> ".bytes " ^ numbers values
  | Region value -> ".region (" ^ lean_region value ^ ")"
  | OutputSlot slot -> ".outputSlot " ^ string_of_int slot
  | Node (tag, fields) -> ".node ." ^ tag ^ " [" ^ String.concat ", " (List.map lean fields) ^ "]"
  | Binder (ids, contents) -> ".binder " ^ numbers ids ^ " (" ^ lean contents ^ ")"

let expressions values = "[" ^ String.concat ", " (List.map lean values) ^ "]"
let regions values = "[" ^ String.concat ", " (List.map lean_region values) ^ "]"
