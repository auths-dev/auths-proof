(* Complete structural native type reflection for the represented forms.
   A decoder reconstructs the entire actual Pure.ty, including dictionaries;
   unknown constants refuse rather than becoming uninterpreted type tokens. *)
open Charon
module Q = Aeneas.Pure
module N = Native_pure_payload
type t = Natural of int | Integer of Z.t | Bytes of string | Node of string * t list
let nat n = if n < 0 then invalid_arg "negative native type syntax identity" else Natural n
let id to_int value = nat (to_int value)
let list tag fields = Node (tag, fields)
let db to_int = function
  | Types.Free value -> Node ("free", [id to_int value])
  | Types.Bound (depth, value) -> Node ("bound", [nat depth; id to_int value])
let builtin = function
  | Q.TResult -> 0 | Q.TSum -> 1 | Q.TLoopResult -> 2 | Q.TError -> 3 | Q.TFuel -> 4
  | Q.TArray -> 5 | Q.TSlice -> 6 | Q.TStr -> 7 | Q.TRawPtr Q.Mut -> 8 | Q.TRawPtr Q.Const -> 9
let native_builtin = function
  | 0 -> Q.TResult | 1 -> Q.TSum | 2 -> Q.TLoopResult | 3 -> Q.TError | 4 -> Q.TFuel
  | 5 -> Q.TArray | 6 -> Q.TSlice | 7 -> Q.TStr | 8 -> Q.TRawPtr Q.Mut | 9 -> Q.TRawPtr Q.Const
  | _ -> invalid_arg "unknown native builtin type identity"
let builtin_trait = function
  | Q.BuiltinCopy -> 0 | Q.BuiltinClone -> 1 | Q.BuiltinDiscriminantKind -> 2
  | Q.BuiltinFn -> 3 | Q.BuiltinFnMut -> 4 | Q.BuiltinFnOnce -> 5
let native_builtin_trait = function
  | 0 -> Q.BuiltinCopy | 1 -> Q.BuiltinClone | 2 -> Q.BuiltinDiscriminantKind
  | 3 -> Q.BuiltinFn | 4 -> Q.BuiltinFnMut | 5 -> Q.BuiltinFnOnce
  | _ -> invalid_arg "unknown native builtin trait identity"

let literal = function
  | Q.VScalar (Values.SignedScalar (kind, value)) -> Node ("scalar", [nat (N.literal (Q.TInt kind)); Integer value])
  | Q.VScalar (Values.UnsignedScalar (kind, value)) -> Node ("scalar", [nat (N.literal (Q.TUInt kind)); Integer value])
  | Q.VBool value -> Node ("boolean", [nat (if value then 1 else 0)])
  | Q.VByteStr values -> Node ("byteString", List.map nat values)
  | Q.VStr value -> Node ("string", [Bytes value])
  | Q.VPureNat value when Z.sign value >= 0 -> Node ("naturalValue", [Integer value])
  | Q.VPureInt value -> Node ("integerValue", [Integer value])
  | Q.VFloat _ | Q.VChar _ | Q.VPureNat _ ->
      invalid_arg "native type constants require exact float/character/nonnegative representation; no constant is erased"

let rec encode = function
  | Q.TAdt (identity, arguments) ->
      let identity = match identity with Q.TAdtId value -> Node ("nominal", [id Q.TypeDeclId.to_int value])
        | Q.TTuple -> Node ("tuple", []) | Q.TBuiltin value -> Node ("builtin", [nat (builtin value)]) in
      Node ("adt", [identity; args arguments])
  | Q.TVar value -> Node ("typeVariable", [db Q.TypeVarId.to_int value])
  | Q.TLiteral kind -> Node ("literalType", [nat (N.literal kind)])
  | Q.TArrow (input, output) -> Node ("arrow", [encode input; encode output])
  | Q.TTraitType (value, name) -> Node ("associatedType", [trait value; id Types.AssocTypeId.to_int name])
  | Q.TNever -> Node ("never", []) | Q.TError -> Node ("error", [])
  | Q.TDynTrait value -> Node ("dynamic", [parameters value.params])
and args (value : Q.generic_args) = Node ("arguments", [
  list "types" (List.map encode value.types); list "constants" (List.map constant value.const_generics);
  list "traits" (List.map trait value.trait_refs)])
and constant = function
  | Q.CgGlobal value -> Node ("globalConstant", [id Q.GlobalDeclId.to_int value])
  | Q.CgVar value -> Node ("variableConstant", [db Q.ConstGenericVarId.to_int value])
  | Q.CgValue value -> Node ("valueConstant", [literal value])
and trait (value : Q.trait_ref) = Node ("trait", [instance value.trait_id;
  Node ("traitDeclaration", [id Q.TraitDeclId.to_int value.trait_decl_ref.trait_decl_id;
    args value.trait_decl_ref.decl_generics])])
and instance = function
  | Q.Self -> Node ("self", [])
  | Q.TraitImpl (value, generics) -> Node ("implementation", [id Q.TraitImplId.to_int value; args generics])
  | Q.Clause value -> Node ("clause", [db Q.TraitClauseId.to_int value])
  | Q.ParentClause (parent, declaration, clause) -> Node ("parent", [instance parent;
      id Q.TraitDeclId.to_int declaration; id Q.TraitClauseId.to_int clause])
  | Q.BuiltinOrAuto value -> Node ("builtinTrait", [nat (builtin_trait value)])
  | Q.UnknownTrait name -> Node ("unknownTrait", [Bytes name])
and parameters (value : Q.generic_params) = Node ("parameters", [
  list "types" (List.map (fun (value : Q.type_param) -> Node ("typeParameter", [id Q.TypeVarId.to_int value.index; Bytes value.name])) value.types);
  list "constants" (List.map (fun (value : Q.const_generic_param) -> Node ("constantParameter", [
    id Q.ConstGenericVarId.to_int value.index; Bytes value.name; nat (N.literal value.ty)])) value.const_generics);
  list "traits" (List.map (fun (value : Q.trait_param) -> Node ("traitParameter", [
    id Q.TraitClauseId.to_int value.clause_id; id Q.TraitDeclId.to_int value.trait_id; args value.generics])) value.trait_clauses)])

let malformed () = invalid_arg "malformed complete native type syntax"
let number = function Natural value when value >= 0 -> value | _ -> malformed ()
let text = function Bytes value -> value | _ -> malformed ()
let fields name = function Node (actual, values) when actual = name -> values | _ -> malformed ()
let undb of_int = function
  | Node ("free", [value]) -> Types.Free (of_int (number value))
  | Node ("bound", [depth; value]) -> Types.Bound (number depth, of_int (number value))
  | _ -> malformed ()
let unliteral = function
  | Node ("scalar", [kind; Integer value]) ->
      (match N.native_literal (number kind) with
       | Q.TInt kind -> Q.VScalar (Values.SignedScalar (kind, value))
       | Q.TUInt kind when Z.sign value >= 0 -> Q.VScalar (Values.UnsignedScalar (kind, value))
       | _ -> malformed ())
  | Node ("boolean", [Natural 0]) -> Q.VBool false | Node ("boolean", [Natural 1]) -> Q.VBool true
  | Node ("byteString", values) -> Q.VByteStr (List.map number values)
  | Node ("string", [value]) -> Q.VStr (text value)
  | Node ("naturalValue", [Integer value]) when Z.sign value >= 0 -> Q.VPureNat value
  | Node ("integerValue", [Integer value]) -> Q.VPureInt value
  | _ -> malformed ()

let rec decode = function
  | Node ("adt", [identity; generics]) ->
      let identity = match identity with Node ("nominal", [value]) -> Q.TAdtId (Q.TypeDeclId.of_int (number value))
        | Node ("tuple", []) -> Q.TTuple | Node ("builtin", [value]) -> Q.TBuiltin (native_builtin (number value))
        | _ -> malformed () in
      Q.TAdt (identity, unargs generics)
  | Node ("typeVariable", [value]) -> Q.TVar (undb Q.TypeVarId.of_int value)
  | Node ("literalType", [value]) -> Q.TLiteral (N.native_literal (number value))
  | Node ("arrow", [input; output]) -> Q.TArrow (decode input, decode output)
  | Node ("associatedType", [value; name]) -> Q.TTraitType (untrait value, Types.AssocTypeId.of_int (number name))
  | Node ("never", []) -> Q.TNever | Node ("error", []) -> Q.TError
  | Node ("dynamic", [value]) -> Q.TDynTrait { params = unparameters value }
  | _ -> malformed ()
and unargs = function
  | Node ("arguments", [types; constants; traits]) -> Q.{ types = List.map decode (fields "types" types);
      const_generics = List.map unconstant (fields "constants" constants); trait_refs = List.map untrait (fields "traits" traits) }
  | _ -> malformed ()
and unconstant = function
  | Node ("globalConstant", [value]) -> Q.CgGlobal (Q.GlobalDeclId.of_int (number value))
  | Node ("variableConstant", [value]) -> Q.CgVar (undb Q.ConstGenericVarId.of_int value)
  | Node ("valueConstant", [value]) -> Q.CgValue (unliteral value)
  | _ -> malformed ()
and untrait = function
  | Node ("trait", [value; Node ("traitDeclaration", [declaration; generics])]) -> Q.{ trait_id = uninstance value;
      trait_decl_ref = { trait_decl_id = TraitDeclId.of_int (number declaration); decl_generics = unargs generics } }
  | _ -> malformed ()
and uninstance = function
  | Node ("self", []) -> Q.Self
  | Node ("implementation", [value; generics]) -> Q.TraitImpl (Q.TraitImplId.of_int (number value), unargs generics)
  | Node ("clause", [value]) -> Q.Clause (undb Q.TraitClauseId.of_int value)
  | Node ("parent", [parent; declaration; clause]) -> Q.ParentClause (uninstance parent,
      Q.TraitDeclId.of_int (number declaration), Q.TraitClauseId.of_int (number clause))
  | Node ("builtinTrait", [value]) -> Q.BuiltinOrAuto (native_builtin_trait (number value))
  | Node ("unknownTrait", [value]) -> Q.UnknownTrait (text value)
  | _ -> malformed ()
and unparameters = function
  | Node ("parameters", [types; constants; traits]) ->
      let type_param = function Node ("typeParameter", [index; name]) -> Q.{ index = TypeVarId.of_int (number index); name = text name } | _ -> malformed () in
      let const_param = function Node ("constantParameter", [index; name; ty]) -> Q.{ index = ConstGenericVarId.of_int (number index); name = text name; ty = N.native_literal (number ty) } | _ -> malformed () in
      let trait_param = function Node ("traitParameter", [index; declaration; generics]) -> Q.{ clause_id = TraitClauseId.of_int (number index);
        trait_id = TraitDeclId.of_int (number declaration); generics = unargs generics } | _ -> malformed () in
      Q.{ types = List.map type_param (fields "types" types); const_generics = List.map const_param (fields "constants" constants);
        trait_clauses = List.map trait_param (fields "traits" traits) }
  | _ -> malformed ()

let reflect source =
  let value = encode source in
  if Q.compare_ty (decode value) source <> 0 then invalid_arg "native type syntax changed an original type/dictionary/constant/binder";
  value

let reflect_parameters source =
  let value = parameters source in
  if Q.compare_generic_params (unparameters value) source <> 0 then
    invalid_arg "native parameter syntax changed a type/constant/dictionary parameter";
  value

let reflect_predicates (source : Q.predicates) =
  let value = Node ("predicates", List.map (fun (constraint_ : Q.trait_type_constraint) ->
    Node ("associatedConstraint", [trait constraint_.trait_ref;
      id Types.AssocTypeId.to_int constraint_.type_id; encode constraint_.ty])) source.trait_type_constraints) in
  let decode_constraint = function
    | Node ("associatedConstraint", [value; name; ty]) -> Q.{ trait_ref = untrait value;
        type_id = Types.AssocTypeId.of_int (number name); ty = decode ty }
    | _ -> malformed () in
  let decoded : Q.predicates = { trait_type_constraints = List.map decode_constraint (fields "predicates" value) } in
  if Q.compare_predicates decoded source <> 0 then invalid_arg "native predicate syntax changed an associated-type constraint";
  value

let rec lean = function
  | Natural value -> ".natural " ^ string_of_int value
  | Integer value -> ".integer (" ^ Z.to_string value ^ ")"
  | Bytes value -> ".bytes [" ^ String.concat ", " (List.init (String.length value) (fun index -> string_of_int (Char.code value.[index]))) ^ "]"
  | Node (tag, values) -> ".node ." ^ tag ^ " [" ^ String.concat ", " (List.map (fun value -> "(" ^ lean value ^ ")") values) ^ "]"
let pure source = lean (reflect source)

let rec depth = function
  | Natural _ | Integer _ | Bytes _ -> 1
  | Node (_, values) -> 1 + List.fold_left (fun size value -> max size (depth value)) 0 values
