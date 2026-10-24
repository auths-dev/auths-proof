(* Actual-source mutation regressions, authored for the final batch only.
   Invoke with the pinned 21-root LLBC and exact root-arguments JSON. These
   checks are not source/loan qualification or a whole-program proof. *)
open Charon
open Types
open Expressions
open LlbcAst

exception Selected of Instance_view.t * Function_frame.t
let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let contains text part =
  let rec at index = index + String.length part <= String.length text &&
    (String.sub text index (String.length part) = part || at (index + 1)) in at 0

let () =
  if Array.length Sys.argv <> 3 then failwith "usage: virtual_source_cases SOURCE.llbc ROOT-ARGUMENTS.json";
  let crate = match OfJson.crate_of_json_file Sys.argv.(1) with Ok crate -> crate | Error message -> failwith message in
  let names = Yojson.Basic.from_file Sys.argv.(2) |> Yojson.Basic.Util.member "roots"
    |> Yojson.Basic.Util.to_list |> List.map Yojson.Basic.Util.to_string in
  let fmt = Print.crate_to_fmt_env crate in
  let view, frame = try
    ignore (Source_closure.build crate (Source_roots.pointers crate names) ~on_view:(fun declaration view ->
      if contains (Print.name_to_string fmt declaration.item_meta.name) "impl_Write_for_Box_Global::write_all" then (
        let frame = Function_frame.prepare crate view in
        if frame.dynamic_calls <> [] then raise (Selected (view, frame)))));
    failwith "the actual source virtual Write method was not discovered"
    with Selected (view, frame) -> view, frame in
  List.iter (fun (call : Function_frame.dynamic_call) ->
    let plan = call.dynamic_plan in
    require "the actual source virtual method interface must replay" (Dynamic_method.replay crate plan);
    require "a different object lifetime is not an equivalent source virtual interface"
      (not (Dynamic_method.replay crate { plan with object_region = RErased }));
    require "a changed full source ABI cannot replay"
      (not (Dynamic_method.replay crate { plan with signature = { plan.signature with is_unsafe = not plan.signature.is_unsafe } }));
    require "a forged source field cannot replay"
      (not (Dynamic_method.replay crate { plan with field = { plan.field with role = VTableDrop } }));
    let actual = { call.dynamic_source_call with func = FnOpRegular plan.pointer } in
    require "a different pointer cannot borrow the ABI of the real virtual method"
      (refuses (fun () -> ignore (Dynamic_method.call_requirements plan { actual with func = FnOpRegular {
        plan.pointer with kind = FunId (FRegular (FunDeclId.of_int 0)) } })));
    require "an absent argument cannot be silently defaulted"
      (refuses (fun () -> ignore (Dynamic_method.call_requirements plan { actual with args = List.tl actual.args })));
    let witness = Virtual_receiver.create crate ~view ~frame ~call in
    require "the actual receiver must retain its original argument identity"
      (not (Virtual_receiver.replay { witness with receiver_origin = { witness.receiver_origin with argument = LocalId.of_int 2 } }));
    require "an extra projection cannot be supplied by an implementation index"
      (not (Virtual_receiver.replay { witness with receiver_origin = { witness.receiver_origin with
        dereferences = witness.receiver_origin.dereferences + 1 } }));
    require "the source Write route must expose its Box access for the ownership proof"
      (witness.box_accesses <> []);
    let mapper change = object inherit [_] map_statement as super
      method! visit_statement env statement = change (super#visit_statement env statement)
    end in
    let borrowed = mapper (fun statement -> match statement.kind with
      | Assign (destination, RvRef (source, kind, _)) when (match source.ty with TDynTrait _ -> true | _ -> false) ->
          { statement with kind = Assign (destination, RvRef (source, kind,
            Constant { ty = Vtable_shape.unit; kind = COpaque "synthetic-unmodeled-metadata" })) }
      | _ -> statement) in
    let changed = { frame with body = borrowed#visit_block () frame.body } in
    require "arbitrary metadata cannot replace the source Box carrier's exact route"
      (refuses (fun () -> ignore (Virtual_receiver.derive ~view ~frame:changed ~call)));
    let moving = mapper (fun statement -> match statement.kind with
      | Assign (destination, Use (Copy source, NoRetag)) when Option.is_some (Virtual_receiver.box_pointee source.ty) ->
          { statement with kind = Assign (destination, Use (Move source, NoRetag)) }
      | _ -> statement) in
    let changed = { frame with body = moving#visit_block () frame.body } in
    require "a shallow Box access cannot become another ownership transfer"
      (refuses (fun () -> ignore (Virtual_receiver.derive ~view ~frame:changed ~call)));
    let alias = (List.hd witness.box_accesses).destination in
    let escaping = mapper (fun statement -> match statement.kind with
      | Return -> { statement with kind = Assign (alias, Use (Copy alias, NoRetag)) }
      | _ -> statement) in
    let changed = { frame with body = escaping#visit_block () frame.body } in
    require "the source temporary Box alias cannot escape after the reborrow"
      (refuses (fun () -> ignore (Virtual_receiver.derive ~view ~frame:changed ~call)));
    let copy_receiver (source : call) = match source.args with Move receiver :: rest ->
        { source with args = Copy receiver :: rest }
      | _ -> invalid_arg "the source virtual Write call changed its move receiver" in
    let changed_call = { call with dynamic_source_call = copy_receiver call.dynamic_source_call } in
    let copying = mapper (fun statement -> match statement.kind with
      | Call (source, unwind) when statement.statement_id = call.dynamic_statement_id ->
          { statement with kind = Call (copy_receiver source, unwind) }
      | _ -> statement) in
    let changed = { frame with body = copying#visit_block () frame.body; dynamic_calls = [changed_call] } in
    require "an exclusive source receiver cannot be copied into dispatch"
      (refuses (fun () -> ignore (Virtual_receiver.derive ~view ~frame:changed ~call:changed_call)));
    require "a forged prepared frame cannot acquire actual-source provenance"
      (refuses (fun () -> ignore (Virtual_receiver.create crate ~view ~frame:changed ~call:changed_call)))
  ) frame.dynamic_calls;
  Printf.printf "Actual-source virtual interface/receiver mutation cases completed; this is not native qualification\n%!"
