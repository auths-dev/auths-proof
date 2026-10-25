(* Conditional normal-source paths. Branch tests and original indices survive;
   no ordinary call result or branch outcome is evaluated/supplied here.
   Native CFG/loan simulation remains a separate obligation. *)
open Charon
open Expressions
open LlbcAst

exception Not_dominating
type selector = Value of operand | Discriminant of place
type choice = { statement : statement; index : int; selector : selector }
type step = Execute of statement | Branch of choice

let mentions_local id statement =
  let found = ref false in
  let scan = object inherit [_] iter_statement as super
    method! visit_statement env statement =
      (match statement.kind with
       | StorageLive actual | StorageDead actual when actual = id -> found := true
       | _ -> ()); super#visit_statement env statement
    method! visit_place env place =
      (match place.kind with PlaceLocal actual when actual = id -> found := true | _ -> ());
      super#visit_place env place
  end in scan#visit_statement () statement; !found

let branches = function
  | If (condition, yes, no) -> Value condition, [yes; no]
  | SwitchInt (condition, _, branches, otherwise) -> Value condition, List.map snd branches @ [otherwise]
  | Match (place, branches, otherwise) -> Discriminant place,
      List.map snd branches @ (match otherwise with Some source -> [source] | None -> [])

let rec can_continue (block : block) = List.for_all (fun (statement : statement) -> match statement.kind with
  | Return | Abort _ | UnwindResume -> false
  | Switch switch -> let _, targets = branches switch in List.exists can_continue targets
  | _ -> true) block.statements

let contains block target =
  let found = ref false in
  let scan = object inherit [_] iter_statement as super
    method! visit_statement env statement =
      if statement.statement_id = target then found := true;
      super#visit_statement env statement
  end in scan#visit_block () block; !found

let unique_ids (body : block) =
  let ids = ref StatementId.Set.empty in
  let unique = object inherit [_] iter_statement as super
    method! visit_statement env statement =
      if StatementId.Set.mem statement.statement_id !ids then invalid_arg "a conditional source path has duplicate statement IDs";
      ids := StatementId.Set.add statement.statement_id !ids;
      super#visit_statement env statement
  end in unique#visit_block () body; !ids

let before (body : block) target =
  if not (StatementId.Set.mem target (unique_ids body)) then invalid_arg "the exact source path target is absent";
  let rec continuation (statement : statement) = match statement.kind with
    | Return | Abort _ | UnwindResume -> raise Not_dominating
    | Switch switch ->
        let selector, targets = branches switch in
        let continuing = List.mapi (fun index source -> index, source) targets |> List.filter (fun (_, source) -> can_continue source) in
        (match continuing with
         | [] -> raise Not_dominating
         | [index, source] -> Branch { statement; index; selector } :: List.concat_map continuation source.statements
         | _ -> [Execute statement])
    | _ -> [Execute statement]
  and path (block : block) =
    let rec statements prefix = function
      | [] -> invalid_arg "a conditional source path lost its exact target block"
      | statement :: _ when statement.statement_id = target -> List.rev prefix
      | statement :: rest ->
          let contains_target = let found = ref false in
            let scan = object inherit [_] iter_statement as super
              method! visit_statement env statement =
                if statement.statement_id = target then found := true;
                super#visit_statement env statement
            end in scan#visit_statement () statement; !found in
          if contains_target then (
            match statement.kind with
            | Switch switch ->
                let selector, targets = branches switch in
                let matching = List.mapi (fun index source -> index, source) targets |> List.filter (fun (_, source) -> contains source target) in
                (match matching with [index, source] -> List.rev prefix @ (Branch { statement; index; selector } :: path source)
                 | _ -> invalid_arg "the exact source target has ambiguous original branch membership")
            | _ -> invalid_arg "a loop/unwind/non-switch source path needs its explicit control-flow semantics"
          ) else statements (List.rev_append (continuation statement) prefix) rest in
    statements [] block.statements in
  path body

let between body first last =
  if first = last then raise Not_dominating;
  let path = before body last in
  let rec after = function
    | [] -> raise Not_dominating
    | Execute statement :: rest when statement.statement_id = first -> rest
    | _ :: rest -> after rest in
  after path

let report steps = `List (List.map (function
  | Execute statement -> `Assoc ["kind", `String "original_statement";
      "statement", `Int (StatementId.to_int statement.statement_id)]
  | Branch choice -> `Assoc ["kind", `String "original_conditional_branch";
      "statement", `Int (StatementId.to_int choice.statement.statement_id); "branch_index", `Int choice.index;
      "selector", (match choice.selector with Value source -> `String (Diagnostic.show_operand source)
        | Discriminant source -> `String (Diagnostic.show_place source));
      "branch_condition_evaluated_or_supplied", `Bool false]) steps)
