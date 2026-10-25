import Auths.Product.TemplateAstMeaning
import Auths.Product.TemplateAstTermination

namespace Auths.Product.TemplateAst
open RequestConstruction BodyCompiler
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

private def jsonView (output : JsonBuild) (environment : Bytes → Option Arg) (token : Bytes) : Rendered :=
  renderedTemplate (.json output.pieces) environment token
private def formView (output : FormBuild) (environment : Bytes → Option Arg) (token : Bytes) : Rendered :=
  renderedTemplate (.form output.pieces) environment token

@[simp] private theorem append_empty_left (value : Rendered) : appendRendered emptyRendered value = value := by
  cases value <;> simp [appendRendered, emptyRendered]
@[simp] private theorem append_empty_right (value : Rendered) : appendRendered value emptyRendered = value := by
  cases value <;> simp [appendRendered, emptyRendered]

private theorem bind_ok {α β : Type} {first : Except Error α} {next : α → Except Error β}
    {output : β} (run : (first >>= next) = .ok output) :
    ∃ middle, first = .ok middle ∧ next middle = .ok output := by
  cases first with
  | error error => simp [Bind.bind, Except.bind] at run
  | ok middle => exact ⟨middle, rfl, by simpa [Bind.bind, Except.bind] using run⟩

private theorem member_ok {α : Type} (computation : Except TemplateMembers.Error α)
    (output : α) (run : computation.mapError memberError = .ok output) : computation = .ok output := by
  cases computation <;> simp_all [Except.mapError]

/-- Rendering effects follow from the successful checked push itself. A
resource invariant is unnecessary for this semantic fact. -/
private theorem json_push_effect (before after : JsonBuild) (piece : NamedJson)
    (environment : Bytes → Option Arg) (token : Bytes) (run : pushJson before piece = .ok after) :
    jsonView after environment token = appendRendered (jsonView before environment token)
      (renderedTemplate (.json [piece]) environment token) := by
  unfold pushJson at run
  split at run
  · cases charged : BodyCompiler.Resources.add before.resources (BodyCompiler.Resources.jsonQuantity piece) with
    | none => simp [charged] at run
    | some resources =>
      have same : after = ⟨before.nodes, resources, before.pieces ++ [piece]⟩ := by
        simpa [charged] using run.symm
      subst after
      exact rendered_json_append _ _ _ _
  · contradiction

private theorem form_push_effect (before after : FormBuild) (piece : NamedForm)
    (environment : Bytes → Option Arg) (token : Bytes) (run : pushForm before piece = .ok after) :
    formView after environment token = appendRendered (formView before environment token)
      (renderedTemplate (.form [piece]) environment token) := by
  unfold pushForm at run
  split at run
  · cases charged : BodyCompiler.Resources.formCharge before.resources piece with
    | none => simp [charged] at run
    | some resources =>
      have same : after = ⟨before.nodes, resources, before.pieces ++ [piece]⟩ := by
        simpa [charged] using run.symm
      subst after
      exact rendered_form_append _ _ _ _
  · contradiction

@[simp] private theorem json_raw_singleton (bytes : Bytes) (environment : Bytes → Option Arg) (token : Bytes) :
    renderedTemplate (.json [.raw bytes]) environment token = literalRendered bytes := by
  simp [renderedTemplate, literalRendered, namedJson, namedJsonValid, namedJsonPiece]
@[simp] private theorem json_field_singleton (name : Bytes) (environment : Bytes → Option Arg) (token : Bytes) :
    renderedTemplate (.json [.field name]) environment token = jsonFieldRendered environment name := by
  cases found : environment name <;>
    simp [renderedTemplate, jsonFieldRendered, namedJson, namedJsonValid, namedJsonPiece, found]
@[simp] private theorem json_echo_singleton (environment : Bytes → Option Arg) (token : Bytes) :
    renderedTemplate (.json [.echo]) environment token = literalRendered (jsonString token) := by
  simp [renderedTemplate, literalRendered, namedJson, namedJsonValid, namedJsonPiece]
@[simp] private theorem form_raw_singleton (bytes : Bytes) (environment : Bytes → Option Arg) (token : Bytes) :
    renderedTemplate (.form [.raw bytes]) environment token = literalRendered bytes := by
  simp [renderedTemplate, literalRendered, namedForm, namedFormValid, namedFormPiece]
@[simp] private theorem form_field_singleton (name : Bytes) (environment : Bytes → Option Arg) (token : Bytes) :
    renderedTemplate (.form [.field name]) environment token = formFieldRendered environment name := by
  cases found : environment name with
  | none => simp [renderedTemplate, formFieldRendered, namedForm, namedFormValid, namedFormPiece, found]
  | some value => cases value <;>
      simp [renderedTemplate, formFieldRendered, namedForm, namedFormValid, namedFormPiece, found]
@[simp] private theorem form_echo_singleton (environment : Bytes → Option Arg) (token : Bytes) :
    renderedTemplate (.form [.echo]) environment token = literalRendered (formEncode token) := by
  simp [renderedTemplate, literalRendered, namedForm, namedFormValid, namedFormPiece]

/-- Relational fold support is internal. Public compiler theorems discharge
the relation using the closed emitter and original-name interpreter. -/
private theorem fold_indexed_simulation {α β σ τ : Type}
    (related : α → β → Prop) (states : σ → τ → Prop)
    (leftStep : σ → α × Nat → Except Error σ) (rightStep : τ → β × Nat → Except Error τ)
    (simulate : ∀ item name position before reference after,
      related item name → states before reference → leftStep before (item, position) = .ok after →
        ∃ next, rightStep reference (name, position) = .ok next ∧ states after next)
    (items : List α) (names : List β) (paired : List.Forall₂ related items names)
    (position : Nat) (before : σ) (reference : τ) (after : σ) (initial : states before reference)
    (run : (items.zipIdx position).foldlM leftStep before = .ok after) :
    ∃ output, (names.zipIdx position).foldlM rightStep reference = .ok output ∧ states after output := by
  induction paired generalizing position before reference with
  | nil =>
    have same : before = after := by simpa using run
    subst after
    exact ⟨reference, rfl, initial⟩
  | @cons item name items names associated remaining ih =>
    rw [List.zipIdx_cons, List.foldlM_cons] at run
    obtain ⟨middle, headRun, tailRun⟩ := bind_ok run
    obtain ⟨next, nextRun, linked⟩ := simulate item name position before reference middle associated initial headRun
    obtain ⟨output, outputRun, finished⟩ := ih (position + 1) middle next linked tailRun
    exact ⟨output, by simp [List.zipIdx_cons, List.foldlM_cons, nextRun, outputRun], finished⟩

private def choiceLabel (keys : List Bytes) (insertion : Option Bytes) : TemplateMembers.Choice → Option Bytes
  | .source index => keys[index]?
  | .echo => insertion

private theorem selected_pairs (keys : List Bytes) (insertion : Option Bytes)
    (choices : List TemplateMembers.Choice) (labels : List Bytes)
    (selected : TemplateMembers.selectedNames keys insertion choices = some labels) :
    List.Forall₂ (fun choice name => choiceLabel keys insertion choice = some name) choices labels := by
  induction choices generalizing labels with
  | nil =>
    have same : labels = [] := by simpa [TemplateMembers.selectedNames] using selected.symm
    subst labels
    exact .nil
  | cons choice rest ih =>
    cases choice with
    | source index =>
      cases found : keys[index]? with
      | none => simp [TemplateMembers.selectedNames, found] at selected
      | some name =>
        cases tail : TemplateMembers.selectedNames keys insertion rest with
        | none => simp [TemplateMembers.selectedNames, found, tail] at selected
        | some remaining =>
          have same : name :: remaining = labels := by
            simpa [TemplateMembers.selectedNames, found, tail] using selected
          subst labels
          exact .cons (by simpa [choiceLabel] using found) (ih remaining tail)
    | echo =>
      cases insertion with
      | none => simp [TemplateMembers.selectedNames] at selected
      | some name =>
        cases tail : TemplateMembers.selectedNames keys (some name) rest with
        | none => simp [TemplateMembers.selectedNames, tail] at selected
        | some remaining =>
          have same : name :: remaining = labels := by
            simpa [TemplateMembers.selectedNames, tail] using selected
          subst labels
          exact .cons rfl (ih remaining tail)

private theorem canonical_labels (keys : List Bytes) (insertion : Option Bytes) (domain : TemplateMembers.Domain)
    (choices : List TemplateMembers.Choice) (run : TemplateMembers.canonicalMembers keys insertion domain = .ok choices) :
    TemplateMembers.selectedNames keys insertion choices = some (TemplateMembers.namedMerge keys insertion false) := by
  have admitted := TemplateMembers.canonical_success_earns_admission _ _ _ _ run
  have merged : TemplateMembers.membersFrom keys insertion 0 false = .ok choices := by
    cases insertion with
    | none => simpa [TemplateMembers.canonicalMembers, admitted.1] using run
    | some name => simpa [TemplateMembers.canonicalMembers, admitted.1, admitted.2.1, admitted.2.2.1] using run
  simpa using TemplateMembers.members_from_select_original_names [] keys insertion false choices merged

private theorem unique_key_indices (keys : List Bytes) (unique : keys.Nodup) (first second : Nat) (name : Bytes)
    (left : keys[first]? = some name) (right : keys[second]? = some name) : first = second := by
  induction keys generalizing first second with
  | nil => simp at left
  | cons key rest ih =>
    obtain ⟨absent, tailUnique⟩ := List.nodup_cons.mp unique
    cases first with
    | zero =>
      have equal : key = name := by simpa using left
      cases second with
      | zero => rfl
      | succ second =>
        have present : name ∈ rest := List.mem_iff_getElem?.mpr ⟨second, by simpa using right⟩
        exact False.elim (absent (by simpa [equal] using present))
    | succ first =>
      cases second with
      | zero =>
        have equal : key = name := by simpa using right
        have present : name ∈ rest := List.mem_iff_getElem?.mpr ⟨first, by simpa using left⟩
        exact False.elim (absent (by simpa [equal] using present))
      | succ second => exact congrArg Nat.succ (ih tailUnique first second (by simpa using left) (by simpa using right))

private def targetCall (keys : List Bytes) (echo : Option (List Bytes)) : Except Error (Option TemplateMembers.Target) :=
  match echo with
  | none => .ok none
  | some tokens => ((TemplateMembers.jsonEchoTarget keys tokens).mapError memberError).map some

private def insertionCall (target : Option TemplateMembers.Target) (echo : Option (List Bytes)) : Except Error (Option Bytes) :=
  match target, echo with
  | some .insert, some tokens => match tokens.head? with
    | none => .error .echoConflict
    | some name => .ok (some name)
  | some .insert, none => .error .echoConflict
  | _, _ => .ok none

private def childEchoCall (target : Option TemplateMembers.Target) (echo : Option (List Bytes)) (index : Nat) :
    Except Error (Option (List Bytes)) :=
  match target, echo with
  | some (.descend selected), some tokens =>
    if selected = index then
      if 0 < tokens.length then .ok (some (tokens.drop 1)) else .error .echoConflict
    else .ok none
  | _, _ => .ok none

/-- Actual successful target selection agrees with a route through the
original names. The returned selector is never assumed to mean a parent. -/
theorem object_selection_named_route (keys : List Bytes) (column : TemplateMembers.KeyColumn keys .json)
    (echo : Option (List Bytes)) (target : Option TemplateMembers.Target) (insertion : Option Bytes)
    (targetRun : targetCall keys echo = .ok target) (insertionRun : insertionCall target echo = .ok insertion) :
    ∃ route, namedEchoRoute keys echo = .ok route ∧ route.insertion = insertion ∧
      ∀ index name, keys[index]? = some name → childEchoCall target echo index = .ok (namedChildEcho route name) := by
  cases echo with
  | none =>
    have targetNone : target = none := by simpa [targetCall] using targetRun.symm
    subst target
    have insertionNone : insertion = none := by simpa [insertionCall] using insertionRun.symm
    subst insertion
    exact ⟨⟨none, none⟩, rfl, rfl, by intros; rfl⟩
  | some tokens =>
    cases selected : TemplateMembers.jsonEchoTarget keys tokens with
    | error error => simp [targetCall, selected, Except.map, Except.mapError] at targetRun
    | ok actual =>
      have targetSome : target = some actual := by
        simpa [targetCall, selected, Except.map, Except.mapError] using targetRun.symm
      subst target
      have domain := TemplateMembers.target_success_retains_pointer keys tokens actual selected
      cases tokens with
      | nil => simp [TemplateMembers.PointerDomain] at domain
      | cons parent tail =>
        cases tail with
        | nil =>
          have inserted := TemplateMembers.target_success_earns_admission keys [parent] actual selected
          have fresh : parent ∉ keys ∧ keys.length < 32 := by simpa using inserted.2.2
          have actualInsert : actual = .insert := by
            simpa [TemplateMembers.jsonEchoTarget, column, domain.2, fresh.1, Nat.not_le.mpr fresh.2] using selected.symm
          subst actual
          have insertionSome : insertion = some parent := by simpa [insertionCall] using insertionRun.symm
          subst insertion
          refine ⟨⟨some parent, none⟩, ?_, rfl, ?_⟩
          · simp [namedEchoRoute, domain.2, fresh]
          · intros; rfl
        | cons next rest =>
          have notLast : ([parent, next] ++ rest).length ≠ 1 := by simp
          cases found : TemplateMembers.keyPosition parent keys with
          | none => simp [TemplateMembers.jsonEchoTarget, column, domain.2, notLast, found] at selected
          | some chosen =>
            have actualDescend : actual = .descend chosen := by
              simpa [TemplateMembers.jsonEchoTarget, column, domain.2, notLast, found] using selected.symm
            subst actual
            have insertionNone : insertion = none := by simpa [insertionCall] using insertionRun.symm
            subst insertion
            have original := TemplateMembers.key_position_is_exact keys parent chosen found
            have present : parent ∈ keys := List.mem_iff_getElem?.mpr ⟨chosen, original⟩
            refine ⟨⟨none, some (parent, next :: rest)⟩, ?_, rfl, ?_⟩
            · simp [namedEchoRoute, domain.2, present]
            · intro index name atName
              have equivalence : chosen = index ↔ parent = name := by
                constructor
                · intro same
                  subst index
                  simpa [original] using atName
                · intro same
                  exact unique_key_indices keys (admitted_keys_are_unique keys .json column) chosen index parent
                    original (by simpa [same] using atName)
              simp [childEchoCall, namedChildEcho, equivalence]

private theorem identical_pairs {α : Type} (items : List α) : List.Forall₂ Eq items items := by
  induction items with
  | nil => exact .nil
  | cons item rest ih => exact .cons rfl ih

private def arrayEmitStep (fuel depth : Nat) (output : JsonBuild) (item : Value × Nat) : Except Error JsonBuild := do
  let separated ← if 0 < item.2 then pushJson output (.raw [44]) else .ok output
  emitJson fuel item.1 none (depth + 1) separated

private def arrayMeaningStep (fuel : Nat) (environment : Bytes → Option Arg) (token : Bytes)
    (rendered : Rendered) (item : Value × Nat) : Except Error Rendered := do
  let child ← interpretJson fuel item.1 none environment token
  let separator := literalRendered (if 0 < item.2 then [44] else [])
  .ok (appendRendered rendered (appendRendered separator child))

private def objectEmitStep (fuel depth : Nat) (fields : List (Bytes × Value))
    (target : Option TemplateMembers.Target) (echo : Option (List Bytes)) (insertion : Option Bytes)
    (output : JsonBuild) (item : TemplateMembers.Choice × Nat) : Except Error JsonBuild :=
  match item.1 with
  | .source index => match fields[index]? with
    | none => .error .shape
    | some (name, child) => do
      let prefixed ← pushJson output (.raw (jsonPrefix name (decide (0 < item.2))))
      let nested ← childEchoCall target echo index
      emitJson fuel child nested (depth + 1) prefixed
  | .echo => match insertion with
    | none => .error .echoConflict
    | some name => do
      let prefixed ← pushJson output (.raw (jsonPrefix name (decide (0 < item.2))))
      pushJson prefixed .echo

private def objectMeaningStep (fuel : Nat) (fields : List (Bytes × Value)) (route : NamedEchoRoute)
    (environment : Bytes → Option Arg) (token : Bytes) (rendered : Rendered) (item : Bytes × Nat) : Except Error Rendered := do
  let child ← if route.insertion = some item.1 then .ok (literalRendered (jsonString token)) else
    match lookupSource item.1 fields with
    | none => .error .shape
    | some child => interpretJson fuel child (namedChildEcho route item.1) environment token
  let prefix := literalRendered (jsonPrefix item.1 (decide (0 < item.2)))
  .ok (appendRendered rendered (appendRendered prefix child))

/-- Successful emission renders exactly the original AST, interpreted by
original object/argument names. This statement quantifies over every argument
environment, including missing and wrong-kind fields. No desired bytes,
validity flag, source index or AST admission is a caller premise. -/
theorem emit_json_refines_original_ast (fuel : Nat) (value : Value) (echo : Option (List Bytes))
    (depth : Nat) (before after : JsonBuild) (run : emitJson fuel value echo depth before = .ok after)
    (environment : Bytes → Option Arg) (token : Bytes) :
    ∃ meaning, interpretJson fuel value echo environment token = .ok meaning ∧
      renderedTemplate (.json after.pieces) environment token =
        appendRendered (renderedTemplate (.json before.pieces) environment token) meaning := by
  change ∃ meaning, interpretJson fuel value echo environment token = .ok meaning ∧
    jsonView after environment token = appendRendered (jsonView before environment token) meaning
  induction fuel generalizing value echo depth before after with
  | zero => simp [emitJson] at run
  | succ fuel ih =>
    rw [emitJson] at run
    obtain ⟨nodes, charged, rest⟩ := bind_ok run
    let initial : JsonBuild := { before with nodes }
    have unchanged : jsonView initial environment token = jsonView before environment token := rfl
    change (if echo.isSome && !isObject value then .error .echoConflict else _) = .ok after at rest
    split at rest
    · contradiction
    · rename_i permitted
      cases value with
      | text bytes =>
        split at rest
        · rename_i admitted
          exact ⟨literalRendered (jsonString bytes), by simp [interpretJson, permitted, admitted],
            by simpa [unchanged] using json_push_effect initial after (.raw (jsonString bytes)) environment token rest⟩
        · contradiction
      | integer value =>
        split at rest
        · rename_i admitted
          exact ⟨literalRendered (integerBytes value), by simp [interpretJson, permitted, admitted],
            by simpa [unchanged] using json_push_effect initial after (.raw (integerBytes value)) environment token rest⟩
        · contradiction
      | boolean value =>
        exact ⟨literalRendered (if value then [116,114,117,101] else [102,97,108,115,101]),
          by simp [interpretJson, permitted],
          by simpa [unchanged] using json_push_effect initial after _ environment token rest⟩
      | field name =>
        split at rest
        · rename_i admitted
          exact ⟨jsonFieldRendered environment name, by simp [interpretJson, permitted, admitted],
            by simpa [unchanged] using json_push_effect initial after (.field name) environment token rest⟩
        · contradiction
      | authorEcho => contradiction
      | array items =>
        split at rest
        · rename_i admitted
          obtain ⟨opened, openRun, afterOpen⟩ := bind_ok rest
          obtain ⟨folded, foldRun, closeRun⟩ := bind_ok afterOpen
          change items.zipIdx.foldlM (arrayEmitStep fuel depth) opened = .ok folded at foldRun
          have opening : jsonView opened environment token =
              appendRendered (jsonView before environment token) (literalRendered [91]) := by
            simpa [unchanged] using json_push_effect initial opened (.raw [91]) environment token openRun
          have simulation : ∀ child name position current reference next,
              child = name →
              jsonView current environment token = appendRendered (jsonView before environment token) reference →
              arrayEmitStep fuel depth current (child, position) = .ok next →
              ∃ result, arrayMeaningStep fuel environment token reference (name, position) = .ok result ∧
                jsonView next environment token = appendRendered (jsonView before environment token) result := by
            intro child name position current reference next same linked stepRun
            subst name
            unfold arrayEmitStep at stepRun
            obtain ⟨separated, separatorRun, childRun⟩ := bind_ok stepRun
            have separatorEffect : jsonView separated environment token = appendRendered (jsonView current environment token)
                (literalRendered (if 0 < position then [44] else [])) := by
              by_cases positive : 0 < position
              · simpa [positive] using json_push_effect current separated (.raw [44]) environment token
                  (by simpa [positive] using separatorRun)
              · have unchanged : current = separated := by simpa [positive] using separatorRun
                subst separated
                simp [positive, literalRendered, appendRendered]
            obtain ⟨childMeaning, interpreted, rendered⟩ := ih child none (depth + 1) separated next childRun
            refine ⟨appendRendered reference (appendRendered (literalRendered (if 0 < position then [44] else [])) childMeaning),
              by simp [arrayMeaningStep, interpreted], ?_⟩
            simpa [separatorEffect, linked, append_rendered_assoc] using rendered
          obtain ⟨foldMeaning, foldMeaningRun, foldedMeaning⟩ := fold_indexed_simulation Eq
            (fun output meaning => jsonView output environment token = appendRendered (jsonView before environment token) meaning)
            (arrayEmitStep fuel depth) (arrayMeaningStep fuel environment token) simulation items items
            (identical_pairs items) 0 opened (literalRendered [91]) folded opening foldRun
          refine ⟨appendRendered foldMeaning (literalRendered [93]), ?_, ?_⟩
          · unfold interpretJson
            simp only [permitted, admitted, ↓reduceIte]
            change (do
              let rendered ← items.zipIdx.foldlM (arrayMeaningStep fuel environment token) (literalRendered [91])
              .ok (appendRendered rendered (literalRendered [93]))) = _
            simp [foldMeaningRun]
          · simpa [foldedMeaning, append_rendered_assoc] using
              json_push_effect folded after (.raw [93]) environment token closeRun
        · contradiction
      | object fields =>
        split at rest
        · obtain ⟨target, targetRun, afterTarget⟩ := bind_ok rest
          obtain ⟨insertion, insertionRun, afterInsertion⟩ := bind_ok afterTarget
          obtain ⟨choices, choicesRun, afterChoices⟩ := bind_ok afterInsertion
          obtain ⟨opened, openRun, afterOpen⟩ := bind_ok afterChoices
          obtain ⟨folded, foldRun, closeRun⟩ := bind_ok afterOpen
          have members := member_ok _ choices choicesRun
          have admitted := TemplateMembers.canonical_success_earns_admission _ _ _ _ members
          have unique := admitted_keys_are_unique _ .json admitted.1
          obtain ⟨route, routeRun, routeInsertion, children⟩ := object_selection_named_route _ admitted.1 echo target insertion targetRun insertionRun
          have labels := selected_pairs _ _ _ _ (canonical_labels _ _ _ _ members)
          change choices.zipIdx.foldlM (objectEmitStep fuel depth fields target echo insertion) opened = .ok folded at foldRun
          have opening : jsonView opened environment token =
              appendRendered (jsonView before environment token) (literalRendered [123]) := by
            simpa [unchanged] using json_push_effect initial opened (.raw [123]) environment token openRun
          have simulation : ∀ choice name position current reference next,
              choiceLabel (fields.map Prod.fst) insertion choice = some name →
              jsonView current environment token = appendRendered (jsonView before environment token) reference →
              objectEmitStep fuel depth fields target echo insertion current (choice, position) = .ok next →
              ∃ result, objectMeaningStep fuel fields route environment token reference (name, position) = .ok result ∧
                jsonView next environment token = appendRendered (jsonView before environment token) result := by
            intro choice name position current reference next associated linked stepRun
            cases choice with
            | source index =>
              cases atSource : fields[index]? with
              | none => simp [objectEmitStep, atSource] at stepRun
              | some member =>
                obtain ⟨originalName, child⟩ := member
                have originalKey : (fields.map Prod.fst)[index]? = some originalName := by
                  simpa using congrArg (Option.map Prod.fst) atSource
                have sameName : originalName = name := by simpa [choiceLabel, originalKey] using associated
                subst name
                have fresh : insertion ≠ some originalName := by
                  intro collision
                  have absent := admitted.2
                  rw [collision] at absent
                  exact absent.2.2 (List.mem_iff_getElem?.mpr ⟨index, originalKey⟩)
                have lookedUp := lookup_source_at_unique fields originalName child index unique atSource
                simp only [objectEmitStep, atSource] at stepRun
                obtain ⟨prefixed, prefixRun, afterPrefix⟩ := bind_ok stepRun
                obtain ⟨nested, nestedRun, childRun⟩ := bind_ok afterPrefix
                have nestedMeaning := children index originalName originalKey
                have sameNested : nested = namedChildEcho route originalName := by simpa [nestedRun] using nestedMeaning
                rw [sameNested] at childRun
                obtain ⟨childMeaning, interpreted, rendered⟩ := ih child (namedChildEcho route originalName)
                  (depth + 1) prefixed next childRun
                have prefixMeaning := json_push_effect current prefixed _ environment token prefixRun
                refine ⟨appendRendered reference (appendRendered (literalRendered (jsonPrefix originalName (decide (0 < position)))) childMeaning),
                  ?_, ?_⟩
                · simp [objectMeaningStep, routeInsertion, fresh, lookedUp, interpreted]
                · simpa [prefixMeaning, linked, append_rendered_assoc] using rendered
            | echo =>
              have inserted : insertion = some name := by simpa [choiceLabel] using associated
              simp only [objectEmitStep, inserted] at stepRun
              obtain ⟨prefixed, prefixRun, echoRun⟩ := bind_ok stepRun
              have prefixMeaning := json_push_effect current prefixed _ environment token prefixRun
              have echoMeaning := json_push_effect prefixed next .echo environment token echoRun
              refine ⟨appendRendered reference (appendRendered (literalRendered (jsonPrefix name (decide (0 < position))))
                (literalRendered (jsonString token))), ?_, ?_⟩
              · simp [objectMeaningStep, routeInsertion, inserted]
              · simpa [prefixMeaning, linked, append_rendered_assoc] using echoMeaning
          obtain ⟨foldMeaning, foldMeaningRun, foldedMeaning⟩ := fold_indexed_simulation
            (fun choice name => choiceLabel (fields.map Prod.fst) insertion choice = some name)
            (fun output meaning => jsonView output environment token = appendRendered (jsonView before environment token) meaning)
            (objectEmitStep fuel depth fields target echo insertion) (objectMeaningStep fuel fields route environment token)
            simulation choices (TemplateMembers.namedMerge (fields.map Prod.fst) insertion false) labels
            0 opened (literalRendered [123]) folded opening foldRun
          refine ⟨appendRendered foldMeaning (literalRendered [125]), ?_, ?_⟩
          · unfold interpretJson
            simp only [permitted, admitted.1, ↓reduceIte]
            change (do
              let actualRoute ← namedEchoRoute (fields.map Prod.fst) echo
              let rendered ← (TemplateMembers.namedMerge (fields.map Prod.fst) actualRoute.insertion false).zipIdx.foldlM
                (objectMeaningStep fuel fields actualRoute environment token) (literalRendered [123])
              .ok (appendRendered rendered (literalRendered [125]))) = _
            simp [routeRun, routeInsertion, foldMeaningRun]
          · simpa [foldedMeaning, append_rendered_assoc] using
              json_push_effect folded after (.raw [125]) environment token closeRun
        · contradiction

private theorem nested_form_rendering (pieces : List NamedJson) (environment : Bytes → Option Arg) (token : Bytes) :
    renderedTemplate (.form [.json pieces]) environment token =
      let nested := renderedTemplate (.json pieces) environment token
      ⟨nested.valid, formEncode nested.bytes⟩ := by
  simp [renderedTemplate, namedForm, namedFormValid, namedFormPiece]

/-- Nested JSON is interpreted before form encoding. Its validity bit is
retained, and the complete JSON byte sequence is encoded exactly once. -/
theorem emit_form_value_refines_original_ast (value : FormValue) (before after : FormBuild)
    (run : emitFormValue value before = .ok after) (environment : Bytes → Option Arg) (token : Bytes) :
    ∃ meaning, interpretFormValue value environment token = .ok meaning ∧
      renderedTemplate (.form after.pieces) environment token =
        appendRendered (renderedTemplate (.form before.pieces) environment token) meaning := by
  change ∃ meaning, interpretFormValue value environment token = .ok meaning ∧
    formView after environment token = appendRendered (formView before environment token) meaning
  cases value with
  | text bytes =>
    unfold emitFormValue at run
    split at run
    · rename_i admitted
      exact ⟨literalRendered (formEncode bytes), by simp [interpretFormValue, admitted],
        by simpa using form_push_effect before after (.raw (formEncode bytes)) environment token run⟩
    · contradiction
  | field name =>
    unfold emitFormValue at run
    split at run
    · rename_i admitted
      exact ⟨formFieldRendered environment name, by simp [interpretFormValue, admitted],
        by simpa using form_push_effect before after (.field name) environment token run⟩
    · contradiction
  | authorEcho => simp [emitFormValue] at run
  | json value =>
    unfold emitFormValue at run
    split at run
    · rename_i admitted
      obtain ⟨nested, nestedRun, pushed⟩ := bind_ok run
      obtain ⟨meaning, interpreted, rendered⟩ := emit_json_refines_original_ast 7 value none 0
        (jsonStart before.nodes) nested nestedRun environment token
      have exactNested : renderedTemplate (.json nested.pieces) environment token = meaning := by
        simpa [jsonStart, renderedTemplate, namedJson, appendRendered] using rendered
      have effect := form_push_effect { before with nodes := nested.nodes } after (.json nested.pieces)
        environment token pushed
      refine ⟨⟨meaning.valid, formEncode meaning.bytes⟩, by simp [interpretFormValue, admitted, interpreted], ?_⟩
      simpa [nested_form_rendering, exactNested, formView] using effect
    · contradiction

private def formEmitStep (fields : List (Bytes × FormValue)) (insertion : Option Bytes)
    (output : FormBuild) (item : TemplateMembers.Choice × Nat) : Except Error FormBuild :=
  match item.1 with
  | .source index => match fields[index]? with
    | none => .error .shape
    | some (name, value) => do
      let prefixed ← pushForm output (.raw (formPrefix name (decide (0 < item.2))))
      emitFormValue value prefixed
  | .echo => match insertion with
    | none => .error .echoConflict
    | some name => do
      let prefixed ← pushForm output (.raw (formPrefix name (decide (0 < item.2))))
      pushForm prefixed .echo

private def formMeaningStep (fields : List (Bytes × FormValue)) (insertion : Option Bytes)
    (environment : Bytes → Option Arg) (token : Bytes) (rendered : Rendered) (item : Bytes × Nat) : Except Error Rendered := do
  let value ← if insertion = some item.1 then .ok (literalRendered (formEncode token)) else
    match lookupSource item.1 fields with
    | none => .error .shape
    | some value => interpretFormValue value environment token
  let prefix := literalRendered (formPrefix item.1 (decide (0 < item.2)))
  .ok (appendRendered rendered (appendRendered prefix value))

/-- Whole successful compilation preserves exact original AST meaning,
including canonical label association, echo location, literal bytes, argument
validity and one-time nested form encoding. The interpreter has no emitted
template or compiler-produced child/argument index as input. -/
theorem compile_body_refines_original_ast (body : Body) (echo : Option Echo) (output : NamedTemplate)
    (run : compileBody body echo = .ok output) (environment : Bytes → Option Arg) (token : Bytes) :
    interpretBody body echo environment token = .ok (renderedTemplate output environment token) := by
  cases body with
  | json value =>
    unfold compileBody at run
    obtain ⟨tokens, placementRun, afterPlacement⟩ := bind_ok run
    obtain ⟨emitted, emittedRun, resultRun⟩ := bind_ok afterPlacement
    have same : NamedTemplate.json emitted.pieces = output := by simpa using resultRun
    subst output
    obtain ⟨meaning, interpreted, rendered⟩ := emit_json_refines_original_ast 7 value tokens 0
      (jsonStart 0) emitted emittedRun environment token
    have exactBody : renderedTemplate (.json emitted.pieces) environment token = meaning := by
      simpa [jsonStart, renderedTemplate, namedJson, appendRendered] using rendered
    rw [exactBody]
    unfold interpretBody
    simp [placementRun, interpreted]
  | form fields =>
    unfold compileBody at run
    split at run
    · rename_i count
      obtain ⟨insertion, placementRun, afterPlacement⟩ := bind_ok run
      obtain ⟨choices, choicesRun, afterChoices⟩ := bind_ok afterPlacement
      obtain ⟨emitted, emittedRun, resultRun⟩ := bind_ok afterChoices
      have same : NamedTemplate.form emitted.pieces = output := by simpa using resultRun
      subst output
      have members := member_ok _ choices choicesRun
      have admitted := TemplateMembers.canonical_success_earns_admission _ _ _ _ members
      have unique := admitted_keys_are_unique _ .form admitted.1
      have labels := selected_pairs _ _ _ _ (canonical_labels _ _ _ _ members)
      change choices.zipIdx.foldlM (formEmitStep fields insertion) formStart = .ok emitted at emittedRun
      have simulation : ∀ choice name position current reference next,
          choiceLabel (fields.map Prod.fst) insertion choice = some name →
          formView current environment token = reference →
          formEmitStep fields insertion current (choice, position) = .ok next →
          ∃ result, formMeaningStep fields insertion environment token reference (name, position) = .ok result ∧
            formView next environment token = result := by
        intro choice name position current reference next associated linked stepRun
        cases choice with
        | source index =>
          cases atSource : fields[index]? with
          | none => simp [formEmitStep, atSource] at stepRun
          | some member =>
            obtain ⟨originalName, value⟩ := member
            have originalKey : (fields.map Prod.fst)[index]? = some originalName := by
              simpa using congrArg (Option.map Prod.fst) atSource
            have sameName : originalName = name := by simpa [choiceLabel, originalKey] using associated
            subst name
            have fresh : insertion ≠ some originalName := by
              intro collision
              have absent := admitted.2
              rw [collision] at absent
              exact absent.2.2 (List.mem_iff_getElem?.mpr ⟨index, originalKey⟩)
            have lookedUp := lookup_source_at_unique fields originalName value index unique atSource
            simp only [formEmitStep, atSource] at stepRun
            obtain ⟨prefixed, prefixRun, valueRun⟩ := bind_ok stepRun
            obtain ⟨valueMeaning, interpreted, rendered⟩ := emit_form_value_refines_original_ast value prefixed next valueRun environment token
            have prefixMeaning := form_push_effect current prefixed _ environment token prefixRun
            refine ⟨appendRendered reference (appendRendered (literalRendered (formPrefix originalName (decide (0 < position)))) valueMeaning),
              ?_, ?_⟩
            · simp [formMeaningStep, fresh, lookedUp, interpreted]
            · simpa [prefixMeaning, linked, append_rendered_assoc] using rendered
        | echo =>
          have inserted : insertion = some name := by simpa [choiceLabel] using associated
          simp only [formEmitStep, inserted] at stepRun
          obtain ⟨prefixed, prefixRun, echoRun⟩ := bind_ok stepRun
          have prefixMeaning := form_push_effect current prefixed _ environment token prefixRun
          have echoMeaning := form_push_effect prefixed next .echo environment token echoRun
          refine ⟨appendRendered reference (appendRendered (literalRendered (formPrefix name (decide (0 < position))))
            (literalRendered (formEncode token))), ?_, ?_⟩
          · simp [formMeaningStep, inserted]
          · simpa [prefixMeaning, linked, append_rendered_assoc] using echoMeaning
      have initial : formView formStart environment token = emptyRendered := by
        simp [formView, formStart, renderedTemplate, namedForm, emptyRendered]
      obtain ⟨meaning, interpreted, rendered⟩ := fold_indexed_simulation
        (fun choice name => choiceLabel (fields.map Prod.fst) insertion choice = some name)
        (fun output meaning => formView output environment token = meaning)
        (formEmitStep fields insertion) (formMeaningStep fields insertion environment token) simulation choices
        (TemplateMembers.namedMerge (fields.map Prod.fst) insertion false) labels 0 formStart emptyRendered emitted initial emittedRun
      change interpretBody (.form fields) echo environment token = .ok (formView emitted environment token)
      rw [rendered]
      unfold interpretBody
      simp only [count, ↓reduceIte]
      change (do
        let actualInsertion ← match echo with
          | none => .ok none
          | some (.form name) => .ok (some name)
          | some (.json _) => .error .echoConflict
        if TemplateMembers.KeyColumn (fields.map Prod.fst) .form then
          if TemplateMembers.EchoAdmitted (fields.map Prod.fst) actualInsertion .form then
            (TemplateMembers.namedMerge (fields.map Prod.fst) actualInsertion false).zipIdx.foldlM
              (formMeaningStep fields actualInsertion environment token) emptyRendered
          else .error .echoConflict
        else .error .shape) = .ok meaning
      simp [placementRun, admitted.1, admitted.2, interpreted]
    · contradiction

/-- The existing final validity/byte-limit check sees exactly the independent
original AST bytes. This is a model theorem until recursive Rust refinement
and the native decoded-source/profile bridge are qualified. -/
theorem compiled_body_reference_exact (body : Body) (echo : Option Echo) (output : NamedTemplate)
    (run : compileBody body echo = .ok output) (environment : Bytes → Option Arg) (token : Bytes) :
    referenceBody body echo environment token = .ok
      (finishNamedBody (renderedTemplate output environment token).valid (renderedTemplate output environment token).bytes) := by
  simp [referenceBody, compile_body_refines_original_ast body echo output run environment token]

/-- Composition through positional lowering and the complete body writer.
The conclusion preserves exact refusal codes as well as successful bytes;
the projection alignment is the existing original-name relation. Complete
native AST compilation/projection must earn these intermediate results. -/
theorem lowered_body_refines_original_ast (body : Body) (echo : Option Echo) (output : NamedTemplate)
    (compiled : compileBody body echo = .ok output) (names : List Bytes) (values : List Arg)
    (environment : Bytes → Option Arg) (token : Bytes) (plan : BodyPlan)
    (aligned : SchemaIndex.Aligned names values environment)
    (lowered : RequestCompiler.lowerBody names (namedBody output) = .ok plan) :
    referenceBody body echo environment token = .ok (buildBody plan values token) := by
  have writer := RequestCompiler.lowered_body_preserves_named_rendering names values environment token aligned
    (namedBody output) plan lowered
  have named : RequestCompiler.namedBody environment token (namedBody output) =
      finishNamedBody (renderedTemplate output environment token).valid (renderedTemplate output environment token).bytes := by
    cases output <;> rfl
  rw [writer, named]
  exact compiled_body_reference_exact body echo output compiled environment token

end Auths.Product.TemplateAst
