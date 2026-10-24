import Auths.Product.ProfileSchema

namespace Auths.Product.ProfileSchema
open RequestConstruction ScalarProjection FieldProjection
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

theorem exact_keys_from_presence (members : List (Bytes × Value)) (expected : List Bytes)
    (unique : expected.Nodup) :
    ExactKeys members expected ↔ members.length = expected.length ∧
      ∀ name ∈ expected, member name members ≠ none := by
  constructor
  · intro exact
    refine ⟨exact_keys_size members expected exact, ?_⟩
    intro name present absent
    have missing := (member_none_iff_absent members name).mp absent
    exact missing (exact.mem_iff.mpr present)
  · rintro ⟨size, present⟩
    have subset : expected ⊆ members.map Prod.fst := by
      intro name found
      by_contra absent
      exact present name found ((member_none_iff_absent members name).mpr absent)
    exact (List.subperm_of_subset unique subset).perm_of_length_le (by simpa using Nat.le_of_eq size) |>.symm

theorem string_bound_exact (source : Option Value) (number : Nat) :
    stringBound source = some number ↔
      ∃ value, source = some value ∧ Numeric value (number : Int) ∧ number ≤ 4096 := by
  cases source with
  | none => simp [stringBound]
  | some value =>
    cases value <;> simp [stringBound, numeric, Numeric]
    all_goals split_ifs <;> simp_all <;> omega

theorem signed_bound_sound (source : Option Value) (number : Int)
    (parsed : signedBound source = some number) : ∃ value, source = some value ∧ Numeric value number := by
  cases source with
  | none => simp [signedBound] at parsed
  | some value =>
    refine ⟨value, rfl, ?_⟩
    cases value <;> simp [signedBound, Numeric] at parsed ⊢
    all_goals split_ifs at parsed <;> simp_all

theorem signed_bound_exact_on_safe_integer (value : Value) (number : Int)
    (safe : -9007199254740991 ≤ number ∧ number ≤ 9007199254740991) :
    signedBound (some value) = some number ↔ Numeric value number := by
  cases value <;> simp [signedBound, Numeric]
  all_goals split_ifs <;> simp_all <;> omega

theorem scalar_parse_sound (source : Value) (schema : Schema)
    (parsed : parseScalar source = some schema) : ScalarMeaning source schema := by
  cases source with
  | object members =>
    by_cases enumKeys : ExactKeys members [typeKey, variantsKey]
    · simp only [parseScalar, enumKeys, ↓reduceIte] at parsed
      cases kindAt : member typeKey members with
      | none => simp [kindAt] at parsed
      | some kind =>
        cases kind with
        | text bytes =>
          by_cases tag : bytes = enumTag
          · cases valuesAt : member variantsKey members with
            | none => simp [kindAt, tag, valuesAt] at parsed
            | some values =>
              cases values with
              | array values =>
                cases textsAt : texts values with
                | none => simp [kindAt, tag, valuesAt, textsAt] at parsed
                | some variants =>
                  by_cases valid : EnumSchema variants
                  · have same : schema = .enumeration variants := by
                      simpa [kindAt, tag, valuesAt, textsAt, valid] using parsed.symm
                    subst schema
                    exact .enumeration members values variants enumKeys (by simpa [tag] using kindAt)
                      valuesAt ((texts_exact values variants).mp textsAt) valid
                  · simp [kindAt, tag, valuesAt, textsAt, valid] at parsed
              | _ => simp [kindAt, tag, valuesAt] at parsed
          · simp [kindAt, tag] at parsed
        | _ => simp [kindAt] at parsed
    · by_cases boolKeys : ExactKeys members [kindKey]
      · by_cases kind : member kindKey members = some (.text booleanTag)
        · have same : schema = .boolean := by simpa [parseScalar, enumKeys, boolKeys, kind] using parsed.symm
          subst schema
          exact .boolean members boolKeys kind
        · simp [parseScalar, enumKeys, boolKeys, kind] at parsed
      · by_cases boundedKeys : ExactKeys members [kindKey, minimumKey, maximumKey]
        · by_cases stringKind : member kindKey members = some (.text stringTag)
          · cases lowAt : stringBound (member minimumKey members) with
            | none => simp [parseScalar, enumKeys, boolKeys, boundedKeys, stringKind, lowAt] at parsed
            | some minimum =>
              cases highAt : stringBound (member maximumKey members) with
              | none => simp [parseScalar, enumKeys, boolKeys, boundedKeys, stringKind, lowAt, highAt] at parsed
              | some maximum =>
                by_cases valid : StringSchema minimum maximum
                · have same : schema = .text minimum maximum := by
                    simpa [parseScalar, enumKeys, boolKeys, boundedKeys, stringKind, lowAt, highAt, valid] using parsed.symm
                  subst schema
                  obtain ⟨low, lowMember, lowMeaning, _⟩ := (string_bound_exact _ _).mp lowAt
                  obtain ⟨high, highMember, highMeaning, _⟩ := (string_bound_exact _ _).mp highAt
                  exact .string members minimum maximum low high boundedKeys stringKind lowMember highMember lowMeaning highMeaning valid
                · simp [parseScalar, enumKeys, boolKeys, boundedKeys, stringKind, lowAt, highAt, valid] at parsed
          · by_cases integerKind : member kindKey members = some (.text integerTag)
            · cases lowAt : signedBound (member minimumKey members) with
              | none => simp [parseScalar, enumKeys, boolKeys, boundedKeys, stringKind, integerKind, lowAt] at parsed
              | some minimum =>
                cases highAt : signedBound (member maximumKey members) with
                | none => simp [parseScalar, enumKeys, boolKeys, boundedKeys, stringKind, integerKind, lowAt, highAt] at parsed
                | some maximum =>
                  by_cases valid : IntegerSchema minimum maximum
                  · have same : schema = .integer minimum maximum := by
                      simpa [parseScalar, enumKeys, boolKeys, boundedKeys, stringKind, integerKind, lowAt, highAt, valid] using parsed.symm
                    subst schema
                    obtain ⟨low, lowMember, lowMeaning⟩ := signed_bound_sound _ _ lowAt
                    obtain ⟨high, highMember, highMeaning⟩ := signed_bound_sound _ _ highAt
                    exact .integer members minimum maximum low high boundedKeys integerKind lowMember highMember lowMeaning highMeaning valid
                  · simp [parseScalar, enumKeys, boolKeys, boundedKeys, stringKind, integerKind, lowAt, highAt, valid] at parsed
            · simp [parseScalar, enumKeys, boolKeys, boundedKeys, stringKind, integerKind] at parsed
        · simp [parseScalar, enumKeys, boolKeys, boundedKeys] at parsed
  | _ => simp [parseScalar] at parsed

private theorem key_count_excludes (members : List (Bytes × Value)) (left right : List Bytes)
    (known : ExactKeys members left) (different : left.length ≠ right.length) : ¬ExactKeys members right := by
  intro other
  exact different ((exact_keys_size members left known).symm.trans (exact_keys_size members right other))

theorem scalar_parse_complete (source : Value) (schema : Schema) (meaning : ScalarMeaning source schema) :
    parseScalar source = some schema := by
  cases meaning with
  | string members minimum maximum low high keys kind lowAt highAt lowValue highValue bounds =>
    have notEnum := key_count_excludes members _ [typeKey, variantsKey] keys (by decide)
    have notBool := key_count_excludes members _ [kindKey] keys (by decide)
    have lowParsed := (string_bound_exact (member minimumKey members) minimum).mpr
      ⟨low, lowAt, lowValue, bounds.1.trans bounds.2⟩
    have highParsed := (string_bound_exact (member maximumKey members) maximum).mpr
      ⟨high, highAt, highValue, bounds.2⟩
    simp [parseScalar, notEnum, notBool, keys, kind, lowParsed, highParsed, bounds]
  | integer members minimum maximum low high keys kind lowAt highAt lowValue highValue bounds =>
    have notEnum := key_count_excludes members _ [typeKey, variantsKey] keys (by decide)
    have notBool := key_count_excludes members _ [kindKey] keys (by decide)
    have lowSafe : -9007199254740991 ≤ minimum ∧ minimum ≤ 9007199254740991 :=
      ⟨bounds.2.1, bounds.1.trans bounds.2.2⟩
    have highSafe : -9007199254740991 ≤ maximum ∧ maximum ≤ 9007199254740991 :=
      ⟨bounds.2.1.trans bounds.1, bounds.2.2⟩
    have lowParsed : signedBound (member minimumKey members) = some minimum := by
      rw [lowAt]
      exact (signed_bound_exact_on_safe_integer low minimum lowSafe).mpr lowValue
    have highParsed : signedBound (member maximumKey members) = some maximum := by
      rw [highAt]
      exact (signed_bound_exact_on_safe_integer high maximum highSafe).mpr highValue
    simp [parseScalar, notEnum, notBool, keys, kind, integerTag, stringTag, lowParsed, highParsed, bounds]
  | enumeration members values variants keys kind valuesAt paired valid =>
    have decoded := (texts_exact values variants).mpr paired
    simp [parseScalar, keys, kind, valuesAt, decoded, valid]
  | boolean members keys kind =>
    have notEnum := key_count_excludes members _ [typeKey, variantsKey] keys (by decide)
    simp [parseScalar, notEnum, keys, kind]

theorem scalar_parse_exact (source : Value) (schema : Schema) :
    parseScalar source = some schema ↔ ScalarMeaning source schema :=
  ⟨scalar_parse_sound source schema, scalar_parse_complete source schema⟩

theorem scalar_refusal_exact (source : Value) :
    parseScalar source = none ↔ ¬∃ schema, ScalarMeaning source schema := by
  constructor
  · rintro refused ⟨schema, meaning⟩
    have accepted := scalar_parse_complete source schema meaning
    simp [refused] at accepted
  · intro invalid
    cases parsed : parseScalar source with
    | none => rfl
    | some schema => exact False.elim (invalid ⟨schema, scalar_parse_sound source schema parsed⟩)

theorem collected_fields_sound (members : List (Bytes × Value)) (fields : List Field)
    (parsed : collectFields members = some fields) : List.Forall₂ FieldMeaning members fields := by
  induction members generalizing fields with
  | nil => simp [collectFields] at parsed; subst fields; exact .nil
  | cons first rest ih =>
    rcases first with ⟨name, value⟩
    cases scalarAt : parseScalar value with
    | none => simp [collectFields, scalarAt] at parsed
    | some schema =>
      cases tailAt : collectFields rest with
      | none => simp [collectFields, scalarAt, tailAt] at parsed
      | some tail =>
        have same : fields = ⟨name, schema⟩ :: tail := by simpa [collectFields, scalarAt, tailAt] using parsed.symm
        subst fields
        exact .cons ⟨rfl, scalar_parse_sound value schema scalarAt⟩ (ih tail tailAt)

theorem collected_fields_complete (members : List (Bytes × Value)) (fields : List Field)
    (paired : List.Forall₂ FieldMeaning members fields) : collectFields members = some fields := by
  induction paired with
  | nil => rfl
  | @cons first field rest fields firstMeaning restMeaning ih =>
    rcases first with ⟨name, value⟩
    rcases field with ⟨actualName, schema⟩
    obtain ⟨same, meaning⟩ := firstMeaning
    have parsed := scalar_parse_complete value schema meaning
    simp [collectFields, parsed, ih, same]

theorem fields_parse_exact (members : List (Bytes × Value)) (fields : List Field) :
    parseFields members = some fields ↔ FieldsMeaning members fields := by
  constructor
  · intro parsed
    by_cases excluded : members = [] ∨ 32 < members.length
    · simp [parseFields, excluded] at parsed
    · cases collected : collectFields members with
      | none => simp [parseFields, excluded, collected] at parsed
      | some actual =>
        by_cases layout : LayoutValid actual
        · have same : fields = actual := by simpa [parseFields, excluded, collected, layout] using parsed.symm
          subst fields
          have paired := collected_fields_sound members actual collected
          refine ⟨?_, layout, paired⟩
          have size := paired.length_eq
          have nonempty : members ≠ [] := fun empty => excluded (Or.inl empty)
          have positive := List.length_pos.mpr nonempty
          omega
        · simp [parseFields, excluded, collected, layout] at parsed
  · rintro ⟨nonempty, layout, paired⟩
    have collected := collected_fields_complete members fields paired
    have size := paired.length_eq
    have excluded : ¬(members = [] ∨ 32 < members.length) := by
      intro invalid
      rcases invalid with empty | long
      · simp [empty] at size
        omega
      · have bound := layout.1
        omega
    simp [parseFields, excluded, collected, layout]

theorem root_parse_exact (source : Value) (fields : List Field) :
    parseRoot source = some fields ↔ RootMeaning source fields := by
  constructor
  · intro parsed
    cases source with
    | object root =>
      by_cases admitted : ExactKeys root [kindKey, fieldsKey] ∧ member kindKey root = some (.text objectTag)
      · cases valuesAt : member fieldsKey root with
        | none => simp [parseRoot, admitted, valuesAt] at parsed
        | some values =>
          cases values with
          | object members =>
            refine ⟨root, members, rfl, admitted.1, admitted.2, valuesAt, ?_⟩
            apply (fields_parse_exact members fields).mp
            simpa [parseRoot, admitted, valuesAt] using parsed
          | _ => simp [parseRoot, admitted, valuesAt] at parsed
      · simp [parseRoot, admitted] at parsed
    | _ => simp [parseRoot] at parsed
  · rintro ⟨root, members, rfl, keys, kind, valuesAt, meaning⟩
    have parsed := (fields_parse_exact members fields).mpr meaning
    simp [parseRoot, keys, kind, valuesAt, parsed]

theorem root_refusal_exact (source : Value) :
    parseRoot source = none ↔ ¬∃ fields, RootMeaning source fields := by
  constructor
  · rintro refused ⟨fields, meaning⟩
    have accepted := (root_parse_exact source fields).mpr meaning
    simp [refused] at accepted
  · intro invalid
    cases parsed : parseRoot source with
    | none => rfl
    | some fields => exact False.elim (invalid ⟨fields, (root_parse_exact source fields).mp parsed⟩)

end Auths.Product.ProfileSchema
