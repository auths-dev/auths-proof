import Auths.Product.BodyCompilerResources
import Auths.Product.PathCompilerLeaves

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.SchemaIndex.Refinement

namespace Auths.Product.BodyCompiler.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def jsonSourceView : body_compiler.NamedJsonPiece → NamedJson
  | .Raw bytes => .raw (vecBytes bytes)
  | .Field name => .field (vecBytes name)
  | .Echo => .echo

def formSourceView : body_compiler.NamedFormPiece → NamedForm
  | .Raw bytes => .raw (vecBytes bytes)
  | .Field name => .field (vecBytes name)
  | .Json pieces => .json (pieces.val.map jsonSourceView)
  | .Echo => .echo

def jsonSource (pieces : Slice body_compiler.NamedJsonPiece) : List NamedJson := pieces.val.map jsonSourceView
def formSource (pieces : Slice body_compiler.NamedFormPiece) : List NamedForm := pieces.val.map formSourceView
def usageOf (used : body_compiler.ResourceUse) : Resources.Usage :=
  ⟨used.literal_bytes.val, used.dynamic_pieces.val⟩

@[step] theorem add_resources_exact (current : body_compiler.ResourceUse) (literal dynamic : Usize) :
    body_compiler.add_resources current literal dynamic ⦃ actual =>
      actual.map usageOf = Resources.add (usageOf current) ⟨literal.val, dynamic.val⟩ ⦄ := by
  unfold body_compiler.add_resources body_compiler.MAX_TEMPLATE_LITERAL_BYTES body_compiler.MAX_TEMPLATE_PIECES
  by_cases oldLiteral : 524288 < current.literal_bytes.val
  · have native : current.literal_bytes > 524288#usize := by scalar_tac
    simp [native, Resources.add, Resources.Bounded, usageOf, Nat.not_le.mpr oldLiteral]
  · have oldLiteralBound : current.literal_bytes.val ≤ 524288 := by omega
    have nativeLiteral : ¬current.literal_bytes > 524288#usize := by scalar_tac
    by_cases oldDynamic : 256 < current.dynamic_pieces.val
    · have native : current.dynamic_pieces > 256#usize := by scalar_tac
      simp [nativeLiteral, native, Resources.add, Resources.Bounded, usageOf, Nat.not_le.mpr oldDynamic]
    · have oldDynamicBound : current.dynamic_pieces.val ≤ 256 := by omega
      have nativeDynamic : ¬current.dynamic_pieces > 256#usize := by scalar_tac
      simp only [nativeLiteral, nativeDynamic, Bool.false_or]
      step as ⟨literalRoom, literalRoomValue⟩
      by_cases tooMuchLiteral : 524288 - current.literal_bytes.val < literal.val
      · have native : literal > literalRoom := by scalar_tac
        have invalid : ¬Resources.Bounded (Resources.plus (usageOf current) ⟨literal.val, dynamic.val⟩) := by
          unfold Resources.Bounded Resources.plus usageOf
          omega
        simp [native, Resources.add, invalid]
      · have literalBound : current.literal_bytes.val + literal.val ≤ 524288 := by omega
        have nativeLiteralFits : ¬literal > literalRoom := by scalar_tac
        simp only [nativeLiteralFits, Bool.false_or]
        step as ⟨dynamicRoom, dynamicRoomValue⟩
        by_cases tooMuchDynamic : 256 - current.dynamic_pieces.val < dynamic.val
        · have native : dynamic > dynamicRoom := by scalar_tac
          have invalid : ¬Resources.Bounded (Resources.plus (usageOf current) ⟨literal.val, dynamic.val⟩) := by
            unfold Resources.Bounded Resources.plus usageOf
            omega
          simp [native, Resources.add, invalid]
        · have dynamicBound : current.dynamic_pieces.val + dynamic.val ≤ 256 := by omega
          have nativeDynamicFits : ¬dynamic > dynamicRoom := by scalar_tac
          have currentBound : Resources.Bounded (usageOf current) := ⟨oldLiteralBound, oldDynamicBound⟩
          have totalBound : Resources.Bounded (Resources.plus (usageOf current) ⟨literal.val, dynamic.val⟩) :=
            ⟨literalBound, dynamicBound⟩
          simp only [nativeDynamicFits, ↓reduceIte]
          step as ⟨literalSum, literalSumValue⟩
          step as ⟨dynamicSum, dynamicSumValue⟩
          simp [usageOf, Resources.add, Resources.plus, currentBound, totalBound, literalSumValue, dynamicSumValue]


@[step] theorem json_resources_loop_exact (source : Slice body_compiler.NamedJsonPiece)
    (bounded : source.val.length ≤ 256) :
    body_compiler.json_resources_loop source
      { literal_bytes := 0#usize, dynamic_pieces := 0#usize } 0#usize
      ⦃ actual => actual.map usageOf = Resources.scan Resources.jsonCharge Resources.zero (jsonSource source) ⦄ := by
  unfold body_compiler.json_resources_loop
  let wanted := Resources.scan Resources.jsonCharge Resources.zero (jsonSource source)
  apply loop.spec_decr_nat
    (measure := fun state => source.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ source.val.length ∧ Resources.Bounded (usageOf state.1) ∧
      wanted = Resources.scan Resources.jsonCharge (usageOf state.1) ((jsonSource source).drop state.2.val))
  · rintro ⟨current, index⟩ invariant
    unfold body_compiler.json_resources_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < source.val.length := by simpa using within
      step as ⟨piece, pieceAt⟩
      have suffix : (jsonSource source).drop index.val =
          jsonSourceView piece :: (jsonSource source).drop (index.val + 1) := by
        simpa [jsonSource, List.drop_map, pieceAt] using
          congrArg (List.map jsonSourceView) (List.drop_eq_getElem_cons inside)
      rw [suffix, Resources.scan] at invariant
      cases piece with
      | Raw bytes =>
        step with add_resources_exact as ⟨charged, chargeMeaning⟩
        have meaning : charged.map usageOf =
            Resources.jsonCharge (usageOf current) (jsonSourceView (body_compiler.NamedJsonPiece.Raw bytes)) := by
          simpa [Resources.jsonCharge, Resources.jsonQuantity, jsonSourceView, jsonLiteralSize,
            jsonDynamicSize, vecBytes, length_byteList] using chargeMeaning
        cases charged with
        | none =>
          simp only [Option.map_none] at meaning
          simpa [← meaning] using invariant.2.2.symm
        | some next =>
          simp only [Option.map_some] at meaning
          have nextBound : Resources.Bounded (usageOf next) :=
            Resources.add_success_earns_bound _ _ _ meaning.symm
          step as ⟨nextIndex, nextIndexValue⟩
          refine ⟨by omega, nextBound, ?_, by omega⟩
          simpa [← meaning, nextIndexValue] using invariant.2.2
      | Field name =>
        step with add_resources_exact as ⟨charged, chargeMeaning⟩
        have meaning : charged.map usageOf =
            Resources.jsonCharge (usageOf current) (jsonSourceView (body_compiler.NamedJsonPiece.Field name)) := by
          simpa [Resources.jsonCharge, Resources.jsonQuantity, jsonSourceView, jsonLiteralSize,
            jsonDynamicSize, vecBytes, length_byteList] using chargeMeaning
        cases charged with
        | none =>
          simp only [Option.map_none] at meaning
          simpa [← meaning] using invariant.2.2.symm
        | some next =>
          simp only [Option.map_some] at meaning
          have nextBound : Resources.Bounded (usageOf next) :=
            Resources.add_success_earns_bound _ _ _ meaning.symm
          step as ⟨nextIndex, nextIndexValue⟩
          refine ⟨by omega, nextBound, ?_, by omega⟩
          simpa [← meaning, nextIndexValue] using invariant.2.2
      | Echo =>
        step with add_resources_exact as ⟨charged, chargeMeaning⟩
        have meaning : charged.map usageOf =
            Resources.jsonCharge (usageOf current) (jsonSourceView (body_compiler.NamedJsonPiece.Echo)) := by
          simpa [Resources.jsonCharge, Resources.jsonQuantity, jsonSourceView, jsonLiteralSize,
            jsonDynamicSize, vecBytes, length_byteList] using chargeMeaning
        cases charged with
        | none =>
          simp only [Option.map_none] at meaning
          simpa [← meaning] using invariant.2.2.symm
        | some next =>
          simp only [Option.map_some] at meaning
          have nextBound : Resources.Bounded (usageOf next) :=
            Resources.add_success_earns_bound _ _ _ meaning.symm
          step as ⟨nextIndex, nextIndexValue⟩
          refine ⟨by omega, nextBound, ?_, by omega⟩
          simpa [← meaning, nextIndexValue] using invariant.2.2
    · simp only [spec_ok, Option.map_some]
      have atEnd : source.val.length ≤ index.val := by simpa using within
      have modelAtEnd : (jsonSource source).length ≤ index.val := by simpa [jsonSource] using atEnd
      simpa [List.drop_of_length_le modelAtEnd, Resources.scan] using invariant.2.2.symm
  · simp [wanted, Resources.zero, Resources.Bounded, usageOf]

@[step] theorem json_resources_exact (source : Slice body_compiler.NamedJsonPiece) :
    body_compiler.json_resources source ⦃ actual =>
      actual.map usageOf = Resources.jsonResources (jsonSource source) ⦄ := by
  unfold body_compiler.json_resources body_compiler.MAX_TEMPLATE_PIECES
  by_cases tooMany : 256 < source.val.length
  · have native : source.len > 256#usize := by scalar_tac
    simp [native, Resources.jsonResources, jsonSource, Nat.not_le.mpr tooMany]
  · have bounded : source.val.length ≤ 256 := by omega
    have native : ¬source.len > 256#usize := by scalar_tac
    simp only [native, ↓reduceIte]
    apply spec_mono (json_resources_loop_exact source bounded)
    intro actual meaning
    simpa [Resources.jsonResources, jsonSource, bounded] using meaning

@[step] theorem form_piece_resources_exact (current : body_compiler.ResourceUse)
    (piece : body_compiler.NamedFormPiece) :
    body_compiler.form_piece_resources current piece ⦃ actual =>
      actual.map usageOf = Resources.formCharge (usageOf current) (formSourceView piece) ⦄ := by
  cases piece with
  | Raw bytes =>
    unfold body_compiler.form_piece_resources
    step with add_resources_exact as ⟨charged, meaning⟩
    simpa [Resources.formCharge, Resources.formQuantity, formSourceView, NestedCount,
      formLiteralSize, formDynamicSize, vecBytes, length_byteList] using meaning
  | Field name =>
    unfold body_compiler.form_piece_resources
    step with add_resources_exact as ⟨charged, meaning⟩
    simpa [Resources.formCharge, Resources.formQuantity, formSourceView, NestedCount,
      formLiteralSize, formDynamicSize] using meaning
  | Echo =>
    unfold body_compiler.form_piece_resources
    step with add_resources_exact as ⟨charged, meaning⟩
    simpa [Resources.formCharge, Resources.formQuantity, formSourceView, NestedCount,
      formLiteralSize, formDynamicSize] using meaning
  | Json pieces =>
    unfold body_compiler.form_piece_resources
    step with json_resources_exact as ⟨nested, meaning⟩
    cases nested with
    | none =>
      simp only [Option.map_none] at meaning
      have invalid : ¬((pieces.val.map jsonSourceView).length ≤ 256 ∧
          JsonResourceDomain (pieces.val.map jsonSourceView)) := by
        intro admitted
        rw [Resources.json_resources_exact_totals] at meaning
        simp [jsonSource, admitted] at meaning
      by_cases count : (pieces.val.map jsonSourceView).length ≤ 256
      · have badDomain : ¬JsonResourceDomain (pieces.val.map jsonSourceView) := by tauto
        have badTotal : ¬Resources.Bounded (Resources.plus (usageOf current)
            ⟨jsonLiterals (pieces.val.map jsonSourceView), jsonDynamics (pieces.val.map jsonSourceView)⟩) := by
          intro bounded
          apply badDomain
          unfold JsonResourceDomain
          unfold Resources.Bounded Resources.plus at bounded
          constructor <;> omega
        simp [Resources.formCharge, formSourceView, NestedCount, count, Resources.formQuantity,
          formLiteralSize, formDynamicSize, Resources.add, badTotal]
      · simp [Resources.formCharge, formSourceView, NestedCount, count]
    | some nested =>
      have checked : Resources.jsonResources (pieces.val.map jsonSourceView) = some (usageOf nested) := by
        simpa [jsonSource] using meaning.symm
      obtain ⟨totals, count, domain⟩ := Resources.json_resources_success_earns_totals _ _ checked
      step with add_resources_exact as ⟨charged, chargeMeaning⟩
      have literalExact : nested.literal_bytes.val = jsonLiterals (pieces.val.map jsonSourceView) :=
        congrArg Resources.Usage.literalBytes totals
      have dynamicExact : nested.dynamic_pieces.val = jsonDynamics (pieces.val.map jsonSourceView) :=
        congrArg Resources.Usage.dynamicPieces totals
      simpa [Resources.formCharge, formSourceView, NestedCount, count, Resources.formQuantity,
        formLiteralSize, formDynamicSize, literalExact, dynamicExact] using chargeMeaning

@[step] theorem form_resources_loop_exact (source : Slice body_compiler.NamedFormPiece)
    (bounded : source.val.length ≤ 256) :
    body_compiler.form_resources_loop source
      { literal_bytes := 0#usize, dynamic_pieces := 0#usize } 0#usize
      ⦃ actual => actual.map usageOf = Resources.scan Resources.formCharge Resources.zero (formSource source) ⦄ := by
  unfold body_compiler.form_resources_loop
  let wanted := Resources.scan Resources.formCharge Resources.zero (formSource source)
  apply loop.spec_decr_nat
    (measure := fun state => source.val.length - state.2.val)
    (inv := fun state => state.2.val ≤ source.val.length ∧ Resources.Bounded (usageOf state.1) ∧
      wanted = Resources.scan Resources.formCharge (usageOf state.1) ((formSource source).drop state.2.val))
  · rintro ⟨current, index⟩ invariant
    unfold body_compiler.form_resources_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < source.val.length := by simpa using within
      step as ⟨piece, pieceAt⟩
      have suffix : (formSource source).drop index.val =
          formSourceView piece :: (formSource source).drop (index.val + 1) := by
        simpa [formSource, List.drop_map, pieceAt] using
          congrArg (List.map formSourceView) (List.drop_eq_getElem_cons inside)
      rw [suffix, Resources.scan] at invariant
      step with form_piece_resources_exact as ⟨charged, meaning⟩
      cases charged with
      | none =>
        simp only [Option.map_none] at meaning
        simpa [← meaning] using invariant.2.2.symm
      | some next =>
        simp only [Option.map_some] at meaning
        have nextBound : Resources.Bounded (usageOf next) :=
          Resources.form_charge_success_earns_bound _ _ _ meaning.symm
        step as ⟨nextIndex, nextIndexValue⟩
        refine ⟨by omega, nextBound, ?_, by omega⟩
        simpa [← meaning, nextIndexValue] using invariant.2.2
    · simp only [spec_ok, Option.map_some]
      have atEnd : source.val.length ≤ index.val := by simpa using within
      have modelAtEnd : (formSource source).length ≤ index.val := by simpa [formSource] using atEnd
      simpa [List.drop_of_length_le modelAtEnd, Resources.scan] using invariant.2.2.symm
  · simp [wanted, Resources.zero, Resources.Bounded, usageOf]

@[step] theorem form_resources_exact (source : Slice body_compiler.NamedFormPiece) :
    body_compiler.form_resources source ⦃ actual =>
      actual.map usageOf = Resources.formResources (formSource source) ⦄ := by
  unfold body_compiler.form_resources body_compiler.MAX_TEMPLATE_PIECES
  by_cases tooMany : 256 < source.val.length
  · have native : source.len > 256#usize := by scalar_tac
    simp [native, Resources.formResources, formSource, Nat.not_le.mpr tooMany]
  · have bounded : source.val.length ≤ 256 := by omega
    have native : ¬source.len > 256#usize := by scalar_tac
    simp only [native, ↓reduceIte]
    apply spec_mono (form_resources_loop_exact source bounded)
    intro actual meaning
    simpa [Resources.formResources, formSource, bounded] using meaning

end Auths.Product.BodyCompiler.Refinement

