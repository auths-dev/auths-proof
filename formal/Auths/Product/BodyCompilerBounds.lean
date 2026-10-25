import Auths.Product.BodyCompiler

namespace Auths.Product.BodyCompiler
open RequestConstruction

def EnvironmentBounded (environment : Bytes → Option Arg) : Prop :=
  ∀ name value, environment name = some value → ScalarProjection.PayloadLength value ≤ 4096

theorem json_byte_length (byte : Nat) : (jsonByte byte).length ≤ 6 := by
  unfold jsonByte
  split <;> simp_all
  all_goals split <;> simp_all
  all_goals split <;> simp_all
  all_goals split <;> simp_all
  all_goals split <;> simp_all
  all_goals split <;> simp_all
  all_goals split <;> simp_all

theorem json_escape_length (bytes : Bytes) : (jsonEscape bytes).length ≤ 6 * bytes.length := by
  induction bytes with
  | nil => simp [jsonEscape]
  | cons byte rest ih =>
    have one := json_byte_length byte
    simp only [jsonEscape, List.flatMap_cons, List.length_append, List.length_cons] at *
    omega

theorem json_string_length (bytes : Bytes) : (jsonString bytes).length ≤ 6 * bytes.length + 2 := by
  have escaped := json_escape_length bytes
  simp only [jsonString, List.length_cons, List.length_append, List.length_singleton]
  omega

theorem form_encode_length (bytes : Bytes) : (formEncode bytes).length ≤ 3 * bytes.length := by
  induction bytes with
  | nil => simp [formEncode]
  | cons byte rest ih =>
    have one : (formByte byte).length ≤ 3 := by
      unfold formByte
      split <;> simp_all [percent]
      split <;> simp [percent]
    simp only [formEncode, List.flatMap_cons, List.length_append, List.length_cons] at *
    omega

theorem json_argument_length (value : Arg) (bounded : ScalarProjection.PayloadLength value ≤ 4096) :
    (jsonArgument value).length ≤ 24578 := by
  cases value with
  | text bytes =>
    have size := json_string_length bytes
    simp only [ScalarProjection.PayloadLength] at bounded
    simpa only [jsonArgument] using (show (jsonString bytes).length ≤ 24578 by omega)
  | integer bytes => simpa [jsonArgument, ScalarProjection.PayloadLength] using bounded.trans (by omega)
  | boolean value => cases value <;> decide

theorem named_json_piece_length (environment : Bytes → Option Arg) (echo : Bytes)
    (bounded : EnvironmentBounded environment) (echoBound : echo.length ≤ 128) (source : NamedJson) :
    (namedJsonPiece environment echo source).length ≤ jsonLiteralSize source + 24578 * jsonDynamicSize source := by
  cases source with
  | raw bytes => simp [namedJsonPiece, jsonLiteralSize, jsonDynamicSize]
  | field name =>
    cases found : environment name with
    | none => simp [namedJsonPiece, found, jsonLiteralSize, jsonDynamicSize]
    | some value =>
      simpa [namedJsonPiece, found, jsonLiteralSize, jsonDynamicSize] using
        json_argument_length value (bounded name value found)
  | echo =>
    have size := json_string_length echo
    simp only [namedJsonPiece, jsonLiteralSize, jsonDynamicSize]
    omega

theorem named_json_length (environment : Bytes → Option Arg) (echo : Bytes)
    (bounded : EnvironmentBounded environment) (echoBound : echo.length ≤ 128) (source : List NamedJson) :
    (namedJson environment echo source).length ≤ jsonLiterals source + 24578 * jsonDynamics source := by
  induction source with
  | nil => simp [namedJson, jsonLiterals, jsonDynamics]
  | cons first rest ih =>
    have one := named_json_piece_length environment echo bounded echoBound first
    simp only [namedJson, List.flatMap_cons, List.length_append, jsonLiterals, jsonDynamics,
      List.map_cons, List.sum_cons] at *
    omega

theorem named_form_piece_length (environment : Bytes → Option Arg) (echo : Bytes)
    (bounded : EnvironmentBounded environment) (echoBound : echo.length ≤ 128) (source : NamedForm) :
    (namedFormPiece environment echo source).length ≤ 3 * formLiteralSize source + 73734 * formDynamicSize source := by
  cases source with
  | raw bytes => simp [namedFormPiece, formLiteralSize, formDynamicSize]; omega
  | field name =>
    cases found : environment name with
    | none => simp [namedFormPiece, found, formLiteralSize, formDynamicSize]
    | some value =>
      have payload := bounded name value found
      cases value with
      | text bytes =>
        have size := form_encode_length bytes
        simp only [ScalarProjection.PayloadLength] at payload
        simp only [namedFormPiece, found, formLiteralSize, formDynamicSize]
        omega
      | integer bytes =>
        have size := form_encode_length bytes
        simp only [ScalarProjection.PayloadLength] at payload
        simp only [namedFormPiece, found, formLiteralSize, formDynamicSize]
        omega
      | boolean value => simp [namedFormPiece, found, formLiteralSize, formDynamicSize]
  | json pieces =>
    have jsonSize := named_json_length environment echo bounded echoBound pieces
    have formSize := form_encode_length (namedJson environment echo pieces)
    simp only [namedFormPiece, formLiteralSize, formDynamicSize]
    omega
  | echo =>
    have size := form_encode_length echo
    simp only [namedFormPiece, formLiteralSize, formDynamicSize]
    omega

theorem named_form_length (environment : Bytes → Option Arg) (echo : Bytes)
    (bounded : EnvironmentBounded environment) (echoBound : echo.length ≤ 128) (source : List NamedForm) :
    (namedForm environment echo source).length ≤ 3 * formLiterals source + 73734 * formDynamics source := by
  induction source with
  | nil => simp [namedForm, formLiterals, formDynamics]
  | cons first rest ih =>
    have one := named_form_piece_length environment echo bounded echoBound first
    simp only [namedForm, List.flatMap_cons, List.length_append, formLiterals, formDynamics,
      List.map_cons, List.sum_cons] at *
    omega

theorem json_resource_domain_earns_writer_fit (environment : Bytes → Option Arg) (echo : Bytes)
    (bounded : EnvironmentBounded environment) (echoBound : echo.length ≤ 128)
    (source : List NamedJson) (domain : JsonResourceDomain source) :
    (namedJson environment echo source).length < 4294967295 := by
  have bound := named_json_length environment echo bounded echoBound source
  obtain ⟨literalBound, dynamicBound⟩ := domain
  omega

theorem form_resource_domain_earns_writer_fit (environment : Bytes → Option Arg) (echo : Bytes)
    (bounded : EnvironmentBounded environment) (echoBound : echo.length ≤ 128)
    (source : List NamedForm) (domain : FormResourceDomain source) :
    (namedForm environment echo source).length < 4294967295 := by
  have bound := named_form_length environment echo bounded echoBound source
  obtain ⟨literalBound, dynamicBound, nestedCounts⟩ := domain
  omega

end Auths.Product.BodyCompiler
