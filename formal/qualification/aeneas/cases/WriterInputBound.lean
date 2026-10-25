import Auths.Support.WriterInputBound
/- Actual source getter and call input signatures. Dynamic output predicates are
   checked by the construction AST replay, not independently reflected here.
   Source input WF, capture reachability and native adequacy remain required.
   All scripts are unelaborated; this file is not qualification evidence. -/
namespace Auths.Qualification.WriterInputBound
open Auths.Support.SourceClosureRegions Auths.Support.WriterInputBound
def sourceOwner : Nat := 315
def getterNodes : List Nat := [860]
universe u
def producer0Case : Nat := 47
def producer0Statement : Nat := 1449553
def producer0Original : SignatureView := {
  regionParameters := [0]
  bodyRegions := 0
  inputs := [.node .mutRef [.region (.parameter 0), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.parameter 0), .node .typeFree [.natural 0]]]
  writerIndex := 1
  writerType := .node .typeFree [.natural 0]
  outputObjectRegion := .parameter 0 }
theorem producer0Original_exact_input : check producer0Original = true := by decide
theorem producer0Original_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : producer0Original.inputs[producer0Original.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive producer0Original.writerType producer0Original.outputObjectRegion :=
  source_getter_input_supplies_object_bound producer0Original regions typeLive producer0Original_exact_input input actual typed
def producer0Prepared : SignatureView := {
  regionParameters := [0, 1]
  bodyRegions := 0
  inputs := [.node .mutRef [.region (.parameter 0), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.parameter 0), .node .mutRef [.region (.parameter 1), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 1), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .parameter 0 }
theorem producer0Prepared_exact_input : check producer0Prepared = true := by decide
theorem producer0Prepared_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : producer0Prepared.inputs[producer0Prepared.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive producer0Prepared.writerType producer0Prepared.outputObjectRegion :=
  source_getter_input_supplies_object_bound producer0Prepared regions typeLive producer0Prepared_exact_input input actual typed
def producer1Case : Nat := 48
def producer1Statement : Nat := 1449567
def producer1Original : SignatureView := {
  regionParameters := [0]
  bodyRegions := 0
  inputs := [.node .mutRef [.region (.parameter 0), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.parameter 0), .node .typeFree [.natural 0]]]
  writerIndex := 1
  writerType := .node .typeFree [.natural 0]
  outputObjectRegion := .parameter 0 }
theorem producer1Original_exact_input : check producer1Original = true := by decide
theorem producer1Original_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : producer1Original.inputs[producer1Original.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive producer1Original.writerType producer1Original.outputObjectRegion :=
  source_getter_input_supplies_object_bound producer1Original regions typeLive producer1Original_exact_input input actual typed
def producer1Prepared : SignatureView := {
  regionParameters := [0, 1]
  bodyRegions := 0
  inputs := [.node .mutRef [.region (.parameter 0), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.parameter 0), .node .mutRef [.region (.parameter 1), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 1), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .parameter 0 }
theorem producer1Prepared_exact_input : check producer1Prepared = true := by decide
theorem producer1Prepared_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : producer1Prepared.inputs[producer1Prepared.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive producer1Prepared.writerType producer1Prepared.outputObjectRegion :=
  source_getter_input_supplies_object_bound producer1Prepared regions typeLive producer1Prepared_exact_input input actual typed
def call0Caller : Nat := 760
def call0Statement : Nat := 1427639
def call0 : SignatureView := {
  regionParameters := [0, 1, 2]
  bodyRegions := 91
  inputs := [.node .mutRef [.region (.body 8), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.body 8), .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .body 8 }
theorem call0_exact_input : check call0 = true := by decide
theorem call0_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : call0.inputs[call0.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive call0.writerType call0.outputObjectRegion :=
  source_getter_input_supplies_object_bound call0 regions typeLive call0_exact_input input actual typed
def call1Caller : Nat := 844
def call1Statement : Nat := 1426268
def call1 : SignatureView := {
  regionParameters := [0, 1, 2]
  bodyRegions := 40
  inputs := [.node .mutRef [.region (.body 10), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.body 10), .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .body 10 }
theorem call1_exact_input : check call1 = true := by decide
theorem call1_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : call1.inputs[call1.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive call1.writerType call1.outputObjectRegion :=
  source_getter_input_supplies_object_bound call1 regions typeLive call1_exact_input input actual typed
def call2Caller : Nat := 845
def call2Statement : Nat := 1426351
def call2 : SignatureView := {
  regionParameters := [0, 1, 2]
  bodyRegions := 49
  inputs := [.node .mutRef [.region (.body 21), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.body 21), .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .body 21 }
theorem call2_exact_input : check call2 = true := by decide
theorem call2_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : call2.inputs[call2.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive call2.writerType call2.outputObjectRegion :=
  source_getter_input_supplies_object_bound call2 regions typeLive call2_exact_input input actual typed
def call3Caller : Nat := 974
def call3Statement : Nat := 1426679
def call3 : SignatureView := {
  regionParameters := [0, 1, 2]
  bodyRegions := 54
  inputs := [.node .mutRef [.region (.body 14), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.body 14), .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .body 14 }
theorem call3_exact_input : check call3 = true := by decide
theorem call3_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : call3.inputs[call3.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive call3.writerType call3.outputObjectRegion :=
  source_getter_input_supplies_object_bound call3 regions typeLive call3_exact_input input actual typed
def call4Caller : Nat := 976
def call4Statement : Nat := 1426903
def call4 : SignatureView := {
  regionParameters := [0, 1, 2]
  bodyRegions := 40
  inputs := [.node .mutRef [.region (.body 10), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.body 10), .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .body 10 }
theorem call4_exact_input : check call4 = true := by decide
theorem call4_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : call4.inputs[call4.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive call4.writerType call4.outputObjectRegion :=
  source_getter_input_supplies_object_bound call4 regions typeLive call4_exact_input input actual typed
def call5Caller : Nat := 978
def call5Statement : Nat := 1426859
def call5 : SignatureView := {
  regionParameters := [0, 1, 2]
  bodyRegions := 40
  inputs := [.node .mutRef [.region (.body 10), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.body 10), .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .body 10 }
theorem call5_exact_input : check call5 = true := by decide
theorem call5_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : call5.inputs[call5.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive call5.writerType call5.outputObjectRegion :=
  source_getter_input_supplies_object_bound call5 regions typeLive call5_exact_input input actual typed
def call6Caller : Nat := 979
def call6Statement : Nat := 1427381
def call6 : SignatureView := {
  regionParameters := [0, 1, 2]
  bodyRegions := 40
  inputs := [.node .mutRef [.region (.body 10), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.body 10), .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .body 10 }
theorem call6_exact_input : check call6 = true := by decide
theorem call6_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : call6.inputs[call6.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive call6.writerType call6.outputObjectRegion :=
  source_getter_input_supplies_object_bound call6 regions typeLive call6_exact_input input actual typed
def call7Caller : Nat := 1149
def call7Statement : Nat := 1427029
def call7 : SignatureView := {
  regionParameters := [0, 1, 2]
  bodyRegions := 120
  inputs := [.node .mutRef [.region (.body 13), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.body 13), .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .body 13 }
theorem call7_exact_input : check call7 = true := by decide
theorem call7_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : call7.inputs[call7.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive call7.writerType call7.outputObjectRegion :=
  source_getter_input_supplies_object_bound call7 regions typeLive call7_exact_input input actual typed
def call8Caller : Nat := 1149
def call8Statement : Nat := 1427195
def call8 : SignatureView := {
  regionParameters := [0, 1, 2]
  bodyRegions := 120
  inputs := [.node .mutRef [.region (.body 33), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.body 33), .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .body 33 }
theorem call8_exact_input : check call8 = true := by decide
theorem call8_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : call8.inputs[call8.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive call8.writerType call8.outputObjectRegion :=
  source_getter_input_supplies_object_bound call8 regions typeLive call8_exact_input input actual typed
def call9Caller : Nat := 1149
def call9Statement : Nat := 1427275
def call9 : SignatureView := {
  regionParameters := [0, 1, 2]
  bodyRegions := 120
  inputs := [.node .mutRef [.region (.body 40), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.body 40), .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .body 40 }
theorem call9_exact_input : check call9 = true := by decide
theorem call9_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : call9.inputs[call9.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive call9.writerType call9.outputObjectRegion :=
  source_getter_input_supplies_object_bound call9 regions typeLive call9_exact_input input actual typed
def call10Caller : Nat := 1151
def call10Statement : Nat := 1426948
def call10 : SignatureView := {
  regionParameters := [0, 1, 2, 3]
  bodyRegions := 41
  inputs := [.node .mutRef [.region (.body 12), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.body 12), .node .mutRef [.region (.parameter 3), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 3), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .body 12 }
theorem call10_exact_input : check call10 = true := by decide
theorem call10_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : call10.inputs[call10.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive call10.writerType call10.outputObjectRegion :=
  source_getter_input_supplies_object_bound call10 regions typeLive call10_exact_input input actual typed
def call11Caller : Nat := 1160
def call11Statement : Nat := 1427337
def call11 : SignatureView := {
  regionParameters := [0, 1, 2]
  bodyRegions := 40
  inputs := [.node .mutRef [.region (.body 10), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.body 10), .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .body 10 }
theorem call11_exact_input : check call11 = true := by decide
theorem call11_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : call11.inputs[call11.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive call11.writerType call11.outputObjectRegion :=
  source_getter_input_supplies_object_bound call11 regions typeLive call11_exact_input input actual typed
def call12Caller : Nat := 1459
def call12Statement : Nat := 1427429
def call12 : SignatureView := {
  regionParameters := [0, 1, 2]
  bodyRegions := 40
  inputs := [.node .mutRef [.region (.body 10), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.body 10), .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .body 10 }
theorem call12_exact_input : check call12 = true := by decide
theorem call12_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : call12.inputs[call12.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive call12.writerType call12.outputObjectRegion :=
  source_getter_input_supplies_object_bound call12 regions typeLive call12_exact_input input actual typed
def capture0Caller : Nat := 760
def capture0Statement : Nat := 1427904
def capture0GetterCall : Nat := 0
def capture0ParentWriter : Expr := .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
def capture0ObjectRegion : Region := .body 8
def capture0Input : SignatureView := {
  regionParameters := [0, 1, 2]
  bodyRegions := 91
  inputs := [.node .mutRef [.region (.body 8), .node .adt [.natural 237, .node .arguments [.node .regions [], .node .types [], .node .constants [], .node .traits []]]], .node .mutRef [.region (.body 8), .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]]]
  writerIndex := 1
  writerType := .node .mutRef [.region (.parameter 2), .node .adt [.natural 5, .node .arguments [.node .regions [], .node .types [.node .literal [.natural 1]], .node .constants [], .node .traits []]]]
  outputObjectRegion := .body 8 }
theorem capture0Input_exact_input : check capture0Input = true := by decide
theorem capture0Input_source_input_supplies_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop)
    (input : Expr)
    (actual : capture0Input.inputs[capture0Input.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive capture0Input.writerType capture0Input.outputObjectRegion :=
  source_getter_input_supplies_object_bound capture0Input regions typeLive capture0Input_exact_input input actual typed
theorem capture0_exact_source_interface :
    capture0Input.writerType = capture0ParentWriter ∧
    capture0Input.outputObjectRegion = capture0ObjectRegion := by decide
theorem capture0_source_reference_input_supplies_captured_bound {Point : Type u}
    (regions : RegionMeaning Point) (typeLive : Expr → Point → Prop) (input : Expr)
    (actual : capture0Input.inputs[capture0Input.writerIndex]? = some input)
    (typed : ReferenceLifetimeWF regions typeLive input) :
    TypeOutlives regions typeLive capture0ParentWriter capture0ObjectRegion :=
  capture0Input_source_input_supplies_bound regions typeLive input actual typed
end Auths.Qualification.WriterInputBound
