import Auths.Support.NativePureClosures
import qualification.aeneas.cases.NativeCurrentSeeds
/- Actual native lexical closures for the explicit ending model. Unelaborated/unqualified.
   Original native signatures/effects, defaults and Rust closure/loan/heap adequacy remain open. -/
namespace Auths.Qualification.NativeCaptureClosures
open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection
open Auths.Support.NativePurePayload Auths.Support.NativePureExpressions
open Auths.Qualification.NativePureExpressions
open Auths.Qualification.BorrowProjection.Candidate3400
universe u
def bundle : Term := .lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.tuple [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))]))) (.bound (.literal 0) (some [99, 97, 112, 116, 117, 114, 101, 100, 95, 98, 111, 114, 114, 111, 119, 95, 48])) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.tuple [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [99, 97, 112, 116, 117, 114, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 54])) (.application (.tuple [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))]) (.application (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))) (.tuple [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))])) (.application (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))) (.tuple [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))]))) (.application (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))) (.tuple [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))])))) (.constructor (.arrow (.arrow (.literal 0) (.result (.literal 0))) (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.arrow (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))) (.tuple [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))]))))) (.tuple) (none) [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))]) (.lambda (.arrow (.literal 0) (.result (.literal 0))) (.bound (.literal 0) (some [105, 110, 99, 111, 109, 105, 110, 103, 95, 55])) (.binding (.result (.literal 0)) (.bound (.literal 0) (some [114, 101, 99, 101, 105, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 55])) (.bound (.literal 0) 0 0) (.switch (.result (.literal 0)) (.application (.result (.literal 0)) (.constructor (.arrow (.literal 0) (.result (.literal 0))) (.result) (some 0) [.literal 0]) (.bound (.literal 0) 0 0)) [(.constructor (.result (.literal 0)) (some 0) [.bound (.literal 0) (some [111, 117, 116, 112, 117, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 55])], .application (.result (.literal 0)) (.constructor (.arrow (.literal 0) (.result (.literal 0))) (.result) (some 0) [.literal 0]) (.bound (.literal 0) 0 0)), (.constructor (.result (.literal 0)) (some 1) [.bound (.error) (some [101, 114, 114, 111, 114, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 55])], .application (.result (.literal 0)) (.constructor (.arrow (.error) (.result (.literal 0))) (.result) (some 1) [.literal 0]) (.bound (.error) 0 0))])))) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.literal 0) (some [105, 110, 105, 116, 105, 97, 108, 95, 98, 111, 114, 114, 111, 119, 95, 48])) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [105, 110, 99, 111, 109, 105, 110, 103, 95, 57])) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (some [100, 101, 102, 97, 117, 108, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 56])) (.bound (.literal 0) 1 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (some [111, 98, 115, 101, 114, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 56])) (.bound (.literal 0) 0 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [114, 101, 99, 101, 105, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 57])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0)) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [111, 117, 116, 112, 117, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 57])], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0)), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (some [101, 114, 114, 111, 114, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 57])], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.error) 0 0))])))))) (.bound (.literal 0) 1 0))) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))))) (.bound (.literal 0) (some [105, 110, 105, 116, 105, 97, 108, 95, 98, 111, 114, 114, 111, 119, 95, 48])) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [105, 110, 105, 116, 105, 97, 108, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 54])) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [105, 110, 99, 111, 109, 105, 110, 103, 95, 49, 49])) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (some [100, 101, 102, 97, 117, 108, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 48])) (.bound (.literal 0) 2 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.literal 0) (some [111, 98, 115, 101, 114, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 48])) (.bound (.literal 0) 0 0) (.binding (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [114, 101, 99, 101, 105, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 49])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 4 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0)))])]) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [111, 117, 116, 112, 117, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 49])], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0)), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (some [101, 114, 114, 111, 114, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 49])], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.error) 0 0))]))))))) (.bound (.literal 0) 1 0)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0))) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))))) (.lambda (.arrow (.literal 0) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))))) (.bound (.literal 0) (some [105, 110, 105, 116, 105, 97, 108, 95, 98, 111, 114, 114, 111, 119, 95, 48])) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [105, 110, 105, 116, 105, 97, 108, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 54])) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [105, 110, 99, 111, 109, 105, 110, 103, 95, 49, 52])) (.lambda (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [105, 110, 99, 111, 109, 105, 110, 103, 95, 49, 53])) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.literal 0) (some [100, 101, 102, 97, 117, 108, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 50])) (.bound (.literal 0) 3 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.literal 0) (some [111, 98, 115, 101, 114, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 50])) (.bound (.literal 0) 0 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [100, 101, 102, 97, 117, 108, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 51])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 4 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [111, 98, 115, 101, 114, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 51])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0) (.binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [114, 101, 99, 101, 105, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 52])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 5 0) (.switch (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 1 0)))])]) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [111, 117, 116, 112, 117, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 52])], .binding (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [114, 101, 99, 101, 105, 118, 101, 100, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 53])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 6 0) (.switch (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 9 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 0) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 0 0))), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) []))]), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .switch (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 1 0) [(.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 0) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.error) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 1) [.nominal 507 [.nominal 5 [.literal 1]]]) (.constructor (.error) (.error) (some 0) [])), (.constructor (.nominal 507 [.nominal 5 [.literal 1]]) (some 1) [.bound (.nominal 5 [.literal 1]) (none)], .application (.result (.nominal 507 [.nominal 5 [.literal 1]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]]))) (.result) (some 0) [.nominal 507 [.nominal 5 [.literal 1]]]) (.application (.nominal 507 [.nominal 5 [.literal 1]]) (.constructor (.arrow (.nominal 5 [.literal 1]) (.nominal 507 [.nominal 5 [.literal 1]])) (.nominal 507) (some 1) [.nominal 5 [.literal 1]]) (.bound (.nominal 5 [.literal 1]) 1 0)))])]) [(.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 0) [.bound (.nominal 507 [.nominal 5 [.literal 1]]) (some [111, 117, 116, 112, 117, 116, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 53])], .application (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.result) (some 0) [.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]]) (.application (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]) (.application (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.tuple) (none) [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 2 0)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0))), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (some [101, 114, 114, 111, 114, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 53])], .application (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.error) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.result) (some 1) [.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]]) (.bound (.error) 0 0))])), (.constructor (.result (.nominal 507 [.nominal 5 [.literal 1]])) (some 1) [.bound (.error) (some [101, 114, 114, 111, 114, 95, 115, 121, 109, 98, 111, 108, 105, 99, 95, 49, 52])], .application (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])) (.constructor (.arrow (.error) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]))) (.result) (some 1) [.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]]]) (.bound (.error) 0 0))])))))))))) (.bound (.literal 0) 1 0)) (.bound (.nominal 507 [.nominal 5 [.literal 1]]) 0 0))))
def fuel : Nat := 272
theorem bundle_well_typed : check builtins schemas fuel [] bundle = true := by decide
def build (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Option (Dynamic Atom) :=
  Auths.Support.NativePureClosures.execute builtins schemas fuel bundle [pack fuel counter, pack fuel writer]
def memberTypes : List Ty := [.arrow (.literal 0) (.result (.literal 0)), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.nominal 507 [.nominal 5 [.literal 1]])), .arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.arrow (.nominal 507 [.nominal 5 [.literal 1]]) (.result (.tuple [.nominal 507 [.nominal 5 [.literal 1]], .nominal 507 [.nominal 5 [.literal 1]]])))]
theorem build_has_exact_member_types (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    (build Atom counter writer).map Dynamic.type = some (.tuple memberTypes) := by
  unfold build
  rw [Auths.Support.NativePureClosures.checked_runs_body builtins schemas fuel bundle bundle_well_typed]
  cases counter with
  | atom v0 =>
    cases writer with
    | named v1 =>
      cases v1 with
      | left v2 =>
        cases v2 with
        | named v4 =>
          cases v4 with
          | product v5 v6 =>
            cases v5 with
            | named v7 =>
              cases v7 with
              | atom v8 =>
                cases v6 with
                | unit =>
                  rfl
      | right v3 =>
        cases v3 with
        | left v9 =>
          cases v9 with
          | named v11 =>
            cases v11 with
            | product v12 v13 =>
              cases v12 with
              | named v14 =>
                cases v14 with
                | atom v15 =>
                  cases v13 with
                  | unit =>
                    rfl
        | right v10 =>
          cases v10
theorem build_produces_bundle (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : ∃ functions, build Atom counter writer = some functions := by
  cases result : build Atom counter writer with
  | none =>
    have accepted := build_has_exact_member_types Atom counter writer
    simp [result] at accepted
  | some functions => exact ⟨functions, by simp [result]⟩
def branch0Invoke (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← build Atom counter writer
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured 0 [pack fuel incoming0]
theorem branch0_lexical_closure_matches_state_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) :
    branch0Invoke Atom counter writer incoming0 = Auths.Qualification.NativeCurrentWiring.branch0Run Atom counter writer incoming0 := by
  unfold branch0Invoke build
  rw [Auths.Support.NativePureClosures.checked_runs_body builtins schemas fuel bundle bundle_well_typed]
  unfold Auths.Qualification.NativeCurrentWiring.branch0Run
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeCurrentWiring.branch0Fuel Auths.Qualification.NativeCurrentWiring.branch0 Auths.Qualification.NativeCurrentWiring.branch0_well_typed]
  cases counter with
  | atom v16 =>
    cases writer with
    | named v17 =>
      cases v17 with
      | left v18 =>
        cases v18 with
        | named v20 =>
          cases v20 with
          | product v21 v22 =>
            cases v21 with
            | named v23 =>
              cases v23 with
              | atom v24 =>
                cases v22 with
                | unit =>
                  cases incoming0 with
                  | atom v25 =>
                    rfl
      | right v19 =>
        cases v19 with
        | left v26 =>
          cases v26 with
          | named v28 =>
            cases v28 with
            | product v29 v30 =>
              cases v29 with
              | named v31 =>
                cases v31 with
                | atom v32 =>
                  cases v30 with
                  | unit =>
                    cases incoming0 with
                    | atom v33 =>
                      rfl
        | right v27 =>
          cases v27
def branch1Invoke (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← build Atom counter writer
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured 1 [pack fuel incoming0]
theorem branch1_lexical_closure_matches_state_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) :
    branch1Invoke Atom counter writer incoming0 = Auths.Qualification.NativeCurrentWiring.branch1Run Atom counter writer incoming0 := by
  unfold branch1Invoke build
  rw [Auths.Support.NativePureClosures.checked_runs_body builtins schemas fuel bundle bundle_well_typed]
  unfold Auths.Qualification.NativeCurrentWiring.branch1Run
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeCurrentWiring.branch1Fuel Auths.Qualification.NativeCurrentWiring.branch1 Auths.Qualification.NativeCurrentWiring.branch1_well_typed]
  cases counter with
  | atom v34 =>
    cases writer with
    | named v35 =>
      cases v35 with
      | left v36 =>
        cases v36 with
        | named v38 =>
          cases v38 with
          | product v39 v40 =>
            cases v39 with
            | named v41 =>
              cases v41 with
              | atom v42 =>
                cases v40 with
                | unit =>
                  cases incoming0 with
                  | named v43 =>
                    cases v43 with
                    | left v44 =>
                      cases v44 with
                      | named v46 =>
                        cases v46 with
                        | product v47 v48 =>
                          cases v47 with
                          | named v49 =>
                            cases v49 with
                            | atom v50 =>
                              cases v48 with
                              | unit =>
                                rfl
                    | right v45 =>
                      cases v45 with
                      | left v51 =>
                        cases v51 with
                        | named v53 =>
                          cases v53 with
                          | product v54 v55 =>
                            cases v54 with
                            | named v56 =>
                              cases v56 with
                              | atom v57 =>
                                cases v55 with
                                | unit =>
                                  rfl
                      | right v52 =>
                        cases v52
      | right v37 =>
        cases v37 with
        | left v58 =>
          cases v58 with
          | named v60 =>
            cases v60 with
            | product v61 v62 =>
              cases v61 with
              | named v63 =>
                cases v63 with
                | atom v64 =>
                  cases v62 with
                  | unit =>
                    cases incoming0 with
                    | named v65 =>
                      cases v65 with
                      | left v66 =>
                        cases v66 with
                        | named v68 =>
                          cases v68 with
                          | product v69 v70 =>
                            cases v69 with
                            | named v71 =>
                              cases v71 with
                              | atom v72 =>
                                cases v70 with
                                | unit =>
                                  rfl
                      | right v67 =>
                        cases v67 with
                        | left v73 =>
                          cases v73 with
                          | named v75 =>
                            cases v75 with
                            | product v76 v77 =>
                              cases v76 with
                              | named v78 =>
                                cases v78 with
                                | atom v79 =>
                                  cases v77 with
                                  | unit =>
                                    rfl
                        | right v74 =>
                          cases v74
        | right v59 =>
          cases v59
def branch2Invoke (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← build Atom counter writer
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured 2 [pack fuel incoming0]
theorem branch2_lexical_closure_matches_state_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    branch2Invoke Atom counter writer incoming0 = Auths.Qualification.NativeCurrentWiring.branch2Run Atom counter writer incoming0 := by
  unfold branch2Invoke build
  rw [Auths.Support.NativePureClosures.checked_runs_body builtins schemas fuel bundle bundle_well_typed]
  unfold Auths.Qualification.NativeCurrentWiring.branch2Run
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeCurrentWiring.branch2Fuel Auths.Qualification.NativeCurrentWiring.branch2 Auths.Qualification.NativeCurrentWiring.branch2_well_typed]
  cases counter with
  | atom v80 =>
    cases writer with
    | named v81 =>
      cases v81 with
      | left v82 =>
        cases v82 with
        | named v84 =>
          cases v84 with
          | product v85 v86 =>
            cases v85 with
            | named v87 =>
              cases v87 with
              | atom v88 =>
                cases v86 with
                | unit =>
                  cases incoming0 with
                  | named v89 =>
                    cases v89 with
                    | left v90 =>
                      cases v90 with
                      | named v92 =>
                        cases v92 with
                        | product v93 v94 =>
                          cases v93 with
                          | named v95 =>
                            cases v95 with
                            | atom v96 =>
                              cases v94 with
                              | unit =>
                                rfl
                    | right v91 =>
                      cases v91 with
                      | left v97 =>
                        cases v97 with
                        | named v99 =>
                          cases v99 with
                          | product v100 v101 =>
                            cases v100 with
                            | named v102 =>
                              cases v102 with
                              | atom v103 =>
                                cases v101 with
                                | unit =>
                                  rfl
                      | right v98 =>
                        cases v98
      | right v83 =>
        cases v83 with
        | left v104 =>
          cases v104 with
          | named v106 =>
            cases v106 with
            | product v107 v108 =>
              cases v107 with
              | named v109 =>
                cases v109 with
                | atom v110 =>
                  cases v108 with
                  | unit =>
                    cases incoming0 with
                    | named v111 =>
                      cases v111 with
                      | left v112 =>
                        cases v112 with
                        | named v114 =>
                          cases v114 with
                          | product v115 v116 =>
                            cases v115 with
                            | named v117 =>
                              cases v117 with
                              | atom v118 =>
                                cases v116 with
                                | unit =>
                                  rfl
                      | right v113 =>
                        cases v113 with
                        | left v119 =>
                          cases v119 with
                          | named v121 =>
                            cases v121 with
                            | product v122 v123 =>
                              cases v122 with
                              | named v124 =>
                                cases v124 with
                                | atom v125 =>
                                  cases v123 with
                                  | unit =>
                                    rfl
                        | right v120 =>
                          cases v120
        | right v105 =>
          cases v105
def branch3Invoke (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) : Option (Dynamic Atom) := do
  let captured ← build Atom counter writer
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured 3 [pack fuel incoming0, pack fuel incoming1]
theorem branch3_lexical_closure_matches_state_program (Atom : Ty → Type u) (counter : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) (writer : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) :
    branch3Invoke Atom counter writer incoming0 incoming1 = Auths.Qualification.NativeCurrentWiring.branch3Run Atom counter writer incoming0 incoming1 := by
  unfold branch3Invoke build
  rw [Auths.Support.NativePureClosures.checked_runs_body builtins schemas fuel bundle bundle_well_typed]
  unfold Auths.Qualification.NativeCurrentWiring.branch3Run
  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeCurrentWiring.branch3Fuel Auths.Qualification.NativeCurrentWiring.branch3 Auths.Qualification.NativeCurrentWiring.branch3_well_typed]
  cases counter with
  | atom v126 =>
    cases writer with
    | named v127 =>
      cases v127 with
      | left v128 =>
        cases v128 with
        | named v130 =>
          cases v130 with
          | product v131 v132 =>
            cases v131 with
            | named v133 =>
              cases v133 with
              | atom v134 =>
                cases v132 with
                | unit =>
                  cases incoming0 with
                  | named v135 =>
                    cases v135 with
                    | left v136 =>
                      cases v136 with
                      | named v138 =>
                        cases v138 with
                        | product v139 v140 =>
                          cases v139 with
                          | named v141 =>
                            cases v141 with
                            | atom v142 =>
                              cases v140 with
                              | unit =>
                                cases incoming1 with
                                | named v143 =>
                                  cases v143 with
                                  | left v144 =>
                                    cases v144 with
                                    | named v146 =>
                                      cases v146 with
                                      | product v147 v148 =>
                                        cases v147 with
                                        | named v149 =>
                                          cases v149 with
                                          | atom v150 =>
                                            cases v148 with
                                            | unit =>
                                              rfl
                                  | right v145 =>
                                    cases v145 with
                                    | left v151 =>
                                      cases v151 with
                                      | named v153 =>
                                        cases v153 with
                                        | product v154 v155 =>
                                          cases v154 with
                                          | named v156 =>
                                            cases v156 with
                                            | atom v157 =>
                                              cases v155 with
                                              | unit =>
                                                rfl
                                    | right v152 =>
                                      cases v152
                    | right v137 =>
                      cases v137 with
                      | left v158 =>
                        cases v158 with
                        | named v160 =>
                          cases v160 with
                          | product v161 v162 =>
                            cases v161 with
                            | named v163 =>
                              cases v163 with
                              | atom v164 =>
                                cases v162 with
                                | unit =>
                                  cases incoming1 with
                                  | named v165 =>
                                    cases v165 with
                                    | left v166 =>
                                      cases v166 with
                                      | named v168 =>
                                        cases v168 with
                                        | product v169 v170 =>
                                          cases v169 with
                                          | named v171 =>
                                            cases v171 with
                                            | atom v172 =>
                                              cases v170 with
                                              | unit =>
                                                rfl
                                    | right v167 =>
                                      cases v167 with
                                      | left v173 =>
                                        cases v173 with
                                        | named v175 =>
                                          cases v175 with
                                          | product v176 v177 =>
                                            cases v176 with
                                            | named v178 =>
                                              cases v178 with
                                              | atom v179 =>
                                                cases v177 with
                                                | unit =>
                                                  rfl
                                      | right v174 =>
                                        cases v174
                      | right v159 =>
                        cases v159
      | right v129 =>
        cases v129 with
        | left v180 =>
          cases v180 with
          | named v182 =>
            cases v182 with
            | product v183 v184 =>
              cases v183 with
              | named v185 =>
                cases v185 with
                | atom v186 =>
                  cases v184 with
                  | unit =>
                    cases incoming0 with
                    | named v187 =>
                      cases v187 with
                      | left v188 =>
                        cases v188 with
                        | named v190 =>
                          cases v190 with
                          | product v191 v192 =>
                            cases v191 with
                            | named v193 =>
                              cases v193 with
                              | atom v194 =>
                                cases v192 with
                                | unit =>
                                  cases incoming1 with
                                  | named v195 =>
                                    cases v195 with
                                    | left v196 =>
                                      cases v196 with
                                      | named v198 =>
                                        cases v198 with
                                        | product v199 v200 =>
                                          cases v199 with
                                          | named v201 =>
                                            cases v201 with
                                            | atom v202 =>
                                              cases v200 with
                                              | unit =>
                                                rfl
                                    | right v197 =>
                                      cases v197 with
                                      | left v203 =>
                                        cases v203 with
                                        | named v205 =>
                                          cases v205 with
                                          | product v206 v207 =>
                                            cases v206 with
                                            | named v208 =>
                                              cases v208 with
                                              | atom v209 =>
                                                cases v207 with
                                                | unit =>
                                                  rfl
                                      | right v204 =>
                                        cases v204
                      | right v189 =>
                        cases v189 with
                        | left v210 =>
                          cases v210 with
                          | named v212 =>
                            cases v212 with
                            | product v213 v214 =>
                              cases v213 with
                              | named v215 =>
                                cases v215 with
                                | atom v216 =>
                                  cases v214 with
                                  | unit =>
                                    cases incoming1 with
                                    | named v217 =>
                                      cases v217 with
                                      | left v218 =>
                                        cases v218 with
                                        | named v220 =>
                                          cases v220 with
                                          | product v221 v222 =>
                                            cases v221 with
                                            | named v223 =>
                                              cases v223 with
                                              | atom v224 =>
                                                cases v222 with
                                                | unit =>
                                                  rfl
                                      | right v219 =>
                                        cases v219 with
                                        | left v225 =>
                                          cases v225 with
                                          | named v227 =>
                                            cases v227 with
                                            | product v228 v229 =>
                                              cases v228 with
                                              | named v230 =>
                                                cases v230 with
                                                | atom v231 =>
                                                  cases v229 with
                                                  | unit =>
                                                    rfl
                                        | right v226 =>
                                          cases v226
                        | right v211 =>
                          cases v211
        | right v181 =>
          cases v181
structure Captured (Atom : Ty → Type u) where
  value : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) outputShape
  backwards : Dynamic Atom
def capture (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) : Option (Captured Atom) := do
  let prepared ← Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1
  let backwards ← build Atom prepared.current0 prepared.current1
  pure { value := prepared.value, backwards }
theorem capture_keeps_prepared_value (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) :
    (capture Atom input0 input1).map Captured.value = (Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1).map Auths.Qualification.NativeCurrentSeeds.Prepared.value := by
  unfold capture
  cases prepared : Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1 with
  | none => simp [prepared]
  | some value =>
    obtain ⟨functions, found⟩ := build_produces_bundle Atom value.current0 value.current1
    simp [prepared, found]
theorem capture_keeps_original_source_value (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) :
    (capture Atom input0 input1).map Captured.value = some (construct (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0 input1) := by
  rw [capture_keeps_prepared_value]
  exact Auths.Qualification.NativeCurrentSeeds.prepared_value_is_original_source_capture Atom input0 input1
def branch0FromCapture (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← capture Atom input0 input1
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured.backwards 0 [pack fuel incoming0]
theorem branch0_captures_its_own_forward_current (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch0Channel0Layout) :
    branch0FromCapture Atom input0 input1 incoming0 = Auths.Qualification.NativeCurrentSeeds.branch0FromForward Atom input0 input1 incoming0 := by
  unfold branch0FromCapture capture Auths.Qualification.NativeCurrentSeeds.branch0FromForward
  cases prepared : Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1 with
  | none => simp [prepared]
  | some value =>
    simp only [prepared, Option.bind_some]
    simpa [branch0Invoke, Option.bind_assoc] using branch0_lexical_closure_matches_state_program Atom value.current0 value.current1 incoming0
def branch1FromCapture (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← capture Atom input0 input1
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured.backwards 1 [pack fuel incoming0]
theorem branch1_captures_its_own_forward_current (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch1Channel0Layout) :
    branch1FromCapture Atom input0 input1 incoming0 = Auths.Qualification.NativeCurrentSeeds.branch1FromForward Atom input0 input1 incoming0 := by
  unfold branch1FromCapture capture Auths.Qualification.NativeCurrentSeeds.branch1FromForward
  cases prepared : Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1 with
  | none => simp [prepared]
  | some value =>
    simp only [prepared, Option.bind_some]
    simpa [branch1Invoke, Option.bind_assoc] using branch1_lexical_closure_matches_state_program Atom value.current0 value.current1 incoming0
def branch2FromCapture (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) : Option (Dynamic Atom) := do
  let captured ← capture Atom input0 input1
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured.backwards 2 [pack fuel incoming0]
theorem branch2_captures_its_own_forward_current (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch2Channel0Layout) :
    branch2FromCapture Atom input0 input1 incoming0 = Auths.Qualification.NativeCurrentSeeds.branch2FromForward Atom input0 input1 incoming0 := by
  unfold branch2FromCapture capture Auths.Qualification.NativeCurrentSeeds.branch2FromForward
  cases prepared : Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1 with
  | none => simp [prepared]
  | some value =>
    simp only [prepared, Option.bind_some]
    simpa [branch2Invoke, Option.bind_assoc] using branch2_lexical_closure_matches_state_program Atom value.current0 value.current1 incoming0
def branch3FromCapture (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) : Option (Dynamic Atom) := do
  let captured ← capture Atom input0 input1
  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured.backwards 3 [pack fuel incoming0, pack fuel incoming1]
theorem branch3_captures_its_own_forward_current (Atom : Ty → Type u) (input0 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input0Shape) (input1 : Data (SourceAtom Auths.Qualification.NativePurePayload.atomTyping Atom) input1Shape) (incoming0 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel0Layout) (incoming1 : Value Atom Auths.Qualification.NativePurePayload.branch3Channel1Layout) :
    branch3FromCapture Atom input0 input1 incoming0 incoming1 = Auths.Qualification.NativeCurrentSeeds.branch3FromForward Atom input0 input1 incoming0 incoming1 := by
  unfold branch3FromCapture capture Auths.Qualification.NativeCurrentSeeds.branch3FromForward
  cases prepared : Auths.Qualification.NativeCurrentSeeds.prepare Atom input0 input1 with
  | none => simp [prepared]
  | some value =>
    simp only [prepared, Option.bind_some]
    simpa [branch3Invoke, Option.bind_assoc] using branch3_lexical_closure_matches_state_program Atom value.current0 value.current1 incoming0 incoming1
end Auths.Qualification.NativeCaptureClosures
