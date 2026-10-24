# The upstream Lean runtime remains pinned and pristine. This derivation patches
# only the OCaml translator, embeds the exact patch digest, and runs its small
# erasure regression executable when the hosted toolchain is built.
{ system ? builtins.currentSystem }:
let
  commit = "3a8586facab25b31bdb1e1f5f45acd60d1cc5ff0";
  upstream = builtins.getFlake "github:AeneasVerif/aeneas/${commit}";
  patch = ./runtime-region-erasure-v1.patch;
  digest = builtins.hashFile "sha256" patch;
in
upstream.packages.${system}.aeneas.overrideAttrs (old: {
  patches = (old.patches or []) ++ [ patch ];
  AENEAS_VERSION = "${commit}-auths-runtime-regions-v1-${digest}";
  postPatch = (old.postPatch or "") + ''
    mkdir auths_tests
    cp ${./tests/dune} auths_tests/dune
    cp ${./tests/runtime_region_erasure_test.ml} auths_tests/runtime_region_erasure_test.ml
  '';
  doCheck = true;
  checkPhase = ''
    runHook preCheck
    dune exec ./auths_tests/runtime_region_erasure_test.exe
    runHook postCheck
  '';
})
