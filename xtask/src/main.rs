#![forbid(unsafe_code)]

mod architecture;
mod benchmark;
mod bounded_benchmark;
mod bounded_domains;
mod checks;
mod compliance;
mod conformance;
mod fixtures;
mod formal;
mod formal_qualification;
mod fuzz;
mod live_demo;
mod prelude;
mod process;
mod public_naming;
mod release;
mod semantic_freeze;
mod stripe;

pub(crate) use architecture::*;
pub(crate) use benchmark::*;
pub(crate) use bounded_benchmark::*;
pub(crate) use bounded_domains::*;
pub(crate) use checks::*;
pub(crate) use compliance::*;
pub(crate) use conformance::*;
pub(crate) use fixtures::*;
pub(crate) use formal::*;
pub(crate) use fuzz::*;
pub(crate) use live_demo::*;
pub(crate) use prelude::*;
pub(crate) use process::*;
pub(crate) use public_naming::*;
pub(crate) use release::*;
pub(crate) use semantic_freeze::*;
pub(crate) use stripe::*;

const USAGE: &str = "usage: cargo xtask <fmt|arch [--update]|semantic-freeze [--update]|public-naming|core-boundary|workspace-msrv|abi|core|exchange|product|bindings|demos|package|wire [--update]|spec-sync|conformance|exchange-conformance|product-conformance|stripe-profiles|bounded-domains|compliance|matrix|cross-language|product-fixtures [--update]|semantic-digest|wasm|live-demo|fuzz-inventory|fuzz-smoke|platform-artifact [output]|formal [--skip-kani] [--update]|formal qualify aeneas [--update]|adversarial-conformance [--surface <name>|--adapter <name>|--case <id>]|bench <prepare|run|report|compare|verify-artifact|bounded>|ci [authoritative|formal-translation|compliance]|release-check>";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    dispatch(env::args().skip(1))
}

fn dispatch(arguments: impl IntoIterator<Item = String>) -> Result<(), String> {
    let mut args = arguments.into_iter();
    let command = args.next().unwrap_or_else(|| "help".into());
    match command.as_str() {
        "ci" => {
            let arguments: Vec<_> = args.collect();
            match arguments.as_slice() {
                [] => ci(),
                [phase] if phase == "authoritative" => ci_authoritative(),
                [phase] if phase == "formal-translation" => ci_formal_translation(),
                [phase] if phase == "compliance" => ci_compliance(),
                _ => Err(format!(
                    "unknown CI phase {}; expected authoritative, formal-translation, or compliance",
                    arguments.join(" ")
                )),
            }
        }
        "arch" => arch(args.any(|arg| arg == "--update")),
        "semantic-freeze" => semantic_freeze(args.any(|arg| arg == "--update")),
        "public-naming" => public_naming(),
        "fmt" => format_all(),
        "core-boundary" => core_boundary(),
        "workspace-msrv" | "core-msrv" => workspace_msrv(),
        "abi" => abi(),
        "core" => layer_check("core"),
        "exchange" => exchange_check(),
        "product" => product_check(),
        "bindings" => bindings_check(),
        "demos" => demos_check(),
        "package" => package_check(),
        "wire" => wire(args.any(|arg| arg == "--update")),
        "spec-sync" => spec_sync(),
        "conformance" => target_conformance(),
        "exchange-conformance" => exchange_conformance(),
        "product-conformance" => product_conformance(),
        "stripe-profiles" => stripe_profiles(),
        "bounded-domains" => bounded_domains(),
        "compliance" => compliance(),
        "matrix" => matrix(),
        "cross-language" => cross_language_corpus(),
        "product-fixtures" => product_fixtures(args.any(|arg| arg == "--update")),
        "semantic-digest" => semantic_digest(),
        "wasm" => wasm(),
        "live-demo" => live_demo(),
        "fuzz-inventory" => fuzz_inventory(),
        "fuzz-smoke" => fuzz_smoke(),
        "formal" => {
            let arguments: Vec<_> = args.collect();
            match arguments.as_slice() {
                [qualify, tool] if qualify == "qualify" && tool == "aeneas" => {
                    formal_qualify_aeneas(false)
                }
                [qualify, tool, update]
                    if qualify == "qualify" && tool == "aeneas" && update == "--update" =>
                {
                    formal_qualify_aeneas(true)
                }
                _ => formal(
                    arguments.iter().any(|arg| arg == "--skip-kani"),
                    arguments.iter().any(|arg| arg == "--update"),
                ),
            }
        }
        "adversarial-conformance" => adversarial_conformance(args.collect()),
        "bench" => benchmark(args.collect()),
        "platform-artifact" => {
            let output = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| root().join("target/release-evidence/platform.json"));
            platform_artifact(&output)
        }
        "release-check" => release_check(),
        _ => {
            println!("{USAGE}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_output_is_stable() {
        assert_eq!(
            USAGE,
            "usage: cargo xtask <fmt|arch [--update]|semantic-freeze [--update]|public-naming|core-boundary|workspace-msrv|abi|core|exchange|product|bindings|demos|package|wire [--update]|spec-sync|conformance|exchange-conformance|product-conformance|stripe-profiles|bounded-domains|compliance|matrix|cross-language|product-fixtures [--update]|semantic-digest|wasm|live-demo|fuzz-inventory|fuzz-smoke|platform-artifact [output]|formal [--skip-kani] [--update]|formal qualify aeneas [--update]|adversarial-conformance [--surface <name>|--adapter <name>|--case <id>]|bench <prepare|run|report|compare|verify-artifact|bounded>|ci [authoritative|formal-translation|compliance]|release-check>"
        );
    }

    #[test]
    fn invalid_ci_phase_preserves_error_contract() {
        let error =
            dispatch(["ci".to_owned(), "unknown".to_owned()]).expect_err("unknown phase must fail");
        assert_eq!(
            error,
            "unknown CI phase unknown; expected authoritative, formal-translation, or compliance"
        );
    }
}
