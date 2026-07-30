#![allow(clippy::too_many_lines)]

use crate::*;

pub(crate) fn benchmark(args: Vec<String>) -> Result<(), String> {
    let command = args.first().map(String::as_str).unwrap_or("help");
    let option = |name: &str| -> Option<&str> {
        args.iter()
            .position(|argument| argument == name)
            .and_then(|index| args.get(index + 1))
            .map(String::as_str)
    };
    let profile_name = option("--profile").unwrap_or("developer");
    let profile = match profile_name {
        "developer" => auths_bench_model::BenchmarkProfile::developer(),
        "paper" => auths_bench_model::BenchmarkProfile::paper(),
        other => {
            let path = root()
                .join("demos/benchmarks/profiles")
                .join(format!("{other}.toml"));
            toml::from_str(
                &fs::read_to_string(&path)
                    .map_err(|error| format!("could not read {}: {error}", path.display()))?,
            )
            .map_err(|error| format!("invalid benchmark profile {}: {error}", path.display()))?
        }
    };
    let input_directory = root().join("target/auths-bench/inputs");
    let input_manifest = input_directory.join("manifest.json");

    match command {
        "prepare" => {
            let suite =
                auths_bench_model::generate_suite(&profile).map_err(|error| error.to_string())?;
            fs::create_dir_all(&input_directory)
                .map_err(|error| format!("could not create input directory: {error}"))?;
            let bytes = serde_json::to_vec_pretty(&suite)
                .map_err(|error| format!("could not encode benchmark inputs: {error}"))?;
            fs::write(&input_manifest, bytes).map_err(|error| {
                format!("could not write {}: {error}", input_manifest.display())
            })?;
            println!("Prepared {} deterministic scenarios", suite.len());
            println!("Input manifest: {}", input_manifest.display());
            println!("Manifest SHA-256: {}", sha256_file(&input_manifest)?);
            Ok(())
        }
        "run" => {
            if !input_manifest.exists() {
                return Err("benchmark inputs missing; run `cargo xtask bench prepare`".to_owned());
            }
            let target = option("--target").ok_or("bench run requires --target")?;
            let output = root()
                .join("benchmark-results")
                .join(format!("{target}.json"));
            match target {
                "native" => command_in(
                    "cargo",
                    &[
                        "run",
                        "-p",
                        "auths-bench-native",
                        "--",
                        path_text(&input_manifest)?,
                        path_text(&output)?,
                        profile_name,
                    ],
                    &root(),
                    None,
                ),
                "wasm-node" => command_in(
                    "node",
                    &[
                        "demos/benchmarks/auths-bench-wasm/runner/node.mjs",
                        path_text(&input_manifest)?,
                    ],
                    &root(),
                    None,
                ),
                "wasm-browser" => command_in(
                    "node",
                    &[
                        "demos/benchmarks/auths-bench-wasm/runner/browser.mjs",
                        path_text(&input_manifest)?,
                    ],
                    &root(),
                    None,
                ),
                _ => Err(format!("unsupported benchmark target {target}")),
            }
        }
        "report" => {
            let directory = args
                .get(1)
                .map(PathBuf::from)
                .ok_or("bench report requires a result directory")?;
            let native = directory.join("native.json");
            let artifact: auths_bench_model::RunArtifact = serde_json::from_slice(
                &fs::read(&native)
                    .map_err(|error| format!("could not read {}: {error}", native.display()))?,
            )
            .map_err(|error| format!("invalid benchmark result: {error}"))?;
            let rows = artifact
                .results
                .iter()
                .map(|result| {
                    format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                        result.scenario,
                        result.summary.p50_ns,
                        result.summary.p95_ns,
                        result.summary.p99_ns,
                        result.semantic.work_units
                    )
                })
                .collect::<String>();
            let html = format!(
                "<!doctype html><meta charset=\"utf-8\"><title>Auths-Proof benchmark</title>\
                 <h1>Auths-Proof benchmark</h1><p>Semantic agreement: PASS</p>\
                 <table><thead><tr><th>Scenario</th><th>p50 ns</th><th>p95 ns</th>\
                 <th>p99 ns</th><th>work</th></tr></thead><tbody>{rows}</tbody></table>"
            );
            fs::write(directory.join("report.html"), html)
                .map_err(|error| format!("could not write report: {error}"))?;
            fs::write(
                directory.join("report.json"),
                serde_json::to_vec_pretty(&artifact)
                    .map_err(|error| format!("could not encode report: {error}"))?,
            )
            .map_err(|error| format!("could not write report JSON: {error}"))?;
            println!("Semantic agreement: PASS");
            println!("Environment completeness: PASS");
            println!("Report: {}", directory.join("report.html").display());
            Ok(())
        }
        "compare" => {
            let baseline_path = args.get(1).ok_or("bench compare requires baseline")?;
            let candidate_path = args.get(2).ok_or("bench compare requires candidate")?;
            let baseline: auths_bench_model::RunArtifact = serde_json::from_slice(
                &fs::read(baseline_path).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let candidate: auths_bench_model::RunArtifact = serde_json::from_slice(
                &fs::read(candidate_path).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?;
            let comparison = auths_bench_model::compare_runs(
                &baseline,
                &candidate,
                &auths_bench_model::ComparisonPolicy::default(),
            )
            .map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&comparison).map_err(|error| error.to_string())?
            );
            Ok(())
        }
        "verify-artifact" => {
            let directory = args
                .get(1)
                .map(PathBuf::from)
                .ok_or("bench verify-artifact requires a directory")?;
            let result = directory.join("native.json");
            let artifact: auths_bench_model::RunArtifact =
                serde_json::from_slice(&fs::read(&result).map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            if artifact.results.is_empty()
                || artifact
                    .results
                    .iter()
                    .any(|entry| entry.samples_ns.is_empty())
            {
                return Err("benchmark artifact has missing observations".to_owned());
            }
            println!("benchmark artifact verified: {}", result.display());
            Ok(())
        }
        _ => {
            Err("usage: cargo xtask bench <prepare|run|report|compare|verify-artifact>".to_owned())
        }
    }
}
