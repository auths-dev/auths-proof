#![forbid(unsafe_code)]

use auths_apps_testkit::{DemoResult, run_iroh_demo, run_memory_demo};
use auths_proof_exchange_model::ExchangeOutcome;
use clap::{Parser, Subcommand, ValueEnum};
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "auths-mcp-demo")]
#[command(about = "Milestone 4 exact MCP authorization demonstration")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Demo {
        #[arg(long, value_enum, default_value_t = Transport::Memory)]
        transport: Transport,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Transport {
    Memory,
    Iroh,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Demo {
            transport: Transport::Memory,
        } => run_memory_demo().await,
        Command::Demo {
            transport: Transport::Iroh,
        } => run_iroh_demo().await,
    };
    print_result(&result);
    if matches!(result.response.outcome(), ExchangeOutcome::Completed { .. }) {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn print_result(result: &DemoResult) {
    println!("transport              {}", result.path);
    println!("outcome                {:?}", result.response.outcome());
    println!("proof_bytes            {}", result.proof_bytes);
    println!("total_micros           {}", result.total_micros);
    println!(
        "verification_micros    {}",
        result.response.metrics().verification_micros()
    );
    println!(
        "execution_micros       {}",
        result.response.metrics().execution_micros()
    );
    if let Some(request_id) = result.response.request_id() {
        println!("request_id             {}", hex::encode(request_id));
    }
}
