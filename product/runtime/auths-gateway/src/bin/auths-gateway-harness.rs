//! Test harness process: the gateway's application socket over the counting
//! provider, for packed SDK consumers. Test trust only; never a gateway.
//!
//! Usage: `auths-gateway-harness --state-dir <empty dir> --agent <principal>
//! --now <unix seconds>`. It prints one JSON line of setup facts once both
//! sockets accept connections, then serves until killed.

#[cfg(not(unix))]
fn main() {
    eprintln!("auths-gateway-harness requires Unix sockets");
    std::process::exit(2);
}

#[cfg(unix)]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    use clap::Parser;
    use std::io::Write as _;
    use std::path::PathBuf;

    #[derive(Parser)]
    #[command(
        name = "auths-gateway-harness",
        about = "Counting-provider gateway test harness"
    )]
    struct Cli {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long)]
        agent: String,
        #[arg(long)]
        now: u64,
    }

    let cli = Cli::parse();
    let (setup, running) =
        match auths_gateway::harness::serve(&cli.state_dir, &cli.agent, cli.now).await {
            Ok(value) => value,
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        };
    let Ok(line) = serde_json::to_string(&setup) else {
        eprintln!("harness setup could not be encoded");
        std::process::exit(1);
    };
    let mut stdout = std::io::stdout();
    if writeln!(stdout, "{line}")
        .and_then(|()| stdout.flush())
        .is_err()
    {
        std::process::exit(1);
    }
    if let Err(error) = running.await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
