use auths_node::encode_sandbox_authority_request;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use std::{
    env, fs,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() -> ExitCode {
    let mut arguments = env::args().skip(1);
    let Some(action_path) = arguments.next() else {
        eprintln!("usage: auths-sandbox-request <action-file> [lifetime-seconds]");
        return ExitCode::from(1);
    };
    let lifetime = arguments
        .next()
        .as_deref()
        .unwrap_or("600")
        .parse::<u64>()
        .ok()
        .filter(|value| (1..=86_400).contains(value));
    if arguments.next().is_some() || lifetime.is_none() {
        eprintln!("auths-sandbox-request: invalid arguments");
        return ExitCode::from(1);
    }
    let Ok(action) = fs::read(action_path) else {
        eprintln!("auths-sandbox-request: action is unavailable");
        return ExitCode::from(1);
    };
    if action.is_empty() || action.len() > 1024 * 1024 {
        eprintln!("auths-sandbox-request: action is outside bounds");
        return ExitCode::from(1);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let Some(expires_at) = now.checked_add(lifetime.unwrap()) else {
        eprintln!("auths-sandbox-request: expiry overflow");
        return ExitCode::from(1);
    };
    let Ok(request) = encode_sandbox_authority_request(expires_at, 2, 2, &[&action]) else {
        eprintln!("auths-sandbox-request: request could not be encoded");
        return ExitCode::from(1);
    };
    let Ok(attenuation) = encode_sandbox_authority_request(expires_at, 1, 1, &[&action]) else {
        eprintln!("auths-sandbox-request: attenuation could not be encoded");
        return ExitCode::from(1);
    };
    println!(
        "{{\"request\":\"{}\",\"attenuation\":\"{}\",\"action\":\"{}\"}}",
        Base64UrlUnpadded::encode_string(&request),
        Base64UrlUnpadded::encode_string(&attenuation),
        Base64UrlUnpadded::encode_string(&action)
    );
    ExitCode::SUCCESS
}
