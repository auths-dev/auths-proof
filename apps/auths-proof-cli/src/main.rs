#![forbid(unsafe_code)]

use auths_proof_adapter_api::{AdapterRegistry, PrincipalControlVerifier};
use auths_proof_author::{ActionBuilder, GrantBuilder, ProofBundleBuilder};
use auths_proof_codec::{
    body_digest, decode_action_signing_input, decode_bundle, decode_grant_signing_input,
    decode_principal_evidence, decode_signed_action, decode_signed_grant,
    encode_action_signing_input, encode_bundle, encode_grant_signing_input,
    encode_principal_evidence, encode_signed_action, encode_signed_grant, DecodeLimits,
};
use auths_proof_did_keri::DidKeriAdapter;
use auths_proof_did_key::DidKeyAdapter;
use auths_proof_did_web::{DidWebAdapter, DidWebTrustRecord};
use auths_proof_did_web_http::{DidWebHttpResolver, ResolverPolicy};
use auths_proof_model::{
    AlgorithmId, AssuranceClaim, AssuranceClaims, AssuranceRequirements, Audience, AuthorityScope,
    CapabilityId, Challenge, Decision, DelegationDepth, GrantId, Permission, PermissionSet,
    PrincipalRef, ResourceId, SignatureBytes, SignatureDescriptor, SignatureEnvelope, SignedAction,
    SignedGrant, Timestamp, TrustAnchor, ValidityWindow, VerificationMethodRef, VerificationPolicy,
};
use auths_proof_raw_key::{KeyDescriptor, RawKeyAdapter, RawKeyType};
use auths_proof_verifier::{verify, VerificationContext};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "auths-proof",
    version,
    about = "Proof-carrying authorization verifier and authoring utility"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Verify(VerifyArgs),
    Inspect(InspectArgs),
    RawEvidence(RawEvidenceArgs),
    GrantRequest(GrantRequestArgs),
    GrantAttach(AttachArgs),
    ActionRequest(ActionRequestArgs),
    ActionAttach(AttachArgs),
    Bundle(BundleArgs),
    DidWebResolve(DidWebResolveArgs),
}

#[derive(Args)]
struct VerifyArgs {
    #[arg(long)]
    proof: PathBuf,
    #[arg(long)]
    body: PathBuf,
    #[arg(long)]
    now: u64,
    #[arg(long)]
    audience: String,
    #[arg(long)]
    challenge_hex: String,
    #[arg(long)]
    anchor_principal: String,
    #[arg(long)]
    anchor_capability: String,
    #[arg(long)]
    anchor_resource: String,
    #[arg(long)]
    anchor_valid_from: u64,
    #[arg(long)]
    anchor_valid_until: u64,
    #[arg(long, default_value_t = 1)]
    anchor_depth: u8,
    #[arg(long, value_enum, default_value_t = PolicyProfile::LiveAction)]
    profile: PolicyProfile,
    #[arg(long)]
    json: bool,
    #[arg(long = "did-web-trust")]
    did_web_trust: Vec<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum PolicyProfile {
    LiveAction,
    OfflineAudit,
}

#[derive(Args)]
struct InspectArgs {
    #[arg(long)]
    proof: PathBuf,
}

#[derive(Clone, Copy, ValueEnum)]
enum RawKeyKind {
    Ed25519,
    P256,
}

#[derive(Args)]
struct RawEvidenceArgs {
    #[arg(long, value_enum)]
    key_type: RawKeyKind,
    #[arg(long)]
    public_key_hex: String,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct GrantRequestArgs {
    #[arg(long)]
    issuer: String,
    #[arg(long)]
    subject: String,
    #[arg(long)]
    capability: String,
    #[arg(long)]
    resource: String,
    #[arg(long)]
    issued_at: u64,
    #[arg(long)]
    valid_from: u64,
    #[arg(long)]
    valid_until: u64,
    #[arg(long)]
    remaining_depth: u8,
    #[arg(long)]
    adapter: String,
    #[arg(long)]
    verification_method: String,
    #[arg(long)]
    algorithm: String,
    #[arg(long)]
    parent_grant_hex: Option<String>,
    #[arg(long)]
    request_out: PathBuf,
    #[arg(long)]
    signing_bytes_out: PathBuf,
}

#[derive(Args)]
struct ActionRequestArgs {
    #[arg(long)]
    actor: String,
    #[arg(long)]
    capability: String,
    #[arg(long)]
    resource: String,
    #[arg(long)]
    body: PathBuf,
    #[arg(long)]
    audience: String,
    #[arg(long)]
    issued_at: u64,
    #[arg(long)]
    expires_at: u64,
    #[arg(long)]
    challenge_hex: String,
    #[arg(long)]
    adapter: String,
    #[arg(long)]
    verification_method: String,
    #[arg(long)]
    algorithm: String,
    #[arg(long)]
    request_out: PathBuf,
    #[arg(long)]
    signing_bytes_out: PathBuf,
}

#[derive(Args)]
struct AttachArgs {
    #[arg(long)]
    request: PathBuf,
    #[arg(long)]
    signature: PathBuf,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct BundleArgs {
    #[arg(long)]
    action: PathBuf,
    #[arg(long)]
    action_evidence: PathBuf,
    #[arg(long = "grant")]
    grants: Vec<PathBuf>,
    #[arg(long = "grant-evidence")]
    grant_evidence: Vec<PathBuf>,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct DidWebResolveArgs {
    #[arg(long)]
    did: String,
    #[arg(long = "allow-host", required = true)]
    allowed_hosts: Vec<String>,
    #[arg(long)]
    observed_at: u64,
    #[arg(long)]
    valid_until: u64,
    #[arg(long, default_value_t = 10)]
    timeout_seconds: u64,
    #[arg(long, default_value_t = 131_072)]
    max_bytes: usize,
    #[arg(long)]
    evidence_out: PathBuf,
    #[arg(long)]
    trust_out: PathBuf,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Command::Verify(args) => verify_command(args),
        Command::Inspect(args) => inspect_command(args),
        Command::RawEvidence(args) => raw_evidence_command(args),
        Command::GrantRequest(args) => grant_request_command(args),
        Command::GrantAttach(args) => grant_attach_command(args),
        Command::ActionRequest(args) => action_request_command(args),
        Command::ActionAttach(args) => action_attach_command(args),
        Command::Bundle(args) => bundle_command(args),
        Command::DidWebResolve(args) => did_web_resolve_command(args),
    }
}

fn verify_command(args: VerifyArgs) -> Result<ExitCode, String> {
    let encoded = read(&args.proof)?;
    let body = read(&args.body)?;
    let audience = Audience::parse(&args.audience).map_err(display)?;
    let challenge = Challenge::new(parse_hex_32(&args.challenge_hex)?);
    let permission = permission(&args.anchor_capability, &args.anchor_resource)?;
    let anchor = TrustAnchor::new(
        PrincipalRef::parse(&args.anchor_principal).map_err(display)?,
        AuthorityScope::new(PermissionSet::new(vec![permission]).map_err(display)?),
        ValidityWindow::new(
            Timestamp::new(args.anchor_valid_from),
            Timestamp::new(args.anchor_valid_until),
        )
        .map_err(display)?,
        DelegationDepth::new(args.anchor_depth),
        AssuranceRequirements::new(
            AssuranceClaims::new(vec![
                AssuranceClaim::SelfCertifyingIdentifier,
                AssuranceClaim::OfflineVerifiable,
            ]),
            None,
            true,
            true,
        ),
    );
    let policy = match args.profile {
        PolicyProfile::LiveAction => VerificationPolicy::live_action(),
        PolicyProfile::OfflineAudit => VerificationPolicy::offline_audit(),
    };
    let raw_key = RawKeyAdapter::new().map_err(display)?;
    let did_keri = DidKeriAdapter::new().map_err(display)?;
    let did_key = DidKeyAdapter::new().map_err(display)?;
    let trust = args
        .did_web_trust
        .iter()
        .map(|path| DidWebTrustRecord::decode(&read(path)?).map_err(display))
        .collect::<Result<Vec<_>, _>>()?;
    let did_web = DidWebAdapter::new(trust).map_err(display)?;
    let mut principal_adapters: Vec<&dyn PrincipalControlVerifier> =
        vec![&raw_key, &did_keri, &did_key];
    if !args.did_web_trust.is_empty() {
        principal_adapters.push(&did_web);
    }
    let registry = AdapterRegistry::new(&principal_adapters, &[]);
    let verdict = verify(
        &encoded,
        &VerificationContext {
            now: Timestamp::new(args.now),
            expected_audience: &audience,
            expected_challenge: &challenge,
            action_body: &body,
            trust_anchors: core::slice::from_ref(&anchor),
            policy: &policy,
            decode_limits: DecodeLimits::standard(),
        },
        &registry,
    );

    if args.json {
        let reason = verdict
            .reasons()
            .first()
            .map(|reason| format!("{reason:?}"));
        println!(
            "{{\"decision\":\"{:?}\",\"reason\":{},\"root\":{},\"actor\":{},\"grants\":{}}}",
            verdict.decision(),
            json_option(reason.as_deref()),
            json_option(verdict.root().map(PrincipalRef::as_str)),
            json_option(verdict.actor().map(PrincipalRef::as_str)),
            verdict.grant_count()
        );
    } else {
        println!("{:?}", verdict.decision());
        if let Some(reason) = verdict.reasons().first() {
            println!("reason  {reason:?}");
        }
        if let Some(root) = verdict.root() {
            println!("root    {root}");
        }
        if let Some(actor) = verdict.actor() {
            println!("actor   {actor}");
        }
        println!("grants  {}", verdict.grant_count());
        for limitation in verdict.limitations() {
            println!("limit   {limitation:?}");
        }
    }

    Ok(match verdict.decision() {
        Decision::Authorized => ExitCode::SUCCESS,
        Decision::Denied => ExitCode::from(2),
        Decision::Indeterminate => ExitCode::from(3),
    })
}

fn inspect_command(args: InspectArgs) -> Result<ExitCode, String> {
    let encoded = read(&args.proof)?;
    let bundle = decode_bundle(&encoded, DecodeLimits::standard()).map_err(display)?;
    println!("version   {}", bundle.version().get());
    println!(
        "root      {}",
        bundle
            .grants()
            .first()
            .map(|grant| grant.payload().issuer())
            .unwrap_or_else(|| bundle.action().payload().actor())
    );
    println!("actor     {}", bundle.action().payload().actor());
    println!(
        "permission {} {}",
        bundle.action().payload().permission().capability(),
        bundle.action().payload().permission().resource()
    );
    println!("audience  {}", bundle.action().payload().audience());
    println!("grants    {}", bundle.grants().len());
    println!("evidence  {}", bundle.principal_evidence().len());
    Ok(ExitCode::SUCCESS)
}

fn raw_evidence_command(args: RawEvidenceArgs) -> Result<ExitCode, String> {
    let bytes = hex::decode(&args.public_key_hex).map_err(display)?;
    let key_type = match args.key_type {
        RawKeyKind::Ed25519 => RawKeyType::Ed25519,
        RawKeyKind::P256 => RawKeyType::P256,
    };
    let descriptor = KeyDescriptor::new(key_type, bytes).map_err(display)?;
    let evidence = descriptor.evidence_entry().map_err(display)?;
    write(&args.out, &encode_principal_evidence(&evidence))?;
    println!("{}", descriptor.principal().map_err(display)?);
    Ok(ExitCode::SUCCESS)
}

fn grant_request_command(args: GrantRequestArgs) -> Result<ExitCode, String> {
    let descriptor =
        signature_descriptor(&args.adapter, &args.verification_method, &args.algorithm)?;
    let mut builder = GrantBuilder::new(
        PrincipalRef::parse(&args.issuer).map_err(display)?,
        PrincipalRef::parse(&args.subject).map_err(display)?,
        descriptor,
    )
    .permission(permission(&args.capability, &args.resource)?)
    .issued_at(Timestamp::new(args.issued_at))
    .valid_between(
        Timestamp::new(args.valid_from),
        Timestamp::new(args.valid_until),
    )
    .map_err(display)?
    .delegation_depth(DelegationDepth::new(args.remaining_depth))
    .expiry_only();
    if let Some(parent) = args.parent_grant_hex {
        builder = builder.parent(GrantId::new(parse_hex_32(&parent)?));
    }
    let draft = builder.build().map_err(display)?;
    let request = draft.signing_request();
    write(
        &args.request_out,
        &encode_grant_signing_input(request.payload(), request.descriptor()),
    )?;
    write(&args.signing_bytes_out, request.bytes())?;
    Ok(ExitCode::SUCCESS)
}

fn grant_attach_command(args: AttachArgs) -> Result<ExitCode, String> {
    let (payload, descriptor) =
        decode_grant_signing_input(&read(&args.request)?).map_err(display)?;
    let signature = SignatureEnvelope::new(
        descriptor,
        SignatureBytes::new(read(&args.signature)?).map_err(display)?,
    );
    write(
        &args.out,
        &encode_signed_grant(&SignedGrant::new(payload, signature)),
    )?;
    Ok(ExitCode::SUCCESS)
}

fn action_request_command(args: ActionRequestArgs) -> Result<ExitCode, String> {
    let body = read(&args.body)?;
    let draft = ActionBuilder::new(
        PrincipalRef::parse(&args.actor).map_err(display)?,
        signature_descriptor(&args.adapter, &args.verification_method, &args.algorithm)?,
        permission(&args.capability, &args.resource)?,
        body_digest(&body),
        Audience::parse(&args.audience).map_err(display)?,
        Timestamp::new(args.issued_at),
        Timestamp::new(args.expires_at),
        Challenge::new(parse_hex_32(&args.challenge_hex)?),
    )
    .build()
    .map_err(display)?;
    let request = draft.signing_request();
    write(
        &args.request_out,
        &encode_action_signing_input(request.payload(), request.descriptor()),
    )?;
    write(&args.signing_bytes_out, request.bytes())?;
    Ok(ExitCode::SUCCESS)
}

fn action_attach_command(args: AttachArgs) -> Result<ExitCode, String> {
    let (payload, descriptor) =
        decode_action_signing_input(&read(&args.request)?).map_err(display)?;
    let signature = SignatureEnvelope::new(
        descriptor,
        SignatureBytes::new(read(&args.signature)?).map_err(display)?,
    );
    write(
        &args.out,
        &encode_signed_action(&SignedAction::new(payload, signature)),
    )?;
    Ok(ExitCode::SUCCESS)
}

fn bundle_command(args: BundleArgs) -> Result<ExitCode, String> {
    if args.grants.len() != args.grant_evidence.len() {
        return Err("--grant and --grant-evidence counts must match".into());
    }
    let action = decode_signed_action(&read(&args.action)?).map_err(display)?;
    let action_evidence =
        decode_principal_evidence(&read(&args.action_evidence)?, 1024 * 1024).map_err(display)?;
    let mut builder = ProofBundleBuilder::new(action, action_evidence).map_err(display)?;
    for (grant_path, evidence_path) in args.grants.iter().zip(args.grant_evidence.iter()) {
        let grant = decode_signed_grant(&read(grant_path)?).map_err(display)?;
        let evidence =
            decode_principal_evidence(&read(evidence_path)?, 1024 * 1024).map_err(display)?;
        builder = builder.push_grant(grant, evidence).map_err(display)?;
    }
    let bundle = builder.build().map_err(display)?;
    write(&args.out, &encode_bundle(&bundle).map_err(display)?)?;
    Ok(ExitCode::SUCCESS)
}

fn did_web_resolve_command(args: DidWebResolveArgs) -> Result<ExitCode, String> {
    let policy = ResolverPolicy::new(args.allowed_hosts)
        .map_err(display)?
        .with_timeout(std::time::Duration::from_secs(args.timeout_seconds))
        .map_err(display)?
        .with_max_response_bytes(args.max_bytes)
        .map_err(display)?;
    let resolved = DidWebHttpResolver::new(policy)
        .resolve_current(
            &args.did,
            Timestamp::new(args.observed_at),
            Timestamp::new(args.valid_until),
        )
        .map_err(display)?;
    write(
        &args.evidence_out,
        &encode_principal_evidence(&resolved.evidence_entry),
    )?;
    write(&args.trust_out, &resolved.trust.encode().map_err(display)?)?;
    println!("resolved {}", args.did);
    println!("evidence {}", args.evidence_out.display());
    println!("trust    {}", args.trust_out.display());
    Ok(ExitCode::SUCCESS)
}

fn permission(capability: &str, resource: &str) -> Result<Permission, String> {
    Ok(Permission::new(
        CapabilityId::parse(capability).map_err(display)?,
        ResourceId::parse(resource).map_err(display)?,
    ))
}

fn signature_descriptor(
    adapter: &str,
    verification_method: &str,
    algorithm: &str,
) -> Result<SignatureDescriptor, String> {
    Ok(SignatureDescriptor::new(
        auths_proof_model::AdapterId::parse(adapter).map_err(display)?,
        VerificationMethodRef::parse(verification_method).map_err(display)?,
        AlgorithmId::parse(algorithm).map_err(display)?,
    ))
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value).map_err(display)?;
    bytes
        .try_into()
        .map_err(|_| "expected exactly 32 bytes of hexadecimal data".into())
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::write(path, bytes).map_err(|error| format!("could not write {}: {error}", path.display()))
}

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn json_option(value: Option<&str>) -> String {
    match value {
        Some(value) => format!("\"{}\"", json_escape(value)),
        None => "null".into(),
    }
}

fn json_escape(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            other => output.push(other),
        }
    }
    output
}
