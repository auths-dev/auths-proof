use crate::*;

const OUTPUTS: [&str; 3] = [
    "product/profiles/auths-profile-mcp/profile-v1.json",
    "bindings/typescript/src/generated/mcp-profile.ts",
    "bindings/python/python/auths/_mcp_profile.py",
];

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct McpSessionContract {
    schema: &'static str,
    profile: &'static str,
    profile_version: u16,
    semantic_subject: &'static str,
    limits: auths_profile_mcp::McpProfileLimitsV1,
    steps: &'static [&'static str],
    handler_effects: &'static [&'static str],
    error_codes: Vec<&'static str>,
}

pub(crate) fn mcp_session_contract(update: bool) -> Result<(), String> {
    let contract = McpSessionContract {
        schema: "auths.mcp-session-contract/1",
        profile: auths_profile_mcp::PROFILE_ID,
        profile_version: auths_profile_mcp::PROFILE_VERSION,
        semantic_subject: auths_profile_mcp::MCP_SESSION_SEMANTIC_SUBJECT,
        limits: auths_profile_mcp::mcp_profile_limits_v1(),
        steps: &[
            "reserve",
            "mark-provider-entry",
            "invoke",
            "persist-receipt",
            "reconcile",
        ],
        handler_effects: &["not-applied", "applied", "possible"],
        error_codes: auths_errors::registry()
            .filter(|definition| definition.owner == "mcp")
            .map(|definition| definition.code)
            .collect(),
    };
    let mut json = serde_json::to_vec_pretty(&contract)
        .map_err(|error| format!("could not encode MCP session contract: {error}"))?;
    json.push(b'\n');
    let source = String::from_utf8_lossy(&json);
    let outputs = [
        json.clone(),
        format!(
            "export const MCP_PROFILE = {} as const;\n",
            source.trim_end()
        )
        .into_bytes(),
        format!(
            "from __future__ import annotations\n\nimport json\nfrom typing import Any, Final\n\nMCP_PROFILE: Final[dict[str, Any]] = json.loads(r\"\"\"{source}\"\"\")\n"
        )
        .into_bytes(),
    ];
    for (path, bytes) in OUTPUTS.iter().zip(outputs) {
        let path = root().join(path);
        if update {
            fs::create_dir_all(path.parent().ok_or("MCP contract output has no parent")?)
                .map_err(|error| format!("could not create {}: {error}", path.display()))?;
            fs::write(&path, bytes)
                .map_err(|error| format!("could not update {}: {error}", path.display()))?;
        } else {
            let committed = fs::read(&path).map_err(|error| {
                format!(
                    "could not read {}: {error}; run `cargo xtask mcp-session-contract --update`",
                    path.display()
                )
            })?;
            if committed != bytes {
                return Err(format!(
                    "MCP session contract drifted: {}; run `cargo xtask mcp-session-contract --update`",
                    path.display()
                ));
            }
        }
    }
    if update {
        println!("MCP session contract projections updated");
    } else {
        println!(
            "MCP session contract passed ({} stable errors)",
            contract.error_codes.len()
        );
    }
    Ok(())
}
