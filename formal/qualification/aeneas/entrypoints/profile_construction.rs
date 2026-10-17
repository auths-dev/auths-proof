//! Extraction selection only. The constructor's body remains the shipping
//! `auths-connections` implementation, translated transparently by Charon.

/// Selects the actual inherent constructor without duplicating its checks.
pub fn construct(
    id: auths_connections::SemanticId,
    version: u16,
) -> Result<auths_connections::ConnectionProfile, auths_connections::ConnectionRecordError> {
    auths_connections::ConnectionProfile::new(id, version)
}

/// Selects the actual provider constructor with String's identity conversion.
pub fn parse_provider(
    value: String,
) -> Result<auths_connections::ProviderKind, auths_connections::ConnectionRecordError> {
    auths_connections::ProviderKind::parse(value)
}

/// Selects the actual alias constructor with String's identity conversion.
pub fn parse_alias(
    value: String,
) -> Result<auths_connections::ConnectionAlias, auths_connections::ConnectionRecordError> {
    auths_connections::ConnectionAlias::parse(value)
}

/// Selects the actual semantic-ID constructor with String's identity conversion.
pub fn parse_semantic(
    value: String,
) -> Result<auths_connections::SemanticId, auths_connections::ConnectionRecordError> {
    auths_connections::SemanticId::parse(value)
}
