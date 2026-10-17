//! Extraction selection only. The constructor's body remains the shipping
//! `auths-connections` implementation, translated transparently by Charon.

/// Selects the actual inherent constructor without duplicating its checks.
pub fn construct(
    id: auths_connections::SemanticId,
    version: u16,
) -> Result<auths_connections::ConnectionProfile, auths_connections::ConnectionRecordError> {
    auths_connections::ConnectionProfile::new(id, version)
}
