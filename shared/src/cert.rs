use std::path::Path;

use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};

/// Generates a certificate with the given common name and key usages.
pub fn generate_certificate(
    common_name: &str,
    is_ca: IsCa,
    key_usages: Vec<KeyUsagePurpose>,
) -> anyhow::Result<(Certificate, KeyPair)> {
    tracing::info!("Crafting certificate: {common_name}");

    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, common_name);
    distinguished_name.push(DnType::OrganizationName, "Talus Foundation");

    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.is_ca = is_ca;
    params.key_usages = key_usages;

    // Set validity (10 years for CA)
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(365 * 10);

    // Generate with a 4096-bit key for the certificate
    // TODO: get key pair secret from args
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((cert, key_pair))
}

/// Saves a certificate and its key pair.
pub fn save_cert(
    outdir: &Path,
    name: &str,
    cert: Certificate,
    key_pair: KeyPair,
) -> Result<(), anyhow::Error> {
    let pem_serialized = cert.pem();

    tracing::debug!("{pem_serialized}");
    tracing::debug!("{}", key_pair.serialize_pem());

    std::fs::create_dir_all(outdir)?;

    let path = outdir.join(format!("{name}.crt"));
    tracing::info!("Saving certificate to {}", path.to_string_lossy());
    std::fs::write(path, pem_serialized.as_bytes())?;

    let path = outdir.join(format!("{name}.key"));
    tracing::info!("Saving key pair to {}", path.to_string_lossy());
    std::fs::write(path, key_pair.serialize_pem().as_bytes())?;

    Ok(())
}
