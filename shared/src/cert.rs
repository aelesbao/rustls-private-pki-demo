use std::{fs, io, path::Path};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequest,
    CertificateSigningRequestParams, CertifiedKey, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519, SanType,
};

#[derive(Debug, Clone)]
/// The PEM of an issued certificate, together with the subject key pair.
pub struct PemCertifiedKey {
    pub cert_pem: String,
    pub private_key_pem: String,
}

impl PemCertifiedKey {
    /// Write the PEM certificate and key pair to the filesystem.
    pub fn write(&self, outdir: &Path, name: &str) -> Result<(), io::Error> {
        tracing::info!(
            "Writing PEM certificate and key pair to '{}'",
            outdir.to_string_lossy()
        );

        fs::create_dir_all(outdir)?;

        let path = outdir.join(format!("{name}.crt"));
        tracing::debug!(%self.cert_pem, "Saving certificate to {}", path.to_string_lossy());
        fs::write(path, self.cert_pem.as_bytes())?;

        let path = outdir.join(format!("{name}.key"));
        tracing::debug!(%self.private_key_pem, "Saving key pair to {}", path.to_string_lossy());
        fs::write(path, self.private_key_pem.as_bytes())?;

        Ok(())
    }

    // Loads a PEM certificate and key pair from the file system.
    pub fn read(cert_path: &Path, private_key_path: &Path) -> Result<Self, io::Error> {
        let cert_pem = fs::read_to_string(cert_path)?;
        let private_key_pem = fs::read_to_string(private_key_path)?;

        Ok(Self {
            cert_pem,
            private_key_pem,
        })
    }
}

impl From<&CertifiedKey> for PemCertifiedKey {
    fn from(value: &CertifiedKey) -> Self {
        PemCertifiedKey {
            cert_pem: value.cert.pem(),
            private_key_pem: value.key_pair.serialize_pem(),
        }
    }
}

impl TryFrom<&Csr> for PemCertifiedKey {
    type Error = rcgen::Error;

    fn try_from(value: &Csr) -> Result<Self, rcgen::Error> {
        Ok(PemCertifiedKey {
            cert_pem: value.csr.pem()?,
            private_key_pem: value.key_pair.serialize_pem(),
        })
    }
}

impl TryFrom<PemCertifiedKey> for CertifiedKey {
    type Error = rcgen::Error;

    fn try_from(value: PemCertifiedKey) -> Result<Self, Self::Error> {
        let params = CertificateParams::from_ca_cert_pem(&value.cert_pem)?;
        let key_pair = KeyPair::from_pem(&value.private_key_pem)?;
        let cert = params.self_signed(&key_pair)?;
        Ok(Self { cert, key_pair })
    }
}

/// Builder to configure TLS [CertificateParams] to be finalized into either a CA ([CertifiedKey]) or a CSR ([Csr]).
#[derive(Default)]
pub struct CertificateBuilder {
    params: CertificateParams,
}

impl CertificateBuilder {
    /// Initialize `CertificateParams` with defaults and CommonName (CN).
    pub fn new(common_name: &str) -> Self {
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, common_name);

        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name;

        Self { params }
    }

    /// Set options for `CA` Certificates.
    ///
    /// # Example
    ///
    /// ```
    /// # use shared::CertificateBuilder;
    /// let cert = CertificateBuilder::new("Acme Ltd. CA").certificate_authority();
    /// ```
    pub fn certificate_authority(self) -> CaBuilder {
        CaBuilder::new(self.params)
    }

    /// Set options for Certificate Signing Requests.
    ///
    /// # Example
    ///
    /// ```
    /// # use shared::CertificateBuilder;
    /// let cert = CertificateBuilder::new("example.com").certificate_signing_request();
    /// ```
    pub fn certificate_signing_request(self) -> CsrBuilder {
        CsrBuilder::new(self.params)
    }
}

/// [CertificateParams] from which a [CertifiedKey] `CA` can be built.
pub struct CaBuilder {
    params: CertificateParams,
}

impl CaBuilder {
    /// Initializes the `CaBuilder`.
    pub fn new(mut params: CertificateParams) -> Self {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        Self { params }
    }

    /// Add OrganizationName to `distinguished_name`.
    /// Multiple calls will replace previous value.
    pub fn organization_name(mut self, name: &str) -> Self {
        self.params
            .distinguished_name
            .push(DnType::OrganizationName, name);
        self
    }

    /// Sets the validity period for the certificate.
    pub fn validity(mut self, days: u32) -> Self {
        let now = time::OffsetDateTime::now_utc();
        self.params.not_before = now;
        self.params.not_after = now + time::Duration::days(days as i64);
        self
    }

    /// Builds a new self-signed CA [CertifiedKey].
    pub fn build(self) -> Result<CertifiedKey, rcgen::Error> {
        tracing::debug!("Building and signing Certificate Authority");
        let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;
        let cert = self.params.self_signed(&key_pair)?;
        Ok(CertifiedKey { cert, key_pair })
    }
}

/// [CertificateParams] from which an Certificate Signing Request [Csr] can be built.
pub struct CsrBuilder {
    params: CertificateParams,
}

impl CsrBuilder {
    /// Initializes the `CsrBuilder`.
    pub fn new(mut params: CertificateParams) -> Self {
        params.is_ca = IsCa::NoCa;
        // Set key usage and extended key usage for a client/server certificate
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyEncipherment);
        Self { params }
    }

    /// `SanTypes` that will be recorded as `subject_alt_names`.
    /// Multiple calls will append to previous values.
    pub fn subject_alternative_names(mut self, sans: Vec<SanType>) -> Self {
        self.params.subject_alt_names.extend(sans);
        self
    }

    /// Add ClientAuth to `extended_key_usages` if it is not already present.
    pub fn client_auth(mut self) -> Self {
        let usage = ExtendedKeyUsagePurpose::ClientAuth;
        if !self.params.extended_key_usages.iter().any(|e| e == &usage) {
            self.params.extended_key_usages.push(usage);
        }
        self
    }

    /// Add ServerAuth to `extended_key_usages` if it is not already present.
    pub fn server_auth(mut self) -> Self {
        let usage = ExtendedKeyUsagePurpose::ServerAuth;
        if !self.params.extended_key_usages.iter().any(|e| e == &usage) {
            self.params.extended_key_usages.push(usage);
        }
        self
    }

    /// Builds and serialize a new certificate signing request [Csr].
    pub fn build(self) -> Result<Csr, rcgen::Error> {
        tracing::debug!("Building and serializing Certificate Signing Request");
        let key_pair = KeyPair::generate_for(&PKCS_ED25519)?;
        let csr = self.params.serialize_request(&key_pair)?;
        Ok(Csr { csr, key_pair })
    }
}

/// Encapsulates a [CertificateSigningRequest]
pub struct Csr {
    csr: CertificateSigningRequest,
    key_pair: KeyPair,
}

impl Csr {
    /// Sign with `signer` and serialize.
    pub fn serialize_pem(&self) -> Result<PemCertifiedKey, rcgen::Error> {
        let pem = PemCertifiedKey {
            cert_pem: self.csr.pem()?,
            private_key_pem: self.key_pair.serialize_pem(),
        };
        Ok(pem)
    }

    /// Return the `&CertificateSigningRequest`.
    pub fn csr(&self) -> &CertificateSigningRequest {
        &self.csr
    }
}


/// Signs a Certificate Signing Request using a CA and key pair.
pub struct CertificateSigner {}

impl CertificateSigner {}

#[cfg(test)]
mod tests {
    use assert_fs::prelude::*;
    use rcgen::CertificateSigningRequestParams;
    use x509_parser::prelude::{FromDer, X509Certificate};

    use super::*;

    #[test]
    fn test_write_files() -> anyhow::Result<()> {
        let temp = assert_fs::TempDir::new()?;
        let dir = temp.path();
        let entity_cert = temp.child("cert.crt");
        let entity_key = temp.child("cert.key");

        let pck = PemCertifiedKey {
            cert_pem: "x".into(),
            private_key_pem: "y".into(),
        };

        pck.write(dir, "cert")?;

        // assert contents of created files
        entity_cert.assert("x");
        entity_key.assert("y");

        Ok(())
    }

    #[test]
    fn test_read_files() -> anyhow::Result<()> {
        let temp = assert_fs::TempDir::new()?;

        let entity_cert = temp.child("cert.crt");
        entity_cert.write_str("w")?;

        let entity_key = temp.child("cert.key");
        entity_key.write_str("y")?;

        let pem = PemCertifiedKey::read(entity_cert.path(), entity_key.path())?;

        // assert contents of PEM
        assert_eq!(pem.cert_pem, "w");
        assert_eq!(pem.private_key_pem, "y");

        Ok(())
    }

    #[test]
    fn init_ca() {
        let builder = CertificateBuilder::new("CA").certificate_authority();
        assert_eq!(
            builder.params.is_ca,
            IsCa::Ca(BasicConstraints::Unconstrained)
        )
    }

    #[test]
    fn load_ca_from_pem() -> anyhow::Result<()> {
        let cert = CertificateBuilder::new("Acme Ltd. CA")
            .certificate_authority()
            .build()?;
        let cert_key_pem = PemCertifiedKey::from(&cert);
        let ca = CertifiedKey::try_from(cert_key_pem)?;
        let issuer_der = pem::parse(ca.cert.pem())?;
        let (_, cert) = X509Certificate::from_der(issuer_der.contents())?;
        assert_eq!(cert.issuer().to_string(), "CN=Acme Ltd. CA".to_string());

        Ok(())
    }

    #[test]
    fn serialize_csr_with_ed25519_sig() -> anyhow::Result<()> {
        let ca = CertificateBuilder::new("CA")
            .certificate_authority()
            .build()?;

        let PemCertifiedKey { cert_pem, .. } = PemCertifiedKey::from(&ca);
        let issuer_der = pem::parse(cert_pem)?;
        let (_, issuer) = X509Certificate::from_der(issuer_der.contents())?;

        let csr = CertificateBuilder::new("localhost")
            .certificate_signing_request()
            .build()?;
        let PemCertifiedKey {
            cert_pem: csr_pem, ..
        } = PemCertifiedKey::try_from(&csr)?;
        let signed_cert = CertificateSigningRequestParams::from_pem(csr_pem.as_str())?
            .signed_by(&ca.cert, &ca.key_pair)?;

        let der = pem::parse(signed_cert.pem())?;
        let (_, cert) = X509Certificate::from_der(der.contents())?;

        let verified = cert.verify_signature(Some(issuer.public_key())).is_ok();
        assert!(verified);

        Ok(())
    }

    #[test]
    fn init_csr() {
        let builder = CertificateBuilder::new("localhost").certificate_signing_request();
        assert_eq!(builder.params.is_ca, IsCa::NoCa)
    }

    #[test]
    fn client_auth_csr() {
        let builder = CertificateBuilder::new("localhost").certificate_signing_request();
        assert_eq!(
            builder.client_auth().params.extended_key_usages,
            vec![ExtendedKeyUsagePurpose::ClientAuth]
        );
    }

    #[test]
    fn server_auth_csr() {
        let builder = CertificateBuilder::new("localhost").certificate_signing_request();
        assert_eq!(
            builder.server_auth().params.extended_key_usages,
            vec![ExtendedKeyUsagePurpose::ServerAuth]
        );
    }

    #[test]
    fn sans_end_entity() {
        let name = "test.potato.xyz";
        let names = vec![SanType::DnsName(name.try_into().unwrap())];
        let builder = CertificateBuilder::new("localhost")
            .certificate_signing_request()
            .subject_alternative_names(names);
        assert_eq!(
            builder.params.subject_alt_names,
            vec![rcgen::SanType::DnsName(name.try_into().unwrap())]
        );
    }

    #[test]
    fn sans_csr_empty() {
        let names = vec![];
        let builder = CertificateBuilder::new("localhost")
            .certificate_signing_request()
            .subject_alternative_names(names);
        assert_eq!(builder.params.subject_alt_names, vec![]);
    }
}
