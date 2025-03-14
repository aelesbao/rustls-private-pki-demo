use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use rcgen::{Certificate, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

use shared::Runnable;

#[derive(Parser)]
#[command(about = "Commands to work with X.509 certificates")]
pub struct CertArgs {
    #[command(subcommand)]
    command: CertCommands,
}

#[derive(Subcommand)]
pub enum CertCommands {
    /// Generates a root CA certificate.
    Gen(GenArgs),

    /// Signs a certificate signing request.
    Sign(SignArgs),
}

#[derive(Parser)]
#[command(about = "Generates a root CA certificate")]
pub struct GenArgs {
    /// The common name of the certificate.
    #[arg(short, long)]
    pub common_name: String,

    /// The output directory.
    #[arg(short, long)]
    pub outdir: PathBuf,
}

#[derive(Parser)]
#[command(about = "Signs a certificate signing request")]
pub struct SignArgs {}

impl Runnable for CertArgs {
    fn run(&self) -> anyhow::Result<()> {
        match &self.command {
            CertCommands::Gen(args) => run_gen(&args.common_name, &args.outdir),
            CertCommands::Sign(_) => todo!(),
        }
    }
}

fn run_gen(common_name: &str, outdir: &Path) -> anyhow::Result<()> {
    let (cert, key_pair) = generate_ca_certificate(common_name)?;
    save_cert(outdir, cert, key_pair)?;

    tracing::info!("Root CA certificate generated successfully");

    Ok(())
}

fn generate_ca_certificate(common_name: &str) -> anyhow::Result<(Certificate, KeyPair)> {
    tracing::info!("Generating root CA certificate: {common_name}");

    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Talus Foundation");
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    // Mark as CA with basic constraints and key usage for signing
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    // Set validity (10 years for CA)
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(365 * 10);

    // Generate with a 4096-bit key for the CA
    // TODO: get key pair secret from args
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((cert, key_pair))
}

fn save_cert(outdir: &Path, cert: Certificate, key_pair: KeyPair) -> Result<(), anyhow::Error> {
    let pem_serialized = cert.pem();

    tracing::debug!("{pem_serialized}");
    tracing::debug!("{}", key_pair.serialize_pem());

    tracing::info!("Saving certificates to {:?}", outdir.as_os_str());

    std::fs::create_dir_all(outdir)?;
    std::fs::write("certs/ca.crt", pem_serialized.as_bytes())?;
    std::fs::write("certs/ca.key", key_pair.serialize_pem().as_bytes())?;

    Ok(())
}
