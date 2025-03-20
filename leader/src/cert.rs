use std::{
    fs,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use clap::{Parser, Subcommand};

use shared::{
    Runnable,
    cert::{CertificateBuilder, CertificateSigner, PemCertifiedKey},
};

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

#[async_trait]
impl Runnable for CertArgs {
    async fn run(&self) -> anyhow::Result<()> {
        match &self.command {
            CertCommands::Gen(args) => run_gen(&args.common_name, &args.outdir),
            CertCommands::Sign(args) => {
                run_sign(&args.ca_cert, &args.ca_key, &args.csr, &args.signed_cert)
            }
        }
    }
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

fn run_gen(common_name: &str, outdir: &Path) -> anyhow::Result<()> {
    tracing::info!("Generating Root Certificate Authority for '{common_name}");

    let ca = CertificateBuilder::new(common_name)
        .certificate_authority()
        .organization_name("Acme Ltd.")
        .validity(365 * 10)
        .build()?;

    PemCertifiedKey::from(&ca).write(outdir, "ca")?;

    tracing::info!("Root CA generated successfully");

    Ok(())
}

#[derive(Parser)]
#[command(about = "Signs a certificate signing request")]
pub struct SignArgs {
    /// Path to the CA certificate file.
    #[arg(long)]
    pub ca_cert: PathBuf,

    /// Path to the CA key pair file.
    #[arg(long)]
    pub ca_key: PathBuf,

    /// Path to the CSR file.
    #[arg(long)]
    pub csr: PathBuf,

    /// Path to save the signed certificate file.
    #[arg(long)]
    pub signed_cert: PathBuf,
}

fn run_sign(
    ca_cert_path: &Path,
    ca_key_path: &Path,
    csr_path: &Path,
    signed_cert_path: &Path,
) -> anyhow::Result<()> {
    let ca = PemCertifiedKey::read(ca_cert_path, ca_key_path)?.try_into()?;
    tracing::debug!("Opening CSR at {}", csr_path.to_string_lossy());
    let csr_pem = fs::read_to_string(csr_path)?;

    let signed_cert = CertificateSigner::from_pem(ca, &csr_pem)?
        .validity(90)
        .sign()?;

    if let Some(outdir) = signed_cert_path.parent() {
        fs::create_dir_all(outdir)?;
    }

    tracing::debug!(
        signed_cert = %signed_cert.pem(),
        "Saving signed certificate to {}",
        signed_cert_path.to_string_lossy()
    );
    fs::write(signed_cert_path, signed_cert.pem().as_bytes())?;

    tracing::info!("Certificate signed successfully");

    Ok(())
}
