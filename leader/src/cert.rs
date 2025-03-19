use std::path::{Path, PathBuf};

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

impl Runnable for CertArgs {
    fn run(&self) -> anyhow::Result<()> {
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
    let signer = CertificateSigner::new(ca);
    signer.sign_pem_file(csr_path, signed_cert_path)?;

    tracing::info!("Certificate signed successfully");

    Ok(())
}
