use std::path::{Path, PathBuf};

use async_trait::async_trait;
use clap::{Parser, Subcommand};

use shared::{
    Runnable,
    cert::{CertificateBuilder, PemCertifiedKey},
};

#[derive(Parser)]
#[command(about = "Commands to work with X.509 certificates")]
pub struct CertArgs {
    #[command(subcommand)]
    command: CertCommands,
}

#[derive(Subcommand)]
pub enum CertCommands {
    /// Generates a Certificate Sign Request (CSR.
    Gen(GenArgs),
}

#[derive(Parser)]
#[command(about = "Generates a Certificate Sign Request (CSR")]
pub struct GenArgs {
    /// The common name of the certificate.
    #[arg(short, long)]
    pub common_name: String,

    /// The output directory.
    #[arg(short, long)]
    pub outdir: PathBuf,
}

#[async_trait]
impl Runnable for CertArgs {
    async fn run(&self) -> anyhow::Result<()> {
        match &self.command {
            CertCommands::Gen(args) => run_gen(&args.common_name, &args.outdir),
        }
    }
}

fn run_gen(common_name: &str, outdir: &Path) -> anyhow::Result<()> {
    tracing::info!("Generating Certificate Sign Request (CSR) for '{common_name}'");

    let csr = CertificateBuilder::new(common_name)
        .certificate_signing_request()
        .client_auth()
        .server_auth()
        .build()?;
    PemCertifiedKey::try_from(&csr)?.write(outdir, "worker")?;

    tracing::info!("CSR generated successfully");

    Ok(())
}
