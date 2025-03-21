use std::path::{Path, PathBuf};

use async_trait::async_trait;
use clap::{Parser, Subcommand};

use rcgen::{Ia5String, SanType};
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
    Csr(CsrArgs),
}

#[derive(Parser)]
#[command(about = "Generates a Certificate Sign Request (CSR)")]
pub struct CsrArgs {
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
            CertCommands::Csr(args) => run_csr(&args.common_name, &args.outdir),
        }
    }
}

fn run_csr(common_name: &str, outdir: &Path) -> anyhow::Result<()> {
    tracing::info!("Generating Certificate Sign Request (CSR) for '{common_name}'");

    let sans = vec![
        SanType::IpAddress("127.0.0.1".parse()?),
        SanType::DnsName(Ia5String::try_from("localhost")?),
    ];
    let csr = CertificateBuilder::new(common_name)
        .certificate_signing_request()
        .client_auth()
        .server_auth()
        .subject_alternative_names(sans)
        .build()?;
    PemCertifiedKey::try_from(&csr)?.write(outdir, "worker")?;

    tracing::info!("CSR generated successfully");

    Ok(())
}
