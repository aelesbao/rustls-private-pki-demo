use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use rcgen::CertifiedKey;
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

impl Runnable for CertArgs {
    fn run(&self) -> anyhow::Result<()> {
        match &self.command {
            CertCommands::Gen(args) => run_gen(&args.common_name, &args.outdir),
            CertCommands::Sign(_) => todo!(),
        }
    }
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

}
