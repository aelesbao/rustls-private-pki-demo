use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use rcgen::{Certificate, IsCa, KeyPair, KeyUsagePurpose};

use shared::{
    Runnable,
    cert::{generate_certificate, save_cert},
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
    tracing::info!("Generating Root Certificate Authority");

    let (cert, key_pair) = generate_ca(common_name)?;
    save_cert(outdir, "ca", cert, key_pair)?;

    tracing::info!("Root CA generated successfully");

    Ok(())
}

pub fn generate_ca(common_name: &str) -> anyhow::Result<(Certificate, KeyPair)> {
    let is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    // Mark as CA with basic constraints and key usage for signing
    let key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    generate_certificate(common_name, is_ca, key_usages)
}
