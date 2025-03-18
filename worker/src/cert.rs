use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use rcgen::{Certificate, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
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

impl Runnable for CertArgs {
    fn run(&self) -> anyhow::Result<()> {
        match &self.command {
            CertCommands::Gen(args) => run_gen(&args.common_name, &args.outdir),
        }
    }
}

fn run_gen(common_name: &str, outdir: &Path) -> anyhow::Result<()> {
    tracing::info!("Generating Root Certificate Authority");

    let (cert, key_pair) = generate_csr(common_name)?;
    save_cert(outdir, "worker", cert, key_pair)?;

    tracing::info!("Root CA generated successfully");

    Ok(())
}

pub fn generate_csr(common_name: &str) -> anyhow::Result<(Certificate, KeyPair)> {
    // Set Subject Alternative Name for the worker (use hostname or IP as needed)
    //let subject_alt_names = vec![SanType::DnsName("localhost".to_string())];

    // Set key usage and extended key usage for a client/server certificate
    let key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    let extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];

    let is_ca = IsCa::ExplicitNoCa;

    generate_certificate(common_name, is_ca, key_usages, extended_key_usages)
}
