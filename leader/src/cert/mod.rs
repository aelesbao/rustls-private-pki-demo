use clap::{Parser, Subcommand};
use shared::Runnable;

#[derive(Parser)]
#[command(about = "COmmands to work with X.509 certificates")]
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
pub struct GenArgs {}

#[derive(Parser)]
#[command(about = "Signs a certificate signing request")]
pub struct SignArgs {}

impl Runnable for CertArgs {
    fn run(&self) -> anyhow::Result<()> {
        match &self.command {
            CertCommands::Gen(_) => todo!(),
            CertCommands::Sign(_) => todo!(),
        }
    }
}
