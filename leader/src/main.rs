mod cert;
mod validate;

use clap::{Parser, Subcommand};

use shared::Runnable;
use tracing::{metadata::LevelFilter, subscriber::SetGlobalDefaultError};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_error::ErrorLayer;
use tracing_subscriber::prelude::*;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Sets the log level..
    #[arg(long, value_name = "LEVEL", default_value = "info")]
    pub log_level: tracing::metadata::LevelFilter,
}

#[derive(Subcommand)]
enum Commands {
    /// COmmands to work with X.509 certificates.
    Cert(cert::CertArgs),
    /// Lists all prefixes contained in a CSV file.
    Validate(validate::ValidateArgs),
}

impl Runnable for Cli {
    fn run(&self) -> anyhow::Result<()> {
        match &self.command {
            Commands::Cert(cert) => cert.run(),
            Commands::Validate(validate) => validate.run(),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let _guard = setup_logger(cli.log_level)?;

    cli.run()
}

pub fn setup_logger(level: LevelFilter) -> Result<WorkerGuard, SetGlobalDefaultError> {
    let buffer = std::io::stderr();
    let (writer, _guard) = tracing_appender::non_blocking(buffer);
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(writer)
        .finish()
        .with(ErrorLayer::default());

    tracing::subscriber::set_global_default(subscriber)?;

    Ok(_guard)
}
