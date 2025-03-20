use std::{fs, path::PathBuf};

use async_trait::async_trait;
use clap::Parser;
use reqwest::{Certificate, Url};
use shared::Runnable;

#[derive(Parser)]
#[command(about = "Starts the leader")]
pub struct ValidateArgs {
    /// Worker server address.
    #[arg(short, long)]
    pub address: Url,

    /// Path to the Root CA certificate file.
    #[arg(long)]
    pub ca_cert: PathBuf,
}

#[async_trait]
impl Runnable for ValidateArgs {
    async fn run(&self) -> Result<(), anyhow::Error> {
        tracing::info!(address = %self.address, "Validating the worker TLS...");

        let client = build_client(&self.ca_cert)?;
        let response = client
            .get(self.address.clone())
            .send()
            .await?
            .error_for_status()?;

        let text = response.text().await?;
        tracing::info!(%text, "Connection successfull!");

        Ok(())
    }
}

fn build_client(ca_cert: &PathBuf) -> anyhow::Result<reqwest::Client> {
    let ca_cert_pem = fs::read(ca_cert)?;
    let ca_cert = Certificate::from_pem(&ca_cert_pem)?;

    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .build()?;

    Ok(client)
}
