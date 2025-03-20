use std::path::PathBuf;

use async_trait::async_trait;
use clap::Parser;
use shared::Runnable;

#[derive(Parser)]
#[command(about = "Starts the worker")]
pub struct ServerArgs {
    /// Path to the signed server certificate file.
    #[arg(long)]
    pub cert: PathBuf,

    /// Path to the server private key file.
    #[arg(long)]
    pub key: PathBuf,
}

#[async_trait]
impl Runnable for ServerArgs {
    async fn run(&self) -> anyhow::Result<()> {
        tracing::info!("Starting the worker server...");

        use warp::Filter;

        let routes = warp::any().map(|| "OK");

        warp::serve(routes)
            .tls()
            .cert_path(&self.cert)
            .key_path(&self.key)
            .run(([127, 0, 0, 1], 3030))
            .await;

        Ok(())
    }
}
