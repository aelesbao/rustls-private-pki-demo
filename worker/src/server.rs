use clap::Parser;
use shared::Runnable;

#[derive(Parser)]
#[command(about = "Starts the worker")]
pub struct ServerArgs {}

#[async_trait]
impl Runnable for ServerArgs {
    async fn run(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
