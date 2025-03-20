use async_trait::async_trait;
use clap::Parser;
use shared::Runnable;

#[derive(Parser)]
#[command(about = "Starts the leader")]
pub struct ValidateArgs {}

#[async_trait]
impl Runnable for ValidateArgs {
    async fn run(&self) -> Result<(), anyhow::Error> {
        todo!()
    }
}
