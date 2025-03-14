use clap::Parser;
use shared::Runnable;

#[derive(Parser)]
#[command(about = "Starts the leader")]
pub struct ValidateArgs {}

impl Runnable for ValidateArgs {
    fn run(&self) -> Result<(), anyhow::Error> {
        todo!()
    }
}
