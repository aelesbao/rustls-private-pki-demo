use clap::Parser;
use shared::Runnable;

#[derive(Parser)]
#[command(about = "Starts the worker")]
pub struct ServerArgs {}

impl Runnable for ServerArgs {
    fn run(&self) -> Result<(), anyhow::Error> {
        todo!()
    }
}
