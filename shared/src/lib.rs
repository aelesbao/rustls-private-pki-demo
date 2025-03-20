use async_trait::async_trait;

pub mod cert;

#[async_trait]
pub trait Runnable<E = anyhow::Error> {
    async fn run(&self) -> Result<(), E>;
}
