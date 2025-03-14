pub trait Runnable<E = anyhow::Error> {
    fn run(&self) -> Result<(), E>;
}
