pub trait Runnable<E> {
    fn run(&self) -> Result<(), E>;
}
