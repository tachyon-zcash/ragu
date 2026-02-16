use super::{Maybe, MaybeCast, MaybeKind, Perhaps};

/// The kind of `Maybe<T>` that represents a value that exists. This is
/// guaranteed by the compiler to have the same size and memory layout as `T`
/// itself.
#[repr(transparent)]
pub struct Always<T: Send>(T);

impl MaybeKind for Always<()> {
    type Rebind<T: Send> = Always<T>;

    fn empty<T: Send>() -> Perhaps<Self, T> {
        // See the comment in `Empty::take`.
        const { panic!("MaybeKind::empty called on AlwaysKind") }
    }
}

impl<T: Send> Maybe<T> for Always<T> {
    type Kind = Always<()>;

    fn just<R: Send>(f: impl FnOnce() -> R) -> Perhaps<Self::Kind, R> {
        Always(f())
    }
    fn with<R: Send, E>(f: impl FnOnce() -> Result<R, E>) -> Result<Perhaps<Self::Kind, R>, E> {
        Ok(Always(f()?))
    }
    fn take(self) -> T {
        self.0
    }
    fn map<U: Send, F>(self, f: F) -> Perhaps<Self::Kind, U>
    where
        F: FnOnce(T) -> U,
    {
        Always(f(self.0))
    }
    fn into<U: Send>(self) -> Perhaps<Self::Kind, U>
    where
        T: Into<U>,
    {
        Always(self.0.into())
    }
    fn clone(&self) -> Self
    where
        T: Clone,
    {
        Always(self.0.clone())
    }
    fn and_then<U: Send, F>(self, f: F) -> Perhaps<Self::Kind, U>
    where
        F: FnOnce(T) -> Perhaps<Self::Kind, U>,
    {
        f(self.0)
    }
    fn view(&self) -> Perhaps<Self::Kind, &T>
    where
        T: Sync,
    {
        Always(&self.0)
    }
    fn view_mut(&mut self) -> Perhaps<Self::Kind, &mut T> {
        Always(&mut self.0)
    }

    fn cast<R>(self) -> T::Output
    where
        T: MaybeCast<R, Self::Kind>,
    {
        T::cast(self.0)
    }
}
