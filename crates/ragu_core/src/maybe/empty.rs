use super::{Maybe, MaybeCast, MaybeKind, Perhaps};

/// The kind of `Maybe<T>` that represents a value that does not exist. This is
/// a zero-sized type.
pub struct Empty;

impl MaybeKind for Empty {
    type Rebind<T: Send> = Empty;

    fn empty<T: Send>() -> Perhaps<Self, T> {
        Empty
    }
}

impl<T: Send> Maybe<T> for Empty {
    type Kind = Empty;

    fn just<R: Send>(_: impl FnOnce() -> R) -> Perhaps<Self::Kind, R> {
        Empty
    }
    fn with<R: Send, E>(_: impl FnOnce() -> Result<R, E>) -> Result<Perhaps<Self::Kind, R>, E> {
        Ok(Empty)
    }
    fn take(self) -> T {
        // This panic is guaranteed to occur at compile-time if this function is
        // invoked. (`Maybe<T>` is not dyn compatible so dynamic dispatch will
        // not provoke the evaluation of the `const` expression itself.) As long
        // as the user does not call `Empty::take()` then this expression will
        // also be optimized away after monomorphization and dead-code
        // elimination passes, though this is not strictly guaranteed by the
        // Rust language.
        //
        // https://doc.rust-lang.org/reference/expressions/block-expr.html#r-expr.block.const.not-executed
        //
        // Crates exist which depend on this behavior so it is unlikely to
        // change in the Rust compiler. And if it changes, it will cause an
        // unwanted compile-time error in the worst case.
        const {
            panic!(
                "Empty::take() called; you should not call Maybe<T>::take() outside of a context permitted by the API providing the Maybe<T> concrete type"
            );
        }
    }
    fn map<U: Send, F>(self, _: F) -> Perhaps<Self::Kind, U>
    where
        F: FnOnce(T) -> U,
    {
        Empty
    }
    fn into<U: Send>(self) -> Perhaps<Self::Kind, U>
    where
        T: Into<U>,
    {
        Empty
    }
    fn clone(&self) -> Self
    where
        T: Clone,
    {
        Empty
    }
    fn and_then<U: Send, F>(self, _: F) -> Perhaps<Self::Kind, U>
    where
        F: FnOnce(T) -> Perhaps<Self::Kind, U>,
    {
        Empty
    }
    fn view(&self) -> Perhaps<Self::Kind, &T>
    where
        T: Sync,
    {
        Empty
    }
    fn view_mut(&mut self) -> Perhaps<Self::Kind, &mut T> {
        Empty
    }

    fn cast<R>(self) -> T::Output
    where
        T: MaybeCast<R, Self::Kind>,
    {
        T::empty()
    }
}
