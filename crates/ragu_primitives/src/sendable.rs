use ragu_core::drivers::Driver;
use ragu_core::gadgets::Gadget;

/// A wrapper that asserts its contents are [`Send`].
///
/// This type can only be constructed (via [`new`](Sendable::new)) when
/// `D::Wire: Send`, which — together with the safety contract of
/// [`GadgetKind`](ragu_core::gadgets::GadgetKind) — guarantees the wrapped
/// gadget is `Send`.
pub struct Sendable<G>(G);

impl<G> Sendable<G> {
    /// Wraps a gadget in `Sendable`, asserting it is [`Send`].
    ///
    /// The `D::Wire: Send` bound, combined with the safety contract of
    /// [`GadgetKind`](ragu_core::gadgets::GadgetKind) (which requires that
    /// `D::Wire: Send` implies `Rebind<'dr, D>: Send`), guarantees the
    /// wrapped gadget is actually `Send`.
    pub fn new<'dr, D: Driver<'dr>>(gadget: G) -> Self
    where
        G: Gadget<'dr, D>,
        D::Wire: Send,
    {
        Sendable(gadget)
    }

    /// Unwraps the `Sendable`, returning the inner gadget.
    pub fn into_inner(self) -> G {
        self.0
    }
}

/// Safety: `Sendable<G>` can only be constructed when `D::Wire: Send`, and the
/// safety contract of `GadgetKind` guarantees that `D::Wire: Send` implies the
/// gadget (its `Rebind`) is `Send`.
unsafe impl<G> Send for Sendable<G> {}

impl<G: Clone> Clone for Sendable<G> {
    fn clone(&self) -> Self {
        Sendable(self.0.clone())
    }
}

impl<G> core::ops::Deref for Sendable<G> {
    type Target = G;

    fn deref(&self) -> &G {
        &self.0
    }
}
