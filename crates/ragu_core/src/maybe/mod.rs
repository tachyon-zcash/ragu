//! The [`Maybe<T>`] trait, an [`Option`]-like abstraction that encodes
//! optionality into the type system so that the compiler can perform various
//! optimizations and correctness checks via static analysis.
//!
//! ## Overview
//!
//! Optional values are common in Rust, and in `ragu` (like many SNARK
//! frameworks) we wish to express the optional presence of witness data when
//! writing composable and unified circuit abstractions and algorithms.
//! Typically, the witness is present during proof generation and absent during
//! key generation, yet the code paths are shared to ensure consistency,
//! maintainability and readability.
//!
//! However, we almost always _statically_ know whether an `Option<T>`
//! containing witness data is a `None` or a `Some(T)` since the synthesis is
//! monomorphized for a specific backend context. In these cases, an `Option<T>`
//! leads to unnecessary memory usage in contexts where the value is known to
//! not exist. (This is both in terms of the empty, uninitialized value it
//! contains and the discriminant that identifies the variant at runtime.)
//!
//! These overheads are normally negligible, but in `ragu` we very frequently
//! need to perform circuit synthesis (polynomial reductions) without access to
//! a witness. In fact, this process consumes the _vast_ majority of the proof
//! generation time, even after the aggressive optimizations implemented in this
//! library. One of the easiest and most impactful wins would be static analysis
//! of monomorphized circuit synthesis code that proxies an `Option<T>` to a `T`
//! when the value is required to exist and proxies it to a zero-sized type when
//! it is guaranteed _not_ to exist.
//!
//! Rust cannot perform this static analysis with the native `Option<T>` type,
//! and so the [`Maybe<T>`] trait is a higher-kinded abstraction for this
//! purpose. There are further benefits. We now achieve compile-time guarantees
//! about the presence or absence of witness data, and entire classes of bugs
//! and error conditions are eliminated by design. (As an example, `ragu` does
//! not have the concept of a "missing witness" error that can be seen in
//! `halo2`, `bellman`, `arkworks`, etc.) The [`Maybe<T>`] trait also simplifies
//! situations involving _nested_ optionality of witness data, which can be
//! confusing in the context of recursive proofs.
//!
//! See the *Witness Data* chapter in the [book] for the full motivation
//! and design rationale.
//!
//! ## Design
//!
//! End users typically have access to a [`Maybe<T>`] type that they can treat
//! like an `Option<T>` in many cases: it has [`map`](Maybe::map),
//! [`and_then`](Maybe::and_then) and similar methods. In contexts where the API
//! allows it, the [`Maybe<T>`] can be "unwrapped" to its enclosed `T` value
//! using the [`take`](Maybe::take) method. (In contexts where this is not
//! allowed, a compile-time error _always_ occurs.)
//!
//! It is possible to _create_ a new [`Maybe<T>`] value using the
//! [`just`](Maybe::just) or [`try_just`](Maybe::try_just) methods or another function
//! that proxies to these methods. These methods are provided a closure that is
//! only executed if the concrete type is expected to exist. The compiler
//! dead-code eliminates the closure in all other cases.
//!
//! The actual concrete backing type (and the rebinding) for a [`Maybe<T>`] is
//! determined by its `Kind` associated type that implements [`MaybeKind`].
//! There are only two implementations of this, one for the [`Always`] type and
//! one for the [`Empty`] type. Typically, end users of the [`Maybe<T>`] API
//! will not need to interact with these types or traits or be aware that they
//! exist.
//!
//! There is an additional trait, [`MaybeCast`], that provides the ability to
//! split [`Maybe<T>`] values into multiple values that contain the separate
//! pieces of the enclosed value, or reinterpret the enclosed value somehow.
//! This is done by value in a way that often does not lead to any runtime
//! overhead due to existing memory layout optimizations in the Rust compiler.
//!
//! [book]: https://tachyon.z.cash/ragu/guide/drivers/witness.html

mod always;
mod cast;
mod empty;

mod sealed {
    pub trait Sealed {}
}

pub use always::Always;
pub use empty::Empty;

/// Represents a value that may or may not exist, like an `Option<T>`, except
/// that its existence is inherent to its concrete type rather than to a runtime
/// discriminant. This means that _non-existing_ `Maybe<T>` values are
/// zero-sized types and _existing_ `Maybe<T>` values are transparently
/// equivalent to their enclosed `T` values.
pub trait Maybe<T: Send>: sealed::Sealed + Send {
    /// The kind of this `Maybe<T>` that defines how it is rebound when mapped.
    type Kind: MaybeKind;

    /// Creates a new value of this `Maybe<T>` given a closure that returns `T`.
    /// The closure may not be called if the concrete type of this `Maybe<T>`
    /// does not represent existing values.
    fn just<R: Send>(f: impl FnOnce() -> R) -> Perhaps<Self::Kind, R>;

    /// Creates a new value of this `Maybe<T>` given a fallible closure. Similar
    /// to `just` the provided closure is not called if the concrete type does
    /// not represent an existing value.
    fn try_just<R: Send, E>(f: impl FnOnce() -> Result<R, E>) -> Result<Perhaps<Self::Kind, R>, E>;

    /// In contexts where the `Maybe<T>` is known or guaranteed to be an
    /// existing value, this returns the enclosed value. In other contexts, this
    /// will fail at compile time.
    fn take(self) -> T;

    /// Returns a reference to the enclosed value, analogous to
    /// [`Option::as_ref`].
    fn as_ref(&self) -> Perhaps<Self::Kind, &T>
    where
        T: Sync;

    /// Mutable counterpart of [`as_ref`](Maybe::as_ref).
    fn as_mut(&mut self) -> Perhaps<Self::Kind, &mut T>;

    /// Shorthand for `.as_ref().take()` to obtain a reference to the enclosed value
    /// in contexts where the `Maybe<T>` is guaranteed to be an existing value.
    /// In other contexts, just as in [`Maybe<T>::take`], this will fail at
    /// compile time.
    fn snag(&self) -> &T
    where
        T: Sync,
    {
        self.as_ref().take()
    }

    /// Helper to clone the enclosed `Maybe<T>` value when `T` is `Clone`.
    fn clone(&self) -> Self
    where
        T: Clone;

    /// Maps the enclosed value given the provided closure, as in `Option<T>::map`.
    fn map<U: Send, F>(self, f: F) -> Perhaps<Self::Kind, U>
    where
        F: FnOnce(T) -> U;

    /// Given a closure that returns a `Maybe<U>`, this maps the enclosed
    /// value to a new `Maybe<U>`, as in `Option<T>::and_then`.
    fn and_then<U: Send, F>(self, f: F) -> Perhaps<Self::Kind, U>
    where
        F: FnOnce(T) -> Perhaps<Self::Kind, U>;

    /// Converts the `Maybe<T>` into a `Maybe<U>` where `T: Into<U>`. Equivalent
    /// to `.map(|t| t.into())`.
    fn into<U: Send>(self) -> Perhaps<Self::Kind, U>
    where
        T: Into<U>;

    /// This consumes a `Maybe<T>` and deconstructs or reinterprets the value as
    /// a different type defined by the `MaybeCast` trait. This is useful for
    /// doing things like converting a `Maybe<(T, U)>` into a tuple `(Maybe<T>,
    /// Maybe<U>)`. (Forgive the abuse of notation.)
    fn cast<R>(self) -> T::Output
    where
        T: MaybeCast<R, Self::Kind>;
}

/// This trait defines the nature of rebinding for a [`Maybe<T>`] type back into
/// its concrete type, using generic associated types to simulate a
/// higher-kinded type abstraction.
pub trait MaybeKind: sealed::Sealed {
    /// How a `Maybe<T>` is rebound into a `Maybe<U>` for this kind.
    /// Use [`Perhaps`] type alias instead of accessing this directly.
    type Rebind<T: Send>: Maybe<T, Kind = Self>;

    /// Proxy for the associated [`Maybe<T>::just`] method.
    fn maybe_just<R: Send>(f: impl FnOnce() -> R) -> Self::Rebind<R> {
        Self::Rebind::<R>::just(f)
    }

    /// Proxy for the associated [`Maybe<T>::try_just`] method.
    fn maybe_try_just<R: Send, E>(f: impl FnOnce() -> Result<R, E>) -> Result<Self::Rebind<R>, E> {
        Self::Rebind::<R>::try_just(f)
    }

    /// Creates an empty `Maybe<T>` value for this kind. This will fail at
    /// compile time for kinds that represent existing values.
    fn empty<T: Send>() -> Self::Rebind<T>;
}

/// Alias for `<K as MaybeKind>::Rebind<T>`.
pub type Perhaps<K, T> = <K as MaybeKind>::Rebind<T>;

/// This trait provides a generic method to describe how enclosed [`Maybe<T>`]
/// values can be deconstructed into multiple (and/or different) `Maybe` values
/// through cheap reinterpretation or conversion. The type parameter `R` is used
/// to disambiguate multiple possible conversions from a particular `Self` type
/// based on the possible rebinding of the `Output` type.
pub trait MaybeCast<R, K: MaybeKind> {
    /// The output of the conversion.
    type Output;

    /// Creates `Self::Output` assuming that the `Maybe<T>` represents
    /// non-existing values.
    fn empty() -> Self::Output;

    /// Creates `Self::Output` assuming that the `Maybe<T>` represents an
    /// existing value, using the current value of `self` to perform the
    /// conversion.
    fn cast(self) -> Self::Output;
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{Always, Empty, Maybe, MaybeKind, Perhaps};

    trait Interface {
        type MaybeKind: MaybeKind;

        fn op(f: impl FnOnce() -> usize);

        fn just<R: Send>(f: impl FnOnce() -> R) -> Perhaps<Self::MaybeKind, R> {
            <Self::MaybeKind as MaybeKind>::maybe_just(f)
        }

        fn try_just<R: Send, E>(
            f: impl FnOnce() -> Result<R, E>,
        ) -> Result<Perhaps<Self::MaybeKind, R>, E> {
            <Self::MaybeKind as MaybeKind>::maybe_try_just(f)
        }
    }

    fn my_operation<I: Interface, E>(
        value: Perhaps<I::MaybeKind, usize>,
    ) -> Result<Perhaps<I::MaybeKind, usize>, E> {
        let my_value = 100usize;
        let just_value = I::just(|| my_value + 10).map(|v| v * 2);
        let err_value = I::try_just(|| Ok(10))?;

        let x = value
            .and_then(|v| just_value.map(|j| v + j))
            .and_then(|v| err_value.map(|e| v + e));

        let mut ninenine = I::just(|| 99999);
        let ninenine_cloned = ninenine.clone();

        I::op(|| ninenine_cloned.take());

        I::just(|| {
            assert_eq!(ninenine.snag(), &99999);
        });

        ninenine.as_mut().map(|v| *v = 1181818);

        I::just(|| {
            assert_eq!(ninenine.snag(), &1181818);
        });

        I::just(|| {
            let a = ninenine.as_mut().take();
            *a = 1181819;
        });

        I::just(|| {
            assert_eq!(ninenine.snag(), &1181819);
        });

        let mut a = I::just(|| vec![1, 2, 3]);
        let mut b = a.as_mut().map(|v| v.iter_mut());

        I::just(|| {
            for i in 1..4 {
                assert_eq!(*b.as_mut().take().next().unwrap(), i);
            }
        });

        Ok(x)
    }

    #[test]
    fn test_always() {
        struct AlwaysInterface;
        impl Interface for AlwaysInterface {
            type MaybeKind = Always<()>;

            fn op(f: impl FnOnce() -> usize) {
                assert_eq!(f(), 99999);
            }
        }

        // 42 + ((100 + 10) * 2) + 10 = 272
        assert_eq!(
            my_operation::<AlwaysInterface, ()>(Always::<()>::just(|| 42))
                .unwrap()
                .take(),
            272
        );
    }

    #[test]
    fn test_empty() {
        struct EmptyInterface;
        impl Interface for EmptyInterface {
            type MaybeKind = Empty;

            fn op(_: impl FnOnce() -> usize) {}
        }

        my_operation::<EmptyInterface, ()>(Empty).unwrap();
    }

    // Generic test helpers parameterized on MaybeKind. Each exercises the
    // Maybe trait API in a generic context (the primary usage pattern), with
    // assertions guarded by `K::maybe_just` so they compile away for Empty.

    fn check_just_and_snag<K: MaybeKind>() {
        let v = K::maybe_just(|| 42usize);
        K::maybe_just(|| {
            assert_eq!(v.snag(), &42);
        });
    }

    fn check_map<K: MaybeKind>() {
        let v = K::maybe_just(|| 21usize).map(|x| x * 2);
        K::maybe_just(|| {
            assert_eq!(v.snag(), &42);
        });
    }

    fn check_and_then<K: MaybeKind>() {
        let v = K::maybe_just(|| 10usize).and_then(|x| K::maybe_just(|| x + 32));
        K::maybe_just(|| {
            assert_eq!(v.snag(), &42);
        });
    }

    fn check_as_ref<K: MaybeKind>() {
        let v = K::maybe_just(|| 42usize);
        let r = v.as_ref();
        r.map(|r| assert_eq!(*r, 42));
    }

    fn check_as_mut<K: MaybeKind>() {
        let mut v = K::maybe_just(|| 10usize);
        v.as_mut().map(|r| *r = 42);
        K::maybe_just(|| {
            assert_eq!(v.snag(), &42);
        });
    }

    fn check_clone<K: MaybeKind>() {
        let a = K::maybe_just(|| 42usize);
        let b = Maybe::clone(&a);
        K::maybe_just(|| {
            assert_eq!(a.snag(), &42);
            assert_eq!(b.snag(), &42);
        });
    }

    fn check_into<K: MaybeKind>() {
        let v: Perhaps<K, u64> = Maybe::into(K::maybe_just(|| 42u32));
        K::maybe_just(|| {
            assert_eq!(v.snag(), &42u64);
        });
    }

    fn check_try_just_ok<K: MaybeKind>() {
        let v: Result<Perhaps<K, usize>, &str> = K::maybe_try_just(|| Ok(42));
        let v = v.unwrap();
        K::maybe_just(|| {
            assert_eq!(v.snag(), &42);
        });
    }

    #[test]
    fn test_just_and_snag() {
        check_just_and_snag::<Always<()>>();
        check_just_and_snag::<Empty>();
    }

    #[test]
    fn test_map() {
        check_map::<Always<()>>();
        check_map::<Empty>();
    }

    #[test]
    fn test_and_then() {
        check_and_then::<Always<()>>();
        check_and_then::<Empty>();
    }

    #[test]
    fn test_as_ref() {
        check_as_ref::<Always<()>>();
        check_as_ref::<Empty>();
    }

    #[test]
    fn test_as_mut() {
        check_as_mut::<Always<()>>();
        check_as_mut::<Empty>();
    }

    #[test]
    fn test_clone() {
        check_clone::<Always<()>>();
        check_clone::<Empty>();
    }

    #[test]
    fn test_into() {
        check_into::<Always<()>>();
        check_into::<Empty>();
    }

    #[test]
    fn test_try_just_ok() {
        check_try_just_ok::<Always<()>>();
        check_try_just_ok::<Empty>();
    }

    // Concrete tests for impl-specific guarantees that cannot be expressed
    // generically: take() is only callable on Always, error propagation
    // requires Always to actually invoke the closure, and Empty tests use
    // Cell tracking to prove closures are never called.

    #[test]
    fn test_always_just_and_take() {
        assert_eq!(Always::<()>::just(|| 42usize).take(), 42);
    }

    #[test]
    fn test_always_try_just_err() {
        let v: Result<Always<usize>, &str> = Always::<usize>::try_just(|| Err("fail"));
        match v {
            Err(e) => assert_eq!(e, "fail"),
            Ok(_) => panic!("expected Err"),
        }
    }

    #[test]
    fn test_empty_just_ignores_closure() {
        use core::cell::Cell;
        let called = Cell::new(false);
        let _: Empty = <Empty as Maybe<usize>>::just(|| {
            called.set(true);
            999
        });
        assert!(!called.get());
    }

    #[test]
    fn test_empty_map_ignores_closure() {
        use core::cell::Cell;
        let called = Cell::new(false);
        let _: Empty = <Empty as Maybe<usize>>::just(|| 0).map(|_: usize| {
            called.set(true);
            0usize
        });
        assert!(!called.get());
    }

    #[test]
    fn test_empty_and_then_ignores_closure() {
        use core::cell::Cell;
        let called = Cell::new(false);
        let _: Empty = <Empty as Maybe<usize>>::just(|| 0).and_then::<usize, _>(|_: usize| {
            called.set(true);
            Empty
        });
        assert!(!called.get());
    }

    #[test]
    fn test_empty_try_just_never_calls_closure() {
        use core::cell::Cell;
        let called = Cell::new(false);
        let v: Result<Empty, &str> = <Empty as Maybe<usize>>::try_just(|| {
            called.set(true);
            Err::<usize, _>("fail")
        });
        assert!(!called.get());
        assert!(v.is_ok());
    }

    #[test]
    fn test_always_is_transparent() {
        assert_eq!(
            core::mem::size_of::<Always<u64>>(),
            core::mem::size_of::<u64>()
        );
        assert_eq!(core::mem::size_of::<Always<[u8; 32]>>(), 32);
    }

    #[test]
    fn test_empty_is_zst() {
        assert_eq!(core::mem::size_of::<Empty>(), 0);
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn always_map_identity(v in 0usize..10000) {
                let original = Always::<()>::just(|| v);
                let mapped = Always::<()>::just(|| v).map(|x| x);
                prop_assert_eq!(original.take(), mapped.take());
            }

            #[test]
            fn always_map_composition(v in 0usize..10000) {
                let f = |x: usize| x.wrapping_mul(3);
                let g = |x: usize| x.wrapping_add(7);
                let chained = Always::<()>::just(|| v).map(f).map(g).take();
                let composed = Always::<()>::just(|| v).map(|x| g(f(x))).take();
                prop_assert_eq!(chained, composed);
            }
        }
    }
}
