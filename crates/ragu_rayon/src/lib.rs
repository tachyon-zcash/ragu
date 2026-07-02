//! Parallelism facade for the Ragu project.
//!
//! With the `threads` feature enabled this crate is a transparent re-export of
//! [`rayon`](https://docs.rs/rayon). With it disabled, it provides an
//! API-compatible, single-threaded
//! fallback that requires only `core` and `alloc`, so crates that depend on it
//! can build for `no_std` targets when parallelism is not needed.
//!
//! This is a vendored, `no_std`-friendly adaptation of the `maybe-rayon` crate
//! (<https://github.com/shssoichiro/maybe-rayon>). The upstream serial facade
//! reaches for `std` in a handful of places (`std::iter`, `std::slice`,
//! `std::marker`, and an un-`alloc`'d `Box`); here those are rewritten in terms
//! of `core`/`alloc` so the fallback builds on bare-metal targets such as
//! `thumbv7em-none-eabihf`.

#![cfg_attr(not(feature = "threads"), no_std)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]

cfg_if::cfg_if! {
    if #[cfg(any(
        not(feature = "threads"),
        all(target_arch = "wasm32", not(target_feature = "atomics"))
    ))] {
        extern crate alloc;

        use core::marker::PhantomData;

        /// Single-threaded stand-in for `rayon::ThreadPoolBuilder`.
        #[derive(Default)]
        pub struct ThreadPoolBuilder();

        impl ThreadPoolBuilder {
            /// Creates a new builder.
            #[inline(always)]
            pub fn new() -> ThreadPoolBuilder {
                ThreadPoolBuilder()
            }

            /// Builds the (single-threaded) thread pool. Never fails.
            #[inline(always)]
            pub fn build(self) -> Result<ThreadPool, core::convert::Infallible> {
                Ok(ThreadPool())
            }

            /// Sets the number of threads. Ignored by the single-threaded facade.
            #[inline(always)]
            pub fn num_threads(self, _num_threads: usize) -> ThreadPoolBuilder {
                ThreadPoolBuilder()
            }
        }

        /// Single-threaded stand-in for `rayon::ThreadPool`.
        #[derive(Debug)]
        pub struct ThreadPool();

        impl ThreadPool {
            /// Runs `op` immediately on the current thread.
            #[inline(always)]
            pub fn install<OP, R>(&self, op: OP) -> R
            where
                OP: FnOnce() -> R + Send,
                R: Send,
            {
                op()
            }
        }

        /// Sequential stand-ins for rayon's parallel iterator traits.
        pub mod iter {
            /// Sequential stand-in for `rayon::iter::IntoParallelIterator`.
            pub trait IntoParallelIterator {
                /// The sequential iterator this converts into.
                type Iter: Iterator<Item = Self::Item>;
                /// The type of item produced.
                type Item: Send;

                /// Converts `self` into a sequential iterator.
                fn into_par_iter(self) -> Self::Iter;
            }

            impl<I: IntoIterator> IntoParallelIterator for I
            where
                I::Item: Send,
            {
                type Item = I::Item;
                type Iter = I::IntoIter;

                #[inline(always)]
                fn into_par_iter(self) -> I::IntoIter {
                    self.into_iter()
                }
            }

            /// Sequential stand-in for `rayon::iter::IntoParallelRefMutIterator`.
            pub trait IntoParallelRefMutIterator<'data> {
                /// The resulting sequential iterator type.
                type Iter: IntoParallelIterator<Item = Self::Item>;
                /// The type of item produced.
                type Item: Send + 'data;

                /// Borrows `self` mutably as a sequential iterator.
                fn par_iter_mut(&'data mut self) -> Self::Iter;
            }

            impl<'data, I: 'data + ?Sized> IntoParallelRefMutIterator<'data> for I
            where
                &'data mut I: IntoParallelIterator,
            {
                type Iter = <&'data mut I as IntoParallelIterator>::Iter;
                type Item = <&'data mut I as IntoParallelIterator>::Item;

                #[inline(always)]
                fn par_iter_mut(&'data mut self) -> Self::Iter {
                    self.into_par_iter()
                }
            }

            /// Sequential stand-in for `rayon::iter::ParallelIterator`.
            pub trait ParallelIterator: Iterator {
                /// Sequential stand-in for `ParallelIterator::flat_map_iter`.
                #[inline(always)]
                fn flat_map_iter<U, F>(self, f: F) -> core::iter::FlatMap<Self, U, F>
                where
                    Self: Sized,
                    U: IntoIterator,
                    F: FnMut(<Self as Iterator>::Item) -> U,
                {
                    self.flat_map(f)
                }
            }

            impl<I: Iterator> ParallelIterator for I {}
        }

        /// Sequential stand-ins for rayon's parallel slice traits.
        pub mod slice {
            /// Sequential stand-in for `rayon::slice::ParallelSlice`.
            pub trait ParallelSlice<T: Sync> {
                /// Sequential stand-in for `ParallelSlice::par_chunks_exact`.
                fn par_chunks_exact(&self, chunk_size: usize) -> core::slice::ChunksExact<'_, T>;
            }

            impl<T: Sync> ParallelSlice<T> for [T] {
                #[inline(always)]
                fn par_chunks_exact(&self, chunk_size: usize) -> core::slice::ChunksExact<'_, T> {
                    self.chunks_exact(chunk_size)
                }
            }
        }

        /// Convenience re-exports mirroring `rayon::prelude`.
        pub mod prelude {
            pub use super::iter::*;
            pub use super::slice::*;
        }

        /// Runs `oper_a` then `oper_b` sequentially, returning both results.
        ///
        /// Sequential stand-in for `rayon::join`.
        #[inline(always)]
        pub fn join<A, B, RA, RB>(oper_a: A, oper_b: B) -> (RA, RB)
        where
            A: FnOnce() -> RA + Send,
            B: FnOnce() -> RB + Send,
            RA: Send,
            RB: Send,
        {
            (oper_a(), oper_b())
        }

        /// Sequential stand-in for `rayon::Scope`.
        pub struct Scope<'scope> {
            #[allow(clippy::type_complexity)]
            marker: PhantomData<alloc::boxed::Box<dyn FnOnce(&Scope<'scope>) + Send + Sync + 'scope>>,
        }

        impl<'scope> Scope<'scope> {
            /// Runs `body` immediately on the current thread.
            ///
            /// Sequential stand-in for `rayon::Scope::spawn`.
            #[inline(always)]
            pub fn spawn<BODY>(&self, body: BODY)
            where
                BODY: FnOnce(&Scope<'scope>) + Send + 'scope,
            {
                body(self);
            }
        }

        /// Creates a scope and runs `op` within it, sequentially.
        ///
        /// Sequential stand-in for `rayon::scope`.
        #[inline(always)]
        pub fn scope<'scope, OP, R>(op: OP) -> R
        where
            OP: for<'s> FnOnce(&'s Scope<'scope>) -> R + 'scope + Send,
            R: Send,
        {
            op(&Scope { marker: PhantomData })
        }
    } else {
        pub use rayon::*;
    }
}
