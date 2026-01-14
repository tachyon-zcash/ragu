//! Conditional parallelism abstraction using Rayon.
//!
//! Adapted from <https://github.com/0xPolygonZero/plonky2/blob/main/maybe_rayon/src/lib.rs>
//! Credit: Polygon Zero team
//!
//! This module provides traits and implementations to abstract over parallel and
//! sequential iteration using the Rayon library. By enabling or disabling the
//! "parallel" feature, users can switch between parallel and sequential execution
//! **without changing the code or the APIs**.
//!
//! The main traits provided are `MaybeParIter`, `MaybeParIterMut`, and `MaybeIntoParIter`,
//! which allow for parallel or sequential iteration over references, mutable references,
//! and owned values, respectively. Additionally, there are traits for chunked iteration:
//! `MaybeParChunks` and `MaybeParChunksMut`.
//! The module also includes a `join` function that executes two closures in parallel
//! if the "parallel" feature is enabled, or sequentially otherwise.
//!
//! # Example
//!
//! The following code, when compiled with `parallel` feature, will enables rayon-powered
//! parallelism. Without the feature, it will run sequentially.
//!
//! ```rust
//! use ragu_primitives::maybe_rayon::MaybeParIter;
//! #[cfg(feature = "parallel")]
//! use ragu_primitives::maybe_rayon::ParallelIterator;
//!
//! // compile-time conditional parallelism
//! fn sum_of_squares(input: &[i32]) -> i32 {
//!    input.par_iter()
//!         .map(|i| i * i)
//!         .sum()
//! }
//! ```

#![allow(missing_docs)]

#[cfg(not(feature = "parallel"))]
extern crate alloc;

#[cfg(feature = "parallel")]
pub use rayon::{
    self,
    prelude::{
        IndexedParallelIterator, ParallelDrainFull, ParallelDrainRange, ParallelExtend,
        ParallelIterator,
    },
};
#[cfg(feature = "parallel")]
use rayon::{
    prelude::*,
    slice::{
        Chunks as ParChunks, ChunksExact as ParChunksExact, ChunksExactMut as ParChunksExactMut,
        ChunksMut as ParChunksMut,
    },
};
#[cfg(not(feature = "parallel"))]
use {
    alloc::vec::Vec,
    core::{
        iter::{FlatMap, IntoIterator, Iterator},
        slice::{self, Chunks, ChunksExact, ChunksExactMut, ChunksMut},
    },
};

pub trait MaybeParIter<'data> {
    #[cfg(feature = "parallel")]
    type Item: Send + 'data;

    #[cfg(feature = "parallel")]
    type Iter: ParallelIterator<Item = Self::Item>;

    #[cfg(not(feature = "parallel"))]
    type Item;

    #[cfg(not(feature = "parallel"))]
    type Iter: Iterator<Item = Self::Item>;

    fn par_iter(&'data self) -> Self::Iter;
}

#[cfg(feature = "parallel")]
impl<'data, T> MaybeParIter<'data> for T
where
    T: ?Sized + IntoParallelRefIterator<'data>,
{
    type Item = T::Item;
    type Iter = T::Iter;

    fn par_iter(&'data self) -> Self::Iter {
        self.par_iter()
    }
}

#[cfg(not(feature = "parallel"))]
impl<'data, T: 'data> MaybeParIter<'data> for Vec<T> {
    type Item = &'data T;
    type Iter = slice::Iter<'data, T>;

    fn par_iter(&'data self) -> Self::Iter {
        self.iter()
    }
}

#[cfg(not(feature = "parallel"))]
impl<'data, T: 'data> MaybeParIter<'data> for [T] {
    type Item = &'data T;
    type Iter = slice::Iter<'data, T>;

    fn par_iter(&'data self) -> Self::Iter {
        self.iter()
    }
}

pub trait MaybeParIterMut<'data> {
    #[cfg(feature = "parallel")]
    type Item: Send + 'data;

    #[cfg(feature = "parallel")]
    type Iter: ParallelIterator<Item = Self::Item>;

    #[cfg(not(feature = "parallel"))]
    type Item;

    #[cfg(not(feature = "parallel"))]
    type Iter: Iterator<Item = Self::Item>;

    fn par_iter_mut(&'data mut self) -> Self::Iter;
}

#[cfg(feature = "parallel")]
impl<'data, T> MaybeParIterMut<'data> for T
where
    T: ?Sized + IntoParallelRefMutIterator<'data>,
{
    type Item = T::Item;
    type Iter = T::Iter;

    fn par_iter_mut(&'data mut self) -> Self::Iter {
        self.par_iter_mut()
    }
}

#[cfg(not(feature = "parallel"))]
impl<'data, T: 'data> MaybeParIterMut<'data> for Vec<T> {
    type Item = &'data mut T;
    type Iter = slice::IterMut<'data, T>;

    fn par_iter_mut(&'data mut self) -> Self::Iter {
        self.iter_mut()
    }
}

#[cfg(not(feature = "parallel"))]
impl<'data, T: 'data> MaybeParIterMut<'data> for [T] {
    type Item = &'data mut T;
    type Iter = slice::IterMut<'data, T>;

    fn par_iter_mut(&'data mut self) -> Self::Iter {
        self.iter_mut()
    }
}

pub trait MaybeIntoParIter {
    #[cfg(feature = "parallel")]
    type Item: Send;

    #[cfg(feature = "parallel")]
    type Iter: ParallelIterator<Item = Self::Item>;

    #[cfg(not(feature = "parallel"))]
    type Item;

    #[cfg(not(feature = "parallel"))]
    type Iter: Iterator<Item = Self::Item>;

    fn into_par_iter(self) -> Self::Iter;
}

#[cfg(feature = "parallel")]
impl<T> MaybeIntoParIter for T
where
    T: IntoParallelIterator,
{
    type Item = T::Item;
    type Iter = T::Iter;

    fn into_par_iter(self) -> Self::Iter {
        self.into_par_iter()
    }
}

#[cfg(not(feature = "parallel"))]
impl<T> MaybeIntoParIter for T
where
    T: IntoIterator,
{
    type Item = T::Item;
    type Iter = T::IntoIter;

    fn into_par_iter(self) -> Self::Iter {
        self.into_iter()
    }
}

#[cfg(feature = "parallel")]
pub trait MaybeParChunks<T: Sync> {
    fn par_chunks(&self, chunk_size: usize) -> ParChunks<'_, T>;
    fn par_chunks_exact(&self, chunk_size: usize) -> ParChunksExact<'_, T>;
}

#[cfg(not(feature = "parallel"))]
pub trait MaybeParChunks<T> {
    fn par_chunks(&self, chunk_size: usize) -> Chunks<'_, T>;
    fn par_chunks_exact(&self, chunk_size: usize) -> ChunksExact<'_, T>;
}

#[cfg(feature = "parallel")]
impl<T: ParallelSlice<U> + ?Sized, U: Sync> MaybeParChunks<U> for T {
    fn par_chunks(&self, chunk_size: usize) -> ParChunks<'_, U> {
        self.par_chunks(chunk_size)
    }
    fn par_chunks_exact(&self, chunk_size: usize) -> ParChunksExact<'_, U> {
        self.par_chunks_exact(chunk_size)
    }
}

#[cfg(not(feature = "parallel"))]
impl<T> MaybeParChunks<T> for [T] {
    fn par_chunks(&self, chunk_size: usize) -> Chunks<'_, T> {
        self.chunks(chunk_size)
    }

    fn par_chunks_exact(&self, chunk_size: usize) -> ChunksExact<'_, T> {
        self.chunks_exact(chunk_size)
    }
}

#[cfg(feature = "parallel")]
pub trait MaybeParChunksMut<T: Send> {
    fn par_chunks_mut(&mut self, chunk_size: usize) -> ParChunksMut<'_, T>;
    fn par_chunks_exact_mut(&mut self, chunk_size: usize) -> ParChunksExactMut<'_, T>;
}

#[cfg(not(feature = "parallel"))]
pub trait MaybeParChunksMut<T: Send> {
    fn par_chunks_mut(&mut self, chunk_size: usize) -> ChunksMut<'_, T>;
    fn par_chunks_exact_mut(&mut self, chunk_size: usize) -> ChunksExactMut<'_, T>;
}

#[cfg(feature = "parallel")]
impl<T: ?Sized + ParallelSliceMut<U>, U: Send> MaybeParChunksMut<U> for T {
    fn par_chunks_mut(&mut self, chunk_size: usize) -> ParChunksMut<'_, U> {
        self.par_chunks_mut(chunk_size)
    }
    fn par_chunks_exact_mut(&mut self, chunk_size: usize) -> ParChunksExactMut<'_, U> {
        self.par_chunks_exact_mut(chunk_size)
    }
}

#[cfg(not(feature = "parallel"))]
impl<T: Send> MaybeParChunksMut<T> for [T] {
    fn par_chunks_mut(&mut self, chunk_size: usize) -> ChunksMut<'_, T> {
        self.chunks_mut(chunk_size)
    }
    fn par_chunks_exact_mut(&mut self, chunk_size: usize) -> ChunksExactMut<'_, T> {
        self.chunks_exact_mut(chunk_size)
    }
}

#[cfg(not(feature = "parallel"))]
pub trait ParallelIteratorMock {
    type Item;
    fn find_any<P>(self, predicate: P) -> Option<Self::Item>
    where
        P: Fn(&Self::Item) -> bool + Sync + Send;

    fn flat_map_iter<U, F>(self, map_op: F) -> FlatMap<Self, U, F>
    where
        Self: Sized,
        U: IntoIterator,
        F: Fn(Self::Item) -> U;
}

#[cfg(not(feature = "parallel"))]
impl<T: Iterator> ParallelIteratorMock for T {
    type Item = T::Item;

    fn find_any<P>(mut self, predicate: P) -> Option<Self::Item>
    where
        P: Fn(&Self::Item) -> bool + Sync + Send,
    {
        self.find(predicate)
    }

    fn flat_map_iter<U, F>(self, map_op: F) -> FlatMap<Self, U, F>
    where
        Self: Sized,
        U: IntoIterator,
        F: Fn(Self::Item) -> U,
    {
        self.flat_map(map_op)
    }
}

#[cfg(feature = "parallel")]
pub fn join<A, B, RA, RB>(oper_a: A, oper_b: B) -> (RA, RB)
where
    A: FnOnce() -> RA + Send,
    B: FnOnce() -> RB + Send,
    RA: Send,
    RB: Send,
{
    rayon::join(oper_a, oper_b)
}

#[cfg(not(feature = "parallel"))]
pub fn join<A, B, RA, RB>(oper_a: A, oper_b: B) -> (RA, RB)
where
    A: FnOnce() -> RA,
    B: FnOnce() -> RB,
{
    (oper_a(), oper_b())
}
