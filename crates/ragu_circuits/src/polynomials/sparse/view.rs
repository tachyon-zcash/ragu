//! Builder for constructing a [`Polynomial`] from gate-indexed wire values.
//!
//! A [`View`] provides four dense wire buffers (`a`, `b`, `c`, `d`) that the
//! caller fills in at gate indices. Calling [`View::build`] maps each buffer
//! to the appropriate degree positions and produces a sparse [`Polynomial`].
//!
//! # Perspectives
//!
//! Here $n$ = `R::n()` is the maximum number of multiplication gates.
//!
//! - **[`Trace`]**: the standard perspective for trace polynomials $r(X)$.
//!   - `a[i]` maps to degree $2n + i$
//!   - `b[i]` maps to degree $2n - 1 - i$
//!   - `c[i]` maps to degree $i$
//!   - `d[i]` maps to degree $4n - 1 - i$
//!
//! - **[`Wiring`]**: the reversed perspective for wiring polynomials
//!   $s(X, y)$. Swaps `a` with `b` and `c` with `d` in the degree mapping.
//!   - `a[i]` maps to degree $2n - 1 - i$
//!   - `b[i]` maps to degree $2n + i$
//!   - `c[i]` maps to degree $4n - 1 - i$
//!   - `d[i]` maps to degree $i$
//!
//! # Usage
//!
//! ```ignore
//! let mut view = View::trace();
//! view.a.push(some_value);
//! view.b.push(other_value);
//! view.c.push(product);
//! let poly = view.build();
//! ```

use alloc::vec::Vec;
use core::marker::PhantomData;

use ff::Field;

use super::{Polynomial, Rank, extend_runs};

mod private {
    pub trait Sealed {}
    impl Sealed for super::Trace {}
    impl Sealed for super::Wiring {}
}

/// Marker trait for the perspective of a [`View`].
pub trait Perspective: private::Sealed {
    /// Maps the four wire buffers (a, b, c, d) to degree-ordered blocks.
    ///
    /// Returns up to 4 blocks sorted by start degree. Adjacent blocks can
    /// occur when wire regions share a boundary (for example, when both `b`
    /// and `a` are full); this is permitted by the sparse polynomial
    /// representation. The `n` parameter is `R::n()` (the maximum number of
    /// multiplication gates).
    ///
    /// # Preconditions
    ///
    /// Each vector must have at most `n` entries. This is enforced by
    /// [`View::build`] before calling this method.
    fn map_to_blocks<T>(
        a: Vec<T>,
        b: Vec<T>,
        c: Vec<T>,
        d: Vec<T>,
        n: usize,
    ) -> Vec<(usize, Vec<T>)>;
}

/// Trace perspective: `a[i]` maps to degree $2n + i$, `b[i]` to
/// $2n - 1 - i$, `c[i]` to $i$, and `d[i]` to $4n - 1 - i$.
pub struct Trace;

/// Wiring perspective: swaps `a` with `b` and `c` with `d` relative to
/// [`Trace`]. See the [module documentation](self) for the full degree
/// mapping.
pub struct Wiring;

impl Perspective for Trace {
    fn map_to_blocks<T>(
        a: Vec<T>,
        mut b: Vec<T>,
        c: Vec<T>,
        mut d: Vec<T>,
        n: usize,
    ) -> Vec<(usize, Vec<T>)> {
        // c[i] -> degree i             (range [0, c.len()))
        // b[i] -> degree 2*n-1-i       (reversed, range [2*n-b.len(), 2*n))
        // a[i] -> degree 2*n+i         (range [2*n, 2*n+a.len()))
        // d[i] -> degree 4*n-1-i       (reversed, range [4*n-d.len(), 4*n))
        b.reverse();
        d.reverse();

        let mut blocks = Vec::new();
        if !c.is_empty() {
            blocks.push((0, c));
        }
        if !b.is_empty() {
            blocks.push((2 * n - b.len(), b));
        }
        if !a.is_empty() {
            blocks.push((2 * n, a));
        }
        if !d.is_empty() {
            blocks.push((4 * n - d.len(), d));
        }
        blocks
    }
}

impl Perspective for Wiring {
    fn map_to_blocks<T>(
        a: Vec<T>,
        b: Vec<T>,
        c: Vec<T>,
        d: Vec<T>,
        n: usize,
    ) -> Vec<(usize, Vec<T>)> {
        // Wiring swaps a<->b and c<->d relative to Trace:
        //   a[i] -> degree 2*n-1-i   (b's trace mapping)
        //   b[i] -> degree 2*n+i     (a's trace mapping)
        //   c[i] -> degree 4*n-1-i   (d's trace mapping)
        //   d[i] -> degree i         (c's trace mapping)
        Trace::map_to_blocks(b, a, d, c, n)
    }
}

/// A builder for constructing a [`Polynomial`] from gate-indexed wire values.
///
/// Fill the wire buffers (`a`, `b`, `c`, `d`) by gate index, then call
/// [`build`](Self::build) to map them to degree positions. Use
/// [`trace`](Self::trace) for trace polynomials or
/// [`wiring`](Self::wiring) for wiring polynomials.
///
/// Each wire buffer must have at most `R::n()` entries. This invariant is
/// enforced by [`build`](Self::build), which panics if any buffer exceeds the
/// limit.
pub struct View<T, R: Rank, P: Perspective> {
    /// The A wires of multiplication gates. Must have at most `R::n()` entries.
    pub a: Vec<T>,

    /// The B wires of multiplication gates. Must have at most `R::n()` entries.
    pub b: Vec<T>,

    /// The C wires of multiplication gates. Must have at most `R::n()` entries.
    pub c: Vec<T>,

    /// The D wires of multiplication gates. Must have at most `R::n()` entries.
    pub d: Vec<T>,

    _marker: PhantomData<(R, P)>,
}

impl<T, R: Rank> View<T, R, Trace> {
    /// Creates a new empty trace view.
    pub fn trace() -> Self {
        Self {
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
            d: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<T, R: Rank> View<T, R, Wiring> {
    /// Creates a new empty wiring view.
    pub fn wiring() -> Self {
        Self {
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
            d: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<F: Field, R: Rank, P: Perspective> View<F, R, P> {
    /// Consumes this view, mapping wire buffers to degree positions and
    /// producing a [`Polynomial`].
    ///
    /// Raw blocks are compressed via `extend_runs` (stripping leading/trailing
    /// zeros and splitting interior zero gaps exceeding `GAP_TOLERANCE`) before
    /// final validation.
    ///
    /// # Panics
    ///
    /// Panics if any wire buffer exceeds `R::n()` entries (one entry per
    /// multiplication gate).
    pub fn build(self) -> Polynomial<F, R> {
        let n = R::n();
        assert!(
            self.a.len() <= n,
            "a buffer length {} exceeds n={n}",
            self.a.len()
        );
        assert!(
            self.b.len() <= n,
            "b buffer length {} exceeds n={n}",
            self.b.len()
        );
        assert!(
            self.c.len() <= n,
            "c buffer length {} exceeds n={n}",
            self.c.len()
        );
        assert!(
            self.d.len() <= n,
            "d buffer length {} exceeds n={n}",
            self.d.len()
        );

        let raw_blocks = P::map_to_blocks(self.a, self.b, self.c, self.d, n);
        let mut blocks = Vec::with_capacity(raw_blocks.len());
        for (start, data) in raw_blocks {
            extend_runs(&mut blocks, start, data);
        }
        Polynomial::from_blocks(blocks)
    }
}
