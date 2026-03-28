//! Builder for constructing a [`Polynomial`] from gate-indexed wire values.
//!
//! A [`View`] provides four dense wire buffers (`a`, `b`, `c`, `d`) that the
//! caller fills in at gate indices. Calling [`View::build`] maps each buffer
//! to the appropriate degree positions and produces a [`Polynomial`].
//!
//! # Perspectives
//!
//! Here $n$ = `R::n()` is the maximum number of multiplication gates.
//!
//! - **[`Forward`]**: the standard perspective for trace polynomials $r(X)$.
//!   - `a[i]` maps to degree $2n + i$
//!   - `b[i]` maps to degree $2n - 1 - i$
//!   - `c[i]` maps to degree $i$
//!   - `d[i]` maps to degree $4n - 1 - i$
//!
//! - **[`Backward`]**: the reversed perspective for wiring polynomials
//!   $s(X, y)$. Swaps `a` with `b` and `c` with `d` in the degree mapping.
//!   - `a[i]` maps to degree $2n - 1 - i$
//!   - `b[i]` maps to degree $2n + i$
//!   - `c[i]` maps to degree $4n - 1 - i$
//!   - `d[i]` maps to degree $i$
//!
//! # Usage
//!
//! ```ignore
//! let mut view = View::forward();
//! view.a.push(some_value);
//! view.b.push(other_value);
//! view.c.push(product);
//! let poly = view.build();
//! ```

use alloc::vec::Vec;
use core::marker::PhantomData;

use super::{Polynomial, Rank};

mod private {
    pub trait Sealed {}
    impl Sealed for super::Forward {}
    impl Sealed for super::Backward {}
}

/// Marker trait for the perspective of a [`View`].
pub trait Perspective: private::Sealed {
    /// Maps the four wire buffers to three `(offset, data)` blocks
    /// corresponding to the lo, mid, and hi degree regions.
    ///
    /// The `n` parameter is `R::n()` (the maximum number of multiplication
    /// gates).
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
    ) -> [(usize, Vec<T>); 3];
}

/// Standard perspective: `a[i]` maps to degree $2n + i$, `b[i]` to
/// $2n - 1 - i$, `c[i]` to $i$, and `d[i]` to $4n - 1 - i$.
pub struct Forward;

/// Reversed perspective: swaps `a` with `b` and `c` with `d` relative to
/// [`Forward`]. See the [module documentation](self) for the full degree
/// mapping.
pub struct Backward;

impl Perspective for Forward {
    fn map_to_blocks<T>(
        a: Vec<T>,
        mut b: Vec<T>,
        c: Vec<T>,
        mut d: Vec<T>,
        n: usize,
    ) -> [(usize, Vec<T>); 3] {
        // c[i] -> degree i             (range [0, c.len()))
        // b[i] -> degree 2*n-1-i       (reversed, range [2*n-b.len(), 2*n))
        // a[i] -> degree 2*n+i         (range [2*n, 2*n+a.len()))
        // d[i] -> degree 4*n-1-i       (reversed, range [4*n-d.len(), 4*n))
        b.reverse();
        d.reverse();

        // b_rev and a are adjacent at the 2n boundary, forming the mid segment
        let mid_offset = 2 * n - b.len();
        let mut mid = b;
        mid.extend(a);

        let hi_offset = 4 * n - d.len();

        [(0, c), (mid_offset, mid), (hi_offset, d)]
    }
}

impl Perspective for Backward {
    fn map_to_blocks<T>(
        a: Vec<T>,
        b: Vec<T>,
        c: Vec<T>,
        d: Vec<T>,
        n: usize,
    ) -> [(usize, Vec<T>); 3] {
        // Backward swaps a<->b and c<->d relative to Forward:
        //   a[i] -> degree 2*n-1-i   (b's forward mapping)
        //   b[i] -> degree 2*n+i     (a's forward mapping)
        //   c[i] -> degree 4*n-1-i   (d's forward mapping)
        //   d[i] -> degree i         (c's forward mapping)
        Forward::map_to_blocks(b, a, d, c, n)
    }
}

/// A builder for constructing a [`Polynomial`] from gate-indexed wire values.
///
/// Fill the wire buffers (`a`, `b`, `c`, `d`) by gate index, then call
/// [`build`](Self::build) to map them to degree positions. Use
/// [`forward`](Self::forward) for trace polynomials or
/// [`backward`](Self::backward) for wiring polynomials.
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

impl<T, R: Rank> View<T, R, Forward> {
    /// Creates a new empty forward view.
    pub fn forward() -> Self {
        Self {
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
            d: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<T, R: Rank> View<T, R, Backward> {
    /// Creates a new empty backward view.
    pub fn backward() -> Self {
        Self {
            a: Vec::new(),
            b: Vec::new(),
            c: Vec::new(),
            d: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<T, R: Rank, P: Perspective> View<T, R, P> {
    /// Consumes this view, mapping wire buffers to degree positions and
    /// producing a [`Polynomial`].
    ///
    /// # Panics
    ///
    /// Panics if any wire buffer exceeds `R::n()` entries (one entry per
    /// multiplication gate).
    pub fn build(self) -> Polynomial<T, R> {
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

        Polynomial::from_blocks(P::map_to_blocks(self.a, self.b, self.c, self.d, n))
    }
}
