//! Modules for evaluating the wiring polynomial $s(X, Y)$.
//!
//! # Background
//!
//! Circuits are fully described by [wiring polynomials] that encode their
//! linear constraints, and all linear constraints are determined by a sequence
//! of [`enforce_zero`] calls made during circuit synthesis. In each such call,
//! a new univariate polynomial in $X$ (representing the constraint over the
//! wires) is added to $s(X, Y)$ as a separate term weighted by $Y$ to keep
//! constraints linearly independent.
//!
//! The full wiring polynomial $s(X, Y)$ can be written as
//!
//! $$
//! s(X, Y) = \sum_{j = 0}^{q - 1} Y^j \left(\sum_{i = 0}^{n - 1} (
//!   \mathbf{u}\_{i,j} X^{2n - 1 - i} +
//!   \mathbf{v}\_{i,j} X^{2n + i} +
//!   \mathbf{w}\_{i,j} X^{4n - 1 - i}
//! )\right)
//! $$
//!
//! where $\mathbf{u}, \mathbf{v}, \mathbf{w}$ are fixed coefficient matrices
//! determined by the `enforce_zero` (and indirectly,
//! [`add`](ragu_core::drivers::Driver::add)) calls.
//!
//! ### Circuit Synthesis
//!
//! Naively, one could pre-compute $s(X, Y)$ as a bivariate polynomial for each
//! circuit and then evaluate it as needed. However, this is inefficient in both
//! time and space, as $s(X, Y)$ can be very large, and we never actually need
//! it written explicitly.
//!
//! The design of the [`Driver`] trait is meant to accommodate a direct
//! synthesis approach, whereby the circuit code is interpreted by a specialized
//! driver to evaluate $s(X, Y)$ at arbitrary points without ever constructing
//! the full polynomial. Drivers define their own wire type, and so naturally we
//! can represent wires as the (partial) polynomial evaluations they correspond
//! to. This can avoid unnecessary allocations and redundant arithmetic.
//!
//! ### Memoizations
//!
//! Further, because circuit code will often repeatedly invoke the same (or
//! nearly identical) operations during synthesis, we can cache large portions
//! of the intermediate polynomial evaluations produced and consumed by our
//! specialized drivers. This behavior will vary by context, but two similar
//! sequences of operations may produce interstitial evaluations that are
//! related by simple linear transformations.
//!
//! One of the purposes of the [`Routine`] trait is to allow circuit code to
//! indicate which sections of synthesis are likely to be repeated with similar
//! inputs and to provide guarantees about those inputs that drivers can safely
//! exploit to memoize.
//!
//! # Overview
//!
//! This module provides implementations that interpret circuit code directly
//! (via specialized [`Driver`] implementations) to evaluate $s(X, Y)$ at
//! specific restrictions more efficiently:
//!
//! * [`sx`]: Evaluates $s(X, Y)$ at $X = x$ for some $x \in \mathbb{F}$.
//! * [`sy`]: Evaluates $s(X, Y)$ at $Y = y$ for some $y \in \mathbb{F}$.
//! * [`sxy`]: Evaluates $s(X, Y)$ at $(x, y)$ for some $x, y \in \mathbb{F}$.
//!
//! [`Driver`]: ragu_core::drivers::Driver
//! [`Routine`]: ragu_core::routines::Routine
//! [`enforce_zero`]: ragu_core::drivers::Driver::enforce_zero
//! [wiring polynomials]: http://TODO

mod common;
pub mod sx;
pub mod sxy;
pub mod sy;
