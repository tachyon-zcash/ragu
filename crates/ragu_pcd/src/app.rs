//! Developer APIs for PCD applications using Ragu.
//!
//! This module provides simplified [`Step`] and [`HeaderContent`] traits that
//! application developers implement. The `#[application]` proc-macro (from
//! `ragu_macros`) then generates:
//!
//! - [`crate::header::Header`] impls with auto-assigned `const SUFFIX`
//!   values from each [`HeaderContent`] impl
//! - [`crate::step::Step`] impls with `const INDEX` and `Encoded` bridging
//!   from each [`Step`] impl
//! - A wrapper struct with typed `build()`/`seed()`/`fuse()`/`verify()`/
//!   `rerandomize()` methods, sealed to the application's declared steps and
//!   headers
//!
//! # Future direction
//!
//! The [`Step`] trait, its associated types, and the `synthesize` scaffolding
//! are an interim shape: they still expose more machinery than an application
//! developer should have to care about. The intended long-term API is for
//! steps to be plain annotated functions, with the macros inferring
//! `Left`/`Right`/`Output` from the parameter and return types and
//! `Witness`/`Aux` from what the function consumes and produces:
//!
//! ```ignore
//! #[produces(LeafNode)]
//! fn witness_leaf(dr, witness: F, _left: (), _right: ()) {
//!     let leaf = Element::alloc(dr, allocator, witness)?;
//!     Ok(sponge.absorb_and_squeeze(dr, &leaf)?)
//! }
//! ```

pub use ragu_arithmetic::{Cycle, ff::Field};
pub use ragu_circuits::polynomials::{ProductionRank, Rank, TestRank};
pub use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe,
};
pub use ragu_macros::{application, header};
pub use ragu_primitives::{
    allocator::{Allocatable, Allocator, Standard},
    io::Write,
};

pub use crate::header::Header;

/// Re-exports used by `#[application]` and `#[header]` generated code.
/// Not public API.
#[doc(hidden)]
pub mod __macro_internal {
    pub use ragu_arithmetic::{CryptoRngCore, ff::Field};
    pub use ragu_circuits::polynomials::Rank;
    pub use ragu_core::{
        Error, Result,
        drivers::{Driver, DriverValue},
        gadgets::{Bound, Gadget, Kind},
    };
    pub use ragu_primitives::allocator::{Allocatable, Allocator, Standard};

    pub use crate::{
        Application, ApplicationBuilder, Pcd,
        header::{Header, Suffix},
        step::{Encoded, Index, Step as PcdStep},
    };
}

/// Simplified header trait for application developers.
///
/// Unlike [`crate::header::Header`], this trait has no `const SUFFIX`.
/// The [`#[application]`](macro@application) macro generates the full
/// [`crate::header::Header`] impl with auto-assigned suffix values based
/// on declaration order.
///
/// # Using `#[header]` for single-gadget headers
///
/// When `encode()` just allocates one gadget from the data, the
/// [`#[header]`](macro@header) attribute macro generates the whole impl from
/// the gadget alone — its kind's [`Allocatable`] impl supplies the witness
/// (`Data`) type, the constructor, and any field constraint:
///
/// ```ignore
/// use ragu_pcd::app::header;
/// use ragu_primitives::{Element, Point};
///
/// /// A leaf node carrying a hashed field element. Generic over every field.
/// #[header(gadget = Element)]
/// pub struct LeafNode;
///
/// /// A header carrying a curve point. The point kind is allocatable only
/// /// over the curve's base field, which pins this header to `Fp`.
/// #[header(gadget = Point<EpAffine>)]
/// pub struct ScaledPoint;
/// ```
///
/// # Manual implementation
///
/// Implement `HeaderContent` manually when `encode()` derives the committed
/// value from the data — for example, a Merkle root from a full tree:
///
/// ```ignore
/// pub struct MerkleRoot;
///
/// impl<F: Field> HeaderContent<F> for MerkleRoot {
///     // encode() receives the full tree but only commits the root hash.
///     type Data = MerkleTree<F>;
///     type Output = Kind![F; Element<'_, _>];
///
///     fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
///         dr: &mut D,
///         allocator: &mut A,
///         witness: DriverValue<D, Self::Data>,
///     ) -> Result<Bound<'dr, D, Self::Output>> {
///         let root = witness.map(|tree| tree.root());
///         Element::alloc(dr, allocator, root)
///     }
/// }
/// ```
///
/// # Authenticated data
///
/// A PCD authenticates only [`Self::Output`]. The mapping from [`Self::Data`]
/// may be non-injective (a full tree mapped to its root); whatever `encode()`
/// does not constrain into the output is unauthenticated witness data, never
/// proof-backed state.
pub trait HeaderContent<F: Field>: Send + Sync + 'static {
    /// The data needed to encode a header.
    type Data: Send + Clone;

    /// The output gadget that encodes the data for this header.
    ///
    /// Its serialized length must depend only on the header type: a
    /// data-dependent length lets two values pad to identical encodings,
    /// indistinguishable to a verifier.
    type Output: Write<F>;

    /// Encode some data into a gadget representing this header.
    ///
    /// Implementations should pass `allocator` through to all allocation
    /// calls rather than substituting a different allocator.
    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>>;
}

/// Simplified step trait for application developers.
///
/// Unlike [`crate::step::Step`], this trait has no `const INDEX` and works
/// with pre-encoded header gadgets (`&Bound<...>`) instead of raw `Encoded`
/// types. The `#[application]` macro generates the full [`crate::step::Step`]
/// impl that bridges between this trait and the internal encoding layer.
pub trait Step<C: Cycle>: Sized + Send + Sync {
    /// The witness data needed to construct a proof for this step.
    type Witness: Send;

    /// The "left" header expected during this step.
    type Left: Header<C::CircuitField>;

    /// The "right" header expected during this step.
    type Right: Header<C::CircuitField>;

    /// The header produced during this step.
    type Output: Header<C::CircuitField>;

    /// Auxiliary information produced during circuit synthesis that may be
    /// used to pipeline witness data to future steps.
    type Aux: Send;

    /// Constrain this step. Receives pre-encoded left/right header gadgets.
    ///
    /// Returns the output header gadget, the output data to carry in the
    /// resulting PCD, and any auxiliary witness data.
    ///
    /// # Agreement between the returned gadget and data
    ///
    /// The gadget and data must agree: the gadget must serialize to exactly
    /// the encoding of the data, as if by [`Header::encode`].
    ///
    /// The proof commits to the gadget, while a parent step and
    /// [`Application::verify`](crate::Application::verify) re-encode the
    /// carried data. Nothing cross-checks the two, so a mismatch surfaces only
    /// later: this step and the surrounding
    /// [`fuse`](crate::Application::fuse) succeed, and verification of the
    /// result returns `Ok(false)` without naming the culprit.
    ///
    /// Deriving the data from the gadget keeps them in agreement by
    /// construction:
    ///
    /// ```ignore
    /// let output = sponge.squeeze(dr)?;
    /// let output_data = output.value().map(|v| *v);
    /// Ok((output, output_data, D::unit()))
    /// ```
    ///
    /// A deliberately non-injective header (a tree mapped to its root) must
    /// return data that encodes to the gadget under that same mapping; see
    /// [`HeaderContent`] for what verification then authenticates.
    fn synthesize<'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness>,
        left: &Bound<'dr, D, <Self::Left as Header<C::CircuitField>>::Output>,
        right: &Bound<'dr, D, <Self::Right as Header<C::CircuitField>>::Output>,
    ) -> Result<(
        Bound<'dr, D, <Self::Output as Header<C::CircuitField>>::Output>,
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux>,
    )>
    where
        Self: 'dr;
}
