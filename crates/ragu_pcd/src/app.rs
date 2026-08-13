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
pub use ragu_circuits::polynomials::Rank;
pub use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
};
pub use ragu_macros::{application, header};
pub use ragu_primitives::{
    allocator::{Allocator, Standard},
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
    pub use ragu_primitives::allocator::{Allocator, Standard};

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
/// Most headers allocate a single gadget from their witness data. For these
/// cases, the [`#[header]`](macro@header) attribute macro generates the entire
/// `HeaderContent` implementation automatically:
///
/// ```ignore
/// use ragu_pcd::app::header;
/// use ragu_primitives::Element;
///
/// /// A leaf node carrying a hashed field element.
/// #[header(data = F, gadget = Element)]
/// pub struct LeafNode;
/// ```
///
/// This generates a generic `impl<F: Field> HeaderContent<F>` where `encode()`
/// calls `Element::alloc(dr, allocator, witness)`. When the gadget carries
/// additional type parameters — such as a curve type — `data` alone cannot
/// serve as the field parameter. In that case, provide an explicit `field`.
/// For gadgets whose `alloc` constructor takes no allocator (such as
/// `Point`), add `alloc = direct`:
///
/// ```ignore
/// use ragu_pcd::app::header;
/// use ragu_primitives::Point;
///
/// /// A header carrying a curve point.
/// #[header(data = EpAffine, gadget = Point<EpAffine>, field = Fp, alloc = direct)]
/// pub struct ScaledPoint;
/// ```
///
/// # Manual implementation
///
/// Implement `HeaderContent` manually when `encode()` computes a derived value
/// from the witness data rather than encoding it directly — for example,
/// encoding a Merkle root from a full Merkle tree:
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
/// A PCD authenticates only the value represented by [`Self::Output`]. The
/// mapping from [`Self::Data`] may intentionally be non-injective (for example,
/// a full Merkle tree mapped to its root). Fields that `encode()` does not
/// constrain into the output are accompanying witness data, not authenticated
/// application state. Consumers must not treat those fields as proof-backed.
pub trait HeaderContent<F: Field>: Send + Sync + 'static {
    /// The data needed to encode a header.
    type Data: Send + Clone;

    /// The output gadget that encodes the data for this header.
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
    /// The two returned outputs describe the same header through different
    /// channels, and implementations must keep them in agreement: the gadget
    /// must serialize to exactly what encoding the data would produce, as if by
    /// [`Header::encode`] applied to the returned data.
    ///
    /// The gadget is what this proof commits to, while a parent step and
    /// [`Application::verify`](crate::Application::verify) both re-encode the
    /// carried data instead. Nothing checks the two against each other, so a
    /// mismatch is not reported where it is introduced: the step succeeds, the
    /// surrounding [`fuse`](crate::Application::fuse) succeeds, and only a later
    /// verification of the resulting PCD fails, by returning `Ok(false)` rather
    /// than an error naming this step.
    ///
    /// Deriving the returned data from the gadget, rather than recomputing it
    /// alongside, keeps the two in step by construction:
    ///
    /// ```ignore
    /// let output = sponge.squeeze(dr)?;
    /// let output_data = output.value().map(|v| *v);
    /// Ok((output, output_data, D::unit()))
    /// ```
    ///
    /// A header whose `encode` is deliberately non-injective, such as one
    /// mapping a Merkle tree to its root, must return data that encodes to the
    /// gadget under that same mapping; see [`HeaderContent`] for which parts of
    /// the data verification then authenticates.
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
