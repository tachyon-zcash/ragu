//! Developer APIs for PCD applications using Ragu.
//!
//! This crate provides simplified [`Step`] and [`HeaderContent`] traits that
//! application developers implement. The `#[application]` proc-macro (from
//! `ragu_macros`) then generates:
//!
//! - [`ragu_pcd::header::Header`] impls with auto-assigned `const SUFFIX`
//!   values from each [`HeaderContent`] impl
//! - [`ragu_pcd::step::Step`] impls with `const INDEX` and `Encoded` bridging
//!   from each [`Step`] impl
//! - A wrapper struct with typed `build()`/`seed()`/`fuse()`/`verify()`/
//!   `rerandomize()` methods

#![no_std]
#![allow(clippy::type_complexity)]
#![deny(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![doc(html_favicon_url = "https://tachyon.z.cash/assets/ragu/v1/favicon-32x32.png")]
#![doc(html_logo_url = "https://tachyon.z.cash/assets/ragu/v1/rustdoc-128x128.png")]

pub use ff::Field;
pub use ragu_arithmetic::Cycle;
pub use ragu_circuits::polynomials::Rank;
pub use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Bound,
};
pub use ragu_macros::{application, header};
pub use ragu_pcd::header::Header;
pub use ragu_primitives::io::Write;

/// Re-exports used by `#[application]` and `#[header]` generated code.
/// Not public API.
#[doc(hidden)]
pub mod __macro_internal {
    pub use ::ff::Field;
    pub use ::rand::CryptoRng;
    pub use ragu_circuits::polynomials::Rank;
    pub use ragu_core::{
        Result,
        drivers::{Driver, DriverValue},
        gadgets::{Bound, Kind},
    };
    pub use ragu_pcd::{
        Application, ApplicationBuilder, Pcd,
        header::{Header, Suffix},
        step::{Encoded, Index, Step as PcdStep},
    };
}

/// Simplified header trait for application developers.
///
/// Unlike [`ragu_pcd::header::Header`], this trait has no `const SUFFIX`.
/// The [`#[application]`](macro@application) macro generates the full
/// [`ragu_pcd::header::Header`] impl with auto-assigned suffix values based
/// on declaration order.
///
/// # Using `#[header]` for single-gadget headers
///
/// Most headers allocate a single gadget from their witness data. For these
/// cases, the [`#[header]`](macro@header) attribute macro generates the entire
/// `HeaderContent` implementation automatically:
///
/// ```ignore
/// use ragu_app::header;
/// use ragu_primitives::Element;
///
/// /// A leaf node carrying a hashed field element.
/// #[header(data = F, gadget = Element)]
/// pub struct LeafNode;
/// ```
///
/// This generates a generic `impl<F: Field> HeaderContent<F>` where `encode()`
/// calls `Element::alloc(dr, witness)`. When the gadget carries additional
/// type parameters — such as a curve type — `data` alone cannot serve as the
/// field parameter. In that case, provide an explicit `field`:
///
/// ```ignore
/// use ragu_app::header;
/// use ragu_primitives::Point;
///
/// /// A header carrying a curve point.
/// #[header(data = EpAffine, gadget = Point<EpAffine>, field = Fp)]
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
///     fn encode<'dr, D: Driver<'dr, F = F>>(
///         dr: &mut D,
///         witness: DriverValue<D, Self::Data>,
///     ) -> Result<Bound<'dr, D, Self::Output>> {
///         let root = witness.map(|tree| tree.root());
///         Element::alloc(dr, root)
///     }
/// }
/// ```
pub trait HeaderContent<F: Field>: Send + Sync + 'static {
    /// The data needed to encode a header.
    type Data: Send + Clone;

    /// The output gadget that encodes the data for this header.
    type Output: Write<F>;

    /// Encode some data into a gadget representing this header.
    fn encode<'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>>;
}

/// Simplified step trait for application developers.
///
/// Unlike [`ragu_pcd::step::Step`], this trait has no `const INDEX` and works
/// with pre-encoded header gadgets (`&Bound<...>`) instead of raw `Encoded`
/// types. The `#[application]` macro generates the full [`ragu_pcd::step::Step`]
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
