//! Headers are succinct representations of data used to represent the current
//! state of a computation.

use ff::Field;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::GadgetKind,
};
use ragu_primitives::io::Write;

use core::any::Any;

/// The number of prefixes used internally by Ragu.
///
/// * `0` is reserved for all circuits that have a fixed ID, used internally for
///   recursion. This is not used by actual [`Header`] implementations.
/// * `1` is reserved for the trivial header.
const NUM_INTERNAL_PREFIXES: u8 = 2;

/// Internal representation of a [`Prefix`] distinguishing internal vs.
/// application prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
enum HeaderPrefix {
    Internal(usize),
    Application(usize),
}

/// The unique prefix for a [`Header`].
///
/// All steps register an `Output` header that represents their computational
/// state. In order to distinguish headers (regardless of the step that produced
/// them) a prefix is added to each header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct Prefix {
    prefix: HeaderPrefix,
}

impl Prefix {
    /// Creates a new application-defined [`Header`] prefix.
    pub const fn new(value: usize) -> Self {
        Prefix {
            prefix: HeaderPrefix::Application(value),
        }
    }

    /// Obtain this prefix's `u64` value based on whether this represents an
    /// internal or application [`Header`] prefix.
    pub(crate) fn get(&self) -> u64 {
        match self.prefix {
            HeaderPrefix::Internal(i) => i as u64,
            HeaderPrefix::Application(i) => (i + NUM_INTERNAL_PREFIXES as usize) as u64,
        }
    }

    /// Creates a new internal-defined [`Header`] prefix. Only called internally
    /// by Ragu.
    pub(crate) const fn internal(value: usize) -> Self {
        if value >= NUM_INTERNAL_PREFIXES as usize {
            panic!("invalid internal header prefix index");
        }

        Prefix {
            prefix: HeaderPrefix::Internal(value),
        }
    }
}

#[test]
fn test_prefix_map() {
    assert_eq!(Prefix::internal(0).get(), 0);
    assert_eq!(Prefix::internal(1).get(), 1);
    assert_eq!(Prefix::new(0).get(), 2);
    assert_eq!(Prefix::new(1).get(), 3);
}

/// Headers are succinct representations of data, essentially used as public
/// inputs to recursive proofs in order to represent the current state of the
/// computation.
pub trait Header<F: Field>: Send + Sync + Any {
    /// Each header should use a unique prefix to distinguish itself from other
    /// headers.
    const PREFIX: Prefix;

    /// The data needed to encode a header.
    type Data<'source>: Send + Clone;

    /// The output gadget that encodes the data for this header.
    type Output: Write<F>;

    /// Encode some data into a gadget representing this header.
    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        dr: &mut D,
        witness: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>>;
}

/// Trivial header that encodes no data.
impl<F: Field> Header<F> for () {
    const PREFIX: Prefix = Prefix::internal(1);

    type Data<'source> = ();
    type Output = ();

    fn encode<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        _: &mut D,
        _: DriverValue<D, Self::Data<'source>>,
    ) -> Result<<Self::Output as GadgetKind<F>>::Rebind<'dr, D>> {
        Ok(())
    }
}
