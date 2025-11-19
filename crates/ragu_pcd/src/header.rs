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
const INTERNAL_HEADER_PREFIXES: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
enum HeaderPrefix {
    Internal(usize),
    Application(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub struct Prefix {
    prefix: HeaderPrefix,
}

impl Prefix {
    /// Creates a new application-defined header prefix.
    pub const fn new(value: usize) -> Self {
        Prefix {
            prefix: HeaderPrefix::Application(value),
        }
    }

    /// Creates a new internal header prefix, used by Ragu itself.
    pub(crate) const fn internal(value: usize) -> Self {
        if value >= INTERNAL_HEADER_PREFIXES as usize {
            panic!("invalid internal step index");
        }

        Prefix {
            prefix: HeaderPrefix::Internal(value),
        }
    }

    /// Maps this prefix to the "actual" prefix used internally by Ragu to
    /// globally distinguish internal and application headers.
    pub(crate) fn map(&self) -> usize {
        match self.prefix {
            HeaderPrefix::Internal(i) => i,
            HeaderPrefix::Application(i) => i + INTERNAL_HEADER_PREFIXES as usize,
        }
    }
}

#[test]
fn test_prefix_map() {
    assert_eq!(Prefix::internal(0).map(), 0);
    assert_eq!(Prefix::internal(1).map(), 1);
    assert_eq!(Prefix::new(0).map(), 2);
    assert_eq!(Prefix::new(1).map(), 3);
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
