use ff::{Field, PrimeField};
use ragu_core::{
    Result,
    drivers::Driver,
    gadgets::{Bound, Gadget, GadgetKind, Kind},
};
use ragu_primitives::{
    Element, GadgetExt,
    io::{Buffer, Write},
};

use core::marker::PhantomData;

use crate::Header;
use crate::components::suffix::WithSuffix;

/// A header gadget padded to a fixed size with a suffix element appended.
///
/// The serialization order is `[gadget_data | zeros | suffix]`:
/// - First, the header gadget data
/// - Then, zero padding to fill up to `HEADER_SIZE - 1` elements
/// - Finally, the suffix element at position `HEADER_SIZE - 1`
#[derive(Gadget, Write)]
pub(crate) struct Padded<
    'dr,
    D: Driver<'dr>,
    G: GadgetKind<D::F> + Write<D::F>,
    const HEADER_SIZE: usize,
> {
    #[ragu(gadget)]
    inner: WithSuffix<'dr, D, Kind![D::F; PaddedContent<'_, _, G, HEADER_SIZE>]>,
}

/// Constructs a [`Padded`] gadget representing a gadget for a [`Header`] padded
/// to some fixed size `HEADER_SIZE` encoding, including the header suffix.
pub(crate) fn for_header<
    'dr,
    H: Header<D::F>,
    const HEADER_SIZE: usize,
    D: Driver<'dr, F: PrimeField>,
>(
    dr: &mut D,
    gadget: Bound<'dr, D, H::Output>,
) -> Result<Padded<'dr, D, H::Output, HEADER_SIZE>> {
    let padded_content = PaddedContent { gadget };
    let suffix = Element::constant(dr, D::F::from(H::SUFFIX.get()));
    Ok(Padded {
        inner: WithSuffix::new(padded_content, suffix),
    })
}

/// Inner gadget that writes the header gadget followed by zero padding up to
/// `HEADER_SIZE - 1` elements (reserving space for the suffix).
#[derive(Gadget)]
pub(crate) struct PaddedContent<
    'dr,
    D: Driver<'dr>,
    G: GadgetKind<D::F> + Write<D::F>,
    const HEADER_SIZE: usize,
> {
    #[ragu(gadget)]
    gadget: Bound<'dr, D, G>,
}

impl<F: Field, G: GadgetKind<F> + Write<F>, const HEADER_SIZE: usize> Write<F>
    for PaddedContent<'static, PhantomData<F>, G, HEADER_SIZE>
{
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Bound<'dr, D, Self>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        // Create a buffer that intercepts the data being written and counts it,
        // prohibiting more than HEADER_SIZE - 1 writes (reserving space for
        // suffix).
        let mut counting = CountingBuffer::<B, HEADER_SIZE> {
            written: 0,
            inner: buf,
        };

        this.gadget.write(dr, &mut counting)?;

        // Add padding to reach HEADER_SIZE - 1 elements (suffix will be added
        // after).
        while counting.written < HEADER_SIZE - 1 {
            Element::zero(dr).write(dr, &mut counting)?;
        }

        Ok(())
    }
}

struct CountingBuffer<'a, B, const HEADER_SIZE: usize> {
    written: usize,
    inner: &'a mut B,
}

impl<'dr, D, B, const HEADER_SIZE: usize> Buffer<'dr, D> for CountingBuffer<'_, B, HEADER_SIZE>
where
    D: Driver<'dr>,
    B: Buffer<'dr, D>,
{
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        // Limit is N - 1 to reserve space for the suffix element
        if self.written >= HEADER_SIZE - 1 {
            return Err(ragu_core::Error::MalformedEncoding(
                alloc::format!(
                    "Header encoding size exceeded HEADER_SIZE - 1 ({})",
                    HEADER_SIZE - 1,
                )
                .into(),
            ));
        }
        self.inner.write(dr, value)?;
        self.written += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::{
        Result,
        drivers::{Driver, emulator::Emulator},
        gadgets::{Gadget, Kind},
        maybe::{Always, Maybe, MaybeKind},
    };
    use ragu_pasta::Fp as F;
    use ragu_primitives::{
        Element, GadgetExt,
        io::Write,
        vec::{CollectFixed, ConstLen, FixedVec},
    };

    use super::Padded;
    use crate::components::suffix::WithSuffix;

    #[derive(Gadget, Write)]
    struct MySillyGadget<'dr, D: Driver<'dr>> {
        #[ragu(gadget)]
        blah: FixedVec<Element<'dr, D>, ConstLen<4>>,
    }

    #[test]
    fn test_write() -> Result<()> {
        let mut dr = Emulator::execute();
        let dr = &mut dr;
        let gadget = MySillyGadget {
            blah: (1u64..=4)
                .map(|n| Element::alloc(dr, Always::maybe_just(|| F::from(n))))
                .try_collect_fixed()?,
        };

        {
            // Create Padded gadget with suffix value 42
            let padded_content = super::PaddedContent::<'_, _, Kind![F; MySillyGadget<'_, _>], 6> {
                gadget: gadget.clone(),
            };
            let padded_gadget = Padded::<'_, _, Kind![F; MySillyGadget<'_, _>], 6> {
                inner: WithSuffix::new(padded_content, Element::constant(dr, F::from(42u64))),
            };
            let mut buffer = vec![];
            padded_gadget.write(dr, &mut buffer)?;

            // Expected: [1, 2, 3, 4, 0, 42] - gadget data, zero padding, suffix
            assert_eq!(buffer.len(), 6);
            assert_eq!(*buffer[0].value().take(), F::from(1u64));
            assert_eq!(*buffer[1].value().take(), F::from(2u64));
            assert_eq!(*buffer[2].value().take(), F::from(3u64));
            assert_eq!(*buffer[3].value().take(), F::from(4u64));
            assert_eq!(*buffer[4].value().take(), F::from(0u64));
            assert_eq!(*buffer[5].value().take(), F::from(42u64)); // suffix at end
        }

        Ok(())
    }

    #[test]
    fn test_exceeding_buffer() -> Result<()> {
        let mut dr = Emulator::execute();
        let dr = &mut dr;
        let gadget = MySillyGadget {
            blah: (1u64..=4)
                .map(|n| Element::alloc(dr, Always::maybe_just(|| F::from(n))))
                .try_collect_fixed()?,
        };

        {
            // HEADER_SIZE=4 means only 3 elements for content (4 - 1 for suffix)
            // But gadget has 4 elements, so it should fail
            let padded_content = super::PaddedContent::<'_, _, Kind![F; MySillyGadget<'_, _>], 4> {
                gadget: gadget.clone(),
            };
            let padded_gadget = Padded::<'_, _, Kind![F; MySillyGadget<'_, _>], 4> {
                inner: WithSuffix::new(padded_content, Element::constant(dr, F::from(42u64))),
            };
            let mut buffer = vec![];
            assert!(padded_gadget.write(dr, &mut buffer).is_err());
        }

        Ok(())
    }
}
