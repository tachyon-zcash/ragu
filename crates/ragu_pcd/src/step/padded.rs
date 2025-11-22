use ff::PrimeField;
use ragu_core::{
    Result,
    drivers::Driver,
    gadgets::{Gadget, GadgetKind},
};
use ragu_primitives::{
    Element, GadgetExt,
    io::{Buffer, Write},
};

use core::marker::PhantomData;

use super::Header;

#[derive(Gadget)]
pub struct Padded<'dr, D: Driver<'dr>, G: GadgetKind<D::F> + Write<D::F>, const HEADER_SIZE: usize>
{
    #[ragu(gadget)]
    prefix: Element<'dr, D>,
    #[ragu(gadget)]
    gadget: G::Rebind<'dr, D>,
}

/// Constructs a [`Padded`] gadget representing a gadget for a [`Header`] padded
/// to some fixed size `HEADER_SIZE` encoding, including the header prefix.
pub fn for_header<'dr, H: Header<D::F>, const HEADER_SIZE: usize, D: Driver<'dr, F: PrimeField>>(
    dr: &mut D,
    gadget: <H::Output as GadgetKind<D::F>>::Rebind<'dr, D>,
) -> Result<Padded<'dr, D, H::Output, HEADER_SIZE>> {
    Ok(Padded {
        prefix: Element::constant(dr, D::F::from(H::PREFIX.get())),
        gadget,
    })
}

impl<F: PrimeField, G: GadgetKind<F> + Write<F>, const HEADER_SIZE: usize> Write<F>
    for Padded<'static, PhantomData<F>, G, HEADER_SIZE>
{
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Self::Rebind<'dr, D>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        // Create a buffer that intercepts the data being written and counts it,
        // prohibiting more than HEADER_SIZE writes.
        let mut counting = CountingBuffer::<B, HEADER_SIZE> {
            written: 0,
            inner: buf,
        };

        this.prefix.write(dr, &mut counting)?;
        this.gadget.write(dr, &mut counting)?;

        // Add padding to the header until we reach HEADER_SIZE.
        while counting.written < HEADER_SIZE {
            Element::zero(dr).write(dr, &mut counting)?;
        }

        Ok(())
    }
}

struct CountingBuffer<'a, B, const N: usize> {
    written: usize,
    inner: &'a mut B,
}

impl<'dr, D, B, const N: usize> Buffer<'dr, D> for CountingBuffer<'_, B, N>
where
    D: Driver<'dr>,
    B: Buffer<'dr, D>,
{
    fn write(&mut self, dr: &mut D, value: &Element<'dr, D>) -> Result<()> {
        if self.written >= N {
            return Err(ragu_core::Error::MalformedEncoding(
                alloc::format!("Header encoding size exceeded HEADER_SIZE ({})", N,).into(),
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
        vec::{ConstLen, FixedVec},
    };

    use super::Padded;

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
            blah: FixedVec::try_from(vec![
                Element::alloc(dr, Always::maybe_just(|| F::from(1u64)))?,
                Element::alloc(dr, Always::maybe_just(|| F::from(2u64)))?,
                Element::alloc(dr, Always::maybe_just(|| F::from(3u64)))?,
                Element::alloc(dr, Always::maybe_just(|| F::from(4u64)))?,
            ])
            .unwrap(),
        };

        {
            let padded_gadget = Padded::<'_, _, Kind![F; MySillyGadget<'_, _>], 6> {
                prefix: Element::constant(dr, F::from(42u64)),
                gadget: gadget.clone(),
            };
            let mut buffer = vec![];
            padded_gadget.write(dr, &mut buffer)?;

            assert_eq!(buffer.len(), 6);
            assert_eq!(*buffer[0].value().take(), F::from(42u64));
            assert_eq!(*buffer[1].value().take(), F::from(1u64));
            assert_eq!(*buffer[2].value().take(), F::from(2u64));
            assert_eq!(*buffer[3].value().take(), F::from(3u64));
            assert_eq!(*buffer[4].value().take(), F::from(4u64));
            assert_eq!(*buffer[5].value().take(), F::from(0u64));
        }

        Ok(())
    }

    #[test]
    fn test_exceeding_buffer() -> Result<()> {
        let mut dr = Emulator::execute();
        let dr = &mut dr;
        let gadget = MySillyGadget {
            blah: FixedVec::try_from(vec![
                Element::alloc(dr, Always::maybe_just(|| F::from(1u64)))?,
                Element::alloc(dr, Always::maybe_just(|| F::from(2u64)))?,
                Element::alloc(dr, Always::maybe_just(|| F::from(3u64)))?,
                Element::alloc(dr, Always::maybe_just(|| F::from(4u64)))?,
            ])
            .unwrap(),
        };

        {
            let padded_gadget = Padded::<'_, _, Kind![F; MySillyGadget<'_, _>], 4> {
                prefix: Element::constant(dr, F::from(42u64)),
                gadget: gadget.clone(),
            };
            let mut buffer = vec![];
            assert!(padded_gadget.write(dr, &mut buffer).is_err());
        }

        Ok(())
    }
}
