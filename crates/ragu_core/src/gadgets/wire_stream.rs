//! [`WireStream`], the gadget whose number of wires is known only at run
//! time.

use alloc::vec::Vec;
use core::marker::PhantomData;

use udon::field::Field;

use crate::{
    Error, Result,
    convert::WireMap,
    drivers::Driver,
    gadgets::{Bound, Gadget, GadgetKind, WireEqualizer},
};

/// A run of wires whose number is known only at run time.
///
/// Every other gadget of this crate has a number of wires that its type
/// fixes. A `WireStream` is for the code that cannot name that number when
/// it is written, such as a routine that replays a recording of another.
/// Its traversal visits the wires in order, so a stream of `n` wires is to
/// every driver what an array of `n` single wires is. Use an array wherever
/// the number is known when the code is written.
///
/// The wires carry no values. A routine that takes a `WireStream` and needs
/// the values of its wires must be given them another way, such as in a
/// value field beside the stream.
///
/// # Fungibility
///
/// A `WireStream` is [fungible]: its number of wires is its length, so that
/// number alone gives its shape (see [run-time-sized gadgets]). Two rules
/// are not held by the types, and the code that uses a `WireStream` must
/// hold them:
///
/// * The length is fixed by the code that builds the stream and never
///   depends on witness data, as nothing that affects emitted constraints
///   may.
/// * A gadget holds at most one `WireStream`. Two of them, as two fields or
///   as the elements of an array, have two lengths over one number of
///   wires: streams of one and two wires, and streams of two and one, are
///   two shapes over three wires. Such a gadget is not fungible.
///
/// [fungible]: crate::gadgets#fungibility
/// [run-time-sized gadgets]: crate::gadgets#run-time-sized-gadgets
pub struct WireStream<'dr, D: Driver<'dr>> {
    wires: Vec<D::Wire>,
    _marker: PhantomData<&'dr ()>,
}

/// The [`GadgetKind`] of a [`WireStream`].
pub struct WireStreamKind;

impl<'dr, D: Driver<'dr>> WireStream<'dr, D> {
    /// Returns the wires, in order.
    pub fn as_slice(&self) -> &[D::Wire] {
        &self.wires
    }

    /// Returns the number of wires.
    pub fn len(&self) -> usize {
        self.wires.len()
    }

    /// Returns `true` if the stream has no wires.
    pub fn is_empty(&self) -> bool {
        self.wires.is_empty()
    }
}

impl<'dr, D: Driver<'dr>> Clone for WireStream<'dr, D> {
    fn clone(&self) -> Self {
        self.wires.iter().cloned().collect()
    }
}

impl<'dr, D: Driver<'dr>> FromIterator<D::Wire> for WireStream<'dr, D> {
    fn from_iter<I: IntoIterator<Item = D::Wire>>(wires: I) -> Self {
        WireStream {
            wires: wires.into_iter().collect(),
            _marker: PhantomData,
        }
    }
}

impl<'dr, D: Driver<'dr>> IntoIterator for WireStream<'dr, D> {
    type Item = D::Wire;
    type IntoIter = alloc::vec::IntoIter<D::Wire>;

    fn into_iter(self) -> Self::IntoIter {
        self.wires.into_iter()
    }
}

impl<'dr, D: Driver<'dr>> Gadget<'dr, D> for WireStream<'dr, D> {
    type Kind = WireStreamKind;
}

/// Safety: a `WireStream` holds wires and nothing else, so it is `Send`
/// when `D::Wire` is `Send`.
unsafe impl<F: Field> GadgetKind<F> for WireStreamKind {
    type Rebind<'dr, D: Driver<'dr, F = F>> = WireStream<'dr, D>;

    /// Maps the wires in order.
    fn map_gadget<
        'src,
        'dst,
        WM: WireMap<F, Src: Driver<'src, F = F>, Dst: Driver<'dst, F = F>>,
    >(
        this: &Bound<'src, WM::Src, Self>,
        wm: &mut WM,
    ) -> Result<Bound<'dst, WM::Dst, Self>> {
        this.wires
            .iter()
            .map(|wire| wm.convert_wire(wire))
            .collect()
    }

    /// Pairs the wires in order.
    ///
    /// # Errors
    ///
    /// Fails if the two do not have the same length: they are not then
    /// instances of the same shape, and no pairing of their wires is
    /// defined.
    fn enforce_conservative_equal_gadget<
        'dr,
        D1: Driver<'dr, F = F>,
        D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
    >(
        eq: &mut WireEqualizer<'_, 'dr, D1>,
        a: &Bound<'dr, D2, Self>,
        b: &Bound<'dr, D2, Self>,
    ) -> Result<()> {
        if a.len() != b.len() {
            return Err(Error::VectorLengthMismatch {
                expected: a.len(),
                actual: b.len(),
            });
        }
        for (a, b) in a.wires.iter().zip(&b.wires) {
            eq.enforce_conservative_equal(a, b)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::{
        convert::extract_wires,
        drivers::emulator::{Emulator, Wired},
        pasta::Fp,
    };

    /// A driver whose wires are field elements, so that a test names each
    /// wire by a value of its own.
    type Dr = Emulator<Wired<Fp>>;

    /// One wire: what an array holds where a stream holds a wire.
    struct Wire<'dr, D: Driver<'dr>>(D::Wire, PhantomData<&'dr ()>);

    impl<'dr, D: Driver<'dr>> Clone for Wire<'dr, D> {
        fn clone(&self) -> Self {
            Wire(self.0.clone(), PhantomData)
        }
    }

    struct WireKind;

    impl<'dr, D: Driver<'dr>> Gadget<'dr, D> for Wire<'dr, D> {
        type Kind = WireKind;
    }

    /// Safety: `Wire` holds one wire and nothing else.
    unsafe impl<F: Field> GadgetKind<F> for WireKind {
        type Rebind<'dr, D: Driver<'dr, F = F>> = Wire<'dr, D>;

        fn map_gadget<
            'src,
            'dst,
            WM: WireMap<F, Src: Driver<'src, F = F>, Dst: Driver<'dst, F = F>>,
        >(
            this: &Bound<'src, WM::Src, Self>,
            wm: &mut WM,
        ) -> Result<Bound<'dst, WM::Dst, Self>> {
            Ok(Wire(wm.convert_wire(&this.0)?, PhantomData))
        }

        fn enforce_conservative_equal_gadget<
            'dr,
            D1: Driver<'dr, F = F>,
            D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
        >(
            eq: &mut WireEqualizer<'_, 'dr, D1>,
            a: &Bound<'dr, D2, Self>,
            b: &Bound<'dr, D2, Self>,
        ) -> Result<()> {
            eq.enforce_conservative_equal(&a.0, &b.0)
        }
    }

    /// The stream that holds the wires `values` name, in order.
    fn by_hand<'dr>(values: &[u64]) -> WireStream<'dr, Dr> {
        values.iter().map(|&value| Fp::from(value)).collect()
    }

    fn stream_of<'dr, G: Gadget<'dr, Dr>>(gadget: &G) -> Vec<Fp> {
        extract_wires(gadget, |wire: &Fp| *wire).expect("extraction does not fail")
    }

    /// Hands out the wires of a stream in order, whatever wire it is given.
    struct Injector<'a>(core::slice::Iter<'a, Fp>);

    impl WireMap<Fp> for Injector<'_> {
        type Src = Dr;
        type Dst = Dr;

        fn convert_wire(&mut self, _: &Fp) -> Result<Fp> {
            self.0
                .next()
                .copied()
                .ok_or_else(|| Error::InvalidWitness("the stream ran out".into()))
        }
    }

    /// Allocation determinism: the `WireStream` that holds `wires`, from
    /// the kind and the wires alone. Their number gives the length, and an
    /// instance of that length, whatever its wires, gives the rest.
    fn assemble<'dr>(wires: &[Fp]) -> Result<WireStream<'dr, Dr>> {
        let blank = by_hand(&vec![0; wires.len()]);
        let mut injector = Injector(wires.iter());
        let assembled = blank.map(&mut injector)?;
        assert!(injector.0.next().is_none());
        Ok(assembled)
    }

    #[test]
    fn an_empty_stream_has_no_wires() -> Result<()> {
        let empty = by_hand(&[]);
        assert!(empty.is_empty());
        assert_eq!(empty.num_wires()?, 0);
        assert!(stream_of(&empty).is_empty());
        assert!(assemble(&[])?.is_empty());
        Ok(())
    }

    #[test]
    fn streams_of_unequal_length_are_not_paired() -> Result<()> {
        let mut dr = Dr::extractor();
        let (two, three) = (by_hand(&[1, 2]), by_hand(&[1, 2, 3]));
        assert!(matches!(
            two.enforce_conservative_equal(&mut dr, &three),
            Err(Error::VectorLengthMismatch {
                expected: 2,
                actual: 3
            })
        ));
        two.enforce_conservative_equal(&mut dr, &two.clone())
    }

    /// Why a gadget holds at most one stream. A pair of streams has two
    /// run-time lengths, and instances of different shapes over the same
    /// wires: the wires do not give the shape. The types do not refuse the
    /// pair.
    #[test]
    fn two_streams_are_not_told_apart_by_their_wires() {
        let a = (by_hand(&[1]), by_hand(&[2, 3]));
        let b = (by_hand(&[1, 2]), by_hand(&[3]));
        assert_eq!(stream_of(&a), stream_of(&b));
        assert_ne!(a.0.len(), b.0.len());
    }

    mod proptests {
        use proptest::prelude::*;

        use super::*;

        /// The wires of a stream of up to 120, each named by a value.
        fn streams() -> impl Strategy<Value = Vec<u64>> {
            proptest::collection::vec(any::<u64>(), 0..120)
        }

        proptest! {
            /// The traversal visits the wires in order, and the number of
            /// wires is the length.
            #[test]
            fn a_stream_is_traversed_in_order(values in streams()) {
                let stream = by_hand(&values);
                let wires: Vec<Fp> = values.iter().map(|&value| Fp::from(value)).collect();
                prop_assert_eq!(stream.as_slice(), &wires[..]);
                prop_assert_eq!(stream_of(&stream), wires.clone());
                prop_assert_eq!(stream.num_wires().unwrap(), values.len());
                prop_assert_eq!(stream.into_iter().collect::<Vec<_>>(), wires);
            }

            /// A stream of `n` wires is what an array of `n` single wires
            /// is: the same wires in the same order.
            #[test]
            fn a_stream_is_traversed_as_an_array(values in proptest::array::uniform12(any::<u64>())) {
                let stream = by_hand(&values);
                let array: [Wire<'_, Dr>; 12] = values.map(|value| Wire(Fp::from(value), PhantomData));
                prop_assert_eq!(stream_of(&stream), stream_of(&array));
                prop_assert_eq!(stream.num_wires().unwrap(), array.num_wires().unwrap());
            }

            /// Substitution at one length: an instance takes the wires of
            /// another of its length, in order, and is then that other.
            #[test]
            fn streams_of_one_length_are_fungible(values in streams(), other in any::<u64>()) {
                let a = by_hand(&values);
                let shifted: Vec<u64> = values.iter().map(|value| value.wrapping_add(other)).collect();
                let b = by_hand(&shifted);
                let substituted = a.map(&mut Injector(stream_of(&b).iter())).unwrap();
                prop_assert_eq!(substituted.as_slice(), b.as_slice());
            }

            /// Allocation determinism: the kind and the wires give the
            /// gadget. What is assembled from a gadget's wires has its
            /// length and its wires.
            #[test]
            fn a_stream_is_assembled_from_its_wires(values in streams()) {
                let stream = by_hand(&values);
                let assembled = assemble(&stream_of(&stream)).unwrap();
                prop_assert_eq!(assembled.as_slice(), stream.as_slice());
            }

            /// Instances of two lengths never share a number of wires, so
            /// that number gives the shape.
            #[test]
            fn a_number_of_wires_is_of_one_length(a in 0usize..200, b in 0usize..200) {
                let count = |length: usize| by_hand(&vec![0; length]).num_wires().unwrap();
                prop_assert_eq!(count(a) == count(b), a == b);
            }
        }
    }
}
