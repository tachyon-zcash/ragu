//! Implementations of gadgets for foreign types.

use alloc::{boxed::Box, vec::Vec};
use core::marker::PhantomData;

use udon::field::Field;

use crate::{
    Result,
    convert::WireMap,
    drivers::Driver,
    gadgets::{Bound, Gadget, GadgetKind, WireEqualizer},
};

mod unit_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>> Gadget<'dr, D> for () {
        type Kind = ();
    }

    /// Safety: `Rebind<'dr, D> = ()`, which is unconditionally `Send`
    /// regardless of `D::Wire`.
    unsafe impl<F: Field> GadgetKind<F> for () {
        type Rebind<'dr, D: Driver<'dr, F = F>> = ();

        fn map_gadget<
            'src,
            'dst,
            WM: WireMap<F, Src: Driver<'src, F = F>, Dst: Driver<'dst, F = F>>,
        >(
            _: &Bound<'src, WM::Src, Self>,
            _: &mut WM,
        ) -> Result<Bound<'dst, WM::Dst, Self>> {
            Ok(())
        }

        fn enforce_conservative_equal_gadget<
            'dr,
            D1: Driver<'dr, F = F>,
            D2: Driver<'dr, F = F, Wire = <D1 as Driver<'dr>>::Wire>,
        >(
            _: &mut WireEqualizer<'_, 'dr, D1>,
            _: &Bound<'dr, D2, Self>,
            _: &Bound<'dr, D2, Self>,
        ) -> Result<()> {
            Ok(())
        }
    }
}

mod array_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>, const N: usize> Gadget<'dr, D> for [G; N] {
        type Kind = [PhantomData<G::Kind>; N];
    }

    /// Safety: `G: GadgetKind<F>` implies that `Bound<'dr, D, G>` is `Send`
    /// when `D::Wire` is `Send`, by the safety contract of `GadgetKind`. Because
    /// `[Bound<'dr, D, G>; N]` only contains `Bound<'dr, D, G>`, it is also
    /// `Send` when `D::Wire` is `Send`.
    unsafe impl<F: Field, G: GadgetKind<F>, const N: usize> GadgetKind<F> for [PhantomData<G>; N] {
        type Rebind<'dr, D: Driver<'dr, F = F>> = [Bound<'dr, D, G>; N];

        fn map_gadget<
            'src,
            'dst,
            WM: WireMap<F, Src: Driver<'src, F = F>, Dst: Driver<'dst, F = F>>,
        >(
            this: &Bound<'src, WM::Src, Self>,
            wm: &mut WM,
        ) -> Result<Bound<'dst, WM::Dst, Self>> {
            // TODO(ebfull): perhaps replace with core::array::try_from_fn when
            // stable (see https://github.com/rust-lang/rust/issues/89379)
            let mut result = Vec::with_capacity(N);
            for item in this.iter() {
                result.push(G::map_gadget(item, wm)?);
            }
            Ok(result
                .try_into()
                .unwrap_or_else(|_| unreachable!("Vec had exactly N elements")))
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
            for (a, b) in a.iter().zip(b.iter()) {
                G::enforce_conservative_equal_gadget(eq, a, b)?;
            }
            Ok(())
        }
    }
}

mod pair_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>, G1: Gadget<'dr, D>, G2: Gadget<'dr, D>> Gadget<'dr, D> for (G1, G2) {
        type Kind = (PhantomData<G1::Kind>, PhantomData<G2::Kind>);
    }

    /// Safety: `G1: GadgetKind<F>` and `G2: GadgetKind<F>` imply that both
    /// `Bound<'dr, D, G1>` and `Bound<'dr, D, G2>` are `Send` when `D::Wire`
    /// is `Send`, by the safety contract of `GadgetKind`. Because the tuple
    /// only contains these two types, it is also `Send` when `D::Wire` is `Send`.
    unsafe impl<F: Field, G1: GadgetKind<F>, G2: GadgetKind<F>> GadgetKind<F>
        for (PhantomData<G1>, PhantomData<G2>)
    {
        type Rebind<'dr, D: Driver<'dr, F = F>> = (Bound<'dr, D, G1>, Bound<'dr, D, G2>);

        fn map_gadget<
            'src,
            'dst,
            WM: WireMap<F, Src: Driver<'src, F = F>, Dst: Driver<'dst, F = F>>,
        >(
            this: &Bound<'src, WM::Src, Self>,
            wm: &mut WM,
        ) -> Result<Bound<'dst, WM::Dst, Self>> {
            Ok((G1::map_gadget(&this.0, wm)?, G2::map_gadget(&this.1, wm)?))
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
            G1::enforce_conservative_equal_gadget(eq, &a.0, &b.0)?;
            G2::enforce_conservative_equal_gadget(eq, &a.1, &b.1)?;
            Ok(())
        }
    }
}

mod box_impl {
    use super::*;

    impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Gadget<'dr, D> for Box<G> {
        type Kind = PhantomData<Box<G::Kind>>;
    }

    /// Safety: `G: GadgetKind<F>` implies that `Bound<'dr, D, G>` is `Send`
    /// when `D::Wire` is `Send`, by the safety contract of `GadgetKind`. Because
    /// `Box<Bound<'dr, D, G>>` is `Send` when its contents are `Send`, it is
    /// also `Send` when `D::Wire` is `Send`.
    unsafe impl<F: Field, G: GadgetKind<F>> GadgetKind<F> for PhantomData<Box<G>> {
        type Rebind<'dr, D: Driver<'dr, F = F>> = Box<Bound<'dr, D, G>>;

        fn map_gadget<
            'src,
            'dst,
            WM: WireMap<F, Src: Driver<'src, F = F>, Dst: Driver<'dst, F = F>>,
        >(
            this: &Bound<'src, WM::Src, Self>,
            wm: &mut WM,
        ) -> Result<Bound<'dst, WM::Dst, Self>> {
            Ok(Box::new(G::map_gadget(this, wm)?))
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
            G::enforce_conservative_equal_gadget(eq, a, b)
        }
    }
}

mod vec_impl {
    use super::*;

    /// A run of gadgets whose number is known only at run time. It is
    /// fungible where its elements have a fixed, nonzero number of wires:
    /// see [run-time-sized gadgets](crate::gadgets#run-time-sized-gadgets).
    impl<'dr, D: Driver<'dr>, G: Gadget<'dr, D>> Gadget<'dr, D> for Vec<G> {
        type Kind = PhantomData<Vec<G::Kind>>;
    }

    /// Safety: `G: GadgetKind<F>` implies that `Bound<'dr, D, G>` is `Send`
    /// when `D::Wire` is `Send`, by the safety contract of `GadgetKind`. Because
    /// `Vec<Bound<'dr, D, G>>` is `Send` when its contents are `Send`, it is
    /// also `Send` when `D::Wire` is `Send`.
    unsafe impl<F: Field, G: GadgetKind<F>> GadgetKind<F> for PhantomData<Vec<G>> {
        type Rebind<'dr, D: Driver<'dr, F = F>> = Vec<Bound<'dr, D, G>>;

        /// Maps the gadgets in order: the wires of the first, then those of
        /// the second, and so on.
        fn map_gadget<
            'src,
            'dst,
            WM: WireMap<F, Src: Driver<'src, F = F>, Dst: Driver<'dst, F = F>>,
        >(
            this: &Bound<'src, WM::Src, Self>,
            wm: &mut WM,
        ) -> Result<Bound<'dst, WM::Dst, Self>> {
            this.iter().map(|item| G::map_gadget(item, wm)).collect()
        }

        /// Pairs the gadgets in order.
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
                return Err(crate::Error::VectorLengthMismatch {
                    expected: a.len(),
                    actual: b.len(),
                });
            }
            for (a, b) in a.iter().zip(b.iter()) {
                G::enforce_conservative_equal_gadget(eq, a, b)?;
            }
            Ok(())
        }
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

    /// One wire.
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

    /// An element with three wires: one, and a pair.
    type Three<'dr> = (Wire<'dr, Dr>, [Wire<'dr, Dr>; 2]);

    /// The number of wires of a [`Three`].
    const WIDTH: usize = 3;

    fn wire<'dr>(value: u64) -> Wire<'dr, Dr> {
        Wire(Fp::from(value), PhantomData)
    }

    /// The `Vec` of `stream.len() / WIDTH` elements that holds `stream`'s
    /// wires in order, built by hand.
    fn by_hand<'dr>(stream: &[u64]) -> Vec<Three<'dr>> {
        stream
            .chunks(WIDTH)
            .map(|wires| (wire(wires[0]), [wire(wires[1]), wire(wires[2])]))
            .collect()
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
                .ok_or_else(|| crate::Error::InvalidWitness("the stream ran out".into()))
        }
    }

    /// Allocation determinism for a `Vec` of fixed-width elements: the
    /// gadget of kind `Vec<Three>` that holds `stream`, from the kind and
    /// the stream alone. The stream's length gives the `Vec`'s, and an
    /// instance of that length, whatever its wires, gives the rest. No
    /// stream of another length is one of this kind.
    fn assemble<'dr>(stream: &[Fp]) -> Option<Vec<Three<'dr>>> {
        if !stream.len().is_multiple_of(WIDTH) {
            return None;
        }
        let blank: Vec<Three<'_>> = by_hand(&vec![0; stream.len()]);
        let mut injector = Injector(stream.iter());
        let assembled = blank.map(&mut injector).ok()?;
        injector.0.next().is_none().then_some(assembled)
    }

    #[test]
    fn an_empty_vec_has_no_wires() -> Result<()> {
        let empty: Vec<Three<'_>> = Vec::new();
        assert_eq!(empty.num_wires()?, 0);
        assert!(stream_of(&empty).is_empty());
        assert!(assemble(&[]).is_some_and(|vec| vec.is_empty()));
        Ok(())
    }

    #[test]
    fn vecs_of_unequal_length_are_not_paired() -> Result<()> {
        let mut dr = Dr::extractor();
        let (two, three) = (
            by_hand(&[1, 2, 3, 4, 5, 6]),
            by_hand(&[1, 2, 3, 4, 5, 6, 7, 8, 9]),
        );
        assert!(matches!(
            two.enforce_conservative_equal(&mut dr, &three),
            Err(crate::Error::VectorLengthMismatch {
                expected: 2,
                actual: 3
            })
        ));
        two.enforce_conservative_equal(&mut dr, &two.clone())
    }

    /// Where allocation determinism ends. A kind with two run-time lengths
    /// has instances of different shapes over the same number of wires, and
    /// a `Vec` of gadgets without wires has one stream at every length: the
    /// stream does not give the shape of either.
    #[test]
    fn a_stream_does_not_give_every_shape() -> Result<()> {
        let nested = |lengths: &[usize]| -> Vec<Vec<Wire<'_, Dr>>> {
            let mut next = 0;
            lengths
                .iter()
                .map(|&length| {
                    (0..length)
                        .map(|_| {
                            next += 1;
                            wire(next)
                        })
                        .collect()
                })
                .collect()
        };
        let (a, b) = (nested(&[1, 2]), nested(&[2, 1]));
        assert_eq!(stream_of(&a), stream_of(&b));
        assert_ne!(a[0].len(), b[0].len());

        let units = |length: usize| vec![(); length];
        assert_eq!(
            Gadget::<Dr>::num_wires(&units(2))?,
            Gadget::<Dr>::num_wires(&units(5))?
        );
        Ok(())
    }

    mod proptests {
        use proptest::prelude::*;

        use super::*;

        /// A stream of wires, each named by a value, for a `Vec` of up to
        /// 40 elements.
        fn streams() -> impl Strategy<Value = Vec<u64>> {
            (0usize..40)
                .prop_flat_map(|length| proptest::collection::vec(any::<u64>(), length * WIDTH))
        }

        proptest! {
            /// The traversal visits the elements in order, each as it is
            /// visited alone: a `Vec`'s wires are its elements' wires, one
            /// element after another.
            #[test]
            fn a_vec_is_traversed_in_order(stream in streams()) {
                let vec = by_hand(&stream);
                let wires: Vec<Fp> = stream.iter().map(|&value| Fp::from(value)).collect();
                prop_assert_eq!(stream_of(&vec), wires.clone());
                let each: Vec<Fp> = vec.iter().flat_map(stream_of).collect();
                prop_assert_eq!(each, wires);
                prop_assert_eq!(vec.num_wires().unwrap(), stream.len());
            }

            /// A `Vec` of `n` elements is what an array of `n` is: the same
            /// wires in the same order.
            #[test]
            fn a_vec_is_traversed_as_an_array(stream in proptest::collection::vec(any::<u64>(), 4 * WIDTH)) {
                let vec = by_hand(&stream);
                let array: [Three<'_>; 4] = vec.clone().try_into().ok().unwrap();
                prop_assert_eq!(stream_of(&vec), stream_of(&array));
            }

            /// Fungibility at one length: an instance takes the wires of
            /// another of its length, in order, and is then that other.
            #[test]
            fn vecs_of_one_length_are_fungible(stream in streams(), other in any::<u64>()) {
                let a = by_hand(&stream);
                let shifted: Vec<u64> = stream.iter().map(|value| value.wrapping_add(other)).collect();
                let b = by_hand(&shifted);
                let substituted = a.map(&mut Injector(stream_of(&b).iter())).unwrap();
                prop_assert_eq!(substituted.len(), b.len());
                prop_assert_eq!(stream_of(&substituted), stream_of(&b));
            }

            /// Allocation determinism: the kind and the stream give the
            /// gadget. What is assembled from a gadget's stream has its
            /// length and its wires, and a stream is of exactly one length.
            #[test]
            fn a_vec_is_assembled_from_its_stream(stream in streams()) {
                let vec = by_hand(&stream);
                let assembled = assemble(&stream_of(&vec)).unwrap();
                prop_assert_eq!(assembled.len(), vec.len());
                prop_assert_eq!(stream_of(&assembled), stream_of(&vec));
            }

            /// No instance holds a stream whose length is not a whole number
            /// of elements, and instances of two lengths never share a
            /// number of wires.
            #[test]
            fn a_stream_is_of_one_length(wires in 0usize..200, a in 0usize..60, b in 0usize..60) {
                let stream = vec![Fp::ZERO; wires];
                prop_assert_eq!(assemble(&stream).is_some(), wires % WIDTH == 0);
                let count = |length: usize| by_hand(&vec![0; length * WIDTH]).num_wires().unwrap();
                prop_assert_eq!(count(a) == count(b), a == b);
            }
        }
    }
}
