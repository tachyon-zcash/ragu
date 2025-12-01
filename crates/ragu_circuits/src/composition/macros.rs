//! Staging macros.

/// This is used for creating nested commitments, which solves the issue
/// of witnessing data from one curve inside a circuit over a different curve,
/// for instance Fq elements inside an Fp circuit. It's "ephemeral" because
/// it's an intermediate step for nested commitments.
///
/// Imprtantly, we can't form a connection between the inner and outer stages due to
/// the field boundary constraint in the `Stage` trait that disallowes stages from
/// building stages that aren't in the same curve. That's why the this acts as
/// an interstitial, temporary stage that we use to construct the commitment, and
/// then we can form an outer stage from which subsequent stages can be built on.
#[macro_export]
macro_rules! stage {
    // Curve mode: witnesses `NUM` curve points
    (curve $name:ident) => {
        pub struct $name<Curve, const NUM: usize> {
            _marker: core::marker::PhantomData<Curve>,
        }

        impl<Curve: CurveAffine, R: Rank, const NUM: usize> Stage<Curve::Base, R>
            for $name<Curve, NUM>
        {
            type Parent = ();
            type Witness<'source> = &'source [Curve; NUM];
            type OutputKind = Kind![Curve::Base;
                                                    FixedVec<Point<'_, _, Curve>, ConstLen<NUM>>];

            fn values() -> usize {
                NUM * 2
            }

            fn witness<'dr, 'source: 'dr, D>(
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<<Self::OutputKind as GadgetKind<Curve::Base>>::Rebind<'dr, D>>
            where
                D: Driver<'dr, F = Curve::Base>,
                Self: 'dr,
            {
                let mut v = Vec::with_capacity(NUM);
                for i in 0..NUM {
                    v.push(Point::alloc(dr, witness.view().map(|w| w[i]))?);
                }
                Ok(FixedVec::new(v).expect("length"))
            }
        }
    };

    // Field mode: witnesses `L` field elements
    (field $name:ident) => {
        pub struct $name<F, L: Len> {
            _marker: core::marker::PhantomData<(F, L)>,
        }

        impl<F: ff::Field, R: Rank, L: Len> Stage<F, R> for $name<F, L> {
            type Parent = ();
            type Witness<'source> = &'source [F];
            type OutputKind = Kind![F; FixedVec<Element<'_, _>, L>];

            fn values() -> usize {
                L::len()
            }

            fn witness<'dr, 'source: 'dr, D>(
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<<Self::OutputKind as GadgetKind<F>>::Rebind<'dr, D>>
            where
                D: Driver<'dr, F = F>,
                Self: 'dr,
            {
                let len = L::len();
                let mut v = Vec::with_capacity(len);
                for i in 0..len {
                    v.push(Element::alloc(dr, witness.view().map(|w| w[i]))?);
                }
                Ok(FixedVec::new(v).expect("length"))
            }
        }
    };
}

/// Nesting stage.
#[macro_export]
macro_rules! nested_stage {
    ($name:ident) => {
        pub struct $name<NestedCurve, const NUM: usize> {
            _marker: core::marker::PhantomData<NestedCurve>,
        }

        impl<NestedCurve: CurveAffine, R: Rank, const NUM: usize> Stage<NestedCurve::Base, R>
            for $name<NestedCurve, NUM>
        {
            type Parent = ();
            type Witness<'source> = &'source [NestedCurve; NUM];
            type OutputKind = Kind![NestedCurve::Base;
                                            FixedVec<Point<'_, _, NestedCurve>, ConstLen<NUM>>];

            fn values() -> usize {
                NUM * 2
            }

            fn witness<'dr, 'source: 'dr, D>(
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<<Self::OutputKind as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>>
            where
                D: Driver<'dr, F = NestedCurve::Base>,
                Self: 'dr,
            {
                let mut v = Vec::with_capacity(NUM);
                for i in 0..NUM {
                    v.push(Point::alloc(dr, witness.view().map(|w| w[i]))?);
                }
                Ok(FixedVec::new(v).expect("length"))
            }
        }
    };
}
