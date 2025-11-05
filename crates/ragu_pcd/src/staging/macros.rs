/// Staging macros.

/// Ephemeral stage.
///
/// This is used for creating nested commitments, which solves the issue
/// of witnessing data from one curve inside a circuit over a different curve,
/// for instance Fq elements inside an Fp circuit.
///
/// Imprtantly, we can't form a connection between the inner and outer stages due to
/// the field boundary constraint in the `Stage` trait that disallowes stages from
/// building stages that aren't in the same curve. That's why the this acts as
/// an interstitial, temporary stage that we use to construct the commitment, and
/// then we can form an outer stage from which subsequent stages can be built on.
#[macro_export]
macro_rules! ephemeral_stage {
    ($name:ident) => {
        pub struct $name<HostCurve, const NUM: usize> {
            _marker: core::marker::PhantomData<HostCurve>,
        }

        impl<HostCurve: CurveAffine, R: Rank, const NUM: usize> Stage<<HostCurve>::Base, R>
            for $name<HostCurve, NUM>
        {
            type Parent = ();
            type Witness<'source> = &'source [HostCurve; NUM];
            type OutputKind = Kind![<HostCurve>::Base;
                                            FixedVec<Point<'_, _, HostCurve>, ConstLen<NUM>>];

            fn values() -> usize {
                NUM * 2
            }

            fn witness<'dr, 'source: 'dr, D>(
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<<Self::OutputKind as GadgetKind<<HostCurve>::Base>>::Rebind<'dr, D>>
            where
                D: Driver<'dr, F = <HostCurve>::Base>,
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

/// Indirection stage.
#[macro_export]
macro_rules! indirection_stage {
    ($name:ident) => {
        pub struct $name<NestedCurve>(core::marker::PhantomData<NestedCurve>);

        impl<NestedCurve: CurveAffine, R: Rank> Stage<NestedCurve::Base, R> for $name<NestedCurve> {
            type Parent = ();
            type Witness<'source> = NestedCurve;
            type OutputKind = Kind![NestedCurve::Base; Point<'_, _, NestedCurve>];

            fn values() -> usize {
                2
            }

            fn witness<'dr, 'source: 'dr, D>(
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<<Self::OutputKind as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>>
            where
                D: Driver<'dr, F = NestedCurve::Base>,
                Self: 'dr,
            {
                Point::alloc(dr, witness)
            }
        }
    };
}
