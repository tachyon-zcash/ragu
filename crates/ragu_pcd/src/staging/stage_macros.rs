//! Stage generation macros.

/// Inner stages (array of host curve points).
#[macro_export]
macro_rules! inner_stage {
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

/// Outer stages (curve points) with optional parent
#[macro_export]
macro_rules! outer_stage {
    ($name:ident, ()) => {
        pub struct $name<NestedCurve>(PhantomData<NestedCurve>);

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
    ($name:ident, $parent:ident) => {
        pub struct $name<NestedCurve>(PhantomData<NestedCurve>);

        impl<NestedCurve: CurveAffine, R: Rank> Stage<NestedCurve::Base, R> for $name<NestedCurve> {
            type Parent = $parent<NestedCurve>;
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

/// Indirection stages (curve point, no parent)
#[macro_export]
macro_rules! indirection_stage {
    ($name:ident) => {
        pub struct $name<NestedCurve>(PhantomData<NestedCurve>);

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

/// Challenge stages (field elements) using NestedCurve::Base
#[macro_export]
macro_rules! challenge_stage {
    ($name:ident, ()) => {
        pub struct $name<NestedCurve>(PhantomData<NestedCurve>);

        impl<NestedCurve: CurveAffine, R: Rank> Stage<NestedCurve::Base, R> for $name<NestedCurve> {
            type Parent = ();
            type Witness<'source> = NestedCurve::Base;
            type OutputKind = Kind![NestedCurve::Base; Element<'_, _>];

            fn values() -> usize {
                1
            }

            fn witness<'dr, 'source: 'dr, D>(
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<<Self::OutputKind as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>>
            where
                D: Driver<'dr, F = NestedCurve::Base>,
                Self: 'dr,
            {
                Element::alloc(dr, witness)
            }
        }
    };
    ($name:ident, $parent:ident) => {
        pub struct $name<NestedCurve>(PhantomData<NestedCurve>);

        impl<NestedCurve: CurveAffine, R: Rank> Stage<NestedCurve::Base, R> for $name<NestedCurve> {
            type Parent = $parent<NestedCurve>;
            type Witness<'source> = NestedCurve::Base;
            type OutputKind = Kind![NestedCurve::Base; Element<'_, _>];

            fn values() -> usize {
                1
            }

            fn witness<'dr, 'source: 'dr, D>(
                dr: &mut D,
                witness: DriverValue<D, Self::Witness<'source>>,
            ) -> Result<<Self::OutputKind as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>>
            where
                D: Driver<'dr, F = NestedCurve::Base>,
                Self: 'dr,
            {
                Element::alloc(dr, witness)
            }
        }
    };
}
