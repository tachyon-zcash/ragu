//! E-stage wsith subcircuits that together handle challenge derivation (mu, nu).

use arithmetic::CurveAffine;
use ragu_circuits::staging::{StageBuilder, StagedCircuit};
use ragu_circuits::{polynomials::Rank, staging::Stage};
use ragu_core::Result;
use ragu_core::maybe::Maybe;
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{GadgetKind, Kind},
};
use ragu_pasta::{Fp, PoseidonFp};
use ragu_primitives::{Element, GadgetExt, Sponge};
use ragu_primitives::{
    Point,
    vec::{ConstLen, FixedVec},
};

use crate::staging::d_stage::{MuChallengeStage, NuChallengeStage};
use crate::{indirection_stage, inner_stage};

inner_stage!(E1InnerStage);
inner_stage!(E2InnerStage);

// Indirection stage.
indirection_stage!(EIndirectionStage);

/// C Circuit Witness: mu/nu derivation and c value computation
pub struct ESubcircuit1Witness<C: CurveAffine> {
    /// Commitment to the staged circuit that computed C.
    pub c_staged_circuit_nested_commitment: C,
    pub mu_challenge: C::Base,
    pub nu_challenge: C::Base,
}

/// Output containing mu, nu challenges and computed c value.
#[derive(ragu_macros::Gadget, ragu_primitives::io::Write)]
pub struct ESubcircuit1Output<'dr, D: Driver<'dr>, C: CurveAffine<Base = D::F>> {
    #[ragu(gadget)]
    pub c_staged_circuit_nested_commitment: Point<'dr, D, C>,
    #[ragu(gadget)]
    pub mu_challenge: Element<'dr, D>,
    #[ragu(gadget)]
    pub nu_challenge: Element<'dr, D>,
}

#[derive(Clone)]
pub struct ESubcircuit1<NestedCurve>(core::marker::PhantomData<NestedCurve>);

impl<NestedCurve> ESubcircuit1<NestedCurve> {
    pub fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<NestedCurve: CurveAffine<Base = Fp>, R: Rank> StagedCircuit<NestedCurve::Base, R>
    for ESubcircuit1<NestedCurve>
{
    type Final = NuChallengeStage<NestedCurve>;
    type Instance<'src> = ();
    type Witness<'w> = ESubcircuit1Witness<NestedCurve>;
    type Output = Kind![NestedCurve::Base; ESubcircuit1Output<'_, _, NestedCurve>];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = NestedCurve::Base>>(
        &self,
        _dr: &mut D,
        _instance: DriverValue<D, Self::Instance<'source>>,
    ) -> Result<<Self::Output as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>> {
        unimplemented!()
    }

    fn witness<'a, 'dr, 'source: 'dr, D: Driver<'dr, F = NestedCurve::Base>>(
        &self,
        dr: StageBuilder<'a, 'dr, D, R, (), Self::Final>,
        witness: DriverValue<D, Self::Witness<'source>>,
    ) -> Result<(
        <Self::Output as GadgetKind<NestedCurve::Base>>::Rebind<'dr, D>,
        DriverValue<D, Self::Aux<'source>>,
    )> {
        let (mu_challenge, dr) =
            dr.add_stage::<MuChallengeStage<NestedCurve>>(witness.view().map(|w| w.mu_challenge))?;

        let (nu_challenge, dr) =
            dr.add_stage::<NuChallengeStage<NestedCurve>>(witness.view().map(|w| w.nu_challenge))?;

        let dr = dr.finish();

        // Now allocate `d3_nested_commitment` (NOT in the staging polynomial) and verify
        // that mu and nu were correctly derived. This keeps D and E as separate staging
        // polynomials while still verifying the FS challenge derivation.
        let c_staged_circuit_nested_commitment = Point::alloc(
            dr,
            witness.view().map(|w| w.c_staged_circuit_nested_commitment),
        )?;

        // Initialize a single sponge for FS challenge derivation.
        let mut sponge = Sponge::new(dr, &PoseidonFp);

        // Derive mu = H(state_0 || D3)
        c_staged_circuit_nested_commitment.write(dr, &mut sponge)?;
        let mu_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(mu_computed.wire(), mu_challenge.wire())?;

        // Absorb Mu challenge.
        mu_computed.write(dr, &mut sponge)?;

        // Derive nu = H(state_1 || mu) where state_1 contains (D3, mu).
        let nu_computed = sponge.squeeze(dr)?;
        dr.enforce_equal(nu_computed.wire(), nu_challenge.wire())?;

        let output = ESubcircuit1Output {
            c_staged_circuit_nested_commitment,
            mu_challenge,
            nu_challenge,
        };

        Ok((output, D::just(|| ())))
    }
}
