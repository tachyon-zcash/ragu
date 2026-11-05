//! The verifier must check its own registered circuits even when a custom
//! prover uses the same proof shape and the verifier's exact registry tags.

use alloc::{vec, vec::Vec};
use core::marker::PhantomData;

use ragu_backend::Backend;
use ragu_circuits::{
    Circuit, CircuitExt, WithAux,
    registry::{CircuitIndex, Registry},
};
use ragu_core::{
    gadgets::{Bound, Kind},
    pasta::Fq,
};
use rand::CryptoRng;
use udon::field::Field;

use super::*;
use crate::profile::{CircuitSlot, Extension, ExtensionRxs, Registered};

/// Both circuits constrain a Boolean; the verifier additionally requires one.
struct BitCircuit<F, const REQUIRE_ONE: bool>(PhantomData<fn() -> F>);

impl<F: Field, const REQUIRE_ONE: bool> Circuit<F> for BitCircuit<F, REQUIRE_ONE> {
    type Instance<'source> = ();
    type Witness<'source> = F;
    type Output = Kind![F; ()];
    type Aux<'source> = ();

    fn instance<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        _: &mut D,
        _: DriverValue<D, ()>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        Ok(())
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = F>>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, F>,
    ) -> Result<WithAux<Bound<'dr, D, Self::Output>, DriverValue<D, ()>>> {
        let value = Element::alloc(dr, &mut (), witness)?;
        value.square(dr)?.enforce_equal(dr, &value)?;
        if REQUIRE_ONE {
            let one = Element::one();
            value.enforce_equal(dr, &one)?;
        }
        Ok(WithAux::new((), D::unit()))
    }
}

/// Identical declarations, with a weaker registered extension on either side.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ExtensionPolicy<const REQUIRE_ONE: bool, const NATIVE: bool>;

impl<const REQUIRE_ONE: bool, const NATIVE: bool> Profile for ExtensionPolicy<REQUIRE_ONE, NATIVE> {
    const NAME: &'static str = match (REQUIRE_ONE, NATIVE) {
        (true, true) => "required native extension",
        (false, true) => "weaker native extension",
        (true, false) => "required nested extension",
        (false, false) => "weaker nested extension",
    };
    const NATIVE_EXTENSION: usize = NATIVE as usize;
    const NESTED_EXTENSION: usize = (!NATIVE) as usize;

    type Context<'params, Base, Rk, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: crate::SelectableBackend;

    fn native_extension() -> Extension {
        if NATIVE {
            Proving::native_extension()
        } else {
            Extension::EMPTY
        }
    }

    fn nested_extension() -> Extension {
        if NATIVE {
            Extension::EMPTY
        } else {
            Proving::nested_extension()
        }
    }

    fn register_native_circuit<'params, Base, Rk: Rank, const HS: usize>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::CircuitField, Rk>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::CircuitField, Rk>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        assert!(NATIVE);
        assert_eq!(circuit, 0);
        slot.register(BitCircuit::<Base::CircuitField, REQUIRE_ONE>(PhantomData))
    }

    fn register_nested_circuit<'params, Base, Rk: Rank>(
        circuit: usize,
        slot: CircuitSlot<'params, Base::ScalarField, Rk>,
        _: &'params Base::Params,
    ) -> Result<Registered<'params, Base::ScalarField, Rk>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
    {
        assert!(!NATIVE);
        assert_eq!(circuit, 0);
        slot.register(BitCircuit::<Base::ScalarField, REQUIRE_ONE>(PhantomData))
    }

    fn native_extension_rxs<'params, Base, Rk, const HS: usize, B, RNG>(
        _: &Self::Context<'params, Base, Rk, B>,
        registry: &Registry<'params, Base::CircuitField, Rk>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::CircuitField, Rk>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: crate::SelectableBackend,
        RNG: CryptoRng,
    {
        if !NATIVE {
            return Ok(ExtensionRxs::default());
        }
        extension_rxs::<_, _, _, REQUIRE_ONE>(
            registry,
            crate::internal::native::InternalCircuitIndex::ExtensionCircuit(0)
                .circuit_index::<Self>(),
            rng,
        )
    }

    fn nested_extension_rxs<'params, Base, Rk, const HS: usize, B, RNG>(
        _: &Self::Context<'params, Base, Rk, B>,
        registry: &Registry<'params, Base::ScalarField, Rk>,
        rng: &mut RNG,
    ) -> Result<ExtensionRxs<Base::ScalarField, Rk>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: crate::SelectableBackend,
        RNG: CryptoRng,
    {
        if NATIVE {
            return Ok(ExtensionRxs::default());
        }
        extension_rxs::<_, _, _, REQUIRE_ONE>(
            registry,
            crate::internal::nested::InternalCircuitIndex::ExtensionCircuit(0)
                .circuit_index::<Self>(),
            rng,
        )
    }
}

fn extension_rxs<F: Field, Rk: Rank, RNG: CryptoRng, const REQUIRE_ONE: bool>(
    registry: &Registry<'_, F, Rk>,
    circuit: CircuitIndex,
    rng: &mut RNG,
) -> Result<ExtensionRxs<F, Rk>> {
    let value = if REQUIRE_ONE { F::ONE } else { F::ZERO };
    let (trace, ()) = BitCircuit::<F, REQUIRE_ONE>(PhantomData)
        .trace(value)?
        .into_parts();
    Ok(ExtensionRxs {
        circuits: vec![registry.assemble(&trace, circuit, rng)?],
        stages: Vec::new(),
    })
}

fn verifier<P: Profile, Rk: Rank>() -> Result<App<P, Rk>>
where
    P::Context<'static, Pasta, Rk, ReferenceBackend>: Default,
{
    application::<P, Rk>((None, None), Some(Fp::from(7)))
}

fn check_prover<S: Profile, T: Profile, Rk: Rank>(
    verifier: &App<T, Rk>,
    constraint: Option<Fp>,
    value: Fp,
    same_registries: (bool, bool),
    accepted: bool,
) -> Result<()>
where
    S::Context<'static, Pasta, Rk, ReferenceBackend>: Default,
{
    assert_eq!(Shape::of::<S>(), Shape::of::<T>());
    // The test seam gives a custom prover the exact tags the verifier derived,
    // which the derivation would not give the prover's different circuits.
    // This keeps registry contents as the difference being tested, including
    // after copying away the Rust profile types. Only the verifier's setup is
    // trusted; the prover's registry generates the adversarial witnesses and
    // compression messages.
    let prover = application::<S, Rk>(
        (
            Some(verifier.native_registry.tag()),
            Some(verifier.nested_registry.tag()),
        ),
        constraint,
    )?;
    assert_eq!(prover.native_registry.tag(), verifier.native_registry.tag());
    assert_eq!(prover.nested_registry.tag(), verifier.nested_registry.tag());
    assert_eq!(
        (
            ReferenceBackend::registry_wxy(
                &prover.native_registry,
                Fp::from(2),
                Fp::from(3),
                Fp::from(5)
            ) == ReferenceBackend::registry_wxy(
                &verifier.native_registry,
                Fp::from(2),
                Fp::from(3),
                Fp::from(5)
            ),
            ReferenceBackend::registry_wxy(
                &prover.nested_registry,
                Fq::from(2),
                Fq::from(3),
                Fq::from(5)
            ) == ReferenceBackend::registry_wxy(
                &verifier.nested_registry,
                Fq::from(2),
                Fq::from(3),
                Fq::from(5)
            ),
        ),
        same_registries,
    );

    let mut rng = StdRng::seed_from_u64(0x908_f17e);
    let (source, ()) = prover.seed(
        &mut rng,
        Seed {
            expected: constraint,
        },
        value,
    )?;
    check_both_verifiers(&prover, &source, true, &mut rng)?;
    let compressed = prover.compress(&source, &mut rng)?;
    let compressed =
        copy_compressed_payload::<C<S>, C<T>>(compressed.into_parts().0).carry::<Value>(value);
    assert_eq!(verifier.verify_compressed(&compressed)?, accepted);

    let foreign = copy_proof_payload::<C<S>, C<T>, Rk>(source.into_parts().0).carry::<Value>(value);
    assert!(foreign.proof().well_formed::<HEADER_SIZE>());
    check_both_verifiers(verifier, &foreign, accepted, &mut rng)?;
    let refreshed = verifier.rerandomize(foreign.clone(), &mut rng)?;
    check_both_verifiers(verifier, &refreshed, accepted, &mut rng)?;

    let (local, ()) = verifier.seed(
        &mut rng,
        Seed {
            expected: Some(Fp::from(7)),
        },
        Fp::from(7),
    )?;
    check_both_verifiers(verifier, &local, true, &mut rng)?;
    for foreign_on_left in [true, false] {
        let (left, right) = if foreign_on_left {
            (foreign.clone(), local.clone())
        } else {
            (local.clone(), foreign.clone())
        };
        let (parent, ()) = verifier.fuse(&mut rng, Sum, (), left, right)?;
        assert_eq!(*parent.data(), value + Fp::from(7));
        check_both_verifiers(verifier, &parent, accepted, &mut rng)?;
        let (left, right) = if foreign_on_left {
            (parent, local.clone())
        } else {
            (local.clone(), parent)
        };
        let (grandparent, ()) = verifier.fuse(&mut rng, Sum, (), left, right)?;
        assert_eq!(*grandparent.data(), value + Fp::from(14));
        check_both_verifiers(verifier, &grandparent, accepted, &mut rng)?;
    }
    Ok(())
}

fn check_application_circuits<P: Profile>() -> Result<()>
where
    P::Context<'static, Pasta, ProductionRank, ReferenceBackend>: Default,
{
    let verifier = verifier::<P, ProductionRank>()?;
    // An equivalent registered relation is the control for erasing the Rust
    // profile type. Removing its constraint or changing its constant must fail.
    for (constraint, value, accepted) in [
        (Some(Fp::from(7)), Fp::from(7), true),
        (None, Fp::from(9), false),
        (Some(Fp::from(9)), Fp::from(9), false),
    ] {
        check_prover::<Permissive, P, ProductionRank>(
            &verifier,
            constraint,
            value,
            (accepted, true),
            accepted,
        )?;
    }
    Ok(())
}

#[test]
fn standard_verifier_uses_its_registered_application_circuits() -> Result<()> {
    check_application_circuits::<Standard>()
}

#[test]
fn aggregator_verifier_uses_its_registered_application_circuits() -> Result<()> {
    check_application_circuits::<Aggregator>()
}

fn check_extension_circuit<const NATIVE: bool>() -> Result<()> {
    let verifier = verifier::<ExtensionPolicy<true, NATIVE>, R<14>>()?;
    check_prover::<ExtensionPolicy<false, NATIVE>, ExtensionPolicy<true, NATIVE>, R<14>>(
        &verifier,
        Some(Fp::from(7)),
        Fp::from(7),
        (!NATIVE, NATIVE),
        false,
    )
}

#[test]
fn verifier_uses_its_registered_native_extension_circuit() -> Result<()> {
    check_extension_circuit::<true>()
}

#[test]
fn verifier_uses_its_registered_nested_extension_circuit() -> Result<()> {
    check_extension_circuit::<false>()
}
