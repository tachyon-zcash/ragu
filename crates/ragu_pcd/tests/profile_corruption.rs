//! The corruption vocabulary over an extension profile's proof.
//!
//! `tests/corruption.rs` sweeps the vocabulary's constant lists, the standard
//! profile's, over standard proofs. The polynomials and commitment caches a
//! profile's extension adds are targets too, which the vocabulary's
//! `all::<P>()` lists name: every one of them must be classified
//! [`Binding::MustReject`], and the verifier must reject the edit.

use alloc::{format, vec::Vec};

use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::R;
use ragu_core::{
    Result,
    pasta::{Fp, Fq, Pasta},
};
use rand::{SeedableRng, rngs::StdRng};

use crate::{
    ApplicationBuilder, Proof,
    fuzzing::corrupt::{
        Binding, Corruption, NativeCommitment, NativeRx, NestedCommitment, NestedRx, RxComponent,
    },
    profile::{
        Profile, Profiled,
        testing::{Crossing, CrossingBack, CrossingContext, UnitStep},
    },
};

const HEADER_SIZE: usize = 4;
type C<P> = Profiled<Pasta, P>;
type Rk = R<14>;

/// A profile's extension components, as the vocabulary names them.
fn extension_components<P: Profile>() -> (Vec<NativeRx>, Vec<NestedRx>) {
    let native: Vec<_> = NativeRx::all::<P>()
        .into_iter()
        .filter(|rx| {
            matches!(
                rx,
                NativeRx::ExtensionCircuit(_) | NativeRx::ExtensionStage(_)
            )
        })
        .collect();
    let nested: Vec<_> = NestedRx::all::<P>()
        .into_iter()
        .filter(|rx| {
            matches!(
                rx,
                NestedRx::ExtensionCircuit(_) | NestedRx::ExtensionStage(_)
            )
        })
        .collect();
    (native, nested)
}

/// The vocabulary's profile-generic lists name every component of `P`'s
/// proofs, the extension's among them, and the standard profile's are the
/// constant lists.
#[test]
fn the_vocabulary_follows_the_profile() {
    use crate::profile::Standard;

    assert_eq!(NativeRx::all::<Standard>(), NativeRx::ALL);
    assert_eq!(NestedRx::all::<Standard>(), NestedRx::ALL);
    assert_eq!(NativeCommitment::all::<Standard>(), NativeCommitment::ALL);
    assert_eq!(NestedCommitment::all::<Standard>(), NestedCommitment::ALL);

    let (native, nested) = extension_components::<Crossing>();
    assert_eq!(native.len(), Crossing::NATIVE_EXTENSION);
    assert_eq!(nested.len(), Crossing::NESTED_EXTENSION);
    let (native, nested) = extension_components::<CrossingBack>();
    assert_eq!(native.len(), CrossingBack::NATIVE_EXTENSION);
    assert_eq!(nested.len(), CrossingBack::NESTED_EXTENSION);

    // The commitment lists follow the rx lists: every rx commitment, the
    // bridges' aside on the nested side, then the four others.
    assert_eq!(
        NativeCommitment::all::<Crossing>().len(),
        NativeRx::all::<Crossing>().len() + 4
    );
    assert_eq!(
        NestedCommitment::all::<Crossing>().len(),
        NestedRx::all::<Crossing>()
            .iter()
            .filter(|rx| !rx.is_bridge())
            .count()
            + 4
    );
}

/// Every edit to an extension polynomial or its cached commitment, on either
/// side, is classified `MustReject` and rejected by the verifier.
fn check_extension_corruptions<P>() -> Result<()>
where
    P: Profile<Context<'static, Pasta, Rk, ReferenceBackend> = CrossingContext<'static, Pasta>>,
{
    let params = crate::pasta::baked_aggregator();
    let bits = [true, false, true, true];
    let app = ApplicationBuilder::<C<P>, Rk, HEADER_SIZE>::new()
        .register(UnitStep)?
        .finalize_with(
            params,
            CrossingContext {
                params,
                native: bits,
                nested: bits,
            },
        )?;
    let mut rng = StdRng::seed_from_u64(0x908_c0de);
    let (left, ()) = app.seed(&mut rng, UnitStep, ())?;
    let (right, ()) = app.seed(&mut rng, UnitStep, ())?;
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), left, right)?;
    assert!(app.verify_uncompressed(&parent, &mut rng)?);
    let honest = parent.proof().clone();

    let (native, nested) = extension_components::<P>();
    assert_eq!(
        native.len() + nested.len(),
        P::NATIVE_EXTENSION + P::NESTED_EXTENSION
    );
    let n = Proof::<C<P>, Rk>::num_bound_coeffs();
    let total = Proof::<C<P>, Rk>::num_coeffs();
    let coeffs = [0, n - 1, n, total - 1];

    let mut corruptions: Vec<Corruption<C<P>>> = Vec::new();
    for rx in native {
        corruptions.push(Corruption::NegateNativeCommitment(NativeCommitment::Rx(rx)));
        for coeff in coeffs {
            corruptions.push(Corruption::NativeCoeff {
                component: RxComponent::Rx(rx),
                coeff,
                delta: Fp::from(7),
            });
        }
    }
    for rx in nested {
        corruptions.push(Corruption::NegateNestedCommitment(NestedCommitment::Rx(rx)));
        for coeff in coeffs {
            corruptions.push(Corruption::NestedCoeff {
                index: rx,
                coeff,
                delta: Fq::from(7),
            });
        }
    }
    assert!(!corruptions.is_empty());

    for corruption in corruptions {
        let described = format!("{corruption:?}");
        let mut proof = honest.clone();
        assert_eq!(
            proof.corrupt(corruption),
            Binding::MustReject,
            "{}: {described}",
            P::NAME
        );
        assert!(
            !app.verify_uncompressed(&proof.carry::<()>(()), &mut rng)?,
            "the verifier accepted a corrupted {} proof: {described}",
            P::NAME
        );
    }
    Ok(())
}

#[test]
fn native_extension_corruptions_reject() -> Result<()> {
    check_extension_corruptions::<CrossingBack>()
}

#[test]
fn nested_extension_corruptions_reject() -> Result<()> {
    check_extension_corruptions::<Crossing>()
}
