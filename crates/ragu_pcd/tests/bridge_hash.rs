//! The bridge hash $H(O_1)$: a step reads the hash of its own last online
//! commitment, which is the sum of the commitment's limbs times fixed
//! nested-curve generators, and an application can recompute it outside
//! the circuit.

use alloc::{vec, vec::Vec};

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Cycle, FixedGenerators, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe,
    pasta::{EpAffine, Fp, Fq, Pasta},
};
use ragu_primitives::{Element, allocator::Allocator, vec::FixedVec};
use rand::{SeedableRng, rngs::StdRng};
use udon::{
    curve::{Affine, Projective},
    field::Field,
};

use crate::{
    Application, ApplicationBuilder,
    header::{HEADER_POLYNOMIALS, Header, Suffix},
    internal::limbs,
    step::{Encoded, HeaderInput, Index, Oracles, Step},
};

type R = ProductionRank;
const HEADER_SIZE: usize = 4;
type App = Application<'static, Pasta, R, HEADER_SIZE>;

/// A header carrying a digest: the two coordinates of a nested-curve point.
struct Digest;
impl Header<Fp> for Digest {
    const SUFFIX: Suffix = Suffix::new(0);
    type Data = [Fp; 2];
    type Output = Kind![Fp; FixedVec<Element<'_, _>, ragu_primitives::vec::ConstLen<2>>];

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, [Fp; 2]>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        FixedVec::try_from_fn(|i| Element::alloc(dr, allocator, witness.as_ref().map(|w| w[i])))
    }
}

/// Commits `X + c` in its last slot and outputs that slot's bridge hash,
/// read from its oracles, as its header.
struct HashOut;
impl Step<Pasta> for HashOut {
    const INDEX: Index = Index::new(0);
    type Witness<'source> = Fp;
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = Digest;

    fn polynomials<'source>(
        &self,
        c: &Fp,
        _: HeaderInput<'_, Fp, ()>,
        _: HeaderInput<'_, Fp, ()>,
    ) -> Result<[Vec<Fp>; HEADER_POLYNOMIALS]> {
        Ok(core::array::from_fn(|i| {
            if i == HEADER_POLYNOMIALS - 1 {
                vec![*c, Fp::ONE]
            } else {
                vec![Fp::ONE]
            }
        }))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HS: usize>(
        &self,
        _: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _: DriverValue<D, Fp>,
        _: DriverValue<D, ()>,
        _: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, (), HS>,
            Encoded<'dr, D, Digest, HS>,
        ),
        DriverValue<D, [Fp; 2]>,
        DriverValue<D, ()>,
    )> {
        let [x, y] = oracles.bridge_hash().clone();
        let data = D::just(|| [*x.value().take(), *y.value().take()]);
        let digest = FixedVec::try_from(vec![x, y])?;
        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                Encoded::from_gadget(digest),
            ),
            data,
            D::unit(),
        ))
    }
}

fn app() -> App {
    ApplicationBuilder::<Pasta, R, HEADER_SIZE>::new()
        .register(HashOut)
        .unwrap()
        .finalize(crate::pasta::baked())
        .unwrap()
}

/// The step reads the bridge hash of its own last online commitment: the
/// proof verifies, and the hash is the one the proof carries, what
/// [`Application::bridge_hash`] computes from the commitment alone, and the
/// sum of the commitment's limbs times the challenge stage's generators.
#[test]
fn a_step_reads_the_bridge_hash_of_its_last_slot() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0xb415);
    let (pcd, ()) = app.seed(&mut rng, HashOut, Fp::from(7)).unwrap();
    assert!(app.verify_differential(&pcd, &mut rng).unwrap());

    let proof = pcd.proof();
    let o1 = proof.online_commitments()[HEADER_POLYNOMIALS - 1];
    let digest = app.bridge_hash(o1).unwrap();
    assert_eq!(digest, proof.bridge_hash());
    let (x, y) = digest.coordinates().unwrap();
    assert_eq!(*pcd.data(), [x, y]);

    // l_0 G_i0 + ... + l_3 G_i3, at the generators of the limbs' wires.
    let generators = Pasta::nested_generators(app.params).g();
    let manual: EpAffine = limbs::limbs::<_, Fq>(o1)
        .unwrap()
        .iter()
        .enumerate()
        .fold(EpAffine::identity().to_projective(), |acc, (i, limb)| {
            acc + generators[limbs::limb_generator_index::<Pasta, R>(i)] * *limb
        })
        .to_affine();
    assert_eq!(manual, digest);

    // Different points, different hashes.
    let (other, ()) = app.seed(&mut rng, HashOut, Fp::from(8)).unwrap();
    assert_ne!(*other.data(), *pcd.data());
}

/// A proof claiming a bridge hash other than its commitment's is rejected:
/// a header carrying another digest, and a proof whose carried hash is
/// replaced by another point's (which moves the application's instance and
/// the limb binders' too).
#[test]
fn a_misstated_bridge_hash_is_rejected() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0xb416);
    let (pcd, ()) = app.seed(&mut rng, HashOut, Fp::from(7)).unwrap();
    let (other, ()) = app.seed(&mut rng, HashOut, Fp::from(8)).unwrap();

    let (proof, _) = pcd.clone().into_parts();
    let claimed = proof.clone().carry::<Digest>(*other.data());
    assert!(!app.verify_uncompressed(&claimed, &mut rng).unwrap());

    let mut replaced = proof;
    replaced.bridge_hash = other.proof().bridge_hash();
    let replaced = replaced.carry::<Digest>(*other.data());
    assert!(!app.verify_uncompressed(&replaced, &mut rng).unwrap());
}
