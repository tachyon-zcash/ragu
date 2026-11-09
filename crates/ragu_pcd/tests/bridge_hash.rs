//! The bridge hash $H^{bridge}(O_1)$: a step reads the digest of its own
//! last online commitment, the prover constructs its stage from the
//! point's coordinates alone, and an application can recompute it outside
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
    internal::nested::stages::bridge_hash,
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

/// The step reads the digest of its own last online commitment: the proof
/// verifies, and the digest is the proof's bridge-hash commitment, what
/// [`Application::bridge_hash`] computes from the commitment alone, and the
/// combination of the two generators the point's coordinates sit at.
#[test]
fn a_step_reads_the_digest_of_its_last_slot() {
    let app = app();
    let mut rng = StdRng::seed_from_u64(0xb415);
    let (pcd, ()) = app.seed(&mut rng, HashOut, Fp::from(7)).unwrap();
    assert!(app.verify_differential(&pcd, &mut rng).unwrap());

    let proof = pcd.proof();
    let o1 = proof.oracle_commitments()[HEADER_POLYNOMIALS - 1];
    let digest = app.bridge_hash(o1).unwrap();
    assert_eq!(digest, proof.bridge_hash_commitment());
    let (x, y) = digest.coordinates().unwrap();
    assert_eq!(*pcd.data(), [x, y]);

    // x * G_i + y * G_j, at the generators of the stage's two wires.
    let generators = Pasta::nested_generators(app.params).g();
    let (ox, oy) = o1.coordinates().unwrap();
    let rx = bridge_hash::rx::<_, R>(o1).unwrap();
    let positions: Vec<usize> = rx
        .iter_coeffs()
        .enumerate()
        .filter(|(_, c)| *c != Fq::ZERO)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        positions.len(),
        2,
        "the stage holds the two coordinates only"
    );
    let manual: EpAffine = (generators[positions[0]] * rx.iter_coeffs().nth(positions[0]).unwrap()
        + generators[positions[1]] * rx.iter_coeffs().nth(positions[1]).unwrap())
    .to_affine();
    assert_eq!(manual, digest);
    assert!(
        [ox, oy].iter().all(|c| rx.iter_coeffs().any(|v| v == *c)),
        "the coefficients are the point's coordinates"
    );

    // Different points, different digests.
    let (other, ()) = app.seed(&mut rng, HashOut, Fp::from(8)).unwrap();
    assert_ne!(*other.data(), *pcd.data());
}
