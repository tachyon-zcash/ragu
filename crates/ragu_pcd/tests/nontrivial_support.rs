//! Shared proof constructors with nontrivial application headers.

use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Cycle,
    pasta::{Fp, Pasta},
};
use ragu_pcd::{Application, ApplicationBuilder, Pcd};
use ragu_testing::pcd::nontrivial::{Hash2, InternalNode, LeafNode, Merge2, WitnessLeaf};
use rand::{SeedableRng, rngs::StdRng};

pub(super) type C = Pasta;
pub(super) type R = ProductionRank;
pub(super) const HEADER_SIZE: usize = 4;

pub(super) fn app() -> Application<'static, C, R, HEADER_SIZE> {
    let pasta = ragu_pcd::pasta::baked();
    let poseidon = Pasta::circuit_poseidon(pasta);
    ApplicationBuilder::<C, R, HEADER_SIZE>::new(pasta)
        .register(WitnessLeaf {
            poseidon_params: poseidon,
        })
        .and_then(|b| {
            b.register(Hash2 {
                poseidon_params: poseidon,
            })
        })
        .and_then(|b| {
            b.register(Merge2 {
                poseidon_params: poseidon,
            })
        })
        .and_then(|b| b.finalize())
        .expect("the application must build")
}

pub(super) fn leaf(
    app: &Application<'_, C, R, HEADER_SIZE>,
    rng: &mut StdRng,
    witness: u64,
) -> Pcd<C, R, LeafNode> {
    app.seed(
        rng,
        WitnessLeaf {
            poseidon_params: Pasta::circuit_poseidon(ragu_pcd::pasta::baked()),
        },
        Fp::from(witness),
    )
    .expect("seeding must succeed")
    .0
}

pub(super) fn deep(app: &Application<'_, C, R, HEADER_SIZE>) -> Pcd<C, R, InternalNode> {
    let poseidon = Pasta::circuit_poseidon(ragu_pcd::pasta::baked());
    let node = |rng: &mut StdRng, l: u64, r: u64| {
        let (left, right) = (leaf(app, rng, l), leaf(app, rng, r));
        app.fuse(
            rng,
            Hash2 {
                poseidon_params: poseidon,
            },
            (),
            left,
            right,
        )
        .expect("fusing two leaves must succeed")
        .0
    };

    let mut rng = StdRng::seed_from_u64(0xdeeb);
    let (left, right) = (node(&mut rng, 13, 17), node(&mut rng, 19, 23));
    app.fuse(
        &mut rng,
        Merge2 {
            poseidon_params: poseidon,
        },
        (),
        left,
        right,
    )
    .expect("fusing two nodes must succeed")
    .0
}
