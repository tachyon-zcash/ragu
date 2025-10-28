use ff::Field;
use ragu_circuits::polynomials::R;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::engine::CycleEngine;
use ragu_pcd::utilities::dummy_circuits::SquaringCircuit;
use rand::thread_rng;

type TestRank = R<8>;

fn main() -> Result<()> {
    let mut engine = CycleEngine::<Pasta, TestRank>::new();

    engine.register_circuit(SquaringCircuit(3))?;
    engine.register_circuit(SquaringCircuit(4))?;
    engine.register_circuit(SquaringCircuit(10))?;
    engine.register_circuit(SquaringCircuit(19))?;

    let witnesses = vec![
        Fp::random(thread_rng()),
        Fp::random(thread_rng()),
        Fp::random(thread_rng()),
        Fp::random(thread_rng()),
    ];

    engine.step(&witnesses)?;

    Ok(())
}
