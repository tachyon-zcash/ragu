use ff::Field;
use ragu_circuits::polynomials::R;
use ragu_core::Result;
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::engine::{CycleEngine, CycleEngineBuilder};
use ragu_pcd::utilities::dummy_circuits::SquaringCircuit;
use rand::thread_rng;
type TestRank = R<8>;

fn main() -> Result<()> {
    let params = Pasta::default();
    let mut builder = CycleEngineBuilder::<Pasta, TestRank>::new(&params);

    builder.register_circuit(SquaringCircuit(3))?;
    builder.register_circuit(SquaringCircuit(4))?;
    builder.register_circuit(SquaringCircuit(10))?;
    builder.register_circuit(SquaringCircuit(19))?;

    let engine: CycleEngine<'_, Pasta, R<8>> = builder.finalize()?;

    let witnesses = vec![
        Fp::random(thread_rng()),
        Fp::random(thread_rng()),
        Fp::random(thread_rng()),
        Fp::random(thread_rng()),
    ];

    let leaf_a = engine.base();
    let leaf_b = engine.base();

    let _merged = engine.fold(leaf_a, leaf_b, &witnesses)?;

    Ok(())
}
