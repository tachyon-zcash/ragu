use ff::Field;
use ragu_circuits::mesh::Mesh;
use ragu_circuits::{Circuit, mesh::MeshBuilder, polynomials::R, staging::Staged};
use ragu_core::gadgets::{GadgetKind, Kind};
use ragu_core::maybe::Maybe;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
};
use ragu_pasta::{Fp, Pasta};
use ragu_pcd::engine::CycleEngine;
use ragu_pcd::staging::utility::dummy_circuits::SquaringCircuit;
use ragu_primitives::Element;
use rand::thread_rng;

fn main() -> Result<()> {
    // TODO: incrementally register staged circuits.
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

    engine.step(&witnesses);

    Ok(())
}
