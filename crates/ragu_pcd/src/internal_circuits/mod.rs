use arithmetic::Cycle;
use ragu_circuits::{
    mesh::{CircuitIndex, MeshBuilder},
    polynomials::Rank,
    staging::StageExt,
};
use ragu_core::Result;

pub mod compute_v;
pub mod full_collapse;
pub mod hashes_1;
pub mod hashes_2;
pub mod partial_collapse;
pub mod stages;
pub mod unified;

pub use crate::components::fold_revdot::NativeParameters;

#[derive(Clone, Copy, Debug)]
#[repr(usize)]
pub enum InternalCircuitIndex {
    // Native stages
    PreambleStage = 0,
    ErrorMStage = 1,
    ErrorNStage = 2,
    QueryStage = 3,
    EvalStage = 4,
    // Final stage objects
    ErrorNFinalStaged = 5,
    EvalFinalStaged = 6,
    // Actual circuits
    Hashes1Circuit = 7,
    Hashes2Circuit = 8,
    PartialCollapseCircuit = 9,
    FullCollapseCircuit = 10,
    ComputeVCircuit = 11,
}

/// The number of internal circuits registered by [`register_all`],
/// and the number of variants in [`InternalCircuitIndex`].
pub const NUM_INTERNAL_CIRCUITS: usize = 12;

/// Compute the total circuit count and log2 domain size from the number of
/// application-defined steps.
pub(crate) fn total_circuit_counts(num_application_steps: usize) -> (usize, u32) {
    let total_circuits =
        num_application_steps + super::step::NUM_INTERNAL_STEPS + NUM_INTERNAL_CIRCUITS;
    let log2_circuits = total_circuits.next_power_of_two().trailing_zeros();
    (total_circuits, log2_circuits)
}

impl InternalCircuitIndex {
    pub fn circuit_index(self, num_application_steps: usize) -> CircuitIndex {
        CircuitIndex::new(num_application_steps + super::step::NUM_INTERNAL_STEPS + self as usize)
    }
}

/// Register internal polynomials into the provided mesh.
pub fn register_all<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>(
    mut mesh: MeshBuilder<'params, C::CircuitField, R>,
    params: &'params C::Params,
    log2_circuits: u32,
) -> Result<MeshBuilder<'params, C::CircuitField, R>> {
    let initial_num_circuits = mesh.num_circuits();

    // Insert the stages.
    {
        // preamble stage
        mesh = mesh.register_circuit_object(
            stages::native::preamble::Stage::<C, R, HEADER_SIZE>::into_object()?,
        )?;

        // error_m stage
        mesh = mesh.register_circuit_object(stages::native::error_m::Stage::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::into_object()?)?;

        // error_n stage
        mesh = mesh.register_circuit_object(stages::native::error_n::Stage::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::into_object()?)?;

        // query stage
        mesh = mesh.register_circuit_object(
            stages::native::query::Stage::<C, R, HEADER_SIZE>::into_object()?,
        )?;

        // eval stage
        mesh = mesh.register_circuit_object(
            stages::native::eval::Stage::<C, R, HEADER_SIZE>::into_object()?,
        )?;
    }

    // Insert the "final stage polynomials" for each stage.
    //
    // These are sometimes shared by multiple circuits. Each unique `Final`
    // stage is only registered once here.
    {
        // preamble -> error_m -> error_n -> [CIRCUIT]
        mesh = mesh.register_circuit_object(stages::native::error_n::Stage::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::final_into_object()?)?;

        // preamble -> query -> eval -> [CIRCUIT]
        mesh = mesh.register_circuit_object(
            stages::native::eval::Stage::<C, R, HEADER_SIZE>::final_into_object()?,
        )?;
    }

    // Insert the internal circuits.
    {
        // hashes_1
        mesh = mesh.register_circuit(
            hashes_1::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(params, log2_circuits),
        )?;

        // hashes_2
        mesh = mesh.register_circuit(
            hashes_2::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(params),
        )?;

        // partial_collapse
        mesh = mesh.register_circuit(partial_collapse::Circuit::<
            C,
            R,
            HEADER_SIZE,
            NativeParameters,
        >::new())?;

        // full_collapse
        mesh =
            mesh.register_circuit(
                full_collapse::Circuit::<C, R, HEADER_SIZE, NativeParameters>::new(),
            )?;

        // compute_v
        mesh = mesh.register_circuit(compute_v::Circuit::<C, R, HEADER_SIZE>::new())?;
    }

    // Verify we registered the expected number of circuits.
    assert_eq!(
        mesh.num_circuits(),
        initial_num_circuits + NUM_INTERNAL_CIRCUITS,
        "internal circuit count mismatch"
    );

    Ok(mesh)
}

#[cfg(test)]
mod test_params {
    use super::*;
    use crate::*;
    use ragu_circuits::polynomials::R;
    use ragu_circuits::staging::{Stage, StageExt};
    use ragu_pasta::Pasta;
    use stages::native::{error_m, error_n, eval, preamble, query};

    // When changing HEADER_SIZE, update the constraint counts by running:
    //   cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture
    // Then copy-paste the output into the check_constraints! calls in the test below.
    const HEADER_SIZE: usize = 37;

    // Number of dummy application circuits to register before testing internal
    // circuits. This ensures the tests work correctly even when application
    // steps are present.
    const NUM_APP_STEPS: usize = 6000;

    type Preamble = preamble::Stage<Pasta, R<13>, HEADER_SIZE>;
    type ErrorM = error_m::Stage<Pasta, R<13>, HEADER_SIZE, NativeParameters>;
    type ErrorN = error_n::Stage<Pasta, R<13>, HEADER_SIZE, NativeParameters>;
    type Query = query::Stage<Pasta, R<13>, HEADER_SIZE>;
    type Eval = eval::Stage<Pasta, R<13>, HEADER_SIZE>;

    #[rustfmt::skip]
    #[test]
    fn test_internal_circuit_constraint_counts() {
        let pasta = Pasta::baked();

        let app = ApplicationBuilder::<Pasta, R<13>, HEADER_SIZE>::new()
            .register_dummy_circuits(NUM_APP_STEPS)
            .unwrap()
            .finalize(pasta)
            .unwrap();

        let circuits = app.circuit_mesh.circuits();

        macro_rules! check_constraints {
            ($variant:ident, mul = $mul:expr, lin = $lin:expr) => {{
                let idx =
                    NUM_APP_STEPS + step::NUM_INTERNAL_STEPS + InternalCircuitIndex::$variant as usize;
                let circuit = &circuits[idx];
                let (actual_mul, actual_lin) = circuit.constraint_counts();
                assert_eq!(
                    actual_mul,
                    $mul,
                    "{}: multiplication constraints: expected {}, got {}",
                    stringify!($variant),
                    $mul,
                    actual_mul
                );
                assert_eq!(
                    actual_lin,
                    $lin,
                    "{}: linear constraints: expected {}, got {}",
                    stringify!($variant),
                    $lin,
                    actual_lin
                );
            }};
        }

        check_constraints!(Hashes1Circuit,         mul = 1937, lin = 2815);
        check_constraints!(Hashes2Circuit,         mul = 2047, lin = 2952);
        check_constraints!(PartialCollapseCircuit, mul = 1891, lin = 2650);
        check_constraints!(FullCollapseCircuit,    mul = 1876, lin = 2620);
        check_constraints!(ComputeVCircuit,        mul = 266,  lin = 248);
    }

    #[rustfmt::skip]
    #[test]
    fn test_internal_stage_parameters() {
        macro_rules! check_stage {
            ($Stage:ty, skip = $skip:expr, num = $num:expr) => {{
                assert_eq!(<$Stage>::skip_multiplications(), $skip, "{}: skip", stringify!($Stage));
                assert_eq!(<$Stage as StageExt<_, _>>::num_multiplications(), $num, "{}: num", stringify!($Stage));
            }};
        }

        check_stage!(Preamble, skip =   0, num = 141);
        check_stage!(ErrorM,   skip = 141, num = 270);
        check_stage!(ErrorN,   skip = 411, num = 168);
        check_stage!(Query,    skip = 141, num =   3);
        check_stage!(Eval,     skip = 144, num =   3);
    }

    /// Helper test to print current constraint counts in copy-pasteable format.
    /// Run with: `cargo test -p ragu_pcd --release print_internal_circuit -- --nocapture`
    #[test]
    fn print_internal_circuit_constraint_counts() {
        let pasta = Pasta::baked();

        let app = ApplicationBuilder::<Pasta, R<13>, HEADER_SIZE>::new()
            .register_dummy_circuits(NUM_APP_STEPS)
            .unwrap()
            .finalize(pasta)
            .unwrap();

        let circuits = app.circuit_mesh.circuits();

        let variants = [
            ("Hashes1Circuit", InternalCircuitIndex::Hashes1Circuit),
            ("Hashes2Circuit", InternalCircuitIndex::Hashes2Circuit),
            (
                "PartialCollapseCircuit",
                InternalCircuitIndex::PartialCollapseCircuit,
            ),
            (
                "FullCollapseCircuit",
                InternalCircuitIndex::FullCollapseCircuit,
            ),
            ("ComputeVCircuit", InternalCircuitIndex::ComputeVCircuit),
        ];

        println!("\n// Copy-paste the following into test_internal_circuit_constraint_counts:");
        for (name, variant) in variants {
            let idx = NUM_APP_STEPS + step::NUM_INTERNAL_STEPS + variant as usize;
            let circuit = &circuits[idx];
            let (mul, lin) = circuit.constraint_counts();
            println!(
                "        check_constraints!({:<24} mul = {:<4}, lin = {});",
                format!("{},", name),
                mul,
                lin
            );
        }
    }

    /// Helper test to print current stage parameters in copy-pasteable format.
    /// Run with: `cargo test -p ragu_pcd --release print_internal_stage -- --nocapture`
    #[test]
    fn print_internal_stage_parameters() {
        macro_rules! print_stage {
            ($Stage:ty) => {{
                let skip = <$Stage>::skip_multiplications();
                let num = <$Stage as StageExt<_, _>>::num_multiplications();
                println!(
                    "        check_stage!({:<8} skip = {:>3}, num = {:>3});",
                    format!("{},", stringify!($Stage)),
                    skip,
                    num
                );
            }};
        }

        println!("\n// Copy-paste the following into test_internal_stage_parameters:");
        print_stage!(Preamble);
        print_stage!(ErrorM);
        print_stage!(ErrorN);
        print_stage!(Query);
        print_stage!(Eval);
    }
}
