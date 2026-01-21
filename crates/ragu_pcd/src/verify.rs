//! This module provides the [`Application::verify`] method implementation.

use arithmetic::Cycle;
use ff::Field;
use ragu_circuits::{
    mesh::CircuitIndex,
    polynomials::{Rank, structured},
};
use ragu_core::{Result, drivers::emulator::Emulator, maybe::Maybe};
use ragu_primitives::Element;
use rand::Rng;

use core::iter::once;

use crate::{
    Application, Pcd, Proof, circuits::native::stages::preamble::ProofInputs, components::claims,
    header::Header,
};

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    /// Verifies some [`Pcd`] for the provided [`Header`].
    pub fn verify<RNG: Rng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<'_, C, R, H>,
        mut rng: RNG,
    ) -> Result<bool> {
        // Sample verification challenges w, y, and z.
        let w = C::CircuitField::random(&mut rng);
        let y = C::CircuitField::random(&mut rng);
        let z = C::CircuitField::random(&mut rng);

        // Validate that the application circuit_id is within the mesh domain.
        // (Internal circuit IDs are constants and don't need this check.)
        if !self
            .native_mesh
            .circuit_in_domain(pcd.proof.application.circuit_id)
        {
            return Ok(false);
        }

        // Validate that the `left_header` and `right_header` lengths match
        // `HEADER_SIZE`. Alternatively, the `Proof` structure could be
        // parameterized on the `HEADER_SIZE`, but this appeared to be simpler.
        if pcd.proof.application.left_header.len() != HEADER_SIZE
            || pcd.proof.application.right_header.len() != HEADER_SIZE
        {
            return Ok(false);
        }

        // Compute unified k(y), unified_bridge k(y), application k(y), and endoscale k(y).
        let (unified_ky, unified_bridge_ky, application_ky, endoscale_ky) =
            Emulator::emulate_wireless((&pcd.proof, pcd.data.clone(), y), |dr, witness| {
                let (proof, data, y) = witness.cast();
                let y = Element::alloc(dr, y)?;
                let proof_inputs =
                    ProofInputs::<_, C, HEADER_SIZE>::alloc_for_verify::<R, H>(dr, proof, data)?;

                let (unified_ky, unified_bridge_ky) = proof_inputs.unified_ky_values(dr, &y)?;
                let unified_ky = *unified_ky.value().take();
                let unified_bridge_ky = *unified_bridge_ky.value().take();
                let application_ky = *proof_inputs.application_ky(dr, &y)?.value().take();
                let endoscale_ky = *proof_inputs.endoscale_ky(dr, &y)?.value().take();

                Ok((unified_ky, unified_bridge_ky, application_ky, endoscale_ky))
            })?;

        // Build a and b polynomials for each revdot claim.
        let source = native::SingleProofSource { proof: &pcd.proof };
        let mut builder = claims::Builder::new(&self.native_mesh, self.num_application_steps, y, z);
        claims::native::build(&source, &mut builder)?;

        // Check all native revdot claims.
        let native_revdot_claims = {
            let ky_source = native::SingleProofKySource {
                raw_c: pcd.proof.ab.c,
                application_ky,
                unified_bridge_ky,
                unified_ky,
                endoscale_ky,
            };

            native::ky_values(&ky_source)
                .zip(builder.a.iter().zip(builder.b.iter()))
                .all(|(ky, (a, b))| a.revdot(b) == ky)
        };

        // Check all nested revdot claims.
        let nested_revdot_claims = {
            let nested_source = nested::SingleProofSource { proof: &pcd.proof };
            let y_nested = C::ScalarField::random(&mut rng);
            let z_nested = C::ScalarField::random(&mut rng);
            let mut nested_builder = claims::Builder::new(&self.nested_mesh, 0, y_nested, z_nested);
            claims::nested::build(&nested_source, &mut nested_builder)?;

            let ky_source = nested::SingleProofKySource::<C::ScalarField>::new();
            nested::ky_values(&ky_source)
                .zip(nested_builder.a.iter().zip(nested_builder.b.iter()))
                .all(|(ky, (a, b))| a.revdot(b) == ky)
        };

        // Check polynomial evaluation claim.
        let p_eval_claim = pcd.proof.p.poly.eval(pcd.proof.challenges.u) == pcd.proof.p.v;

        // Check P commitment corresponds to polynomial and blind.
        let p_commitment_claim = pcd
            .proof
            .p
            .poly
            .commit(C::host_generators(self.params), pcd.proof.p.blind)
            == pcd.proof.p.commitment;

        // Check mesh_xy polynomial evaluation at the sampled w.
        // mesh_xy_poly is m(W, x, y) - the mesh evaluated at current x, y, free in W.
        let mesh_xy_claim = {
            let x = pcd.proof.challenges.x;
            let y = pcd.proof.challenges.y;
            let poly_eval = pcd.proof.query.mesh_xy_poly.eval(w);
            let expected = self.native_mesh.wxy(w, x, y);
            poly_eval == expected
        };

        // TODO: Add checks for mesh_wx0_poly, mesh_wx1_poly, and mesh_wy_poly.
        // - mesh_wx0/wx1: need child proof x challenges (x₀, x₁) which "disappear" in preamble
        // - mesh_wy: interstitial value that will be elided later

        Ok(native_revdot_claims
            && nested_revdot_claims
            && p_eval_claim
            && p_commitment_claim
            && mesh_xy_claim)
    }
}

mod native {
    use super::*;
    use crate::components::claims::{
        Source,
        native::{KySource, RxComponent},
    };

    pub use crate::components::claims::native::ky_values;

    pub struct SingleProofSource<'rx, C: Cycle, R: Rank> {
        pub proof: &'rx Proof<C, R>,
    }

    impl<'rx, C: Cycle, R: Rank> Source for SingleProofSource<'rx, C, R> {
        type RxComponent = RxComponent;
        type Rx = &'rx structured::Polynomial<C::CircuitField, R>;
        type AppCircuitId = CircuitIndex;

        fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
            use RxComponent::*;
            let poly = match component {
                AbA => &self.proof.ab.a_poly,
                AbB => &self.proof.ab.b_poly,
                Application => &self.proof.application.rx,
                Hashes1 => &self.proof.circuits.hashes_1_rx,
                Hashes2 => &self.proof.circuits.hashes_2_rx,
                PartialCollapse => &self.proof.circuits.partial_collapse_rx,
                FullCollapse => &self.proof.circuits.full_collapse_rx,
                ComputeV => &self.proof.circuits.compute_v_rx,
                EndoscaleChallenges => &self.proof.circuits.endoscale_challenges_rx,
                Preamble => &self.proof.preamble.native_rx,
                ErrorM => &self.proof.error_m.native_rx,
                ErrorN => &self.proof.error_n.native_rx,
                Query => &self.proof.query.native_rx,
                Eval => &self.proof.eval.native_rx,
            };
            core::iter::once(poly)
        }

        fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
            core::iter::once(self.proof.application.circuit_id)
        }
    }

    /// Source for k(y) values for single-proof verification.
    pub struct SingleProofKySource<F> {
        pub raw_c: F,
        pub application_ky: F,
        pub unified_bridge_ky: F,
        pub unified_ky: F,
        pub endoscale_ky: F,
    }

    impl<F: Field> KySource for SingleProofKySource<F> {
        type Ky = F;

        fn raw_c(&self) -> impl Iterator<Item = F> {
            once(self.raw_c)
        }

        fn application_ky(&self) -> impl Iterator<Item = F> {
            once(self.application_ky)
        }

        fn unified_bridge_ky(&self) -> impl Iterator<Item = F> {
            once(self.unified_bridge_ky)
        }

        fn unified_ky(&self) -> impl Iterator<Item = F> + Clone {
            once(self.unified_ky)
        }

        fn endoscale_ky(&self) -> impl Iterator<Item = F> {
            once(self.endoscale_ky)
        }

        fn zero(&self) -> F {
            F::ZERO
        }
    }
}

mod nested {
    use super::*;
    use crate::components::claims::{
        Source,
        nested::{KySource, RxComponent},
    };

    pub use crate::components::claims::nested::ky_values;

    /// Source for nested field rx polynomials for single-proof verification.
    pub struct SingleProofSource<'rx, C: Cycle, R: Rank> {
        pub proof: &'rx Proof<C, R>,
    }

    impl<'rx, C: Cycle, R: Rank> Source for SingleProofSource<'rx, C, R> {
        type RxComponent = RxComponent;
        type Rx = &'rx structured::Polynomial<C::ScalarField, R>;
        type AppCircuitId = ();

        fn rx(&self, component: RxComponent) -> impl Iterator<Item = Self::Rx> {
            use RxComponent::*;
            let poly = match component {
                EndoscalarStage => &self.proof.p.endoscalar_rx,
                PointsStage => &self.proof.p.points_rx,
                EndoscalingStep(step) => &self.proof.p.step_rxs[step], // TODO: bounds
            };
            core::iter::once(poly)
        }

        fn app_circuits(&self) -> impl Iterator<Item = Self::AppCircuitId> {
            core::iter::empty()
        }
    }

    /// Source for k(y) values for nested single-proof verification.
    pub struct SingleProofKySource<F>(core::marker::PhantomData<F>);

    impl<F> SingleProofKySource<F> {
        pub fn new() -> Self {
            Self(core::marker::PhantomData)
        }
    }

    impl<F: Field> KySource for SingleProofKySource<F> {
        type Ky = F;

        fn one(&self) -> F {
            F::ONE
        }

        fn zero(&self) -> F {
            F::ZERO
        }
    }
}
