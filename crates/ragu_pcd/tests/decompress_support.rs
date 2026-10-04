//! Shared support for the decompression gadgets' tests: a real compressed
//! proof, the compression's transcript at each point the native verifier
//! reaches, and allocation under the simulator.

use alloc::vec::Vec;

use ragu_backend::ReferenceBackend;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    Cycle, Result,
    drivers::Driver,
    pasta::{Fp, Fq, Pasta},
};
use ragu_primitives::{Element, Simulator};
use rand::{SeedableRng, rngs::StdRng};
use udon::{curve::Affine, field::Field};

use crate::{
    Application, ApplicationBuilder, CompressedProof, RAGU_TAG,
    compress::{
        Sampled,
        batch::{self, Batch},
        revdot::{self, Openings, Reduction, fold::Weights},
        transcript,
    },
    internal::{ky, nested},
    ipa::{CycleTranscript, IpaCycle, IpaProof, IpaTranscript},
};

pub(crate) type TestR = ProductionRank;
pub(crate) const HEADER_SIZE: usize = 4;
pub(crate) type App = Application<'static, Pasta, TestR, HEADER_SIZE>;
pub(crate) type Transcript = CycleTranscript<'static, Pasta>;
pub(crate) type EqAffine = <Pasta as Cycle>::HostCurve;
pub(crate) type EpAffine = <Pasta as Cycle>::NestedCurve;

/// A compressed bootstrap proof with what the verifier derives before the
/// reductions: the fuse's challenges and the output header.
pub(crate) struct Setup {
    pub app: App,
    pub proof: CompressedProof<Pasta>,
    pub challenges: nested::Challenges<Fp>,
    pub header: Vec<Fp>,
}

impl Setup {
    pub fn new() -> Self {
        let app = ApplicationBuilder::<Pasta, TestR, HEADER_SIZE>::new()
            .finalize(crate::pasta::baked())
            .expect("failed to create test application");
        let pcd = app.bootstrap_pcd();
        let proof = app
            .compress(&pcd, &mut StdRng::seed_from_u64(1))
            .expect("compress should not error")
            .into_parts()
            .0;
        let mut fuse = Transcript::new(crate::pasta::baked(), RAGU_TAG).unwrap();
        let challenges = proof
            .instance
            .challenges(&mut fuse)
            .unwrap()
            .expect("pre_beta is in range");
        let header = ky::output_header::<Pasta, (), HEADER_SIZE>(()).unwrap();
        Setup {
            app,
            proof,
            challenges,
            header,
        }
    }

    /// The compression's transcript with the statement absorbed and both
    /// curves' challenges sampled, as the verifier starts.
    pub fn transcript(&self) -> (Transcript, Sampled<Fp>, Sampled<Fq>) {
        let mut t = transcript::<Pasta, ReferenceBackend>(
            crate::pasta::baked(),
            &self.proof.instance,
            &self.header,
        )
        .unwrap();
        let native = Sampled::squeeze(&mut t.host()).unwrap();
        let nested = Sampled::squeeze(&mut t.nested()).unwrap();
        (t, native, nested)
    }

    /// The claims' targets at the sampled `y` and `nested_y`.
    pub fn targets(&self, y: Fp, nested_y: Fq) -> (ky::NativeKy<Fp>, ky::NestedKy<Fq>) {
        self.proof
            .instance
            .targets::<HEADER_SIZE>(&self.challenges, &self.header, y, nested_y)
            .unwrap()
    }

    /// The native openings the batch takes, as `verify_compressed` builds
    /// them on `t`: the reduction's, then the instance's.
    pub fn native_openings(
        &self,
        t: &mut Transcript,
        sampled: &Sampled<Fp>,
        nested_y: Fq,
    ) -> Openings<EqAffine> {
        let instance = &self.proof.instance;
        let registry = &self.app.native_registry;
        let (targets, _) = self.targets(sampled.y, nested_y);
        let masked = instance
            .native_bindings::<TestR, ReferenceBackend, HEADER_SIZE>(
                &self.challenges,
                registry,
                sampled.sigma,
            )
            .unwrap();
        let mut openings = revdot::verify_native::<Pasta, TestR, ReferenceBackend>(
            instance.circuit_id,
            |component| instance.native_commitment(component),
            registry,
            sampled.y,
            sampled.z,
            &targets,
            &masked,
            &self.proof.native.reduction,
            &mut t.host(),
        )
        .unwrap()
        .expect("the honest native reduction holds");
        let (commitments, claims) = instance.native_openings::<TestR, ReferenceBackend>(
            &self.challenges,
            registry,
            sampled.w,
            openings.commitments.len(),
        );
        openings.commitments.extend(commitments);
        openings.claims.extend(claims);
        openings
    }

    /// The nested openings the batch takes, as `verify_compressed` builds
    /// them on `t`, which must stand where the nested reduction starts.
    pub fn nested_openings(
        &self,
        t: &mut Transcript,
        sampled: &Sampled<Fq>,
        native_y: Fp,
    ) -> Openings<EpAffine> {
        let instance = &self.proof.instance;
        let registry = &self.app.nested_registry;
        let (_, targets) = self.targets(native_y, sampled.y);
        let masked = instance
            .nested_bindings::<TestR, ReferenceBackend>(&self.challenges, registry, sampled.sigma)
            .unwrap();
        let mut openings = revdot::verify_nested::<Pasta, TestR, ReferenceBackend>(
            |component| instance.nested_commitment(component),
            registry,
            sampled.y,
            sampled.z,
            &targets,
            &masked,
            &self.proof.nested.reduction,
            &mut t.nested(),
        )
        .unwrap()
        .expect("the honest nested reduction holds");
        let (commitments, claims) = instance
            .nested_openings::<TestR, ReferenceBackend>(
                &self.challenges,
                registry,
                sampled.w,
                openings.commitments.len(),
            )
            .unwrap();
        openings.commitments.extend(commitments);
        openings.claims.extend(claims);
        openings
    }

    /// Runs the native side of the verifier on `t`, as `verify_compressed`
    /// does before the nested side, so that `t` stands where the nested
    /// reduction starts.
    pub fn run_native(&self, t: &mut Transcript, sampled: &Sampled<Fp>, nested_y: Fq) {
        let openings = self.native_openings(t, sampled, nested_y);
        assert!(
            batch::verify_openings::<_, TestR, ReferenceBackend>(
                &openings,
                &self.proof.native.batch,
                &self.proof.native.opening,
                Pasta::host_generators(crate::pasta::baked()),
                *Pasta::host_u(crate::pasta::baked()),
                &mut t.host(),
            )
            .unwrap(),
            "the honest native batch opens"
        );
    }
}

/// Replays the reduction's messages on `t` as the verifier does,
/// returning the challenges it squeezes: the fold's weights, $\rho$ and
/// $r$.
pub(crate) fn replay_reduction<C: Affine>(
    reduction: &Reduction<C>,
    t: &mut impl IpaTranscript<C>,
) -> (Weights<C::Scalar>, C::Scalar, C::Scalar) {
    let weights = reduction.fold.replay(t).unwrap();
    let rho = t.squeeze_challenge().unwrap();
    t.write_point(reduction.p).unwrap();
    t.write_point(reduction.q).unwrap();
    let r = t.squeeze_challenge().unwrap();
    for &opened in &reduction.openings {
        t.write_scalar(opened).unwrap();
    }
    t.write_scalar(reduction.p_at_inverse_r).unwrap();
    t.write_scalar(reduction.q_at_r).unwrap();
    (weights, rho, r)
}

/// Replays the batch's messages on `t` as the verifier does, returning
/// $\alpha$, $u$ and $\beta$.
pub(crate) fn replay_batch<C: Affine>(
    batch: &Batch<C>,
    t: &mut impl IpaTranscript<C>,
) -> (C::Scalar, C::Scalar, C::Scalar) {
    let alpha = t.squeeze_challenge().unwrap();
    t.write_point(batch.f).unwrap();
    let u = t.squeeze_challenge().unwrap();
    for &value in &batch.evaluations {
        t.write_scalar(value).unwrap();
    }
    let beta = t.squeeze_challenge().unwrap();
    (alpha, u, beta)
}

/// Replays the IPA's messages on `t` as the verifier does, returning
/// $\xi$, $z$ and the round challenges.
pub(crate) fn replay_ipa<C: Affine>(
    proof: &IpaProof<C>,
    t: &mut impl IpaTranscript<C>,
) -> (C::Scalar, C::Scalar, Vec<C::Scalar>) {
    t.write_point(proof.s_commitment).unwrap();
    let xi = t.squeeze_challenge().unwrap();
    let z = t.squeeze_challenge().unwrap();
    let mut rounds = Vec::with_capacity(proof.rounds.len());
    for &(l, r) in &proof.rounds {
        t.write_point(l).unwrap();
        t.write_point(r).unwrap();
        rounds.push(t.squeeze_challenge().unwrap());
    }
    t.write_scalar(proof.c).unwrap();
    (xi, z, rounds)
}

/// Allocates a value as an element under the simulator.
pub(crate) fn alloc<F: Field>(
    dr: &mut Simulator<F>,
    value: F,
) -> Result<Element<'static, Simulator<F>>> {
    Element::alloc(dr, &mut (), <Simulator<F> as Driver>::just(|| value))
}

/// Allocates each value as an element under the simulator.
pub(crate) fn alloc_all<F: Field>(
    dr: &mut Simulator<F>,
    values: impl IntoIterator<Item = F>,
) -> Result<Vec<Element<'static, Simulator<F>>>> {
    values.into_iter().map(|value| alloc(dr, value)).collect()
}
