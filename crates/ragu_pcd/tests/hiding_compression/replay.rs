//! Honest witness generation and public checks of the implemented slices.

use alloc::vec;
use ragu_circuits::registry::CircuitIndex;
use udon::curve::Affine;

use super::{
    committed_instance::InstanceCommitments,
    fuse_prefix::FusePrefix,
    reduction_schedule::{Challenges, DiagnosticReplay, Messages, Prover},
    *,
};
use crate::{
    compress::revdot::{
        claims::{Masked, Shape, native_shapes, nested_shapes},
        fold::Layout,
        native_components, native_position, nested_components, nested_position,
    },
    profile::Standard,
};

type Side<C> = (BatchOpening<C>, Bases<C>, Params<C>);

fn native_shape(z: Fp) -> Vec<Shape<native::RxComponent, Fp>> {
    // The index only selects the application circuit polynomial. It has no
    // effect on any point coefficients or on the fold's shape.
    use native::RxIndex::*;
    let masks = [Preamble, Query, Eval, PointsAb, PointsF]
        .map(|index| Masked::new(native::RxComponent::Rx(index), vec![], vec![], Fp::ZERO));
    native_shapes::<Standard, _>(CircuitIndex::new(0), z, &masks).unwrap()
}

fn nested_shape<F: Field>(z: F) -> Vec<Shape<nested::RxComponent, F>> {
    use nested::RxIndex::*;
    let masks = [BridgePreamble, BridgeQuery, BridgeEval]
        .map(|index| Masked::new(nested::RxComponent::Rx(index), vec![], vec![], F::ZERO));
    nested_shapes::<Standard, _>(z, &masks).unwrap()
}

fn native_positions() -> [usize; 4] {
    use native::RxComponent::*;
    let count = native_components::<Standard>().count();
    [
        count,
        count + 1,
        native_position::<Standard>(AbA),
        native_position::<Standard>(AbB),
    ]
}

fn nested_positions() -> [usize; 4] {
    use nested::RxComponent::*;
    let count = nested_components::<Standard>().count();
    [
        count,
        count + 1,
        nested_position::<Standard>(AbA),
        nested_position::<Standard>(AbB),
    ]
}

fn transcript(
    app: &App,
    header: &[Fp; HEADER_SIZE],
    fuse: &FusePrefix,
    instance: &InstanceCommitments,
    side: &[u8],
) -> Transcript {
    let mut transcript = context(app, header);
    fuse.bind(&mut transcript);
    instance.absorb(&mut transcript);
    transcript.bytes(side);
    transcript
}

#[derive(Clone)]
pub(super) struct JointReduction {
    pub(super) instance: InstanceCommitments,
    pub(super) host_messages: Messages<Host>,
    pub(super) nested_messages: Messages<Nested>,
}

impl JointReduction {
    pub(super) fn batch_transcript(
        &self,
        app: &App,
        header: &[Fp; HEADER_SIZE],
        fuse: &FusePrefix,
        side: &[u8],
    ) -> Transcript {
        let transcript = transcript(app, header, fuse, &self.instance, side);
        if side == b"native" {
            self.host_messages.replay(transcript).1
        } else {
            self.nested_messages.replay(transcript).1
        }
    }

    pub(super) fn verify_native(
        &self,
        app: &App,
        header: &[Fp; HEADER_SIZE],
        fuse: &FusePrefix,
        batch: &BatchOpening<Host>,
        bases: Bases<Host>,
        params: &Params<Host>,
    ) -> bool {
        if !self.instance.has_expected_shape() {
            return false;
        }
        let transcript = transcript(app, header, fuse, &self.instance, b"native");
        let (challenges, transcript) = self.host_messages.replay(transcript);
        let shapes = native_shape(challenges.sampled.z);
        let inputs = reduction_schedule::inputs(
            &self.instance.host,
            &self.host_messages,
            &shapes,
            &challenges.weights,
            native_position::<Standard>,
            native_positions(),
        );
        verify_batch_source(
            batch,
            &self.host_messages,
            inputs,
            &challenges,
            shapes.len(),
            bases,
        ) && batch.verify_terminal_batch(transcript, bases, params)
    }

    pub(super) fn verify_nested(
        &self,
        app: &App,
        header: &[Fp; HEADER_SIZE],
        fuse: &FusePrefix,
        batch: &BatchOpening<Nested>,
        bases: Bases<Nested>,
        params: &Params<Nested>,
    ) -> bool {
        if !self.instance.has_expected_shape() {
            return false;
        }
        let transcript = transcript(app, header, fuse, &self.instance, b"nested");
        let (challenges, transcript) = self.nested_messages.replay(transcript);
        let shapes = nested_shape(challenges.sampled.z);
        let inputs = reduction_schedule::inputs(
            &self.instance.nested,
            &self.nested_messages,
            &shapes,
            &challenges.weights,
            nested_position::<Standard>,
            nested_positions(),
        );
        verify_batch_source(
            batch,
            &self.nested_messages,
            inputs,
            &challenges,
            shapes.len(),
            bases,
        ) && batch.verify_terminal_batch(transcript, bases, params)
    }

    pub(super) fn elements(&self) -> usize {
        let size = |points: usize, scalars: usize| 2 * points + scalars + 8 + 9;
        size(
            self.instance.host.points.len(),
            self.instance.host.scalars.len(),
        ) + size(
            self.instance.nested.points.len(),
            self.instance.nested.scalars.len(),
        )
    }
}

fn verify_batch_source<C: Affine>(
    batch: &BatchOpening<C>,
    messages: &Messages<C>,
    expected_inputs: [HiddenPoint<C>; POLYS],
    challenges: &Challenges<C::Scalar>,
    claim_count: usize,
    bases: Bases<C>,
) -> bool {
    let layout = Layout::new(claim_count);
    let weights = &challenges.weights;
    let expected = [
        challenges.r,
        challenges.sampled.z,
        challenges.rho,
        weights.inner::<TestR>(&layout).eval(challenges.r),
        weights.outer::<TestR>(&layout).eval(challenges.r),
    ];
    batch.public.inputs == expected_inputs
        && batch.public.queries[..DERIVED + 2]
            .iter()
            .zip(&messages.scalars[2..])
            .all(|((_, eval), scalar)| eval == scalar)
        && split_proof::PUBLIC_AUX
            .iter()
            .zip(expected)
            .all(|(&i, value)| batch.public.split[i] == bases.commit(value, C::Scalar::ZERO))
}

pub(super) fn batches(
    app: &App,
    pcd: &Pcd<Pasta, TestR, Value>,
    header: &[Fp; HEADER_SIZE],
    rng: &mut impl CryptoRng,
) -> (FusePrefix, JointReduction, Side<Host>, Side<Nested>) {
    let proof = pcd.proof();
    assert!(proof.well_formed::<HEADER_SIZE>());
    assert!(app.native_registry.circuit_in_domain(proof.circuit_id()));
    let instance = Instance::of::<TestR, HEADER_SIZE>(proof).unwrap();
    let mut fuse = CycleTranscript::<Pasta, Verifier>::new(app.params, RAGU_TAG).unwrap();
    let challenges = instance.challenges(&mut fuse).unwrap().unwrap();
    assert_eq!(proof.challenges().in_order(), challenges.in_order());
    assert!(
        instance
            .stages_match::<TestR, Verifier, HEADER_SIZE>(
                &challenges,
                Pasta::nested_generators(app.params)
            )
            .unwrap()
    );

    let native_generator = Pasta::host_generators(app.params);
    let nested_generator = Pasta::nested_generators(app.params);
    let native_u = *Pasta::host_u(app.params);
    let nested_u = *Pasta::nested_u(app.params);
    let native_bases = Bases::new(native_generator, native_u);
    let nested_bases = Bases::new(nested_generator, nested_u);
    let (committed, host_witness, nested_witness) =
        InstanceCommitments::commit(&instance, app.params, rng).unwrap();
    let (fuse, fuse_u) = FusePrefix::prove(
        app,
        header,
        &instance,
        &committed,
        &nested_witness,
        challenges.in_order(),
        native_bases,
        rng,
    )
    .unwrap();
    let host_context = transcript(app, header, &fuse, &committed, b"native");
    let nested_context = transcript(app, header, &fuse, &committed, b"nested");

    let mut host_prover = Prover::new(native_bases, host_context.clone(), rng);
    let Sampled { w, y, z, sigma } = Sampled::squeeze(&mut host_prover).unwrap();
    let host_registry = &app.native_registry;
    let masked = instance
        .native_bindings::<TestR, Verifier, HEADER_SIZE>(&challenges, host_registry, sigma)
        .unwrap();
    let (native_reduction, native_prover_witness) = revdot::reduce_native::<Pasta, TestR, Backend>(
        proof,
        host_registry,
        native_generator,
        y,
        z,
        &masked,
        &mut host_prover,
    )
    .unwrap();
    let (host_messages, host_blinders, host_batch_context) = host_prover.finish();

    let mut nested_prover = Prover::new(nested_bases, nested_context.clone(), rng);
    let Sampled {
        w: w_n,
        y: y_n,
        z: z_n,
        sigma: sigma_n,
    } = Sampled::squeeze(&mut nested_prover).unwrap();
    let nested_registry = &app.nested_registry;
    let masked_n = instance
        .nested_bindings::<TestR, Verifier>(&challenges, nested_registry, sigma_n)
        .unwrap();
    let (nested_reduction, nested_prover_witness) = revdot::reduce_nested::<Pasta, TestR, Backend>(
        proof,
        nested_registry,
        nested_generator,
        y_n,
        z_n,
        &masked_n,
        &mut nested_prover,
    )
    .unwrap();
    let (nested_messages, nested_blinders, nested_batch_context) = nested_prover.finish();

    let (native_targets, nested_targets) = instance
        .targets::<HEADER_SIZE>(&challenges, header, y, y_n)
        .unwrap();
    let native = {
        let mut host_verifier = DiagnosticReplay {
            transcript: host_context.clone(),
            messages: &host_messages,
            at: 0,
        };
        let _: Sampled<Fp> = Sampled::squeeze(&mut host_verifier).unwrap();
        let mut openings = revdot::verify_native::<Pasta, TestR, Verifier>(
            instance.circuit_id,
            |index| instance.native_commitment(index),
            host_registry,
            y,
            z,
            &native_targets,
            &masked,
            &native_reduction,
            &mut host_verifier,
        )
        .unwrap()
        .unwrap();
        let mut polys = native_prover_witness.polys();
        let (commitments, claims) =
            instance.native_openings::<TestR, Verifier>(&challenges, host_registry, w, polys.len());
        openings.commitments.extend(commitments);
        openings.claims.extend(claims);
        polys.extend(
            [
                proof.native_registry_xy_poly(),
                proof.native_p_poly(),
                &proof[native::RxComponent::AbA],
                &proof[native::RxComponent::AbB],
            ]
            .map(Cow::Borrowed),
        );
        let (host_challenges, _) = host_messages.replay(host_context);
        let shapes = native_shape(z);
        let position = native_position::<Standard>;
        let ciphertexts = reduction_schedule::inputs(
            &committed.host,
            &host_messages,
            &shapes,
            &host_challenges.weights,
            position,
            native_positions(),
        );
        let input_blinds = reduction_schedule::input_blinders(
            &host_witness.point_blinds,
            &host_blinders,
            &shapes,
            &host_challenges.weights,
            position,
            native_positions(),
        );
        run_batch(
            host_batch_context,
            &instance,
            &native_reduction,
            &openings,
            &polys,
            native_generator,
            native_u,
            Some(fuse_u),
            BatchSources {
                ciphertexts,
                input_blinds,
                reduction_evaluations: host_blinders.scalars[2..].try_into().unwrap(),
            },
            split_proof::auxiliaries(
                native_prover_witness.r,
                z,
                &native_reduction.openings,
                native_prover_witness.split,
            ),
            rng,
        )
    };
    let nested = {
        let mut nested_verifier = DiagnosticReplay {
            transcript: nested_context.clone(),
            messages: &nested_messages,
            at: 0,
        };
        let _: Sampled<<Nested as Affine>::Scalar> =
            Sampled::squeeze(&mut nested_verifier).unwrap();
        let mut openings = revdot::verify_nested::<Pasta, TestR, Verifier>(
            |index| instance.nested_commitment(index),
            nested_registry,
            y_n,
            z_n,
            &nested_targets,
            &masked_n,
            &nested_reduction,
            &mut nested_verifier,
        )
        .unwrap()
        .unwrap();
        let mut polys = nested_prover_witness.polys();
        let (commitments, claims) = instance
            .nested_openings::<TestR, Verifier>(&challenges, nested_registry, w_n, polys.len())
            .unwrap();
        openings.commitments.extend(commitments);
        openings.claims.extend(claims);
        polys.extend(
            [
                proof.nested_registry_xy_poly(),
                proof.nested_p_poly(),
                &proof[nested::RxComponent::AbA],
                &proof[nested::RxComponent::AbB],
            ]
            .map(Cow::Borrowed),
        );
        let (nested_challenges, _) = nested_messages.replay(nested_context);
        let shapes = nested_shape(z_n);
        let position = nested_position::<Standard>;
        let ciphertexts = reduction_schedule::inputs(
            &committed.nested,
            &nested_messages,
            &shapes,
            &nested_challenges.weights,
            position,
            nested_positions(),
        );
        let input_blinds = reduction_schedule::input_blinders(
            &nested_witness.point_blinds,
            &nested_blinders,
            &shapes,
            &nested_challenges.weights,
            position,
            nested_positions(),
        );
        run_batch(
            nested_batch_context,
            &instance,
            &nested_reduction,
            &openings,
            &polys,
            nested_generator,
            nested_u,
            None,
            BatchSources {
                ciphertexts,
                input_blinds,
                reduction_evaluations: nested_blinders.scalars[2..].try_into().unwrap(),
            },
            split_proof::auxiliaries(
                nested_prover_witness.r,
                z_n,
                &nested_reduction.openings,
                nested_prover_witness.split,
            ),
            rng,
        )
    };
    (
        fuse,
        JointReduction {
            instance: committed,
            host_messages,
            nested_messages,
        },
        native,
        nested,
    )
}
