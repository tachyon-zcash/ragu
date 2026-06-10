//! Mock PCD application — mirrors `ragu_pcd::Application`.

use alloc::{collections::BTreeMap, vec::Vec};
use core::any::TypeId;

use rand_core::CryptoRng;

use crate::{
    ctx::StepCtx,
    error::{Error, Result},
    header::{Header, Suffix},
    hooks::FrameworkHooks,
    proof::{self, PROOF_SIZE_COMPRESSED, Pcd, Proof},
    step::Step,
};

/// Mocks `ragu_pcd::ApplicationBuilder`.
#[derive(Clone, Debug, Default)]
pub struct ApplicationBuilder {
    num_application_steps: usize,
    header_map: BTreeMap<Suffix, TypeId>,
}

/// Mocks `ragu_pcd::Application`.
#[derive(Clone, Debug)]
pub struct Application {
    num_application_steps: usize,
}

impl ApplicationBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            num_application_steps: 0,
            header_map: BTreeMap::new(),
        }
    }

    pub fn register<S: Step>(mut self, _step: S) -> Result<Self> {
        S::INDEX.assert_sequential(self.num_application_steps)?;

        self.prevent_duplicate_suffix::<S::Output>()?;
        self.prevent_duplicate_suffix::<S::Left>()?;
        self.prevent_duplicate_suffix::<S::Right>()?;

        self.num_application_steps = self
            .num_application_steps
            .checked_add(1)
            .ok_or(Error("registered step count overflow"))?;
        Ok(self)
    }

    pub fn finalize(self) -> Result<Application> {
        Ok(Application {
            num_application_steps: self.num_application_steps,
        })
    }

    fn prevent_duplicate_suffix<H: Header>(&mut self) -> Result<()> {
        let suffix = H::SUFFIX;
        let type_id = TypeId::of::<H>();
        match self.header_map.get(&suffix) {
            Some(registered) if *registered != type_id => Err(Error(
                "two distinct Header implementations declared the same suffix",
            )),
            Some(_) => Ok(()),
            None => {
                self.header_map.insert(suffix, type_id);
                Ok(())
            }
        }
    }
}

impl Application {
    /// Delegates to [`fuse`](Self::fuse) with trivial PCDs.
    pub fn seed<'source, RNG: CryptoRng, S: Step<Left = (), Right = ()>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
    ) -> Result<(Pcd<S::Output>, S::Aux<'source>)> {
        let left = Proof::trivial().carry::<()>(());
        let right = Proof::trivial().carry::<()>(());
        self.fuse(rng, step, witness, left, right)
    }

    pub fn fuse<'source, RNG: CryptoRng, S: Step>(
        &self,
        _rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<S::Left>,
        right: Pcd<S::Right>,
    ) -> Result<(Pcd<S::Output>, S::Aux<'source>)> {
        let left_proof = left.proof;
        let right_proof = right.proof;

        let mut hooks = FrameworkHooks::new();
        let mut ctx = StepCtx::new(&mut hooks);
        let (output_data, aux) = step.witness(&mut ctx, witness, left.data, right.data)?;

        // TODO just like the real crate :D
        let _claims = hooks.into_outputs();

        let encoded = S::Output::encode(&output_data);

        let left_bytes = left_proof.serialize();
        let right_bytes = right_proof.serialize();
        let mut witness_data = Vec::with_capacity(2 * PROOF_SIZE_COMPRESSED);
        witness_data.extend_from_slice(left_bytes.as_ref());
        witness_data.extend_from_slice(right_bytes.as_ref());

        let proof_value = Proof::new(S::Output::SUFFIX, S::INDEX, &encoded, &witness_data);
        Ok((proof_value.carry::<S::Output>(output_data), aux))
    }

    pub fn verify<RNG: CryptoRng, H: Header>(&self, pcd: &Pcd<H>, _rng: RNG) -> Result<bool> {
        match pcd.proof.step_index.application() {
            Some(application_index) if application_index < self.num_application_steps => {}
            _ => return Ok(false),
        }

        let encoded = H::encode(&pcd.data);
        let expected_header_hash = proof::compute_header_hash(H::SUFFIX, &encoded);
        if expected_header_hash != pcd.proof.header_hash {
            return Ok(false);
        }

        let expected_binding = proof::compute_binding(
            pcd.proof.step_index,
            &pcd.proof.header_hash,
            &pcd.proof.witness_hash,
        );
        Ok(expected_binding == pcd.proof.binding)
    }

    pub fn rerandomize<RNG: CryptoRng, H: Header>(
        &self,
        pcd: Pcd<H>,
        _rng: &mut RNG,
    ) -> Result<Pcd<H>> {
        Ok(Pcd {
            proof: pcd.proof.rerandomize(),
            data: pcd.data,
        })
    }
}
