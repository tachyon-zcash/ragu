//! Mock PCD application — mirrors `ragu_pcd::Application`.

use alloc::{collections::BTreeMap, vec::Vec};
use core::any::TypeId;

use ragu_core::{
    Error, Result,
    drivers::Driver as _,
    maybe::Maybe as _,
    pasta::{Fp, PastaParams},
};
use ragu_primitives::{Simulator, shared::Shared};
use rand::CryptoRng;

use super::{
    ctx::StepCtx,
    header::{Header, Suffix},
    hooks::FrameworkHooks,
    proof::{self, PROOF_SIZE_COMPRESSED, Pcd, Proof},
    step::{Encoded, Step},
};

/// Mocks `ragu_pcd::ApplicationBuilder`.
#[derive(Clone, Debug)]
pub struct ApplicationBuilder<'params, const HEADER_SIZE: usize> {
    params: &'params PastaParams,
    registered_outputs: Vec<Suffix>,
    shared_size: usize,
    header_map: BTreeMap<Suffix, TypeId>,
}

/// Mocks `ragu_pcd::Application`.
#[derive(Clone, Debug)]
pub struct Application<'params, const HEADER_SIZE: usize> {
    params: &'params PastaParams,
    registered_outputs: Vec<Suffix>,
    shared_size: usize,
}

impl<'params, const HEADER_SIZE: usize> ApplicationBuilder<'params, HEADER_SIZE> {
    #[must_use]
    pub fn new(params: &'params PastaParams) -> Self {
        Self {
            params,
            registered_outputs: Vec::new(),
            shared_size: 0,
            header_map: BTreeMap::new(),
        }
    }

    /// Mirrors `ragu_pcd::ApplicationBuilder::register`.
    pub fn register<S: Step + 'params>(mut self, _step: S) -> Result<Self> {
        S::INDEX.assert_sequential(self.registered_outputs.len())?;

        self.prevent_duplicate_suffix::<S::Output>()?;
        self.prevent_duplicate_suffix::<S::Left>()?;
        self.prevent_duplicate_suffix::<S::Right>()?;
        self.shared_size = self.shared_size.max(S::Shared::num_values()?);

        self.registered_outputs.push(S::Output::SUFFIX);
        Ok(self)
    }

    /// Finalizes the application using the parameters supplied to [`Self::new`].
    ///
    /// Keep `params` alive for the returned application's lifetime. Polynomial
    /// witnessing assumes that its canonical Pasta generator sequence contains
    /// at least the coefficient count for the selected polynomial rank.
    pub fn finalize(self) -> Result<Application<'params, HEADER_SIZE>> {
        if HEADER_SIZE == 0 {
            return Err(Error::Initialization(
                "HEADER_SIZE must include a suffix slot".into(),
            ));
        }
        Ok(Application {
            params: self.params,
            registered_outputs: self.registered_outputs,
            shared_size: self.shared_size,
        })
    }

    fn prevent_duplicate_suffix<H: Header>(&mut self) -> Result<()> {
        let suffix = H::SUFFIX;
        let type_id = TypeId::of::<H>();
        if suffix.get() < super::header::NUM_INTERNAL_SUFFIXES as u64
            && type_id != TypeId::of::<()>()
        {
            return Err(Error::Initialization(
                "only the unit Header () may use a reserved internal suffix".into(),
            ));
        }
        match self.header_map.get(&suffix) {
            Some(registered) if *registered != type_id => Err(Error::Initialization(
                "two different Header implementations using the same suffix".into(),
            )),
            Some(_) => Ok(()),
            None => {
                self.header_map.insert(suffix, type_id);
                Ok(())
            }
        }
    }
}

impl<const HEADER_SIZE: usize> Application<'_, HEADER_SIZE> {
    /// Mirrors `ragu_pcd::Application::seed`: runs a unit-input step over the
    /// bootstrap proof as both children, via [`fuse`](Self::fuse).
    pub fn seed<'source, RNG: CryptoRng, S: Step<Left = (), Right = ()>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
    ) -> Result<(Pcd<S::Output>, S::Aux<'source>)> {
        let left = Proof::bootstrap::<HEADER_SIZE>().carry::<()>(());
        let right = Proof::bootstrap::<HEADER_SIZE>().carry::<()>(());
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
        match S::INDEX.application() {
            Some(index) if index < self.registered_outputs.len() => {}
            _ => return Err(Error::Initialization(
                "attempted to use application Step index that exceeds Application registered steps"
                    .into(),
            )),
        }
        let left_proof = left.proof;
        let right_proof = right.proof;

        let mut dr = Simulator::<Fp>::new();
        let mut hooks = FrameworkHooks::new(self.params);
        let size = S::Shared::num_values()?;
        if size > self.shared_size {
            return Err(Error::Initialization(
                "the step's shared gadget has more wires than the application stage holds".into(),
            ));
        }
        let ((left_header, right_header, output_header), shared, output_data, aux) = {
            let mut ctx = StepCtx::new(&mut dr, &mut hooks);
            step.witness::<_, HEADER_SIZE>(
                &mut ctx,
                Simulator::<Fp>::just(|| witness),
                Simulator::<Fp>::just(|| left.data),
                Simulator::<Fp>::just(|| right.data),
            )?
        };
        let mut shared_values = Vec::with_capacity(size);
        S::Shared::write_shared(&shared, &mut shared_values)?;
        if shared_values.len() != size {
            return Err(Error::Initialization(
                "the shared gadget's witness count differs from its layout".into(),
            ));
        }
        // Mirror the reference adapter: serialize all three returned gadgets
        // on the step's driver before extracting any native values.
        let mut left_elements = Vec::new();
        left_header.write(&mut dr, &mut left_elements)?;
        let mut right_elements = Vec::new();
        right_header.write(&mut dr, &mut right_elements)?;
        let mut output_elements = Vec::new();
        output_header.write(&mut dr, &mut output_elements)?;
        let left_encoded: Vec<Fp> = left_elements.iter().map(|e| *e.value().take()).collect();
        let right_encoded: Vec<Fp> = right_elements.iter().map(|e| *e.value().take()).collect();
        let encoded: Vec<Fp> = output_elements.iter().map(|e| *e.value().take()).collect();
        // The mock has no recursive verifier. Check the header connection
        // directly so a step cannot substitute different input gadget wires.
        if proof::compute_header_hash(S::Left::SUFFIX, &left_encoded)? != left_proof.header_hash
            || proof::compute_header_hash(S::Right::SUFFIX, &right_encoded)?
                != right_proof.header_hash
        {
            return Err(Error::InvalidWitness(
                "input header does not match child proof".into(),
            ));
        }
        let output_data = output_data.take();
        let aux = aux.take();
        let _poly_queries = hooks.into_outputs().take();

        let left_bytes = left_proof.serialize();
        let right_bytes = right_proof.serialize();
        let mut witness_data = Vec::with_capacity(2 * PROOF_SIZE_COMPRESSED);
        witness_data.extend_from_slice(left_bytes.as_ref());
        witness_data.extend_from_slice(right_bytes.as_ref());

        let proof_value = Proof::new(S::Output::SUFFIX, S::INDEX, &encoded, &witness_data)?;
        Ok((proof_value.carry::<S::Output>(output_data), aux))
    }

    pub fn verify<RNG: CryptoRng, H: Header>(&self, pcd: &Pcd<H>, _rng: RNG) -> Result<bool> {
        let Some(application_index) = pcd.proof.step_index.application() else {
            return Ok(false);
        };
        // The header must match the output registered for the proof's step.
        if self.registered_outputs.get(application_index) != Some(&H::SUFFIX) {
            return Ok(false);
        }

        let mut dr = Simulator::<Fp>::new();
        let header = Encoded::<_, H, HEADER_SIZE>::new(
            &mut dr,
            &mut (),
            Simulator::<Fp>::just(|| pcd.data.clone()),
        )?;
        let mut elements = Vec::new();
        header.write(&mut dr, &mut elements)?;
        let encoded: Vec<Fp> = elements.iter().map(|e| *e.value().take()).collect();
        let expected_header_hash = proof::compute_header_hash(H::SUFFIX, &encoded)?;
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
