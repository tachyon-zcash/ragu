//! Mock PCD application — mirrors `ragu_pcd::Application`.

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{any::TypeId, marker::PhantomData};

use ragu_circuits::polynomials::{Rank, sparse};
use ragu_core::{
    Cycle, Error, FixedGenerators as _, Result, drivers::Driver as _, maybe::Maybe as _,
};
use ragu_primitives::{ENDOSCALAR_BITS, ENDOSCALAR_PRODUCTS, Simulator};
use rand::CryptoRng;
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field,
};

use super::{
    header::{HEADER_POLYNOMIALS, Header, NUM_INTERNAL_SUFFIXES, Suffix},
    proof::{self, CompressedPcd, CompressedProof, Pcd, Proof},
    step::{Encoded, Index, Oracles, Step},
};

const BRIDGE_HASH_OFFSET: usize = 2 + (ENDOSCALAR_BITS + ENDOSCALAR_PRODUCTS).div_ceil(2);

/// Mocks `ragu_pcd::ApplicationBuilder`.
#[derive(Clone, Debug)]
pub struct ApplicationBuilder<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    registered_outputs: Vec<Suffix>,
    header_map: BTreeMap<Suffix, TypeId>,
    bootstrap: Option<Proof<C, R>>,
    _marker: PhantomData<(&'params C::Params, R)>,
}

/// Mocks `ragu_pcd::Application`.
#[derive(Clone, Debug)]
pub struct Application<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> {
    params: &'params C::Params,
    registered_outputs: Vec<Suffix>,
    bootstrap: Proof<C, R>,
    setup_hash: [u8; 32],
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize> Default
    for ApplicationBuilder<'params, C, R, HEADER_SIZE>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'params, C: Cycle, R: Rank, const HEADER_SIZE: usize>
    ApplicationBuilder<'params, C, R, HEADER_SIZE>
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            registered_outputs: Vec::new(),
            header_map: BTreeMap::new(),
            bootstrap: None,
            _marker: PhantomData,
        }
    }

    pub fn with_bootstrap(mut self, proof: Proof<C, R>) -> Result<Self> {
        let header = Encoded::<_, (), HEADER_SIZE>::from_gadget(());
        if proof.step_index != Index::internal(1)
            || proof.header_size != HEADER_SIZE
            || proof.header_hash
                != proof::compute_header_hash(&mut Simulator::<C::CircuitField>::new(), &header)?
            || proof
                .polynomials
                .iter()
                .any(|p| p.is_empty() || p.len() > R::num_coeffs())
        {
            return Err(Error::Initialization(
                "the supplied proof is not a reusable bootstrap proof".into(),
            ));
        }
        self.bootstrap = Some(proof);
        Ok(self)
    }

    /// Mirrors `ragu_pcd::ApplicationBuilder::register`.
    pub fn register<S: Step<C> + 'params>(mut self, _step: S) -> Result<Self> {
        S::INDEX.assert_sequential(self.registered_outputs.len())?;

        if S::NUM_STAGED
            .div_ceil(2)
            .checked_add(1)
            .is_none_or(|end| end >= R::n())
        {
            return Err(Error::Initialization(
                "the application stage does not fit the rank's gates".into(),
            ));
        }
        self.prevent_duplicate_suffix::<S::Output>()?;
        self.prevent_duplicate_suffix::<S::Left>()?;
        self.prevent_duplicate_suffix::<S::Right>()?;

        self.registered_outputs.push(S::Output::SUFFIX);
        Ok(self)
    }

    pub fn finalize(
        self,
        params: &'params C::Params,
    ) -> Result<Application<'params, C, R, HEADER_SIZE>> {
        if HEADER_SIZE == 0
            || R::n() < BRIDGE_HASH_OFFSET
            || C::host_generators(params).g().len() < R::num_coeffs()
            || C::nested_generators(params).g().len() < R::num_coeffs()
        {
            return Err(Error::Initialization(
                "invalid header size, rank, or insufficient generators".into(),
            ));
        }
        let polynomials = core::array::from_fn(|_| vec![C::CircuitField::ONE]);
        let setup_hash = proof::compute_setup_hash::<C, R>(params);
        let commitment = sparse::Polynomial::<_, R>::from_coeffs(vec![C::CircuitField::ONE])
            .commit_to_affine(C::host_generators(params));
        let header = Encoded::<_, (), HEADER_SIZE>::from_gadget(());
        let bootstrap = match self.bootstrap {
            Some(proof) => proof,
            None => Proof::new(
                Index::internal(1),
                &mut Simulator::<C::CircuitField>::new(),
                &header,
                &[],
                polynomials,
                [commitment; HEADER_POLYNOMIALS],
                setup_hash,
            )?,
        };
        Ok(Application {
            params,
            registered_outputs: self.registered_outputs,
            bootstrap,
            setup_hash,
        })
    }

    fn prevent_duplicate_suffix<H: Header<C::CircuitField>>(&mut self) -> Result<()> {
        let suffix = H::SUFFIX;
        let type_id = TypeId::of::<H>();
        if H::SUFFIX.get() < NUM_INTERNAL_SUFFIXES as u64 && type_id != TypeId::of::<()>() {
            return Err(Error::Initialization(
                "only the unit Header () may use a reserved internal suffix".into(),
            ));
        }
        match self.header_map.get(&suffix) {
            Some(registered) if *registered != type_id => Err(Error::Initialization(
                "two distinct Header implementations declared the same suffix".into(),
            )),
            Some(_) => Ok(()),
            None => {
                self.header_map.insert(suffix, type_id);
                Ok(())
            }
        }
    }
}

impl<C: Cycle, R: Rank, const HEADER_SIZE: usize> Application<'_, C, R, HEADER_SIZE> {
    pub fn bootstrap_proof(&self) -> &Proof<C, R> {
        &self.bootstrap
    }

    pub fn commit(&self, coefficients: &[C::CircuitField]) -> Result<C::HostCurve> {
        if coefficients.len() > R::num_coeffs() {
            return Err(Error::InvalidWitness(
                "polynomial exceeds rank capacity".into(),
            ));
        }
        Ok(
            sparse::Polynomial::<_, R>::from_coeffs(coefficients.to_vec())
                .commit_to_affine(C::host_generators(self.params)),
        )
    }

    pub fn bridge_hash(&self, point: C::HostCurve) -> Result<C::NestedCurve> {
        let (x, y) = point
            .coordinates()
            .ok_or_else(|| Error::InvalidWitness("cannot hash the identity commitment".into()))?;
        let n = R::n();
        let i = 2 * n - BRIDGE_HASH_OFFSET;
        let j = 4 * n - BRIDGE_HASH_OFFSET;
        let generators = C::nested_generators(self.params).g();
        Ok(ragu_core::msm([x, y], [generators[i], generators[j]]).to_affine())
    }

    /// Mirrors `ragu_pcd::Application::seed`: runs a unit-input step over the
    /// bootstrap proof as both children, via [`fuse`](Self::fuse).
    pub fn seed<'source, RNG: CryptoRng, S: Step<C, Left = (), Right = ()>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
    ) -> Result<(Pcd<C, R, S::Output>, S::Aux<'source>)> {
        let left = self.bootstrap.clone().carry::<()>(());
        let right = self.bootstrap.clone().carry::<()>(());
        self.fuse(rng, step, witness, left, right)
    }

    pub fn fuse<'source, RNG: CryptoRng, S: Step<C>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<C, R, S::Left>,
        right: Pcd<C, R, S::Right>,
    ) -> Result<(Pcd<C, R, S::Output>, S::Aux<'source>)> {
        if S::INDEX
            .application()
            .and_then(|i| self.registered_outputs.get(i))
            != Some(&S::Output::SUFFIX)
        {
            return Err(Error::Initialization(
                "attempted to use an unregistered application Step index".into(),
            ));
        }
        // Bind the carried data before the hooks can stage or commit anything
        // derived from it. Returned gadgets are checked independently below.
        if !self.verify_uncompressed(&left, &mut *rng)?
            || !self.verify_uncompressed(&right, &mut *rng)?
        {
            return Err(Error::InvalidWitness(
                "child proof or carried header is not accepted by this application".into(),
            ));
        }
        let staged = step.staged(&witness, left.input(), right.input())?;
        if staged.len() != S::NUM_STAGED {
            return Err(Error::InvalidWitness(
                "a step must stage exactly NUM_STAGED values".into(),
            ));
        }
        let mut polynomials = step.polynomials(&witness, left.input(), right.input())?;
        let mut commitments = [C::HostCurve::identity(); HEADER_POLYNOMIALS];
        for (coefficients, commitment) in polynomials.iter_mut().zip(&mut commitments) {
            if coefficients.len() > R::num_coeffs() {
                return Err(Error::InvalidWitness(
                    "polynomial exceeds rank capacity".into(),
                ));
            }
            while coefficients.last() == Some(&C::CircuitField::ZERO) {
                coefficients.pop();
            }
            if coefficients.is_empty() {
                return Err(Error::InvalidWitness(
                    "an online polynomial must not be zero".into(),
                ));
            }
            *commitment = self.commit(coefficients)?;
            if commitment.is_identity() {
                return Err(Error::InvalidWitness(
                    "an online commitment must not be the identity".into(),
                ));
            }
        }
        let mut transcript = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(b"MkRagu_Zeta____\0")
            .to_state();
        transcript
            .update(&S::INDEX.get().to_le_bytes())
            .update(&left.proof.header_hash)
            .update(&right.proof.header_hash);
        for points in [
            &left.proof.commitments,
            &right.proof.commitments,
            &commitments,
        ] {
            for point in points {
                transcript.update(point.to_bytes().as_ref());
            }
        }
        for value in &staged {
            transcript.update(value.to_bytes().as_ref());
        }
        let zeta = C::CircuitField::from_uniform_bytes(transcript.finalize().as_array());
        let (x, y) = self
            .bridge_hash(commitments[1])?
            .coordinates()
            .ok_or_else(|| Error::InvalidWitness("bridge hash is the identity".into()))?;
        let mut dr = Simulator::<C::CircuitField>::new();
        let mut oracles = Oracles::alloc(
            &mut dr,
            zeta,
            [x, y],
            staged,
            [
                &left.proof.polynomials,
                &right.proof.polynomials,
                &polynomials,
            ],
        )?;
        let ((left_header, right_header, output_header), output_data, aux) = step
            .witness::<_, HEADER_SIZE>(
                &mut dr,
                &mut oracles,
                Simulator::<C::CircuitField>::just(|| witness),
                Simulator::<C::CircuitField>::just(|| left.data),
                Simulator::<C::CircuitField>::just(|| right.data),
            )?;
        if proof::compute_header_hash(&mut dr, &left_header)? != left.proof.header_hash
            || proof::compute_header_hash(&mut dr, &right_header)? != right.proof.header_hash
        {
            return Err(Error::InvalidWitness(
                "input header does not match child proof".into(),
            ));
        }
        let left_proof = left.proof;
        let right_proof = right.proof;
        let left_bytes = left_proof.hash_input();
        let right_bytes = right_proof.hash_input();
        let mut witness_data = Vec::with_capacity(left_bytes.len() + right_bytes.len());
        witness_data.extend_from_slice(left_bytes.as_ref());
        witness_data.extend_from_slice(right_bytes.as_ref());

        let proof_value = Proof::new(
            S::INDEX,
            &mut dr,
            &output_header,
            &witness_data,
            polynomials,
            commitments,
            self.setup_hash,
        )?;
        Ok((
            proof_value.carry::<S::Output>(output_data.take()),
            aux.take(),
        ))
    }

    pub fn verify_uncompressed<RNG: CryptoRng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<C, R, H>,
        _rng: RNG,
    ) -> Result<bool> {
        if pcd.proof.header_size != HEADER_SIZE {
            return Ok(false);
        }
        for (coefficients, point) in pcd.proof.polynomials.iter().zip(pcd.proof.commitments) {
            if coefficients.is_empty()
                || coefficients.len() > R::num_coeffs()
                || point.is_identity()
                || self.commit(coefficients)? != point
            {
                return Ok(false);
            }
        }
        self.verify_statement::<H>(&pcd.proof.compressed(), &pcd.data)
    }

    pub fn compress<RNG: CryptoRng, H: Header<C::CircuitField>>(
        &self,
        pcd: &Pcd<C, R, H>,
        rng: &mut RNG,
    ) -> Result<CompressedPcd<C, H>> {
        if !self.verify_uncompressed(pcd, rng)? {
            return Err(Error::InvalidWitness(
                "cannot compress an invalid proof".into(),
            ));
        }
        Ok(pcd.proof.compressed().carry(pcd.data.clone()))
    }

    pub fn verify_compressed<H: Header<C::CircuitField>>(
        &self,
        pcd: &CompressedPcd<C, H>,
    ) -> Result<bool> {
        self.verify_statement::<H>(&pcd.proof, &pcd.data)
    }

    fn verify_statement<H: Header<C::CircuitField>>(
        &self,
        proof: &CompressedProof<C>,
        data: &H::Data,
    ) -> Result<bool> {
        if proof.rank != R::RANK
            || proof.header_size != HEADER_SIZE
            || proof.setup_hash != self.setup_hash
        {
            return Ok(false);
        }
        if proof.step_index != Index::internal(1) || TypeId::of::<H>() != TypeId::of::<()>() {
            let Some(application_index) = proof.step_index.application() else {
                return Ok(false);
            };
            // The header must match the output registered for the proof's step.
            if self.registered_outputs.get(application_index) != Some(&H::SUFFIX) {
                return Ok(false);
            }
        }
        let mut dr = Simulator::<C::CircuitField>::new();
        let data = Simulator::<C::CircuitField>::just(|| data.clone());
        let header = Encoded::<_, H, HEADER_SIZE>::new(&mut dr, &mut (), data)?;
        let expected_header_hash = proof::compute_header_hash(&mut dr, &header)?;
        if expected_header_hash != proof.header_hash {
            return Ok(false);
        }

        let expected_binding = proof::compute_binding(
            proof.step_index,
            &proof.header_hash,
            &proof.witness_hash,
            &proof.commitments,
            &proof.setup_hash,
            proof.rank,
            proof.header_size,
        );
        Ok(expected_binding == proof.binding)
    }

    pub fn rerandomize<RNG: CryptoRng, H: Header<C::CircuitField>>(
        &self,
        pcd: Pcd<C, R, H>,
        _rng: &mut RNG,
    ) -> Result<Pcd<C, R, H>> {
        Ok(Pcd {
            proof: pcd.proof.rerandomize(),
            data: pcd.data,
        })
    }
}
