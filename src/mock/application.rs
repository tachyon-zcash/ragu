//! Mock PCD application — mirrors `ragu_pcd::Application`.

use alloc::{collections::BTreeMap, vec::Vec};
use core::{any::TypeId, fmt, marker::PhantomData};

use ragu_arithmetic::CryptoRngCore;
use ragu_core::{Error, Result};
use ragu_pasta::Fp;

use crate::{
    ctx::StepCtx,
    framework_hooks::{FrameworkHooks, HookConfig, NoHooks},
    header::{Header, Suffix},
    poly_commitment::{self, HANDLE_WIRES},
    polynomial::Polynomial,
    proof::{self, PROOF_SIZE_COMPRESSED, Pcd, Proof},
    step::Step,
};

/// Mocks `ragu_pcd::ApplicationBuilder`.
///
/// `J` declares the application's per-step hook budget, as in real ragu
/// (where it is the trailing generic after `C`, `R`, and `HEADER_SIZE`).
pub struct ApplicationBuilder<J: HookConfig = NoHooks> {
    num_application_steps: usize,
    header_map: BTreeMap<Suffix, TypeId>,
    _hooks: PhantomData<J>,
}

/// Mocks `ragu_pcd::Application`.
pub struct Application<J: HookConfig = NoHooks> {
    num_application_steps: usize,
    _hooks: PhantomData<J>,
}

// Hand-written rather than derived: a derive would bound `J` itself, and the
// hook marker types deliberately implement nothing.
impl<J: HookConfig> Clone for ApplicationBuilder<J> {
    fn clone(&self) -> Self {
        Self {
            num_application_steps: self.num_application_steps,
            header_map: self.header_map.clone(),
            _hooks: PhantomData,
        }
    }
}

impl<J: HookConfig> fmt::Debug for ApplicationBuilder<J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApplicationBuilder")
            .field("num_application_steps", &self.num_application_steps)
            .field("header_map", &self.header_map)
            .finish()
    }
}

impl<J: HookConfig> Clone for Application<J> {
    fn clone(&self) -> Self {
        Self {
            num_application_steps: self.num_application_steps,
            _hooks: PhantomData,
        }
    }
}

impl<J: HookConfig> fmt::Debug for Application<J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Application")
            .field("num_application_steps", &self.num_application_steps)
            .finish()
    }
}

impl ApplicationBuilder {
    /// A builder for an application with no hook budget ([`NoHooks`]).
    ///
    /// Real ragu's `new` takes the cycle params (moved there from `finalize`);
    /// the mock has no params object, so `new` stays argless. Real ragu also
    /// needs no [`with_hooks`](ApplicationBuilder::with_hooks) split: its
    /// other generics force a turbofish where a trailing hook config may be
    /// named, while the mock's only generic is the hook config — which cannot
    /// guide inference from a bare `new()` call.
    #[must_use]
    pub fn new() -> Self {
        Self::with_hooks()
    }
}

impl Default for ApplicationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl<J: HookConfig> ApplicationBuilder<J> {
    /// A builder for an application with the hook budget `J`, e.g.
    /// `ApplicationBuilder::<AppHooks<1, 2, 1, HANDLE_WIRES>>::with_hooks()`.
    /// See [`new`](ApplicationBuilder::new) for why this is a separate
    /// constructor.
    #[must_use]
    pub fn with_hooks() -> Self {
        Self {
            num_application_steps: 0,
            header_map: BTreeMap::new(),
            _hooks: PhantomData,
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
            .ok_or_else(|| Error::Initialization("registered step count overflow".into()))?;
        Ok(self)
    }

    pub fn finalize(self) -> Result<Application<J>> {
        let layout = J::layout();
        if layout.challenge_calls > 0 && layout.challenge_width == 0 {
            return Err(Error::Initialization(
                "a challenge layout with derivations needs a nonzero width: one absorbing no inputs would bind nothing"
                    .into(),
            ));
        }
        Ok(Application {
            num_application_steps: self.num_application_steps,
            _hooks: PhantomData,
        })
    }

    fn prevent_duplicate_suffix<H: Header>(&mut self) -> Result<()> {
        let suffix = H::SUFFIX;
        let type_id = TypeId::of::<H>();
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

impl<J: HookConfig> Application<J> {
    /// Delegates to [`fuse`](Self::fuse) with trivial PCDs.
    pub fn seed<'source, RNG: CryptoRngCore, S: Step<Left = (), Right = ()>>(
        &self,
        rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
    ) -> Result<(Pcd<S::Output>, S::Aux<'source>)> {
        let left = Proof::trivial().carry::<()>(());
        let right = Proof::trivial().carry::<()>(());
        self.fuse(rng, step, witness, left, right)
    }

    pub fn fuse<'source, RNG: CryptoRngCore, S: Step>(
        &self,
        _rng: &mut RNG,
        step: S,
        witness: S::Witness<'source>,
        left: Pcd<S::Left>,
        right: Pcd<S::Right>,
    ) -> Result<(Pcd<S::Output>, S::Aux<'source>)> {
        let left_proof = left.proof;
        let right_proof = right.proof;

        let mut hooks = FrameworkHooks::new(J::layout());
        let mut ctx = StepCtx::new(&mut hooks);
        let (output_data, aux) = step.witness(&mut ctx, witness, left.data, right.data)?;

        // Instance assembly, mock style: pad what the body left unused up to
        // the layout, refuse over-use, and fold the hook transcript into the
        // witness hash — from where the binding hash covers it, so tampering
        // surfaces through the existing binding check. The mock does not carry
        // queries or polynomials in the serialized proof and `verify` is
        // structurally unchanged: a dishonest evaluation is already rejected
        // here, and mock proofs only exist through this API or through
        // binding-checked deserialization, so real `verify`'s poly-query and
        // challenge rejection paths have no observable mock equivalent.
        hooks.pad_to_layout()?;
        let transcript = hooks.into_transcript()?;

        let encoded = S::Output::encode(&output_data);

        let left_bytes = left_proof.serialize();
        let right_bytes = right_proof.serialize();
        let mut witness_data = Vec::with_capacity(2 * PROOF_SIZE_COMPRESSED + transcript.len());
        witness_data.extend_from_slice(left_bytes.as_ref());
        witness_data.extend_from_slice(right_bytes.as_ref());
        witness_data.extend_from_slice(&transcript);

        let proof_value = Proof::new(S::Output::SUFFIX, S::INDEX, &encoded, &witness_data);
        Ok((proof_value.carry::<S::Output>(output_data), aux))
    }

    pub fn verify<RNG: CryptoRngCore, H: Header>(&self, pcd: &Pcd<H>, _rng: RNG) -> Result<bool> {
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

    pub fn rerandomize<RNG: CryptoRngCore, H: Header>(
        &self,
        pcd: Pcd<H>,
        _rng: &mut RNG,
    ) -> Result<Pcd<H>> {
        Ok(Pcd {
            proof: pcd.proof.rerandomize(),
            data: pcd.data,
        })
    }

    /// The handle wires
    /// [`StepCtx::witness_polynomial`](crate::ctx::StepCtx::witness_polynomial)
    /// would produce for `polynomial` — for callers outside a step checking a
    /// header-carried handle against a polynomial they hold. Mirrors
    /// `ragu_pcd::Application::commit_polynomial`.
    pub fn commit_polynomial(&self, polynomial: &Polynomial) -> Result<[Fp; HANDLE_WIRES]> {
        poly_commitment::handle(polynomial.commit())
    }
}
