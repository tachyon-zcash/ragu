//! GGM (Goldreich–Goldwasser–Micali) PRF tree derivation example.
//!
//! Ported in shape from the Tachyon nullifier-derivation circuit, adapted
//! onto real `ragu_pcd`. The flow is:
//!
//! ```text
//!   GgmSeed          → MasterHeader    (mk, delegation_id)
//!   GgmFirstStep     → DelegationHeader (node, depth=1, index=b0, delegation_id)
//!   GgmStep<DEPTH> × (DEPTH-1)          (node, depth+1, index*2+b, delegation_id)
//!   GgmLeaf<DEPTH>   → NullifierHeader  (nullifier=node, epoch=index, delegation_id)
//! ```
//!
//! Every cryptographic intermediate is derived **in-circuit** — `cm`, `mk`,
//! and `delegation_id` are computed from the supplied note fields, never
//! accepted as free witnesses.
//!
//! Simplifications vs. Tachyon:
//! * `pk` is a witness rather than being derived from `(ak, nk)`; the
//!   payment-key cross-check (`note.pk == pak.derive_payment_key()`) is
//!   skipped. Bringing in `ak` is orthogonal to GGM shape.
//! * `value` is a plain field element — no u64 range-check.
//!
//! ## Header slot layout
//!
//! * `MasterHeader::Data    = (mk, delegation_id)`.
//! * `DelegationHeader::Data = (node, depth, index, delegation_id)`.
//! * `NullifierHeader::Data  = (nullifier, epoch, delegation_id)`.
//!
//! `Data` is a flat N-tuple for ergonomic `.cast()` destructuring; `Output`
//! is right-nested pairs of `Element`s because the `Gadget` / `Write`
//! tuple blankets only cover 2-tuples.

use ff::{Field, PrimeField};
use ragu_arithmetic::Cycle;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue, emulator::Emulator},
    gadgets::{Bound, Kind},
    maybe::{Always, Maybe, MaybeKind},
};
use ragu_pcd::{
    header::{Header, Suffix},
    step::{Encoded, Index, Step},
};
use ragu_primitives::{
    Boolean, Element,
    allocator::{Allocator, Standard},
    poseidon::Sponge,
};

/// 16-byte domain-separation tags, each packed into a single `u128` and
/// materialised as a constant `Element` via
/// `F::from_u128(u128::from_le_bytes(*tag))`. Parallels Tachyon's
/// `NOTE_COMMITMENT_DOMAIN` / `NOTE_MASTER_DOMAIN` / `NOTE_ID_DOMAIN` /
/// `NOTE_NULLIFIER_DOMAIN`.
pub mod domain {
    /// Note-commitment derivation.
    pub const CM: &[u8; 16] = b"RaguGgmEx/Cm/001";
    /// Note master key (`mk`) derivation.
    pub const MK: &[u8; 16] = b"RaguGgmEx/Mk/001";
    /// Delegation-id derivation.
    pub const ID: &[u8; 16] = b"RaguGgmEx/Id/001";
    /// GGM tree step.
    pub const GGM: &[u8; 16] = b"RaguGgmEx/Ggm/01";
}

/// Pack a 16-byte tag into a field element.
pub fn tag<F: PrimeField>(t: &[u8; 16]) -> F {
    F::from_u128(u128::from_le_bytes(*t))
}

// ========================================================================
// Headers
// ========================================================================

/// Carries `(mk, delegation_id)` after the seed step.
pub struct MasterHeader;

impl<F: PrimeField> Header<F> for MasterHeader {
    const SUFFIX: Suffix = Suffix::new(10);
    type Data = (F, F);
    type Output = Kind![F; (Element<'_, _>, Element<'_, _>)];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (mk, did) = witness.cast();
        Ok((
            Element::alloc(dr, allocator, mk)?,
            Element::alloc(dr, allocator, did)?,
        ))
    }
}

/// Carries `(node, depth, index, delegation_id)` at an interior tree level.
pub struct DelegationHeader;

impl<F: PrimeField> Header<F> for DelegationHeader {
    const SUFFIX: Suffix = Suffix::new(11);
    type Data = (F, F, F, F);
    type Output = Kind![F; (Element<'_, _>, (Element<'_, _>, (Element<'_, _>, Element<'_, _>)))];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (node, depth, index, did) = witness.cast();
        Ok((
            Element::alloc(dr, allocator, node)?,
            (
                Element::alloc(dr, allocator, depth)?,
                (
                    Element::alloc(dr, allocator, index)?,
                    Element::alloc(dr, allocator, did)?,
                ),
            ),
        ))
    }
}

/// Carries `(nullifier, epoch, delegation_id)` at the leaf.
pub struct NullifierHeader;

impl<F: PrimeField> Header<F> for NullifierHeader {
    const SUFFIX: Suffix = Suffix::new(12);
    type Data = (F, F, F);
    type Output = Kind![F; (Element<'_, _>, (Element<'_, _>, Element<'_, _>))];

    fn encode<'dr, D: Driver<'dr, F = F>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> Result<Bound<'dr, D, Self::Output>> {
        let (nf, ep, did) = witness.cast();
        Ok((
            Element::alloc(dr, allocator, nf)?,
            (
                Element::alloc(dr, allocator, ep)?,
                Element::alloc(dr, allocator, did)?,
            ),
        ))
    }
}

// ========================================================================
// Steps
// ========================================================================

/// Seed step: derives `cm`, `mk`, and `delegation_id` from realistic note
/// fields. Produces a `MasterHeader`.
pub struct GgmSeed<'params, C: Cycle> {
    /// Poseidon parameters used for all in-circuit sponges.
    pub poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for GgmSeed<'_, C>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(0);
    type Witness<'source> = (
        C::CircuitField, // nk
        C::CircuitField, // pk
        C::CircuitField, // value
        C::CircuitField, // psi
        C::CircuitField, // rcm
        C::CircuitField, // delegation trapdoor
    );
    type Aux<'source> = ();
    type Left = ();
    type Right = ();
    type Output = MasterHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        _left: DriverValue<D, ()>,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let (nk, pk, value, psi, rcm, trap) = witness.cast();
        let nk = Element::alloc(dr, allocator, nk)?;
        let pk = Element::alloc(dr, allocator, pk)?;
        let value = Element::alloc(dr, allocator, value)?;
        let psi = Element::alloc(dr, allocator, psi)?;
        let rcm = Element::alloc(dr, allocator, rcm)?;
        let trap = Element::alloc(dr, allocator, trap)?;

        // cm = Poseidon(CM_DOMAIN, rcm, pk, value, psi).
        let cm = {
            let tag_cm = Element::constant(dr, tag::<C::CircuitField>(domain::CM));
            let mut sp = Sponge::new(dr, self.poseidon_params);
            sp.absorb(dr, &tag_cm)?;
            sp.absorb(dr, &rcm)?;
            sp.absorb(dr, &pk)?;
            sp.absorb(dr, &value)?;
            sp.absorb(dr, &psi)?;
            sp.squeeze(dr)?
        };

        // mk = Poseidon(MK_DOMAIN, psi, nk).
        let mk = {
            let tag_mk = Element::constant(dr, tag::<C::CircuitField>(domain::MK));
            let mut sp = Sponge::new(dr, self.poseidon_params);
            sp.absorb(dr, &tag_mk)?;
            sp.absorb(dr, &psi)?;
            sp.absorb(dr, &nk)?;
            sp.squeeze(dr)?
        };

        // delegation_id = Poseidon(ID_DOMAIN, mk, cm, trap).
        let did = {
            let tag_id = Element::constant(dr, tag::<C::CircuitField>(domain::ID));
            let mut sp = Sponge::new(dr, self.poseidon_params);
            sp.absorb(dr, &tag_id)?;
            sp.absorb(dr, &mk)?;
            sp.absorb(dr, &cm)?;
            sp.absorb(dr, &trap)?;
            sp.squeeze(dr)?
        };

        let mk_v = mk.value().map(|v| *v);
        let did_v = did.value().map(|v| *v);
        let output_data = mk_v.and_then(move |m| did_v.map(move |d| (m, d)));
        let output = Encoded::from_gadget((mk, did));

        Ok((
            (
                Encoded::from_gadget(()),
                Encoded::from_gadget(()),
                output,
            ),
            output_data,
            D::unit(),
        ))
    }
}

/// First GGM tree step: `MasterHeader` → `DelegationHeader` at depth 1.
pub struct GgmFirstStep<'params, C: Cycle> {
    /// Poseidon parameters used for the tree-step sponge.
    pub poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle> Step<C> for GgmFirstStep<'_, C>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(1);
    type Witness<'source> = bool;
    type Aux<'source> = ();
    type Left = MasterHeader;
    type Right = ();
    type Output = DelegationHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<
            D,
            <Self::Left as Header<C::CircuitField>>::Data,
        >,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, allocator, left)?;
        let right = Encoded::from_gadget(());
        let bit = Boolean::alloc(dr, allocator, witness)?;
        let bit_elem = bit.element();

        let (mk, delegation_id) = left.as_gadget();

        // node_1 = Poseidon(GGM_DOMAIN, mk, bit).
        let node = {
            let tag_ggm = Element::constant(dr, tag::<C::CircuitField>(domain::GGM));
            let mut sp = Sponge::new(dr, self.poseidon_params);
            sp.absorb(dr, &tag_ggm)?;
            sp.absorb(dr, mk)?;
            sp.absorb(dr, &bit_elem)?;
            sp.squeeze(dr)?
        };

        let depth = Element::constant(dr, C::CircuitField::ONE);
        let index = bit_elem;
        let did = delegation_id.clone();

        let node_v = node.value().map(|v| *v);
        let depth_v = depth.value().map(|v| *v);
        let index_v = index.value().map(|v| *v);
        let did_v = did.value().map(|v| *v);
        let output_data = node_v.and_then(move |n| {
            depth_v.and_then(move |d| {
                index_v.and_then(move |i| did_v.map(move |x| (n, d, i, x)))
            })
        });

        let output = Encoded::from_gadget((node, (depth, (index, did))));

        Ok(((left, right, output), output_data, D::unit()))
    }
}

/// Inner GGM tree step: `DelegationHeader` → `DelegationHeader`, descending
/// one level.
pub struct GgmStep<'params, C: Cycle, const DEPTH: u8> {
    /// Poseidon parameters used for the tree-step sponge.
    pub poseidon_params: &'params C::CircuitPoseidon,
}

impl<C: Cycle, const DEPTH: u8> Step<C> for GgmStep<'_, C, DEPTH>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(2);
    type Witness<'source> = bool;
    type Aux<'source> = ();
    type Left = DelegationHeader;
    type Right = ();
    type Output = DelegationHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<
            D,
            <Self::Left as Header<C::CircuitField>>::Data,
        >,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, allocator, left)?;
        let right = Encoded::from_gadget(());
        let bit = Boolean::alloc(dr, allocator, witness)?;
        let bit_elem = bit.element();

        let (prev_node, (prev_depth, (prev_index, delegation_id))) = left.as_gadget();

        // node' = Poseidon(GGM_DOMAIN, prev_node, bit).
        let node = {
            let tag_ggm = Element::constant(dr, tag::<C::CircuitField>(domain::GGM));
            let mut sp = Sponge::new(dr, self.poseidon_params);
            sp.absorb(dr, &tag_ggm)?;
            sp.absorb(dr, prev_node)?;
            sp.absorb(dr, &bit_elem)?;
            sp.squeeze(dr)?
        };

        let one = Element::one();
        let depth = prev_depth.add(dr, &one);
        let index = prev_index.double(dr).add(dr, &bit_elem);
        let did = delegation_id.clone();

        let node_v = node.value().map(|v| *v);
        let depth_v = depth.value().map(|v| *v);
        let index_v = index.value().map(|v| *v);
        let did_v = did.value().map(|v| *v);
        let output_data = node_v.and_then(move |n| {
            depth_v.and_then(move |d| {
                index_v.and_then(move |i| did_v.map(move |x| (n, d, i, x)))
            })
        });

        let output = Encoded::from_gadget((node, (depth, (index, did))));

        // Depth is not range-checked here; soundness of the terminal
        // NullifierHeader is closed by `GgmLeaf`, which asserts
        // `depth == DEPTH`. Any walk that does not terminate at exactly
        // DEPTH cannot produce a valid leaf proof.
        let _ = DEPTH;

        Ok(((left, right, output), output_data, D::unit()))
    }
}

/// Leaf step: re-wraps a depth-`DEPTH` `DelegationHeader` as a
/// `NullifierHeader`. Asserts in-circuit that the incoming depth equals
/// `DEPTH`.
pub struct GgmLeaf<const DEPTH: u8>;

impl<C: Cycle, const DEPTH: u8> Step<C> for GgmLeaf<DEPTH>
where
    C::CircuitField: PrimeField,
{
    const INDEX: Index = Index::new(3);
    type Witness<'source> = ();
    type Aux<'source> = ();
    type Left = DelegationHeader;
    type Right = ();
    type Output = NullifierHeader;

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = C::CircuitField>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<
            D,
            <Self::Left as Header<C::CircuitField>>::Data,
        >,
        _right: DriverValue<D, ()>,
    ) -> Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<C::CircuitField>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let allocator = &mut Standard::new();
        let left = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, allocator, left)?;
        let right = Encoded::from_gadget(());

        let (node, (depth, (index, delegation_id))) = left.as_gadget();

        // Assert depth == DEPTH.
        let expected_depth =
            Element::constant(dr, C::CircuitField::from(DEPTH as u64));
        let diff = depth.sub(dr, &expected_depth);
        diff.enforce_zero(dr)?;

        let nullifier = node.clone();
        let epoch = index.clone();
        let did = delegation_id.clone();

        let nf_v = nullifier.value().map(|v| *v);
        let ep_v = epoch.value().map(|v| *v);
        let did_v = did.value().map(|v| *v);
        let output_data = nf_v.and_then(move |n| {
            ep_v.and_then(move |e| did_v.map(move |x| (n, e, x)))
        });

        let output = Encoded::from_gadget((nullifier, (epoch, did)));

        Ok(((left, right, output), output_data, D::unit()))
    }
}

// ========================================================================
// Native reference
// ========================================================================

/// Six-tuple `(nk, pk, value, psi, rcm, trap)` matching
/// [`GgmSeed::Witness`].
pub type SeedWitness<C> = (
    <C as Cycle>::CircuitField,
    <C as Cycle>::CircuitField,
    <C as Cycle>::CircuitField,
    <C as Cycle>::CircuitField,
    <C as Cycle>::CircuitField,
    <C as Cycle>::CircuitField,
);

/// Native Poseidon walk, mirroring the in-circuit steps bit-for-bit.
///
/// Uses the same `Sponge` / domain-tag / absorb-order logic the `witness()`
/// bodies use, but drives them with [`Emulator::execute`] — a native driver
/// that computes wire assignments without synthesising constraints.
///
/// Returns `(nullifier, epoch, delegation_id)` as field elements.
pub fn native_ggm_walk<C: Cycle>(
    poseidon_params: &C::CircuitPoseidon,
    seed_witness: SeedWitness<C>,
    epoch: u32,
    depth: u8,
) -> Result<(C::CircuitField, C::CircuitField, C::CircuitField)>
where
    C::CircuitField: PrimeField,
{
    let (nk, pk, value, psi, rcm, trap) = seed_witness;
    let mut dr = Emulator::execute();
    let allocator = &mut Standard::new();
    let dr = &mut dr;

    // Allocate raw field inputs as Elements. The wireless emulator's
    // MaybeKind is `Always<()>`, so `Always::maybe_just` produces the
    // DriverValue wrapper for each field value.
    let just = |v: C::CircuitField| Always::maybe_just(|| v);
    let nk_e = Element::alloc(dr, allocator, just(nk))?;
    let pk_e = Element::alloc(dr, allocator, just(pk))?;
    let value_e = Element::alloc(dr, allocator, just(value))?;
    let psi_e = Element::alloc(dr, allocator, just(psi))?;
    let rcm_e = Element::alloc(dr, allocator, just(rcm))?;
    let trap_e = Element::alloc(dr, allocator, just(trap))?;

    // cm = Poseidon(CM_DOMAIN, rcm, pk, value, psi).
    let cm = {
        let t = Element::constant(dr, tag::<C::CircuitField>(domain::CM));
        let mut sp = Sponge::new(dr, poseidon_params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &rcm_e)?;
        sp.absorb(dr, &pk_e)?;
        sp.absorb(dr, &value_e)?;
        sp.absorb(dr, &psi_e)?;
        sp.squeeze(dr)?
    };

    // mk = Poseidon(MK_DOMAIN, psi, nk).
    let mk = {
        let t = Element::constant(dr, tag::<C::CircuitField>(domain::MK));
        let mut sp = Sponge::new(dr, poseidon_params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &psi_e)?;
        sp.absorb(dr, &nk_e)?;
        sp.squeeze(dr)?
    };

    // delegation_id = Poseidon(ID_DOMAIN, mk, cm, trap).
    let did = {
        let t = Element::constant(dr, tag::<C::CircuitField>(domain::ID));
        let mut sp = Sponge::new(dr, poseidon_params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &mk)?;
        sp.absorb(dr, &cm)?;
        sp.absorb(dr, &trap_e)?;
        sp.squeeze(dr)?
    };

    // Walk the GGM tree MSB-first.
    let mut node = mk;
    for d in (0..depth).rev() {
        let bit = (epoch >> d) & 1 != 0;
        let bit_e = Element::alloc(
            dr,
            allocator,
            just(if bit {
                C::CircuitField::ONE
            } else {
                C::CircuitField::ZERO
            }),
        )?;

        let t = Element::constant(dr, tag::<C::CircuitField>(domain::GGM));
        let mut sp = Sponge::new(dr, poseidon_params);
        sp.absorb(dr, &t)?;
        sp.absorb(dr, &node)?;
        sp.absorb(dr, &bit_e)?;
        node = sp.squeeze(dr)?;
    }

    let nullifier = *node.value().take();
    let epoch_f = C::CircuitField::from(epoch as u64);
    let did_f = *did.value().take();
    Ok((nullifier, epoch_f, did_f))
}
