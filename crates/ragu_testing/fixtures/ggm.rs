//! Generic GGM bench/test helpers, parameterised over `Cycle`.
//!
//! Lives under `fixtures/ggm/` (a dedicated fixtures directory at the
//! crate root) because it sits alongside [`setup`], which is Pasta-typed
//! and needs `ragu_pasta` (a dev-dependency, only visible to bench/test
//! compilation units). Both tests and benches pull this module in via a
//! single `#[path]` declaration.
//!
//! Provides the `App` type alias, witness sampling/derivation helpers,
//! thin `*_step` wrappers around `Application::seed`/`fuse`, and a lazy
//! PCD cache. The `ensure_*` helpers + `CacheCell` tuple are what bench
//! and test consume; the cache cell's delegate and nullifier slots are
//! trap-keyed (sound for arbitrary traps — `did` lives in
//! `GgmNullifierHeader::Data` and depends on `trap`, so the nullifier
//! slot must include `trap` in its key, not just `epoch`).

#![allow(clippy::type_complexity, clippy::too_many_arguments, dead_code)]

use std::{
    collections::BTreeMap,
    sync::{Arc, LazyLock, Mutex, MutexGuard, OnceLock, PoisonError},
    time::Instant,
};

use ff::{Field, PrimeField};
use ragu_arithmetic::Cycle;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::{
    drivers::emulator::Emulator,
    maybe::{Always, Maybe, MaybeKind},
};
use ragu_pasta::{Fp, Pasta, fp};
use ragu_pcd::{Application, ApplicationBuilder, Pcd};
use ragu_primitives::{Element, allocator::Standard, poseidon::Sponge};
use ragu_testing::apps::ggm::*;
use rand::{SeedableRng, rngs::StdRng};

pub type App<C> = Application<'static, C, ProductionRank, HEADER_SIZE>;

/// Mock `pk` derivation: `Poseidon(domain::PK, nk)`. Real Zcash binds `ak` too;
/// this example uses `nk` alone since the GGM circuit doesn't constrain `pk`.
pub fn derive_pk<C: Cycle>(
    poseidon: &<C as Cycle>::CircuitPoseidon,
    nk: NullifierKeyWitness<<C as Cycle>::CircuitField>,
) -> <C as Cycle>::CircuitField
where
    C::CircuitField: PrimeField,
{
    let mut dr = Emulator::execute();
    let allocator = &mut Standard::new();
    let dr = &mut dr;

    let nk_e = Element::alloc(dr, allocator, Always::maybe_just(|| nk.0)).expect("alloc nk");
    let t = Element::constant(dr, tag::<C::CircuitField>(domain::PK));
    let mut sp = Sponge::new(dr, poseidon);
    sp.absorb(dr, &t).expect("absorb tag");
    sp.absorb(dr, &nk_e).expect("absorb nk");
    let out = sp.squeeze(dr).expect("squeeze pk");
    *out.value().take()
}

/// Native note commitment: `Poseidon(domain::CM, rcm, pk, value, psi)`,
/// matching `NoteGadget::commit` and `native_ggm`'s commit absorption order.
pub fn commit_note<C: Cycle>(
    poseidon: &<C as Cycle>::CircuitPoseidon,
    note: &NoteWitness<<C as Cycle>::CircuitField>,
) -> NoteCommitmentWitness<<C as Cycle>::CircuitField>
where
    C::CircuitField: PrimeField,
{
    let mut dr = Emulator::execute();
    let allocator = &mut Standard::new();
    let dr = &mut dr;

    let rcm_e = Element::alloc(dr, allocator, Always::maybe_just(|| note.rcm)).expect("alloc rcm");
    let pk_e = Element::alloc(dr, allocator, Always::maybe_just(|| note.pk)).expect("alloc pk");
    let value_e =
        Element::alloc(dr, allocator, Always::maybe_just(|| note.value)).expect("alloc value");
    let psi_e = Element::alloc(dr, allocator, Always::maybe_just(|| note.psi)).expect("alloc psi");

    let t = Element::constant(dr, tag::<C::CircuitField>(domain::CM));
    let mut sp = Sponge::new(dr, poseidon);
    sp.absorb(dr, &t).expect("absorb tag");
    sp.absorb(dr, &rcm_e).expect("absorb rcm");
    sp.absorb(dr, &pk_e).expect("absorb pk");
    sp.absorb(dr, &value_e).expect("absorb value");
    sp.absorb(dr, &psi_e).expect("absorb psi");
    let out = sp.squeeze(dr).expect("squeeze cm");
    NoteCommitmentWitness(*out.value().take())
}

/// Pull one mock note's witnesses from `rng`, given the canonical `nk`.
pub fn sample_note<C: Cycle>(
    rng: &mut StdRng,
    poseidon: &<C as Cycle>::CircuitPoseidon,
    nk: NullifierKeyWitness<<C as Cycle>::CircuitField>,
) -> NoteWitness<<C as Cycle>::CircuitField>
where
    C::CircuitField: PrimeField,
{
    let psi = <C as Cycle>::CircuitField::random(&mut *rng);
    let rcm = <C as Cycle>::CircuitField::random(&mut *rng);
    let value = <C as Cycle>::CircuitField::random(&mut *rng);
    let pk = derive_pk::<C>(poseidon, nk);
    NoteWitness {
        pk,
        value,
        psi,
        rcm,
    }
}

pub fn build_app<C: Cycle>(
    params: &'static C::Params,
    poseidon_params: &'static C::CircuitPoseidon,
) -> App<C>
where
    C::CircuitField: PrimeField,
{
    let t = Instant::now();
    let app = ApplicationBuilder::<C, ProductionRank, HEADER_SIZE>::new()
        .register(GgmMasterSeed::<C> { poseidon_params })
        .unwrap()
        .register(GgmMasterStep::<C> { poseidon_params })
        .unwrap()
        .register(GgmNodeStep::<C> { poseidon_params })
        .unwrap()
        .register(GgmBlindStep::<C> { poseidon_params })
        .unwrap()
        .register(GgmDelegateStep::<C> { poseidon_params })
        .unwrap()
        .register(GgmNullifierStep::<C> { poseidon_params })
        .unwrap()
        .finalize(params)
        .unwrap();
    eprintln!(
        "{:?} [ggm test] build_app {:?}",
        std::thread::current().id(),
        t.elapsed()
    );
    app
}

/// Seed the master PCD and return `(master_pcd, commitment)`.
pub fn seed_master<C: Cycle>(
    app: &App<C>,
    poseidon_params: &<C as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    seed: (
        NullifierKeyWitness<<C as Cycle>::CircuitField>,
        NoteWitness<<C as Cycle>::CircuitField>,
    ),
) -> (
    Pcd<C, ProductionRank, GgmMasterHeader>,
    NoteCommitmentWitness<<C as Cycle>::CircuitField>,
)
where
    C::CircuitField: PrimeField,
{
    let pcd = app
        .seed(rng, GgmMasterSeed::<C> { poseidon_params }, seed)
        .unwrap()
        .0;
    let cm = pcd.data().1;
    (pcd, cm)
}

pub fn master_step<C: Cycle>(
    app: &App<C>,
    poseidon_params: &<C as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    master_pcd: Pcd<C, ProductionRank, GgmMasterHeader>,
    chunk: ChunkWitness,
) -> Pcd<C, ProductionRank, GgmPrivateHeader>
where
    C::CircuitField: PrimeField,
{
    let trivial_pcd = app.seeded_trivial_pcd(rng);
    app.fuse(
        rng,
        GgmMasterStep::<C> { poseidon_params },
        chunk,
        master_pcd,
        trivial_pcd,
    )
    .unwrap()
    .0
}

pub fn node_step<C: Cycle>(
    app: &App<C>,
    poseidon_params: &<C as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    node_pcd: Pcd<C, ProductionRank, GgmPrivateHeader>,
    chunk: ChunkWitness,
) -> Pcd<C, ProductionRank, GgmPrivateHeader>
where
    C::CircuitField: PrimeField,
{
    let trivial_pcd = app.seeded_trivial_pcd(rng);
    app.fuse(
        rng,
        GgmNodeStep::<C> { poseidon_params },
        chunk,
        node_pcd,
        trivial_pcd,
    )
    .unwrap()
    .0
}

pub fn blind_step<C: Cycle>(
    app: &App<C>,
    poseidon_params: &<C as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    node_pcd: Pcd<C, ProductionRank, GgmPrivateHeader>,
    trap: DelegationTrapdoorWitness<C::CircuitField>,
) -> Pcd<C, ProductionRank, GgmDelegateHeader>
where
    C::CircuitField: PrimeField,
{
    let trivial_pcd = app.seeded_trivial_pcd(rng);
    app.fuse(
        rng,
        GgmBlindStep::<C> { poseidon_params },
        trap,
        node_pcd,
        trivial_pcd,
    )
    .unwrap()
    .0
}

pub fn delegate_step<C: Cycle>(
    app: &App<C>,
    poseidon_params: &<C as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    delegate_pcd: Pcd<C, ProductionRank, GgmDelegateHeader>,
    chunk: ChunkWitness,
) -> Pcd<C, ProductionRank, GgmDelegateHeader>
where
    C::CircuitField: PrimeField,
{
    let trivial_pcd = app.seeded_trivial_pcd(rng);
    app.fuse(
        rng,
        GgmDelegateStep::<C> { poseidon_params },
        chunk,
        delegate_pcd,
        trivial_pcd,
    )
    .unwrap()
    .0
}

pub fn nullifier_step<C: Cycle>(
    app: &App<C>,
    poseidon_params: &<C as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    delegate_pcd: Pcd<C, ProductionRank, GgmDelegateHeader>,
) -> Pcd<C, ProductionRank, GgmNullifierHeader>
where
    C::CircuitField: PrimeField,
{
    let trivial_pcd = app.seeded_trivial_pcd(rng);
    app.fuse(
        rng,
        GgmNullifierStep::<C> { poseidon_params },
        (),
        delegate_pcd,
        trivial_pcd,
    )
    .unwrap()
    .0
}

// --- cache ---

/// Extract the `level`-th MSB-first base-`GGM_ARITY` digit of `epoch`
/// as a [`ChunkWitness`] (LE bit order within the chunk).
pub fn chunk_at(epoch: GgmIndex, level: u8) -> ChunkWitness {
    let place = (GGM_ARITY as u16).pow(u32::from(GGM_DEPTH - 1 - level));
    let digit = ((epoch / place) % GGM_ARITY as u16) as u8;
    let mut bits = [false; GGM_CHUNK_SIZE as usize];
    for (i, b) in bits.iter_mut().enumerate() {
        *b = (digit >> i) & 1 != 0;
    }
    ChunkWitness(bits)
}

/// The path-index at `depth` along the chunk-path of `epoch`.
pub fn index_at(epoch: GgmIndex, depth: u8) -> GgmIndex {
    epoch >> ((GGM_DEPTH - depth) * GGM_CHUNK_SIZE)
}

/// Per-note PCD slots for the lazy cache. Tuple shape (master, prefix
/// nodes, delegates, nullifiers). Delegate and nullifier slots are
/// keyed including `trap`, so mixing traps in one cell is sound. Wrap
/// a `Mutex<BTreeMap<commitment, Arc<CacheCell<C>>>>` around this for
/// multi-note scenarios.
pub type CacheCell<C> = (
    OnceLock<Pcd<C, ProductionRank, GgmMasterHeader>>,
    Mutex<BTreeMap<(u8, GgmIndex), Arc<OnceLock<Pcd<C, ProductionRank, GgmPrivateHeader>>>>>,
    Mutex<
        BTreeMap<
            (
                u8,
                GgmIndex,
                DelegationTrapdoorWitness<<C as Cycle>::CircuitField>,
            ),
            Arc<OnceLock<Pcd<C, ProductionRank, GgmDelegateHeader>>>,
        >,
    >,
    Mutex<
        BTreeMap<
            (
                GgmIndex,
                DelegationTrapdoorWitness<<C as Cycle>::CircuitField>,
            ),
            Arc<OnceLock<Pcd<C, ProductionRank, GgmNullifierHeader>>>,
        >,
    >,
);

pub fn default_cell<C: Cycle>() -> CacheCell<C>
where
    C::CircuitField: PrimeField,
{
    (
        OnceLock::new(),
        Mutex::new(BTreeMap::new()),
        Mutex::new(BTreeMap::new()),
        Mutex::new(BTreeMap::new()),
    )
}

fn slot<K, V>(map: &Mutex<BTreeMap<K, Arc<OnceLock<V>>>>, key: K) -> Arc<OnceLock<V>>
where
    K: Ord,
{
    map.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(key)
        .or_insert_with(|| Arc::new(OnceLock::new()))
        .clone()
}

pub fn ensure_master<C: Cycle>(
    cell: &CacheCell<C>,
    app: &App<C>,
    poseidon: &<C as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    nk: NullifierKeyWitness<<C as Cycle>::CircuitField>,
    note: NoteWitness<<C as Cycle>::CircuitField>,
) -> Pcd<C, ProductionRank, GgmMasterHeader>
where
    C::CircuitField: PrimeField,
{
    cell.0
        .get_or_init(|| {
            let cm = commit_note::<C>(poseidon, &note);
            let t = Instant::now();
            let pcd = seed_master::<C>(app, poseidon, rng, (nk, note)).0;
            eprintln!(
                "{:?} [ggm test] seed_master {cm:?} {:?}",
                std::thread::current().id(),
                t.elapsed()
            );
            pcd
        })
        .clone()
}

pub fn ensure_node<C: Cycle>(
    cell: &CacheCell<C>,
    app: &App<C>,
    poseidon: &<C as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    nk: NullifierKeyWitness<<C as Cycle>::CircuitField>,
    note: NoteWitness<<C as Cycle>::CircuitField>,
    depth: u8,
    epoch: GgmIndex,
) -> Pcd<C, ProductionRank, GgmPrivateHeader>
where
    C::CircuitField: PrimeField,
{
    let mut parent: Option<Pcd<C, ProductionRank, GgmPrivateHeader>> = None;
    let mut last: Option<Pcd<C, ProductionRank, GgmPrivateHeader>> = None;

    for d in 1..=depth {
        let key = (d, index_at(epoch, d));
        let node_slot = slot(&cell.1, key);

        let node = if let Some(n) = node_slot.get() {
            n.clone()
        } else {
            let parent_taken = parent.take();
            node_slot
                .get_or_init(|| {
                    let master = ensure_master(cell, app, poseidon, rng, nk, note);
                    let chunk = chunk_at(epoch, d - 1);
                    let cm = commit_note::<C>(poseidon, &note);
                    let t = Instant::now();
                    let n = match (d, parent_taken) {
                        (1, _) => master_step::<C>(app, poseidon, rng, master, chunk),
                        (_, Some(p)) => node_step::<C>(app, poseidon, rng, p, chunk),
                        (_, None) => unreachable!("d > 1 implies a prior parent"),
                    };
                    let step_name = if d == 1 { "master_step" } else { "node_step" };
                    eprintln!(
                        "{:?} [ggm test] {step_name:} {cm:?} {key:?} {:?}",
                        std::thread::current().id(),
                        t.elapsed()
                    );
                    n
                })
                .clone()
        };

        if d == depth {
            last = Some(node.clone());
        }
        parent = Some(node);
    }

    last.expect("loop ran for at least one depth")
}

/// Trap-keyed delegate slot: mixing traps in one cell is sound.
pub fn ensure_delegate<C: Cycle>(
    cell: &CacheCell<C>,
    app: &App<C>,
    poseidon: &<C as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    nk: NullifierKeyWitness<<C as Cycle>::CircuitField>,
    note: NoteWitness<<C as Cycle>::CircuitField>,
    trap: DelegationTrapdoorWitness<<C as Cycle>::CircuitField>,
    depth: u8,
    epoch: GgmIndex,
) -> Pcd<C, ProductionRank, GgmDelegateHeader>
where
    C::CircuitField: PrimeField + Ord,
{
    let key = (depth, index_at(epoch, depth), trap);
    let delegate_slot = slot(&cell.2, key);
    delegate_slot
        .get_or_init(|| {
            let node = ensure_node(cell, app, poseidon, rng, nk, note, depth, epoch);
            let cm = commit_note::<C>(poseidon, &note);
            let t = Instant::now();
            let delegate = blind_step::<C>(app, poseidon, rng, node, trap);
            eprintln!(
                "{:?} [ggm test] blind_step {cm:?} {key:?} {:?}",
                std::thread::current().id(),
                t.elapsed(),
            );
            delegate
        })
        .clone()
}

/// Run the nullifier step on the cached delegate, memoising by
/// `(epoch, trap)`. `nf` is independent of `trap`, but `did` (also in
/// `GgmNullifierHeader::Data`) depends on it — so the cache key must
/// include `trap` to avoid returning a wrong-`did` PCD when traps differ.
pub fn ensure_nullifier<C: Cycle>(
    cell: &CacheCell<C>,
    app: &App<C>,
    poseidon: &<C as Cycle>::CircuitPoseidon,
    rng: &mut StdRng,
    nk: NullifierKeyWitness<<C as Cycle>::CircuitField>,
    note: NoteWitness<<C as Cycle>::CircuitField>,
    trap: DelegationTrapdoorWitness<<C as Cycle>::CircuitField>,
    depth: u8,
    epoch: GgmIndex,
) -> Pcd<C, ProductionRank, GgmNullifierHeader>
where
    C::CircuitField: PrimeField + Ord,
{
    let key = (epoch, trap);
    let nullifier_slot = slot(&cell.3, key);
    nullifier_slot
        .get_or_init(|| {
            let delegate = ensure_delegate(cell, app, poseidon, rng, nk, note, trap, depth, epoch);
            let cm = commit_note::<C>(poseidon, &note);
            let t = Instant::now();
            let leaf = nullifier_step::<C>(app, poseidon, rng, delegate);
            eprintln!(
                "{:?} [ggm test] nullifier_step {cm:?} {key:?} {:?}",
                std::thread::current().id(),
                t.elapsed(),
            );
            leaf
        })
        .clone()
}

pub const NK: NullifierKeyWitness<Fp> = NullifierKeyWitness(fp!(0x01));
pub const PROVE_SEED: u64 = 0;
pub const NOTE_SEED: u64 = 1;
pub const TRAP_SEED: u64 = 2;

pub fn note() -> NoteWitness<Fp> {
    sample_note::<Pasta>(
        &mut StdRng::seed_from_u64(NOTE_SEED),
        Pasta::circuit_poseidon(Pasta::baked()),
        NK,
    )
}

pub fn trap() -> DelegationTrapdoorWitness<Fp> {
    DelegationTrapdoorWitness(Fp::random(&mut StdRng::seed_from_u64(TRAP_SEED)))
}

/// `App` contains a `OnceCell` (not `Sync`), so it can't live in a bare
/// `static`. The `Mutex` makes the wrapper `Sync` and serialises access;
/// bench harnesses are single-threaded, and the test's two `#[test]`
/// fns serialise on this lock when cargo runs them across threads.
pub static APP: LazyLock<Mutex<App<Pasta>>> = LazyLock::new(|| {
    Mutex::new(build_app::<Pasta>(
        Pasta::baked(),
        Pasta::circuit_poseidon(Pasta::baked()),
    ))
});

/// Dynamic per-`cm` cache. Bench warms the entry for the canonical
/// `note()`'s cm; tests add entries for axis variants.
pub static CACHE: LazyLock<Mutex<BTreeMap<NoteCommitmentWitness<Fp>, Arc<CacheCell<Pasta>>>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub fn cells_for(cm: NoteCommitmentWitness<Fp>) -> Arc<CacheCell<Pasta>> {
    CACHE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .entry(cm)
        .or_insert_with(|| Arc::new(default_cell::<Pasta>()))
        .clone()
}

pub fn lock_app() -> MutexGuard<'static, App<Pasta>> {
    APP.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn prove_rng() -> StdRng {
    StdRng::seed_from_u64(PROVE_SEED)
}

// --- bench/test glue ---

/// Acquire the App lock, a seeded prover RNG, and the cached Pasta Poseidon
/// params in one call. Used by every bench `setup_*` and by the tests.
pub fn app_setup() -> (
    MutexGuard<'static, App<Pasta>>,
    StdRng,
    &'static <Pasta as Cycle>::CircuitPoseidon,
) {
    (
        lock_app(),
        prove_rng(),
        Pasta::circuit_poseidon(Pasta::baked()),
    )
}

pub fn setup_seed() -> (MutexGuard<'static, App<Pasta>>, StdRng) {
    let (app, rng, _) = app_setup();
    (app, rng)
}

pub fn setup_master_step() -> (
    MutexGuard<'static, App<Pasta>>,
    StdRng,
    Pcd<Pasta, ProductionRank, GgmMasterHeader>,
    Pcd<Pasta, ProductionRank, ()>,
) {
    let (app, mut rng, poseidon) = app_setup();
    let trivial = app.seeded_trivial_pcd(&mut rng);
    let note = note();
    let cell = cells_for(commit_note::<Pasta>(poseidon, &note));
    let master = ensure_master(&cell, &app, poseidon, &mut rng, NK, note);
    (app, rng, master, trivial)
}

pub fn setup_node_step() -> (
    MutexGuard<'static, App<Pasta>>,
    StdRng,
    Pcd<Pasta, ProductionRank, GgmPrivateHeader>,
    Pcd<Pasta, ProductionRank, ()>,
) {
    let (app, mut rng, poseidon) = app_setup();
    let trivial = app.seeded_trivial_pcd(&mut rng);
    let note = note();
    let cell = cells_for(commit_note::<Pasta>(poseidon, &note));
    let node = ensure_node(&cell, &app, poseidon, &mut rng, NK, note, 1, 0);
    (app, rng, node, trivial)
}

pub fn setup_blind() -> (
    MutexGuard<'static, App<Pasta>>,
    StdRng,
    Pcd<Pasta, ProductionRank, GgmPrivateHeader>,
    Pcd<Pasta, ProductionRank, ()>,
) {
    let (app, mut rng, poseidon) = app_setup();
    let trivial = app.seeded_trivial_pcd(&mut rng);
    let note = note();
    let cell = cells_for(commit_note::<Pasta>(poseidon, &note));
    let leaf = ensure_node(&cell, &app, poseidon, &mut rng, NK, note, GGM_DEPTH, 0);
    (app, rng, leaf, trivial)
}

pub fn setup_delegate() -> (
    MutexGuard<'static, App<Pasta>>,
    StdRng,
    Pcd<Pasta, ProductionRank, GgmDelegateHeader>,
    Pcd<Pasta, ProductionRank, ()>,
) {
    let (app, mut rng, poseidon) = app_setup();
    let trivial = app.seeded_trivial_pcd(&mut rng);
    let note = note();
    let cell = cells_for(commit_note::<Pasta>(poseidon, &note));
    let delegate = ensure_delegate(&cell, &app, poseidon, &mut rng, NK, note, trap(), 1, 0);
    (app, rng, delegate, trivial)
}

pub fn setup_final() -> (
    MutexGuard<'static, App<Pasta>>,
    StdRng,
    Pcd<Pasta, ProductionRank, GgmDelegateHeader>,
    Pcd<Pasta, ProductionRank, ()>,
) {
    let (app, mut rng, poseidon) = app_setup();
    let trivial = app.seeded_trivial_pcd(&mut rng);
    let note = note();
    let cell = cells_for(commit_note::<Pasta>(poseidon, &note));
    let delegate =
        ensure_delegate(&cell, &app, poseidon, &mut rng, NK, note, trap(), GGM_DEPTH, 0);
    (app, rng, delegate, trivial)
}
