//! Source-registry identities on both fields, including recursive and terminal closure.
use alloc::{vec, vec::Vec};

use ragu_backend::ReferenceBackend;
use ragu_circuits::{
    polynomials::{R, Rank, sparse},
    registry::RegistryBuilder,
};
use ragu_core::{
    Result,
    pasta::{Fp, Fq, Pasta},
};
use rand::{SeedableRng, rngs::StdRng};
use udon::{curve::Affine, field::Field};

use crate::{
    Application, ApplicationBuilder, Pcd, Proof, SelectableBackend,
    ipa::IpaCycle,
    profile::{
        Profile, Profiled, ProfiledCycle, Standard,
        online::{
            Challenge, Layout, Opening, Phase, Point,
            mesh::{Helper, Mesh, Restriction},
            prepared::PreparationChallenges,
            source::SourceRegistry,
        },
        testing::UnitStep,
    },
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SourceCapacity;
impl Profile for SourceCapacity {
    const NAME: &'static str = "source-mesh-capacity";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NATIVE_ENDOSCALINGS_PER_STEP: usize = 4;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = 4;
    type Context<'params, Base, Rk, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend;
    const NATIVE_ONLINE: Layout = Layout {
        polynomials: &[
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeY,
            Phase::BeforeY,
            Phase::BeforeY,
            Phase::BeforeY,
            Phase::BeforeY,
            Phase::BeforeY,
            Phase::BeforeY,
            Phase::BeforeX,
            Phase::BeforeAlpha,
        ],
        openings: &[
            Opening {
                polynomial: 0,
                point: Point::Challenge(Challenge::W),
                value: 0,
            },
            Opening {
                polynomial: 12,
                point: Point::Input(1),
                value: 0,
            },
            Opening {
                polynomial: 1,
                point: Point::Challenge(Challenge::W),
                value: 1,
            },
            Opening {
                polynomial: 13,
                point: Point::Input(3),
                value: 1,
            },
            Opening {
                polynomial: 2,
                point: Point::Challenge(Challenge::W),
                value: 2,
            },
            Opening {
                polynomial: 14,
                point: Point::Input(5),
                value: 2,
            },
            Opening {
                polynomial: 3,
                point: Point::Challenge(Challenge::W),
                value: 3,
            },
            Opening {
                polynomial: 15,
                point: Point::Input(7),
                value: 3,
            },
            Opening {
                polynomial: 4,
                point: Point::Challenge(Challenge::W),
                value: 4,
            },
            Opening {
                polynomial: 16,
                point: Point::Input(9),
                value: 4,
            },
            Opening {
                polynomial: 5,
                point: Point::Challenge(Challenge::W),
                value: 5,
            },
            Opening {
                polynomial: 17,
                point: Point::Input(11),
                value: 5,
            },
            Opening {
                polynomial: 6,
                point: Point::Challenge(Challenge::W),
                value: 6,
            },
            Opening {
                polynomial: 18,
                point: Point::Input(13),
                value: 6,
            },
            Opening {
                polynomial: 7,
                point: Point::Challenge(Challenge::W),
                value: 7,
            },
            Opening {
                polynomial: 16,
                point: Point::Input(14),
                value: 7,
            },
            Opening {
                polynomial: 8,
                point: Point::Challenge(Challenge::W),
                value: 8,
            },
            Opening {
                polynomial: 17,
                point: Point::Input(14),
                value: 8,
            },
            Opening {
                polynomial: 9,
                point: Point::Challenge(Challenge::W),
                value: 9,
            },
            Opening {
                polynomial: 16,
                point: Point::Input(15),
                value: 9,
            },
            Opening {
                polynomial: 10,
                point: Point::Challenge(Challenge::W),
                value: 10,
            },
            Opening {
                polynomial: 17,
                point: Point::Input(15),
                value: 10,
            },
            Opening {
                polynomial: 12,
                point: Point::Challenge(Challenge::Y),
                value: 11,
            },
            Opening {
                polynomial: 19,
                point: Point::Input(0),
                value: 11,
            },
            Opening {
                polynomial: 13,
                point: Point::Challenge(Challenge::Y),
                value: 12,
            },
            Opening {
                polynomial: 19,
                point: Point::Input(2),
                value: 12,
            },
            Opening {
                polynomial: 14,
                point: Point::Challenge(Challenge::Y),
                value: 13,
            },
            Opening {
                polynomial: 19,
                point: Point::Input(4),
                value: 13,
            },
            Opening {
                polynomial: 15,
                point: Point::Challenge(Challenge::Y),
                value: 14,
            },
            Opening {
                polynomial: 19,
                point: Point::Input(6),
                value: 14,
            },
            Opening {
                polynomial: 16,
                point: Point::Challenge(Challenge::Y),
                value: 15,
            },
            Opening {
                polynomial: 19,
                point: Point::Input(8),
                value: 15,
            },
            Opening {
                polynomial: 17,
                point: Point::Challenge(Challenge::Y),
                value: 16,
            },
            Opening {
                polynomial: 19,
                point: Point::Input(10),
                value: 16,
            },
            Opening {
                polynomial: 18,
                point: Point::Challenge(Challenge::Y),
                value: 17,
            },
            Opening {
                polynomial: 19,
                point: Point::Input(12),
                value: 17,
            },
            Opening {
                polynomial: 19,
                point: Point::Challenge(Challenge::X),
                value: 18,
            },
            Opening {
                polynomial: 20,
                point: Point::Challenge(Challenge::W),
                value: 18,
            },
            Opening {
                polynomial: 11,
                point: Point::Challenge(Challenge::W),
                value: 19,
            },
            Opening {
                polynomial: 11,
                point: Point::Challenge(Challenge::X),
                value: 20,
            },
        ],
        inputs: 16,
        points: 0,
        values: 21,
    };
    const NESTED_ONLINE: Layout = Self::NATIVE_ONLINE;
    const NATIVE_MESH: Option<Mesh> = Some(Mesh {
        inherited: [
            Restriction {
                polynomial: 0,
                x: 0,
                y: 1,
                helper: 12,
            },
            Restriction {
                polynomial: 1,
                x: 2,
                y: 3,
                helper: 13,
            },
        ],
        introduced: &[
            Restriction {
                polynomial: 2,
                x: 4,
                y: 5,
                helper: 14,
            },
            Restriction {
                polynomial: 3,
                x: 6,
                y: 7,
                helper: 15,
            },
            Restriction {
                polynomial: 4,
                x: 8,
                y: 9,
                helper: 16,
            },
            Restriction {
                polynomial: 5,
                x: 10,
                y: 11,
                helper: 17,
            },
            Restriction {
                polynomial: 6,
                x: 12,
                y: 13,
                helper: 18,
            },
            Restriction {
                polynomial: 7,
                x: 8,
                y: 14,
                helper: 16,
            },
            Restriction {
                polynomial: 8,
                x: 10,
                y: 14,
                helper: 17,
            },
            Restriction {
                polynomial: 9,
                x: 8,
                y: 15,
                helper: 16,
            },
            Restriction {
                polynomial: 10,
                x: 10,
                y: 15,
                helper: 17,
            },
        ],
        helpers: &[
            Helper {
                polynomial: 12,
                x: 0,
            },
            Helper {
                polynomial: 13,
                x: 2,
            },
            Helper {
                polynomial: 14,
                x: 4,
            },
            Helper {
                polynomial: 15,
                x: 6,
            },
            Helper {
                polynomial: 16,
                x: 8,
            },
            Helper {
                polynomial: 17,
                x: 10,
            },
            Helper {
                polynomial: 18,
                x: 12,
            },
        ],
        u: 19,
        outgoing: 20,
    });
    const NESTED_MESH: Option<Mesh> = Self::NATIVE_MESH;

    fn native_online_inputs<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
    ) -> Result<Vec<Base::CircuitField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok((0..16)
            .map(|i| Base::CircuitField::from(i as u64 + 2))
            .collect())
    }
    fn native_online_polynomials<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
        phase: Phase,
        _: &[Base::CircuitField],
        _: PreparationChallenges<Base::CircuitField>,
    ) -> Result<Vec<sparse::Polynomial<Base::CircuitField, Rk>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok(if phase == Phase::BeforeW {
            vec![sparse::Polynomial::from_coeffs(vec![
                Base::CircuitField::ONE,
                Base::CircuitField::from(2),
            ])]
        } else {
            vec![]
        })
    }

    fn nested_online_inputs<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
    ) -> Result<Vec<Base::ScalarField>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok((0..16)
            .map(|i| Base::ScalarField::from(i as u64 + 2))
            .collect())
    }
    fn nested_online_polynomials<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
        phase: Phase,
        _: &[Base::ScalarField],
        _: PreparationChallenges<Base::ScalarField>,
    ) -> Result<Vec<sparse::Polynomial<Base::ScalarField, Rk>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok(if phase == Phase::BeforeW {
            vec![sparse::Polynomial::from_coeffs(vec![
                Base::ScalarField::ONE,
                Base::ScalarField::from(2),
            ])]
        } else {
            vec![]
        })
    }
}
type C = Profiled<Pasta, SourceCapacity>;
type Rk = R<14>;
fn altered_point<P: Affine>(point: P) -> P {
    -point
}
fn verify<P: Profile>(
    app: &Application<'_, Profiled<Pasta, P>, Rk, 2>,
    pcd: &Pcd<Profiled<Pasta, P>, Rk, ()>,
    rng: &mut StdRng,
    expected: bool,
) -> Result<()> {
    assert_eq!(app.verify_uncompressed(pcd, &mut *rng)?, expected);
    match app.compress(pcd, rng) {
        Ok(compressed) => {
            let bytes = compressed.proof().to_bytes().expect("encode source mesh");
            let decoded = crate::CompressedProof::<Profiled<Pasta, P>>::from_bytes(&bytes)
                .expect("decode source mesh")
                .carry::<()>(());
            assert_eq!(app.verify_compressed(&decoded)?, expected);
        }
        Err(ragu_core::Error::InvalidWitness(_)) if !expected => {}
        Err(error) => return Err(error),
    }
    Ok(())
}
#[test]
fn both_source_meshes_close_at_the_root_and_survive_ordinary_steps() -> Result<()> {
    let source = ApplicationBuilder::<Pasta, R<13>, 2>::new()
        .register(UnitStep)?
        .finalize(crate::pasta::baked())?;
    let app = ApplicationBuilder::<C, Rk, 2>::new()
        .register(UnitStep)?
        .with_source_registries(
            Some(SourceRegistry::new::<_, ReferenceBackend>(
                source.native_registry(),
            )),
            Some(SourceRegistry::new::<_, ReferenceBackend>(
                source.nested_registry(),
            )),
        )
        .finalize(crate::pasta::baked_aggregator())?;
    let mut rng = StdRng::seed_from_u64(0x606060);
    let (child, ()) = app.seed(&mut rng, UnitStep, ())?;
    assert!(app.verify_uncompressed(&child, &mut rng)?);
    let compressed = app.compress(&child, &mut rng)?;
    let bytes = compressed.proof().to_bytes().expect("encode source mesh");
    let compressed = crate::CompressedProof::<C>::from_bytes(&bytes)
        .expect("decode source mesh")
        .carry::<()>(());
    assert!(app.verify_compressed(&compressed)?);
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), child.clone(), child.clone())?;
    let (grandparent, ()) = app.fuse(&mut rng, UnitStep, (), parent.clone(), child.clone())?;
    verify(&app, &grandparent, &mut rng, true)?;
    // A restriction, a helper and the outgoing restriction on each field.
    let outgoing = SourceCapacity::NATIVE_MESH.expect("mesh declared").outgoing;
    crate::online_batch_tests::check_identity_online_commitments(
        &app,
        &child,
        &mut rng,
        &[0, 12, outgoing],
        &[0, 12, outgoing],
    )?;
    let decoded = Proof::<C, Rk>::from_bytes(
        &parent
            .proof()
            .to_bytes()
            .expect("encode retained source polynomials"),
    )
    .expect("decode retained source polynomials")
    .carry::<()>(());
    verify(&app, &decoded, &mut rng, true)?;
    // A valid registry other than the source: one trivial circuit under a
    // nonzero tag, whose restrictions do not vanish.
    let wrong_native = RegistryBuilder::<Fp, R<13>>::new()
        .register_circuit(())?
        .with_tag(Fp::ONE)
        .finalize()?;
    let wrong_nested = RegistryBuilder::<Fq, R<13>>::new()
        .register_circuit(())?
        .with_tag(Fq::ONE)
        .finalize()?;
    for side in 0..2 {
        let receiving = ApplicationBuilder::<C, Rk, 2>::new()
            .register(UnitStep)?
            .with_source_registries(
                Some(SourceRegistry::new::<_, ReferenceBackend>(if side == 0 {
                    &wrong_native
                } else {
                    source.native_registry()
                })),
                Some(SourceRegistry::new::<_, ReferenceBackend>(if side == 1 {
                    &wrong_nested
                } else {
                    source.nested_registry()
                })),
            )
            .finalize(crate::pasta::baked_aggregator())?;
        assert!(!receiving.verify_uncompressed(&child, &mut rng)?);
        assert!(
            !receiving.verify_compressed(&compressed)?,
            "accepted the sender's compressed proof with source substitution on side {side}"
        );
    }
    // The only source-polynomial witnesses retained for a parent are the two outgoing restrictions.
    assert_eq!(child.proof().native_source_out.len(), 1);
    assert_eq!(child.proof().nested_source_out.len(), 1);
    assert_eq!(child.proof().native_online_commitments.len(), 21);
    assert_eq!(child.proof().nested_online_commitments.len(), 21);
    for side in 0..2 {
        for coordinate_or_edge in [0, 4, 16, 34] {
            let mut proof = child.proof().clone();
            if side == 0 {
                proof.native_mesh_claims[coordinate_or_edge] += Fp::ONE;
            } else {
                proof.nested_mesh_claims[coordinate_or_edge] += Fq::ONE;
            }
            let bad = proof.carry::<()>(());
            verify(&app, &bad, &mut rng, false)?;
            if coordinate_or_edge == 0 {
                let (next, ()) = app.fuse(&mut rng, UnitStep, (), bad, child.clone())?;
                verify(&app, &next, &mut rng, false)?;
            }
        }
        for slot in [0, 12, 19, 20] {
            let mut proof = child.proof().clone();
            if side == 0 {
                proof.native_online_commitments[slot] =
                    altered_point(proof.native_online_commitments[slot]);
            } else {
                proof.nested_online_commitments[slot] =
                    altered_point(proof.nested_online_commitments[slot]);
            }
            let bad = proof.carry::<()>(());
            verify(&app, &bad, &mut rng, false)?;
            if slot == 19 {
                let (next, ()) = app.fuse(&mut rng, UnitStep, (), child.clone(), bad)?;
                let (next, ()) = app.fuse(&mut rng, UnitStep, (), next, child.clone())?;
                verify(&app, &next, &mut rng, false)?;
            }
        }
        let mut proof = child.proof().clone();
        if side == 0 {
            proof.native_source_out[0] = sparse::Polynomial::new();
        } else {
            proof.nested_source_out[0] = sparse::Polynomial::new();
        }
        let bad = proof.carry::<()>(());
        verify(&app, &bad, &mut rng, false)?;
        assert!(
            app.fuse(&mut rng, UnitStep, (), child.clone(), bad)
                .is_err()
        );
    }
    Ok(())
}
/// An empty source registry with a zero tag restricts to the zero
/// polynomial, whose commitment the walk cannot take, so setup rejects it
/// rather than the first proof failing.
#[test]
fn a_source_registry_whose_restrictions_vanish_is_rejected_at_setup() -> Result<()> {
    let native = RegistryBuilder::<Fp, R<13>>::new()
        .with_tag(Fp::ZERO)
        .finalize()?;
    let nested = RegistryBuilder::<Fq, R<13>>::new()
        .with_tag(Fq::ZERO)
        .finalize()?;
    let result = ApplicationBuilder::<C, Rk, 2>::new()
        .register(UnitStep)?
        .with_source_registries(
            Some(SourceRegistry::new::<_, ReferenceBackend>(&native)),
            Some(SourceRegistry::new::<_, ReferenceBackend>(&nested)),
        )
        .finalize(crate::pasta::baked_aggregator());
    assert!(matches!(
        result,
        Err(ragu_core::Error::Initialization(message)) if alloc::format!("{message}").contains("vanish")
    ));
    Ok(())
}

/// The smallest mesh: the two inherited restrictions, their helpers, U and
/// the outgoing restriction, with the slots starting at `base`.
macro_rules! small_mesh {
    ($base:expr) => {
        Mesh {
            inherited: [
                Restriction {
                    polynomial: $base,
                    x: 0,
                    y: 1,
                    helper: $base + 2,
                },
                Restriction {
                    polynomial: $base + 1,
                    x: 2,
                    y: 3,
                    helper: $base + 3,
                },
            ],
            introduced: &[],
            helpers: &[
                Helper {
                    polynomial: $base + 2,
                    x: 0,
                },
                Helper {
                    polynomial: $base + 3,
                    x: 2,
                },
            ],
            u: $base + 4,
            outgoing: $base + 5,
        }
    };
}

/// Both ends of each of the small mesh's five edges, with slots from `base`.
macro_rules! small_mesh_openings {
    ($base:expr) => {
        [
            Opening {
                polynomial: $base,
                point: Point::Challenge(Challenge::W),
                value: 0,
            },
            Opening {
                polynomial: $base + 2,
                point: Point::Input(1),
                value: 0,
            },
            Opening {
                polynomial: $base + 1,
                point: Point::Challenge(Challenge::W),
                value: 1,
            },
            Opening {
                polynomial: $base + 3,
                point: Point::Input(3),
                value: 1,
            },
            Opening {
                polynomial: $base + 2,
                point: Point::Challenge(Challenge::Y),
                value: 2,
            },
            Opening {
                polynomial: $base + 4,
                point: Point::Input(0),
                value: 2,
            },
            Opening {
                polynomial: $base + 3,
                point: Point::Challenge(Challenge::Y),
                value: 3,
            },
            Opening {
                polynomial: $base + 4,
                point: Point::Input(2),
                value: 3,
            },
            Opening {
                polynomial: $base + 4,
                point: Point::Challenge(Challenge::X),
                value: 4,
            },
            Opening {
                polynomial: $base + 5,
                point: Point::Challenge(Challenge::W),
                value: 4,
            },
        ]
    };
}

const SMALL_MESH_OPENINGS: [Opening; 10] = small_mesh_openings!(0);

/// A native mesh alone, in slots 0 to 5.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NativeMeshOnly;
impl Profile for NativeMeshOnly {
    const NAME: &'static str = "native-source-mesh-only";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NATIVE_ENDOSCALINGS_PER_STEP: usize = 4;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = 4;
    type Context<'params, Base, Rk, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend;
    const NATIVE_ONLINE: Layout = Layout {
        polynomials: &[
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeY,
            Phase::BeforeY,
            Phase::BeforeX,
            Phase::BeforeAlpha,
        ],
        openings: &SMALL_MESH_OPENINGS,
        inputs: 4,
        points: 0,
        values: 5,
    };
    const NATIVE_MESH: Option<Mesh> = Some(small_mesh!(0));
}

const SHIFTED_MESH_OPENINGS: [Opening; 11] = {
    let mesh = small_mesh_openings!(1);
    let mut openings = [Opening {
        polynomial: 0,
        point: Point::Challenge(Challenge::W),
        value: 5,
    }; 11];
    let mut i = 0;
    while i < mesh.len() {
        openings[i + 1] = mesh[i];
        i += 1;
    }
    openings
};

/// A nested mesh alone, behind one polynomial outside the mesh, so its
/// slots are 1 to 6 rather than the native case's 0 to 5.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct NestedMeshOnly;
impl Profile for NestedMeshOnly {
    const NAME: &'static str = "nested-source-mesh-only";
    const NATIVE_EXTENSION: usize = 0;
    const NESTED_EXTENSION: usize = 0;
    const NATIVE_ENDOSCALINGS_PER_STEP: usize = 4;
    const NESTED_ENDOSCALINGS_PER_STEP: usize = 4;
    type Context<'params, Base, Rk, B>
        = ()
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend;
    const NESTED_ONLINE: Layout = Layout {
        polynomials: &[
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeW,
            Phase::BeforeY,
            Phase::BeforeY,
            Phase::BeforeX,
            Phase::BeforeAlpha,
        ],
        openings: &SHIFTED_MESH_OPENINGS,
        inputs: 4,
        points: 0,
        values: 6,
    };
    const NESTED_MESH: Option<Mesh> = Some(small_mesh!(1));

    fn nested_online_polynomials<'params, Base, Rk, B>(
        _: &Self::Context<'params, Base, Rk, B>,
        phase: Phase,
        _: &[Base::ScalarField],
        _: PreparationChallenges<Base::ScalarField>,
    ) -> Result<Vec<sparse::Polynomial<Base::ScalarField, Rk>>>
    where
        Base: IpaCycle + ProfiledCycle<Profile = Standard>,
        Rk: Rank,
        B: SelectableBackend,
    {
        Ok(if phase == Phase::BeforeW {
            vec![sparse::Polynomial::from_coeffs(vec![
                Base::ScalarField::ONE,
                Base::ScalarField::from(2),
            ])]
        } else {
            vec![]
        })
    }
}

/// Proves, recurses and verifies a profile whose mesh is on one side only,
/// then corrupts that side's mesh claims and outgoing commitment.
fn one_sided_mesh<P>(native: bool, seed: u64) -> Result<()>
where
    P: for<'params> Profile<Context<'params, Pasta, Rk, ReferenceBackend> = ()>,
{
    let source = ApplicationBuilder::<Pasta, R<13>, 2>::new()
        .register(UnitStep)?
        .finalize(crate::pasta::baked())?;
    let app = ApplicationBuilder::<Profiled<Pasta, P>, Rk, 2>::new()
        .register(UnitStep)?
        .with_source_registries(
            native.then(|| SourceRegistry::new::<_, ReferenceBackend>(source.native_registry())),
            (!native).then(|| SourceRegistry::new::<_, ReferenceBackend>(source.nested_registry())),
        )
        .finalize(crate::pasta::baked_aggregator())?;
    let mut rng = StdRng::seed_from_u64(seed);
    let (child, ()) = app.seed(&mut rng, UnitStep, ())?;
    verify(&app, &child, &mut rng, true)?;
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), child.clone(), child.clone())?;
    let (grandparent, ()) = app.fuse(&mut rng, UnitStep, (), parent, child.clone())?;
    verify(&app, &grandparent, &mut rng, true)?;

    let proof = child.proof();
    let (inactive_empty, mesh_len) = if native {
        (
            proof.nested_mesh_claims.is_empty()
                && proof.nested_online_commitments.is_empty()
                && proof.nested_source_out.is_empty(),
            proof.native_mesh_claims.len(),
        )
    } else {
        (
            proof.native_mesh_claims.is_empty()
                && proof.native_online_commitments.is_empty()
                && proof.native_source_out.is_empty(),
            proof.nested_mesh_claims.len(),
        )
    };
    assert!(inactive_empty, "the side without a mesh carries mesh data");
    let mesh = if native {
        P::NATIVE_MESH
    } else {
        P::NESTED_MESH
    }
    .expect("one mesh");
    assert_eq!(mesh_len, mesh.claims_len());

    // A coordinate, then the last edge value: U(x) = R_out(w).
    for index in [0, mesh_len - 1] {
        let mut proof = child.proof().clone();
        if native {
            proof.native_mesh_claims[index] += Fp::ONE;
        } else {
            proof.nested_mesh_claims[index] += Fq::ONE;
        }
        verify(&app, &proof.carry::<()>(()), &mut rng, false)?;
    }
    let mut proof = child.proof().clone();
    if native {
        proof.native_online_commitments[mesh.outgoing] =
            altered_point(proof.native_online_commitments[mesh.outgoing]);
    } else {
        proof.nested_online_commitments[mesh.outgoing] =
            altered_point(proof.nested_online_commitments[mesh.outgoing]);
    }
    verify(&app, &proof.carry::<()>(()), &mut rng, false)
}

#[test]
fn a_native_mesh_alone_closes_and_rejects_corruption() -> Result<()> {
    one_sided_mesh::<NativeMeshOnly>(true, 0x606070)
}

#[test]
fn a_nested_mesh_alone_at_other_slots_closes_and_rejects_corruption() -> Result<()> {
    one_sided_mesh::<NestedMeshOnly>(false, 0x606071)
}

#[path = "source_mesh_costs.rs"]
mod costs;
