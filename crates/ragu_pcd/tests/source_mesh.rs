//! Source-registry identities on both fields, including recursive and terminal closure.
use alloc::{vec, vec::Vec};

use ragu_backend::ReferenceBackend;
use ragu_circuits::{
    polynomials::{R, Rank, sparse},
    registry::{RegistryBuilder, Tag},
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
type App<'a> = Application<'a, C, Rk, 2>;
fn altered_point<P: Affine>(point: P) -> P {
    if point.is_identity() {
        P::generator()
    } else {
        -point
    }
}
fn verify(app: &App<'_>, pcd: &Pcd<C, Rk, ()>, rng: &mut StdRng, expected: bool) -> Result<()> {
    assert_eq!(app.verify_uncompressed(pcd, &mut *rng)?, expected);
    match app.compress(pcd, rng) {
        Ok(compressed) => {
            let bytes = compressed.proof().to_bytes().expect("encode source mesh");
            let decoded = crate::CompressedProof::<C>::from_bytes(&bytes)
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
    verify(&app, &child, &mut rng, true)?;
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), child.clone(), child.clone())?;
    let (grandparent, ()) = app.fuse(&mut rng, UnitStep, (), parent.clone(), child.clone())?;
    verify(&app, &grandparent, &mut rng, true)?;
    let decoded = Proof::<C, Rk>::from_bytes(
        &parent
            .proof()
            .to_bytes()
            .expect("encode retained source polynomials"),
    )
    .expect("decode retained source polynomials")
    .carry::<()>(());
    verify(&app, &decoded, &mut rng, true)?;
    let wrong_native = RegistryBuilder::<Fp, R<13>>::new()
        .with_tag(Tag::new(Fp::ZERO))
        .finalize()?;
    let wrong_nested = RegistryBuilder::<Fq, R<13>>::new()
        .with_tag(Tag::new(Fq::ZERO))
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
        verify(&receiving, &child, &mut rng, false)?;
    }
    // The only source-polynomial witnesses retained for a parent are the two outgoing restrictions.
    assert_eq!(child.proof().native_source_out.len(), 1);
    assert_eq!(child.proof().nested_source_out.len(), 1);
    assert_eq!(child.proof().native_private_commitments.len(), 21);
    assert_eq!(child.proof().nested_private_commitments.len(), 21);
    for side in 0..2 {
        for coordinate_or_edge in [0, 4, 16, 34] {
            let mut proof = child.proof().clone();
            if side == 0 {
                proof.native_mesh[coordinate_or_edge] += Fp::ONE;
            } else {
                proof.nested_mesh[coordinate_or_edge] += Fq::ONE;
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
                proof.native_private_commitments[slot] =
                    altered_point(proof.native_private_commitments[slot]);
            } else {
                proof.nested_private_commitments[slot] =
                    altered_point(proof.nested_private_commitments[slot]);
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
#[test]
fn zero_source_restrictions_keep_identity_commitments_through_compression() -> Result<()> {
    let native = RegistryBuilder::<Fp, R<13>>::new()
        .with_tag(Tag::new(Fp::ZERO))
        .finalize()?;
    let nested = RegistryBuilder::<Fq, R<13>>::new()
        .with_tag(Tag::new(Fq::ZERO))
        .finalize()?;
    let app = ApplicationBuilder::<C, Rk, 2>::new()
        .register(UnitStep)?
        .with_source_registries(
            Some(SourceRegistry::new::<_, ReferenceBackend>(&native)),
            Some(SourceRegistry::new::<_, ReferenceBackend>(&nested)),
        )
        .finalize(crate::pasta::baked_aggregator())?;
    let mut rng = StdRng::seed_from_u64(0x606061);
    let (child, ()) = app.seed(&mut rng, UnitStep, ())?;
    for slot in SourceCapacity::NATIVE_MESH.unwrap().polynomial_indices() {
        assert!(child.proof().native_private_commitments[slot].is_identity());
        assert!(child.proof().nested_private_commitments[slot].is_identity());
    }
    verify(&app, &child, &mut rng, true)?;
    let (parent, ()) = app.fuse(&mut rng, UnitStep, (), child.clone(), child)?;
    verify(&app, &parent, &mut rng, true)
}

#[path = "source_mesh_costs.rs"]
mod costs;
