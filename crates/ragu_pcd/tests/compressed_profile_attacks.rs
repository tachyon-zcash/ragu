//! Attacks checked directly by a fixed application's compressed verifier.

use ragu_circuits::registry::CircuitIndex;
use ragu_core::pasta::Fq;
use udon::field::Field;

use super::*;
use crate::profile::testing::{Crossing, CrossingBack, CrossingContext, Twin};

fn reject<P: Profile, Rk: Rank>(
    app: &App<P, Rk>,
    proof: CompressedProof<C<P>>,
    data: Fp,
    case: &str,
) {
    let result = app.verify_compressed(&proof.carry::<Value>(data));
    assert!(matches!(result, Ok(false)), "{case}: {result:?}");
}

fn check_edits<P: Profile, Rk: Rank>(
    app: &App<P, Rk>,
    proof: &CompressedProof<C<P>>,
    data: Fp,
) -> usize {
    assert!(
        app.verify_compressed(&proof.clone().carry::<Value>(data))
            .unwrap()
    );
    let mut cases = 0;
    let mut edit = |case: &str, mutate: &dyn Fn(&mut CompressedProof<C<P>>)| {
        let mut changed = proof.clone();
        mutate(&mut changed);
        reject(app, changed, data, case);
        cases += 1;
    };

    edit("other application circuit", &|p| {
        p.instance.circuit_id = CircuitIndex::new(0)
    });
    edit("out-of-domain circuit", &|p| {
        p.instance.circuit_id = CircuitIndex::new(u32::MAX as usize)
    });

    macro_rules! scalar {
        ($field:ident $(.$part:ident)*, $one:expr) => {
            edit(stringify!($field $(.$part)*), &|p| p.instance.$field $(.$part)* += $one);
        };
    }
    scalar!(c, Fp::ONE);
    scalar!(v, Fp::ONE);
    scalar!(left.x, Fp::ONE);
    scalar!(left.y, Fp::ONE);
    scalar!(left.id, Fp::ONE);
    scalar!(right.x, Fp::ONE);
    scalar!(right.y, Fp::ONE);
    scalar!(right.id, Fp::ONE);
    scalar!(a_at_u, Fp::ONE);
    scalar!(b_at_u, Fp::ONE);
    scalar!(bridge_alpha, Fq::ONE);
    scalar!(nested_c, Fq::ONE);
    scalar!(nested_v, Fq::ONE);
    scalar!(nested_left.x, Fq::ONE);
    scalar!(nested_left.y, Fq::ONE);
    scalar!(nested_right.x, Fq::ONE);
    scalar!(nested_right.y, Fq::ONE);
    scalar!(nested_a_at_u, Fq::ONE);
    scalar!(nested_b_at_u, Fq::ONE);

    for i in 0..HEADER_SIZE {
        edit(&alloc::format!("left header {i}"), &|p| {
            p.instance.left_header[i] += Fp::ONE
        });
        edit(&alloc::format!("right header {i}"), &|p| {
            p.instance.right_header[i] += Fp::ONE
        });
    }
    for i in 0..proof.instance.native.len() {
        edit(&alloc::format!("native component {i}"), &|p| {
            p.instance.native[i] = -p.instance.native[i]
        });
    }
    for i in 0..proof.instance.nested.len() {
        edit(&alloc::format!("nested component {i}"), &|p| {
            p.instance.nested[i] = -p.instance.nested[i]
        });
    }
    macro_rules! point {
        ($field:ident) => {
            edit(stringify!($field), &|p| {
                p.instance.$field = -p.instance.$field
            });
        };
    }
    point!(native_registry_xy);
    point!(native_p);
    point!(nested_registry_xy);
    point!(nested_p);
    point!(nested_challenges_partial);

    macro_rules! length {
        ($field:ident $(.$part:ident)*) => {
            edit(concat!(stringify!($field $(.$part)*), " missing entry"), &|p| {
                p.instance.$field $(.$part)* .pop().unwrap();
            });
            edit(concat!(stringify!($field $(.$part)*), " trailing entry"), &|p| {
                let extra = p.instance.$field $(.$part)* [0];
                p.instance.$field $(.$part)* .push(extra);
            });
        };
    }
    length!(left_header);
    length!(right_header);
    length!(native);
    length!(nested);
    edit("native component order", &|p| p.instance.native.reverse());
    edit("nested component order", &|p| p.instance.nested.reverse());

    macro_rules! messages {
        ($side:ident, $one:expr) => {{
            edit(
                concat!(stringify!($side), " inner error commitment"),
                &|p| p.$side.reduction.fold.inner = -p.$side.reduction.fold.inner,
            );
            edit(
                concat!(stringify!($side), " outer error commitment"),
                &|p| p.$side.reduction.fold.outer = -p.$side.reduction.fold.outer,
            );
            edit(concat!(stringify!($side), " inner error value"), &|p| {
                p.$side.reduction.fold.inner_epsilon += $one
            });
            edit(concat!(stringify!($side), " outer error value"), &|p| {
                p.$side.reduction.fold.outer_epsilon += $one
            });
            edit(concat!(stringify!($side), " reduction p"), &|p| {
                p.$side.reduction.p = -p.$side.reduction.p
            });
            edit(concat!(stringify!($side), " reduction q"), &|p| {
                p.$side.reduction.q = -p.$side.reduction.q
            });
            edit(concat!(stringify!($side), " p opening"), &|p| {
                p.$side.reduction.p_at_inverse_r += $one
            });
            edit(concat!(stringify!($side), " q opening"), &|p| {
                p.$side.reduction.q_at_r += $one
            });
            for i in 0..proof.$side.reduction.openings.len() {
                edit(
                    &alloc::format!("{} reduction opening {i}", stringify!($side)),
                    &|p| p.$side.reduction.openings[i] += $one,
                );
            }
            edit(
                concat!(stringify!($side), " missing reduction opening"),
                &|p| {
                    p.$side.reduction.openings.pop().unwrap();
                },
            );
            edit(
                concat!(stringify!($side), " trailing reduction opening"),
                &|p| p.$side.reduction.openings.push($one),
            );
            edit(concat!(stringify!($side), " batch quotient"), &|p| {
                p.$side.batch.f = -p.$side.batch.f
            });
            for i in 0..proof.$side.batch.evaluations.len() {
                edit(
                    &alloc::format!("{} batch value {i}", stringify!($side)),
                    &|p| p.$side.batch.evaluations[i] += $one,
                );
            }
            edit(concat!(stringify!($side), " missing batch value"), &|p| {
                p.$side.batch.evaluations.pop().unwrap();
            });
            edit(concat!(stringify!($side), " trailing batch value"), &|p| {
                p.$side.batch.evaluations.push($one)
            });
            edit(
                concat!(stringify!($side), " IPA masking commitment"),
                &|p| p.$side.opening.s_commitment = -p.$side.opening.s_commitment,
            );
            edit(concat!(stringify!($side), " IPA coefficient"), &|p| {
                p.$side.opening.c += $one
            });
            for i in 0..proof.$side.opening.rounds.len() {
                edit(&alloc::format!("{} IPA L {i}", stringify!($side)), &|p| {
                    p.$side.opening.rounds[i].0 = -p.$side.opening.rounds[i].0
                });
                edit(&alloc::format!("{} IPA R {i}", stringify!($side)), &|p| {
                    p.$side.opening.rounds[i].1 = -p.$side.opening.rounds[i].1
                });
            }
            edit(concat!(stringify!($side), " missing IPA round"), &|p| {
                p.$side.opening.rounds.pop().unwrap();
            });
            edit(concat!(stringify!($side), " trailing IPA round"), &|p| {
                p.$side.opening.rounds.push(p.$side.opening.rounds[0])
            });
            edit(concat!(stringify!($side), " IPA round order"), &|p| {
                p.$side.opening.rounds.reverse()
            });
            edit(concat!(stringify!($side), " IPA L/R roles"), &|p| {
                let (left, right) = &mut p.$side.opening.rounds[0];
                core::mem::swap(left, right);
            });
        }};
    }
    messages!(native, Fp::ONE);
    messages!(nested, Fq::ONE);
    reject(app, proof.clone(), data + Fp::ONE, "output statement");
    cases += 1;
    assert!(
        cases > 200,
        "the mutation suite must cover the full instance and both message lists"
    );
    cases
}

/// Assemble independently selected native and nested instance halves. Naming
/// every field makes a new instance field require an explicit choice here.
fn mix_instance<P: Profile>(native: &Instance<C<P>>, nested: &Instance<C<P>>) -> Instance<C<P>> {
    Instance {
        circuit_id: native.circuit_id,
        left_header: native.left_header.clone(),
        right_header: native.right_header.clone(),
        native: native.native.clone(),
        native_registry_xy: native.native_registry_xy,
        native_p: native.native_p,
        c: native.c,
        v: native.v,
        left: native.left,
        right: native.right,
        a_at_u: native.a_at_u,
        b_at_u: native.b_at_u,
        nested: nested.nested.clone(),
        nested_registry_xy: nested.nested_registry_xy,
        nested_p: nested.nested_p,
        nested_challenges_partial: nested.nested_challenges_partial,
        bridge_alpha: nested.bridge_alpha,
        nested_c: nested.nested_c,
        nested_v: nested.nested_v,
        nested_left: nested.nested_left,
        nested_right: nested.nested_right,
        nested_a_at_u: nested.nested_a_at_u,
        nested_b_at_u: nested.nested_b_at_u,
    }
}

fn check_splices<P: Profile>(
    app: &App<P, ProductionRank>,
    local: &CompressedProof<C<P>>,
    local_data: Fp,
    donor: &CompressedProof<C<P>>,
    donor_data: Fp,
    donor_is_valid: bool,
) {
    // All 16 choices of native instance, nested instance, native messages
    // and nested messages. The receiving application never changes.
    for mask in 0..16 {
        let choose = |bit| if mask & bit == 0 { local } else { donor };
        let candidate = CompressedProof {
            instance: mix_instance(&choose(1).instance, &choose(2).instance),
            native: choose(4).native.clone(),
            nested: choose(8).nested.clone(),
        };
        let expected = (mask == 0 && donor_data == local_data) || (mask == 15 && donor_is_valid);
        let result = app.verify_compressed(&candidate.carry::<Value>(donor_data));
        assert!(
            matches!(result, Ok(actual) if actual == expected),
            "splice mask {mask:#06b}: {result:?}"
        );
    }
}

fn check_profile_packets<S: Profile, T: Profile>(
    source_constraint: Option<Fp>,
    source_value: Fp,
    edit_fields: bool,
) -> Result<()>
where
    S::Context<'static, Pasta, ProductionRank, ReferenceBackend>: Default,
    T::Context<'static, Pasta, ProductionRank, ReferenceBackend>: Default,
{
    let sender = application::<S, ProductionRank>(
        RegistryTags::from_beacon(&[0x42; 32], SENDER_MANIFEST),
        SENDER_MANIFEST,
        source_constraint,
    )?;
    let receiver = application::<T, ProductionRank>(
        RegistryTags::from_beacon(&[0x42; 32], RECEIVER_MANIFEST),
        RECEIVER_MANIFEST,
        Some(Fp::from(7)),
    )?;
    let mut rng = StdRng::seed_from_u64(0x908_c001);
    let (source, ()) = sender.seed(
        &mut rng,
        Seed {
            expected: source_constraint,
        },
        source_value,
    )?;
    let (source, ()) = sender.fuse(&mut rng, Sum, (), source.clone(), source)?;
    let compressed = sender.compress(&source, &mut rng)?;
    assert!(sender.verify_compressed(&compressed)?);
    let foreign_data = *source.data();
    let foreign = copy_compressed_payload::<C<S>, C<T>>(compressed.into_parts().0);

    let (leaf, ()) = receiver.seed(
        &mut rng,
        Seed {
            expected: Some(Fp::from(7)),
        },
        Fp::from(7),
    )?;
    let (parent, ()) = receiver.fuse(&mut rng, Sum, (), leaf.clone(), leaf.clone())?;
    let local = receiver.compress(&parent, &mut rng)?;
    assert!(receiver.verify_compressed(&local)?);
    let (local, data) = local.into_parts();
    check_splices(&receiver, &local, data, &foreign, foreign_data, false);

    let (second, ()) = receiver.fuse(&mut rng, Sum, (), leaf.clone(), leaf)?;
    let second = receiver.compress(&second, &mut rng)?;
    assert!(receiver.verify_compressed(&second)?);
    check_splices(
        &receiver,
        &local,
        data,
        second.proof(),
        *second.data(),
        true,
    );
    if edit_fields {
        let cases = check_edits(&receiver, &local, data);
        std::println!(
            "{} receiving {}: {cases} rejected edits, 32 splice combinations",
            T::NAME,
            S::NAME
        );
    }
    Ok(())
}

#[test]
fn compressed_standard_rejects_twin_packets_and_edits() -> Result<()> {
    check_profile_packets::<Twin, Standard>(Some(Fp::from(7)), Fp::from(7), true)
}

#[test]
fn compressed_twin_rejects_standard_packets_and_edits() -> Result<()> {
    check_profile_packets::<Standard, Twin>(Some(Fp::from(7)), Fp::from(7), true)
}

#[test]
fn compressed_standard_rejects_weaker_profile_packet_splices() -> Result<()> {
    check_profile_packets::<Permissive, Standard>(None, Fp::from(9), false)
}

fn check_fresh_weaker_proving<P: Profile>() -> Result<()>
where
    P::Context<'static, Pasta, ProductionRank, ReferenceBackend>: Default,
{
    let app = application::<P, ProductionRank>(
        RegistryTags::from_beacon(&[0x42; 32], RECEIVER_MANIFEST),
        RECEIVER_MANIFEST,
        Some(Fp::from(7)),
    )?;
    let mut rng = StdRng::seed_from_u64(0x908_c002);
    let (honest, ()) = app.seed(
        &mut rng,
        Seed {
            expected: Some(Fp::from(7)),
        },
        Fp::from(7),
    )?;
    assert!(app.verify_compressed(&app.compress(&honest, &mut rng)?)?);

    // The attacker knows and uses the receiver's exact tags, parameters and
    // profile. Only its proving step is weakened or given another constant.
    // Every reduction, batch and IPA is freshly generated for the attempt.
    for expected in [None, Some(Fp::from(9))] {
        let (bad, ()) = app.seed(&mut rng, Seed { expected }, Fp::from(9))?;
        assert!(bad.proof().well_formed::<HEADER_SIZE>());
        let compressed = app.compress(&bad, &mut rng)?;
        reject(
            &app,
            compressed.into_parts().0,
            Fp::from(9),
            "fresh weaker seed under receiver setup",
        );
        let refreshed = app.rerandomize(bad.clone(), &mut rng)?;
        let compressed = app.compress(&refreshed, &mut rng)?;
        reject(
            &app,
            compressed.into_parts().0,
            Fp::from(9),
            "fresh rerandomized weaker seed",
        );
        let (parent, ()) = app.fuse(&mut rng, Sum, (), bad, honest.clone())?;
        let compressed = app.compress(&parent, &mut rng)?;
        reject(
            &app,
            compressed.into_parts().0,
            *parent.data(),
            "fresh weaker parent",
        );
        let (grandparent, ()) = app.fuse(&mut rng, Sum, (), honest.clone(), parent)?;
        let compressed = app.compress(&grandparent, &mut rng)?;
        reject(
            &app,
            compressed.into_parts().0,
            *grandparent.data(),
            "fresh weaker grandparent",
        );
    }
    Ok(())
}

#[test]
fn compressed_standard_rejects_fresh_weaker_proving_with_its_own_setup() -> Result<()> {
    check_fresh_weaker_proving::<Standard>()
}

#[test]
fn compressed_twin_rejects_fresh_weaker_proving_with_its_own_setup() -> Result<()> {
    check_fresh_weaker_proving::<Twin>()
}

fn check_extension_edits<P>() -> Result<()>
where
    P: Profile<Context<'static, Pasta, R<14>, ReferenceBackend> = CrossingContext<'static, Pasta>>,
{
    let params = crate::pasta::baked_aggregator();
    let bits = [true, false, false, true];
    let app = ApplicationBuilder::<C<P>, R<14>, HEADER_SIZE>::new()
        .register(Seed {
            expected: Some(Fp::from(7)),
        })?
        .register(Sum)?
        .with_registry_tags(
            RegistryTags::from_beacon(&[0x42; 32], RECEIVER_MANIFEST),
            RECEIVER_MANIFEST,
        )?
        .finalize_with(
            params,
            CrossingContext {
                params,
                native: bits,
                nested: bits,
            },
        )?;
    let mut rng = StdRng::seed_from_u64(0x908_c003);
    let (leaf, ()) = app.seed(
        &mut rng,
        Seed {
            expected: Some(Fp::from(7)),
        },
        Fp::from(7),
    )?;
    let (parent, ()) = app.fuse(&mut rng, Sum, (), leaf.clone(), leaf)?;
    let compressed = app.compress(&parent, &mut rng)?;
    let cases = check_edits(&app, compressed.proof(), *compressed.data());
    std::println!(
        "{}: {cases} rejected edits, including extension commitments",
        P::NAME
    );
    Ok(())
}

#[test]
fn compressed_native_extension_binding_rejects_packet_edits() -> Result<()> {
    check_extension_edits::<Crossing>()
}

#[test]
fn compressed_nested_extension_binding_rejects_packet_edits() -> Result<()> {
    check_extension_edits::<CrossingBack>()
}
