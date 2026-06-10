extern crate alloc;

use std::{
    env,
    fs::File,
    io::{Result, Write},
    path::Path,
};

use ragu_arithmetic::{ff::PrimeField, pasta_curves::arithmetic::CurveAffine};

mod common {
    include!("pasta_common.rs");
}

fn write_point<C: CurveAffine, W: Write>(v: &mut W, point: C) -> Result<()> {
    let xy = point
        .coordinates()
        .expect("no points generated should be the identity");
    v.write_all(xy.x().to_repr().as_ref())?;
    v.write_all(xy.y().to_repr().as_ref())?;

    Ok(())
}

fn write_params_for_curve<C: CurveAffine, W: Write>(v: &mut W, g: &[C], h: &C) -> Result<()> {
    for point in g {
        write_point(v, *point)?;
    }
    write_point(v, *h)?;

    Ok(())
}

fn main() {
    if env::var("CARGO_FEATURE_BAKED").is_err() {
        return;
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_path = Path::new(&out_dir).join("pasta_parameters.bin");

    let params = common::PastaParams::generate();

    let mut f = File::create(out_path).unwrap();
    write_params_for_curve(&mut f, &params.pallas.g, &params.pallas.h).unwrap();
    write_params_for_curve(&mut f, &params.vesta.g, &params.vesta.h).unwrap();
}
