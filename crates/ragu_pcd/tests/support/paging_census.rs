//! Shared fit check for the ordinary header-boundary test and the full
//! batched aggregator paging census.

use ragu_circuits::polynomials::AggregatorRank;
use ragu_core::{Result, pasta::Pasta};
#[cfg(ragu_pcd_paging_census)]
use ragu_pcd::profile::paging::{native_walk_census, nested_walk_census};
use ragu_pcd::profile::{
    Aggregator, Profiled,
    paging::{native_census, nested_census},
};

/// Check the non-walk circuits and the first step of each walk at one
/// aggregator header size with the declared page counts and stage layout.
/// The census also checks each resulting page against the unpaged circuit.
pub fn header_pages_fit<const H: usize>() -> Result<()> {
    type C<const H: usize> = Profiled<Pasta, Aggregator<H>>;

    let params = ragu_pcd::pasta::baked();
    let mut census = native_census::<C<H>, AggregatorRank, H>(params, 3, &[], false)?;
    census.extend(nested_census::<C<H>, AggregatorRank>(&[], false)?);
    for sizing in census {
        if let Err(error) = sizing.pages {
            panic!(
                "header size {H}: {} does not fit or check: {error}",
                sizing.name
            );
        }
    }
    Ok(())
}

/// Check every step of both walks as well as the circuits above, and the
/// decompression's two whole circuits with the pages pinned for them. A
/// final walk step can use fewer gates, so the first step cannot stand for
/// all of them in an exhaustive availability check.
#[cfg(ragu_pcd_paging_census)]
pub fn every_page_fits<const H: usize>() -> Result<()> {
    type C<const H: usize> = Profiled<Pasta, Aggregator<H>>;

    header_pages_fit::<H>()?;
    // The pages the profile pins for the decompression's whole circuits
    // hold at this header size too, not only at the sizes the unit tests
    // sample: each side cuts into them, and the pages are the circuit's.
    let params = ragu_pcd::pasta::baked();
    for sizing in Aggregator::<H>::decompression_census::<Pasta, AggregatorRank>(params, false)? {
        if let Err(error) = sizing.pages {
            panic!(
                "header size {H}: {} does not fit or check: {error}",
                sizing.name
            );
        }
    }
    for (step, sizing) in native_walk_census::<C<H>, AggregatorRank>()?
        .into_iter()
        .enumerate()
    {
        if let Err(error) = sizing.pages {
            panic!("header size {H}: native walk step {step} does not fit or check: {error}");
        }
    }
    for (step, sizing) in nested_walk_census::<C<H>, AggregatorRank>()?
        .into_iter()
        .enumerate()
    {
        if let Err(error) = sizing.pages {
            panic!("header size {H}: nested walk step {step} does not fit or check: {error}");
        }
    }
    Ok(())
}
