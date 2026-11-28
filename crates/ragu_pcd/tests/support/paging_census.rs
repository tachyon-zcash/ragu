//! Shared fit check for the ordinary header-boundary test and the full
//! batched aggregator paging census.

use ragu_circuits::polynomials::AggregatorRank;
use ragu_core::{Result, pasta::Pasta};
#[cfg(ragu_pcd_paging_census)]
use ragu_pcd::profile::paging::{native_walk_census, nested_walk_census};
use ragu_pcd::profile::{
    Aggregator, Profiled,
    paging::{Sizing, native_census, nested_census},
};

/// The most values each paged circuit's pages carry over the header sizes
/// checked, beside the values its carry stage is pinned to hold: what a
/// pin has to spare, and the header size that leaves it the least.
#[derive(Default)]
pub struct Most(Vec<Carried>);

/// A paged circuit's name, the values its carry stage holds, the most its
/// pages carry and the header size they carry them at.
struct Carried {
    name: &'static str,
    holds: usize,
    most: usize,
    header: usize,
}

impl Most {
    /// Notes what the pages of `sizing` carry at header size `header`. A
    /// walk's steps share a name, so the most is over them too.
    fn note(&mut self, header: usize, sizing: &Sizing) {
        let Ok((_, report)) = &sizing.pages else {
            return;
        };
        if sizing.count.num_pages() < 2 {
            return;
        }
        let position = self
            .0
            .iter()
            .position(|carried| carried.name == sizing.name)
            .unwrap_or_else(|| {
                self.0.push(Carried {
                    name: sizing.name,
                    holds: sizing.count.carry(),
                    most: 0,
                    header,
                });
                self.0.len() - 1
            });
        let carried = &mut self.0[position];
        if report.slots > carried.most {
            (carried.most, carried.header) = (report.slots, header);
        }
    }

    /// Prints a line for each paged circuit, in census order.
    pub fn print(&self) {
        for carried in &self.0 {
            println!(
                "PAGING CENSUS {}: carries at most {} of the {} values its carry stage holds, at \
                 header size {}",
                carried.name, carried.most, carried.holds, carried.header,
            );
        }
    }
}

/// Check the non-walk circuits and the first step of each walk at one
/// aggregator header size with the declared page counts and stage layout.
/// The census also checks each resulting page against the unpaged circuit.
/// Notes what each circuit's pages carry in `most`.
pub fn header_pages_fit<const H: usize>(most: &mut Most) -> Result<()> {
    type C<const H: usize> = Profiled<Pasta, Aggregator<H>>;

    let params = ragu_pcd::pasta::baked();
    let mut census = native_census::<C<H>, AggregatorRank, H>(params, 3, &[], false)?;
    census.extend(nested_census::<C<H>, AggregatorRank>(&[], false)?);
    for sizing in census {
        most.note(H, &sizing);
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
pub fn every_page_fits<const H: usize>(most: &mut Most) -> Result<()> {
    type C<const H: usize> = Profiled<Pasta, Aggregator<H>>;

    header_pages_fit::<H>(most)?;
    // The pages the profile pins for the decompression's whole circuits
    // hold at this header size too, not only at the sizes the unit tests
    // sample: each side cuts into them, and the pages are the circuit's.
    let params = ragu_pcd::pasta::baked();
    for sizing in Aggregator::<H>::decompression_census::<Pasta, AggregatorRank>(params, false)? {
        most.note(H, &sizing);
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
        most.note(H, &sizing);
        if let Err(error) = sizing.pages {
            panic!("header size {H}: native walk step {step} does not fit or check: {error}");
        }
    }
    for (step, sizing) in nested_walk_census::<C<H>, AggregatorRank>()?
        .into_iter()
        .enumerate()
    {
        most.note(H, &sizing);
        if let Err(error) = sizing.pages {
            panic!("header size {H}: nested walk step {step} does not fit or check: {error}");
        }
    }
    Ok(())
}
