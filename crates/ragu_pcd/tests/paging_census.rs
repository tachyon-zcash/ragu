//! The aggregator's declared page layouts fit every supported header size.
//! The paging census workflow compiles this target in thirteen batches so no
//! single runner must compile all 195 circuit specializations.
//!
//! A batch prints, for each paged circuit, the most values its pages carry
//! over the batch's header sizes beside what its carry stage is pinned to
//! hold, so the most over the thirteen batches is a pin's slack.

use ragu_core::Result;

#[cfg(ragu_pcd_paging_census)]
#[path = "support/paging_census.rs"]
mod support;
#[cfg(ragu_pcd_paging_census)]
use support::{Most, every_page_fits};

#[cfg(ragu_pcd_paging_census)]
macro_rules! check_headers {
    ($most:ident; $($header:literal),+ $(,)?) => {
        $(every_page_fits::<$header>(&mut $most)?;)+
    };
}

#[test]
fn all_aggregator_headers_fit_in_batch() -> Result<()> {
    assert!(
        cfg!(ragu_pcd_paging_census),
        "set RAGU_PCD_PAGING_CENSUS_BATCH to a value from 0 through 12"
    );

    #[cfg(ragu_pcd_paging_census)]
    let mut most = Most::default();
    #[cfg(ragu_pcd_paging_census_batch = "0")]
    check_headers!(most; 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    #[cfg(ragu_pcd_paging_census_batch = "1")]
    check_headers!(most; 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30);
    #[cfg(ragu_pcd_paging_census_batch = "2")]
    check_headers!(most; 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45);
    #[cfg(ragu_pcd_paging_census_batch = "3")]
    check_headers!(most; 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60);
    #[cfg(ragu_pcd_paging_census_batch = "4")]
    check_headers!(most; 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75);
    #[cfg(ragu_pcd_paging_census_batch = "5")]
    check_headers!(most; 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90);
    #[cfg(ragu_pcd_paging_census_batch = "6")]
    check_headers!(
        most; 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105
    );
    #[cfg(ragu_pcd_paging_census_batch = "7")]
    check_headers!(
        most; 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120
    );
    #[cfg(ragu_pcd_paging_census_batch = "8")]
    check_headers!(
        most; 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135
    );
    #[cfg(ragu_pcd_paging_census_batch = "9")]
    check_headers!(
        most; 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150
    );
    #[cfg(ragu_pcd_paging_census_batch = "10")]
    check_headers!(
        most; 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165
    );
    #[cfg(ragu_pcd_paging_census_batch = "11")]
    check_headers!(
        most; 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180
    );
    #[cfg(ragu_pcd_paging_census_batch = "12")]
    check_headers!(
        most; 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195
    );
    #[cfg(ragu_pcd_paging_census)]
    most.print();
    Ok(())
}
