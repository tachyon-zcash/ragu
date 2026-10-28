//! Derives an application's registry tags from a beacon output and manifest digest.
//!
//! QA tooling for the temporary registry-collision workaround. The caller
//! chooses the beacon and setup procedure; this tool only derives the tags.
//!
//! ```text
//! cargo run -p ragu_ceremony --bin registry_tags -- [--profile standard|aggregator] <beacon-hex> <manifest-digest-hex>
//! ```
//!
//! `<beacon-hex>` is the beacon output as hex, for example the hash of the
//! Bitcoin block the ceremony selected. `<manifest-digest-hex>` is the digest of
//! the canonical, versioned setup manifest covering the code and complete
//! setup of both registries, as hex. Both inputs are decoded to raw bytes
//! before deriving the tags.
//! Omitting `--profile` retains Standard's existing labels and tag values.
//! Select `aggregator` only for a description of that profile's own setup.
//! The QA example uses SHA-256 of `setup.manifest`, whose artifact
//! digests bind the actual code and parameter bytes. A Git commit ID, or a
//! hash of that ID, is not a substitute. See `qa/ceremony/README.md`.
//! Prints the native and nested tags as big-endian hex, ready to pin next to
//! the inputs and timestamp proof. See `qa/ceremony/README.md` for the example
//! procedure and [`RegistryTags::from_beacon`]
//! for the sampling requirement. Use [`ApplicationBuilder::with_registry_tags`](ragu_pcd::ApplicationBuilder::with_registry_tags)
//! to build an application with these tags.

use ragu_core::pasta::{Fp, Fq, Pasta};
use ragu_pcd::{
    RegistryTags,
    profile::{Aggregator, Profiled},
};
use udon::field::Field;

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let inputs = parse_args(&args).unwrap_or_else(|error| {
        eprintln!("{error}");
        std::process::exit(2);
    });
    let beacon = decode_hex(inputs.beacon).unwrap_or_else(|e| {
        eprintln!("invalid beacon hex: {e}");
        std::process::exit(2);
    });
    let manifest_digest = decode_hex(inputs.manifest_digest).unwrap_or_else(|e| {
        eprintln!("invalid manifest digest hex: {e}");
        std::process::exit(2);
    });

    let (native, nested) = derive(inputs.profile, &beacon, &manifest_digest);
    println!("beacon ({} bytes): {}", beacon.len(), be_hex_bytes(&beacon));
    println!(
        "manifest digest ({} bytes): {}",
        manifest_digest.len(),
        be_hex_bytes(&manifest_digest)
    );
    println!("native tag (Fp): 0x{}", be_hex(native));
    println!("nested tag (Fq): 0x{}", be_hex(nested));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Profile {
    Standard,
    Aggregator,
}

struct Inputs<'a> {
    profile: Profile,
    beacon: &'a str,
    manifest_digest: &'a str,
}

fn parse_args(args: &[String]) -> Result<Inputs<'_>, String> {
    let (name, beacon, manifest_digest) = match args {
        [beacon, digest] => ("standard", beacon, digest),
        [flag, profile, beacon, digest] if flag == "--profile" => (profile.as_str(), beacon, digest),
        _ => return Err("usage: registry_tags [--profile standard|aggregator] <beacon-hex> <manifest-digest-hex>".into()),
    };
    let profile = match name {
        "standard" => Profile::Standard,
        "aggregator" => Profile::Aggregator,
        _ => return Err(format!("unsupported profile: {name}")),
    };
    Ok(Inputs {
        profile,
        beacon,
        manifest_digest,
    })
}

fn derive(profile: Profile, beacon: &[u8], manifest_digest: &[u8]) -> (Fp, Fq) {
    match profile {
        Profile::Standard => {
            let tags = RegistryTags::<Pasta>::from_beacon(beacon, manifest_digest);
            (tags.native(), tags.nested())
        }
        Profile::Aggregator => {
            // The labels name the profile, not its header size.
            let tags = RegistryTags::<Profiled<Pasta, Aggregator<4>>>::from_beacon(
                beacon,
                manifest_digest,
            );
            (tags.native(), tags.nested())
        }
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() || !s.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("expected a nonempty ASCII hex string".into());
    }
    if !s.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn be_hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Big-endian hex of a field element, matching Udon's field literal format.
fn be_hex<F: Field>(f: F) -> String {
    f.to_bytes()
        .as_ref()
        .iter()
        .rev()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_arguments_select_standard() {
        let legacy = ["42".into(), "24".into()];
        let explicit = [
            "--profile".into(),
            "standard".into(),
            "42".into(),
            "24".into(),
        ];
        assert_eq!(parse_args(&legacy).unwrap().profile, Profile::Standard);
        assert_eq!(parse_args(&explicit).unwrap().profile, Profile::Standard);
        let aggregator = [
            "--profile".into(),
            "aggregator".into(),
            "42".into(),
            "24".into(),
        ];
        assert_eq!(
            parse_args(&aggregator).unwrap().profile,
            Profile::Aggregator
        );
        let unknown = [
            "--profile".into(),
            "unknown".into(),
            "42".into(),
            "24".into(),
        ];
        assert!(parse_args(&unknown).is_err());
    }

    #[test]
    fn profile_manifest_fixtures_match_independent_vectors() {
        // SHA-256 of canonical test-only manifests. Expected field values were
        // computed independently using Python hashlib and integer reduction.
        for (profile, digest, expected_native, expected_nested) in [
            (
                Profile::Standard,
                include_str!("fixtures/standard.manifest.sha256"),
                include_str!("fixtures/standard.native.tag"),
                include_str!("fixtures/standard.nested.tag"),
            ),
            (
                Profile::Aggregator,
                include_str!("fixtures/aggregator.manifest.sha256"),
                include_str!("fixtures/aggregator.native.tag"),
                include_str!("fixtures/aggregator.nested.tag"),
            ),
        ] {
            let digest = decode_hex(digest.trim()).unwrap();
            let (native, nested) = derive(profile, &[0x42; 32], &digest);
            assert_eq!(be_hex(native), expected_native.trim());
            assert_eq!(be_hex(nested), expected_nested.trim());
        }
    }

    #[test]
    fn standard_derivation_is_unchanged() {
        let (native, nested) = derive(Profile::Standard, &[0x42; 32], &[0x24; 20]);
        assert_eq!(
            be_hex(native),
            "1c141fc950c9d298c205840012742d12b765e6cb495b9d4dccf775410d779870"
        );
        assert_eq!(
            be_hex(nested),
            "0d02d867670856cbd43265aff57b50accb9b3f7179e72859a43336609dd0ac6f"
        );
    }
}
