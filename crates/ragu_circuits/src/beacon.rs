//! Temporary setup-time tag injection for the registry-collision issue.
//!
//! [`Tag::from_beacon`] is an optional derivation helper. API consumers choose
//! the beacon and setup procedure; the Bitcoin ceremony in `qa/ceremony` is
//! an example for exercising this stopgap.

use blake2b_simd::Params;
use udon::field::Field;

use crate::registry::Tag;

impl<F: Field> Tag<F> {
    /// Derives a registry tag from a public randomness beacon and a setup
    /// manifest digest.
    ///
    /// This is a temporary helper for the registry-collision workaround in
    /// [#78](https://github.com/tachyon-zcash/ragu/issues/78). It derives tags
    /// from caller-provided inputs without prescribing a beacon provider or
    /// ceremony protocol.
    ///
    /// `beacon` is the raw beacon output, for example a block hash published
    /// after the system's description was committed. `manifest_digest` is the
    /// raw digest of the canonical, versioned setup manifest described below.
    /// `label` separates the tags of distinct registries drawn from the same
    /// output, such as an application's native and nested registries.
    ///
    /// The label, manifest digest, and beacon output are absorbed in that
    /// order into BLAKE2b, personalized for this purpose. Each is prefixed by
    /// its byte length as a little-endian `u64`. The 64-byte digest is reduced
    /// to a field element.
    ///
    /// # Caller requirement
    ///
    /// The inputs must satisfy [`Tag`]'s [sampling requirement](Tag#sampling-requirement).
    /// Commit the complete description before the beacon output is known,
    /// fixing the beacon source, label, and derivation rule in advance.
    /// The circuit author must not control or grind the output.
    ///
    /// `manifest_digest` must bind the complete description through a canonical,
    /// versioned manifest. Hash its bytes with SHA-256 or an equivalent
    /// collision-resistant hash, and bind the actual referenced code,
    /// dependency, and parameter contents with digests of that strength.
    /// A Git commit ID alone does not provide that content binding. The caller
    /// must check that the committed description matches the actual setup.
    ///
    /// A future Bitcoin block provides unpredictability after commitment, not
    /// unbiasability. Using it as a beacon assumes miners do not selectively
    /// withhold blocks or reorganize the chain to bias the tags.
    ///
    /// `qa/ceremony` demonstrates one Bitcoin/OpenTimestamps procedure for
    /// exercising this temporary helper; it is not a production ceremony
    /// specification.
    pub fn from_beacon(beacon: &[u8], manifest_digest: &[u8], label: &[u8]) -> Self {
        let digest = Params::new()
            .personal(b"ragu_tag_beacon_")
            .to_state()
            .update(&(label.len() as u64).to_le_bytes())
            .update(label)
            .update(&(manifest_digest.len() as u64).to_le_bytes())
            .update(manifest_digest)
            .update(&(beacon.len() as u64).to_le_bytes())
            .update(beacon)
            .finalize();
        Self::new(F::from_uniform_bytes(digest.as_array()))
    }
}

#[cfg(test)]
mod tests {
    use ragu_core::{
        Result,
        pasta::{Fp, Fq},
    };
    use udon::field::Field;

    use super::*;
    use crate::{
        polynomials::{Rank, TestRank},
        registry::RegistryBuilder,
    };

    #[test]
    fn beacon_tags_match_vectors() {
        // Independently generated with Python hashlib.blake2b, then reduced
        // modulo Fp/Fq using the digest's little-endian integer value.
        assert_eq!(
            Tag::<Fp>::from_beacon(&[0x42; 32], &[0x24; 20], b"ragu_pcd native registry").value(),
            Fp::new(udon::fp_hex!(
                "0x1c141fc950c9d298c205840012742d12b765e6cb495b9d4dccf775410d779870"
            )),
        );
        assert_eq!(
            Tag::<Fq>::from_beacon(&[0x42; 32], &[0x24; 20], b"ragu_pcd nested registry").value(),
            Fq::new(udon::fq_hex!(
                "0x0d02d867670856cbd43265aff57b50accb9b3f7179e72859a43336609dd0ac6f"
            )),
        );
    }

    #[test]
    fn beacon_tag_binds_each_input() {
        let tag = Tag::<Fp>::from_beacon(b"beacon", b"manifest digest", b"label").value();
        for (beacon, manifest_digest, label) in [
            (&b"other beacon"[..], &b"manifest digest"[..], &b"label"[..]),
            (b"beacon", b"other manifest digest", b"label"),
            (b"beacon", b"manifest digest", b"other label"),
        ] {
            assert_ne!(
                tag,
                Tag::<Fp>::from_beacon(beacon, manifest_digest, label).value()
            );
        }
    }

    #[test]
    fn beacon_tag_separates_input_boundaries() {
        assert_ne!(
            Tag::<Fp>::from_beacon(b"bc", b"a", b"label").value(),
            Tag::<Fp>::from_beacon(b"c", b"ab", b"label").value(),
        );
        assert_ne!(
            Tag::<Fp>::from_beacon(b"beacon", b"bc", b"a").value(),
            Tag::<Fp>::from_beacon(b"beacon", b"c", b"ab").value(),
        );
    }

    #[test]
    fn beacon_tag_sets_the_registry_term() -> Result<()> {
        let tag = Tag::<Fp>::from_beacon(b"beacon", b"manifest digest", b"label");
        let value = tag.value();
        let registry = RegistryBuilder::<Fp, TestRank>::new()
            .with_tag(tag)
            .register_circuit(())?
            .finalize()?;
        assert_eq!(registry.tag(), value);

        let w = Fp::from(5);
        let x = Fp::from(2);
        let y = Fp::from(3);
        let tagged = registry.wxy(w, x, y);
        let untagged = RegistryBuilder::<Fp, TestRank>::new()
            .with_tag(Tag::new(Fp::ZERO))
            .register_circuit(())?
            .finalize()?;
        assert_eq!(
            tagged - untagged.wxy(w, x, y),
            value * (x * y).pow_u64((4 * TestRank::n() - 1) as u64),
        );
        Ok(())
    }
}
