use std::cmp;

use digest::Digest as _;

use crate::{Error, Result};
use crate::crypto::hash::Digest;
use crate::types::HashAlgorithm;

macro_rules! impl_digest_for {
    ($ty:ty, $algo:ident) => {
        impl Digest for $ty {
            fn update(&mut self, data: &[u8]) {
                digest::Digest::update(self, data)
            }

            fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
                let buf = self.finalize_reset();
                let n = cmp::min(buf.len(), digest.len());
                digest[..n].copy_from_slice(&buf[..n]);
                Ok(())
            }
        }
    }
}

impl_digest_for!(md5::Md5, MD5);
impl_digest_for!(ripemd::Ripemd160, RipeMD);
impl_digest_for!(sha2::Sha224, SHA224);
impl_digest_for!(sha2::Sha256, SHA256);
impl_digest_for!(sha2::Sha384, SHA384);
impl_digest_for!(sha2::Sha512, SHA512);
impl_digest_for!(sha3::Sha3_256, SHA3_256);
impl_digest_for!(sha3::Sha3_512, SHA3_512);

impl HashAlgorithm {
    /// Whether Sequoia supports this algorithm.
    pub fn is_supported(self) -> bool {
        match self {
            HashAlgorithm::SHA1 => true,
            HashAlgorithm::SHA224 => true,
            HashAlgorithm::SHA256 => true,
            HashAlgorithm::SHA384 => true,
            HashAlgorithm::SHA512 => true,
            HashAlgorithm::SHA3_256 => true,
            HashAlgorithm::SHA3_512 => true,
            HashAlgorithm::RipeMD => true,
            HashAlgorithm::MD5 => true,
            HashAlgorithm::Private(_) => false,
            HashAlgorithm::Unknown(_) => false,
        }
    }

    /// Creates a new hash context for this algorithm.
    ///
    /// # Errors
    ///
    /// Fails with `Error::UnsupportedHashAlgorithm` if Sequoia does
    /// not support this algorithm. See
    /// [`HashAlgorithm::is_supported`].
    ///
    /// [`HashAlgorithm::is_supported`]: #method.is_supported
    pub(crate) fn new_hasher(self) -> Result<Box<dyn Digest>> {
        match self {
            // Note: SHA1 is implemented using SHA1CD, this is handled
            // in HashAlgorithm::context.
            HashAlgorithm::SHA1 =>
                Err(Error::UnsupportedHashAlgorithm(self).into()),
            HashAlgorithm::SHA224 => Ok(Box::new(sha2::Sha224::new())),
            HashAlgorithm::SHA256 => Ok(Box::new(sha2::Sha256::new())),
            HashAlgorithm::SHA384 => Ok(Box::new(sha2::Sha384::new())),
            HashAlgorithm::SHA512 => Ok(Box::new(sha2::Sha512::new())),
            HashAlgorithm::SHA3_256 => Ok(Box::new(sha3::Sha3_256::new())),
            HashAlgorithm::SHA3_512 => Ok(Box::new(sha3::Sha3_512::new())),
            HashAlgorithm::RipeMD => Ok(Box::new(ripemd::Ripemd160::new())),
            HashAlgorithm::MD5 => Ok(Box::new(md5::Md5::new())),
            HashAlgorithm::Private(_) | HashAlgorithm::Unknown(_) =>
                Err(Error::UnsupportedHashAlgorithm(self).into()),
        }
    }
}
