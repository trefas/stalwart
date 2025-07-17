//! Symmetrically Encrypted Integrity Protected data packets.
//!
//! An encrypted data packet is a container.  See [Section 5.13 of RFC
//! 9580] for details.
//!
//! [Section 5.13 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.13

use crate::packet;
use crate::Packet;

mod v2;
pub use v2::*;

/// Holds an encrypted data packet.
///
/// An encrypted data packet is a container.  See [Section 5.13 of RFC
/// 9580] for details.
///
/// [Section 5.13 of RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.13
///
/// # A note on equality
///
/// An unprocessed (encrypted) `SEIP` packet is never considered equal
/// to a processed (decrypted) one.  Likewise, a processed (decrypted)
/// packet is never considered equal to a structured (parsed) one.
// IMPORTANT: If you add fields to this struct, you need to explicitly
// IMPORTANT: implement PartialEq, Eq, and Hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SEIP1 {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,

    /// This is a container packet.
    container: packet::Container,
}

assert_send_and_sync!(SEIP1);

impl SEIP1 {
    /// Creates a new SEIP1 packet.
    pub fn new() -> Self {
        Self {
            common: Default::default(),
            container: Default::default(),
        }
    }
}

impl_processed_body_forwards!(SEIP1);

impl From<SEIP1> for super::SEIP {
    fn from(p: SEIP1) -> Self {
        super::SEIP::V1(p)
    }
}

impl From<SEIP1> for Packet {
    fn from(s: SEIP1) -> Self {
        Packet::SEIP(s.into())
    }
}
