//! BIP9-style version bits activation.
//!
//! Computes soft-fork activation height from block header version bits so the node
//! can enforce a fork when miners signal (e.g. BIP54) without a fixed activation height.

use crate::types::BlockHeader;

/// BIP9 lock-in period (2016 blocks).
pub const LOCK_IN_PERIOD: u32 = 2016;

/// BIP9 activation threshold (95% of LOCK_IN_PERIOD).
pub const ACTIVATION_THRESHOLD: u32 = 1916;

/// BIP9 deployment parameters (bit index and time window).
#[derive(Debug, Clone, Copy)]
pub struct Bip9Deployment {
    /// Version bit index (0–28).
    pub bit: u8,
    /// Start time (Unix timestamp). Before this, state is Defined.
    pub start_time: u64,
    /// Timeout (Unix timestamp). After this, state is Failed.
    pub timeout: u64,
}

/// Returns the BIP54 deployment for mainnet when using version-bits activation.
///
/// Uses bit 15 and no time bounds so that once 95% of blocks in a 2016-block period
/// signal the bit, BIP54 is considered active. If the network assigns a different bit
/// or timeline, pass a custom `Bip9Deployment` to `activation_height_from_headers` instead.
pub fn bip54_deployment_mainnet() -> Bip9Deployment {
    Bip9Deployment {
        bit: 15,
        start_time: 0,
        timeout: u64::MAX,
    }
}

/// Computes the activation height for a BIP9 deployment from recent block headers.
///
/// * `headers` – Last N block headers (oldest first), typically the 2016 blocks before the
///   block we are validating. Must be the period ending at `current_height - 1`.
/// * `current_height` – Height of the block we are validating.
/// * `current_time` – Network time (Unix timestamp) for start/timeout checks.
/// * `deployment` – BIP9 deployment (bit, start_time, timeout).
///
/// Returns `Some(activation_height)` if the deployment is active at or before
/// `current_height`, so the caller can pass it as `bip54_activation_override`.
/// Returns `None` if the deployment is not active (defined, started, locked in but not
/// yet active, or failed), or if there are too few headers to determine lock-in.
pub fn activation_height_from_headers<H: AsRef<BlockHeader>>(
    headers: &[H],
    current_height: u64,
    current_time: u64,
    deployment: &Bip9Deployment,
) -> Option<u64> {
    if deployment.start_time >= deployment.timeout {
        return None;
    }
    if current_time < deployment.start_time || current_time >= deployment.timeout {
        return None;
    }
    if headers.len() < LOCK_IN_PERIOD as usize {
        return None;
    }

    let mut count = 0u32;
    for h in headers.iter().take(LOCK_IN_PERIOD as usize) {
        let v = h.as_ref().version as u32;
        if ((v >> deployment.bit) & 1) != 0 {
            count += 1;
        }
    }
    if count < ACTIVATION_THRESHOLD {
        return None;
    }

    // Lock-in detected for the period ending at (current_height - 1).
    // BIP9: ACTIVE for all blocks after the LOCKED_IN retarget period. So if period p
    // had ≥95%, we are LOCKED_IN at start of period p+1 and ACTIVE at start of period p+2.
    // period_index p = (current_height - 1) / 2016; activation = (p + 2) * 2016.
    let period_end = current_height.saturating_sub(1);
    let period_index = period_end / LOCK_IN_PERIOD as u64;
    let activation_height = (period_index + 2) * LOCK_IN_PERIOD as u64;

    if current_height >= activation_height {
        Some(activation_height)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BlockHeader;

    fn header(version: u32) -> BlockHeader {
        BlockHeader {
            version,
            prev_block_hash: [0u8; 32],
            merkle_root: [0u8; 32],
            timestamp: 0,
            bits: 0x1d00ffff,
            nonce: 0,
        }
    }

    #[test]
    fn disabled_deployment_returns_none() {
        let dep = Bip9Deployment {
            bit: 0,
            start_time: 100,
            timeout: 100,
        };
        let headers: Vec<BlockHeader> = (0..2016).map(|_| header(1)).collect();
        assert!(activation_height_from_headers(&headers, 4032, 150, &dep).is_none());
    }

    #[test]
    fn active_after_lockin() {
        let dep = Bip9Deployment {
            bit: 0,
            start_time: 0,
            timeout: u64::MAX,
        };
        // 2016 headers all with bit 0 set (period ending at current_height-1)
        let headers: Vec<BlockHeader> = (0..2016).map(|_| header(1)).collect();
        // Period 1 (2016..4031) had lock-in → LOCKED_IN at 4032, ACTIVE at 6048 (BIP9)
        assert!(activation_height_from_headers(&headers, 4032, 1, &dep).is_none());
        assert_eq!(
            activation_height_from_headers(&headers, 6048, 1, &dep),
            Some(6048)
        );
    }

    #[test]
    fn not_active_before_activation_height() {
        let dep = Bip9Deployment {
            bit: 0,
            start_time: 0,
            timeout: u64::MAX,
        };
        let headers: Vec<BlockHeader> = (0..2016).map(|_| header(1)).collect();
        // current_height 4031: period 1 had lock-in, activation is 6048
        assert!(activation_height_from_headers(&headers, 4031, 1, &dep).is_none());
    }
}
