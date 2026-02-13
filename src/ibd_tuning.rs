//! IBD Hardware Tuning
//!
//! Derives batch verification and parallelization parameters from hardware
//! (CPU count, cache size). Used when config does not supply explicit overrides.
//!
//! Precedence: Config override (if set) > Hardware-derived > Hardcoded default

use std::sync::OnceLock;

/// Hardware profile detected at first use.
#[derive(Debug, Clone)]
pub struct IbdHardwareProfile {
    /// From std::thread::available_parallelism()
    pub num_threads: usize,
    /// L3 cache size in KB (None if unknown)
    pub l3_cache_kb: Option<u64>,
    /// Many-core system (16+ logical cores)
    pub is_many_core: bool,
}

static HARDWARE_PROFILE: OnceLock<IbdHardwareProfile> = OnceLock::new();

fn detect_hardware() -> IbdHardwareProfile {
    let num_threads = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
        .max(1);

    let l3_cache_kb = detect_l3_cache_kb();
    let is_many_core = num_threads >= 16;

    IbdHardwareProfile {
        num_threads,
        l3_cache_kb,
        is_many_core,
    }
}

/// Detect L3 cache size on Linux via /sys. Returns None on non-Linux or if unreadable.
#[cfg(target_os = "linux")]
fn detect_l3_cache_kb() -> Option<u64> {
    use std::fs;
    use std::path::Path;

    let path = Path::new("/sys/devices/system/cpu/cpu0/cache/index3/size");
    if !path.exists() {
        return None;
    }
    let s = fs::read_to_string(path).ok()?.trim().to_string();
    let (num, suffix) = s.split_at(s.len().saturating_sub(1));
    let num: u64 = num.trim().parse().ok()?;
    let mult = match suffix {
        "K" | "k" => 1u64,
        "M" | "m" => 1024,
        _ => 1,
    };
    Some(num * mult)
}

#[cfg(not(target_os = "linux"))]
fn detect_l3_cache_kb() -> Option<u64> {
    None
}

fn hardware_profile() -> &'static IbdHardwareProfile {
    HARDWARE_PROFILE.get_or_init(detect_hardware)
}

/// secp256k1-fork allocates scratch and uses Pippenger when n_sigs >= this.
/// ECMULT_PIPPENGER_THRESHOLD in secp256k1 ecmult_impl.h is 88.
/// Only chunk when each chunk has >= this many sigs, so we stay on Pippenger/Strauss.
pub const PIPPENGER_SCRATCH_THRESHOLD: usize = 128;

/// Minimum sigs per chunk when parallelizing. Chunks smaller than this use ecmult_multi_simple_var (slow).
/// secp256k1: n>=64 gets Strauss, n>=88 gets Pippenger. We require >=88 so every chunk uses Pippenger.
pub const PIPPENGER_MIN_CHUNK: usize = 88;

/// Chunk threshold: parallelize when sig count exceeds this.
/// Higher = less chunking, more single Pippenger batches. Lower = more parallel chunks.
/// 176: 177+ sig blocks split to 2 chunks (≥88 each) → Pippenger; improves Rayon utilization.
/// Config/env BLVM_CONSENSUS_PERFORMANCE_IBD_CHUNK_THRESHOLD overrides.
pub fn chunk_threshold_config_or_hardware(config_override: Option<usize>) -> usize {
    config_override.unwrap_or(176)
}

/// Min chunk size for parallel batches. Larger chunks = better libsecp256k1 ecmult efficiency.
/// Hardware-derived from L3 cache when known; otherwise 96. Config overrides when Some.
pub fn min_chunk_size_config_or_hardware(config_override: Option<usize>) -> usize {
    config_override.unwrap_or_else(|| {
        let p = hardware_profile();
        let from_l3 = p.l3_cache_kb.map(|kb| (kb / 32) as usize);
        let derived = from_l3.unwrap_or(96);
        derived.clamp(64, 128)
    })
}

/// Chunk size for batch hash operations (SHA256, HASH160). Cache-friendly, fits in L1.
/// Hardware-derived from L3 when known (L3/256 clamped 8–32); otherwise 16.
/// Used by simd_vectorization for batch hashing.
pub fn hash_batch_chunk_size() -> usize {
    let p = hardware_profile();
    let from_l3 = p.l3_cache_kb.map(|kb| (kb / 256) as usize);
    let derived = from_l3.unwrap_or(16);
    derived.clamp(8, 32)
}
