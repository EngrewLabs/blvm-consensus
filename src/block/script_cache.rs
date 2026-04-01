//! Script verification flags and script-exec cache helpers for block validation.
//!
//! Groups base/per-tx script flags, cache insertion/merge, and BIP143 precompute
//! so block connect logic stays in the parent module.

use crate::activation::{ForkActivationTable, IsForkActive};
use crate::constants::*;
use crate::opcodes::*;
use crate::segwit::{is_segwit_transaction, Witness};
use crate::transaction::is_coinbase;
use crate::types::*;
use crate::witness::is_witness_empty;
use blvm_spec_lock::spec_locked;
#[cfg(feature = "production")]
use rustc_hash::{FxHashMap, FxHashSet};

use super::BlockValidationContext;

// ---------------------------------------------------------------------------
// Script flags (base, per-tx, and combined)
// ---------------------------------------------------------------------------

/// Base script flags for a block from activation context.
/// Call once per block, then use `calculate_script_flags_for_block` or `add_per_tx_script_flags`.
#[spec_locked("5.2.5")]
#[inline]
pub(crate) fn calculate_base_script_flags_for_block(
    height: u64,
    activation: &impl IsForkActive,
) -> u32 {
    let mut flags: u32 = 0;

    if activation.is_fork_active(ForkId::Bip16, height) {
        flags |= 0x01; // SCRIPT_VERIFY_P2SH
    }
    // BIP66: strict DER for ECDSA signatures only. Bitcoin Core `GetBlockScriptFlags`
    // adds SCRIPT_VERIFY_DERSIG here — not SCRIPT_VERIFY_STRICTENC or SCRIPT_VERIFY_LOW_S
    // (those are standardness / mempool policy; legacy blocks may contain high-S sigs).
    if activation.is_fork_active(ForkId::Bip66, height) {
        flags |= 0x04; // SCRIPT_VERIFY_DERSIG
    }
    if activation.is_fork_active(ForkId::Bip65, height) {
        flags |= 0x200; // CHECKLOCKTIMEVERIFY
    }
    if activation.is_fork_active(ForkId::Bip147, height) {
        flags |= 0x10 | 0x400; // NULLDUMMY, CHECKSEQUENCEVERIFY
    }
    #[cfg(feature = "ctv")]
    if activation.is_fork_active(ForkId::Ctv, height) {
        flags |= 0x80000000; // CHECK_TEMPLATE_VERIFY_HASH
    }

    flags
}

/// Convenience: base script flags from (height, network) when no context is available (e.g. mempool).
#[inline]
pub fn calculate_base_script_flags_for_block_network(
    height: u64,
    network: crate::types::Network,
) -> u32 {
    let table = ForkActivationTable::from_network(network);
    calculate_base_script_flags_for_block(height, &table)
}

/// Per-tx script flags (SegWit + Taproot). Add to base flags from `calculate_base_script_flags_for_block`.
#[spec_locked("5.2.5")]
#[inline]
fn add_per_tx_script_flags(
    base_flags: u32,
    tx: &Transaction,
    has_witness: bool,
    height: u64,
    activation: &impl IsForkActive,
) -> u32 {
    let mut flags = base_flags;
    if activation.is_fork_active(ForkId::SegWit, height)
        && (has_witness || is_segwit_transaction(tx))
    {
        flags |= 0x800;
    }
    if activation.is_fork_active(ForkId::Taproot, height) {
        for output in &tx.outputs {
            let script = &output.script_pubkey;
            if script.len() == TAPROOT_SCRIPT_LENGTH
                && script[0] == OP_1
                && script[1] == PUSH_32_BYTES
            {
                flags |= 0x8000;
                break;
            }
        }
    }
    flags
}

/// Calculate script verification flags for a transaction in a block (with activation context).
#[spec_locked("5.2.5")]
pub(crate) fn calculate_script_flags_for_block(
    tx: &Transaction,
    has_witness: bool,
    height: u64,
    activation: &impl IsForkActive,
) -> u32 {
    let base = calculate_base_script_flags_for_block(height, activation);
    add_per_tx_script_flags(base, tx, has_witness, height, activation)
}

/// Convenience: script flags from (height, network) when no context is available (e.g. mempool, bench tools).
#[spec_locked("5.2.5")]
pub fn calculate_script_flags_for_block_network(
    tx: &Transaction,
    has_witness: bool,
    height: u64,
    network: crate::types::Network,
) -> u32 {
    let table = ForkActivationTable::from_network(network);
    calculate_script_flags_for_block(tx, has_witness, height, &table)
}

/// Calculate script verification flags for a transaction in a block (with precomputed base flags).
#[spec_locked("5.2.5")]
#[inline]
pub(crate) fn calculate_script_flags_for_block_with_base(
    tx: &Transaction,
    has_witness: bool,
    base_flags: u32,
    height: u64,
    activation: &impl IsForkActive,
) -> u32 {
    add_per_tx_script_flags(base_flags, tx, has_witness, height, activation)
}

// ---------------------------------------------------------------------------
// Script-exec cache and overlay merge
// ---------------------------------------------------------------------------

/// Insert script exec cache keys for all txs in block (call when block validation passes).
#[cfg(all(feature = "production", feature = "rayon"))]
pub(super) fn insert_script_exec_cache_for_block(
    block: &Block,
    witnesses: &[Vec<Witness>],
    height: u64,
    context: &BlockValidationContext,
) {
    let base_script_flags = calculate_base_script_flags_for_block(height, context);
    for (i, tx) in block.transactions.iter().enumerate() {
        if is_coinbase(tx) {
            continue;
        }
        let wits = witnesses.get(i).map(|w| w.as_slice()).unwrap_or(&[]);
        let has_witness = wits.iter().any(|wit| !is_witness_empty(wit));
        let flags = calculate_script_flags_for_block_with_base(
            tx,
            has_witness,
            base_script_flags,
            height,
            context,
        );
        let witnesses_vec: Vec<_> = if wits.len() == tx.inputs.len() {
            wits.to_vec()
        } else {
            (0..tx.inputs.len()).map(|_| Vec::new()).collect()
        };
        let key = crate::script_exec_cache::compute_key(tx, &witnesses_vec, flags);
        crate::script_exec_cache::insert(&key);
    }
}

/// Merge overlay changes into cache. Updates bip30_index and optionally builds undo log.
/// When `undo_log` is None (IBD mode), skips undo entry construction entirely.
#[cfg(feature = "production")]
pub(super) fn merge_overlay_changes_to_cache(
    additions: &FxHashMap<OutPoint, std::sync::Arc<UTXO>>,
    deletions: &FxHashSet<crate::utxo_overlay::UtxoDeletionKey>,
    utxo_set: &mut UtxoSet,
    mut bip30_index: Option<&mut crate::bip_validation::Bip30Index>,
    mut undo_log: Option<&mut crate::reorganization::BlockUndoLog>,
) {
    use crate::reorganization::UndoEntry;

    for del_key in deletions {
        let outpoint = crate::utxo_overlay::utxo_deletion_key_to_outpoint(del_key);
        if let Some(arc) = utxo_set.remove(&outpoint) {
            if let Some(idx) = bip30_index.as_deref_mut() {
                if arc.is_coinbase {
                    if let std::collections::hash_map::Entry::Occupied(mut o) =
                        idx.entry(outpoint.hash)
                    {
                        *o.get_mut() = o.get().saturating_sub(1);
                        if *o.get() == 0 {
                            o.remove();
                        }
                    }
                }
            }
            if let Some(ref mut log) = undo_log {
                log.entries.push(UndoEntry {
                    outpoint,
                    previous_utxo: Some(arc),
                    new_utxo: None,
                });
            }
        }
    }
    for (outpoint, arc) in additions {
        if let Some(ref mut log) = undo_log {
            log.entries.push(UndoEntry {
                outpoint: *outpoint,
                previous_utxo: None,
                new_utxo: Some(std::sync::Arc::clone(arc)),
            });
        }
        utxo_set.insert(*outpoint, std::sync::Arc::clone(arc));
    }
}

/// Compute BIP143/precomputed sighash for CCheckQueue path. Uses local refs and specs Vecs
/// (dropped before return) so buf borrow ends.
#[cfg(all(feature = "production", feature = "rayon"))]
pub(super) fn compute_bip143_and_precomp(
    tx: &Transaction,
    prevout_values: &[i64],
    script_pubkey_indices: &[(usize, usize)],
    script_pubkey_buffer: &[u8],
    has_witness: bool,
) -> (
    Option<crate::transaction_hash::Bip143PrecomputedHashes>,
    Vec<Option<[u8; 32]>>,
) {
    let buf = script_pubkey_buffer;
    let refs: Vec<&[u8]> = script_pubkey_indices
        .iter()
        .map(|&(s, l)| buf[s..s + l].as_ref())
        .collect();
    let refs: &[&[u8]] = &refs;
    if has_witness {
        let bip =
            crate::transaction_hash::Bip143PrecomputedHashes::compute(tx, prevout_values, refs);
        let mut precomp = vec![None; script_pubkey_indices.len()];
        let mut specs: Vec<(usize, u8, &[u8])> = Vec::new();
        for (j, &(s, l)) in script_pubkey_indices.iter().enumerate() {
            let spk = &buf[s..s + l];
            if spk.len() == 22 && spk[0] == OP_0 && spk[1] == PUSH_20_BYTES {
                let mut script_code = [0u8; 25];
                script_code[0] = OP_DUP;
                script_code[1] = OP_HASH160;
                script_code[2] = PUSH_20_BYTES;
                script_code[3..23].copy_from_slice(&spk[2..22]);
                script_code[23] = OP_EQUALVERIFY;
                script_code[24] = OP_CHECKSIG;
                let amount = prevout_values.get(j).copied().unwrap_or(0);
                if let Ok(h) = crate::transaction_hash::calculate_bip143_sighash(
                    tx,
                    j,
                    &script_code,
                    amount,
                    0x01,
                    Some(&bip),
                ) {
                    precomp[j] = Some(h);
                }
            } else if spk.len() == 23
                && spk[0] == OP_HASH160
                && spk[1] == PUSH_20_BYTES
                && spk[22] == OP_EQUAL
            {
                if let Some((sighash_byte, redeem)) =
                    crate::script::parse_p2sh_p2pkh_for_precompute(&tx.inputs[j].script_sig)
                {
                    specs.push((j, sighash_byte, redeem));
                }
            }
        }
        if !specs.is_empty() {
            if let Ok(hashes) = crate::transaction_hash::batch_compute_legacy_sighashes(
                tx,
                prevout_values,
                refs,
                &specs,
            ) {
                for (k, &(j, _, _)) in specs.iter().enumerate() {
                    precomp[j] = Some(hashes[k]);
                }
            }
        }
        (Some(bip), precomp)
    } else {
        let mut precomp = vec![None; script_pubkey_indices.len()];
        let mut specs: Vec<(usize, u8, &[u8])> = Vec::new();
        for (j, &(s, l)) in script_pubkey_indices.iter().enumerate() {
            let spk = &buf[s..s + l];
            if spk.len() == 25
                && spk[0] == OP_DUP
                && spk[1] == OP_HASH160
                && spk[2] == PUSH_20_BYTES
                && spk[23] == OP_EQUALVERIFY
                && spk[24] == OP_CHECKSIG
            {
                let script_sig = &tx.inputs[j].script_sig;
                if let Some((sig, _pubkey)) = crate::script::parse_p2pkh_script_sig(script_sig) {
                    if !sig.is_empty() {
                        specs.push((j, sig[sig.len() - 1], spk));
                    }
                }
            } else if spk.len() == 23
                && spk[0] == OP_HASH160
                && spk[1] == PUSH_20_BYTES
                && spk[22] == OP_EQUAL
            {
                if let Some((sighash_byte, redeem)) =
                    crate::script::parse_p2sh_p2pkh_for_precompute(&tx.inputs[j].script_sig)
                {
                    specs.push((j, sighash_byte, redeem));
                }
            }
        }
        if !specs.is_empty() {
            if let Ok(hashes) = crate::transaction_hash::batch_compute_legacy_sighashes(
                tx,
                prevout_values,
                refs,
                &specs,
            ) {
                for (k, &(j, _, _)) in specs.iter().enumerate() {
                    precomp[j] = Some(hashes[k]);
                }
            }
        }
        (None, precomp)
    }
}
