//! Base script flags must match Bitcoin Core `GetBlockScriptFlags` buried deployments:
//! CSV (BIP112) at 419328; NULLDUMMY (BIP147) at SegWit 481824 — not both at SegWit.

use blvm_consensus::block::{
    calculate_base_script_flags_for_block_network, calculate_script_flags_for_block_network,
};
use blvm_consensus::types::Network;
use blvm_consensus::{BIP112_CSV_ACTIVATION_MAINNET, BIP147_ACTIVATION_MAINNET};

const P2SH: u32 = 0x01;
const DERSIG: u32 = 0x04;
const NULLDUMMY: u32 = 0x10;
const CLTV: u32 = 0x200;
const CSV: u32 = 0x400;

fn base_mainnet_from(height: u64) -> u32 {
    calculate_base_script_flags_for_block_network(height, Network::Mainnet)
}

#[test]
fn mainnet_csv_without_nulldummy_in_csv_segwit_gap() {
    // Typical block in the divergence range (e.g. height ~444k): CSV on, NULLDUMMY off.
    let h = 443_992_u64;
    assert!(h >= BIP112_CSV_ACTIVATION_MAINNET);
    assert!(h < BIP147_ACTIVATION_MAINNET);

    let f = base_mainnet_from(h);
    assert!(
        f & CSV != 0,
        "CHECKSEQUENCEVERIFY must be active from CSV height (Core DEPLOYMENT_CSV)"
    );
    assert!(
        f & NULLDUMMY == 0,
        "NULLDUMMY must not be active before SegWit/BIP147 height"
    );
    let expected = P2SH | DERSIG | CLTV | CSV;
    assert_eq!(
        f, expected,
        "base flags at height {h} should match Core buried forks (P2SH|DERSIG|CLTV|CSV)"
    );
}

#[test]
fn mainnet_csv_flips_at_bip112_height() {
    let pre = BIP112_CSV_ACTIVATION_MAINNET - 1;
    let post = BIP112_CSV_ACTIVATION_MAINNET;
    assert!(base_mainnet_from(pre) & CSV == 0);
    assert!(base_mainnet_from(post) & CSV != 0);
}

#[test]
fn mainnet_nulldummy_flips_at_segwit_bip147_height() {
    let pre = BIP147_ACTIVATION_MAINNET - 1;
    let post = BIP147_ACTIVATION_MAINNET;
    let base_pre = base_mainnet_from(pre);
    let base_post = base_mainnet_from(post);
    assert!(base_pre & NULLDUMMY == 0);
    assert!(base_post & NULLDUMMY != 0);
    assert!(
        base_pre & CSV != 0 && base_post & CSV != 0,
        "CSV stays on through SegWit activation"
    );
}

#[test]
fn per_tx_flags_unchanged_for_empty_legacy_tx() {
    use blvm_consensus::types::{OutPoint, Transaction, TransactionInput};

    let tx = Transaction {
        version: 1,
        inputs: smallvec::smallvec![TransactionInput {
            prevout: OutPoint {
                hash: [0u8; 32],
                index: 0,
            },
            sequence: 0xffffffff,
            script_sig: vec![],
        }],
        outputs: smallvec::smallvec![],
        lock_time: 0,
    };
    let h = 443_992_u64;
    let base = base_mainnet_from(h);
    let combined = calculate_script_flags_for_block_network(&tx, false, h, Network::Mainnet);
    assert_eq!(
        combined, base,
        "pre-segwit legacy tx with no witness should not add witness/taproot flag bits"
    );
}

#[test]
fn regtest_bip112_zero_means_csv_from_genesis() {
    let f = calculate_base_script_flags_for_block_network(1, Network::Regtest);
    assert!(f & CSV != 0, "regtest CSV activation height is 0");
    assert!(f & DERSIG != 0);
}
