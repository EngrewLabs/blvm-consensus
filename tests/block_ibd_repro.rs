//! Reproduce IBD failure using dumped block data.
//!
//! When IBD fails, the node dumps to $BLVM_IBD_FAILURE_DUMP_DIR/height_{N}/
//! Run: `scripts/ibd_failure_to_repro_test.sh [HEIGHT]` to copy dump to repo.
//!
//! Run test: BLVM_IBD_FAILURE_HEIGHT=N cargo test --test block_ibd_repro -- --ignored

use blvm_consensus::block::connect_block_ibd;
use blvm_consensus::types::{Block, Network, UtxoSet};
use blvm_consensus::segwit::Witness;
use blvm_consensus::ValidationResult;
use std::path::Path;

const DEFAULT_DUMP_DIR: &str = "/tmp/blvm_ibd_failure";
fn height() -> u64 {
    std::env::var("BLVM_IBD_FAILURE_HEIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .expect("Set BLVM_IBD_FAILURE_HEIGHT to the failing block height")
}

fn dump_dir() -> std::path::PathBuf {
    let h = height();
    if let Ok(d) = std::env::var("BLVM_IBD_FAILURE_DUMP_DIR") {
        return std::path::PathBuf::from(d).join(format!("height_{}", h));
    }
    // Repo backup: blvm-consensus/tests/test_data/ibd_failure_height_{h}
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/test_data")
        .join(format!("ibd_failure_height_{}", h));
    if repo.join("block.bin").exists() {
        return repo;
    }
    std::path::PathBuf::from(DEFAULT_DUMP_DIR).join(format!("height_{}", h))
}

fn load_dump(dir: &Path) -> Result<(Block, Vec<Vec<Witness>>, UtxoSet), Box<dyn std::error::Error + Send + Sync>> {
    let block: Block = bincode::deserialize_from(std::io::BufReader::new(std::fs::File::open(dir.join("block.bin"))?))?;
    let witnesses: Vec<Vec<Witness>> = bincode::deserialize_from(std::io::BufReader::new(std::fs::File::open(dir.join("witnesses.bin"))?))?;
    let utxo_set: UtxoSet = bincode::deserialize_from(std::io::BufReader::new(std::fs::File::open(dir.join("utxo_set.bin"))?))?;
    Ok((block, witnesses, utxo_set))
}

#[test]
#[ignore = "Slow: loads UTXO set; run with --ignored and BLVM_IBD_FAILURE_HEIGHT set"]
fn block_ibd_repro() {
    let h = height();
    let dir = dump_dir();
    if !dir.join("block.bin").exists() {
        eprintln!(
            "Skip: dump not found at {}. Run: ./scripts/ibd_failure_to_repro_test.sh {}",
            dir.display(),
            h
        );
        return;
    }

    let (block, mut witnesses, utxo_set) = load_dump(&dir).expect("load dump");
    if witnesses.len() != block.transactions.len() {
        witnesses = block
            .transactions
            .iter()
            .map(|tx| (0..tx.inputs.len()).map(|_| Vec::new()).collect())
            .collect();
    }

    let (result, _new_utxo_set, _tx_ids) = connect_block_ibd(
        &block,
        &witnesses,
        utxo_set,
        h,
        None::<&[blvm_consensus::types::BlockHeader]>,
        0u64,
        Network::Mainnet,
        None,
    )
    .expect("connect_block_ibd");

    match result {
        ValidationResult::Valid => {}
        ValidationResult::Invalid(reason) => panic!("Block {} should be valid: {}", h, reason),
    }
}
