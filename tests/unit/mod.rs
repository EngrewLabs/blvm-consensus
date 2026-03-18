//! Unit tests for blvm-consensus modules

mod transaction_tests;
mod script_tests;
mod economic_tests;
mod pow_tests;
mod transaction_edge_cases;
mod block_edge_cases;
mod script_opcode_property_tests;
mod mempool_edge_cases;
mod mempool_more_tests;
mod difficulty_edge_cases;
mod reorganization_edge_cases;
mod utxo_edge_cases;
mod segwit_taproot_property_tests;
mod comprehensive_property_tests;

// Production optimization tests (only compiled with production feature)
#[cfg(feature = "production")]
mod production_correctness_tests;
#[cfg(feature = "production")]
mod production_context_tests;
#[cfg(feature = "production")]
mod production_parallel_tests;
#[cfg(feature = "production")]
mod production_memory_tests;
#[cfg(feature = "production")]
mod production_edge_tests;
#[cfg(feature = "production")]
mod production_cache_tests;
#[cfg(feature = "production")]
mod blvm_optimization_tests;
#[cfg(feature = "production")]
mod blvm_memory_profiling_tests;

// UTXO commitments and spam filter tests moved to blvm-protocol


























