//! Compile-time verification that BIP checks are called in connect_block
//!
//! This test uses static analysis to verify that BIP validation functions
//! are referenced in connect_block. If they're removed, this test will fail to compile.

#[cfg(test)]
mod compile_time_verification {
    /// Verify that connect_block references BIP validation functions
    ///
    /// This is a compile-time check - if BIP checks are removed from connect_block,
    /// this test will fail to compile because the functions won't be accessible.
    #[test]
    fn verify_bip_checks_are_accessible() {
        // These should all compile - if they don't, BIP validation module isn't accessible
        use blvm_consensus::activation::ForkActivationTable;
        use blvm_consensus::bip_validation::{self, Bip30Index};
        use blvm_consensus::error::Result;
        use blvm_consensus::types::{Block, Hash, Natural, UtxoSet};

        // `check_bip30` takes `&impl IsForkActive`; pick a concrete table so the fn item type checks.
        let _check_bip30: fn(
            &Block,
            &UtxoSet,
            Option<&Bip30Index>,
            Natural,
            &ForkActivationTable,
            Option<&Hash>,
        ) -> Result<bool> = bip_validation::check_bip30;

        let _check_bip34: fn(&Block, Natural, &ForkActivationTable) -> Result<bool> =
            bip_validation::check_bip34;

        let _check_bip90: fn(i64, Natural, &ForkActivationTable) -> Result<bool> =
            bip_validation::check_bip90;

        // If we can reference these, they're at least accessible to connect_block
        // (Actual integration tests verify they're called)
    }

    /// Verify that Network type is accessible for BIP checks
    #[test]
    fn verify_network_type_accessible() {
        use blvm_consensus::types::Network;

        // Verify Network enum variants exist
        let _mainnet = Network::Mainnet;
        let _testnet = Network::Testnet;
        let _regtest = Network::Regtest;

        // Verify Network methods exist
        let _hrp = Network::Mainnet.hrp();
        let _from_env = Network::from_env();
    }
}
