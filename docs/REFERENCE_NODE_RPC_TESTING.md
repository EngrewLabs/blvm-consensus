# blvm-node RPC Integration for Testing Consensus

This document explains how to use blvm-node's RPC infrastructure to test blvm-consensus validation.

## Overview

blvm-node provides a complete Bitcoin node implementation with JSON-RPC 2.0 API that uses blvm-consensus for all consensus decisions. This allows testing consensus validation through RPC calls instead of direct function calls.

## Architecture

```
┌─────────────────┐
│  Test Suite     │
│  (blvm-         │
│   consensus)    │
└────────┬────────┘
         │ RPC Calls
         ▼
┌─────────────────┐
│  blvm-node      │
│  (RPC Server)   │
└────────┬────────┘
         │ Uses
         ▼
┌─────────────────┐
│ blvm-consensus  │
│  (Validation)   │
└─────────────────┘
```

## Starting blvm-node for Testing

### Method 1: In-Process Test Node

For unit tests, start a test node in the same process:

```rust
use blvm_node::{Node, NodeConfig};
use blvm_protocol::ProtocolVersion;

#[tokio::test]
async fn test_consensus_validation_via_rpc() {
    // Start blvm-node in regtest mode (safe for testing)
    let mut config = NodeConfig::default();
    config.network = ProtocolVersion::Regtest;
    let node = Node::new(config)?;
    
    // Start RPC server on random port
    let rpc_manager = node.rpc_manager();
    let rpc_addr = "127.0.0.1:0".parse()?;
    rpc_manager.start(rpc_addr).await?;
    
    // Get actual RPC address
    let actual_addr = rpc_manager.server_addr();
    
    // Now you can make RPC calls to test blvm-consensus
    // ...
}
```

### Method 2: Standalone Test Node

For integration tests, start a standalone node:

```bash
# Start blvm-node in regtest mode
cd blvm-node
cargo run -- --network regtest --rpc-bind=127.0.0.1:18332
```

Then connect to it from tests using the RPC client of your choice (e.g. `jsonrpc` crate).

## RPC Methods for Testing Consensus

### Transaction Validation

Use `testmempoolaccept` to test transaction validation. See [RPC Reference](https://github.com/BTCDecoded/blvm-node/blob/main/docs/RPC_REFERENCE.md) for method details.

### Block Validation

Use `submitblock` to test block validation.

### Blockchain Queries

Use blockchain RPC methods (`getblock`, `getblockchaininfo`, `gettxoutsetinfo`) to query validated state.

## Testing Workflow

### 1. Start blvm-node

```bash
cd blvm-node
cargo run -- --network regtest --rpc-bind=127.0.0.1:18332
```

### 2. Run Consensus Tests

```bash
cd blvm-consensus
cargo test
```

### 3. Verify Results

Tests will validate transactions and blocks via direct blvm-consensus API. For integration testing via RPC, use blvm-node's RPC server and compare results with direct validation.

## Benefits of RPC Testing

1. **Integration Testing**: Tests the full stack from RPC → node → blvm-consensus
2. **Real-World Scenarios**: Tests how blvm-consensus behaves in a real node context
3. **Protocol Validation**: Ensures RPC methods correctly use blvm-consensus
4. **Network Testing**: Can test across multiple nodes (future enhancement)

## Future Enhancements

1. **Multi-Node Testing**: Test consensus across multiple blvm-nodes
2. **Network Scenarios**: Test block/transaction propagation
3. **Performance Testing**: Benchmark consensus validation via RPC
4. **Differential Testing**: Compare blvm-node RPC results with Core RPC

## See Also

- [blvm-node RPC Reference](https://github.com/BTCDecoded/blvm-node/blob/main/docs/RPC_REFERENCE.md)

