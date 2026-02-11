# ECDSA Batch Sighash Debug Findings

Block 164676: batch reported "31 ECDSA signatures, 4 invalid" but in-place verification passed.
**RESOLVED** (see Resolution section below).

## Root Cause

When the ECDSA collector is enabled, `verify_signature` collects `(sig, msg, pubkey)` and returns `Ok(true)` **without** verifying. For interpreter CHECKMULTISIG (inputs 20, 21, 23 in block 164676), the collected triples can be invalid: wrong `(sig, pubkey)` pairing from iterating pubkeys/sigs without per-pair verification. Batch verification of those triples fails (4 invalid at idx 1310720, 1376256, 1507328, 1507329). In-place verification succeeds because each `(sig, msg, pubkey)` is actually checked before being accepted.

## Resolution

**Do not collect from interpreter path.** Only fast paths (P2PKH, P2WPKH, P2WSH) collect; interpreter (bare multisig, P2WSH-in-P2SH, etc.) verifies in-place only.

Implementation in `script.rs`:
1. Pass `None` for `ecdsa_collector` and `ecdsa_global_index` when executing scriptPubkey (interpreter path).
2. Pass `None` for witness script execution (P2WSH, P2WSH-in-P2SH).
3. Thread-local `ECDSA_INTERPRETER_NO_COLLECT` guard: when set, `verify_signature` skips collection even if a collector is threaded through. RAII `EcdsaNoCollectGuard` sets this for duration of interpreter script execution.

Result: Batch collects ~24 sigs (P2PKH only for block 164676); 4 multisig inputs verify in-place. Block validates without retry.

## Debug Setup (historical)

1. **Collect run** (batch fails): `BLVM_DEBUG_SIGHASH=1 cargo test --test block_164676_ibd_repro --features production -- --ignored`
   - Writes `target/blvm_sighash_collect.txt` with `idx\tsighash_hex` for each collected triple.

2. **Verify run** (in-place, passes): `BLVM_DEBUG_SIGHASH=1 BLVM_DEBUG_SIGHASH_NO_COLLECTOR=1 cargo test --test block_164676_ibd_repro --features production -- --ignored`
   - Writes `target/blvm_sighash_verify.txt` with `seq\tsighash_hex` in processing order.

3. **Compare** (after both runs):
   ```bash
   sort -n target/blvm_sighash_collect.txt > target/blvm_sighash_collect_sorted.txt
   paste target/blvm_sighash_collect_sorted.txt target/blvm_sighash_verify.txt | \
     awk '{if($2!=$4) print "DIFF idx=" $1 " collect=" $2 " verify=" $4}'
   ```

## Findings (historical)

- **Collect**: 31 entries. **Verify**: 35 entries. Extra verifications when running without collector (different code paths).
- **Mismatches**: Interpreter CHECKMULTISIG produced invalid (sig, pubkey) pairings for batch; sighashes matched, but pairing was wrong.
