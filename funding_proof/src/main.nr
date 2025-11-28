/// Funding Proof Circuit
///
/// Proves that a user has sufficient balance to cover a transaction
/// without revealing the actual balance.
///
/// Public inputs:
/// - commitment_hash: Hash of the Pedersen commitment to balance
/// - minimum_required: Minimum balance required
/// - asset_id: Asset identifier
///
/// Private inputs (witness):
/// - balance: Actual user balance
/// - blinding: Blinding factor for commitment
///
/// Constraints:
/// 1. balance >= minimum_required
/// 2. commitment = pedersen([balance, blinding])
/// 3. commitment_hash = hash(commitment, asset_id)

use std::hash::pedersen_hash;
use std::hash::blake3;

/// Main entry point for the funding proof circuit
fn main(
    // Public inputs
    commitment_hash: pub [u8; 32],
    minimum_required: pub u64,
    asset_id: pub Field,

    // Private inputs (witness)
    balance: u64,
    blinding: Field,
) {
    // Constraint 1: Balance must be at least the minimum required
    assert(balance >= minimum_required, "Insufficient balance");

    // Constraint 2: Compute the Pedersen commitment to (balance, blinding)
    let balance_field = balance as Field;
    let commitment = pedersen_hash([balance_field, blinding]);

    // Constraint 3: Verify the commitment hash matches
    // We hash: commitment || asset_id to bind the commitment to the asset
    let computed_hash = compute_commitment_hash(commitment, asset_id);

    // Verify the hashes match byte by byte
    for i in 0..32 {
        assert(computed_hash[i] == commitment_hash[i], "Commitment hash mismatch");
    }
}

/// Compute the commitment hash from commitment and asset_id
/// Uses BLAKE3 for efficiency (built-in to Noir)
fn compute_commitment_hash(commitment: Field, asset_id: Field) -> [u8; 32] {
    // Convert commitment to bytes (32 bytes, big-endian)
    let commitment_bytes: [u8; 32] = commitment.to_be_bytes();

    // Convert asset_id to bytes (32 bytes, big-endian)
    let asset_bytes: [u8; 32] = asset_id.to_be_bytes();

    // Create preimage: commitment || asset_id (64 bytes)
    let mut preimage: [u8; 64] = [0; 64];
    for i in 0..32 {
        preimage[i] = commitment_bytes[i];
        preimage[i + 32] = asset_bytes[i];
    }

    // Hash with BLAKE3
    blake3(preimage)
}

// --- Tests ---

#[test]
fn test_valid_funding_proof() {
    // Test case: balance = 100, minimum = 50
    let balance: u64 = 100;
    let minimum_required: u64 = 50;
    let blinding = 12345 as Field;
    let asset_id = 1 as Field;

    // Compute expected commitment hash
    let balance_field = balance as Field;
    let commitment = pedersen_hash([balance_field, blinding]);
    let commitment_hash = compute_commitment_hash(commitment, asset_id);

    // This should pass
    main(commitment_hash, minimum_required, asset_id, balance, blinding);
}

#[test]
fn test_exact_balance_passes() {
    // Test case: balance exactly equals minimum
    let balance: u64 = 50;
    let minimum_required: u64 = 50;
    let blinding = 67890 as Field;
    let asset_id = 2 as Field;

    let balance_field = balance as Field;
    let commitment = pedersen_hash([balance_field, blinding]);
    let commitment_hash = compute_commitment_hash(commitment, asset_id);

    main(commitment_hash, minimum_required, asset_id, balance, blinding);
}

#[test(should_fail_with = "Insufficient balance")]
fn test_insufficient_balance_fails() {
    // Test case: balance < minimum should fail
    let balance: u64 = 40;
    let minimum_required: u64 = 50;
    let blinding = 11111 as Field;
    let asset_id = 1 as Field;

    let balance_field = balance as Field;
    let commitment = pedersen_hash([balance_field, blinding]);
    let commitment_hash = compute_commitment_hash(commitment, asset_id);

    main(commitment_hash, minimum_required, asset_id, balance, blinding);
}

#[test(should_fail_with = "Commitment hash mismatch")]
fn test_wrong_commitment_fails() {
    // Test case: wrong commitment hash should fail
    let balance: u64 = 100;
    let minimum_required: u64 = 50;
    let blinding = 12345 as Field;
    let asset_id = 1 as Field;

    // Use a completely wrong commitment hash
    let wrong_hash: [u8; 32] = [0; 32];

    main(wrong_hash, minimum_required, asset_id, balance, blinding);
}

#[test(should_fail_with = "Commitment hash mismatch")]
fn test_wrong_blinding_fails() {
    // Test case: correct balance but wrong blinding should fail
    let balance: u64 = 100;
    let minimum_required: u64 = 50;
    let correct_blinding = 12345 as Field;
    let wrong_blinding = 99999 as Field;
    let asset_id = 1 as Field;

    // Compute hash with correct blinding
    let balance_field = balance as Field;
    let commitment = pedersen_hash([balance_field, correct_blinding]);
    let commitment_hash = compute_commitment_hash(commitment, asset_id);

    // Try to prove with wrong blinding
    main(commitment_hash, minimum_required, asset_id, balance, wrong_blinding);
}
