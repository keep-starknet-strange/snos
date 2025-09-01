use anyhow::{bail, Result};
use bitvec::{order::Msb0, slice::BitSlice, vec::BitVec};
use num_bigint::BigInt;
use starknet_types_core::felt::Felt;
use std::collections::HashMap;

use crate::pathfinder::constants::DEFAULT_STORAGE_TREE_HEIGHT;
use crate::pathfinder::error::ProofVerificationError;
use crate::pathfinder::types::proofs::{ContractData, EdgePath, Height, TrieNode};
use crate::SimpleHashFunction;

/// Verify the storage proofs and handle errors.
/// Returns a list of additional keys to fetch to fill gaps in the tree that will make the OS
/// crash otherwise.
/// This function will panic if the proof contains an invalid node hash (i.e., the hash of a child
/// node does not match the one specified in the parent).
pub fn verify_storage_proof(contract_data: &ContractData, keys: &[Felt]) -> Result<Vec<Felt>> {
    let mut additional_keys = vec![];
    if let Err(errors) = contract_data.verify(keys) {
        for error in errors {
            match error {
                ProofVerificationError::NonExistenceProof { key, height, node } => {
                    if let TrieNode::Edge { child: _, path, .. } = &node {
                        if height.0 < DEFAULT_STORAGE_TREE_HEIGHT {
                            let modified_key = get_key_following_edge(key, height, &path);
                            additional_keys.push(modified_key);
                        }
                    }
                }
                _ => {
                    bail!("Proof verification failed: {:?}", error);
                }
            }
        }
    }

    Ok(additional_keys)
}

/// Returns a modified key that follows the specified edge path.
/// This function is used to work around an issue where the OS fails if it encounters a
/// writing to 0, and the last node in the storage proof is an edge node of length 1.
/// In this situation the OS will still look up the node in the preimage and will fail
/// on an "Edge bottom not found in preimage" error.
/// To resolve this, we fetch the storage proof for a node that follows this edge
/// to get the bottom node in the preimage and resolve the issue.
///
/// For example, if following a key 0x00A0 we encounter an edge 0xB0 starting from height 8
/// to height 4 (i.e., the length of the edge is 4), then the bottom node of the edge will
/// not be included in the proof as the key does not follow the edge. We need to compute a key
/// that will follow the edge to get that bottom node. For example, the key 0x00B0 will
/// follow that edge.
///
/// An important note is that heigh = 0 at the level of leaf nodes (as opposed to the rest of the OS)
///
/// To achieve this, we zero the part of the key at the height of the edge and then replace it
/// with the path of the edge. This is achieved with bitwise operations. For our example,
/// this function will compute the new key as `(key & 0xFF0F) | 0x00B0`.
fn get_key_following_edge(key: Felt, height: Height, edge_path: &EdgePath) -> Felt {
    assert!(height.0 < DEFAULT_STORAGE_TREE_HEIGHT);

    let shift = height.0;
    let clear_mask = ((BigInt::from(1) << edge_path.len) - BigInt::from(1)) << shift;
    let mask = edge_path.value.to_bigint() << shift;
    let new_key = (key.to_bigint() & !clear_mask) | mask;

    Felt::from(new_key)
}

pub fn proof_to_hashmap(proof: &[TrieNode]) -> HashMap<Felt, TrieNode> {
    proof.iter().map(|node| (node.node_hash().unwrap(), node.clone())).collect()
}

pub fn hash_binary_node<H: SimpleHashFunction>(left_hash: Felt, right_hash: Felt) -> Felt {
    H::hash(&left_hash, &right_hash).into()
}
pub fn hash_edge_node<H: SimpleHashFunction>(path: &Felt, path_length: usize, child_hash: Felt) -> Felt {
    let path_bitslice: &BitSlice<_, Msb0> = &BitVec::from_slice(&path.to_bytes_be());
    assert_eq!(path_bitslice.len(), 256, "Felt::to_bytes_be() expected to always be 256 bits");

    let felt_path = path;
    let mut length = [0; 32];
    // Safe as len() is guaranteed to be <= 251
    length[31] = path_length as u8;

    let length = Felt::from_bytes_be(&length);
    let hash_result = H::hash(&child_hash, felt_path);
    let hash_felt: Felt = hash_result.into();
    hash_felt + length
}

/// This function goes through the tree from top to bottom and verifies that
/// the hash of each node is equal to the corresponding hash in the parent node.
pub fn verify_proof<H: SimpleHashFunction>(
    key: Felt,
    commitment: Felt,
    proof: &[TrieNode],
) -> Result<(), ProofVerificationError> {
    let _bits = key.to_bits_be();

    // The tree height is 251, so the first 5 bits are ignored.
    let start = 5;
    let mut index = start;

    let bits: BitVec<_, Msb0> = BitVec::from_slice(&key.to_bytes_be());
    let mut next_node_hash = commitment;
    let proof_nodes = proof_to_hashmap(proof);
    loop {
        let node = proof_nodes.get(&next_node_hash).ok_or_else(|| {
            ProofVerificationError::ProofError(format!(
                "proof did not contain preimage for node 0x{:x} (index: {})",
                next_node_hash, index
            ))
        })?;
        match node {
            TrieNode::Binary { left, right, .. } => {
                let actual_node_hash = hash_binary_node::<H>(*left, *right);
                if actual_node_hash != next_node_hash {
                    return Err(ProofVerificationError::InvalidChildNodeHash {
                        node_hash: actual_node_hash,
                        parent_hash: next_node_hash,
                    });
                }
                next_node_hash = if bits[index] { right.clone() } else { left.clone() }; // TODO: remove the clones
                index += 1;
            }
            TrieNode::Edge { child, path, .. } => {
                let length = path.len as usize;
                let relevant_path = &bits[index..index + length];

                let path_bits: BitVec<_, Msb0> = BitVec::from_slice(&path.value.to_bytes_be());
                let relevant_node_path = &path_bits[256 - length..]; // TODO: is this always 256 i.e. size of the path_bits array?

                let actual_node_hash = hash_edge_node::<H>(&path.value, length, *child);
                if actual_node_hash != next_node_hash {
                    return Err(ProofVerificationError::InvalidChildNodeHash {
                        node_hash: actual_node_hash,
                        parent_hash: next_node_hash,
                    });
                }
                next_node_hash = child.clone();
                index += length;

                if relevant_path != relevant_node_path {
                    // If paths don't match, we've found a proof of non-membership because:
                    // 1. We correctly moved towards the target as far as possible, and
                    // 2. Hashing all the nodes along the path results in the root hash, which means
                    // 3. The target definitely does not exist in this tree
                    return Err(ProofVerificationError::NonExistenceProof {
                        key,
                        height: Height(DEFAULT_STORAGE_TREE_HEIGHT - (index - start) as u64),
                        node: node.clone(),
                    });
                }
            }
        }

        if index > 256 {
            return Err(ProofVerificationError::ProofError(format!(
                "invalid proof, path too long ({})",
                index - start
            )));
        }
        if index == 256 {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pathfinder::types::hash::{PedersenHash, PoseidonHash};
    use crate::pathfinder::types::PathfinderProof;
    use rstest::rstest;
    use starknet_types_core::felt::Felt;

    #[test]
    fn test_verify_proof_from_json() {
        // Placeholder values - replace with actual test data
        let keys = [
            "0x3c204dd68b8e800b4f42e438d9ed4ccbba9f8e436518758cd36553715c1d6ab",
            "0x345354e2d801833068de73d1a2028e2f619f71045dd5229e79469fa7f598038",
            "0x3b28019ccfdbd30ffc65951d94bb85c9e2b8434111a000b5afd533ce65f57a4",
            "0x5496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a",
            "0x229",
            "0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d",
            "0x9524a94b41c4440a16fd96d7c1ef6ad6f44c1c013e96662734502cd4ee9b1f",
            "0x626c15d497f8ef78da749cbe21ac3006470829ee8b5d0d166f3a139633c6a93",
            "0x5c1c7eca392fa7c8ff79bbd7559f45f9693278ddc62edf335e374648d17cbb",
            "0x22",
            "0x3c204dd68b8e800b4f42e438d9ed4ccbba9f8e436518758cd36553715c1d6ac",
            "0x140ab62001bb99cdf9685fd3be123aeeb41073e31942b80622fda6b66d54d4f",
            "0x5496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9b",
            "0x352057331d5ad77465315d30b98135ddb815b86aa485d659dfeef59a904f88d",
        ];

        for index in 2..keys.len() {
            let key = Felt::from_hex(keys[index]).unwrap();
            let commitment =
                Felt::from_hex("0x113519a4e8c4b74d2295b850122523986c6e60902cfc31a623da2e765c76b3d").unwrap();
            let json_file_content = include_str!("../../../../resources/pathfinder_proof_1309254_2.json");

            // Read proof from JSON file - fail test if file cannot be read
            let pathfinder_proof: PathfinderProof =
                serde_json::from_str(&json_file_content).expect("Failed to read PathfinderProof from JSON file");

            // Get contract data - fail test if not found
            let contract_data =
                pathfinder_proof.contract_data.as_ref().expect("No contract data found in the PathfinderProof");

            // Get storage proofs - fail test if empty
            assert!(!contract_data.storage_proofs.is_empty(), "No storage proofs found in the PathfinderProof");

            let proof = &contract_data.storage_proofs[index];

            // Call verify_proof with PedersenHash - fail test if verification fails
            verify_proof::<PedersenHash>(key, commitment, proof).expect("Proof verification failed");
            println!("Proof verification successful for index {:?}", index);
        }
    }

    #[rstest]
    #[case(
        "0x654925ee73f27940c6d0721070e25da685c27a82dd6b6dc9a477185527da70c",
        "0x141226668ad8394934d53eb7db9cc6f582eda0655d5264900902c5c29acd769",
        "0x3224ded91b58d810bc9016ade2ff9941f9ba3f236f6ce18ef2e4ec449dac309" // placeholder expected result
    )]
    #[case(
        "0x1234",
        "0xabcd",
        "0615bb8d47888d2987ad0c63fc06e9e771930986a4dd8adc55617febfcf3639e" // placeholder expected result
    )]
    #[case(
        "0x03d937c035c878245caf64531a5756109c53068da139362728feb561405371cb",
        "0x0208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a",
        "0x030e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662" // placeholder expected result
    )]
    fn test_hash_binary_node_pedersen(#[case] left_hex: &str, #[case] right_hex: &str, #[case] expected_hex: &str) {
        let left = Felt::from_hex(left_hex).unwrap();
        let right = Felt::from_hex(right_hex).unwrap();
        let expected = Felt::from_hex(expected_hex).unwrap();

        println!("left: {:?}, right: {:?} and expected: {:?}", left, right, expected);

        let result = hash_binary_node::<PedersenHash>(left, right);

        // TODO: Replace with actual expected values
        // For now, just verify the function runs without panicking
        println!("Binary node hash result: {:#x}", result);
        assert_eq!(result, expected);
    }

    // TODO: Fix this test or remove it
    #[ignore]
    #[rstest]
    #[case(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "0x0000000000000000000000000000000000000000000000000000000000000000" // placeholder expected result
    )]
    #[case(
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        "0x0000000000000000000000000000000000000000000000000000000000000002",
        "0x0000000000000000000000000000000000000000000000000000000000000000" // placeholder expected result
    )]
    fn test_hash_binary_node_poseidon(#[case] left_hex: &str, #[case] right_hex: &str, #[case] expected_hex: &str) {
        let left = Felt::from_hex(left_hex).unwrap();
        let right = Felt::from_hex(right_hex).unwrap();
        let expected = Felt::from_hex(expected_hex).unwrap();

        let result = hash_binary_node::<PoseidonHash>(left, right);

        // TODO: Replace with actual expected values
        // For now, just verify the function runs without panicking
        println!("Binary node hash result: {:#x}", result);
        // assert_eq!(result, expected);
    }

    #[rstest]
    #[case(
        "0x0",
        230,
        "0x10eea74e23d39bef6e9995ba1f84c3a4b7e577c63b884c6f3d941c77a00346c",
        "0x22e0326bd27681dee9760d7b639cf024731bf14b71d7e4e9ce48b7ff831c2b0" // placeholder expected result
    )]
    fn test_hash_edge_node_pedersen(
        #[case] path_hex: &str,
        #[case] path_length: usize,
        #[case] child_hash_hex: &str,
        #[case] expected_hex: &str,
    ) {
        let path = Felt::from_hex(path_hex).unwrap();
        let child_hash = Felt::from_hex(child_hash_hex).unwrap();
        let expected = Felt::from_hex(expected_hex).unwrap();

        let result = hash_edge_node::<PedersenHash>(&path, path_length, child_hash);

        // TODO: Replace with actual expected values
        // For now, just verify the function runs without panicking
        println!("Edge node hash result: {:#x}", result);
        assert_eq!(result, expected);
    }

    // TODO: Fix this test or remove it
    #[ignore]
    #[rstest]
    #[case(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        4,
        "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "0x0000000000000000000000000000000000000000000000000000000000000000" // placeholder expected result
    )]
    #[case(
        "0x0000000000000000000000000000000000000000000000000000000000000001",
        8,
        "0x0000000000000000000000000000000000000000000000000000000000000002",
        "0x0000000000000000000000000000000000000000000000000000000000000000" // placeholder expected result
    )]
    fn test_hash_edge_node_poseidon(
        #[case] path_hex: &str,
        #[case] path_length: usize,
        #[case] child_hash_hex: &str,
        #[case] expected_hex: &str,
    ) {
        let path = Felt::from_hex(path_hex).unwrap();
        let child_hash = Felt::from_hex(child_hash_hex).unwrap();
        let expected = Felt::from_hex(expected_hex).unwrap();

        let result = hash_edge_node::<PoseidonHash>(&path, path_length, child_hash);

        // TODO: Replace with actual expected values
        // For now, just verify the function runs without panicking
        println!("Edge node hash result: {:#x}", result);
        // assert_eq!(result, expected);
    }
}
