use alexandria_data_structures::array_ext::ArrayTraitExt;
use alexandria_math::{keccak256::keccak256, BitShift};
use keccak::cairo_keccak;

/// Converts a `u256` value to a big-endian byte array, removing leading zeroes.
///
/// # Parameters
///
/// - `a`: The `u256` value to convert.
///
/// # Returns
///
/// - A `Array<u8>` containing the big-endian representation of `a`.
///
/// # Panics
///
/// - Panics if any `u256` to `u8` conversion fails.
fn u256_to_be_bytes(a: u256) -> Array<u8> {
    let mut bytes: Array<u8> = array![];
    let mut i = 0;

    while i < 32 {
        let mut byte: u8 = (BitShift::shr(a, 8 * i) & 0xFF).try_into().expect('u256_to_be_bytes');
        bytes.append(byte);
        i += 1;
    };
    bytes = bytes.reversed();

    let mut significant_bytes: Array<u8> = array![];
    while bytes
        .len() > 0 {
            let byte = bytes.pop_front().expect('u256_to_be_bytes');

            if byte != 0 {
                significant_bytes.append(byte);
            };
        };
    significant_bytes
}

/// Hashes a `u256` value using the Keccak-256 hash function.
///
/// # Parameters
///
/// - `a`: The `u256` value to hash.
///
/// # Returns
///
/// - A `u256` hash of the input value.
pub fn hash(a: u256) -> u256 {
    keccak256(u256_to_be_bytes(a).span())
}

/// Hashes two `u256` values together using Keccak-256, ensuring a stable ordering.
///
/// # Parameters
///
/// - `a`: The first `u256` value.
/// - `b`: The second `u256` value.
///
/// # Returns
///
/// - A `u256` hash of the combined values.
pub fn hash_2(a: u256, b: u256) -> u256 {
    let a_array = if a < b {
        u256_to_be_bytes(a)
    } else {
        u256_to_be_bytes(b)
    };
    let b_array = if a < b {
        u256_to_be_bytes(b)
    } else {
        u256_to_be_bytes(a)
    };
    let mut combined = array![];
    let mut i = 0;
    while i < a_array.len() {
        combined.append(*a_array.at(i));
        i += 1;
    };
    i = 0;
    while i < b_array.len() {
        combined.append(*b_array.at(i));
        i += 1;
    };
    keccak256(combined.span())
}

/// Verifies a Merkle proof against a given root and leaf.
///
/// # Parameters
///
/// - `proof`: The proof path as a `Span<u256>`.
/// - `root`: The expected root of the Merkle tree.
/// - `leaf`: The leaf value to verify.
///
/// # Returns
///
/// - `true` if the proof is valid, `false` otherwise.
pub fn verify(proof: Span<u256>, root: u256, leaf: u256) -> bool {
    process_proof(proof, leaf) == root
}

/// Computes the root hash of a Merkle proof.
///
/// # Parameters
///
/// - `proof`: The proof path as a `Span<u256>`.
/// - `leaf`: The leaf value to start the proof computation from.
///
/// # Returns
///
/// - The computed root hash as a `u256`.
pub fn process_proof(proof: Span<u256>, leaf: u256) -> u256 {
    let mut computed_hash = leaf;
    let length = proof.len();
    let mut i = 0;

    while i < length {
        computed_hash = hash_2(computed_hash, *proof.at(i));
        i += 1;
    };
    computed_hash
}

#[cfg(test)]
mod tests {
    use super::{verify, proof, hash_2, hash};

    #[test]
    fn test_hash() {
        let a: u256 = 0x1234;
        let result_a = hash(a);

        let expected_a: u256 =
            39052716502752786868548403558894884608560677189476763460279165921508075402290;
        assert_eq!(result_a, expected_a);

        let b = 106298406765026699961965487713881752097005704017518589984779077308930345656963;
        let result_b = hash(b);

        let expected_b: u256 =
            57250559430431367564505184977397952879238522551013113966764067536667591198680;
        assert_eq!(result_b, expected_b);
    }

    #[test]
    fn test_hash2() {
        let a: u256 = 0x1234;
        let b: u256 = 0x5678;
        let result = hash_2(a, b);

        let expected: u256 =
            22068622680911700764321525266852476815069367068878736168591169089364878371621;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hash2_2() {
        let a: u256 =
            106298406765026699961965487713881752097005704017518589984779077308930345656963;
        let b: u256 =
            103573204444722904296303344141652659848139686841694864445404268162081373140940;
        let result = hash_2(a, b);

        let expected: u256 =
            92456884960513311381953403436580976231217910496200856984999963940562156746935;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_verify_proof() {
        let (leaf, root, proof) = proof();
        let result = verify(proof, root, leaf);

        assert_eq!(result, true);
    }

    #[test]
    fn test_verify_proof_mock_proof() {
        let id_1 = hash(1);
        let id_2 = hash(2);
        let root: u256 = if id_1 < id_2 {
            hash_2(id_1, id_2)
        } else {
            hash_2(id_2, id_1)
        };
        let leaf: u256 = id_1;
        let proof = array![id_2].span();
        let result = verify(proof, root, leaf);

        assert_eq!(result, true);
    }
}

pub fn proof() -> (u256, u256, Span<u256>) {
    let leaf: u256 = 0xeb02c421cfa48976e66dfb29120745909ea3a0f843456c263cf8f1253483e283;
    let root: u256 = 0x2d44082a8e407727c2cc1f17dacfff5d8242610b03e103fed2c18729692a09b9;
    let proof: Span<u256> = array![
        0xe4fc5b35ba4bd627dffb795fa4c398e7896386584837a8a23f7f3c9ab869b7cc,
        0xcc73ab41c84b6f3730ee4f5685205e72de987062c17581b1b4b771b9eab2d7f1,
        0x05374ac461e238a744dd7e328423f7721959d2e4eeec8aeb775ebb58e60d5407,
        0xbf7c4aef9eaad8cec3e6691084f849a4a8c4bdfd93979a9ebf494e98d91e3903
    ]
        .span();
    (leaf, root, proof)
}
