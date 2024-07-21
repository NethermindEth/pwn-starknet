use alexandria_data_structures::array_ext::ArrayTraitExt;
use alexandria_math::{keccak256::keccak256, BitShift};
use keccak::cairo_keccak;


fn u256_to_be_bytes(a: u256) -> Array<u8> {
    let mut bytes: Array<u8> = array![];
    let mut i = 0;

    while i < 32 {
        let mut byte: u8 = (BitShift::shr(a, 8 * i) & 0xFF).try_into().unwrap();
        bytes.append(byte);
        i += 1;
    };
    bytes.reversed()
}

pub fn hash(a: u256) -> u256 {
    keccak256(u256_to_be_bytes(a).span())
}

fn hash_2(a: u256, b: u256) -> u256 {
    let a_array = u256_to_be_bytes(a);
    let b_array = u256_to_be_bytes(b);
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


pub fn verify(proof: Span<u256>, root: u256, leaf: u256) -> bool {
    process_proof(proof, leaf) == root
}

fn process_proof(proof: Span<u256>, leaf: u256) -> u256 {
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
    use super::hash_2;

    #[test]
    fn test_keccak() {
        let a: u256 = 1;
        let b: u256 = 2;

        let result = hash_2(a, b);
        println!("result: {:?}", result);
    }
}
