use core::ecdsa::check_ecdsa_signature;
use starknet::ContractAddress;

#[derive(Debug, Drop, Serde)]
pub struct Signature {
    pub pub_key: felt252,
    pub r: felt252,
    pub s: felt252,
}

pub mod Err {
    pub fn INVALID_SIGNATURE_LENGTH(length: usize) {
        panic!("Signature length is not 64 nor 65 bytes. Length: {}", length);
    }
    pub fn INVALID_SIGNATURE(signer: super::ContractAddress, digest: felt252) {
        panic!("Invalid signature. Signer: {:?}, Digest: {:?}", signer, digest);
    }
}


pub fn is_valid_signature_now(message_hash: felt252, signature: Signature) -> bool {
    check_ecdsa_signature(message_hash, signature.pub_key, signature.r, signature.s)
}

#[cfg(test)]
mod test {
    #[test]
    fn test_is_valid_signature_now() {
        let message_hash = 0x42CC10CB93838362D6E113BD3721BF1A52A060252CB81B8B6B8C494F849F68D;
        let signature = super::Signature {
            pub_key: 0x5d5e1ef1e369b3fe3ec5e165268f0de8ac6aa54349ca825fc89e7e82cb2be80,
            r: 1400567808990775635010488788643282669204079398376308375841312876336057596950,
            s: 3588666903338222362254716964907600060484744603594755888609529576582459244840,
        };
        assert!(super::is_valid_signature_now(message_hash, signature), "Invalid signature");
    }

    #[test]
    fn test_is_valid_signature_now_2() {
        let message_hash =
            77775287090188619328014239614495353543054808922509279362884421925417793990;
        let signature = super::Signature {
            pub_key: 2639462007251241667946431585306619962532615673294080957111746879575777525376,
            r: 3264420510286432364196974833985411116195048715114965845177347018852683064480,
            s: 3569281343639914879386465359026413667985349164753724831902334211250160649073,
        };
        assert!(super::is_valid_signature_now(message_hash, signature), "Invalid signature");
    }
}
