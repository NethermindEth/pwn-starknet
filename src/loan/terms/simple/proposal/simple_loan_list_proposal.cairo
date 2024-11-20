use SimpleLoanListProposal::{Proposal, ProposalValues};
use pwn::loan::lib::signature_checker::Signature;
use pwn::loan::terms::simple::loan::types::Terms;

#[starknet::interface]
pub trait ISimpleLoanListProposal<TState> {
    fn make_proposal(ref self: TState, proposal: Proposal);
    fn accept_proposal(
        ref self: TState,
        acceptor: starknet::ContractAddress,
        refinancing_loan_id: felt252,
        proposal_data: Array<felt252>,
        proposal_inclusion_proof: Array<u256>,
        signature: Signature
    ) -> (felt252, Terms);
    fn get_proposal_hash(self: @TState, proposal: Proposal) -> felt252;
    fn encode_proposal_data(
        self: @TState, proposal: Proposal, proposal_values: ProposalValues
    ) -> Array<felt252>;
    fn decode_proposal_data(
        self: @TState, encoded_data: Array<felt252>
    ) -> (Proposal, ProposalValues);
    fn PROPOSAL_TYPEHASH(self: @TState) -> felt252;
}

//! The `SimpleLoanListProposal` module provides a mechanism for creating and accepting loan 
//! proposals that utilize a whitelist of collateral IDs . This 
//! module integrates multiple components to offer a comprehensive solution for handling loan 
//! proposals, including encoding and decoding proposal data, computing proposal hashes, and 
//! managing credit calculations.
//! 
//! # Features
//! 
//! - **Proposal Creation**: Allows the creation of loan proposals with specific terms and 
//!   conditions, validated against a whitelist of collateral IDs using Merkle proofs.
//! - **Proposal Acceptance**: Facilitates the acceptance of loan proposals, including the 
//!   verification of signatures, proposal data, and whitelist inclusion.
//! - **Proposal Hashing**: Computes unique hashes for proposals to ensure data integrity and 
//!   security.
//! - **Proposal Encoding/Decoding**: Provides functionality to encode and decode proposal data 
//!   for efficient storage and retrieval.
//! 
//! # Components
//! 
//! - `SimpleLoanProposalComponent`: A reusable component that provides the base functionality 
//!   for loan proposals.
//! - `Err`: Contains error handling functions for various invalid operations and input data.
//! 
//! # Constants
//! 
//! - `PROPOSAL_TYPEHASH`: The type hash for proposals.
//! 
//! This module is designed to provide a robust and flexible framework for managing loan proposals 
//! involving a whitelist of collateral IDs, integrating seamlessly with other components of the 
//! .

#[starknet::contract]
pub mod SimpleLoanListProposal {
    use core::array::SpanTrait;
    use core::poseidon::poseidon_hash_span;
    use pwn::ContractAddressDefault;
    use pwn::loan::lib::{serialization, merkle_proof};
    use pwn::loan::terms::simple::proposal::simple_loan_proposal::{
        SimpleLoanProposalComponent, SimpleLoanProposalComponent::ProposalBase
    };
    use pwn::multitoken::library::MultiToken;
    use starknet::ContractAddress;
    use super::{Signature, Terms};

    component!(
        path: SimpleLoanProposalComponent, storage: simple_loan, event: SimpleLoanProposalEvent
    );

    #[abi(embed_v0)]
    impl SimpleLoanProposalImpl =
        SimpleLoanProposalComponent::SimpleLoanProposalImpl<ContractState>;
    impl SimpleLoanProposalInternal = SimpleLoanProposalComponent::InternalImpl<ContractState>;

    // NOTE: we can hard code this by calculating the poseidon hash of the string 
    // in the Solidity contract offline.
    pub const PROPOSAL_TYPEHASH: felt252 =
        0x03bf4de294949c186bbc5f2122c5a2c96baf0ea86d6d3b740cddf83e4f890351;

    /// Represents a loan proposal with specific terms and conditions.
    #[derive(Copy, Default, Drop, Serde)]
    pub struct Proposal {
        /// Category of the collateral asset.
        pub collateral_category: MultiToken::Category,
        /// Address of the collateral asset.
        pub collateral_address: ContractAddress,
        /// Merkle root for whitelisted collateral IDs.
        pub collateral_ids_whitelist_merkle_root: u256,
        /// Amount of the collateral asset.
        pub collateral_amount: u256,
        /// Flag indicating if collateral state fingerprint should be checked.
        pub check_collateral_state_fingerprint: bool,
        /// Fingerprint of the collateral state.
        pub collateral_state_fingerprint: felt252,
        /// Address of the credit asset.
        pub credit_address: ContractAddress,
        /// Amount of the credit asset.
        pub credit_amount: u256,
        /// Available credit limit for the proposal.
        pub available_credit_limit: u256,
        /// Fixed interest amount for the loan.
        pub fixed_interest_amount: u256,
        /// Annual percentage rate of the accruing interest.
        pub accruing_interest_APR: u32,
        /// Duration of the loan in seconds.
        pub duration: u64,
        /// Expiration time of the proposal in seconds since the Unix epoch.
        pub expiration: u64,
        /// Address allowed to accept the proposal.
        pub allowed_acceptor: ContractAddress,
        /// Address of the proposer.
        pub proposer: ContractAddress,
        /// Hash of the proposer's specifications.
        pub proposer_spec_hash: felt252,
        /// Flag indicating if the proposal is an offer.
        pub is_offer: bool,
        /// ID of the loan being refinanced, if applicable.
        pub refinancing_loan_id: felt252,
        /// Namespace for the nonce used in the proposal.
        pub nonce_space: felt252,
        /// Nonce used to prevent replay attacks.
        pub nonce: felt252,
        /// Address of the loan contract.
        pub loan_contract: ContractAddress,
    }


    #[derive(Copy, Drop, Serde)]
    pub struct ProposalValues {
        pub collateral_id: felt252,
        pub merkle_inclusion_proof: Span<u256>,
    }

    #[storage]
    struct Storage {
        #[substorage(v0)]
        simple_loan: SimpleLoanProposalComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        ProposalMade: ProposalMade,
        #[flat]
        SimpleLoanProposalEvent: SimpleLoanProposalComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ProposalMade {
        pub proposal_hash: felt252,
        pub proposer: ContractAddress,
        pub proposal: Proposal,
    }

    pub mod Err {
        pub fn COLLATERAL_ID_NOT_WHITELISTED(id: felt252) {
            panic!("Collateral ID {} is not whitelisted", id);
        }
    }


    #[constructor]
    fn constructor(
        ref self: ContractState,
        hub: ContractAddress,
        revoke_nonce: ContractAddress,
        config: ContractAddress,
    ) {
        self.simple_loan._initialize(hub, revoke_nonce, config, 'SimpleLoanListProposal', '1.2');
    }

    #[abi(embed_v0)]
    impl SimpleLoanListProposalImpl of super::ISimpleLoanListProposal<ContractState> {
        /// Makes a loan proposal using the provided proposal details.
        ///
        /// # Arguments
        ///
        /// - `proposal`: The details of the proposal.
        ///
        /// # Actions
        ///
        /// - Computes the hash of the proposal.
        /// - Calls the internal method to make the proposal.
        /// - Emits a `ProposalMade` event.
        fn make_proposal(ref self: ContractState, proposal: Proposal) {
            let proposal_hash = self.get_proposal_hash(proposal);
            self.simple_loan._make_proposal(proposal_hash, proposal.proposer);

            self.emit(ProposalMade { proposal_hash, proposer: proposal.proposer, proposal, });
        }

        /// Accepts a loan proposal, verifies the proposal's validity, and processes the loan terms.
        ///
        /// This function decodes the provided proposal data, verifies the inclusion proof for the collateral ID, and
        /// ensures that the proposal's terms meet the required conditions. If all checks pass, the loan terms are
        /// constructed, and the proposal is accepted.
        ///
        /// # Parameters
        /// - `acceptor`: The address of the account accepting the proposal.
        /// - `refinancing_loan_id`: The ID of the loan being refinanced, if applicable.
        /// - `proposal_data`: An array of felt252 values representing the proposal data.
        /// - `proposal_inclusion_proof`: An array of felt252 values representing the proof of inclusion for the proposal.
        /// - `signature`: The signature of the proposer.
        ///
        /// # Returns
        /// A tuple containing the proposal hash and the constructed loan terms.
        ///
        /// # Errors
        /// This function will return an error if:
        /// - The collateral ID is not whitelisted.
        /// - Any other validity check fails.
        fn accept_proposal(
            ref self: ContractState,
            acceptor: starknet::ContractAddress,
            refinancing_loan_id: felt252,
            proposal_data: Array<felt252>,
            proposal_inclusion_proof: Array<u256>,
            signature: Signature
        ) -> (felt252, super::Terms) {
            let (proposal, proposal_values) = self.decode_proposal_data(proposal_data);

            let mut serialized_proposal = array![];
            proposal.serialize(ref serialized_proposal);
            let proposal_hash = self
                .simple_loan
                ._get_proposal_hash(PROPOSAL_TYPEHASH, serialized_proposal);

            if proposal.collateral_ids_whitelist_merkle_root != 0 {
                if !merkle_proof::verify(
                    proposal_values.merkle_inclusion_proof,
                    proposal.collateral_ids_whitelist_merkle_root,
                    merkle_proof::hash(proposal_values.collateral_id.into()),
                ) {
                    Err::COLLATERAL_ID_NOT_WHITELISTED(proposal_values.collateral_id);
                }
            }

            let proposal_base = ProposalBase {
                collateral_address: proposal.collateral_address,
                collateral_id: proposal_values.collateral_id,
                check_collateral_state_fingerprint: proposal.check_collateral_state_fingerprint,
                collateral_state_fingerprint: proposal.collateral_state_fingerprint,
                credit_amount: proposal.credit_amount,
                available_credit_limit: proposal.available_credit_limit,
                expiration: proposal.expiration,
                allowed_acceptor: proposal.allowed_acceptor,
                proposer: proposal.proposer,
                is_offer: proposal.is_offer,
                refinancing_loan_id: proposal.refinancing_loan_id,
                nonce_space: proposal.nonce_space,
                nonce: proposal.nonce,
                loan_contract: proposal.loan_contract,
            };

            self
                .simple_loan
                ._accept_proposal(
                    acceptor,
                    refinancing_loan_id,
                    proposal_hash,
                    proposal_inclusion_proof,
                    signature,
                    proposal_base
                );

            let loan_terms = Terms {
                lender: if proposal.is_offer {
                    proposal.proposer
                } else {
                    acceptor
                },
                borrower: if proposal.is_offer {
                    acceptor
                } else {
                    proposal.proposer
                },
                duration: proposal.duration,
                collateral: MultiToken::Asset {
                    category: proposal.collateral_category,
                    asset_address: proposal.collateral_address,
                    id: proposal_values.collateral_id,
                    amount: proposal.collateral_amount,
                },
                credit: MultiToken::ERC20(proposal.credit_address, proposal.credit_amount),
                fixed_interest_amount: proposal.fixed_interest_amount,
                accruing_interest_APR: proposal.accruing_interest_APR,
                lender_spec_hash: if proposal.is_offer {
                    proposal.proposer_spec_hash
                } else {
                    0
                },
                borrower_spec_hash: if proposal.is_offer {
                    0
                } else {
                    proposal.proposer_spec_hash
                },
            };

            (proposal_hash, loan_terms)
        }

        /// Computes the hash of a given proposal to ensure data integrity and security.
        ///
        /// This function serializes the proposal and computes its hash using a predefined type hash.
        ///
        /// # Parameters
        /// - `proposal`: The proposal to be hashed.
        ///
        /// # Returns
        /// The hash of the serialized proposal.
        fn get_proposal_hash(self: @ContractState, proposal: Proposal) -> felt252 {
            let mut serialized_proposal = array![];
            proposal.serialize(ref serialized_proposal);
            self.simple_loan._get_proposal_hash(PROPOSAL_TYPEHASH, serialized_proposal)
        }

        /// Encodes proposal data and its values into a compact array format for storage and retrieval.
        ///
        /// This function serializes both the proposal and its associated values, then concatenates
        /// the serialized data into a single array.
        ///
        /// # Parameters
        /// - `proposal`: The proposal to be encoded.
        /// - `proposal_values`: The values associated with the proposal.
        ///
        /// # Returns
        /// An array of felt252 representing the encoded proposal data.
        fn encode_proposal_data(
            self: @ContractState, proposal: Proposal, proposal_values: ProposalValues
        ) -> Array<felt252> {
            let mut serialized_proposal = array![];
            proposal.serialize(ref serialized_proposal);

            let mut serialized_proposal_values = array![];
            proposal_values.serialize(ref serialized_proposal_values);

            serialization::serde_concat(
                serialized_proposal.span(), serialized_proposal_values.span()
            )
        }

        /// Decodes the encoded proposal data back into its original proposal and values.
        ///
        /// This function decomposes the encoded data into separate proposal and proposal values
        /// and deserializes them.
        ///
        /// # Parameters
        /// - `encoded_data`: The encoded proposal data to be decoded.
        ///
        /// # Returns
        /// A tuple containing the deserialized proposal and its associated values.
        fn decode_proposal_data(
            self: @ContractState, encoded_data: Array<felt252>
        ) -> (Proposal, ProposalValues) {
            let (proposal_data, proposal_values_data) = serialization::serde_decompose(
                encoded_data.span()
            );
            let proposal = self.decode_serde_proposal(proposal_data);
            let proposal_values = self.decode_serde_proposal_values(proposal_values_data);

            (proposal, proposal_values)
        }

        fn PROPOSAL_TYPEHASH(self: @ContractState) -> felt252 {
            PROPOSAL_TYPEHASH
        }
    }

    #[generate_trait]
    impl Private of PrivateTrait {
        fn decode_serde_proposal(self: @ContractState, data: Span<felt252>) -> Proposal {
            let collateral_category = match *data.at(0) {
                0 => MultiToken::Category::ERC20,
                1 => MultiToken::Category::ERC721,
                2 => MultiToken::Category::ERC1155,
                _ => panic!("Invalid collateral category"),
            };
            let collateral_address: ContractAddress = (*data.at(1))
                .try_into()
                .expect('decode_serde_proposal');
            let collateral_ids_whitelist_merkle_root_low: u128 = (*data.at(2))
                .try_into()
                .expect('decode_serde_proposal');
            let collateral_ids_whitelist_merkle_root_high: u128 = (*data.at(3))
                .try_into()
                .expect('decode_serde_proposal');
            let collateral_low: u128 = (*data.at(4)).try_into().expect('decode_serde_proposal');
            let collateral_high: u128 = (*data.at(5)).try_into().expect('decode_serde_proposal');
            let credit_address: ContractAddress = (*data.at(8))
                .try_into()
                .expect('decode_serde_proposal');
            let credit_low: u128 = (*data.at(9)).try_into().expect('decode_serde_proposal');
            let credit_high: u128 = (*data.at(10)).try_into().expect('decode_serde_proposal');
            let credit_limit_low: u128 = (*data.at(11)).try_into().expect('decode_serde_proposal');
            let credit_limit_high: u128 = (*data.at(12)).try_into().expect('decode_serde_proposal');
            let fixed_interest_low: u128 = (*data.at(13))
                .try_into()
                .expect('decode_serde_proposal');
            let fixed_interest_high: u128 = (*data.at(14))
                .try_into()
                .expect('decode_serde_proposal');
            let accruing_interest_APR: u32 = (*data.at(15))
                .try_into()
                .expect('decode_serde_proposal');
            let duration: u64 = (*data.at(16)).try_into().expect('decode_serde_proposal');
            let expiration: u64 = (*data.at(17)).try_into().expect('decode_serde_proposal');
            let allowed_acceptor: ContractAddress = (*data.at(18))
                .try_into()
                .expect('decode_serde_proposal');
            let proposer: ContractAddress = (*data.at(19))
                .try_into()
                .expect('decode_serde_proposal');
            let loan_contract: ContractAddress = (*data.at(25))
                .try_into()
                .expect('decode_serde_proposal');

            Proposal {
                collateral_category,
                collateral_address,
                collateral_ids_whitelist_merkle_root: u256 {
                    low: collateral_ids_whitelist_merkle_root_low,
                    high: collateral_ids_whitelist_merkle_root_high
                },
                collateral_amount: u256 { low: collateral_low, high: collateral_high },
                check_collateral_state_fingerprint: if *data.at(6) == 1 {
                    true
                } else {
                    false
                },
                collateral_state_fingerprint: *data.at(7),
                credit_address,
                credit_amount: u256 { low: credit_low, high: credit_high },
                available_credit_limit: u256 { low: credit_limit_low, high: credit_limit_high },
                fixed_interest_amount: u256 { low: fixed_interest_low, high: fixed_interest_high },
                accruing_interest_APR,
                duration,
                expiration,
                allowed_acceptor,
                proposer,
                proposer_spec_hash: *data.at(20),
                is_offer: if *data.at(21) == 1 {
                    true
                } else {
                    false
                },
                refinancing_loan_id: *data.at(22),
                nonce_space: *data.at(23),
                nonce: *data.at(24),
                loan_contract,
            }
        }

        fn decode_serde_proposal_values(
            self: @ContractState, data: Span<felt252>
        ) -> ProposalValues {
            // Extract the length of the merkle_inclusion_proof
            let proof_len: usize = (*data.at(1)).try_into().expect('decode_serde_proposal_values')
                * 2;
            let mut merkle_inclusion_proof: Array<u256> = array![];
            let mut i = 2;
            while i <= proof_len {
                let low: u128 = (*data.at(i)).try_into().expect('decode_serde_proposal_values');
                let high: u128 = (*data.at(i + 1))
                    .try_into()
                    .expect('decode_serde_proposal_values');
                merkle_inclusion_proof.append(u256 { low, high });
                i += 2;
            };

            // Create ProposalValues with the collateral_id being the first element after the proof array
            ProposalValues {
                collateral_id: *data.at(0), merkle_inclusion_proof: merkle_inclusion_proof.span()
            }
        }
    }
}

