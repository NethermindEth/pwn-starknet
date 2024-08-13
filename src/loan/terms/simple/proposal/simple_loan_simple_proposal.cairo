use SimpleLoanSimpleProposal::Proposal;
use pwn::loan::lib::signature_checker::Signature;
use pwn::loan::terms::simple::loan::types::Terms;

#[starknet::interface]
pub trait ISimpleLoanSimpleProposal<TState> {
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
    fn encode_proposal_data(self: @TState, proposal: Proposal) -> Array<felt252>;
    fn decode_proposal_data(self: @TState, encoded_data: Array<felt252>) -> Proposal;
}

//! The `SimpleLoanSimpleProposal` module provides a streamlined approach to creating and
//! accepting loan proposals . This module leverages key
//! components and functionality to manage loan proposals efficiently, ensuring data integrity
//! and security throughout the process.
//!
//! # Features
//!
//! - **Proposal Creation**: Enables the creation of loan proposals with specific terms and
//!   conditions.
//! - **Proposal Acceptance**: Supports the acceptance of loan proposals, including validation
//!   of signatures and proposal data.
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
//! This module is designed to provide a robust and efficient framework for managing loan proposals
//! integrating seamlessly with other components and ensuring a secure and reliable process.
#[starknet::contract]
pub mod SimpleLoanSimpleProposal {
    use pwn::ContractAddressDefault;
    use pwn::loan::lib::serialization;
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
        0x51f6ba475e1a1eb81008cc3bdf2084518ae00fd5f333e5738b597a26c75a761;

    #[derive(Copy, Debug, Default, Drop, Serde)]
    pub struct Proposal {
        /// The category of the collateral asset (e.g., ERC20, ERC721, ERC1155).
        pub collateral_category: MultiToken::Category,
        /// The contract address of the collateral asset.
        pub collateral_address: ContractAddress,
        /// The unique identifier of the collateral asset.
        pub collateral_id: felt252,
        /// The amount of collateral being proposed.
        pub collateral_amount: u256,
        /// A flag indicating whether to check the state fingerprint of the collateral.
        pub check_collateral_state_fingerprint: bool,
        /// The state fingerprint of the collateral, if applicable.
        pub collateral_state_fingerprint: felt252,
        /// The contract address of the credit asset.
        pub credit_address: ContractAddress,
        /// The amount of credit being offered or requested.
        pub credit_amount: u256,
        /// The available credit limit for the proposal.
        pub available_credit_limit: u256,
        /// The fixed amount of interest for the loan.
        pub fixed_interest_amount: u256,
        /// The annual percentage rate (APR) for accruing interest.
        pub accruing_interest_APR: u32,
        /// The duration of the loan in seconds.
        pub duration: u64,
        /// The expiration timestamp of the proposal.
        pub expiration: u64,
        /// The contract address of the allowed acceptor of the proposal.
        pub allowed_acceptor: ContractAddress,
        /// The contract address of the proposer.
        pub proposer: ContractAddress,
        /// The hash of the proposer specification.
        pub proposer_spec_hash: felt252,
        /// A boolean flag indicating whether the proposal is an offer.
        pub is_offer: bool,
        /// The identifier of the loan being refinanced, if applicable.
        pub refinancing_loan_id: felt252,
        /// The nonce space for the proposal.
        pub nonce_space: felt252,
        /// The nonce value for the proposal.
        pub nonce: felt252,
        /// The contract address of the loan contract.
        pub loan_contract: ContractAddress,
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

    #[constructor]
    fn constructor(
        ref self: ContractState,
        hub: ContractAddress,
        revoke_nonce: ContractAddress,
        config: ContractAddress,
        name: felt252,
        version: felt252,
    ) {
        self.simple_loan._initialize(hub, revoke_nonce, config, name, version);
    }

    #[abi(embed_v0)]
    impl SimpleLoanSimpleProposalImpl of super::ISimpleLoanSimpleProposal<ContractState> {
        /// Creates a new loan proposal and emits an event.
        ///
        /// # Arguments
        ///
        /// * `proposal` - A `Proposal` struct containing the details of the loan proposal.
        fn make_proposal(ref self: ContractState, proposal: Proposal) {
            let proposal_hash = self.get_proposal_hash(proposal);
            self.simple_loan._make_proposal(proposal_hash, proposal.proposer);

            self.emit(ProposalMade { proposal_hash, proposer: proposal.proposer, proposal, });
        }

        /// Accepts a loan proposal, validates it, and creates a new loan with the given terms.
        ///
        /// # Arguments
        ///
        /// * `acceptor` - The address of the entity accepting the proposal.
        /// * `refinancing_loan_id` - An optional ID for a loan being refinanced.
        /// * `proposal_data` - Encoded data representing the proposal details.
        /// * `proposal_inclusion_proof` - Proof of inclusion in the proposal data.
        /// * `signature` - A signature validating the proposal.
        ///
        /// # Returns
        ///
        /// Returns a tuple containing the proposal hash and the terms of the accepted loan.
        fn accept_proposal(
            ref self: ContractState,
            acceptor: starknet::ContractAddress,
            refinancing_loan_id: felt252,
            proposal_data: Array<felt252>,
            proposal_inclusion_proof: Array<u256>,
            signature: Signature
        ) -> (felt252, super::Terms) {
            let proposal = self.decode_proposal_data(proposal_data);

            let mut serialized_proposal = array![];
            proposal.serialize(ref serialized_proposal);
            let proposal_hash = self
                .simple_loan
                ._get_proposal_hash(PROPOSAL_TYPEHASH, serialized_proposal);

            let proposal_base = ProposalBase {
                collateral_address: proposal.collateral_address,
                collateral_id: proposal.collateral_id,
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
                    proposal_base,
                );

            // Create loan terms object
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
                    id: proposal.collateral_id,
                    amount: proposal.collateral_amount,
                },
                credit: MultiToken::ERC20(proposal.credit_address, proposal.credit_amount),
                fixed_interest_amount: proposal.fixed_interest_amount,
                accruing_interest_APR: proposal.accruing_interest_APR,
                lender_spec_hash: if proposal.is_offer {
                    proposal.proposer_spec_hash
                } else {
                    0.into()
                },
                borrower_spec_hash: if proposal.is_offer {
                    0.into()
                } else {
                    proposal.proposer_spec_hash
                },
            };

            (proposal_hash, loan_terms)
        }

        /// Computes the hash of a proposal for validation and uniqueness.
        ///
        /// # Arguments
        ///
        /// * `proposal` - The proposal object containing all necessary details.
        ///
        /// # Returns
        ///
        /// Returns the felt252 hash of the serialized proposal data.
        fn get_proposal_hash(self: @ContractState, proposal: Proposal) -> felt252 {
            let mut serialized_proposal = array![];
            proposal.serialize(ref serialized_proposal);
            self.simple_loan._get_proposal_hash(PROPOSAL_TYPEHASH, serialized_proposal)
        }

        /// Encodes the proposal data into a serialized format for storage or transmission.
        ///
        /// # Arguments
        ///
        /// * `proposal` - The proposal object containing all necessary details.
        ///
        /// # Returns
        ///
        /// Returns an array of felt252 representing the serialized proposal data.
        fn encode_proposal_data(self: @ContractState, proposal: Proposal,) -> Array<felt252> {
            let mut serialized_proposal = array![];
            proposal.serialize(ref serialized_proposal);

            serialized_proposal
        }

        /// Decodes the serialized proposal data back into a Proposal object.
        ///
        /// # Arguments
        ///
        /// * `encoded_data` - The serialized proposal data as an array of felt252.
        ///
        /// # Returns
        ///
        /// Returns a `Proposal` object reconstructed from the encoded data.
        fn decode_proposal_data(self: @ContractState, encoded_data: Array<felt252>) -> Proposal {
            self.decode_serde_proposal(encoded_data.span())
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
            let collateral_low: u128 = (*data.at(3)).try_into().expect('decode_serde_proposal');
            let collateral_high: u128 = (*data.at(4)).try_into().expect('decode_serde_proposal');
            let credit_address: ContractAddress = (*data.at(7))
                .try_into()
                .expect('decode_serde_proposal');
            let credit_low: u128 = (*data.at(8)).try_into().expect('decode_serde_proposal');
            let credit_high: u128 = (*data.at(9)).try_into().expect('decode_serde_proposal');
            let credit_limit_low: u128 = (*data.at(10)).try_into().expect('decode_serde_proposal');
            let credit_limit_high: u128 = (*data.at(11)).try_into().expect('decode_serde_proposal');
            let fixed_interest_low: u128 = (*data.at(12))
                .try_into()
                .expect('decode_serde_proposal');
            let fixed_interest_high: u128 = (*data.at(13))
                .try_into()
                .expect('decode_serde_proposal');
            let accruing_interest_APR: u32 = (*data.at(14))
                .try_into()
                .expect('decode_serde_proposal');
            let duration: u64 = (*data.at(15)).try_into().expect('decode_serde_proposal');
            let expiration: u64 = (*data.at(16)).try_into().expect('decode_serde_proposal');
            let allowed_acceptor: ContractAddress = (*data.at(17))
                .try_into()
                .expect('decode_serde_proposal');
            let proposer: ContractAddress = (*data.at(18))
                .try_into()
                .expect('decode_serde_proposal');
            let loan_contract: ContractAddress = (*data.at(24))
                .try_into()
                .expect('decode_serde_proposal');

            Proposal {
                collateral_category,
                collateral_address,
                collateral_id: *data.at(2),
                collateral_amount: u256 { low: collateral_low, high: collateral_high },
                check_collateral_state_fingerprint: if *data.at(5) == 1 {
                    true
                } else {
                    false
                },
                collateral_state_fingerprint: *data.at(6),
                credit_address,
                credit_amount: u256 { low: credit_low, high: credit_high },
                available_credit_limit: u256 { low: credit_limit_low, high: credit_limit_high },
                fixed_interest_amount: u256 { low: fixed_interest_low, high: fixed_interest_high },
                accruing_interest_APR,
                duration,
                expiration,
                allowed_acceptor,
                proposer,
                proposer_spec_hash: *data.at(19),
                is_offer: if *data.at(20) == 1 {
                    true
                } else {
                    false
                },
                refinancing_loan_id: *data.at(21),
                nonce_space: *data.at(22),
                nonce: *data.at(23),
                loan_contract,
            }
        }
    }
}

