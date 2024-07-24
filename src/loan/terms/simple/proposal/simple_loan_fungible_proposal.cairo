use SimpleLoanFungibleProposal::{Proposal, ProposalValues};
use pwn::loan::lib::signature_checker::Signature;
use pwn::loan::terms::simple::loan::types::Terms;

#[starknet::interface]
pub trait ISimpleLoanFungibleProposal<TState> {
    fn make_proposal(ref self: TState, proposal: Proposal) -> felt252;
    fn accept_proposal(
        ref self: TState,
        acceptor: starknet::ContractAddress,
        refinancing_loan_id: felt252,
        proposal_data: Array<felt252>,
        proposal_inclusion_proof: Array<u256>,
        signature: Signature,
    ) -> (felt252, Terms);
    fn get_proposal_hash(self: @TState, proposal: Proposal) -> felt252;
    fn encode_proposal_data(
        self: @TState, proposal: Proposal, proposal_values: ProposalValues
    ) -> Array<felt252>;
    fn decode_proposal_data(
        self: @TState, encoded_data: Array<felt252>
    ) -> (Proposal, ProposalValues);
    fn get_credit_amount(
        self: @TState, collateral_amount: u256, credit_per_collateral_unit: u256
    ) -> u256;
}

//! The `SimpleLoanFungibleProposal` module provides a mechanism for creating and accepting loan 
//! proposals for fungible assets . This module integrates multiple 
//! components to offer a comprehensive solution for handling loan proposals, including encoding 
//! and decoding proposal data, computing proposal hashes, and managing credit calculations.
//! 
//! # Features
//! 
//! - **Proposal Creation**: Allows the creation of loan proposals with specific terms and conditions.
//! - **Proposal Acceptance**: Facilitates the acceptance of loan proposals, including the 
//!   verification of signatures and proposal data.
//! - **Proposal Hashing**: Computes unique hashes for proposals to ensure data integrity and 
//!   security.
//! - **Proposal Encoding/Decoding**: Provides functionality to encode and decode proposal data 
//!   for efficient storage and retrieval.
//! - **Credit Calculation**: Manages the calculation of credit amounts based on collateral and 
//!   credit per collateral unit values.
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
//! - `CREDIT_PER_COLLATERAL_UNIT_DENOMINATOR`: The denominator for credit per collateral unit 
//!   calculations.
//! - `FUNGIBLE_PROPOSAL_DATA_LEN`: The expected length of the encoded proposal data.
//! 
//! This module is designed to provide a robust and flexible framework for managing loan proposals 
//! involving fungible assets, integrating seamlessly with other components of the Starknet 
//! ecosystem.
#[starknet::contract]
pub mod SimpleLoanFungibleProposal {
    use pwn::ContractAddressDefault;
    use pwn::loan::lib::{math, serialization};
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
        0x062dbce0eca7d4486c66e0d48cdd72744db07523b68e9e4dad30aa4bee1356;
    pub const CREDIT_PER_COLLATERAL_UNIT_DENOMINATOR: u256 =
        100_000_000_000_000_000_000_000_000_000_000_000_000;
    pub const FUNGIBLE_PROPOSAL_DATA_LEN: usize = 29;


    /// Represents a loan proposal with specific terms and conditions.
    #[derive(Copy, Default, Drop, Serde)]
    pub struct Proposal {
        /// Category of the collateral asset.
        pub collateral_category: MultiToken::Category,
        /// Address of the collateral asset.
        pub collateral_address: ContractAddress,
        /// ID of the collateral asset.
        pub collateral_id: felt252,
        /// Minimum amount of the collateral asset.
        pub min_collateral_amount: u256,
        /// Flag indicating if collateral state fingerprint should be checked.
        pub check_collateral_state_fingerprint: bool,
        /// Fingerprint of the collateral state.
        pub collateral_state_fingerprint: felt252,
        /// Address of the credit asset.
        pub credit_address: ContractAddress,
        /// Credit amount per unit of collateral.
        pub credit_per_collateral_unit: u256,
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


    #[derive(Copy, Default, Drop, Serde)]
    pub struct ProposalValues {
        pub collateral_amount: u256,
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

    mod Err {
        pub fn MIN_COLLATERAL_AMOUNT_NOT_SET() {
            panic!("Proposal has no minimal collateral amount set");
        }
        pub fn INSUFFICIENT_COLLATERAL_AMOUNT(current: u256, limit: u256) {
            panic!("Insufficient collateral amount. Current: {}, Limit: {}", current, limit);
        }
        pub fn INVALID_PROPOSAL_DATA(len: usize) {
            panic!(
                "Invalid proposal data length: {}, expected: {}",
                len,
                super::FUNGIBLE_PROPOSAL_DATA_LEN
            );
        }
    }


    #[constructor]
    fn constructor(
        ref self: ContractState,
        hub: ContractAddress,
        revoke_nonce: ContractAddress,
        config: ContractAddress,
        name: felt252,
        version: felt252
    ) {
        self.simple_loan._initialize(hub, revoke_nonce, config, name, version);
    }

    #[abi(embed_v0)]
    impl SimpleLoanDutchAuctionProposalImpl of super::ISimpleLoanFungibleProposal<ContractState> {
        /// Creates a loan proposal using the provided proposal details.
        ///
        /// # Arguments
        ///
        /// - `proposal`: The details of the proposal.
        ///
        /// # Returns
        ///
        /// - The computed hash of the proposal as `felt252`.
        ///
        /// # Actions
        ///
        /// - Computes the hash of the proposal.
        /// - Calls the internal method to make the proposal.
        /// - Emits a `ProposalMade` event.
        /// - Returns the proposal hash.
        fn make_proposal(ref self: ContractState, proposal: Proposal) -> felt252 {
            let proposal_hash = self.get_proposal_hash(proposal);
            self.simple_loan._make_proposal(proposal_hash, proposal.proposer);

            self.emit(ProposalMade { proposal_hash, proposer: proposal.proposer, proposal, });

            proposal_hash
        }

        /// Accepts a loan proposal using the provided details and signature.
        ///
        /// # Arguments
        ///
        /// - `acceptor`: The address of the acceptor.
        /// - `refinancing_loan_id`: The ID of the loan being refinanced, if applicable.
        /// - `proposal_data`: The encoded data of the proposal.
        /// - `proposal_inclusion_proof`: The inclusion proof for the proposal.
        /// - `signature`: The signature for validating the proposal.
        ///
        /// # Returns
        ///
        /// - A tuple containing the proposal hash and the loan terms.
        ///
        /// # Requirements
        ///
        /// - The length of `proposal_data` must match `FUNGIBLE_PROPOSAL_DATA_LEN`.
        /// - The proposal must have a minimum collateral amount set.
        /// - The collateral amount in `proposal_values` must meet or exceed the minimum collateral amount.
        ///
        /// # Actions
        ///
        /// - Decodes the proposal data.
        /// - Computes the proposal hash.
        /// - Validates the collateral amount against the minimum required collateral.
        /// - Calculates the credit amount based on the collateral amount and credit per collateral unit.
        /// - Creates the proposal base and calls the internal method to accept the proposal.
        /// - Constructs the loan terms and returns them along with the proposal hash.
        fn accept_proposal(
            ref self: ContractState,
            acceptor: starknet::ContractAddress,
            refinancing_loan_id: felt252,
            proposal_data: Array<felt252>,
            proposal_inclusion_proof: Array<u256>,
            signature: Signature
        ) -> (felt252, super::Terms) {
            if proposal_data.len() != FUNGIBLE_PROPOSAL_DATA_LEN {
                Err::INVALID_PROPOSAL_DATA(proposal_data.len());
            }

            let (proposal, proposal_values) = self.decode_proposal_data(proposal_data);

            let mut serialized_proposal = array![];
            proposal.serialize(ref serialized_proposal);
            let proposal_hash = self
                .simple_loan
                ._get_proposal_hash(PROPOSAL_TYPEHASH, serialized_proposal);

            if proposal.min_collateral_amount == 0 {
                Err::MIN_COLLATERAL_AMOUNT_NOT_SET();
            }

            if proposal_values.collateral_amount < proposal.min_collateral_amount {
                Err::INSUFFICIENT_COLLATERAL_AMOUNT(
                    proposal_values.collateral_amount, proposal.min_collateral_amount
                );
            }

            let credit_amount = self
                .get_credit_amount(
                    proposal_values.collateral_amount, proposal.credit_per_collateral_unit
                );

            let proposal_base = ProposalBase {
                collateral_address: proposal.collateral_address,
                collateral_id: proposal.collateral_id,
                check_collateral_state_fingerprint: proposal.check_collateral_state_fingerprint,
                collateral_state_fingerprint: proposal.collateral_state_fingerprint,
                credit_amount: credit_amount,
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
                    id: proposal.collateral_id,
                    amount: proposal_values.collateral_amount,
                },
                credit: MultiToken::ERC20(proposal.credit_address, credit_amount),
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

        /// Computes the hash of a loan proposal.
        ///
        /// # Arguments
        ///
        /// - `proposal`: The proposal details.
        ///
        /// # Returns
        ///
        /// - The computed hash as `felt252`.
        fn get_proposal_hash(self: @ContractState, proposal: Proposal) -> felt252 {
            let mut serialized_proposal = array![];
            proposal.serialize(ref serialized_proposal);
            self.simple_loan._get_proposal_hash(PROPOSAL_TYPEHASH, serialized_proposal)
        }

        /// Encodes the proposal data and values into a single array.
        ///
        /// # Arguments
        ///
        /// - `proposal`: The proposal details.
        /// - `proposal_values`: The proposal values.
        ///
        /// # Returns
        ///
        /// - The encoded proposal data as `Array<felt252>`.
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

        /// Decodes the encoded proposal data into proposal and proposal values.
        ///
        /// # Arguments
        ///
        /// - `encoded_data`: The encoded proposal data.
        ///
        /// # Returns
        ///
        /// - A tuple containing the decoded `Proposal` and `ProposalValues`.
        ///
        /// # Requirements
        ///
        /// - The length of `encoded_data` must match `FUNGIBLE_PROPOSAL_DATA_LEN`.
        fn decode_proposal_data(
            self: @ContractState, encoded_data: Array<felt252>
        ) -> (Proposal, ProposalValues) {
            if encoded_data.len() != FUNGIBLE_PROPOSAL_DATA_LEN {
                Err::INVALID_PROPOSAL_DATA(encoded_data.len());
            }

            let (proposal_data, proposal_values_data) = serialization::serde_decompose(
                encoded_data.span()
            );
            let proposal = self.decode_serde_proposal(proposal_data);
            let proposal_values = self.decode_serde_proposal_values(proposal_values_data);

            (proposal, proposal_values)
        }

        /// Calculates the credit amount based on the collateral amount and credit per collateral unit.
        ///
        /// # Arguments
        ///
        /// - `collateral_amount`: The amount of collateral.
        /// - `credit_per_collateral_unit`: The amount of credit per unit of collateral.
        ///
        /// # Returns
        ///
        /// - The calculated credit amount as `u256`.
        fn get_credit_amount(
            self: @ContractState, collateral_amount: u256, credit_per_collateral_unit: u256
        ) -> u256 {
            math::mul_div(
                collateral_amount,
                credit_per_collateral_unit,
                CREDIT_PER_COLLATERAL_UNIT_DENOMINATOR
            )
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
            let min_collateral_low: u128 = (*data.at(3)).try_into().expect('decode_serde_proposal');
            let min_collateral_high: u128 = (*data.at(4))
                .try_into()
                .expect('decode_serde_proposal');
            let credit_address: ContractAddress = (*data.at(7))
                .try_into()
                .expect('decode_serde_proposal');
            let collateral_unit_low: u128 = (*data.at(8))
                .try_into()
                .expect('decode_serde_proposal');
            let collateral_unit_high: u128 = (*data.at(9))
                .try_into()
                .expect('decode_serde_proposal');
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
                min_collateral_amount: u256 { low: min_collateral_low, high: min_collateral_high },
                check_collateral_state_fingerprint: if *data.at(5) == 1 {
                    true
                } else {
                    false
                },
                collateral_state_fingerprint: *data.at(6),
                credit_address,
                credit_per_collateral_unit: u256 {
                    low: collateral_unit_low, high: collateral_unit_high
                },
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

        fn decode_serde_proposal_values(
            self: @ContractState, data: Span<felt252>
        ) -> ProposalValues {
            let amount_low: u128 = (*data.at(0)).try_into().expect('decode_serde_proposal_values');
            let amount_high: u128 = (*data.at(1)).try_into().expect('decode_serde_proposal_values');

            ProposalValues { collateral_amount: u256 { low: amount_low, high: amount_high, }, }
        }
    }
}

