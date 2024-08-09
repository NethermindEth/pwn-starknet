use SimpleLoanDutchAuctionProposal::{Proposal, ProposalValues};
use pwn::loan::lib::signature_checker::Signature;
use pwn::loan::terms::simple::loan::types::Terms;

#[starknet::interface]
pub trait ISimpleLoanDutchAuctionProposal<TState> {
    fn make_proposal(ref self: TState, proposal: Proposal);
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
    fn get_credit_amount(self: @TState, proposal: Proposal, timestamp: u64) -> u256;
}

//! The `SimpleLoanDutchAuctionProposal` module provides a mechanism for creating and accepting 
//! loan proposals using a Dutch auction model . This module 
//! integrates multiple components to offer a comprehensive solution for handling loan proposals, 
//! including encoding and decoding proposal data, computing proposal hashes, and managing auction 
//! dynamics.
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
//! - **Auction Dynamics**: Manages the auction process, including calculating the credit amount 
//!   based on the auction's progress.
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
//! - `MINUTE`: Represents one minute in seconds.
//! - `DUTCH_PROPOSAL_DATA_LEN`: The expected length of the encoded proposal data.
//! 
//! This module is designed to provide a robust and flexible framework for managing loan proposals 
//! using a Dutch auction model, integrating seamlessly with other components of the Starknet 
//! ecosystem.

#[starknet::contract]
pub mod SimpleLoanDutchAuctionProposal {
    use core::num::traits::Bounded;
    use pwn::ContractAddressDefault;
    use pwn::loan::lib::{serialization, math};
    use pwn::loan::terms::simple::proposal::simple_loan_proposal::{
        SimpleLoanProposalComponent, SimpleLoanProposalComponent::ProposalBase
    };
    use pwn::multitoken::library::MultiToken;
    use starknet::ContractAddress;
    use starknet::storage::Map;
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
        0x011b95ba182b3ea59860b7ebc4e42e45c9c9ae5c8f6bd7b8dbbde7415bb396b7;
    pub const MINUTE: u64 = 60;
    pub const DUTCH_PROPOSAL_DATA_LEN: usize = 34;

    /// Represents a loan proposal with specific terms and conditions for a Dutch auction.
    #[derive(Copy, Default, Drop, Serde)]
    pub struct Proposal {
        /// Category of the collateral asset.
        pub collateral_category: MultiToken::Category,
        /// Address of the collateral asset.
        pub collateral_address: ContractAddress,
        /// ID of the collateral asset.
        pub collateral_id: felt252,
        /// Amount of the collateral asset.
        pub collateral_amount: u256,
        /// Flag indicating if collateral state fingerprint should be checked.
        pub check_collateral_state_fingerprint: bool,
        /// Fingerprint of the collateral state.
        pub collateral_state_fingerprint: felt252,
        /// Address of the credit asset.
        pub credit_address: ContractAddress,
        /// Minimum amount of credit offered.
        pub min_credit_amount: u256,
        /// Maximum amount of credit offered.
        pub max_credit_amount: u256,
        /// Available credit limit for the proposal.
        pub available_credit_limit: u256,
        /// Fixed interest amount for the loan.
        pub fixed_interest_amount: u256,
        /// Annual percentage rate of the accruing interest.
        pub accruing_interest_APR: u32,
        /// Duration of the loan in seconds.
        pub duration: u64,
        /// Start time of the auction in seconds since the Unix epoch.
        pub auction_start: u64,
        /// Duration of the auction in seconds.
        pub auction_duration: u64,
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


    #[derive(Default, Drop, Serde)]
    pub struct ProposalValues {
        pub intended_credit_amount: u256,
        pub slippage: u256,
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
        pub fn INVALID_AUCTION_DURATION(current: u64, limit: u64) {
            panic!("Invalid auction duration. Current: {}, Limit: {}", current, limit);
        }
        pub fn AUCTION_DURATION_NOT_IN_FULL_MINUTES(current: u64) {
            panic!("Auction duration is not in full minutes. Current: {}", current);
        }
        pub fn INVALID_CREDIT_AMOUNT_RANGE(min_credit_amount: u256, max_credit_amount: u256) {
            panic!(
                "Invalid credit amount range. Min: {}, Max: {}",
                min_credit_amount,
                max_credit_amount
            );
        }
        pub fn INVALID_CREDIT_AMOUNT(
            auction_credit_amount: u256, intended_credit_amount: u256, slippage: u256
        ) {
            panic!(
                "Invalid credit amount. Auction: {}, Intended: {}, Slippage: {}",
                auction_credit_amount,
                intended_credit_amount,
                slippage
            );
        }
        pub fn AUCTION_NOT_IN_PROGRESS(current_timestamp: u64, auction_start: u64) {
            panic!(
                "Auction not in progress. Current timestamp: {}, Auction start: {}",
                current_timestamp,
                auction_start
            );
        }
        pub fn EXPIRED(current_timestamp: u64, expiration: u64) {
            panic!("Expired. Current timestamp: {}, Expiration: {}", current_timestamp, expiration);
        }
        pub fn INVALID_PROPOSAL_DATA_LEN(len: usize) {
            panic!(
                "Invalid proposal data length: {}, expected: {}",
                len,
                super::DUTCH_PROPOSAL_DATA_LEN
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
        version: felt252,
    ) {
        self.simple_loan._initialize(hub, revoke_nonce, config, name, version);
    }

    #[abi(embed_v0)]
    impl ISimpleLoanDutchAuctionProposalImpl of super::ISimpleLoanDutchAuctionProposal<
        ContractState
    > {
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
        /// - The length of `proposal_data` must match `DUTCH_PROPOSAL_DATA_LEN`.
        /// - The credit amount must be within the valid range specified by the proposal.
        ///
        /// # Actions
        ///
        /// - Decodes the proposal data.
        /// - Computes the proposal hash.
        /// - Calculates the credit amount based on the auction progress.
        /// - Validates the credit amount against the intended credit amount and slippage.
        /// - Creates the proposal base and calls the componet's internal method to accept the proposal.
        /// - Constructs the loan terms and returns them along with the proposal hash.
        fn accept_proposal(
            ref self: ContractState,
            acceptor: starknet::ContractAddress,
            refinancing_loan_id: felt252,
            proposal_data: Array<felt252>,
            proposal_inclusion_proof: Array<u256>,
            signature: Signature,
        ) -> (felt252, Terms) {
            if proposal_data.len() != DUTCH_PROPOSAL_DATA_LEN {
                Err::INVALID_PROPOSAL_DATA_LEN(proposal_data.len());
            }
            let (proposal, proposal_values) = self.decode_proposal_data(proposal_data);

            let mut serialized_proposal = array![];
            proposal.serialize(ref serialized_proposal);
            let proposal_hash = self
                .simple_loan
                ._get_proposal_hash(PROPOSAL_TYPEHASH, serialized_proposal);

            let credit_amount = self.get_credit_amount(proposal, starknet::get_block_timestamp());

            if proposal.is_offer {
                if credit_amount < proposal_values.intended_credit_amount
                    || proposal_values.intended_credit_amount < proposal.min_credit_amount
                    || proposal_values.intended_credit_amount
                    + proposal_values.slippage < credit_amount {
                    Err::INVALID_CREDIT_AMOUNT(
                        credit_amount,
                        proposal_values.intended_credit_amount,
                        proposal_values.slippage
                    );
                }
            } else {
                if credit_amount > proposal_values.intended_credit_amount
                    || proposal_values.intended_credit_amount
                    - proposal_values.slippage > credit_amount {
                    Err::INVALID_CREDIT_AMOUNT(
                        credit_amount,
                        proposal_values.intended_credit_amount,
                        proposal_values.slippage
                    );
                }
            }

            let proposal_base = ProposalBase {
                collateral_address: proposal.collateral_address,
                collateral_id: proposal.collateral_id,
                check_collateral_state_fingerprint: proposal.check_collateral_state_fingerprint,
                collateral_state_fingerprint: proposal.collateral_state_fingerprint,
                credit_amount: credit_amount,
                available_credit_limit: proposal.available_credit_limit,
                expiration: proposal.auction_start + proposal.auction_duration + MINUTE,
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
                    amount: proposal.collateral_amount,
                },
                credit: MultiToken::ERC20(proposal.credit_address, credit_amount,),
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
        /// - The length of `encoded_data` must match `DUTCH_PROPOSAL_DATA_LEN`.
        fn decode_proposal_data(
            self: @ContractState, encoded_data: Array<felt252>
        ) -> (Proposal, ProposalValues) {
            if encoded_data.len() != DUTCH_PROPOSAL_DATA_LEN {
                Err::INVALID_PROPOSAL_DATA_LEN(encoded_data.len());
            }

            let (proposal_data, proposal_values_data) = serialization::serde_decompose(
                encoded_data.span()
            );
            let proposal = self.decode_serde_proposal(proposal_data);
            let proposal_values = self.decode_serde_proposal_values(proposal_values_data);

            (proposal, proposal_values)
        }

        /// Calculates the credit amount for a proposal based on the auction progress.
        ///
        /// # Arguments
        ///
        /// - `proposal`: The proposal details.
        /// - `timestamp`: The current timestamp.
        ///
        /// # Returns
        ///
        /// - The calculated credit amount as `u256`.
        ///
        /// # Requirements
        ///
        /// - The auction duration must be within valid limits.
        /// - The auction duration must be in full minutes.
        /// - The max credit amount must be greater than the min credit amount.
        /// - The auction must be in progress based on the current timestamp.
        ///
        /// # Errors
        ///
        /// - `INVALID_AUCTION_DURATION`: If the auction duration is out of bounds.
        /// - `AUCTION_DURATION_NOT_IN_FULL_MINUTES`: If the auction duration is not in full minutes.
        /// - `INVALID_CREDIT_AMOUNT_RANGE`: If the max credit amount is not greater than the min credit amount.
        /// - `AUCTION_NOT_IN_PROGRESS`: If the auction is not currently in progress.
        /// - `EXPIRED`: If the auction has expired.
        fn get_credit_amount(self: @ContractState, proposal: Proposal, timestamp: u64) -> u256 {
            if proposal.auction_duration < MINUTE || proposal.auction_duration > Bounded::MAX
                - MINUTE {
                Err::INVALID_AUCTION_DURATION(proposal.auction_duration, MINUTE);
            }
            if proposal.auction_duration % MINUTE > 0 {
                Err::AUCTION_DURATION_NOT_IN_FULL_MINUTES(proposal.auction_duration);
            }
            if proposal.max_credit_amount <= proposal.min_credit_amount {
                Err::INVALID_CREDIT_AMOUNT_RANGE(
                    proposal.min_credit_amount, proposal.max_credit_amount
                );
            }
            if timestamp < proposal.auction_start {
                Err::AUCTION_NOT_IN_PROGRESS(timestamp, proposal.auction_start);
            }
            if proposal.auction_start + proposal.auction_duration + MINUTE <= timestamp {
                Err::EXPIRED(
                    timestamp, proposal.auction_start + proposal.auction_duration + MINUTE
                );
            }

            let timestamp: u256 = timestamp.into();
            let credit_amount_delta = math::mul_div(
                proposal.max_credit_amount - proposal.min_credit_amount,
                (timestamp - proposal.auction_start.into()) / MINUTE.into(),
                proposal.auction_duration.into() / MINUTE.into(),
            );

            if proposal.is_offer {
                proposal.min_credit_amount + credit_amount_delta
            } else {
                proposal.max_credit_amount - credit_amount_delta
            }
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
            let min_credit_low: u128 = (*data.at(8)).try_into().expect('decode_serde_proposal');
            let min_credit_high: u128 = (*data.at(9)).try_into().expect('decode_serde_proposal');
            let max_credit_low: u128 = (*data.at(10)).try_into().expect('decode_serde_proposal');
            let max_credit_high: u128 = (*data.at(11)).try_into().expect('decode_serde_proposal');
            let credit_limit_low: u128 = (*data.at(12)).try_into().expect('decode_serde_proposal');
            let credit_limit_high: u128 = (*data.at(13)).try_into().expect('decode_serde_proposal');
            let fixed_interest_low: u128 = (*data.at(14))
                .try_into()
                .expect('decode_serde_proposal');
            let fixed_interest_high: u128 = (*data.at(15))
                .try_into()
                .expect('decode_serde_proposal');
            let accruing_interest_APR: u32 = (*data.at(16))
                .try_into()
                .expect('decode_serde_proposal');
            let duration: u64 = (*data.at(17)).try_into().expect('decode_serde_proposal');
            let auction_start: u64 = (*data.at(18)).try_into().expect('decode_serde_proposal');
            let auction_duration: u64 = (*data.at(19)).try_into().expect('decode_serde_proposal');
            let allowed_acceptor: ContractAddress = (*data.at(20))
                .try_into()
                .expect('decode_serde_proposal');
            let proposer: ContractAddress = (*data.at(21))
                .try_into()
                .expect('decode_serde_proposal');
            let loan_contract: ContractAddress = (*data.at(27))
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
                min_credit_amount: u256 { low: min_credit_low, high: min_credit_high },
                max_credit_amount: u256 { low: max_credit_low, high: max_credit_high },
                available_credit_limit: u256 { low: credit_limit_low, high: credit_limit_high },
                fixed_interest_amount: u256 { low: fixed_interest_low, high: fixed_interest_high },
                accruing_interest_APR,
                duration,
                auction_start,
                auction_duration,
                allowed_acceptor,
                proposer,
                proposer_spec_hash: *data.at(22),
                is_offer: if *data.at(23) == 1 {
                    true
                } else {
                    false
                },
                refinancing_loan_id: *data.at(24),
                nonce_space: *data.at(25),
                nonce: *data.at(26),
                loan_contract,
            }
        }

        fn decode_serde_proposal_values(
            self: @ContractState, data: Span<felt252>
        ) -> ProposalValues {
            let intended_credit_low: u128 = (*data.at(0))
                .try_into()
                .expect('decode_serde_proposal_values');
            let intended_credit_high: u128 = (*data.at(1))
                .try_into()
                .expect('decode_serde_proposal_values');
            let slippage_low: u128 = (*data.at(2))
                .try_into()
                .expect('decode_serde_proposal_values');
            let slippage_high: u128 = (*data.at(3))
                .try_into()
                .expect('decode_serde_proposal_values');

            ProposalValues {
                intended_credit_amount: u256 {
                    low: intended_credit_low, high: intended_credit_high,
                },
                slippage: u256 { low: slippage_low, high: slippage_high },
            }
        }
    }
}
