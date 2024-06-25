use SimpleLoanDutchAuctionProposal::{Proposal, ProposalValues};
use pwn::loan::terms::simple::loan::types::Terms;

#[starknet::interface]
trait ISimpleLoanDutchAuctionProposal<TState> {
    fn make_proposal(ref self: TState, proposal: Proposal);
    fn accept_proposal(
        ref self: TState,
        acceptor: starknet::ContractAddress,
        refinancing_loan_id: felt252,
        proposal_data: Array<felt252>,
        proposal_inclusion_proof: Array<felt252>,
        signature: felt252
    ) -> (felt252, Terms);
    fn get_proposal_hash(self: @TState, proposal: Proposal) -> felt252;
    fn encoded_proposal_data(
        self: @TState, proposal: Proposal, proposal_values: ProposalValues
    ) -> felt252;
    fn decode_proposal_data(self: @TState, encoded_data: felt252) -> (Proposal, ProposalValues);
    fn get_credit_amount(self: @TState, proposal: Proposal, timestamp: u64) -> u256;
}

#[starknet::contract]
mod SimpleLoanDutchAuctionProposal {
    use core::traits::TryInto;
    use pwn::ContractAddressDefault;
    use pwn::multitoken::library::MultiToken;
    use starknet::ContractAddress;

    // NOTE: we can hard code this by calculating the poseidon hash of the string 
    // in the Solidity contract offline.
    const PROPOSAL_TYPEHASH: felt252 = 0;

    #[derive(Default, Drop, Serde)]
    pub struct Proposal {
        collateral_category: MultiToken::Category,
        collateral_address: ContractAddress,
        collateral_id: felt252,
        collateral_amount: u256,
        check_collateral_state_fingerprint: bool,
        collateral_state_fingerprin: felt252,
        credit_address: ContractAddress,
        min_credit_amount: u256,
        max_credit_amount: u256,
        available_credit_limit: u256,
        fixed_interest_amount: u256,
        accruing_interest_APR: u32,
        duration: u64,
        auction_start: u64,
        auction_duration: u64,
        allowed_acceptor: ContractAddress,
        proposer: ContractAddress,
        proposer_specHash: felt252,
        is_offer: bool,
        refinancing_loan_id: felt252,
        nonce_space: felt252,
        nonce: felt252,
        loan_contract: ContractAddress,
    }


    #[derive(Default, Drop, Serde)]
    pub struct ProposalValues {
        intended_credit_amount: u256,
        slippage: u256,
    }

    #[storage]
    struct Storage {}

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        ProposalMade: ProposalMade,
    }

    #[derive(Drop, starknet::Event)]
    struct ProposalMade {
        proposal_hash: felt252,
        proposer: ContractAddress,
        proposal: Proposal,
    }

    mod Err {
        fn INVALID_AUCTION_DURATION(current: u64, limit: u64) {
            panic!("Invalid auction duration. Current: {}, Limit: {}", current, limit);
        }
        fn AUCTION_DURATION_NOT_IN_FULL_MINUTES(current: u64) {
            panic!("Auction duration is not in full minutes. Current: {}", current);
        }
        fn INVALID_CREDIT_AMOUNT_RANGE(min_credit_amount: u256, max_credit_amount: u256) {
            panic!(
                "Invalid credit amount range. Min: {}, Max: {}",
                min_credit_amount,
                max_credit_amount
            );
        }
        fn INVALID_CREDIT_AMOUNT(
            auction_credit_amount: u256, intended_credit_amount: u256, slippage: u256
        ) {
            panic!(
                "Invalid credit amount. Auction: {}, Intended: {}, Slippage: {}",
                auction_credit_amount,
                intended_credit_amount,
                slippage
            );
        }
        fn AUCTION_NOT_IN_PROGRESS(current_timestamp: u64, auction_start: u64) {
            panic!(
                "Auction not in progress. Current timestamp: {}, Auction start: {}",
                current_timestamp,
                auction_start
            );
        }
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        hub: ContractAddress,
        revoke_nonce: ContractAddress,
        config: ContractAddress
    ) {}

    #[abi(embed_v0)]
    impl ISimpleLoanDutchAuctionProposalImpl of super::ISimpleLoanDutchAuctionProposal<
        ContractState
    > {
        fn make_proposal(ref self: ContractState, proposal: Proposal) {}

        fn accept_proposal(
            ref self: ContractState,
            acceptor: starknet::ContractAddress,
            refinancing_loan_id: felt252,
            proposal_data: Array<felt252>,
            proposal_inclusion_proof: Array<felt252>,
            signature: felt252
        ) -> (felt252, super::Terms) {
            (0.try_into().unwrap(), Default::default())
        }

        fn get_proposal_hash(self: @ContractState, proposal: Proposal) -> felt252 {
            0
        }

        fn encoded_proposal_data(
            self: @ContractState, proposal: Proposal, proposal_values: ProposalValues
        ) -> felt252 {
            0
        }

        fn decode_proposal_data(
            self: @ContractState, encoded_data: felt252
        ) -> (Proposal, ProposalValues) {
            (Default::default(), Default::default())
        }

        fn get_credit_amount(self: @ContractState, proposal: Proposal, timestamp: u64) -> u256 {
            0
        }
    }
}
