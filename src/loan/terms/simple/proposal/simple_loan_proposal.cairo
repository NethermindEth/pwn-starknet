use starknet::{ContractAddress, ClassHash};

#[starknet::interface]
trait ISimpleLoanProposal<TState> {
    fn revoked_nonce(ref self: TState, nonce_space: felt252, nonce: felt252);
    // fn accept_proposal(ref self: TState, acceptor: ContractAddress, refinancing_loan_id: felt252, proposal_data: felt252, proposal_inclusion_proof: Array<u8>, signature: felt256) -> (felt252, PwnSimpleLoan);
    fn get_multiproposal_hash(self: @TState, multiproposal: ClassHash) -> felt252;
}

#[starknet::component]
pub mod SimpleLoanProposalComponent {
    use core::traits::TryInto;
    use super::{ContractAddress, ClassHash};

    #[derive(Drop)]
    struct Multiproposal {
        multiproposal_root_hash: felt252
    }

    #[derive(Drop)]
    pub struct ProposalBase {
        pub collateral_address: ContractAddress,
        pub collateral_id: felt252,
        pub check_collateral_state_fingerprint: bool,
        pub collateral_state_fingerprint: felt252,
        pub credit_amount: u256,
        pub available_credit_limit: u256,
        pub expiration: u64,
        pub allowed_acceptor: ContractAddress,
        pub proposer: ContractAddress,
        pub is_offer: bool,
        pub refinancing_loan_id: felt252,
        pub nonce_space: felt252,
        pub nonce: felt252,
        pub loan_contract: ContractAddress,
    }

    #[storage]
    struct Storage {
        proposal_made: LegacyMap::<felt252, bool>,
        credit_used: LegacyMap::<felt252, u256>,
    }

    pub mod Err {
        fn CALLER_NOT_LOAN_CONTRACT(
            caller: super::ContractAddress, loan_contract: super::ContractAddress
        ) {
            panic!("Caller {:?} is not the loan contract {:?}", caller, loan_contract);
        }
        fn MISSING_STATE_FINGERPRINT_COMPUTER() {
            panic!("State fingerprint computer is not registered");
        }
        fn INVALID_COLLATERAL_STATE_FINGERPRINT(current: felt252, proposed: felt252) {
            panic!(
                "Invalid collateral state fingerprint. Current: {:?}, Proposed: {:?}",
                current,
                proposed
            );
        }
        fn CALLER_IS_NOT_STATED_PROPOSER(addr: super::ContractAddress) {
            panic!("Caller {:?} is not the stated proposer", addr);
        }
        fn ACCEPTOR_IS_PROPOSER(addr: super::ContractAddress) {
            panic!("Proposal acceptor {:?} is also the proposer", addr);
        }
        fn INVALID_REFINANCING_LOAN_ID(refinancing_loan_id: u256) {
            panic!("Provided refinance loan ID {:?} cannot be used", refinancing_loan_id);
        }
        fn AVAILABLE_CREDIT_LIMIT_EXCEEDED(used: u256, limit: u256) {
            panic!("Available credit limit exceeded. Used: {}, Limit: {}", used, limit);
        }
        fn CALLER_NOT_ALLOWED_ACCEPTOR(
            current: super::ContractAddress, allowed: super::ContractAddress
        ) {
            panic!("Caller {:?} is not the allowed acceptor {:?}", current, allowed);
        }
    }

    #[embeddable_as(SimpleLoanProposalImpl)]
    impl SimpleLoanProposal<
        TContractState, +HasComponent<TContractState>,
    > of super::ISimpleLoanProposal<ComponentState<TContractState>> {
        fn revoked_nonce(
            ref self: ComponentState<TContractState>, nonce_space: felt252, nonce: felt252
        ) {}

        fn get_multiproposal_hash(
            self: @ComponentState<TContractState>, multiproposal: ClassHash
        ) -> felt252 {
            0
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>,
    > of InternalTrait<TContractState> {
        // NOTE: This is the constuctor of the Solidity contract.
        fn _initialize(
            ref self: ComponentState<TContractState>,
            hub: ContractAddress,
            revoked_nonce: ContractAddress,
            config: ContractAddress,
            name: felt252,
            version: felt252
        ) {}

        // NOTE: here will we use Poseidon hash function to hash the proposal data.
        fn _get_proposal_hash(
            self: @ComponentState<TContractState>,
            proposal_type_hash: felt252,
            encoded_proposal: Array<felt252>
        ) -> felt252 {
            0
        }

        fn _make_proposal(
            ref self: ComponentState<TContractState>,
            proposal_hash: felt252,
            proposer: ContractAddress
        ) {}

        fn _accept_proposal(
            ref self: ComponentState<TContractState>,
            acceptor: ContractAddress,
            refinancing_loan_id: felt252,
            proposal_hash: felt252,
            proposal_inclusion_proof: Array<felt252>,
            signature: felt252,
            proposal: ProposalBase
        ) {}
    }
}
