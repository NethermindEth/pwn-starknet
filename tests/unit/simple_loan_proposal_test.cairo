use core::integer::BoundedInt;
use core::{
    starknet,
    starknet::{storage::StorageMapMemberAccessTrait, ContractAddress, get_contract_address},
    poseidon::poseidon_hash_span, traits::Into
};
use openzeppelin::account::interface::{IPublicKeyDispatcher, IPublicKeyDispatcherTrait};
use pwn::config::interface::{IPwnConfigDispatcher, IPwnConfigDispatcherTrait};
use pwn::hub::{pwn_hub_tags, pwn_hub::{IPwnHubDispatcher, IPwnHubDispatcherTrait}};
use pwn::interfaces::fingerprint_computer::{
    IStateFingerpringComputerDispatcher, IStateFingerpringComputerDispatcherTrait
};

use pwn::loan::{
    terms::simple::proposal::simple_loan_proposal::{
        SimpleLoanProposalComponent::InternalTrait, SimpleLoanProposalComponent, ISimpleLoanProposal
    }
};

use snforge_std::{
    declare, store, map_entry_address, cheat_block_timestamp_global, mock_call, ContractClassTrait,
    cheat_caller_address_global, stop_cheat_caller_address_global
};
use super::super::utils::simple_loan_proposal_component_mock::MockSimpleLoanProposal;

pub const E10: u256 = 10_000_000_000;
pub const E40: u256 = 10_000_000_000_000_000_000_000_000_000_000_000_000_000;
pub const E70: u256 =
    10_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000;
pub const MINUTE: u64 = 60;

#[derive(Drop)]
pub struct Params {
    pub base: SimpleLoanProposalComponent::ProposalBase,
    pub acceptor: ContractAddress,
    pub message_hash: felt252,
    pub refinancing_loan_id: felt252
}

type ComponentState =
    SimpleLoanProposalComponent::ComponentState<MockSimpleLoanProposal::ContractState>;

pub fn COMPONENT_STATE() -> ComponentState {
    SimpleLoanProposalComponent::component_state_for_testing()
}

pub fn TOKEN() -> ContractAddress {
    starknet::contract_address_const::<'token'>()
}

pub fn PROPOSER() -> ContractAddress {
    starknet::contract_address_const::<73661723>()
}

pub fn ACCEPTOR() -> ContractAddress {
    starknet::contract_address_const::<32716637>()
}

pub fn ACTIVATE_LOAN_CONTRACT() -> ContractAddress {
    starknet::contract_address_const::<'activeLoanContract'>()
}

pub fn SF_COMPUTER() -> ContractAddress {
    starknet::contract_address_const::<'stateFingerPrintComputer'>()
}

pub fn mock_sf_computer() {
    mock_call(SF_COMPUTER(), selector!("compute_state_fingerprint"), 'some state fingerprint', 1);
    mock_call(SF_COMPUTER(), selector!("supports_token"), true, 1);
}

pub fn get_dummy_message_hash() -> felt252 {
    poseidon_hash_span(array!['dummy'].span())
}
