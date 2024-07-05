use core::integer::BoundedInt;
use core::poseidon::poseidon_hash_span;
use core::starknet::SyscallResultTrait;
use pwn::config::pwn_config::PwnConfig;
use pwn::hub::{pwn_hub::{PwnHub, IPwnHubDispatcher, IPwnHubDispatcherTrait}, pwn_hub_tags};
use pwn::loan::lib::serialization;
use pwn::loan::lib::signature_checker::Signature;
use pwn::loan::terms::simple::loan::types::Terms;
use pwn::loan::terms::simple::proposal::{
    simple_loan_proposal::{
        SimpleLoanProposalComponent,
        SimpleLoanProposalComponent::{SimpleLoanProposalImpl, InternalImpl, BASE_DOMAIN_SEPARATOR}
    },
    simple_loan_fungible_proposal::{
        SimpleLoanFungibleProposal, SimpleLoanFungibleProposal::{Proposal, ProposalValues}
    }
};
use pwn::multitoken::library::MultiToken;
use pwn::nonce::revoked_nonce::{RevokedNonce, IRevokedNonceDispatcher};
use snforge_std::signature::KeyPairTrait;
use snforge_std::signature::stark_curve::{
    StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl
};
use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    spy_events, SpyOn, EventSpy, EventAssertions, cheat_block_timestamp_global
};
use starknet::secp256k1::{Secp256k1Point};
use starknet::{ContractAddress, testing};
use super::simple_loan_proposal_test::{TOKEN, PROPOSER, ACTIVATE_LOAN_CONTRACT, ACCEPTOR, Params};

#[starknet::interface]
pub trait ISimpleLoanFungibleProposal<TState> {
    fn make_proposal(ref self: TState, proposal: Proposal);
    fn accept_proposal(
        ref self: TState,
        acceptor: starknet::ContractAddress,
        refinancing_loan_id: felt252,
        proposal_data: Array<felt252>,
        proposal_inclusion_proof: Array<felt252>,
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
    fn revoke_nonce(ref self: TState, nonce_space: felt252, nonce: felt252);
    fn get_multiproposal_hash(self: @TState, multiproposal: starknet::ClassHash) -> felt252;
}

fn deploy() -> (ISimpleLoanFungibleProposalDispatcher, IPwnHubDispatcher, IRevokedNonceDispatcher) {
    let contract = declare("PwnHub").unwrap();
    let (hub_address, _) = contract.deploy(@array![]).unwrap();

    let contract = declare("PwnConfig").unwrap();
    let (config_address, _) = contract.deploy(@array![]).unwrap();

    let contract = declare("RevokedNonce").unwrap();
    let (nonce_address, _) = contract
        .deploy(@array![hub_address.into(), pwn_hub_tags::ACTIVE_LOAN])
        .unwrap();

    let contract = declare("SimpleLoanFungibleProposal").unwrap();
    let (contract_address, _) = contract
        .deploy(
            @array![
                hub_address.into(), nonce_address.into(), config_address.into(), 'name', 'version'
            ]
        )
        .unwrap();

    (
        ISimpleLoanFungibleProposalDispatcher { contract_address },
        IPwnHubDispatcher { contract_address: hub_address },
        IRevokedNonceDispatcher { contract_address: nonce_address },
    )
}

fn proposal() -> Proposal {
    Proposal {
        collateral_category: MultiToken::Category::ERC1155(()),
        collateral_address: TOKEN(),
        collateral_id: 0,
        min_collateral_amount: 1,
        check_collateral_state_fingerprint: false,
        collateral_state_fingerprint: 'some state fingerprint',
        credit_address: TOKEN(),
        credit_per_collateral_unit: SimpleLoanFungibleProposal::CREDIT_PER_COLLATERAL_UNIT_DENOMINATOR,
        available_credit_limit: 0,
        fixed_interest_amount: 1,
        accruing_interest_APR: 0,
        duration: 1000,
        expiration: 60303,
        allowed_acceptor: starknet::contract_address_const::<0>(),
        proposer: PROPOSER(),
        proposer_spec_hash: 'proposer spec',
        is_offer: true,
        refinancing_loan_id: 0,
        nonce_space: 1,
        nonce: 'nonce_1',
        loan_contract: ACTIVATE_LOAN_CONTRACT(),
    }
}

fn proposal_hash(proposal: Proposal, proposal_address: ContractAddress) -> felt252 {
    let hash_elements = array![BASE_DOMAIN_SEPARATOR, 'name', 'version', proposal_address.into()];
    let domain_separator = poseidon_hash_span(hash_elements.span());

    let mut serialized_proposal = array![];
    proposal.serialize(ref serialized_proposal);

    let mut hash_elements = serialized_proposal;
    hash_elements.append(1901);
    hash_elements.append(domain_separator);
    hash_elements.append(SimpleLoanFungibleProposal::PROPOSAL_TYPEHASH);

    poseidon_hash_span(hash_elements.span())
}

fn update_proposal(
    mut proposal: Proposal,
    mut proposal_values: ProposalValues,
    new_proposal: SimpleLoanProposalComponent::ProposalBase,
) {
    proposal.collateral_address = new_proposal.collateral_address;
    proposal.collateral_id = new_proposal.collateral_id;
    proposal.check_collateral_state_fingerprint = new_proposal.check_collateral_state_fingerprint;
    proposal.collateral_state_fingerprint = new_proposal.collateral_state_fingerprint;
    proposal.available_credit_limit = new_proposal.available_credit_limit;
    proposal.expiration = new_proposal.expiration;
    proposal.allowed_acceptor = new_proposal.allowed_acceptor;
    proposal.proposer = new_proposal.proposer;
    proposal.is_offer = new_proposal.is_offer;
    proposal.refinancing_loan_id = new_proposal.refinancing_loan_id;
    proposal.nonce_space = new_proposal.nonce_space;
    proposal.nonce = new_proposal.nonce;
    proposal.loan_contract = new_proposal.loan_contract;

    proposal_values.collateral_amount = new_proposal.credit_amount;
}

fn call_accept_proposal_with(
    proposal_contract: ISimpleLoanFungibleProposalDispatcher,
    proposal: Proposal,
    proposal_values: ProposalValues,
    params: Params
) {
    update_proposal(proposal, proposal_values, params.base);
    proposal_contract
        .accept_proposal(
            params.acceptor,
            proposal.refinancing_loan_id,
            proposal_contract.encode_proposal_data(proposal, proposal_values),
            proposal_inclusion_proof: params.proposal_inclusion_proof,
            signature: params.signature,
        );
}

fn get_proposal_with(
    proposal_address: ContractAddress,
    mut proposal: Proposal,
    proposal_values: ProposalValues,
    params: Params
) -> felt252 {
    update_proposal(proposal, proposal_values, params.base);
    proposal_hash(proposal, proposal_address)
}

mod pwn_simple_loan_fungible_proposal_test {
    use super::ISimpleLoanFungibleProposalDispatcherTrait;

    #[test]
    fn test_fuzz_should_return_used_credit(used: u128) {
        let (proposal, _, _) = super::deploy();

        let proposal_hash = super::proposal_hash(super::proposal(), proposal.contract_address);

        super::store(
            proposal.contract_address,
            super::map_entry_address(selector!("credit_used"), array![proposal_hash].span(),),
            array![used.into()].span()
        );

        let stored_used: u128 = (*super::load(
            proposal.contract_address,
            super::map_entry_address(selector!("credit_used"), array![proposal_hash].span()),
            1
        )
            .at(0))
            .try_into()
            .unwrap();

        assert_eq!(stored_used, used);
    }

    #[test]
    fn test_should_call_revoke_nonce() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_proposal_hash() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_caller_is_not_proposer() {
        assert(true, '');
    }

    #[test]
    fn test_should_emit_proposal_made() {
        assert(true, '');
    }

    #[test]
    fn test_should_make_proposal() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_encoded_proposal_data() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_decoded_proposal_data() {
        assert(true, '');
    }

    #[test]
    fn test_should_return_credit_amount() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_zero_min_collateral_amount() {
        assert(true, '');
    }

    #[test]
    fn test_should_fail_when_collateral_amount_less_than_min_collateral_amount() {
        assert(true, '');
    }

    #[test]
    fn test_should_call_loan_contract_with_loan_terms() {
        assert(true, '');
    }
}

