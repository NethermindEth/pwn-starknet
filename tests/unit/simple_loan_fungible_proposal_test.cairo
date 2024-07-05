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
    spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait, cheat_block_timestamp_global
};
use starknet::secp256k1::{Secp256k1Point};
use starknet::{ContractAddress, testing};
use super::simple_loan_proposal_test::{
    TOKEN, PROPOSER, ACTIVATE_LOAN_CONTRACT, ACCEPTOR, Params, E70, E40
};

#[starknet::interface]
pub trait ISimpleLoanFungibleProposal<TState> {
    fn make_proposal(ref self: TState, proposal: Proposal) -> felt252;
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

fn proposal_values() -> ProposalValues {
    ProposalValues { collateral_amount: 10_000 }
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


#[test]
fn test_fuzz_should_return_used_credit(used: u128) {
    let (proposal, _, _) = deploy();

    let proposal_hash = proposal_hash(proposal(), proposal.contract_address);

    store(
        proposal.contract_address,
        map_entry_address(selector!("credit_used"), array![proposal_hash].span(),),
        array![used.into()].span()
    );

    let stored_used: u128 = (*load(
        proposal.contract_address,
        map_entry_address(selector!("credit_used"), array![proposal_hash].span()),
        1
    )
        .at(0))
        .try_into()
        .unwrap();

    assert_eq!(stored_used, used);
}

#[test]
fn test_should_call_revoke_nonce(caller: u128, nonce_space: felt252, nonce: felt252) {
    let (proposal, hub, _) = deploy();

    let caller: felt252 = caller.try_into().unwrap();

    store(
        hub.contract_address,
        map_entry_address(
            selector!("tags"),
            array![proposal.contract_address.into(), pwn_hub_tags::ACTIVE_LOAN].span(),
        ),
        array![true.into()].span()
    );

    start_cheat_caller_address(proposal.contract_address, caller.try_into().unwrap());
    proposal.revoke_nonce(nonce_space, nonce);
}

#[test]
fn test_should_return_proposal_hash() {
    let (proposal, _, _) = deploy();

    let proposal_hash = proposal_hash(proposal(), proposal.contract_address);

    assert_eq!(proposal.get_proposal_hash(proposal()), proposal_hash);
}

#[test]
#[should_panic()]
fn test_fuzz_should_fail_when_caller_is_not_proposer(_proposer: felt252) {
    let (proposal, _, _) = deploy();

    let mut proposer: ContractAddress = _proposer.try_into().unwrap();
    if proposer == proposal().proposer {
        proposer = (_proposer + 1).try_into().unwrap();
    }

    start_cheat_caller_address(proposal.contract_address, proposer);
    proposal.make_proposal(proposal());
}

#[test]
fn test_should_emit_proposal_made() {
    let (proposal, _, _) = deploy();

    let mut spy = spy_events();

    start_cheat_caller_address(proposal.contract_address, proposal().proposer);
    proposal.make_proposal(proposal());

    spy
        .assert_emitted(
            @array![
                (
                    proposal.contract_address,
                    SimpleLoanFungibleProposal::Event::ProposalMade(
                        SimpleLoanFungibleProposal::ProposalMade {
                            proposal_hash: proposal_hash(proposal(), proposal.contract_address),
                            proposer: proposal().proposer,
                            proposal: proposal()
                        }
                    )
                )
            ]
        );
}

#[test]
fn test_should_make_proposal() {
    let (proposal, _, _) = deploy();

    start_cheat_caller_address(proposal.contract_address, proposal().proposer);
    proposal.make_proposal(proposal());

    let proposal_hash = proposal_hash(proposal(), proposal.contract_address);

    let proposal_made = (*load(
        proposal.contract_address,
        map_entry_address(selector!("proposal_made"), array![proposal_hash].span()),
        1
    )
        .at(0));

    assert_eq!(proposal_made, 1);
}

#[test]
fn test_should_return_encoded_proposal_data() {
    let (proposal, _, _) = deploy();

    let encoded_data = proposal.encode_proposal_data(proposal(), proposal_values());

    let mut serialized_proposal = array![];
    proposal().serialize(ref serialized_proposal);

    let mut serialized_proposal_values = array![];
    proposal_values().serialize(ref serialized_proposal_values);

    let expected = serialization::serde_concat(
        serialized_proposal.span(), serialized_proposal_values.span()
    );

    assert_eq!(encoded_data, expected);
}

#[test]
fn test_should_return_decoded_proposal_data() {
    let (proposal, _, _) = deploy();

    let encoded_data = proposal.encode_proposal_data(proposal(), proposal_values());

    let (decoded_proposal, decoded_proposal_values) = proposal.decode_proposal_data(encoded_data);

    assert_eq!(decoded_proposal.collateral_category, proposal().collateral_category);
    assert_eq!(decoded_proposal.collateral_address, proposal().collateral_address);
    assert_eq!(decoded_proposal.collateral_id, proposal().collateral_id);
    assert_eq!(decoded_proposal.min_collateral_amount, proposal().min_collateral_amount);
    assert_eq!(
        decoded_proposal.check_collateral_state_fingerprint,
        proposal().check_collateral_state_fingerprint
    );
    assert_eq!(
        decoded_proposal.collateral_state_fingerprint, proposal().collateral_state_fingerprint
    );
    assert_eq!(decoded_proposal.credit_address, proposal().credit_address);
    assert_eq!(decoded_proposal.credit_per_collateral_unit, proposal().credit_per_collateral_unit);
    assert_eq!(decoded_proposal.available_credit_limit, proposal().available_credit_limit);
    assert_eq!(decoded_proposal.fixed_interest_amount, proposal().fixed_interest_amount);
    assert_eq!(decoded_proposal.accruing_interest_APR, proposal().accruing_interest_APR);
    assert_eq!(decoded_proposal.duration, proposal().duration);
    assert_eq!(decoded_proposal.expiration, proposal().expiration);
    assert_eq!(decoded_proposal.allowed_acceptor, proposal().allowed_acceptor);
    assert_eq!(decoded_proposal.proposer, proposal().proposer);
    assert_eq!(decoded_proposal.proposer_spec_hash, proposal().proposer_spec_hash);
    assert_eq!(decoded_proposal.is_offer, proposal().is_offer);
    assert_eq!(decoded_proposal.refinancing_loan_id, proposal().refinancing_loan_id);
    assert_eq!(decoded_proposal.nonce_space, proposal().nonce_space);
    assert_eq!(decoded_proposal.nonce, proposal().nonce);
    assert_eq!(decoded_proposal.loan_contract, proposal().loan_contract);

    assert_eq!(decoded_proposal_values.collateral_amount, proposal_values().collateral_amount);
}

#[test]
fn test_should_return_credit_amount(
    mut collateral_amount: u256, mut credit_per_collateral_unit: u256
) {
    let (proposal, _, _) = deploy();

    if collateral_amount > E70 {
        collateral_amount = E70;
    }

    if collateral_amount == 0 {
        if credit_per_collateral_unit < 1 {
            credit_per_collateral_unit = 1;
        } else if credit_per_collateral_unit > BoundedInt::max() {
            credit_per_collateral_unit = BoundedInt::max();
        }
    } else {
        let max_credit_per_unit = BoundedInt::max() / collateral_amount;
        if credit_per_collateral_unit < 1 {
            credit_per_collateral_unit = 1;
        } else if (credit_per_collateral_unit > max_credit_per_unit) {
            credit_per_collateral_unit = max_credit_per_unit;
        }
    }

    let credit_amount = proposal.get_credit_amount(collateral_amount, credit_per_collateral_unit);

    let expected = (collateral_amount * credit_per_collateral_unit)
        / SimpleLoanFungibleProposal::CREDIT_PER_COLLATERAL_UNIT_DENOMINATOR;

    assert_eq!(credit_amount, expected);
}

#[test]
#[should_panic()]
fn test_should_fail_when_zero_min_collateral_amount() {
    let (proposal, _, _) = deploy();

    let mut _proposal = proposal();
    _proposal.min_collateral_amount = 0;

    let proposal_hash = proposal.get_proposal_hash(_proposal);

    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let (r, s): (felt252, felt252) = key_pair.sign(proposal_hash).unwrap();

    let signature = Signature { pub_key: key_pair.public_key, r, s, };

    start_cheat_caller_address(proposal.contract_address, _proposal.proposer);
    proposal
        .accept_proposal(
            ACCEPTOR(),
            0,
            proposal.encode_proposal_data(_proposal, proposal_values()),
            array![],
            signature
        );
}

#[test]
#[should_panic()]
fn test_should_fail_when_collateral_amount_less_than_min_collateral_amount(
    min_collateral_amount: u256, collateral_amount: u256
) {
    let (proposal, _, _) = deploy();

    let mut _proposal = proposal();
    let mut _proposal_values = proposal_values();

    if min_collateral_amount == 0 {
        _proposal.min_collateral_amount = 1;
    } else {
        _proposal.min_collateral_amount = min_collateral_amount;
    }

    if collateral_amount > min_collateral_amount {
        _proposal_values.collateral_amount = _proposal.min_collateral_amount - 1;
    } else {
        _proposal_values.collateral_amount = collateral_amount;
    }

    let proposal_hash = proposal.get_proposal_hash(_proposal);

    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let (r, s): (felt252, felt252) = key_pair.sign(proposal_hash).unwrap();

    let signature = Signature { pub_key: key_pair.public_key, r, s, };

    start_cheat_caller_address(proposal.contract_address, ACTIVATE_LOAN_CONTRACT());
    proposal
        .accept_proposal(
            ACCEPTOR(),
            0,
            proposal.encode_proposal_data(_proposal, _proposal_values),
            array![],
            signature
        );
}

#[test]
fn test_should_call_loan_contract_with_loan_terms( // collateral_amount: u256, credit_per_collateral_unit: u256
) {
    let collateral_amount: u256 = 1000000;
    let credit_per_collateral_unit: u256 = 1000000;

    let (proposal, hub, _) = deploy();

    let mut _proposal = proposal();
    let mut _proposal_values = proposal_values();

    if (collateral_amount < _proposal.min_collateral_amount) {
        _proposal_values.collateral_amount = _proposal.min_collateral_amount;
    } else if (collateral_amount > E40) {
        _proposal_values.collateral_amount = E40;
    } else {
        _proposal_values.collateral_amount = collateral_amount;
    }

    let max_credit_per_unit = BoundedInt::max() / _proposal_values.collateral_amount;
    if (credit_per_collateral_unit < 1) {
        _proposal.credit_per_collateral_unit = 1;
    } else if (credit_per_collateral_unit > max_credit_per_unit) {
        _proposal.credit_per_collateral_unit = max_credit_per_unit;
    } else {
        _proposal.credit_per_collateral_unit = credit_per_collateral_unit;
    }

    _proposal.is_offer = true;

    store(
        hub.contract_address,
        map_entry_address(
            selector!("tags"),
            array![_proposal.loan_contract.into(), pwn_hub_tags::ACTIVE_LOAN].span(),
        ),
        array![true.into()].span()
    );

    store(
        hub.contract_address,
        map_entry_address(
            selector!("tags"),
            array![proposal.contract_address.into(), pwn_hub_tags::ACTIVE_LOAN].span(),
        ),
        array![true.into()].span()
    );

    start_cheat_caller_address(proposal.contract_address, ACTIVATE_LOAN_CONTRACT());

    let proposal_hash = proposal.get_proposal_hash(_proposal);

    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let (r, s): (felt252, felt252) = key_pair.sign(proposal_hash).unwrap();

    let signature = Signature { pub_key: key_pair.public_key, r, s, };

    let (proposal_hash, terms) = proposal
        .accept_proposal(
            ACCEPTOR(),
            0,
            proposal.encode_proposal_data(_proposal, _proposal_values),
            array![],
            signature
        );

    assert_eq!(proposal_hash, proposal.get_proposal_hash(_proposal));
    assert_eq!(terms.lender, if _proposal.is_offer {
        PROPOSER()
    } else {
        ACCEPTOR()
    });
    assert_eq!(terms.borrower, if _proposal.is_offer {
        ACCEPTOR()
    } else {
        PROPOSER()
    });
    assert_eq!(terms.duration, _proposal.duration);
    assert_eq!(terms.collateral.category, _proposal.collateral_category);
    assert_eq!(terms.collateral.asset_address, _proposal.collateral_address);
    assert_eq!(terms.collateral.id, _proposal.collateral_id);
    assert_eq!(terms.collateral.amount, _proposal_values.collateral_amount);
    assert_eq!(terms.credit.category, MultiToken::Category::ERC20(()));
    assert_eq!(terms.credit.asset_address, _proposal.credit_address);
    assert_eq!(terms.credit.id, 0);
    assert_eq!(terms.credit.amount, _proposal.available_credit_limit);
    assert_eq!(terms.fixed_interest_amount, _proposal.fixed_interest_amount);
    assert_eq!(terms.accruing_interest_apr, _proposal.accruing_interest_APR);
    assert_eq!(
        terms.lender_spec_hash, if _proposal.is_offer {
            _proposal.proposer_spec_hash
        } else {
            0
        }
    );
    assert_eq!(
        terms.borrower_spec_hash, if _proposal.is_offer {
            0
        } else {
            _proposal.proposer_spec_hash
        }
    );
}

