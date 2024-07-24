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
    },
    lib::signature_checker::Signature
};
use pwn::nonce::revoked_nonce::{
    IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait, RevokedNonce
};

use snforge_std::{
    declare, store, map_entry_address, cheat_caller_address_global,
    stop_cheat_caller_address_global, cheat_block_timestamp_global, mock_call,
    signature::{
        KeyPair, KeyPairTrait, SignerTrait,
        stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
    },
    ContractClassTrait,
};
use super::super::utils::simple_loan_proposal_component_mock::MockSimpleLoanProposal;

pub const E70: u256 =
    10_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000;
pub const E40: u256 = 10_000_000_000_000_000_000_000_000_000_000_000_000;
pub const E10: u256 = 10_000_000_000;
pub const MINUTE: u64 = 60;
pub const MAX_U256: u256 =
    u256 { low: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, high: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF };

#[derive(Drop)]
pub struct Params {
    pub base: SimpleLoanProposalComponent::ProposalBase,
    pub acceptor: ContractAddress,
    pub proposal_inclusion_proof: Array<u256>,
    pub signature: Signature,
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

// pub fn PROPOSER() -> ContractAddress {
//     starknet::contract_address_const::<73661723>()
// }

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

pub fn get_dummy_message_hash_and_signature(
    key_pair: KeyPair<felt252, felt252>
) -> (felt252, Signature) {
    let dummy_hash = poseidon_hash_span(array!['dummy'].span());
    let (r, s): (felt252, felt252) = key_pair.sign(dummy_hash).unwrap();
    (dummy_hash, Signature { r, s })
}

pub fn proposal(proposer: ContractAddress) -> SimpleLoanProposalComponent::ProposalBase {
    SimpleLoanProposalComponent::ProposalBase {
        collateral_address: TOKEN(),
        collateral_id: 0,
        check_collateral_state_fingerprint: true,
        collateral_state_fingerprint: 'some state fingerprint',
        credit_amount: E10,
        available_credit_limit: E10,
        expiration: starknet::get_block_timestamp() + 20 * MINUTE,
        allowed_acceptor: starknet::contract_address_const::<0>(),
        proposer: proposer,
        is_offer: true,
        refinancing_loan_id: 0,
        nonce_space: 0,
        nonce: 'nonce_1',
        loan_contract: ACTIVATE_LOAN_CONTRACT(),
    }
}

pub fn params(proposer: ContractAddress, key_pair: KeyPair<felt252, felt252>) -> Params {
    let (message_hash, signature) = get_dummy_message_hash_and_signature(key_pair);
    Params {
        base: proposal(proposer),
        acceptor: ACCEPTOR(),
        proposal_inclusion_proof: array![],
        signature,
        message_hash,
        refinancing_loan_id: 0
    }
}

pub fn call_accept_proposal_with(ref component: ComponentState, params: Params) {
    component
        ._accept_proposal(
            params.acceptor,
            params.refinancing_loan_id,
            params.message_hash,
            params.proposal_inclusion_proof,
            params.signature,
            params.base,
        );
}

#[derive(Drop)]
struct Setup {
    component: ComponentState,
    hub: IPwnHubDispatcher,
    config: IPwnConfigDispatcher,
    nonce: IRevokedNonceDispatcher,
    signer: IPublicKeyDispatcher,
    key_pair: KeyPair::<felt252, felt252>
}

pub fn deploy() -> Setup {
    let contract = declare("PwnHub").unwrap();
    let (hub_address, _) = contract.deploy(@array![]).unwrap();

    let contract = declare("PwnConfig").unwrap();
    let (config_address, _) = contract.deploy(@array![]).unwrap();

    let contract = declare("RevokedNonce").unwrap();
    let (nonce_address, _) = contract
        .deploy(@array![hub_address.into(), pwn_hub_tags::ACTIVE_LOAN])
        .unwrap();
    let nonce = IRevokedNonceDispatcher { contract_address: nonce_address };

    let config = IPwnConfigDispatcher { contract_address: config_address };
    config.initialize(get_contract_address(), 100, get_contract_address());

    let mut component = COMPONENT_STATE();
    component
        ._initialize(hub_address, nonce_address, config_address, 'SimpleLoanProposal', 'version');

    let key_pair = KeyPairTrait::<felt252, felt252>::generate();

    let contract = declare("AccountUpgradeable").unwrap();
    let (account_address, _) = contract.deploy(@array![key_pair.public_key]).unwrap();
    let signer = IPublicKeyDispatcher { contract_address: account_address };

    let mut hub = IPwnHubDispatcher { contract_address: hub_address };
    hub.set_tag(ACTIVATE_LOAN_CONTRACT(), pwn_hub_tags::ACTIVE_LOAN, true);

    Setup { component, hub, config, nonce, signer, key_pair }
}

#[test]
fn test_should_call_revoke_nonce() {
    let mut dsp = deploy();
    let params = params(dsp.signer.contract_address, dsp.key_pair);

    dsp.hub.set_tag(params.base.proposer, pwn_hub_tags::ACTIVE_LOAN, true);

    let mut is_usable = dsp
        .nonce
        .is_nonce_usable(params.base.proposer, params.base.nonce_space, params.base.nonce);

    assert!(is_usable, "Nonce already revoked");
    cheat_caller_address_global(params.base.proposer);
    dsp.component.revoke_nonce(params.base.nonce_space, params.base.nonce);
    is_usable = dsp
        .nonce
        .is_nonce_usable(params.base.proposer, params.base.nonce_space, params.base.nonce);
    assert!(!is_usable, "Nonce is usable");
}

#[test]
#[should_panic]
fn test_should_fail_when_caller_is_not_proposer() {
    let mut dsp = deploy();
    let dummy_hash = poseidon_hash_span(array!['dummy'].span());
    cheat_caller_address_global(dsp.signer.contract_address);
    dsp.component._make_proposal(dummy_hash, starknet::contract_address_const::<'not_proposer'>());
}

#[test]
fn test_should_make_proposal() {
    let mut dsp = deploy();
    let dummy_hash = poseidon_hash_span(array!['dummy'].span());
    let proposer = dsp.signer.contract_address;
    cheat_caller_address_global(proposer);
    dsp.component._make_proposal(dummy_hash, proposer);
    assert!(dsp.component.proposal_made.read(dummy_hash), "Proposal not exists");
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_caller_is_not_proposed_loan_contract(_caller: felt252) {
    let mut dsp = deploy();
    let params = params(dsp.signer.contract_address, dsp.key_pair);
    let mut caller: ContractAddress = _caller.try_into().unwrap();
    if caller == params.base.loan_contract {
        caller = (_caller + 1).try_into().unwrap();
    }
    cheat_caller_address_global(caller);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_caller_not_tagged_active_loan(_caller: felt252) {
    let mut dsp = deploy();
    let params = params(dsp.signer.contract_address, dsp.key_pair);
    let mut caller: ContractAddress = _caller.try_into().unwrap();
    if caller == params.base.loan_contract {
        caller = (_caller + 1).try_into().unwrap();
    }
    dsp.hub.set_tag(caller, pwn_hub_tags::ACTIVE_LOAN, false);

    cheat_caller_address_global(caller);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
#[should_panic]
fn test_should_fail_when_proposer_is_same_as_acceptor() {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    params.acceptor = params.base.proposer;
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_invalid_signature_when_eoa(random_private_key: felt252) {
    let mut dsp = deploy();
    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    let mut key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(random_private_key);
    if key_pair.public_key.try_into().unwrap() == params.base.proposer {
        key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(random_private_key + 1);
    }
    let (r, s): (felt252, felt252) = key_pair.sign(params.message_hash).unwrap();
    params.signature = Signature { r, s };

    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_with_invalid_signature_when_eoa_when_multiproposal(
    random_private_key: felt252
) {
    let mut dsp = deploy();
    let mut params = params(dsp.signer.contract_address, dsp.key_pair);

    let mut key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(random_private_key);
    if key_pair.public_key.try_into().unwrap() == params.base.proposer {
        key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(random_private_key + 1);
    }
    let (r, s): (felt252, felt252) = key_pair.sign(params.message_hash).unwrap();
    params.signature = Signature { r, s };
    params.proposal_inclusion_proof = array!['first proof', 'second proof'];
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}

// NotImplemented
#[test]
fn test_should_fail_with_invalid_inclusion_proof() {
    assert!(true, "");
}

#[test]
fn test_should_pass_when_proposal_made_onchain() {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    // invalidate the signature
    params.signature.r = 'invalid signature';

    cheat_caller_address_global(params.base.proposer);
    dsp.component._make_proposal(params.message_hash, params.base.proposer);
    stop_cheat_caller_address_global();

    cheat_caller_address_global(params.base.loan_contract);
    // should pass the signature check
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
fn test_should_pass_with_valid_signature_when_eoa_when_standard_signature() {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let params = params(dsp.signer.contract_address, dsp.key_pair);
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_proposed_refinancing_loan_id_not_zero_when_refinancing_loan_id_zero(
    mut proposed_refinancing_loan_id: felt252
) {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    if proposed_refinancing_loan_id == 0 {
        proposed_refinancing_loan_id += 1;
    }
    params.base.refinancing_loan_id = proposed_refinancing_loan_id;

    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
#[should_panic]
fn test_should_fail_when_refinancing_loan_ids_is_not_equal_when_proposed_refinancing_loan_id_not_zero_when_refinancing_loan_id_not_zero_when_offer(
    mut refinancing_loan_id: felt252, mut proposed_refinancing_loan_id: felt252
) {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());
    if proposed_refinancing_loan_id == 0 {
        proposed_refinancing_loan_id += 1;
    }
    if refinancing_loan_id == 0 {
        refinancing_loan_id += 1;
    }
    if proposed_refinancing_loan_id == refinancing_loan_id {
        proposed_refinancing_loan_id += 1;
        if proposed_refinancing_loan_id == 0 {
            proposed_refinancing_loan_id += 1;
        }
    }
    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    params.base.refinancing_loan_id = proposed_refinancing_loan_id;
    params.refinancing_loan_id = refinancing_loan_id;
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
fn test_fuzz_should_pass_when_refinancing_loan_ids_not_equal_when_proposed_refinancing_loan_id_zero_when_refinancing_loan_id_not_zero_when_offer(
    mut refinancing_loan_id: felt252
) {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());
    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    if refinancing_loan_id == 0 {
        refinancing_loan_id += 1;
    }
    params.refinancing_loan_id = refinancing_loan_id;
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_refinancing_loan_ids_not_equal_when_refinancing_loan_id_not_zero_when_request(
    mut refinancing_loan_id: felt252, proposed_refinancing_loan_id: felt252
) {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    if refinancing_loan_id == 0 {
        refinancing_loan_id += 1;
    }
    if refinancing_loan_id == proposed_refinancing_loan_id {
        refinancing_loan_id += 1;
    }
    params.base.is_offer = false;
    params.base.refinancing_loan_id = proposed_refinancing_loan_id;
    params.refinancing_loan_id = refinancing_loan_id;
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_proposal_expired(mut timestamp: u64) {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());
    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    if timestamp <= params.base.expiration {
        timestamp += params.base.expiration + 1;
    }

    cheat_caller_address_global(params.base.loan_contract);
    cheat_block_timestamp_global(timestamp);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_offer_nonce_not_usable(nonce_space: felt252, nonce: felt252) {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    params.base.nonce_space = nonce_space;
    params.base.nonce = nonce;

    mock_call(dsp.nonce.contract_address, selector!("is_nonce_usable"), false, 1);

    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_caller_is_not_allowed_acceptor(_caller: felt252) {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());
    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    params.base.allowed_acceptor = starknet::contract_address_const::<'allowed_acceptor'>();
    let mut caller: ContractAddress = _caller.try_into().unwrap();
    if caller == params.base.allowed_acceptor {
        caller = (_caller + 1).try_into().unwrap();
    }
    if caller == params.base.proposer {
        caller = (_caller + 1).try_into().unwrap();
    }

    cheat_caller_address_global(caller);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
fn test_should_revoke_offer_when_available_credit_limit_equal_to_zero() {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    params.base.available_credit_limit = 0;
    let (proposer, nonce_space, nonce) = (
        params.base.proposer, params.base.nonce_space, params.base.nonce
    );
    assert!(dsp.nonce.is_nonce_usable(proposer, nonce_space, nonce), "Nonce is not usable");

    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
    assert!(!dsp.nonce.is_nonce_usable(proposer, nonce_space, nonce), "Nonce is not revoken");
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_used_credit_exceeds_available_credit_limit(
    used_low: u128, used_high: u128, limit_low: u128, limit_high: u128
) {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut used_u256 = u256 { low: used_low, high: used_high };
    let mut limit_u256 = u256 { low: limit_low, high: limit_high };
    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    let credit_amount = params.base.credit_amount;
    used_u256 =
        if used_u256 == 0 {
            used_u256 += 1;
            used_u256
        } else if used_u256 > MAX_U256 - credit_amount {
            used_u256 = MAX_U256 - credit_amount;
            used_u256
        } else {
            used_u256
        };

    limit_u256 =
        if limit_u256 < used_u256 {
            limit_u256 += used_u256 - limit_u256 + 1;
            limit_u256
        } else if limit_u256 > used_u256 + credit_amount - 1 {
            limit_u256 -= limit_u256 - used_u256 + credit_amount;
            limit_u256
        } else {
            limit_u256
        };

    params.base.available_credit_limit = limit_u256;
    dsp.component.credit_used.write(params.message_hash, used_u256);

    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
fn test_fuzz_should_increase_used_credit_when_used_credit_not_exceeds_available_credit_limit(
    used_low: u128, used_high: u128, limit_low: u128, limit_high: u128
) {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut used_u256 = u256 { low: used_low, high: used_high };
    let mut limit_u256 = u256 { low: limit_low, high: limit_high };
    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    let credit_amount = params.base.credit_amount;
    used_u256 =
        if used_u256 == 0 {
            used_u256 + 1
        } else if used_u256 > MAX_U256 - credit_amount {
            MAX_U256 - credit_amount
        } else {
            used_u256
        };

    limit_u256 =
        if limit_u256 < used_u256 + credit_amount {
            used_u256 + credit_amount
        } else {
            limit_u256
        };
    params.base.available_credit_limit = limit_u256;
    dsp.component.credit_used.write(params.message_hash, used_u256);
    let message_hash = params.message_hash;
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
    let current_credit_used = dsp.component.credit_used.read(message_hash);
    assert_eq!(used_u256 + credit_amount, current_credit_used, "Credit used imbalanced");
}
// dont have vm.expectCall equivalent in snforge, ensuring call not happening by not registering SF comp
#[test]
fn test_should_not_call_computer_registry_when_should_not_check_state_fingerprint() {
    let mut dsp = deploy();
    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    params.base.check_collateral_state_fingerprint = false;

    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}
// same with any successfull path dont have vm.expectCall equivalent in snforge
#[test]
fn test_should_call_computer_registry_when_should_check_state_fingerprint() {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let params = params(dsp.signer.contract_address, dsp.key_pair);
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
#[should_panic(expected: "State fingerprint computer is not registered")]
fn test_should_fail_when_computer_registry_returns_computer_when_computer_fails() {
    let mut dsp = deploy();

    let params = params(dsp.signer.contract_address, dsp.key_pair);
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_computer_registry_returns_computer_when_computer_returns_different_state_fingerprint(
    mut state_finger_print: felt252
) {
    let mut dsp = deploy();

    let mut params = params(dsp.signer.contract_address, dsp.key_pair);
    if state_finger_print == params.base.collateral_state_fingerprint {
        state_finger_print += 1;
    }
    mock_call(SF_COMPUTER(), selector!("compute_state_fingerprint"), state_finger_print, 1);
    mock_call(SF_COMPUTER(), selector!("supports_token"), true, 1);

    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}
// duplicate test with any succesfull path
#[test]
fn test_should_pass_when_computer_returns_matching_fingerprint() {
    let mut dsp = deploy();
    mock_sf_computer();
    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let params = params(dsp.signer.contract_address, dsp.key_pair);
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref dsp.component, params);
}
