use core::{
    starknet,
    starknet::{storage::StorageMapMemberAccessTrait, ContractAddress, get_contract_address},
    poseidon::poseidon_hash_span, traits::Into
};
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
        KeyPairTrait, SignerTrait,
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
    pub proposal_inclusion_proof: Array<felt252>,
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

pub fn get_dummy_message_hash_and_signature() -> (felt252, Signature) {
    let dummy_hash = poseidon_hash_span(array!['dummy'].span());
    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let (r, s): (felt252, felt252) = key_pair.sign(dummy_hash).unwrap();
    (dummy_hash, Signature { pub_key: key_pair.public_key, r, s })
}

pub fn proposal() -> SimpleLoanProposalComponent::ProposalBase {
    SimpleLoanProposalComponent::ProposalBase {
        collateral_address: TOKEN(),
        collateral_id: 0,
        check_collateral_state_fingerprint: true,
        collateral_state_fingerprint: 'some state fingerprint',
        credit_amount: E10,
        available_credit_limit: E10,
        expiration: starknet::get_block_timestamp() + 20 * MINUTE,
        allowed_acceptor: starknet::contract_address_const::<0>(),
        proposer: PROPOSER(),
        is_offer: true,
        refinancing_loan_id: 0,
        nonce_space: 0,
        nonce: 'nonce_1',
        loan_contract: ACTIVATE_LOAN_CONTRACT(),
    }
}

pub fn params() -> Params {
    let (message_hash, signature) = get_dummy_message_hash_and_signature();
    Params {
        base: proposal(),
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

pub fn deploy() -> (
    ComponentState, IPwnHubDispatcher, IPwnConfigDispatcher, IRevokedNonceDispatcher
) {
    let contract = declare("PwnHub").unwrap();
    let (hub_address, _) = contract.deploy(@array![]).unwrap();

    let contract = declare("PwnConfig").unwrap();
    let (config_address, _) = contract.deploy(@array![]).unwrap();

    let contract = declare("RevokedNonce").unwrap();
    let (nonce_address, _) = contract
        .deploy(@array![hub_address.into(), pwn_hub_tags::ACTIVE_LOAN])
        .unwrap();

    let config = IPwnConfigDispatcher { contract_address: config_address };
    config.initialize(get_contract_address(), 100, get_contract_address());

    let mut state = COMPONENT_STATE();
    state._initialize(hub_address, nonce_address, config_address, 'SimpleLoanProposal', 'version');

    let mut hub = IPwnHubDispatcher { contract_address: hub_address };
    hub.set_tag(ACTIVATE_LOAN_CONTRACT(), pwn_hub_tags::ACTIVE_LOAN, true);

    (state, hub, config, IRevokedNonceDispatcher { contract_address: nonce_address },)
}
// is relevant
#[test]
#[ignore]
fn test_should_return_used_credit() {
    assert!(true, "");
}

#[test]
fn test_should_call_revoke_nonce() {
    let (mut component, mut hub, _, mut nonces) = deploy();
    let params = params();

    hub.set_tag(params.base.proposer, pwn_hub_tags::ACTIVE_LOAN, true);

    let mut is_usable = nonces
        .is_nonce_usable(params.base.proposer, params.base.nonce_space, params.base.nonce);

    assert!(is_usable, "Nonce already revoked");
    cheat_caller_address_global(params.base.proposer);
    component.revoke_nonce(params.base.nonce_space, params.base.nonce);
    is_usable = nonces
        .is_nonce_usable(params.base.proposer, params.base.nonce_space, params.base.nonce);
    assert!(!is_usable, "Nonce is usable");
}
// TODO: Write test, proposal_base does not implements serde, should work with dummy hash?
#[test]
#[ignore]
fn test_should_return_proposal_hash() {
    assert!(true, "");
}

#[test]
#[should_panic(expected: "Caller 73661723 is not the stated proposer")]
fn test_should_fail_when_caller_is_not_proposer() {
    let (mut component, _, _, _) = deploy();
    let dummy_hash = poseidon_hash_span(array!['dummy'].span());
    cheat_caller_address_global(PROPOSER());
    component._make_proposal(dummy_hash, starknet::contract_address_const::<'not_proposer'>());
}

#[test]
fn test_should_make_proposal() {
    let (mut component, _, _, _) = deploy();
    let dummy_hash = poseidon_hash_span(array!['dummy'].span());
    let proposer = PROPOSER();
    cheat_caller_address_global(proposer);
    component._make_proposal(dummy_hash, proposer);
    assert!(component.proposal_made.read(dummy_hash), "Proposal not exists");
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_caller_is_not_proposed_loan_contract(_caller: felt252) {
    let (mut component, _, _, _) = deploy();
    let params = params();
    let mut caller: ContractAddress = _caller.try_into().unwrap();
    if caller == params.base.loan_contract {
        caller = (_caller + 1).try_into().unwrap();
    }
    cheat_caller_address_global(caller);
    call_accept_proposal_with(ref component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_caller_not_tagged_active_loan(_caller: felt252) {
    let (mut component, mut hub, _, _) = deploy();
    let params = params();
    let mut caller: ContractAddress = _caller.try_into().unwrap();
    if caller == params.base.loan_contract {
        caller = (_caller + 1).try_into().unwrap();
    }
    hub.set_tag(caller, pwn_hub_tags::ACTIVE_LOAN, false);

    cheat_caller_address_global(caller);
    call_accept_proposal_with(ref component, params);
}

#[test]
#[should_panic(expected: "Proposal acceptor 73661723 is also the proposer")]
fn test_should_fail_when_proposer_is_same_as_acceptor() {
    let (mut component, _, mut config, _) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params();
    params.acceptor = params.base.proposer;
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_invalid_signature_when_eoa(random_private_key: felt252) {
    let (mut component, _, _, _) = deploy();
    let mut params = params();
    let mut key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(random_private_key);
    if key_pair.public_key.try_into().unwrap() == params.base.proposer {
        key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(random_private_key + 1);
    }
    let (r, s): (felt252, felt252) = key_pair.sign(params.message_hash).unwrap();
    params.signature = Signature { pub_key: key_pair.public_key, r, s };

    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_with_invalid_signature_when_eoa_when_multiproposal(
    random_private_key: felt252
) {
    let (mut component, _, _, _) = deploy();
    let mut params = params();

    let mut key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(random_private_key);
    if key_pair.public_key.try_into().unwrap() == params.base.proposer {
        key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(random_private_key + 1);
    }
    let (r, s): (felt252, felt252) = key_pair.sign(params.message_hash).unwrap();
    params.signature = Signature { pub_key: key_pair.public_key, r, s };
    params.proposal_inclusion_proof = array!['first proof', 'second proof'];
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
}

// NotImplemented
#[test]
fn test_should_fail_with_invalid_inclusion_proof() {
    assert!(true, "");
}

#[test]
fn test_should_pass_when_proposal_made_onchain() {
    let (mut component, _, mut config, _) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params();
    // invalidate the signature
    params.signature.r = 'invalid signature';

    cheat_caller_address_global(params.base.proposer);
    component._make_proposal(params.message_hash, params.base.proposer);
    stop_cheat_caller_address_global();

    cheat_caller_address_global(params.base.loan_contract);
    // should pass the signature check
    call_accept_proposal_with(ref component, params);
}

#[test]
fn test_should_pass_with_valid_signature_when_eoa_when_standard_signature() {
    let (mut component, _, mut config, _) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let params = params();
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_proposed_refinancing_loan_id_not_zero_when_refinancing_loan_id_zero(
    mut proposed_refinancing_loan_id: felt252
) {
    let (mut component, _, mut config, _) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params();
    if proposed_refinancing_loan_id == 0 {
        proposed_refinancing_loan_id += 1;
    }
    params.base.refinancing_loan_id = proposed_refinancing_loan_id;

    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
}

#[test]
#[should_panic]
fn test_should_fail_when_refinancing_loan_ids_is_not_equal_when_proposed_refinancing_loan_id_not_zero_when_refinancing_loan_id_not_zero_when_offer(
    mut refinancing_loan_id: felt252, mut proposed_refinancing_loan_id: felt252
) {
    let (mut component, _, mut config, _) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());
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
    let mut params = params();
    params.base.refinancing_loan_id = proposed_refinancing_loan_id;
    params.refinancing_loan_id = refinancing_loan_id;
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
}

#[test]
fn test_fuzz_should_pass_when_refinancing_loan_ids_not_equal_when_proposed_refinancing_loan_id_zero_when_refinancing_loan_id_not_zero_when_offer(
    mut refinancing_loan_id: felt252
) {
    let (mut component, _, mut config, _) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());
    let mut params = params();
    if refinancing_loan_id == 0 {
        refinancing_loan_id += 1;
    }
    params.refinancing_loan_id = refinancing_loan_id;
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_refinancing_loan_ids_not_equal_when_refinancing_loan_id_not_zero_when_request(
    mut refinancing_loan_id: felt252, proposed_refinancing_loan_id: felt252
) {
    let (mut component, _, mut config, _) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params();
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
    call_accept_proposal_with(ref component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_proposal_expired(mut timestamp: u64) {
    let (mut component, _, mut config, _) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());
    let mut params = params();
    if timestamp <= params.base.expiration {
        timestamp += params.base.expiration + 1;
    }

    cheat_caller_address_global(params.base.loan_contract);
    cheat_block_timestamp_global(timestamp);
    call_accept_proposal_with(ref component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_offer_nonce_not_usable(nonce_space: felt252, nonce: felt252) {
    let (mut component, _, mut config, nonces) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params();
    params.base.nonce_space = nonce_space;
    params.base.nonce = nonce;

    mock_call(nonces.contract_address, selector!("is_nonce_usable"), false, 1);

    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_caller_is_not_allowed_acceptor(_caller: felt252) {
    let (mut component, _, mut config, _) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());
    let mut params = params();
    params.base.allowed_acceptor = starknet::contract_address_const::<'allowed_acceptor'>();
    let mut caller: ContractAddress = _caller.try_into().unwrap();
    if caller == params.base.allowed_acceptor {
        caller = (_caller + 1).try_into().unwrap();
    }
    if caller == params.base.proposer {
        caller = (_caller + 1).try_into().unwrap();
    }

    cheat_caller_address_global(caller);
    call_accept_proposal_with(ref component, params);
}

#[test]
fn test_should_revoke_offer_when_available_credit_limit_equal_to_zero() {
    let (mut component, _, mut config, nonces) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params();
    params.base.available_credit_limit = 0;
    let (proposer, nonce_space, nonce) = (
        params.base.proposer, params.base.nonce_space, params.base.nonce
    );
    assert!(nonces.is_nonce_usable(proposer, nonce_space, nonce), "Nonce is not usable");

    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
    assert!(!nonces.is_nonce_usable(proposer, nonce_space, nonce), "Nonce is not revoken");
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_used_credit_exceeds_available_credit_limit(
    used_low: u128, used_high: u128, limit_low: u128, limit_high: u128
) {
    let (mut component, _, mut config, _) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut used_u256 = u256 { low: used_low, high: used_high };
    let mut limit_u256 = u256 { low: limit_low, high: limit_high };
    let mut params = params();
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
    component.credit_used.write(params.message_hash, used_u256);

    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
}

#[test]
fn test_fuzz_should_increase_used_credit_when_used_credit_not_exceeds_available_credit_limit(
    used_low: u128, used_high: u128, limit_low: u128, limit_high: u128
) {
    let (mut component, _, mut config, _) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut used_u256 = u256 { low: used_low, high: used_high };
    let mut limit_u256 = u256 { low: limit_low, high: limit_high };
    let mut params = params();
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
    component.credit_used.write(params.message_hash, used_u256);
    let message_hash = params.message_hash;
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
    let current_credit_used = component.credit_used.read(message_hash);
    assert_eq!(used_u256 + credit_amount, current_credit_used, "Credit used imbalanced");
}
// dont have vm.expectCall equivalent in snforge, ensuring call not happening by not registering SF comp
#[test]
fn test_should_not_call_computer_registry_when_should_not_check_state_fingerprint() {
    let (mut component, _, _, _) = deploy();
    let mut params = params();
    params.base.check_collateral_state_fingerprint = false;

    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
}
// same with any successfull path dont have vm.expectCall equivalent in snforge
#[test]
fn test_should_call_computer_registry_when_should_check_state_fingerprint() {
    let (mut component, _, mut config, _) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let params = params();
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
}

#[test]
#[should_panic(expected: "State fingerprint computer is not registered")]
fn test_should_fail_when_computer_registry_returns_computer_when_computer_fails() {
    let (mut component, _, _, _) = deploy();

    let params = params();
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_computer_registry_returns_computer_when_computer_returns_different_state_fingerprint(
    mut state_finger_print: felt252
) {
    let (mut component, _, mut config, _) = deploy();

    let mut params = params();
    if state_finger_print == params.base.collateral_state_fingerprint {
        state_finger_print += 1;
    }
    mock_call(SF_COMPUTER(), selector!("compute_state_fingerprint"), state_finger_print, 1);
    mock_call(SF_COMPUTER(), selector!("supports_token"), true, 1);

    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
}
// duplicate test with any succesfull path
#[test]
fn test_should_pass_when_computer_returns_matching_fingerprint() {
    let (mut component, _, mut config, _) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let params = params();
    cheat_caller_address_global(params.base.loan_contract);
    call_accept_proposal_with(ref component, params);
}
////////////////////////////////////////// Irrelevants ? ///////////////////////////////////////////
mod irrelevants {
    // is relevant, no events in scope
    #[test]
    #[ignore]
    fn test_should_emit_proposal_made() {
        assert!(true, "");
    }
    // is relevant
    #[test]
    #[ignore]
    fn test_should_return_encoded_proposal_data() {
        assert!(true, "");
    }
    // is relevant
    #[test]
    #[ignore]
    fn test_should_return_decoded_proposal_data() {
        assert!(true, "");
    }
    // is relevant
    // might related to multiproposal verification
    #[test]
    #[ignore]
    fn test_should_accept_any_collateral_id_when_merkle_root_is_zero() {
        assert!(true, "");
    }
    // is relevant
    // might related to multiproposal verification
    #[test]
    #[ignore]
    fn test_should_pass_when_given_collateral_id_is_whitelisted() {
        assert!(true, "");
    }
    // is relevant
    // might related to multiproposal verification
    #[test]
    #[ignore]
    fn test_should_fail_when_given_collateral_id_is_not_whitelisted() {
        assert!(true, "");
    }
    // is relevant
    #[test]
    #[ignore]
    fn test_should_call_loan_contract_with_loan_terms() {
        assert!(true, "");
    }

    // not sure is there any difference between EOA and contract account in current setting we just verify ECDSA
    #[test]
    #[ignore]
    fn test_should_fail_when_invalid_signature_when_contract_account() {
        assert!(true, "");
    }

    // not sure is there any difference between EOA and contract account in current setting we just verify ECDSA
    #[test]
    #[ignore]
    fn test_should_pass_when_valid_signature_when_contract_account() {
        assert!(true, "");
    }

    // is relevant & no fallback to asset for SF for now
    #[test]
    #[ignore]
    fn test_should_fail_when_no_computer_registered_when_asset_does_not_implement_erc165() {
        assert!(true, "");
    }
    // is relevant & no fallback to asset for SF for now
    #[test]
    #[ignore]
    fn test_should_fail_when_no_computer_registered_when_asset_does_not_implement_erc5646() {
        assert!(true, "");
    }
    // is relevant & no fallback to asset for SF for now
    #[test]
    #[ignore]
    fn test_should_fail_when_asset_implements_erc5646_when_computer_returns_different_state_fingerprint() {
        assert!(true, "");
    }

    // is relevant & no fallback to asset for SF for now
    #[test]
    #[ignore]
    fn test_should_pass_when_asset_implements_erc5646_when_returns_matching_fingerprint() {
        assert!(true, "");
    }

    // multiproposal is not implemented yet TODO
    #[test]
    #[ignore]
    fn test_should_pass_with_valid_signature_when_eoa_when_standard_signature_when_multiproposal() {
        assert!(true, "");
    }
    // multiproposal is not implemented yet TODO & currently only support compact signatures
    #[test]
    #[ignore]
    fn test_should_pass_with_valid_signature_when_eoa_when_compact_eip2098_signature_when_multiproposal() {
        assert!(true, "");
    }
    // multiproposal is not implemented yet TODO & currently only support compact signatures
    #[test]
    #[ignore]
    fn test_should_pass_when_valid_signature_when_contract_account_when_multiproposal() {
        assert!(true, "");
    }

    // currently only support compact signatures
    #[test]
    #[ignore]
    fn test_should_pass_with_valid_signature_when_eoa_when_compact_eip2098_signature() {
        assert!(true, "");
    }

    // multiproposal is not implemented yet TODO & currently only support compact signatures
    #[test]
    #[ignore]
    fn test_should_fail_when_invalid_signature_when_contract_account_when_multiproposal() {
        assert!(true, "");
    }
}
