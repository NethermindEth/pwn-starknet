use snforge_std::signature::SignerTrait;
use core::starknet;
use core::starknet::storage::StorageMapMemberAccessTrait;
use pwn::loan::terms::simple::proposal::simple_loan_proposal::ISimpleLoanProposal;
use core::traits::Into;
use core::poseidon::poseidon_hash_span;
use snforge_std::signature::KeyPairTrait;
use snforge_std::signature::stark_curve::{
    StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl
};
use pwn::loan::terms::simple::proposal::simple_loan_proposal::SimpleLoanProposalComponent::InternalTrait;
use pwn::loan::lib::signature_checker::Signature;
use pwn::loan::terms::simple::proposal::simple_loan_proposal::SimpleLoanProposalComponent;
use  super::super::utils::simple_loan_proposal_component_mock::MockSimpleLoanProposal;
use pwn::config::interface::{IPwnConfigDispatcher, IPwnConfigDispatcherTrait};
use pwn::hub::{pwn_hub_tags, pwn_hub::{IPwnHubDispatcher, IPwnHubDispatcherTrait}};
use pwn::interfaces::fingerprint_computer::{
    IStateFingerpringComputerDispatcher, IStateFingerpringComputerDispatcherTrait
};
use pwn::nonce::revoked_nonce::{
    IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait, RevokedNonce
};
use starknet::ContractAddress;
use starknet::get_contract_address;

use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, cheat_caller_address_global,
    stop_cheat_caller_address_global, spy_events, EventSpy, EventSpyTrait, 
    EventSpyAssertionsTrait, cheat_block_timestamp_global, mock_call
};

pub const E70: u256 =
    10_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000_000;
pub const E40: u256 = 10_000_000_000_000_000_000_000_000_000_000_000_000;
// use params instead of proposal
#[derive(Drop)]
pub struct Params {
    pub base: SimpleLoanProposalComponent::ProposalBase,
    pub acceptor: ContractAddress,
    pub proposal_inclusion_proof: Array<felt252>,
    pub signature: Signature,
    pub message_hash: felt252
}

type ComponentState = SimpleLoanProposalComponent::ComponentState<MockSimpleLoanProposal::ContractState>;

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
    mock_call(
        SF_COMPUTER(), 
        selector!("compute_state_fingerprint"), 
        'some state fingerprint', 
        1
    );
    mock_call(
        SF_COMPUTER(), 
        selector!("supports_token"), 
        true, 
        1
    );
}

pub fn proposal() -> SimpleLoanProposalComponent::ProposalBase {
    SimpleLoanProposalComponent::ProposalBase{
        collateral_address: TOKEN(),
        collateral_id: 0,
        check_collateral_state_fingerprint: true,
        collateral_state_fingerprint: 'some state fingerprint',
        credit_amount: 1,
        available_credit_limit: 1,
        expiration: starknet::get_block_timestamp() + 86400_u64,
        allowed_acceptor: starknet::contract_address_const::<0>(),
        proposer: PROPOSER(),
        is_offer: true,
        refinancing_loan_id: 0,
        nonce_space: 0,
        nonce: 'nonce_1',
        loan_contract: ACTIVATE_LOAN_CONTRACT(),
    }
}

pub fn get_dummy_message_hash_and_signature() -> (felt252, Signature) {
    let dummy_hash = poseidon_hash_span(array!['dummy'].span());
    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let (r, s): (felt252, felt252) = key_pair.sign(dummy_hash).unwrap();
    (dummy_hash, Signature{ pub_key: key_pair.public_key, r, s})
}

pub fn params() -> Params {
    let ( message_hash, signature) = get_dummy_message_hash_and_signature();
    Params {
        base: proposal(),
        acceptor: ACCEPTOR(),
        proposal_inclusion_proof: array!['first_proof', 'second_proof'],
        signature,
        message_hash
    }
}
pub fn deploy() -> (
    ComponentState,
    IPwnHubDispatcher, 
    IPwnConfigDispatcher, 
    IRevokedNonceDispatcher
) {
    let contract = declare("PwnHub").unwrap();
    let (hub_address, _) = contract.deploy(@array![]).unwrap();

    let contract = declare("PwnConfig").unwrap();
    let (config_address, _) = contract.deploy(@array![]).unwrap();

    let contract = declare("RevokedNonce").unwrap();
    let (nonce_address, _) = contract
        .deploy(@array![hub_address.into(), pwn_hub_tags::ACTIVE_LOAN])
        .unwrap();

    let config = IPwnConfigDispatcher {contract_address: config_address};
    config.initialize(get_contract_address(), 100, get_contract_address());

    let mut state = COMPONENT_STATE();
    state._initialize(
        hub_address, 
        nonce_address, 
        config_address, 
        'SimpleLoanProposal', 
        'version'
    );

    let mut hub = IPwnHubDispatcher {contract_address: hub_address};
    hub.set_tag(
        ACTIVATE_LOAN_CONTRACT(),
        pwn_hub_tags::ACTIVE_LOAN,
        true
    );

    (
        state,
        hub, 
        config, 
        IRevokedNonceDispatcher{contract_address: nonce_address},
    )
}
// is relevant
#[test]
#[ignore]
fn test_should_return_used_credit() {
    assert!(true, "");
}

#[test]
fn test_should_call_revoke_nonce() {
    let ( mut component, mut hub, _, mut nonces ) = deploy();
    let params = params();

    hub.set_tag(
        params.base.proposer,
        pwn_hub_tags::ACTIVE_LOAN,
        true
    );
    
    let mut is_usable = nonces.is_nonce_usable(
        params.base.proposer,
        params.base.nonce_space, 
        params.base.nonce
    );

    assert!(is_usable, "Nonce already revoked");
    cheat_caller_address_global(params.base.proposer);
    component.revoke_nonce(params.base.nonce_space, params.base.nonce);
    is_usable = nonces.is_nonce_usable(
        params.base.proposer,
        params.base.nonce_space, 
        params.base.nonce
    );
    assert!(!is_usable, "Nonce is usable");
}
// TODO: Write test
#[test]
fn test_should_return_proposal_hash() {
    assert!(true, "");
}

#[test]
// make this parametric
#[should_panic(expected: "Caller 73661723 is not the stated proposer")]
fn test_should_fail_when_caller_is_not_proposer() {
    let ( mut component, _, _, _ ) = deploy();
    let dummy_hash = poseidon_hash_span(array!['dummy'].span());
    cheat_caller_address_global(PROPOSER());
    component._make_proposal(dummy_hash, starknet::contract_address_const::<'not_proposer'>());
}

#[test]
fn test_should_make_proposal() {
    let ( mut component, _, _, _ ) = deploy();
    let dummy_hash = poseidon_hash_span(array!['dummy'].span());
    let proposer = PROPOSER();
    cheat_caller_address_global(proposer);
    component._make_proposal(dummy_hash, proposer);
    assert!(component.proposal_made.read(dummy_hash), "Proposal not exists");
}

////////////////////////////// Accept Proposal //////////////////////////////
#[test]
#[should_panic(expected: "Caller 32716637 is not the loan contract 8483734427745948062160003932684738441077620")]
fn test_should_fail_when_caller_is_not_proposed_loan_contract() {
    let ( mut component, _, _, _ ) = deploy();

    let params = params();
    cheat_caller_address_global(ACCEPTOR());
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
#[should_panic(expected: "Address 8483734427745948062160003932684738441077620 is missing a PWN Hub tag. Tag: 1058189804181510975916798832338785236527145775971845688777453670043630974356")]
fn test_should_fail_when_caller_not_tagged_active_loan() {
    let ( mut component, mut hub, _, _ ) = deploy();    
    let params = params();
    hub.set_tag(params.base.loan_contract, pwn_hub_tags::ACTIVE_LOAN, false);

    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
#[should_panic(expected: "Proposal acceptor 73661723 is also the proposer")]
fn test_should_fail_when_proposer_is_same_as_acceptor() {
    let ( mut component, _, mut config, _ ) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params();
    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.base.proposer,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
// make explicit assertion
//#[should_panic(expected: "Invalid signature. Signer: 73661723, Digest: {:?}")]
#[should_panic()]
fn test_should_fail_when_invalid_signature_when_eoa() {
    let ( mut component, _, _, _ ) = deploy();
    let mut params = params();
    params.signature.pub_key = starknet::contract_address_const::<'anotherAddress'>().into();

    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
#[should_panic]
fn test_should_fail_with_invalid_signature_when_eoa_when_multiproposal() {
    let ( mut component, _, _, _ ) = deploy();
    let params = params();

    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        params.proposal_inclusion_proof,
        params.signature,
        params.base,
    );
}

// NotImplemented
#[test]
fn test_should_fail_with_invalid_inclusion_proof() {
    assert!(true, "");
}

#[test]
fn test_should_pass_when_proposal_made_onchain() {
    let ( mut component, _, mut config, _ ) = deploy();
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
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
fn test_should_pass_with_valid_signature_when_eoa_when_standard_signature() {
    let ( mut component, _, mut config, _) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let params = params();
    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
#[should_panic(expected: "Provided refinance loan ID 1 cannot be used")]
fn test_should_fail_when_proposed_refinancing_loan_id_not_zero_when_refinancing_loan_id_zero() {
    let ( mut component, _, mut config, _ ) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());
    
    let mut params = params();
    params.base.refinancing_loan_id = 1;
  
    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
#[should_panic(expected: "Provided refinance loan ID 1 cannot be used")]
fn test_should_fail_when_refinancing_loan_ids_is_not_equal_when_proposed_refinancing_loan_id_not_zero_when_refinancing_loan_id_not_zero_when_offer() {
    let ( mut component, _, mut config, _ ) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());
  
    let mut params = params();
    params.base.refinancing_loan_id = 1;

    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        2,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
fn test_should_pass_when_refinancing_loan_ids_not_equal_when_proposed_refinancing_loan_id_zero_when_refinancing_loan_id_not_zero_when_offer() {
    let ( mut component, _, mut config, _ ) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params();

    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        2,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
#[should_panic(expected: "Provided refinance loan ID 0 cannot be used")]
fn test_should_fail_when_refinancing_loan_ids_not_equal_when_refinancing_loan_id_not_zero_when_request() {
    let ( mut component, _, mut config, _ ) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params();
    params.base.is_offer = false;

    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        2,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
#[should_panic(expected: "Expired. Current timestamp: 86401, Expiration: 86400")]
fn test_should_fail_when_proposal_expired() {
    let ( mut component, _, mut config, _ ) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());
    
    let mut params = params();
    cheat_caller_address_global(params.base.loan_contract);
    cheat_block_timestamp_global(params.base.expiration + 1);
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
#[should_panic(expected: "Nonce not usable. Address: 73661723, Nonce Space: 0, Nonce: 31084767342845745")]
fn test_should_fail_when_offer_nonce_not_usable() {
    let ( mut component, mut hub, mut config, _ ) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params();
    hub.set_tag(
        params.base.proposer,
        pwn_hub_tags::ACTIVE_LOAN,
        true
    );
    
    cheat_caller_address_global(params.base.proposer);
    component.revoke_nonce(params.base.nonce_space, params.base.nonce);
    stop_cheat_caller_address_global();

    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
#[should_panic(expected: "Caller 32716637 is not the allowed acceptor 129498082983373126191925514260792504178")]
fn test_should_fail_when_caller_is_not_allowed_acceptor() {
    let ( mut component, _, mut config, _ ) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params();
    params.base.allowed_acceptor = starknet::contract_address_const::<'allowed_acceptor'>();

    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
fn test_should_revoke_offer_when_available_credit_limit_equal_to_zero() {
    let ( mut component, _, mut config, nonces ) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params();
    params.base.available_credit_limit = 0;
    let (proposer, nonce_space, nonce) = (params.base.proposer, params.base.nonce_space, params.base.nonce);
    assert!(nonces.is_nonce_usable(proposer, nonce_space, nonce), "Nonce is not usable");
    
    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
    assert!(!nonces.is_nonce_usable(proposer, nonce_space, nonce), "Nonce is not revoken");
}

#[test]
#[should_panic(expected: "Available credit limit exceeded. Used: 0, Limit: 1")]
fn test_should_fail_when_used_credit_exceeds_available_credit_limit() {
    let ( mut component, _, mut config, _ ) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params();
    params.base.credit_amount = 2;

    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
fn test_should_increase_used_credit_when_used_credit_not_exceeds_available_credit_limit() {
    let ( mut component, _, mut config, _ ) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());
    
    let params = params();
    let original_credit_used = component.credit_used.read(params.message_hash);
    let credit_amount = params.base.credit_amount;

    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
    let current_credit_used = component.credit_used.read(params.message_hash);
    assert_eq!(original_credit_used + credit_amount, current_credit_used, "Credit used imbalanced");
    
}

#[test]
fn test_should_not_call_computer_registry_when_should_not_check_state_fingerprint() {
    let ( mut component, _, _, _ ) = deploy();
    let mut params = params();
    params.base.check_collateral_state_fingerprint = false;

    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        2,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
fn test_should_call_computer_registry_when_should_check_state_fingerprint() {
    let ( mut component, _, mut config, _ ) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let params = params();
    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
#[should_panic(expected: "State fingerprint computer is not registered")]
fn test_should_fail_when_computer_registry_returns_computer_when_computer_fails() {
    let ( mut component, _, _, _ ) = deploy();
    
    let params = params();
    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

#[test]
#[should_panic(expected: "Invalid collateral state fingerprint. Current: 11440750905944445611418458124558729561182892454333476468, Proposed: 43189459419961677304411482929265062128274883280989812")]
fn test_should_fail_when_computer_registry_returns_computer_when_computer_returns_different_state_fingerprint() {
    let ( mut component, _, mut config, _ ) = deploy();
    mock_call(
        SF_COMPUTER(), 
        selector!("compute_state_fingerprint"), 
        'wrong state fingerprint', 
        1
    );
    mock_call(
        SF_COMPUTER(), 
        selector!("supports_token"), 
        true, 
        1
    );

    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let mut params = params();
    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        2,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}

// duplicate test with any succesfull path
#[test]
fn test_should_pass_when_computer_returns_matching_fingerprint() {
    let ( mut component, _, mut config, _ ) = deploy();
    mock_sf_computer();
    config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    let params = params();
    cheat_caller_address_global(params.base.loan_contract);
    component._accept_proposal(
        params.acceptor,
        0,
        params.message_hash,
        array![],
        params.signature,
        params.base,
    );
}
////////////////////////////////////////// Irrelevants //////////////////////////////////////////
#[cfg(test)]
mod irrelevants {
    #[test]
    #[ignore]
    fn test_should_emit_proposal_made() {
        assert!(true, "");
    }

    #[test]
    #[ignore]
    fn test_should_return_encoded_proposal_data() {
        assert!(true, "");
    }

    #[test]
    #[ignore]
    fn test_should_return_decoded_proposal_data() {
        assert!(true, "");
    }

    #[test]
    #[ignore]
    fn test_should_accept_any_collateral_id_when_merkle_root_is_zero() {
        assert!(true, "");
    }

    #[test]
    #[ignore]
    fn test_should_pass_when_given_collateral_id_is_whitelisted() {
        assert!(true, "");
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_given_collateral_id_is_not_whitelisted() {
        assert!(true, "");
    }

    #[test]
    #[ignore]
    fn test_should_call_loan_contract_with_loan_terms() {
        assert!(true, "");
    } 

    // does it differ
    #[test]
    #[ignore]
    fn test_should_fail_when_invalid_signature_when_contract_account() {
        assert!(true, "");
    }

    // not sure is there any difference between EOA and C account it just verifies ECDS
    #[test]
    #[ignore]
    fn test_should_pass_when_valid_signature_when_contract_account() {
        assert!(true, "");
    }

    // is relevant?
    #[test]
    #[ignore]
    fn test_should_fail_when_no_computer_registered_when_asset_does_not_implement_erc165() {
        assert!(true, "");
    }
    // is relevant?
    #[test]
    #[ignore]
    fn test_should_fail_when_no_computer_registered_when_asset_does_not_implement_erc5646() {
        assert!(true, "");
    }
    // is relevant?
    #[test]
    #[ignore]
    fn test_should_fail_when_asset_implements_erc5646_when_computer_returns_different_state_fingerprint() {
        assert!(true, "");
    }

    // is relevant
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
    // multiproposal is not implemented yet TODO
    #[test]
    #[ignore]
    fn test_should_pass_with_valid_signature_when_eoa_when_compact_eip2098_signature_when_multiproposal() {
        assert!(true, "");
    }
    // multiproposal is not implemented yet TODO
    #[test]
    #[ignore]
    fn test_should_pass_when_valid_signature_when_contract_account_when_multiproposal() {
        assert!(true, "");
    }

    // seems like we only support compact signatures
    #[test]
    #[ignore]
    fn test_should_pass_with_valid_signature_when_eoa_when_compact_eip2098_signature() {
        assert!(true, "");
    }

    // does it differ
    #[test]
    #[ignore]
    fn test_should_fail_when_invalid_signature_when_contract_account_when_multiproposal() {
        assert!(true, "");
    }
}