use core::integer::BoundedInt;
use core::poseidon::poseidon_hash_span;
use core::starknet::SyscallResultTrait;
use openzeppelin::account::interface::{IPublicKeyDispatcher, IPublicKeyDispatcherTrait};
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
    simple_loan_list_proposal::{
        SimpleLoanListProposal, SimpleLoanListProposal::{Proposal, ProposalValues}
    }
};
use pwn::multitoken::library::MultiToken;
use pwn::nonce::revoked_nonce::{RevokedNonce, IRevokedNonceDispatcher};
use snforge_std::signature::stark_curve::{
    StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl
};
use snforge_std::signature::{KeyPairTrait, KeyPair};
use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait, cheat_block_timestamp_global
};
use starknet::secp256k1::{Secp256k1Point};
use starknet::{ContractAddress, testing};
use super::simple_loan_proposal_test::{
    TOKEN, PROPOSER, ACTIVATE_LOAN_CONTRACT, ACCEPTOR, Params, E70, E40
};
use pwn::loan::lib::merkle_proof::{proof, hash, hash_2};

#[starknet::interface]
trait ISimpleLoanListProposal<TState> {
    fn make_proposal(ref self: TState, proposal: Proposal);
    fn accept_proposal(
        ref self: TState,
        acceptor: starknet::ContractAddress,
        refinancing_loan_id: felt252,
        proposal_data: Array<felt252>,
        proposal_inclusion_proof: Array<felt252>,
        signature: Signature
    ) -> (felt252, Terms);
    fn get_proposal_hash(self: @TState, proposal: Proposal) -> felt252;
    fn encode_proposal_data(
        self: @TState, proposal: Proposal, proposal_values: ProposalValues
    ) -> Array<felt252>;
    fn decode_proposal_data(
        self: @TState, encoded_data: Array<felt252>
    ) -> (Proposal, ProposalValues);
    fn revoke_nonce(ref self: TState, nonce_space: felt252, nonce: felt252);
    fn get_multiproposal_hash(self: @TState, multiproposal: starknet::ClassHash) -> felt252;
}

#[derive(Drop)]
struct Setup {
    proposal: ISimpleLoanListProposalDispatcher,
    hub: IPwnHubDispatcher,
    nonce: IRevokedNonceDispatcher,
    signer: IPublicKeyDispatcher,
    key_pair: KeyPair::<felt252, felt252>
}

fn deploy() -> Setup {
    let contract = declare("PwnHub").unwrap();
    let (hub_address, _) = contract.deploy(@array![]).unwrap();
    let hub = IPwnHubDispatcher { contract_address: hub_address };

    let contract = declare("PwnConfig").unwrap();
    let (config_address, _) = contract.deploy(@array![]).unwrap();

    let contract = declare("RevokedNonce").unwrap();
    let (nonce_address, _) = contract
        .deploy(@array![hub_address.into(), pwn_hub_tags::ACTIVE_LOAN])
        .unwrap();
    let nonce = IRevokedNonceDispatcher { contract_address: nonce_address };

    let contract = declare("SimpleLoanListProposal").unwrap();
    let (contract_address, _) = contract
        .deploy(
            @array![
                hub_address.into(), nonce_address.into(), config_address.into(), 'name', 'version'
            ]
        )
        .unwrap();
    let proposal = ISimpleLoanListProposalDispatcher { contract_address };

    let key_pair = KeyPairTrait::<felt252, felt252>::generate();

    let contract = declare("AccountUpgradeable").unwrap();
    let (account_address, _) = contract.deploy(@array![key_pair.public_key]).unwrap();
    let signer = IPublicKeyDispatcher { contract_address: account_address };

    Setup { proposal, hub, nonce, signer, key_pair }
}

fn proposal() -> Proposal {
    let (_, merkle_root, _) = proof();
    Proposal {
        collateral_category: MultiToken::Category::ERC1155(()),
        collateral_address: TOKEN(),
        collateral_ids_whitelist_merkle_root: merkle_root,
        collateral_amount: 1032,
        check_collateral_state_fingerprint: false,
        collateral_state_fingerprint: 'some state fingerprint',
        credit_address: TOKEN(),
        credit_amount: 1101001,
        available_credit_limit: 0,
        fixed_interest_amount: 1,
        accruing_interest_APR: 0,
        duration: 1000,
        expiration: 60303,
        allowed_acceptor: starknet::contract_address_const::<0>(),
        proposer,
        proposer_spec_hash: 'proposer spec',
        is_offer: true,
        refinancing_loan_id: 0,
        nonce_space: 0,
        nonce: 'nonce_1',
        loan_contract: ACTIVATE_LOAN_CONTRACT(),
    }
}

fn proposal_values() -> ProposalValues {
    let (_,_,merkle_inclusion_proof) = proof();
    ProposalValues { collateral_id: 32, merkle_inclusion_proof }
}

fn proposal_hash(proposal: Proposal, proposal_address: ContractAddress) -> felt252 {
    let hash_elements = array![BASE_DOMAIN_SEPARATOR, 'name', 'version', proposal_address.into()];
    let domain_separator = poseidon_hash_span(hash_elements.span());

    let mut serialized_proposal = array![];
    proposal.serialize(ref serialized_proposal);

    let mut hash_elements = serialized_proposal;
    hash_elements.append(1901);
    hash_elements.append(domain_separator);
    hash_elements.append(SimpleLoanListProposal::PROPOSAL_TYPEHASH);

    poseidon_hash_span(hash_elements.span())
}

#[test]
fn test_should_return_used_credit(used: u128) {
    let dsp = deploy();

    let proposal_hash = proposal_hash(
        proposal(dsp.signer.contract_address), dsp.proposal.contract_address
    );

    store(
        dsp.proposal.contract_address,
        map_entry_address(selector!("credit_used"), array![proposal_hash].span(),),
        array![used.into()].span()
    );

    let stored_used: u128 = (*load(
        dsp.proposal.contract_address,
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
    let dsp = deploy();

    let caller: felt252 = caller.try_into().unwrap();

    store(
        dsp.hub.contract_address,
        map_entry_address(
            selector!("tags"),
            array![dsp.proposal.contract_address.into(), pwn_hub_tags::ACTIVE_LOAN].span(),
        ),
        array![true.into()].span()
    );

    start_cheat_caller_address(dsp.proposal.contract_address, caller.try_into().unwrap());
    dsp.proposal.revoke_nonce(nonce_space, nonce);
}

#[test]
fn test_should_return_proposal_hash() {
    let dsp = deploy();

    let proposal_hash = proposal_hash(
        proposal(dsp.signer.contract_address), dsp.proposal.contract_address
    );

    assert_eq!(
        dsp.proposal.get_proposal_hash(proposal(dsp.signer.contract_address)), proposal_hash
    );
}

#[test]
#[should_panic()]
fn test_fuzz_should_fail_when_caller_is_not_proposer(_proposer: felt252) {
    let dsp = deploy();

    let mut proposer: ContractAddress = _proposer.try_into().unwrap();
    if proposer == proposal(dsp.signer.contract_address).proposer {
        proposer = (_proposer + 1).try_into().unwrap();
    }

    start_cheat_caller_address(dsp.proposal.contract_address, proposer);
    dsp.proposal.make_proposal(proposal(dsp.signer.contract_address));
}

#[test]
fn test_should_emit_proposal_made() {
    let dsp = deploy();

    let mut spy = spy_events();

    let _proposal = proposal(dsp.signer.contract_address);

    start_cheat_caller_address(dsp.proposal.contract_address, _proposal.proposer);
    dsp.proposal.make_proposal(_proposal);

    spy
        .assert_emitted(
            @array![
                (
                    dsp.proposal.contract_address,
                    SimpleLoanListProposal::Event::ProposalMade(
                        SimpleLoanListProposal::ProposalMade {
                            proposal_hash: proposal_hash(_proposal, dsp.proposal.contract_address),
                            proposer: _proposal.proposer,
                            proposal: _proposal
                        }
                    )
                )
            ]
        );
}

#[test]
fn test_should_make_proposal() {
    let dsp = deploy();

    let _proposal = proposal(dsp.signer.contract_address);
    start_cheat_caller_address(dsp.proposal.contract_address, _proposal.proposer);
    dsp.proposal.make_proposal(_proposal);

    let proposal_hash = proposal_hash(_proposal, dsp.proposal.contract_address);

    let proposal_made = (*load(
        dsp.proposal.contract_address,
        map_entry_address(selector!("proposal_made"), array![proposal_hash].span()),
        1
    )
        .at(0));

    assert_eq!(proposal_made, 1);
}

#[test]
fn test_should_return_encoded_proposal_data() {
    let dsp = deploy();

    let encoded_data = dsp
        .proposal
        .encode_proposal_data(proposal(dsp.signer.contract_address), proposal_values());

    let mut serialized_proposal = array![];
    proposal(dsp.signer.contract_address).serialize(ref serialized_proposal);

    let mut serialized_proposal_values = array![];
    proposal_values().serialize(ref serialized_proposal_values);

    let expected = serialization::serde_concat(
        serialized_proposal.span(), serialized_proposal_values.span()
    );

    assert_eq!(encoded_data, expected);
}

#[test]
fn test_should_return_decoded_proposal_data() {
    let dsp = deploy();

    let _proposal = proposal(dsp.signer.contract_address);
    let encoded_data = dsp.proposal.encode_proposal_data(_proposal, proposal_values());

    let (decoded_proposal, decoded_proposal_values) = dsp
        .proposal
        .decode_proposal_data(encoded_data);

    assert_eq!(decoded_proposal.collateral_category, _proposal.collateral_category);
    assert_eq!(decoded_proposal.collateral_address, _proposal.collateral_address);
    assert_eq!(
        decoded_proposal.collateral_ids_whitelist_merkle_root,
        _proposal.collateral_ids_whitelist_merkle_root
    );
    assert_eq!(decoded_proposal.collateral_amount, _proposal.collateral_amount);
    assert_eq!(
        decoded_proposal.check_collateral_state_fingerprint,
        _proposal.check_collateral_state_fingerprint
    );
    assert_eq!(
        decoded_proposal.collateral_state_fingerprint, _proposal.collateral_state_fingerprint
    );
    assert_eq!(decoded_proposal.credit_address, _proposal.credit_address);
    assert_eq!(decoded_proposal.credit_amount, _proposal.credit_amount);
    assert_eq!(decoded_proposal.available_credit_limit, _proposal.available_credit_limit);
    assert_eq!(decoded_proposal.fixed_interest_amount, _proposal.fixed_interest_amount);
    assert_eq!(decoded_proposal.accruing_interest_APR, _proposal.accruing_interest_APR);
    assert_eq!(decoded_proposal.duration, _proposal.duration);
    assert_eq!(decoded_proposal.expiration, _proposal.expiration);
    assert_eq!(decoded_proposal.allowed_acceptor, _proposal.allowed_acceptor);
    assert_eq!(decoded_proposal.proposer, _proposal.proposer);
    assert_eq!(decoded_proposal.proposer_spec_hash, _proposal.proposer_spec_hash);
    assert_eq!(decoded_proposal.is_offer, _proposal.is_offer);
    assert_eq!(decoded_proposal.refinancing_loan_id, _proposal.refinancing_loan_id);
    assert_eq!(decoded_proposal.nonce_space, _proposal.nonce_space);
    assert_eq!(decoded_proposal.nonce, _proposal.nonce);
    assert_eq!(decoded_proposal.loan_contract, _proposal.loan_contract);

    assert_eq!(decoded_proposal_values.collateral_id, proposal_values().collateral_id);
    assert_eq!(
        decoded_proposal_values.merkle_inclusion_proof, proposal_values().merkle_inclusion_proof
    );
}

#[test]
fn test_should_accept_any_collateral_id_when_merkle_root_is_zero(coll_id: felt252) {
    let dsp = deploy();

    let mut _proposal = proposal(dsp.signer.contract_address);
    let mut _proposal_values = proposal_values();

    _proposal_values.collateral_id = coll_id;
    _proposal.collateral_ids_whitelist_merkle_root = 0;

    store(
        dsp.hub.contract_address,
        map_entry_address(
            selector!("tags"),
            array![_proposal.loan_contract.into(), pwn_hub_tags::ACTIVE_LOAN].span(),
        ),
        array![true.into()].span()
    );

    store(
        dsp.hub.contract_address,
        map_entry_address(
            selector!("tags"),
            array![dsp.proposal.contract_address.into(), pwn_hub_tags::ACTIVE_LOAN].span(),
        ),
        array![true.into()].span()
    );

    start_cheat_caller_address(dsp.proposal.contract_address, ACTIVATE_LOAN_CONTRACT());

    let proposal_hash = dsp.proposal.get_proposal_hash(_proposal);

    let (r, s): (felt252, felt252) = dsp.key_pair.sign(proposal_hash).unwrap();

    let signature = Signature { r, s };

    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(),
            0,
            dsp.proposal.encode_proposal_data(_proposal, _proposal_values),
            array![],
            signature
        );
}

#[test]
fn test_should_pass_when_given_collateral_id_is_whitelisted(
    mut coll_id_1: felt252, mut coll_id_2: felt252
) {
    let dsp = deploy();

    let mut _proposal = proposal(dsp.signer.contract_address);
    let mut _proposal_values = proposal_values();

    let id_1_hash: u256 = hash(coll_id_1.into());
    let id_2_hash: u256 = hash(coll_id_2.into());

    let merkle_root: u256 = if id_1_hash < id_2_hash {
        hash_2(id_1_hash, id_2_hash)
    } else {
        hash_2(id_2_hash, id_1_hash)
    };

    _proposal.collateral_ids_whitelist_merkle_root = merkle_root;
    _proposal_values.collateral_id = coll_id_1;
    _proposal_values.merkle_inclusion_proof = array![id_2_hash].span();

    store(
        dsp.hub.contract_address,
        map_entry_address(
            selector!("tags"),
            array![_proposal.loan_contract.into(), pwn_hub_tags::ACTIVE_LOAN].span(),
        ),
        array![true.into()].span()
    );
    store(
        dsp.hub.contract_address,
        map_entry_address(
            selector!("tags"),
            array![dsp.proposal.contract_address.into(), pwn_hub_tags::ACTIVE_LOAN].span(),
        ),
        array![true.into()].span()
    );

    start_cheat_caller_address(dsp.proposal.contract_address, ACTIVATE_LOAN_CONTRACT());

    let proposal_hash = dsp.proposal.get_proposal_hash(_proposal);

    let (r, s): (felt252, felt252) = dsp.key_pair.sign(proposal_hash).unwrap();

    let signature = Signature { r, s };

    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(),
            0,
            dsp.proposal.encode_proposal_data(_proposal, _proposal_values),
            array![],
            signature
        );
}

#[test]
#[should_panic()]
// NOTE: this should panic, need to review once the merkle verify algo is implemented
fn test_should_fail_when_given_collateral_id_is_not_whitelisted(
    mut coll_id_1: u128, mut coll_id_2: u128, mut coll_id_3: u128
) {
    let dsp = deploy();

    let mut _proposal = proposal(dsp.signer.contract_address);
    let mut _proposal_values = proposal_values();

    if coll_id_1 > coll_id_2 {
        let temp = coll_id_1;
        coll_id_1 = coll_id_2;
        coll_id_2 = temp;
    }

    if coll_id_3 == coll_id_1 {
        coll_id_3 = coll_id_1 + 1;
    }
    if coll_id_3 == coll_id_2 {
        coll_id_3 = coll_id_2 + 1;
    }

    let id_1_hash: u256 = hash(coll_id_1.into());
    let id_2_hash: u256 = hash(coll_id_2.into());

    let merkle_root: u256 = if id_1_hash < id_2_hash {
        hash_2(id_1_hash, id_2_hash)
    } else {
        hash_2(id_2_hash, id_1_hash)
    };

    _proposal.collateral_ids_whitelist_merkle_root = merkle_root;
    _proposal_values.collateral_id = coll_id_3.try_into().unwrap();
    _proposal_values.merkle_inclusion_proof = array![id_2_hash.try_into().unwrap()].span();

    store(
        dsp.hub.contract_address,
        map_entry_address(
            selector!("tags"),
            array![_proposal.loan_contract.into(), pwn_hub_tags::ACTIVE_LOAN].span(),
        ),
        array![true.into()].span()
    );
    store(
        dsp.hub.contract_address,
        map_entry_address(
            selector!("tags"),
            array![dsp.proposal.contract_address.into(), pwn_hub_tags::ACTIVE_LOAN].span(),
        ),
        array![true.into()].span()
    );

    start_cheat_caller_address(dsp.proposal.contract_address, ACTIVATE_LOAN_CONTRACT());

    let proposal_hash = dsp.proposal.get_proposal_hash(_proposal);

    let (r, s): (felt252, felt252) = dsp.key_pair.sign(proposal_hash).unwrap();

    let signature = Signature { r, s };

    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(),
            0,
            dsp.proposal.encode_proposal_data(_proposal, _proposal_values),
            array![],
            signature
        );
}

#[test]
fn test_should_call_loan_contract_with_loan_terms(is_offer: u8) {
    let dsp = deploy();

    let mut _proposal = proposal(dsp.signer.contract_address);
    let mut _proposal_values = proposal_values();

    _proposal.is_offer = if is_offer % 2 == 0 {
        true
    } else {
        false
    };

    store(
        dsp.hub.contract_address,
        map_entry_address(
            selector!("tags"),
            array![_proposal.loan_contract.into(), pwn_hub_tags::ACTIVE_LOAN].span(),
        ),
        array![true.into()].span()
    );
    store(
        dsp.hub.contract_address,
        map_entry_address(
            selector!("tags"),
            array![dsp.proposal.contract_address.into(), pwn_hub_tags::ACTIVE_LOAN].span(),
        ),
        array![true.into()].span()
    );

    start_cheat_caller_address(dsp.proposal.contract_address, ACTIVATE_LOAN_CONTRACT());

    let proposal_hash = dsp.proposal.get_proposal_hash(_proposal);

    let (r, s): (felt252, felt252) = dsp.key_pair.sign(proposal_hash).unwrap();

    let signature = Signature { r, s };

    let (proposal_hash, terms) = dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(),
            0,
            dsp.proposal.encode_proposal_data(_proposal, _proposal_values),
            array![],
            signature
        );

    assert_eq!(proposal_hash, dsp.proposal.get_proposal_hash(_proposal));
    assert_eq!(
        terms.lender, if _proposal.is_offer {
            dsp.signer.contract_address
        } else {
            ACCEPTOR()
        }
    );
    assert_eq!(
        terms.borrower, if _proposal.is_offer {
            ACCEPTOR()
        } else {
            dsp.signer.contract_address
        }
    );
    assert_eq!(terms.duration, _proposal.duration);
    assert_eq!(terms.collateral.category, _proposal.collateral_category);
    assert_eq!(terms.collateral.asset_address, _proposal.collateral_address);
    assert_eq!(terms.collateral.id, _proposal_values.collateral_id);
    assert_eq!(terms.collateral.amount, _proposal.collateral_amount);
    assert_eq!(terms.credit.category, MultiToken::Category::ERC20(()));
    assert_eq!(terms.credit.asset_address, _proposal.credit_address);
    assert_eq!(terms.credit.id, 0);
    assert_eq!(terms.credit.amount, _proposal.credit_amount);
    assert_eq!(terms.fixed_interest_amount, _proposal.fixed_interest_amount);
    assert_eq!(terms.accruing_interest_APR, _proposal.accruing_interest_APR);
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


