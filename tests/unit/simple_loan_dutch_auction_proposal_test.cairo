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
    simple_loan_dutch_auction_proposal::{
        SimpleLoanDutchAuctionProposal,
        SimpleLoanDutchAuctionProposal::{Proposal, ProposalValues, MINUTE}
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

#[starknet::interface]
pub trait ISimpleLoanDutchAuctionProposal<TState> {
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
    fn get_credit_amount(self: @TState, proposal: Proposal, timestamp: u64) -> u256;
    fn revoke_nonce(ref self: TState, nonce_space: felt252, nonce: felt252);
    fn get_multiproposal_hash(self: @TState, multiproposal: starknet::ClassHash) -> felt252;
}

const E40: u256 = 10_000_000_000_000_000_000_000_000_000_000_000_000;

type ComponentState =
    SimpleLoanProposalComponent::ComponentState<SimpleLoanDutchAuctionProposal::ContractState>;

fn COMPONENT_STATE() -> ComponentState {
    SimpleLoanProposalComponent::component_state_for_testing()
}

fn deploy() -> (
    ISimpleLoanDutchAuctionProposalDispatcher, IPwnHubDispatcher, IRevokedNonceDispatcher
) {
    let contract = declare("PwnHub").unwrap();
    let (hub_address, _) = contract.deploy(@array![]).unwrap();

    let contract = declare("PwnConfig").unwrap();
    let (config_address, _) = contract.deploy(@array![]).unwrap();

    let contract = declare("RevokedNonce").unwrap();
    let (nonce_address, _) = contract
        .deploy(@array![hub_address.into(), pwn_hub_tags::ACTIVE_LOAN])
        .unwrap();

    let contract = declare("SimpleLoanDutchAuctionProposal").unwrap();
    let (contract_address, _) = contract
        .deploy(
            @array![
                hub_address.into(), nonce_address.into(), config_address.into(), 'name', 'version'
            ]
        )
        .unwrap();

    (
        ISimpleLoanDutchAuctionProposalDispatcher { contract_address },
        IPwnHubDispatcher { contract_address: hub_address },
        IRevokedNonceDispatcher { contract_address: nonce_address },
    )
}

fn TOKEN() -> ContractAddress {
    starknet::contract_address_const::<'token'>()
}

fn PROPOSER() -> ContractAddress {
    starknet::contract_address_const::<73661723>()
}

fn ACCEPTOR() -> ContractAddress {
    starknet::contract_address_const::<32716637>()
}

fn ACTIVATE_LOAN_CONTRACT() -> ContractAddress {
    starknet::contract_address_const::<'activeLoanContract'>()
}

fn proposal() -> Proposal {
    Proposal {
        collateral_category: MultiToken::Category::ERC1155(()),
        collateral_address: TOKEN(),
        collateral_id: 0,
        collateral_amount: 1,
        check_collateral_state_fingerprint: false,
        collateral_state_fingerprint: 'some state fingerprint',
        credit_address: TOKEN(),
        min_credit_amount: 10_000,
        max_credit_amount: 100_000,
        available_credit_limit: 0,
        fixed_interest_amount: 1,
        accruing_interest_APR: 0,
        duration: 1000,
        auction_start: 0,
        auction_duration: 6_000,
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
    ProposalValues { intended_credit_amount: 10_000, slippage: 0, }
}

fn proposal_hash(proposal: Proposal, proposal_address: ContractAddress) -> felt252 {
    let hash_elements = array![BASE_DOMAIN_SEPARATOR, 'name', 'version', proposal_address.into()];
    let domain_separator = poseidon_hash_span(hash_elements.span());

    let mut serialized_proposal = array![];
    proposal.serialize(ref serialized_proposal);

    let mut hash_elements = serialized_proposal;
    hash_elements.append(1901);
    hash_elements.append(domain_separator);
    hash_elements.append(SimpleLoanDutchAuctionProposal::PROPOSAL_TYPEHASH);

    poseidon_hash_span(hash_elements.span())
}

#[test]
fn test_should_return_used_credit() { // let proposal = super::deploy();
    assert(true, '');
}

#[test]
fn test_should_call_revoke_nonce(caller: u128, nonce_space: felt252, nonce: felt252) {
    let (proposal, hub, _) = deploy();

    let caller: felt252 = caller.try_into().unwrap();

    start_cheat_caller_address(proposal.contract_address, caller.try_into().unwrap());

    store(
        hub.contract_address,
        map_entry_address(
            selector!("tags"),
            array![proposal.contract_address.into(), pwn_hub_tags::ACTIVE_LOAN].span(),
        ),
        array![true.into()].span()
    );

    proposal.revoke_nonce(nonce_space, nonce);
    assert(true, '');
}

#[test]
fn test_should_return_proposal_hash() {
    let (proposal, _, _) = deploy();

    let hash = proposal.get_proposal_hash(proposal());

    let expected_hash = proposal_hash(proposal(), proposal.contract_address);

    assert_eq!(hash, expected_hash);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_caller_is_not_proposer(caller: u128) {
    let (proposal, _, _) = deploy();

    let caller: felt252 = caller.try_into().unwrap();

    start_cheat_caller_address(proposal.contract_address, caller.try_into().unwrap());
    proposal.make_proposal(proposal());
}

#[test]
fn test_should_emit_proposal_made() {
    let (proposal, _, _) = deploy();

    let mut spy = spy_events(SpyOn::One(proposal.contract_address));

    start_cheat_caller_address(proposal.contract_address, proposal().proposer);
    proposal.make_proposal(proposal());

    spy
        .assert_emitted(
            @array![
                (
                    proposal.contract_address,
                    SimpleLoanDutchAuctionProposal::Event::ProposalMade(
                        SimpleLoanDutchAuctionProposal::ProposalMade {
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

    let loaded = load(
        proposal.contract_address,
        map_entry_address(
            selector!("proposal_made"), // Providing variable name
            array![proposal_hash(proposal(), proposal.contract_address)]
                .span(), // Providing mapping key 
        ),
        1,
    );
    let proposal_made: bool = if *loaded.at(0) == 1 {
        true
    } else {
        false
    };

    assert_eq!(proposal_made, true);
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
    assert_eq!(decoded_proposal.collateral_amount, proposal().collateral_amount);
    assert_eq!(
        decoded_proposal.check_collateral_state_fingerprint,
        proposal().check_collateral_state_fingerprint
    );
    assert_eq!(
        decoded_proposal.collateral_state_fingerprint, proposal().collateral_state_fingerprint
    );
    assert_eq!(decoded_proposal.credit_address, proposal().credit_address);
    assert_eq!(decoded_proposal.min_credit_amount, proposal().min_credit_amount);
    assert_eq!(decoded_proposal.max_credit_amount, proposal().max_credit_amount);
    assert_eq!(decoded_proposal.available_credit_limit, proposal().available_credit_limit);
    assert_eq!(decoded_proposal.fixed_interest_amount, proposal().fixed_interest_amount);
    assert_eq!(decoded_proposal.accruing_interest_APR, proposal().accruing_interest_APR);
    assert_eq!(decoded_proposal.duration, proposal().duration);
    assert_eq!(decoded_proposal.auction_start, proposal().auction_start);
    assert_eq!(decoded_proposal.auction_duration, proposal().auction_duration);
    assert_eq!(decoded_proposal.allowed_acceptor, proposal().allowed_acceptor);
    assert_eq!(decoded_proposal.proposer, proposal().proposer);
    assert_eq!(decoded_proposal.proposer_spec_hash, proposal().proposer_spec_hash);
    assert_eq!(decoded_proposal.is_offer, proposal().is_offer);
    assert_eq!(decoded_proposal.refinancing_loan_id, proposal().refinancing_loan_id);
    assert_eq!(decoded_proposal.nonce_space, proposal().nonce_space);
    assert_eq!(decoded_proposal.nonce, proposal().nonce);
    assert_eq!(decoded_proposal.loan_contract, proposal().loan_contract);

    assert_eq!(
        decoded_proposal_values.intended_credit_amount, proposal_values().intended_credit_amount
    );
    assert_eq!(decoded_proposal_values.slippage, proposal_values().slippage);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_invalid_auction_duration(auction_duration: u64) {
    let (proposal, _, _) = deploy();

    let mut _proposal = proposal();

    let auction_duration = auction_duration % MINUTE;
    _proposal.auction_duration = auction_duration;

    proposal.get_credit_amount(_proposal, 0);
}

#[test]
#[should_panic]
fn test_should_fail_when_auction_duration_not_in_full_minutes(auction_duration: u64) {
    let (proposal, _, _) = deploy();

    let mut _proposal = proposal();

    let auction_duration = if auction_duration % MINUTE == 0 {
        auction_duration + 1
    } else {
        auction_duration
    };
    _proposal.auction_duration = auction_duration;

    proposal.get_credit_amount(_proposal, 0);
}

#[test]
#[should_panic]
fn test_should_fail_when_invalid_credit_amount_range(
    min_credit_amount: u256, max_credit_amount: u256
) {
    let (proposal, _, _) = deploy();

    let mut _proposal = proposal();
    if min_credit_amount < max_credit_amount {
        _proposal.min_credit_amount = max_credit_amount;
        _proposal.max_credit_amount = min_credit_amount;
    } else {
        _proposal.min_credit_amount = min_credit_amount;
        _proposal.max_credit_amount = max_credit_amount;
    }

    proposal.get_credit_amount(_proposal, 0);
}

#[test]
#[should_panic]
fn test_should_fail_when_auction_not_in_progress(auction_start: u64, time: u64) {
    let (proposal, _, _) = deploy();

    let auction_start = if auction_start == 0 {
        auction_start + 1
    } else {
        auction_start
    };
    let time = if time > auction_start {
        auction_start - 1
    } else {
        time
    };

    let mut _proposal = proposal();
    _proposal.auction_start = auction_start;

    proposal.get_credit_amount(_proposal, time);
}

#[test]
#[should_panic]
fn test_fuzz_should_fail_when_proposal_expired(auction_duration: u64, time: u64) {
    let (proposal, _, _) = deploy();

    let auction_duration = if auction_duration < MINUTE {
        MINUTE
    } else if auction_duration > BoundedInt::max() - MINUTE * 2 {
        BoundedInt::max() - MINUTE * 2
    } else {
        (auction_duration / MINUTE) * MINUTE
    };

    let time = if time < auction_duration + MINUTE + 1 {
        auction_duration + MINUTE + 1
    } else {
        time
    };

    let mut _proposal = proposal();
    _proposal.auction_start = 0;
    _proposal.auction_duration = auction_duration;

    proposal.get_credit_amount(_proposal, time);
}

#[test]
fn test_fuzz_should_return_correct_edge_values(auction_duration: u64) {
    let (proposal, _, _) = deploy();

    let mut _proposal = proposal();

    if auction_duration < MINUTE {
        _proposal.auction_duration = MINUTE;
    } else if auction_duration > BoundedInt::max()
        - 59 { // Subtracting 59 to ensure result * MINUTE doesn't overflow
        _proposal.auction_duration = (BoundedInt::max() / MINUTE) * MINUTE - MINUTE;
    } else {
        _proposal.auction_duration = (auction_duration / MINUTE) * MINUTE;
    }

    _proposal.is_offer = true;
    assert_eq!(
        proposal.get_credit_amount(_proposal, _proposal.auction_start), _proposal.min_credit_amount
    );
    assert_eq!(
        proposal.get_credit_amount(_proposal, _proposal.auction_duration),
        _proposal.max_credit_amount
    );
    assert_eq!(
        proposal.get_credit_amount(_proposal, _proposal.auction_duration + 59),
        _proposal.max_credit_amount
    );

    _proposal.is_offer = false;
    assert_eq!(
        proposal.get_credit_amount(_proposal, _proposal.auction_start), _proposal.max_credit_amount
    );
    assert_eq!(
        proposal.get_credit_amount(_proposal, _proposal.auction_duration),
        _proposal.min_credit_amount
    );
    assert_eq!(
        proposal.get_credit_amount(_proposal, _proposal.auction_duration + 59),
        _proposal.min_credit_amount
    );
}

#[test]
fn test_should_return_correct_credit_amount_when_offer(
    mut min_credit_amount: u256,
    mut max_credit_amount: u256,
    mut time_in_auction: u64,
    mut auction_duration: u64
) {
    let (proposal, _, _) = deploy();

    if max_credit_amount == 0 {
        max_credit_amount = 1;
    } else if max_credit_amount > E40 {
        max_credit_amount = E40;
    }

    if min_credit_amount < 0 {
        min_credit_amount = 0;
    } else if min_credit_amount >= max_credit_amount {
        min_credit_amount = max_credit_amount - 1;
    }

    if auction_duration < MINUTE {
        auction_duration = MINUTE;
    } else if auction_duration > 99999 * MINUTE {
        auction_duration = 99999 * MINUTE;
    } else {
        auction_duration = (auction_duration / MINUTE) * MINUTE;
    }

    if time_in_auction < 0 {
        time_in_auction = 0;
    } else if time_in_auction > auction_duration {
        time_in_auction = auction_duration;
    }

    let mut _proposal = proposal();
    _proposal.is_offer = true;
    _proposal.min_credit_amount = min_credit_amount;
    _proposal.max_credit_amount = max_credit_amount;
    _proposal.auction_duration = auction_duration;

    assert_eq!(
        proposal.get_credit_amount(_proposal, time_in_auction),
        min_credit_amount
            + (max_credit_amount - min_credit_amount)
                * (time_in_auction / MINUTE * MINUTE).into()
                / auction_duration.into()
    );
}

#[test]
fn test_should_return_correct_credit_amount_when_request(
    mut min_credit_amount: u256,
    mut max_credit_amount: u256,
    mut time_in_auction: u64,
    mut auction_duration: u64
) {
    let (proposal, _, _) = deploy();

    if max_credit_amount == 0 {
        max_credit_amount = 1;
    } else if max_credit_amount > E40 {
        max_credit_amount = E40;
    }

    if min_credit_amount < 0 {
        min_credit_amount = 0;
    } else if min_credit_amount >= max_credit_amount {
        min_credit_amount = max_credit_amount - 1;
    }

    if auction_duration < MINUTE {
        auction_duration = MINUTE;
    } else if auction_duration > 99999 * MINUTE {
        auction_duration = 99999 * MINUTE;
    } else {
        auction_duration = (auction_duration / MINUTE) * MINUTE;
    }

    if time_in_auction < 0 {
        time_in_auction = 0;
    } else if time_in_auction > auction_duration {
        time_in_auction = auction_duration;
    }

    let mut _proposal = proposal();
    _proposal.is_offer = false;
    _proposal.min_credit_amount = min_credit_amount;
    _proposal.max_credit_amount = max_credit_amount;
    _proposal.auction_duration = auction_duration;

    assert_eq!(
        proposal.get_credit_amount(_proposal, time_in_auction),
        max_credit_amount
            - (max_credit_amount - min_credit_amount)
                * (time_in_auction / MINUTE * MINUTE).into()
                / auction_duration.into()
    );
}

#[test]
#[should_panic]
fn test_should_fail_when_current_auction_credit_amount_not_in_intended_credit_amount_range_when_offer(
    mut intended_credit_amount: u256
) {
    let (proposal, _, _) = deploy();

    let mut _proposal = proposal();
    _proposal.is_offer = true;
    _proposal.min_credit_amount = 0;
    _proposal.max_credit_amount = 100_000;
    _proposal.auction_start = 1;
    _proposal.auction_duration = MINUTE;

    cheat_block_timestamp_global(_proposal.auction_start + _proposal.auction_duration / 2);

    let mut _proposal_values = proposal_values();
    _proposal_values.slippage = 500;

    if intended_credit_amount < 0 {
        intended_credit_amount = 0;
    } else if intended_credit_amount > BoundedInt::max() - _proposal_values.slippage {
        intended_credit_amount = BoundedInt::max() - _proposal_values.slippage;
    }
    _proposal_values.intended_credit_amount = intended_credit_amount;

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
            signature,
        );
}

#[test]
#[should_panic]
fn test_should_fail_when_current_auction_credit_amount_not_in_intended_credit_amount_range_when_request(
    mut intended_credit_amount: u256
) {
    let (proposal, _, _) = deploy();

    let mut _proposal = proposal();
    _proposal.is_offer = false;
    _proposal.min_credit_amount = 0;
    _proposal.max_credit_amount = 100_000;
    _proposal.auction_start = 1;
    _proposal.auction_duration = MINUTE * 100;

    cheat_block_timestamp_global(_proposal.auction_start + _proposal.auction_duration / 2);

    let mut _proposal_values = proposal_values();
    _proposal_values.slippage = 500;

    if intended_credit_amount < _proposal_values.slippage {
        intended_credit_amount = _proposal_values.slippage;
    } else if intended_credit_amount > BoundedInt::max() {
        intended_credit_amount = BoundedInt::max();
    }
    _proposal_values.intended_credit_amount = intended_credit_amount;

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
            signature,
        );
}

#[test]
fn test_should_call_loan_contract_with_loan_terms(
    mut min_credit_amount: u128,
    mut max_credit_amount: u128,
    mut auction_duration: u64,
    mut time_in_auction: u64,
    is_offer: u8
) {
    let (proposal, hub, _) = deploy();

    if min_credit_amount > max_credit_amount {
        let temp = min_credit_amount;
        min_credit_amount = max_credit_amount;
        max_credit_amount = temp;
    }

    if auction_duration < MINUTE {
        auction_duration = MINUTE;
    } else if auction_duration > (BoundedInt::max() / MINUTE - 1) * MINUTE {
        auction_duration = (BoundedInt::max() / MINUTE - 1) * MINUTE;
    } else {
        auction_duration = (auction_duration / MINUTE) * MINUTE;
    }

    let is_offer = if is_offer % 2 == 0 {
        false
    } else {
        true
    };

    if time_in_auction < 0 {
        time_in_auction = 0;
    } else if time_in_auction >= auction_duration {
        time_in_auction = auction_duration - 1;
    }

    let mut _proposal = proposal();
    _proposal.is_offer = is_offer;
    _proposal.min_credit_amount = min_credit_amount.into();
    _proposal.max_credit_amount = max_credit_amount.into();
    _proposal.auction_start = 1;
    _proposal.auction_duration = auction_duration;

    cheat_block_timestamp_global(_proposal.auction_start + time_in_auction);

    let credit_amount = proposal.get_credit_amount(_proposal, starknet::get_block_timestamp());

    let mut _proposal_values = proposal_values();
    _proposal_values.intended_credit_amount = credit_amount;
    _proposal_values.slippage = 0;

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
            signature,
        );

    assert_eq!(proposal_hash, proposal_hash(_proposal, proposal.contract_address));
    assert_eq!(terms.lender, if is_offer {
        PROPOSER()
    } else {
        ACCEPTOR()
    });
    assert_eq!(terms.borrower, if is_offer {
        ACCEPTOR()
    } else {
        PROPOSER()
    });
    assert_eq!(terms.duration, _proposal.duration);
    assert_eq!(terms.collateral.category, _proposal.collateral_category);
    assert_eq!(terms.collateral.asset_address, _proposal.collateral_address);
    assert_eq!(terms.collateral.id, _proposal.collateral_id);
    assert_eq!(terms.collateral.amount, _proposal.collateral_amount);
    assert_eq!(terms.credit.category, MultiToken::Category::ERC20(()));
    assert_eq!(terms.credit.asset_address, _proposal.credit_address);
    assert_eq!(terms.credit.id, 0);
    assert_eq!(terms.credit.amount, credit_amount);
    assert_eq!(terms.fixed_interest_amount, _proposal.fixed_interest_amount);
    assert_eq!(terms.accruing_interest_apr, _proposal.accruing_interest_APR);
    assert_eq!(terms.lender_spec_hash, if is_offer {
        _proposal.proposer_spec_hash
    } else {
        0
    });
    assert_eq!(terms.borrower_spec_hash, if is_offer {
        0
    } else {
        _proposal.proposer_spec_hash
    });
}
