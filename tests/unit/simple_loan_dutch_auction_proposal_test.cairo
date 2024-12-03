use core::integer::BoundedInt;
use core::poseidon::poseidon_hash_span;
use core::starknet::{SyscallResultTrait, get_contract_address};
use openzeppelin::account::interface::{IPublicKeyDispatcher, IPublicKeyDispatcherTrait};
use pwn::config::{
    pwn_config::PwnConfig, interface::{IPwnConfigDispatcher, IPwnConfigDispatcherTrait}
};
use pwn::hub::{pwn_hub::{PwnHub, IPwnHubDispatcher, IPwnHubDispatcherTrait}, pwn_hub_tags};
use pwn::interfaces::fingerprint_computer::{
    IStateFingerpringComputerDispatcher, IStateFingerpringComputerDispatcherTrait
};
use pwn::loan::lib::serialization;
use pwn::loan::terms::simple::loan::types::Terms;
use pwn::loan::terms::simple::proposal::{
    simple_loan_proposal::{
        ISimpleLoanProposalDispatcher, ISimpleLoanProposalDispatcherTrait,
        SimpleLoanProposalComponent,
        SimpleLoanProposalComponent::{SimpleLoanProposalImpl, InternalImpl}
    },
    simple_loan_dutch_auction_proposal::{
        SimpleLoanDutchAuctionProposal,
        SimpleLoanDutchAuctionProposal::{Proposal, ProposalValues, MINUTE}
    }
};
use pwn::multitoken::library::MultiToken;
use pwn::nonce::revoked_nonce::{IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait};
use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, cheat_caller_address, CheatSpan,
    spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait, mock_call,
    cheat_block_timestamp_global
};
use starknet::{ContractAddress, testing};
use super::simple_loan_proposal_test::{TOKEN, ACTIVATE_LOAN_CONTRACT, ACCEPTOR, SF_COMPUTER, E40};

#[starknet::interface]
pub trait ISimpleLoanDutchAuctionProposal<TState> {
    fn make_proposal(ref self: TState, proposal: Proposal) -> felt252;
    fn accept_proposal(
        ref self: TState,
        acceptor: starknet::ContractAddress,
        refinancing_loan_id: felt252,
        proposal_data: Array<felt252>
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
}

#[derive(Drop)]
struct Setup {
    proposal: ISimpleLoanDutchAuctionProposalDispatcher,
    hub: IPwnHubDispatcher,
    config: IPwnConfigDispatcher,
    nonce: IRevokedNonceDispatcher,
}

fn deploy() -> Setup {
    let contract = declare("PwnHub").unwrap();
    let (hub_address, _) = contract
        .deploy(@array![starknet::get_contract_address().into()])
        .unwrap();
    let hub = IPwnHubDispatcher { contract_address: hub_address };

    let contract = declare("PwnConfig").unwrap();
    let (config_address, _) = contract.deploy(@array![]).unwrap();
    let config = IPwnConfigDispatcher { contract_address: config_address };
    config.initialize(get_contract_address(), 0, get_contract_address());

    let contract = declare("RevokedNonce").unwrap();
    let (nonce_address, _) = contract
        .deploy(@array![hub_address.into(), pwn_hub_tags::NONCE_MANAGER])
        .unwrap();
    let nonce = IRevokedNonceDispatcher { contract_address: nonce_address };

    let contract = declare("SimpleLoanDutchAuctionProposal").unwrap();
    let (contract_address, _) = contract
        .deploy(@array![hub_address.into(), nonce_address.into(), config_address.into()])
        .unwrap();
    let proposal = ISimpleLoanDutchAuctionProposalDispatcher { contract_address };

    hub.set_tag(proposal.contract_address, pwn_hub_tags::NONCE_MANAGER, true);
    hub.set_tag(ACTIVATE_LOAN_CONTRACT(), pwn_hub_tags::ACTIVE_LOAN, true);

    Setup { proposal, hub, config, nonce }
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
        proposer: starknet::contract_address_const::<'proposer'>(),
        proposer_spec_hash: 'proposer spec',
        is_offer: true,
        refinancing_loan_id: 0,
        nonce_space: 0,
        nonce: 'nonce_1',
        loan_contract: ACTIVATE_LOAN_CONTRACT(),
    }
}

fn proposal_values() -> ProposalValues {
    ProposalValues { intended_credit_amount: 10_000, slippage: 90_000, }
}

fn proposal_hash(proposal: Proposal) -> felt252 {
    let mut serialized_proposal = array![];
    proposal.serialize(ref serialized_proposal);
    poseidon_hash_span(serialized_proposal.span())
}

#[test]
fn test_should_return_used_credit() {
    let dsp = deploy();
    let used = 30303;

    let proposal_hash = proposal_hash(proposal());

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
fn test_should_revoke_nonce() {
    let dsp = deploy();

    let caller = starknet::contract_address_const::<'caller'>();
    let nonce_space = 321;
    let nonce = 123;

    cheat_caller_address(dsp.proposal.contract_address, caller, CheatSpan::TargetCalls(1));
    dsp.proposal.revoke_nonce(nonce_space, nonce);

    let is_revoked = dsp.nonce.is_nonce_revoked(caller, nonce_space, nonce);
    assert_eq!(is_revoked, true);
}

#[test]
fn test_should_return_proposal_hash() {
    let dsp = deploy();

    let hash = dsp.proposal.get_proposal_hash(proposal());

    let expected_hash = proposal_hash(proposal());

    assert_eq!(hash, expected_hash);
}

#[test]
#[should_panic]
fn test_should_fail_when_caller_is_not_proposer() {
    let dsp = deploy();

    let not_proposer = starknet::contract_address_const::<'not_proposer'>();

    cheat_caller_address(dsp.proposal.contract_address, not_proposer, CheatSpan::TargetCalls(1));
    dsp.proposal.make_proposal(proposal());
}

#[test]
fn test_should_emit_proposal_made() {
    let dsp = deploy();

    let mut spy = spy_events();

    let _proposal = proposal();

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    spy
        .assert_emitted(
            @array![
                (
                    dsp.proposal.contract_address,
                    SimpleLoanDutchAuctionProposal::Event::ProposalMade(
                        SimpleLoanDutchAuctionProposal::ProposalMade {
                            proposal_hash: proposal_hash(_proposal),
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

    let _proposal = proposal();

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(proposal());

    let proposal_hash = proposal_hash(_proposal);

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

    let encoded_data = dsp.proposal.encode_proposal_data(proposal(), proposal_values());

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
    let dsp = deploy();

    let _proposal = proposal();
    let _proposal_values = proposal_values();

    let encoded_data = dsp.proposal.encode_proposal_data(_proposal, _proposal_values);

    let (decoded_proposal, decoded_proposal_values) = dsp
        .proposal
        .decode_proposal_data(encoded_data);

    assert_eq!(decoded_proposal.collateral_category, _proposal.collateral_category);
    assert_eq!(decoded_proposal.collateral_address, _proposal.collateral_address);
    assert_eq!(decoded_proposal.collateral_id, _proposal.collateral_id);
    assert_eq!(decoded_proposal.collateral_amount, _proposal.collateral_amount);
    assert_eq!(
        decoded_proposal.check_collateral_state_fingerprint,
        _proposal.check_collateral_state_fingerprint
    );
    assert_eq!(
        decoded_proposal.collateral_state_fingerprint, _proposal.collateral_state_fingerprint
    );
    assert_eq!(decoded_proposal.credit_address, _proposal.credit_address);
    assert_eq!(decoded_proposal.min_credit_amount, _proposal.min_credit_amount);
    assert_eq!(decoded_proposal.max_credit_amount, _proposal.max_credit_amount);
    assert_eq!(decoded_proposal.available_credit_limit, _proposal.available_credit_limit);
    assert_eq!(decoded_proposal.fixed_interest_amount, _proposal.fixed_interest_amount);
    assert_eq!(decoded_proposal.accruing_interest_APR, _proposal.accruing_interest_APR);
    assert_eq!(decoded_proposal.duration, _proposal.duration);
    assert_eq!(decoded_proposal.auction_start, _proposal.auction_start);
    assert_eq!(decoded_proposal.auction_duration, _proposal.auction_duration);
    assert_eq!(decoded_proposal.allowed_acceptor, _proposal.allowed_acceptor);
    assert_eq!(decoded_proposal.proposer, _proposal.proposer);
    assert_eq!(decoded_proposal.proposer_spec_hash, _proposal.proposer_spec_hash);
    assert_eq!(decoded_proposal.is_offer, _proposal.is_offer);
    assert_eq!(decoded_proposal.refinancing_loan_id, _proposal.refinancing_loan_id);
    assert_eq!(decoded_proposal.nonce_space, _proposal.nonce_space);
    assert_eq!(decoded_proposal.nonce, _proposal.nonce);
    assert_eq!(decoded_proposal.loan_contract, _proposal.loan_contract);

    assert_eq!(
        decoded_proposal_values.intended_credit_amount, _proposal_values.intended_credit_amount
    );
    assert_eq!(decoded_proposal_values.slippage, _proposal_values.slippage);
}

#[test]
#[should_panic]
fn test_should_fail_when_invalid_auction_duration() {
    let dsp = deploy();

    let mut _proposal = proposal();
    _proposal.auction_duration = 59;

    dsp.proposal.get_credit_amount(_proposal, 0);
}

#[test]
#[should_panic]
fn test_should_fail_when_auction_duration_not_in_full_minutes() {
    let dsp = deploy();

    let mut _proposal = proposal();
    _proposal.auction_duration = 122;

    dsp.proposal.get_credit_amount(_proposal, 0);
}

#[test]
#[should_panic]
fn test_should_fail_when_invalid_credit_amount_range() {
    let dsp = deploy();

    let mut _proposal = proposal();
    _proposal.min_credit_amount = 20000;
    _proposal.max_credit_amount = 10000;

    dsp.proposal.get_credit_amount(_proposal, 0);
}

#[test]
#[should_panic]
fn test_should_fail_when_auction_not_in_progress() {
    let dsp = deploy();

    let mut _proposal = proposal();
    _proposal.auction_start = 100;

    dsp.proposal.get_credit_amount(_proposal, _proposal.auction_start - 1);
}

#[test]
#[should_panic]
fn test_should_fail_when_proposal_expired() {
    let dsp = deploy();

    let _proposal = proposal();

    dsp
        .proposal
        .get_credit_amount(_proposal, _proposal.auction_start + _proposal.auction_duration + 60);
}

#[test]
fn test_should_return_correct_edge_values() {
    let dsp = deploy();

    let mut _proposal = proposal();

    _proposal.is_offer = true;
    assert_eq!(
        dsp.proposal.get_credit_amount(_proposal, _proposal.auction_start),
        _proposal.min_credit_amount
    );
    assert_eq!(
        dsp
            .proposal
            .get_credit_amount(_proposal, _proposal.auction_start + _proposal.auction_duration),
        _proposal.max_credit_amount
    );
    assert_eq!(
        dsp
            .proposal
            .get_credit_amount(
                _proposal, _proposal.auction_start + _proposal.auction_duration + 59
            ),
        _proposal.max_credit_amount
    );

    _proposal.is_offer = false;
    assert_eq!(
        dsp.proposal.get_credit_amount(_proposal, _proposal.auction_start),
        _proposal.max_credit_amount
    );
    assert_eq!(
        dsp
            .proposal
            .get_credit_amount(_proposal, _proposal.auction_start + _proposal.auction_duration),
        _proposal.min_credit_amount
    );
    assert_eq!(
        dsp
            .proposal
            .get_credit_amount(
                _proposal, _proposal.auction_start + _proposal.auction_duration + 59
            ),
        _proposal.min_credit_amount
    );
}

#[test]
fn test_fuzz_should_return_correct_credit_amount_when_offer(
    mut min_credit_amount: u256,
    mut max_credit_amount: u256,
    mut time_in_auction: u64,
    mut auction_duration: u64
) {
    let dsp = deploy();

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
        dsp.proposal.get_credit_amount(_proposal, time_in_auction),
        min_credit_amount
            + (max_credit_amount - min_credit_amount)
                * (time_in_auction / MINUTE * MINUTE).into()
                / auction_duration.into()
    );
}

#[test]
fn test_fuzz_should_return_correct_credit_amount_when_request(
    mut min_credit_amount: u256,
    mut max_credit_amount: u256,
    mut time_in_auction: u64,
    mut auction_duration: u64
) {
    let dsp = deploy();

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
        dsp.proposal.get_credit_amount(_proposal, time_in_auction),
        max_credit_amount
            - (max_credit_amount - min_credit_amount)
                * (time_in_auction / MINUTE * MINUTE).into()
                / auction_duration.into()
    );
}

#[test]
#[should_panic]
fn test_should_fail_when_current_auction_credit_amount_not_in_intended_credit_amount_range_when_offer() {
    let dsp = deploy();

    let mut _proposal = proposal();
    _proposal.is_offer = true;
    _proposal.min_credit_amount = 0;
    _proposal.max_credit_amount = 100_000;
    _proposal.auction_start = 1;
    _proposal.auction_duration = MINUTE * 100;

    cheat_block_timestamp_global(_proposal.auction_start + _proposal.auction_duration / 2);

    let mut _proposal_values = proposal_values();
    _proposal_values.slippage = 500;
    _proposal_values.intended_credit_amount = 1_000;

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 0, dsp.proposal.encode_proposal_data(_proposal, _proposal_values),
        );
}

#[test]
#[should_panic]
fn test_should_fail_when_current_auction_credit_amount_not_in_intended_credit_amount_range_when_request() {
    let dsp = deploy();

    let mut _proposal = proposal();
    _proposal.is_offer = false;
    _proposal.min_credit_amount = 0;
    _proposal.max_credit_amount = 100_000;
    _proposal.auction_start = 1;
    _proposal.auction_duration = MINUTE * 100;

    cheat_block_timestamp_global(_proposal.auction_start + _proposal.auction_duration / 2);

    let mut _proposal_values = proposal_values();
    _proposal_values.slippage = 500;
    _proposal_values.intended_credit_amount = 90_000;

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 0, dsp.proposal.encode_proposal_data(_proposal, _proposal_values),
        );
}

#[test]
#[should_panic]
fn test_should_fail_when_caller_is_not_proposed_loan_contract() {
    let dsp = deploy();
    let _proposal = proposal();

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    let caller = starknet::contract_address_const::<'caller'>();

    cheat_caller_address(dsp.proposal.contract_address, caller, CheatSpan::TargetCalls(2));
    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 0, dsp.proposal.encode_proposal_data(_proposal, proposal_values())
        );
}

#[test]
#[should_panic]
fn test_should_fail_when_caller_not_tagged_active_loan() {
    let dsp = deploy();
    let _proposal = proposal();

    dsp.hub.set_tag(_proposal.loan_contract, pwn_hub_tags::ACTIVE_LOAN, false);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 0, dsp.proposal.encode_proposal_data(_proposal, proposal_values())
        );
}

#[test]
#[should_panic]
fn test_should_fail_when_proposer_is_same_as_acceptor() {
    let dsp = deploy();
    let _proposal = proposal();

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    dsp
        .proposal
        .accept_proposal(
            _proposal.proposer, 0, dsp.proposal.encode_proposal_data(_proposal, proposal_values())
        );
}

#[test]
#[should_panic]
fn test_should_fail_when_proposed_refinancing_loan_id_not_zero_when_refinancing_loan_id_zero() {
    let dsp = deploy();
    let mut _proposal = proposal();
    _proposal.refinancing_loan_id = 1;

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 0, dsp.proposal.encode_proposal_data(_proposal, proposal_values())
        );
}

#[test]
#[should_panic]
fn test_should_fail_when_refinancing_loan_ids_is_not_equal_when_proposed_refinancing_loan_id_not_zero_when_refinancing_loan_id_not_zero_when_offer() {
    let dsp = deploy();
    let mut _proposal = proposal();
    _proposal.refinancing_loan_id = 1;
    _proposal.is_offer = true;

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 2, dsp.proposal.encode_proposal_data(_proposal, proposal_values())
        );
}

#[test]
fn test_should_pass_when_refinancing_loan_ids_not_equal_when_proposed_refinancing_loan_id_zero_when_refinancing_loan_id_not_zero_when_offer() {
    let dsp = deploy();
    let mut _proposal = proposal();
    _proposal.refinancing_loan_id = 0;
    _proposal.is_offer = true;

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 2, dsp.proposal.encode_proposal_data(_proposal, proposal_values())
        );
}

#[test]
#[should_panic]
fn test_should_fail_when_refinancing_loan_ids_not_equal_when_refinancing_loan_id_not_zero_when_request() {
    let dsp = deploy();
    let mut _proposal = proposal();
    _proposal.refinancing_loan_id = 0;
    _proposal.is_offer = false;

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 2, dsp.proposal.encode_proposal_data(_proposal, proposal_values())
        );
}

#[test]
#[should_panic]
fn test_should_fail_when_offer_nonce_not_usable() {
    let dsp = deploy();
    let _proposal = proposal();

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    mock_call(dsp.nonce.contract_address, selector!("is_nonce_usable"), false, 1);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 0, dsp.proposal.encode_proposal_data(_proposal, proposal_values())
        );
}

#[test]
#[should_panic]
fn test_should_fail_when_caller_is_not_allowed_acceptor() {
    let dsp = deploy();
    let mut _proposal = proposal();
    _proposal.allowed_acceptor = starknet::contract_address_const::<'allowed_acceptor'>();

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 0, dsp.proposal.encode_proposal_data(_proposal, proposal_values())
        );
}

#[test]
fn test_should_revoke_offer_when_available_credit_limit_equal_to_zero() {
    let dsp = deploy();
    let mut _proposal = proposal();
    _proposal.available_credit_limit = 0;

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    assert!(
        dsp.nonce.is_nonce_usable(_proposal.proposer, _proposal.nonce_space, _proposal.nonce),
        "Nonce is not usable"
    );

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 0, dsp.proposal.encode_proposal_data(_proposal, proposal_values())
        );

    assert!(
        !dsp.nonce.is_nonce_usable(_proposal.proposer, _proposal.nonce_space, _proposal.nonce),
        "Nonce is usable"
    );
}

#[test]
#[should_panic]
fn test_should_fail_when_used_credit_exceeds_available_credit_limit() {
    let dsp = deploy();
    let mut _proposal = proposal();
    _proposal.available_credit_limit = 1;

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 0, dsp.proposal.encode_proposal_data(_proposal, proposal_values())
        );
}

#[test]
fn test_should_increase_used_credit_when_used_credit_not_exceeds_available_credit_limit() {
    let dsp = deploy();
    let mut _proposal = proposal();
    _proposal.available_credit_limit = 100_000;

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    let (proposal_hash, terms) = dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 0, dsp.proposal.encode_proposal_data(_proposal, proposal_values())
        );

    let simple_loan_proposal = ISimpleLoanProposalDispatcher {
        contract_address: dsp.proposal.contract_address
    };
    let current_credit_used = simple_loan_proposal.get_credit_used(proposal_hash);
    assert_eq!(current_credit_used, terms.credit.amount, "Credit used imbalanced");
}

#[test]
#[should_panic]
fn test_should_fail_when_computer_registry_returns_computer_when_computer_returns_different_state_fingerprint() {
    let dsp = deploy();
    let mut _proposal = proposal();
    _proposal.check_collateral_state_fingerprint = true;

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    mock_call(
        SF_COMPUTER(),
        selector!("compute_state_fingerprint"),
        _proposal.collateral_state_fingerprint + 1,
        1
    );
    mock_call(SF_COMPUTER(), selector!("supports_token"), true, 1);

    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 0, dsp.proposal.encode_proposal_data(_proposal, proposal_values())
        );
}

#[test]
fn test_should_pass_when_computer_returns_matching_fingerprint() {
    let dsp = deploy();
    let mut _proposal = proposal();
    _proposal.check_collateral_state_fingerprint = true;

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    mock_call(
        SF_COMPUTER(),
        selector!("compute_state_fingerprint"),
        _proposal.collateral_state_fingerprint,
        1
    );
    mock_call(SF_COMPUTER(), selector!("supports_token"), true, 1);

    dsp.config.register_state_fingerprint_computer(TOKEN(), SF_COMPUTER());

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 0, dsp.proposal.encode_proposal_data(_proposal, proposal_values())
        );
}

#[test]
fn test_should_call_loan_contract_with_loan_terms() {
    let dsp = deploy();

    let mut _proposal = proposal();
    _proposal.is_offer = true;

    cheat_block_timestamp_global(_proposal.auction_start + 1_000);

    let credit_amount = dsp.proposal.get_credit_amount(_proposal, starknet::get_block_timestamp());

    let mut _proposal_values = proposal_values();
    _proposal_values.intended_credit_amount = _proposal.min_credit_amount;

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    let (proposal_hash, terms) = dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 0, dsp.proposal.encode_proposal_data(_proposal, _proposal_values),
        );

    assert_eq!(proposal_hash, proposal_hash(_proposal));
    assert_eq!(terms.lender, _proposal.proposer);
    assert_eq!(terms.borrower, ACCEPTOR());
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
    assert_eq!(terms.accruing_interest_APR, _proposal.accruing_interest_APR);
    assert_eq!(terms.lender_spec_hash, _proposal.proposer_spec_hash);
    assert_eq!(terms.borrower_spec_hash, 0);

    _proposal.is_offer = false;
    _proposal.nonce += 1;
    _proposal_values.intended_credit_amount = _proposal.max_credit_amount;

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.proposer, CheatSpan::TargetCalls(1)
    );
    dsp.proposal.make_proposal(_proposal);

    cheat_caller_address(
        dsp.proposal.contract_address, _proposal.loan_contract, CheatSpan::TargetCalls(2)
    );
    let (_, terms) = dsp
        .proposal
        .accept_proposal(
            ACCEPTOR(), 0, dsp.proposal.encode_proposal_data(_proposal, _proposal_values),
        );

    assert_eq!(terms.lender, ACCEPTOR());
    assert_eq!(terms.borrower, _proposal.proposer);
    assert_eq!(terms.lender_spec_hash, 0);
    assert_eq!(terms.borrower_spec_hash, _proposal.proposer_spec_hash);
}
