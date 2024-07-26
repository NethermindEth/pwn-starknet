use core::integer::BoundedInt;
use core::poseidon::poseidon_hash_span;
use core::result::ResultTrait;
use core::serde::Serde;
use core::traits::Into;
use openzeppelin::account::interface::{IPublicKeyDispatcher, IPublicKeyDispatcherTrait};
use openzeppelin::token::{
    erc20::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
    erc721::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait},
    erc1155::interface::{ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait},
};
use pwn::loan::terms::simple::loan::{
    interface::{
        IPwnSimpleLoanDispatcher, IPwnSimpleLoanDispatcherTrait, IPwnSimpleLoanSafeDispatcher,
        IPwnSimpleLoanSafeDispatcherTrait
    },
    pwn_simple_loan::PwnSimpleLoan::{
        MIN_LOAN_DURATION, MAX_ACCRUING_INTEREST_APR, MAX_EXTENSION_DURATION, MIN_EXTENSION_DURATION
    },
    types
};

use pwn::{
    nonce::revoked_nonce::{IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait},
    multitoken::{
        library::MultiToken,
        category_registry::{
            IMultiTokenCategoryRegistryDispatcher, IMultiTokenCategoryRegistryDispatcherTrait
        }
    },
    hub::pwn_hub_tags,
    interfaces::pool_adapter::{IPoolAdapterDispatcher, IPoolAdapterDispatcherTrait},
    hub::pwn_hub::{IPwnHubDispatcher, IPwnHubDispatcherTrait},
    config::interface::{IPwnConfigDispatcher, IPwnConfigDispatcherTrait},
    loan::{
        lib::{signature_checker, math,}, vault::permit,
        token::pwn_loan::{IPwnLoanDispatcher, IPwnLoanDispatcherTrait},
    },
};
use snforge_std::{
    declare, store, load, map_entry_address, cheat_caller_address, cheat_block_timestamp_global,
    mock_call, spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait,
    signature::{
        KeyPairTrait, SignerTrait, KeyPair,
        stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
    },
    ContractClassTrait, CheatSpan
};
use starknet::ContractAddress;

impl U8IntoCategory of Into<u8, MultiToken::Category> {
    fn into(self: u8) -> MultiToken::Category {
        match self {
            0 => MultiToken::Category::ERC20,
            1 => MultiToken::Category::ERC721,
            2 => MultiToken::Category::ERC1155,
            _ => panic!("Invalid Category {}", self)
        }
    }
}

#[derive(Clone, Drop)]
pub struct Setup {
    pub hub: IPwnHubDispatcher,
    pub config: IPwnConfigDispatcher,
    pub nonce: IRevokedNonceDispatcher,
    pub registry: IMultiTokenCategoryRegistryDispatcher,
    pub loan_token: IPwnLoanDispatcher,
    pub loan: IPwnSimpleLoanDispatcher,
    pub pool_adapter: IPoolAdapterDispatcher,
    pub t20: ERC20ABIDispatcher,
    pub t721: ERC721ABIDispatcher,
    pub t1155: ERC1155ABIDispatcher,
    pub lender: IPublicKeyDispatcher,
    pub lender2: IPublicKeyDispatcher,
    pub borrower: IPublicKeyDispatcher,
    pub lender_key_pair: KeyPair<felt252, felt252>,
    pub borrower_key_pair: KeyPair<felt252, felt252>,
    pub fee_collector: ContractAddress,
    pub proposal_contract: ContractAddress,
    pub source_of_funds: ContractAddress,
    pub loan_id: felt252,
    pub loan_duration_days: u64,
    pub simple_loan: types::Loan,
    pub simple_loan_terms: types::Terms,
    pub proposal_spec: types::ProposalSpec,
    pub proposal_hash: felt252,
    pub lender_spec: types::LenderSpec,
    pub extension: types::ExtensionProposal,
    pub caller_spec: types::CallerSpec,
    pub refinanced_loan: types::Loan,
    pub refinanced_loan_terms: types::Terms
}

pub fn setup() -> Setup {
    let contract = declare("PwnHub").unwrap();
    let (hub_address, _) = contract.deploy(@array![]).unwrap();
    let hub = IPwnHubDispatcher { contract_address: hub_address };

    let contract = declare("PwnConfig").unwrap();
    let (config_address, _) = contract.deploy(@array![]).unwrap();
    let config = IPwnConfigDispatcher { contract_address: config_address };

    let contract = declare("RevokedNonce").unwrap();
    let (nonce_address, _) = contract
        .deploy(@array![hub_address.into(), pwn_hub_tags::ACTIVE_LOAN])
        .unwrap();
    let nonce = IRevokedNonceDispatcher { contract_address: nonce_address };

    let contract = declare("PwnLoan").unwrap();
    let (loan_token_address, _) = contract.deploy(@array![hub_address.into()]).unwrap();
    let loan_token = IPwnLoanDispatcher { contract_address: loan_token_address };

    let contract = declare("MultiTokenCategoryRegistry").unwrap();
    let (registry_address, _) = contract.deploy(@array![]).unwrap();
    let registry = IMultiTokenCategoryRegistryDispatcher { contract_address: registry_address };

    let contract = declare("PwnSimpleLoan").unwrap();
    let (loan_address, _) = contract
        .deploy(
            @array![
                hub_address.into(),
                loan_token_address.into(),
                config_address.into(),
                nonce_address.into(),
                registry_address.into()
            ]
        )
        .unwrap();
    let loan = IPwnSimpleLoanDispatcher { contract_address: loan_address };

    let erc20_contract = declare("ERC20Mock").unwrap();
    let (t20_address, _) = erc20_contract.deploy(@array![]).unwrap();
    let t20 = ERC20ABIDispatcher { contract_address: t20_address };
    registry.register_category_value(t20_address, MultiToken::Category::ERC20.into());

    let erc721_contract = declare("ERC721Mock").unwrap();
    let (t721_address, _) = erc721_contract.deploy(@array![]).unwrap();
    let t721 = ERC721ABIDispatcher { contract_address: t721_address };
    registry.register_category_value(t721_address, MultiToken::Category::ERC721.into());

    let erc1155_contract = declare("ERC1155Mock").unwrap();
    let (t1155_address, _) = erc1155_contract.deploy(@array![]).unwrap();
    let t1155 = ERC1155ABIDispatcher { contract_address: t1155_address };
    registry.register_category_value(t1155_address, MultiToken::Category::ERC1155.into());

    let lender_key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let contract = declare("AccountUpgradeable").unwrap();
    let (lender_address, _) = contract.deploy(@array![lender_key_pair.public_key]).unwrap();
    let lender = IPublicKeyDispatcher { contract_address: lender_address };

    let lender2_key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let (lender2_address, _) = contract.deploy(@array![lender2_key_pair.public_key]).unwrap();
    let lender2 = IPublicKeyDispatcher { contract_address: lender2_address };

    let borrower_key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let (borrower_address, _) = contract.deploy(@array![borrower_key_pair.public_key]).unwrap();
    let borrower = IPublicKeyDispatcher { contract_address: borrower_address };

    let contract = declare("MockPoolAdapter").unwrap();
    let (pool_adapter_address, _) = contract.deploy(@array![]).unwrap();
    let pool_adapter = IPoolAdapterDispatcher { contract_address: pool_adapter_address };
    let proposal_contract_address = starknet::contract_address_const::<'proposalContract'>();
    hub.set_tag(proposal_contract_address, pwn_hub_tags::LOAN_PROPOSAL, true);
    hub.set_tag(loan_address, pwn_hub_tags::ACTIVE_LOAN, true);
    let loan_duration_days = 101;
    let simple_loan = types::Loan {
        status: 2_u8,
        credit_address: t20_address,
        original_source_of_funds: lender_address,
        start_timestamp: starknet::get_block_timestamp(),
        default_timestamp: starknet::get_block_timestamp() + loan_duration_days * DAY,
        borrower: borrower_address,
        original_lender: lender_address,
        accruing_interest_APR: 0,
        fixed_interest_amount: 6631,
        principal_amount: 100,
        collateral: MultiToken::Asset {
            category: MultiToken::Category::ERC721, asset_address: t721_address, id: 2, amount: 0
        },
    };

    let simple_loan_terms = types::Terms {
        lender: lender_address,
        borrower: borrower_address,
        duration: loan_duration_days * DAY,
        collateral: MultiToken::Asset {
            category: MultiToken::Category::ERC721, asset_address: t721_address, id: 2, amount: 0
        },
        credit: MultiToken::Asset {
            category: MultiToken::Category::ERC20, asset_address: t20_address, id: 0, amount: 100
        },
        fixed_interest_amount: 6631,
        accruing_interest_APR: 0,
        lender_spec_hash: poseidon_hash_span(
            array![Into::<ContractAddress, felt252>::into(lender_address)].span()
        ),
        borrower_spec_hash: 0
    };

    let key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let (r, s) = key_pair.sign(poseidon_hash_span(array!['proposalHash'].span())).unwrap();

    let proposal_spec = types::ProposalSpec {
        proposal_contract: proposal_contract_address,
        proposal_data: array!['proposalData'],
        proposal_inclusion_proof: array![],
        signature: signature_checker::Signature { r, s }
    };

    let lender_spec = types::LenderSpec { source_of_funds: lender_address };
    let source_of_funds = starknet::contract_address_const::<'sourceOfFunds'>();

    erc20_mint(t20_address, lender_address, 6831);
    erc20_mint(t20_address, borrower_address, 6831);
    erc20_mint(t20_address, starknet::get_contract_address(), 6831);
    erc20_mint(t20_address, loan_address, 6831);
    erc20_mint(t20_address, source_of_funds, E30);

    erc721_mint(t721_address, borrower_address, 2);

    cheat_caller_address(t20_address, lender_address, CheatSpan::TargetCalls(1));
    t20.approve(loan_address, BoundedInt::max());

    cheat_caller_address(t20_address, borrower_address, CheatSpan::TargetCalls(1));
    t20.approve(loan_address, BoundedInt::max());

    cheat_caller_address(t20_address, source_of_funds, CheatSpan::TargetCalls(1));
    t20.approve(pool_adapter_address, BoundedInt::max());

    t20.approve(loan_address, BoundedInt::max());

    cheat_caller_address(t721_address, borrower_address, CheatSpan::TargetCalls(1));
    t721.approve(loan_address, 2);

    let proposal_hash = 'proposalHash';
    let fee_collector = starknet::contract_address_const::<'feeCollector'>();

    mock_call(t20_address, selector!("permit"), (), BoundedInt::<u32>::max());

    mock_call(config_address, selector!("get_fee"), 0, BoundedInt::<u32>::max());
    mock_call(
        config_address, selector!("get_fee_collector"), fee_collector, BoundedInt::<u32>::max()
    );
    mock_call(
        config_address, selector!("get_pool_adapter"), pool_adapter, BoundedInt::<u32>::max()
    );

    mock_call(
        proposal_contract_address,
        selector!("accept_proposal"),
        (proposal_hash, simple_loan_terms),
        BoundedInt::<u32>::max()
    );

    let extension = types::ExtensionProposal {
        loan_id: 42,
        compensation_address: t20_address,
        compensation_amount: 100,
        duration: 2 * DAY,
        expiration: simple_loan.default_timestamp,
        proposer: borrower_address,
        nonce_space: 1,
        nonce: 1,
    };

    Setup {
        hub,
        config,
        nonce,
        registry,
        loan_token,
        loan,
        pool_adapter,
        t20,
        t721,
        t1155,
        lender,
        lender2,
        borrower,
        lender_key_pair,
        borrower_key_pair,
        fee_collector: fee_collector,
        proposal_contract: proposal_contract_address,
        source_of_funds: source_of_funds,
        loan_id: 42,
        loan_duration_days: 101,
        simple_loan: simple_loan,
        simple_loan_terms: simple_loan_terms,
        proposal_spec: proposal_spec,
        proposal_hash: proposal_hash,
        lender_spec: lender_spec,
        extension: extension,
        caller_spec: Default::default(),
        refinanced_loan: Default::default(),
        refinanced_loan_terms: Default::default()
    }
}

pub const E30: u256 = 1_000_000_000_000_000_000_000_000_000_000;
pub const E20: u256 = 100_000_000_000_000_000_000;
pub const E18: u256 = 1_000_000_000_000_000_000;
pub const DAY: u64 = 86400;

pub(crate) fn erc20_mint(erc20: ContractAddress, receiver: ContractAddress, amount: u256) {
    let current_balance = ERC20ABIDispatcher { contract_address: erc20 }.balance_of(receiver);
    let total_supply = ERC20ABIDispatcher { contract_address: erc20 }.total_supply();
    let mut serialized_supply: Array<felt252> = array![];
    (total_supply + amount).serialize(ref serialized_supply);
    store(
        erc20,
        map_entry_address(selector!("ERC20_total_supply"), array![].span(),),
        serialized_supply.span()
    );
    let mut serialized_balance: Array<felt252> = array![];
    (current_balance + amount).serialize(ref serialized_balance);
    store(
        erc20,
        map_entry_address(selector!("ERC20_balances"), array![receiver.into()].span(),),
        serialized_balance.span()
    );
}

pub(crate) fn erc721_mint(erc721: ContractAddress, receiver: ContractAddress, id: u256) {
    let mut id_serialized: Array<felt252> = array![];
    id.serialize(ref id_serialized);

    let mut receiver_serialized: Array<felt252> = array![];
    receiver.serialize(ref receiver_serialized);
    store(
        erc721,
        map_entry_address(selector!("ERC721_owners"), id_serialized.span(),),
        receiver_serialized.span()
    );
    let new_balance: u256 = 1;
    let mut balance_serialized: Array<felt252> = array![];
    new_balance.serialize(ref balance_serialized);
    store(
        erc721,
        map_entry_address(selector!("ERC721_balances"), receiver_serialized.span(),),
        balance_serialized.span()
    );
}

pub(crate) fn erc1155_mint(
    erc1155: ContractAddress, receiver: ContractAddress, id: u256, amount: u256
) {
    let mut serialized: Array<felt252> = array![];
    id.serialize(ref serialized);
    receiver.serialize(ref serialized);

    store(
        erc1155,
        map_entry_address(selector!("ERC1155_balances"), serialized.span(),),
        array![amount.try_into().unwrap()].span()
    );
}


// pub fn print_all_addresses(setup: Setup) {
//     println!("Proposal contract: {:?}", setup.propo);
//     println!("Loan token contract: {:?}", LOAN_TOKEN());
//     println!("SimpleLoan contract: {:?}", SIMPLE_LOAN_ADDRESS());
//     println!("ERC20 contract: {:?}", ERC20_MOCK_ADDRESS());
//     println!("ERC721 contract: {:?}", ERC721_MOCK_ADDRESS());
//     println!("ERC1155 contract: {:?}", ERC1155_MOCK_ADDRESS());
//     println!("HUB contract: {:?}", HUB());
//     println!("CONFIG contract: {:?}", CONFIG());
//     println!("CategoryRegistry contract: {:?}", CATEGORY_REGISTRY());
//     println!("POOL_ADAPTER_MOCK_ADDRESS contract: {:?}", POOL_ADAPTER_MOCK_ADDRESS());
//     println!("Nonce contract: {:?}", REVOKED_NONCE());
//     println!("BORROWER {:?}", BORROWER());
//     println!("LENDER {:?}", setup.lender);
//     println!("SOURCE_OF_FUNDS {:?}", SOURCE_OF_FUNDS());
//     println!("ALICE {:?}", ALICE());
//     println!("FEE_COLLECTOR {:?}", FEE_COLLECTOR());
// }

pub fn store_loan(address: ContractAddress, loan_id: felt252, loan: types::Loan) {
    let mut serialized_loan: Array<felt252> = array![];
    loan.serialize(ref serialized_loan);
    store(
        address,
        map_entry_address(selector!("loans"), array![loan_id].span()),
        serialized_loan.span()
    );
}

fn assert_loan_eq(address: ContractAddress, loan_id: felt252, loan: types::Loan) {
    let stored_loan_raw = load(
        address, map_entry_address(selector!("loans"), array![loan_id].span()), 17
    );

    assert_eq!(TryInto::<felt252, u8>::try_into(*stored_loan_raw.at(0)).unwrap(), loan.status);
    assert_eq!(
        TryInto::<felt252, ContractAddress>::try_into(*stored_loan_raw.at(1)).unwrap(),
        loan.credit_address
    );
    assert_eq!(
        TryInto::<felt252, ContractAddress>::try_into(*stored_loan_raw.at(2)).unwrap(),
        loan.original_source_of_funds
    );
    assert_eq!(
        TryInto::<felt252, u64>::try_into(*stored_loan_raw.at(3)).unwrap(), loan.start_timestamp
    );
    assert_eq!(
        TryInto::<felt252, u64>::try_into(*stored_loan_raw.at(4)).unwrap(), loan.default_timestamp
    );
    assert_eq!(
        TryInto::<felt252, ContractAddress>::try_into(*stored_loan_raw.at(5)).unwrap(),
        loan.borrower
    );
    assert_eq!(
        TryInto::<felt252, ContractAddress>::try_into(*stored_loan_raw.at(6)).unwrap(),
        loan.original_lender
    );
    assert_eq!(
        TryInto::<felt252, u32>::try_into(*stored_loan_raw.at(7)).unwrap(),
        loan.accruing_interest_APR
    );
    assert_eq!(
        u256 {
            low: TryInto::<felt252, u128>::try_into(*stored_loan_raw.at(8)).unwrap(),
            high: TryInto::<felt252, u128>::try_into(*stored_loan_raw.at(9)).unwrap()
        },
        loan.fixed_interest_amount
    );
    assert_eq!(
        u256 {
            low: TryInto::<felt252, u128>::try_into(*stored_loan_raw.at(10)).unwrap(),
            high: TryInto::<felt252, u128>::try_into(*stored_loan_raw.at(11)).unwrap()
        },
        loan.principal_amount
    );
    assert_eq!(
        TryInto::<felt252, u8>::try_into(*stored_loan_raw.at(12)).unwrap(),
        loan.collateral.category.into()
    );
    assert_eq!(
        TryInto::<felt252, ContractAddress>::try_into(*stored_loan_raw.at(13)).unwrap(),
        loan.collateral.asset_address
    );
    assert_eq!(*stored_loan_raw.at(14), loan.collateral.id);
    assert_eq!(
        u256 {
            low: TryInto::<felt252, u128>::try_into(*stored_loan_raw.at(15)).unwrap(),
            high: TryInto::<felt252, u128>::try_into(*stored_loan_raw.at(16)).unwrap()
        },
        loan.collateral.amount
    );
}

mod get_lender_spec_hash {
    use core::traits::Into;
    use pwn::loan::terms::simple::loan::interface::IPwnSimpleLoanDispatcherTrait;
    use super::{poseidon_hash_span, setup, Setup, ContractAddress};

    #[test]
    fn test_should_return_lender_spec_hash() {
        let setup = setup();
        let lender_spec = setup.lender_spec;
        let expected = poseidon_hash_span(
            array![Into::<ContractAddress, felt252>::into(lender_spec.source_of_funds)].span()
        );
        let actual = setup.loan.get_lender_spec_hash(lender_spec);
        assert_eq!(expected, actual, "LENDER_SPEC_HASH does not match");
    }
}

mod create_loan {
    use core::array::ArrayTrait;
    use core::clone::Clone;
    use core::num::traits::zero::Zero;
    use core::option::OptionTrait;
    use core::serde::Serde;
    use core::traits::Into;
    use core::traits::TryInto;
    use pwn::loan::lib::fee_calculator;
    use pwn::loan::terms::simple::loan::pwn_simple_loan::PwnSimpleLoan;
    use pwn::loan::vault::permit::{Permit};
    use snforge_std::trace::get_call_trace;
    use super::super::simple_loan_proposal_test::E40;
    use super::{
        IPwnSimpleLoanDispatcher, IPwnSimpleLoanDispatcherTrait, IRevokedNonceDispatcher,
        IRevokedNonceDispatcherTrait, IPwnHubDispatcherTrait, ERC721ABIDispatcher,
        ERC721ABIDispatcherTrait, ERC20ABIDispatcher, ERC20ABIDispatcherTrait, ContractAddress,
        MultiToken, types::{CallerSpec, LenderSpec, ProposalSpec}, cheat_caller_address, CheatSpan,
        pwn_hub_tags, mock_call, MIN_LOAN_DURATION, MAX_ACCRUING_INTEREST_APR, load, store,
        map_entry_address, types, spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait,
        erc20_mint, assert_loan_eq, setup, Setup
    };

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_proposal_contract_not_tagged_loan_proposal(
        _proposal_contract: u128
    ) {
        let setup = setup();
        let mut proposal_contract: ContractAddress = Into::<u128, felt252>::into(_proposal_contract)
            .try_into()
            .unwrap();
        if proposal_contract == setup.proposal_contract {
            proposal_contract = Into::<u128, felt252>::into(_proposal_contract + 1)
                .try_into()
                .unwrap();
        }
        let mut proposal_spec = setup.proposal_spec;
        proposal_spec.proposal_contract = proposal_contract;
        setup
            .loan
            .create_loan(
                proposal_spec, setup.lender_spec, Default::default(), Option::Some(array![])
            );
    }

    #[test]
    fn test_fuzz_should_revoke_callers_nonce_when_flag_is_true(_caller: u128, nonce: felt252) {
        let setup = setup();
        let caller: ContractAddress = Into::<u128, felt252>::into(_caller).try_into().unwrap();
        let mut caller_spec: CallerSpec = Default::default();
        caller_spec.revoke_nonce = true;
        caller_spec.nonce = nonce;

        assert!(setup.nonce.is_nonce_usable(caller, 0, nonce), "Nonce {} is not usable", nonce);
        cheat_caller_address(setup.loan.contract_address, caller, CheatSpan::TargetCalls(1));
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, caller_spec, Option::Some(array![])
            );
        assert!(!setup.nonce.is_nonce_usable(caller, 0, nonce), "Nonce {} is usable", nonce);
    }


    #[test]
    fn test_fuzz_should_not_revoke_callers_nonce_when_flag_is_false(_caller: u128, nonce: felt252) {
        let setup = setup();
        let caller: ContractAddress = Into::<u128, felt252>::into(_caller).try_into().unwrap();
        let mut caller_spec: CallerSpec = Default::default();
        caller_spec.nonce = nonce;

        assert!(setup.nonce.is_nonce_usable(caller, 0, nonce), "Nonce {} is not usable", nonce);
        cheat_caller_address(setup.loan.contract_address, caller, CheatSpan::TargetCalls(1));
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, caller_spec, Option::Some(array![])
            );
        assert!(setup.nonce.is_nonce_usable(caller, 0, nonce), "Nonce {} is not usable", nonce);
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_call_proposal_contract() {
        assert(true, '');
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_caller_not_lender_when_lender_spec_hash_mismatch(
        mut _lender_spec_hash: felt252
    ) {
        let setup = setup();

        if _lender_spec_hash == setup.loan.get_lender_spec_hash(setup.lender_spec) {
            _lender_spec_hash += 1;
        }
        let mut terms = setup.simple_loan_terms;
        terms.lender_spec_hash = _lender_spec_hash;
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );

        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, Default::default(), Option::Some(array![])
            );
    }

    #[test]
    fn test_should_not_fail_when_caller_lender_when_lender_spec_hash_mismatch() {
        let setup = setup();

        let mut terms = setup.simple_loan_terms;
        terms.lender_spec_hash = 0;
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, Default::default(), Option::Some(array![])
            );
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_loan_terms_duration_less_than_min(mut duration: u64) {
        let setup = setup();

        if duration >= MIN_LOAN_DURATION {
            duration %= duration % MIN_LOAN_DURATION;
        }

        let mut terms = setup.simple_loan_terms;
        terms.duration = duration;
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, Default::default(), Option::Some(array![])
            );
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_loan_terms_interest_apr_out_of_bounds(
        mut accruing_interest_APR: u32
    ) {
        let setup = setup();

        if accruing_interest_APR < MAX_ACCRUING_INTEREST_APR {
            accruing_interest_APR += MAX_ACCRUING_INTEREST_APR + 1;
        }

        let mut terms = setup.simple_loan_terms;
        terms.accruing_interest_APR = accruing_interest_APR;
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, Default::default(), Option::Some(array![])
            );
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_invalid_credit_asset() {
        let setup = setup();
        mock_call(
            setup.proposal_contract,
            selector!("accept_proposal"),
            (setup.proposal_hash, setup.simple_loan_terms),
            1
        );

        mock_call(
            setup.registry.contract_address,
            selector!("registered_category_value"),
            Into::<MultiToken::Category, u8>::into(MultiToken::Category::ERC721),
            1
        );

        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, Default::default(), Option::Some(array![])
            );
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_invalid_collateral_asset() {
        let setup = setup();

        mock_call(
            setup.proposal_contract,
            selector!("accept_proposal"),
            (setup.proposal_hash, setup.simple_loan_terms),
            1
        );
        mock_call(
            setup.registry.contract_address,
            selector!("registered_category_value"),
            Into::<MultiToken::Category, u8>::into(MultiToken::Category::ERC20),
            2
        );
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, Default::default(), Option::Some(array![])
            );
    }

    #[test]
    fn test_should_mint_loan_token() {
        let setup = setup();
        let loan_token = ERC721ABIDispatcher {
            contract_address: setup.loan_token.contract_address
        };
        let prev_bal = loan_token.balance_of(setup.lender.contract_address);
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, Default::default(), Option::Some(array![])
            );
        let curr_bal = loan_token.balance_of(setup.lender.contract_address);
        assert_lt!(prev_bal, curr_bal, "Loan token not minted!");
    }

    #[test]
    fn test_should_store_loan_data() {
        let setup = setup();
        let loan_id = setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, Default::default(), Option::Some(array![])
            );
        assert_loan_eq(setup.loan.contract_address, loan_id, setup.simple_loan);
    }

    // #[test]
    // #[ignore]
    // fn test_fuzz_should_fail_when_invalid_permit_data_permit_owner(mut _permit_owner: felt252) {
    //     let setup = setup();
    //     let mut permit_owner: ContractAddress = _permit_owner.try_into().unwrap();
    //     while permit_owner == BORROWER()
    //         || permit_owner == starknet::contract_address_const::<
    //             0
    //         >() {
    //             _permit_owner += 1;
    //             permit_owner = _permit_owner.try_into().unwrap();
    //         };
    // 
    //     let simple_loan = SIMPLE_LOAN();
    // 
    //     let permit = Permit {
    //         asset: simple_loan.credit_address,
    //         owner: permit_owner,
    //         amount: 0_u256,
    //         deadline: 0,
    //         r: 0,
    //         s: 0
    //     };
    // 
    //     let mut caller_spec: CallerSpec = Default::default();
    //     permit.serialize(ref caller_spec.permit_data);
    // 
    //     cheat_caller_address(loan.contract_address, BORROWER(), CheatSpan::TargetCalls(1));
    //     loan.create_loan(setup.proposal_spec, setup.lender_spec, caller_spec, Option::Some(array![]));
    // }

    //#[test]
    //#[should_panic]
    //fn test_fuzz_should_fail_when_invalid_permit_data_permit_asset(mut _permit_asset: u128) {
    //    let setup = setup();
    //    let simple_loan = SIMPLE_LOAN();
    //    let mut _permit_asset: felt252 = _permit_asset.into();
    //    let mut permit_asset: ContractAddress = _permit_asset.try_into().unwrap();
    //    while permit_asset == simple_loan.credit_address
    //        || permit_asset == starknet::contract_address_const::<
    //            0
    //        >() {
    //            _permit_asset += 1;
    //            permit_asset = _permit_asset.try_into().unwrap();
    //        };
    //
    //    let permit = Permit {
    //        asset: permit_asset, owner: BORROWER(), amount: 0_u256, deadline: 0, r: 0, s: 0
    //    };
    //
    //    let mut caller_spec: CallerSpec = Default::default();
    //    permit.serialize(ref caller_spec.permit_data);
    //
    //    cheat_caller_address(loan.contract_address, BORROWER(), CheatSpan::TargetCalls(1));
    //    loan.create_loan(setup.proposal_spec, setup.lender_spec, caller_spec, Option::Some(array![]));
    //}

    #[test]
    #[ignore]
    fn test_should_call_permit_when_provided() {
        assert(true, '');
    }

    #[test]
    fn test_should_transfer_collateral_from_borrower_to_vault() {
        let setup = setup();

        let mut terms = setup.simple_loan_terms;
        terms
            .collateral =
                MultiToken::Asset {
                    category: MultiToken::Category::ERC20,
                    asset_address: setup.t20.contract_address,
                    id: 0,
                    amount: 50
                };

        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        let collateral = ERC20ABIDispatcher { contract_address: setup.t20.contract_address };
        let borrower = setup.borrower.contract_address;
        let prev_bal_loan = collateral.balance_of(setup.loan.contract_address);
        let prev_bal = collateral.balance_of(borrower);

        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, Default::default(), Option::Some(array![])
            );

        let curr_bal = collateral.balance_of(borrower);
        let curr_bal_loan = collateral.balance_of(setup.loan.contract_address);
        assert_eq!(
            prev_bal_loan,
            curr_bal_loan - terms.collateral.amount,
            "Didn't transferred tokens to loan contract"
        );
        assert_eq!(
            prev_bal + terms.credit.amount - terms.collateral.amount,
            curr_bal,
            "Didn't transferred tokens from borrower"
        );
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_pool_adapter_not_registered_when_pool_source_of_funds() {
        let setup = setup();

        let mut lender_spec = setup.lender_spec;
        lender_spec.source_of_funds = setup.source_of_funds;

        let mut terms = setup.simple_loan_terms;
        terms.lender_spec_hash = setup.loan.get_lender_spec_hash(lender_spec);
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        mock_call(
            setup.config.contract_address,
            selector!("get_pool_adapter"),
            starknet::contract_address_const::<0>(),
            1
        );
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, Default::default(), Option::Some(array![])
            );
    }

    #[test]
    fn test_fuzz_should_call_withdraw_when_pool_source_of_funds(mut loan_amount: u256) {
        loan_amount %= E40;
        if loan_amount == 0 {
            loan_amount = 1;
        }

        let setup = setup();

        let mut lender_spec = setup.lender_spec;
        lender_spec.source_of_funds = setup.source_of_funds;

        let mut terms = setup.simple_loan_terms;
        terms.credit.amount = loan_amount;
        terms.lender_spec_hash = setup.loan.get_lender_spec_hash(lender_spec);
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        let mut loan_amount_serialized: Array<felt252> = array![];
        loan_amount.serialize(ref loan_amount_serialized);
        store(
            setup.t20.contract_address,
            map_entry_address(
                selector!("ERC20_balances"), array![setup.source_of_funds.into()].span()
            ),
            loan_amount_serialized.span()
        );

        let prev_bal = setup.t20.balance_of(setup.source_of_funds);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, Default::default(), Option::Some(array![])
            );
        let curr_bal = setup.t20.balance_of(setup.source_of_funds);
        assert_eq!(
            prev_bal - loan_amount,
            curr_bal,
            "Pool havent called and transferred funds from source_of_funds"
        );
    }

    #[test]
    fn test_fuzz_should_transfer_credit_to_borrower_and_fee_collector(
        mut fee: u16, mut loan_amount: u256
    ) {
        fee %= 9999;
        loan_amount %= E40;
        if loan_amount == 0 {
            loan_amount += 1;
        }
        let setup = setup();
        let mut terms = setup.simple_loan_terms;
        terms.credit.amount = loan_amount;

        erc20_mint(setup.t20.contract_address, setup.lender.contract_address, loan_amount);
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        mock_call(setup.config.contract_address, selector!("get_fee"), fee, 1);
        let (fee_amount, loan_amount) = fee_calculator::calculate_fee_amount(fee, loan_amount);
        let prev_bal_borrower = setup.t20.balance_of(setup.borrower.contract_address);
        let prev_bal_lender = setup.t20.balance_of(setup.lender.contract_address);
        let prev_bal_fee_collector = setup.t20.balance_of(setup.fee_collector);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, Default::default(), Option::Some(array![])
            );
        let curr_bal_borrower = setup.t20.balance_of(setup.borrower.contract_address);
        let curr_bal_lender = setup.t20.balance_of(setup.lender.contract_address);
        let curr_bal_fee_collector = setup.t20.balance_of(setup.fee_collector);
        assert_eq!(prev_bal_borrower + loan_amount - terms.collateral.amount, curr_bal_borrower);
        assert_eq!(
            prev_bal_lender - loan_amount - fee_amount + terms.collateral.amount, curr_bal_lender
        );
        assert_eq!(prev_bal_fee_collector + fee_amount, curr_bal_fee_collector);
    }

    #[test]
    fn test_should_emit_loan_created() {
        let setup = setup();
        let caller_spec: CallerSpec = Default::default();
        let refinancing_loan_id = caller_spec.refinancing_loan_id;
        let lender_spec = setup.lender_spec;
        let proposal_spec = setup.proposal_spec;
        let proposal_contract = proposal_spec.proposal_contract;
        let mut spy = spy_events();
        let loan_id = setup
            .loan
            .create_loan(
                proposal_spec, lender_spec, caller_spec, Option::Some(array!['lil extra'])
            );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.loan.contract_address,
                        PwnSimpleLoan::Event::LoanCreated(
                            PwnSimpleLoan::LoanCreated {
                                loan_id: loan_id,
                                proposal_hash: setup.proposal_hash,
                                proposal_contract: proposal_contract,
                                refinancing_loan_id: refinancing_loan_id,
                                terms: setup.simple_loan_terms,
                                lender_spec: lender_spec,
                                extra: Option::Some(array!['lil extra']),
                            }
                        )
                    )
                ]
            );
    }

    #[test]
    fn test_fuzz_should_return_new_loan_id(_loan_id: felt252) {
        let setup = setup();
        mock_call(setup.loan_token.contract_address, selector!("mint"), _loan_id, 1);
        let loan_id = setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, Default::default(), Option::Some(array![])
            );
        assert_eq!(_loan_id, loan_id, "Loan ID mismatch!");
    }
}

mod refinance_loan {
    use core::traits::Into;
    use core::traits::TryInto;
    use core::integer::BoundedInt;
    use starknet::ContractAddress;
    use openzeppelin::token::{
        erc20::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
        erc721::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait},
        erc1155::interface::{ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait},
    };
    use pwn::loan::lib::fee_calculator;
    use pwn::loan::terms::simple::loan::pwn_simple_loan::PwnSimpleLoan;
    use super::super::simple_loan_proposal_test::E40;
    use super::{
        types, MultiToken, erc20_mint, erc721_mint, poseidon_hash_span, store_loan, IPwnSimpleLoanDispatcherTrait, IPwnLoanDispatcherTrait,
        U8IntoCategory, assert_loan_eq, E20, DAY
    };

    use snforge_std::{
        declare, store, load, map_entry_address, cheat_caller_address, cheat_block_timestamp_global,
        mock_call, spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait,
        signature::{
            KeyPairTrait, SignerTrait, KeyPair,
            stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
        },
        ContractClassTrait, CheatSpan
    };

    fn setup() -> super::Setup {
        let mut setup = super::setup();

        cheat_caller_address(
            setup.t721.contract_address, setup.borrower.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.t721.transfer_from(setup.borrower.contract_address, setup.loan.contract_address, 2);

        let new_lender = setup.lender2.contract_address;
        cheat_caller_address(setup.t20.contract_address, new_lender, CheatSpan::TargetCalls(1));
        setup.t20.approve(setup.loan.contract_address, BoundedInt::max());

        setup
            .refinanced_loan =
                types::Loan {
                    status: 2,
                    credit_address: setup.t20.contract_address,
                    original_source_of_funds: setup.lender.contract_address,
                    start_timestamp: starknet::get_block_timestamp(),
                    default_timestamp: starknet::get_block_timestamp() + 40039,
                    borrower: setup.borrower.contract_address,
                    original_lender: setup.lender.contract_address,
                    accruing_interest_APR: 0,
                    fixed_interest_amount: 6631,
                    principal_amount: E20,
                    collateral: MultiToken::Asset {
                        category: MultiToken::Category::ERC721,
                        asset_address: setup.t721.contract_address,
                        id: 2,
                        amount: 0
                    },
                };

        setup
            .refinanced_loan_terms =
                types::Terms {
                    lender: setup.lender.contract_address,
                    borrower: setup.borrower.contract_address,
                    duration: 40039,
                    collateral: MultiToken::Asset {
                        category: MultiToken::Category::ERC721,
                        asset_address: setup.t721.contract_address,
                        id: 2,
                        amount: 0
                    },
                    credit: MultiToken::Asset {
                        category: MultiToken::Category::ERC20,
                        asset_address: setup.t20.contract_address,
                        id: 0,
                        amount: E20
                    },
                    fixed_interest_amount: 6631,
                    accruing_interest_APR: 0,
                    lender_spec_hash: poseidon_hash_span(
                        array![setup.lender.contract_address.into()].span()
                    ),
                    borrower_spec_hash: 0,
                };

        setup.caller_spec.refinancing_loan_id = REFINANCING_LOAN_ID;

        mock_call(
            setup.proposal_contract,
            selector!("accept_proposal"),
            (setup.proposal_hash, setup.refinanced_loan_terms),
            1
        );
        mock_call(setup.loan_token.contract_address, selector!("owner_of"), setup.lender, 1);

        erc20_mint(setup.t20.contract_address, new_lender, E20);
        erc20_mint(setup.t20.contract_address, setup.lender.contract_address, E20);
        erc20_mint(setup.t20.contract_address, setup.loan.contract_address, E20);
        store_loan(setup.t20.contract_address, REFINANCING_LOAN_ID, setup.simple_loan);

        erc721_mint(
            setup.loan_token.contract_address,
            setup.lender.contract_address,
            REFINANCING_LOAN_ID.into()
        );
        store_loan(setup.loan.contract_address, REFINANCING_LOAN_ID, setup.simple_loan);
        store(
            setup.loan_token.contract_address,
            map_entry_address(
                selector!("loan_contract"), array![REFINANCING_LOAN_ID.into()].span()
            ),
            array![setup.loan.contract_address.into()].span()
        );
        setup
    }

    pub const REFINANCING_LOAN_ID: felt252 = 44;

    #[test]
    #[should_panic(expected: "Loan does not exist")]
    fn test_should_fail_when_loan_does_not_exist() {
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.status = 0;
        store_loan(setup.loan.contract_address, REFINANCING_LOAN_ID, simple_loan);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );
    }

    #[test]
    #[should_panic(expected: "Loan is not running")]
    fn test_should_fail_when_loan_is_not_running() {
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.status = 3;
        store_loan(setup.loan.contract_address, REFINANCING_LOAN_ID, simple_loan);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_loan_is_defaulted() {
        let setup = setup();
        cheat_block_timestamp_global(setup.simple_loan.default_timestamp);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );
    }

    #[test]
    #[should_panic(expected: "Credit is not the same")]
    fn test_fuzz_should_fail_when_credit_asset_mismatch(_asset_address: u128) {
        let setup = setup();
        let simple_loan = setup.simple_loan;
        let mut _asset_address: felt252 = _asset_address.into();
        let mut asset_address: ContractAddress = _asset_address.try_into().unwrap();
        while asset_address == simple_loan
            .credit_address {
                _asset_address += 1;
                asset_address = _asset_address.try_into().unwrap();
            };

        let mut terms = setup.refinanced_loan_terms;
        terms.credit.asset_address = asset_address;
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );

        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );
    }

    #[test]
    #[should_panic(expected: "Credit is not the same")]
    fn test_should_fail_when_credit_asset_amount_zero() {
        let setup = setup();
        let mut terms = setup.refinanced_loan_terms;
        terms.credit.amount = 0;
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );
    }

    #[test]
    #[should_panic(expected: "Collateral is not the same")]
    fn test_fuzz_should_fail_when_collateral_category_mismatch(mut category: u8) {
        let setup = setup();
        category %= 3;
        let simple_loan = setup.simple_loan;
        if category == simple_loan.collateral.category.into() {
            category = (category + 1) % 3;
        }
        let mut terms = setup.refinanced_loan_terms;
        terms.collateral.category = category.into();
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );
    }

    #[test]
    #[should_panic(expected: "Collateral is not the same")]
    fn test_fuzz_should_fail_when_collateral_address_mismatch(_asset_address: u128) {
        let setup = setup();
        let simple_loan = setup.simple_loan;
        let mut _asset_address: felt252 = _asset_address.into();
        let mut asset_address: ContractAddress = _asset_address.try_into().unwrap();
        while asset_address == simple_loan
            .collateral
            .asset_address {
                _asset_address += 1;
                asset_address = _asset_address.try_into().unwrap();
            };

        let mut terms = setup.refinanced_loan_terms;
        terms.collateral.asset_address = asset_address;
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );

        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );
    }

    #[test]
    #[should_panic(expected: "Collateral is not the same")]
    fn test_fuzz_should_fail_when_collateral_id_mismatch(mut id: felt252) {
        let setup = setup();
        let simple_loan = setup.simple_loan;
        if id == simple_loan.collateral.id {
            id += 1;
        };

        let mut terms = setup.refinanced_loan_terms;
        terms.collateral.id = id;
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );

        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );
    }

    #[test]
    #[should_panic(expected: "Collateral is not the same")]
    fn test_fuzz_should_fail_when_collateral_amount_mismatch(mut amount: u256) {
        let setup = setup();
        let simple_loan = setup.simple_loan;
        if amount == simple_loan.collateral.amount {
            amount += 1;
        };

        let mut terms = setup.refinanced_loan_terms;
        terms.collateral.amount = amount;
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );

        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_borrower_mismatch(_borrower: u128) {
        let setup = setup();
        let simple_loan = setup.simple_loan;
        let mut _borrower: felt252 = _borrower.into();
        let mut borrower: ContractAddress = _borrower.try_into().unwrap();
        if borrower == simple_loan.borrower {
            borrower = (_borrower + 1).try_into().unwrap();
        };

        let mut terms = setup.refinanced_loan_terms;
        terms.borrower = borrower;
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );

        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );
    }

    #[test]
    fn test_should_emit_loan_paid_back() {
        let setup = setup();

        let mut spy = spy_events();
        setup
            .loan
            .create_loan(
                setup.proposal_spec,
                setup.lender_spec,
                setup.caller_spec,
                Option::Some(array!['lil extra'])
            );
        spy
            .assert_emitted(
                @array![
                    (
                        setup.loan.contract_address,
                        PwnSimpleLoan::Event::LoanPaidBack(
                            PwnSimpleLoan::LoanPaidBack { loan_id: REFINANCING_LOAN_ID }
                        )
                    )
                ]
            );
    }

    #[test]
    fn test_should_emit_loan_created() {
        let setup = setup();

        let mut spy = spy_events();
        let loan_id = setup
            .loan
            .create_loan(
                setup.proposal_spec,
                setup.lender_spec,
                setup.caller_spec,
                Option::Some(array!['lil extra'])
            );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.loan.contract_address,
                        PwnSimpleLoan::Event::LoanCreated(
                            PwnSimpleLoan::LoanCreated {
                                loan_id: loan_id,
                                proposal_hash: setup.proposal_hash,
                                proposal_contract: setup.proposal_contract,
                                refinancing_loan_id: REFINANCING_LOAN_ID,
                                terms: setup.refinanced_loan_terms,
                                lender_spec: setup.lender_spec,
                                extra: Option::Some(array!['lil extra']),
                            }
                        )
                    )
                ]
            );
    }

    #[test]
    #[ignore]
    fn test_should_delete_loan_when_loan_owner_is_original_lender() {
        let setup = setup();

        let loan_token = ERC721ABIDispatcher {
            contract_address: setup.loan_token.contract_address
        };
        let prev_owner = loan_token.owner_of(REFINANCING_LOAN_ID.into());
        assert_eq!(prev_owner, setup.lender.contract_address);
        setup
            .loan
            .create_loan(
                setup.proposal_spec,
                setup.lender_spec,
                setup.caller_spec,
                Option::Some(array!['lil extra'])
            );
        let curr_owner = loan_token.owner_of(REFINANCING_LOAN_ID.into());
        assert_eq!(curr_owner, starknet::contract_address_const::<0>());
    }

    #[test]
    fn test_should_emit_loan_claimed_when_loan_owner_is_original_lender() {
        let setup = setup();

        let mut spy = spy_events();
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );

        spy
            .assert_emitted(
                @array![
                    (
                        setup.loan.contract_address,
                        PwnSimpleLoan::Event::LoanClaimed(
                            PwnSimpleLoan::LoanClaimed {
                                loan_id: REFINANCING_LOAN_ID, defaulted: false
                            }
                        )
                    )
                ]
            );
    }

    #[test]
    fn test_should_update_loan_data_when_loan_owner_is_not_original_lender() {
        let setup = setup();
        let not_original_sender = starknet::contract_address_const::<'notOriginalSender'>();
        mock_call(setup.loan_token.contract_address, selector!("owner_of"), not_original_sender, 1);

        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );

        let mut simple_loan = setup.simple_loan;
        simple_loan.status = 3;
        simple_loan
            .fixed_interest_amount = setup
            .loan
            .get_loan_repayment_amount(REFINANCING_LOAN_ID)
            - simple_loan.principal_amount;
        simple_loan.accruing_interest_APR = 0;
        assert_loan_eq(setup.loan.contract_address, REFINANCING_LOAN_ID, simple_loan);
    }

    #[test]
    #[ignore] // when call fails reverts the whole tx
    fn test_should_update_loan_data_when_loan_owner_is_original_lender_when_direct_repayment_fails() {
        let setup = setup();
        let mut terms = setup.refinanced_loan_terms;
        terms.credit.amount = setup.simple_loan.principal_amount - 1;
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );

        erc20_mint(setup.t20.contract_address, setup.lender.contract_address, BoundedInt::max());

        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );

        let mut simple_loan = setup.simple_loan;
        simple_loan.status = 3;
        simple_loan
            .fixed_interest_amount = setup
            .loan
            .get_loan_repayment_amount(REFINANCING_LOAN_ID)
            - simple_loan.principal_amount;
        simple_loan.accruing_interest_APR = 0;
        assert_loan_eq(setup.loan.contract_address, REFINANCING_LOAN_ID, simple_loan);
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_pool_adapter_not_registered_when_pool_source_of_funds() {
        let setup = setup();
        let lender_spec = types::LenderSpec { source_of_funds: setup.source_of_funds };
        let mut terms = setup.simple_loan_terms;
        terms.lender_spec_hash = setup.loan.get_lender_spec_hash(lender_spec);
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        mock_call(
            setup.config.contract_address,
            selector!("get_pool_adapter"),
            starknet::contract_address_const::<0>(),
            1
        );
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
            );
    }

    #[test]
    fn test_should_withdraw_full_credit_amount_when_should_transfer_common_when_pool_source_of_funds() {
        let setup = setup();
        let lender_spec = types::LenderSpec { source_of_funds: setup.source_of_funds };
        let mut terms = setup.refinanced_loan_terms;
        terms.lender_spec_hash = setup.loan.get_lender_spec_hash(lender_spec);
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        let prev_bal = setup.t20.balance_of(setup.source_of_funds);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let curr_bal = setup.t20.balance_of(setup.source_of_funds);
        assert_eq!(prev_bal - terms.credit.amount, curr_bal, "Source of funds balance mismatch!");
    }

    #[test]
    fn test_should_withdraw_credit_without_common_when_should_not_transfer_common_when_pool_source_of_funds() {
        let setup = setup();
        let lender_spec = types::LenderSpec { source_of_funds: setup.source_of_funds };
        let mut terms = setup.refinanced_loan_terms;
        terms.lender = setup.lender2.contract_address;
        terms.lender_spec_hash = setup.loan.get_lender_spec_hash(lender_spec);
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        mock_call(
            setup.loan_token.contract_address,
            selector!("owner_of"),
            setup.lender2.contract_address,
            1
        );
        let repayment = setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        let common = if terms.credit.amount < repayment {
            terms.credit.amount
        } else {
            repayment
        };
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(setup.source_of_funds);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let curr_bal = credit_asset.balance_of(setup.source_of_funds);
        assert_eq!(
            prev_bal - terms.credit.amount + common, curr_bal, "Source of funds balance mismatch!"
        );
    }

    #[test]
    fn test_should_not_withdraw_credit_when_should_not_transfer_common_when_no_surplus_when_no_fee_when_pool_source_of_funds() {
        let setup = setup();
        let lender_spec = types::LenderSpec { source_of_funds: setup.source_of_funds };
        let mut terms = setup.refinanced_loan_terms;
        terms.lender = setup.lender2.contract_address;
        terms.lender_spec_hash = setup.loan.get_lender_spec_hash(lender_spec);
        terms.credit.amount = setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        mock_call(
            setup.loan_token.contract_address,
            selector!("owner_of"),
            setup.lender2.contract_address,
            1
        );
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(setup.source_of_funds);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let curr_bal = credit_asset.balance_of(setup.source_of_funds);
        assert_eq!(prev_bal, curr_bal, "Source of funds balance mismatch!");
    }

    #[test]
    fn test_fuzz_should_transfer_fee_to_collector(mut fee: u16) {
        let setup = setup();
        fee %= 9999;
        if fee == 0 {
            fee += 1;
        }

        let terms = setup.refinanced_loan_terms;
        let (fee_amount, _) = fee_calculator::calculate_fee_amount(fee, terms.credit.amount);
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(setup.fee_collector);
        mock_call(setup.config.contract_address, selector!("get_fee"), fee, 1);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let curr_bal = credit_asset.balance_of(setup.fee_collector);
        assert_eq!(prev_bal + fee_amount, curr_bal, "Fee collector balance mismatch!");
    }

    #[test]
    fn test_should_transfer_common_to_vault_when_lender_not_loan_owner() {
        let setup = setup();
        let lender_spec = types::LenderSpec { source_of_funds: setup.lender2.contract_address };
        let mut terms = setup.refinanced_loan_terms;
        terms.lender = setup.lender2.contract_address;
        terms.lender_spec_hash = setup.loan.get_lender_spec_hash(lender_spec);
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        mock_call(
            setup.loan_token.contract_address,
            selector!("owner_of"),
            starknet::contract_address_const::<'loanOwner'>(),
            1
        );
        let repayment = setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        let common = if terms.credit.amount < repayment {
            terms.credit.amount
        } else {
            repayment
        };
        let prev_bal = setup.t20.balance_of(setup.loan.contract_address);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let curr_bal = setup.t20.balance_of(setup.loan.contract_address);
        assert_eq!(prev_bal + common, curr_bal, "SimpleLoan balance mismatch!");
    }

    #[test] // this has no fuzzing parameter in original test?
    #[ignore]
    fn test_fuzz_should_transfer_common_to_vault_when_lender_original_lender_when_different_source_of_funds() {
        let setup = setup();
        let lender_spec = types::LenderSpec { source_of_funds: setup.lender2.contract_address };
        let mut terms = setup.refinanced_loan_terms;
        terms.lender = setup.lender2.contract_address;
        terms.lender_spec_hash = setup.loan.get_lender_spec_hash(lender_spec);
        let mut simple_loan = setup.simple_loan;
        simple_loan.original_lender = setup.lender2.contract_address;
        simple_loan.original_source_of_funds = setup.source_of_funds;
        store_loan(setup.loan.contract_address, REFINANCING_LOAN_ID, simple_loan);
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        mock_call(
            setup.loan_token.contract_address,
            selector!("owner_of"),
            setup.lender2.contract_address,
            1
        );
        let repayment = setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        let common = if terms.credit.amount < repayment {
            terms.credit.amount
        } else {
            repayment
        };
        let prev_bal = setup.t20.balance_of(setup.lender2.contract_address);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let curr_bal = setup.t20.balance_of(setup.lender2.contract_address);
        assert_eq!(prev_bal - common, curr_bal, "SimpleLoan balance mismatch!");
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_not_transfer_common_to_vault_when_lender_loan_owner_when_lender_original_lender_when_same_source_of_funds(
        source_of_funds_flag: bool
    ) {
        assert(true, '');
    }

    #[test]
    fn test_should_transfer_surplus_to_borrower() {
        let setup = setup();
        let new_lender = setup.lender2.contract_address;
        let lender_spec = types::LenderSpec { source_of_funds: new_lender };
        let mut terms = setup.refinanced_loan_terms;
        terms.lender = new_lender;
        terms.lender_spec_hash = setup.loan.get_lender_spec_hash(lender_spec);
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        let surplus = terms.credit.amount
            - setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(setup.borrower.contract_address);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let curr_bal = credit_asset.balance_of(setup.borrower.contract_address);
        assert_eq!(prev_bal + surplus, curr_bal, "BORROWER balance mismatch!");
    }

    #[test]
    fn test_should_not_transfer_surplus_to_borrower_when_no_surplus() {
        let setup = setup();
        let new_lender = setup.lender2.contract_address;
        let lender_spec = types::LenderSpec { source_of_funds: new_lender };
        let mut terms = setup.refinanced_loan_terms;
        terms.lender = new_lender;
        terms.lender_spec_hash = setup.loan.get_lender_spec_hash(lender_spec);
        terms.credit.amount = setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(setup.borrower.contract_address);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let curr_bal = credit_asset.balance_of(setup.borrower.contract_address);
        assert_eq!(prev_bal, curr_bal, "BORROWER balance mismatch!");
    }

    #[test]
    fn test_should_transfer_shortage_from_borrower_to_vault() {
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        let terms = setup.refinanced_loan_terms;
        simple_loan.principal_amount = terms.credit.amount + 1;
        store_loan(setup.loan.contract_address, REFINANCING_LOAN_ID, simple_loan);

        let shortage = setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID)
            - terms.credit.amount;
        let credit_asset = ERC20ABIDispatcher { contract_address: simple_loan.credit_address };
        let prev_bal = credit_asset.balance_of(setup.borrower.contract_address);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let curr_bal = credit_asset.balance_of(setup.borrower.contract_address);
        assert_eq!(prev_bal - shortage, curr_bal, "BORROWER balance mismatch!");
    }

    #[test]
    fn test_should_not_transfer_shortage_from_borrower_to_vault_when_no_shortage() {
        let setup = setup();
        let mut terms = setup.refinanced_loan_terms;
        terms.credit.amount = setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        let credit_asset = ERC20ABIDispatcher { contract_address: terms.credit.asset_address };
        let prev_bal = credit_asset.balance_of(setup.borrower.contract_address);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let curr_bal = credit_asset.balance_of(setup.borrower.contract_address);
        assert_eq!(prev_bal, curr_bal, "BORROWER balance mismatch!");
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_try_claim_repaid_loan_full_amount_when_should_transfer_common(
        mut _loan_owner: u128
    ) {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_try_claim_repaid_loan_shortage_amount_when_should_not_transfer_common() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_not_fail_when_try_claim_repaid_loan_fails() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_repay_original_loan() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_collect_protocol_fee(
        mut days: u64,
        mut principal: u256,
        mut fixed_interest: u256,
        mut interest_APR: u32,
        mut refinance_amount: u256,
        mut fee: u16
    ) {
        let setup = setup();
        days %= setup.loan_duration_days - 1;
        principal %= E40;
        if principal == 0 {
            principal += 1;
        }
        fixed_interest %= E40;
        interest_APR %= 16_000_000;
        if interest_APR == 0 {
            interest_APR += 1;
        }

        let mut simple_loan = setup.simple_loan;
        simple_loan.principal_amount = principal;
        simple_loan.fixed_interest_amount = fixed_interest;
        simple_loan.accruing_interest_APR = interest_APR;
        store_loan(setup.loan.contract_address, REFINANCING_LOAN_ID, simple_loan);

        cheat_block_timestamp_global(simple_loan.start_timestamp + days * DAY);
        let loan_repayment_amount = setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        fee %= 9999;
        if fee == 0 {
            fee += 1;
        }
        refinance_amount %= BoundedInt::max() - loan_repayment_amount - setup.t20.total_supply();
        if refinance_amount == 0 {
            refinance_amount += 1;
        }
        let new_lender = setup.lender2.contract_address;
        let (fee_amount, _) = fee_calculator::calculate_fee_amount(fee, refinance_amount);
        let lender_spec = types::LenderSpec { source_of_funds: new_lender };
        let mut terms = setup.refinanced_loan_terms;
        terms.credit.amount = refinance_amount;
        terms.lender = new_lender;
        terms.lender_spec_hash = setup.loan.get_lender_spec_hash(lender_spec);
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        mock_call(
            setup.loan_token.contract_address,
            selector!("owner_of"),
            setup.lender.contract_address,
            1
        );
        mock_call(setup.config.contract_address, selector!("get_fee"), fee, 2);

        erc20_mint(setup.t20.contract_address, setup.lender2.contract_address, refinance_amount);

        if loan_repayment_amount > refinance_amount - fee_amount {
            erc20_mint(
                setup.t20.contract_address,
                setup.borrower.contract_address,
                loan_repayment_amount - (refinance_amount - fee_amount)
            );
        }
        println!("here");
        let original_balance = setup.t20.balance_of(setup.fee_collector);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
            );
        println!("out");
        let current_balance = setup.t20.balance_of(setup.fee_collector);
        assert_eq!(original_balance + fee_amount, current_balance, "Protocol fees not collected");
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_transfer_surplus_to_borrower() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_transfer_shortage_from_borrower() {
        assert(true, '');
    }
}

mod repay_loan {
    #[test]
    #[ignore]
    fn test_should_fail_when_loan_does_not_exist() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_loan_is_not_running() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_loan_is_defaulted() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_invalid_permit_owner_when_permit_provided() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_invalid_permit_asset_when_permit_provided() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_call_permit_when_permit_provided() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_update_loan_data_when_loan_owner_is_not_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_delete_loan_data_when_loan_owner_is_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_burn_loan_token_when_loan_owner_is_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_transfer_repaid_amount_to_vault() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_transfer_collateral_to_borrower() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_emit_loan_paid_back() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_call_try_claim_repaid_loan() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_not_fail_when_try_claim_repaid_loan_fails() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_emit_loan_claimed_when_loan_owner_is_original_lender() {
        assert(true, '');
    }
}

mod loan_repayment_amount {
    use core::option::OptionTrait;
    use core::traits::TryInto;
    use pwn::loan::lib::math;
    use pwn::loan::terms::simple::loan::pwn_simple_loan::PwnSimpleLoan;
    use super::super::simple_loan_proposal_test::E40;
    use super::{
        setup, store_loan, cheat_block_timestamp_global, IPwnSimpleLoanDispatcher,
        IPwnSimpleLoanDispatcherTrait, DAY, E18
    };

    #[test]
    fn test_should_return_zero_when_loan_does_not_exist() {
        let setup = setup();
        assert_eq!(setup.loan.get_loan_repayment_amount(setup.loan_id), 0);
    }

    #[test]
    fn test_fuzz_should_return_fixed_interest_when_zero_accrued_interest(
        mut days: u64, mut principal: u256, mut fixed_interest: u256
    ) {
        let setup = setup();
        days %= 2 * setup.loan_duration_days;
        principal %= E40;
        if principal == 0 {
            principal = 1;
        }
        fixed_interest %= E40;
        let mut simple_loan = setup.simple_loan;
        simple_loan.default_timestamp = simple_loan.start_timestamp + 101 * DAY;
        simple_loan.principal_amount = principal;
        simple_loan.fixed_interest_amount = fixed_interest;
        simple_loan.accruing_interest_APR = 0;
        store_loan(setup.loan.contract_address, setup.loan_id, simple_loan);
        cheat_block_timestamp_global(simple_loan.start_timestamp + days + DAY);
        assert_eq!(
            setup.loan.get_loan_repayment_amount(setup.loan_id),
            principal + fixed_interest,
            "Loan repayment mismatch!"
        );
    }

    #[test]
    fn test_fuzz_should_return_accrued_interest_when_non_zero_accrued_interest(
        mut minutes: u64, mut principal: u256, mut fixed_interest: u256, mut interest_APR: u256
    ) {
        let setup = setup();
        minutes %= 2 * setup.loan_duration_days * 24 * 60;
        principal %= E40;
        if principal == 0 {
            principal = 1;
        }
        fixed_interest %= E40;
        interest_APR %= 16_000_000;
        if interest_APR == 0 {
            principal = 1;
        }
        let mut simple_loan = setup.simple_loan;
        simple_loan.default_timestamp = simple_loan.start_timestamp + 101 * DAY;
        simple_loan.principal_amount = principal;
        simple_loan.fixed_interest_amount = fixed_interest;
        simple_loan.accruing_interest_APR = interest_APR.try_into().unwrap();
        store_loan(setup.loan.contract_address, setup.loan_id, simple_loan);
        cheat_block_timestamp_global(simple_loan.start_timestamp + minutes * 60 + 1);

        let expected_interest = fixed_interest
            + math::mul_div(
                principal,
                (interest_APR * minutes.into()),
                PwnSimpleLoan::ACCRUING_INTEREST_APR_DENOMINATOR
            );
        let expected_loan_repayment = principal + expected_interest;
        assert_eq!(
            setup.loan.get_loan_repayment_amount(setup.loan_id),
            expected_loan_repayment,
            "Loan repayment mismatch!"
        );
    }

    #[test]
    fn test_should_return_accrued_interest() {
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.default_timestamp = simple_loan.start_timestamp + 101 * DAY;
        simple_loan.principal_amount = 100 * E18;
        simple_loan.fixed_interest_amount = 10 * E18;
        simple_loan.accruing_interest_APR = 36500;
        store_loan(setup.loan.contract_address, setup.loan_id, simple_loan);
        cheat_block_timestamp_global(simple_loan.start_timestamp);
        assert_eq!(
            setup.loan.get_loan_repayment_amount(setup.loan_id),
            simple_loan.principal_amount + simple_loan.fixed_interest_amount,
            "Loan repayment mismatch!"
        );

        cheat_block_timestamp_global(simple_loan.start_timestamp + DAY);
        assert_eq!(
            setup.loan.get_loan_repayment_amount(setup.loan_id),
            simple_loan.principal_amount + simple_loan.fixed_interest_amount + E18,
            "Loan repayment mismatch!"
        );

        simple_loan.accruing_interest_APR = 10_000;
        store_loan(setup.loan.contract_address, setup.loan_id, simple_loan);
        cheat_block_timestamp_global(simple_loan.start_timestamp + 365 * DAY);
        assert_eq!(
            setup.loan.get_loan_repayment_amount(setup.loan_id),
            2 * simple_loan.principal_amount + simple_loan.fixed_interest_amount,
            "Loan repayment mismatch!"
        );
    }
}

mod claim_loan {
    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_caller_is_not_loan_token_holder() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_loan_does_not_exist() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_loan_is_not_repaid_nor_expired() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_pass_when_loan_is_repaid() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_pass_when_loan_is_defaulted() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_delete_loan_data() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_burn_loan_token() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_transfer_repaid_amount_to_lender_when_loan_is_repaid() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_transfer_collateral_to_lender_when_loan_is_defaulted() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_emit_loan_claimed_when_repaid() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_emit_loan_claimed_when_defaulted() {
        assert(true, '');
    }
}

mod try_claim_repaid_loan {
    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_caller_is_not_vault() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_not_proceed_when_loan_not_in_repaid_state() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_not_proceed_when_original_lender_not_equal_to_loan_owner() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_burn_loan_token() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_delete_loan_data() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_not_call_transfer_when_credit_amount_is_zero() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_transfer_to_original_lender_when_source_of_funds_equal_to_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_pool_adapter_not_registered_when_source_of_funds_not_equal_to_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_transfer_amount_to_pool_adapter_when_source_of_funds_not_equal_to_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_call_supply_on_pool_adapter_when_source_of_funds_not_equal_to_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_transfer_fails_when_source_of_funds_equal_to_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_transfer_fails_when_source_of_funds_not_equal_to_original_lender() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_emit_loan_claimed() {
        assert(true, '');
    }
}

mod make_extension_proposal {
    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_caller_not_proposer() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_store_made_flag() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_emit_extension_proposal_made() {
        assert(true, '');
    }
}

mod extend_loan {
    #[test]
    #[ignore]
    fn test_should_fail_when_loan_does_not_exist() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_loan_is_repaid() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_invalid_signature_when_eoa() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_offer_expirated() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_offer_nonce_not_usable() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_caller_is_not_borrower_nor_loan_owner() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_caller_is_borrower_and_proposer_is_not_loan_owner() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_caller_is_loan_owner_and_proposer_is_not_borrower() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_extension_duration_less_than_min() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_extension_duration_more_than_max() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_revoke_extension_nonce() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_update_loan_data() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_emit_loan_extended() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_not_transfer_credit_when_amount_zero() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_not_transfer_credit_when_address_zero() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_fail_when_invalid_compensation_asset() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_invalid_permit_data_permit_owner() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_fail_when_invalid_permit_data_permit_asset() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_call_permit_when_provided() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_transfer_compensation_when_defined() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_pass_when_borrower_signature_when_lender_accepts() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_pass_when_lender_signature_when_borrower_accepts() {
        assert(true, '');
    }
}

mod get_extension_hash {
    #[test]
    #[ignore]
    fn test_should_return_extension_hash() {
        assert(true, '');
    }
}

mod get_loan {
    #[test]
    #[ignore]
    fn test_fuzz_should_return_static_loan_data_first_part() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_return_static_loan_data_second_part() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_return_correct_status() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_return_loan_token_owner() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_return_repayment_amount() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_return_empty_loan_data_for_non_existing_loan() {
        assert(true, '');
    }
}

mod loan_metadata_uri {
    #[test]
    #[ignore]
    fn test_should_call_config() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_return_correct_value() {
        assert(true, '');
    }
}

mod get_state_fingerprint {
    #[test]
    #[ignore]
    fn test_should_return_zero_if_loan_does_not_exist() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_should_update_state_fingerprint_when_loan_defaulted() {
        assert(true, '');
    }

    #[test]
    #[ignore]
    fn test_fuzz_should_return_correct_state_fingerprint() {
        assert(true, '');
    }
}
