use core::integer::BoundedInt;
use core::poseidon::poseidon_hash_span;
use core::result::ResultTrait;
use core::serde::Serde;
use core::traits::Into;
use core::traits::TryInto;
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
    pwn_simple_loan::PwnSimpleLoan, types
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
// upper bound is exclusive
pub fn bound<T, +PartialOrd<T>, +RemEq<T>, +Drop<T>, +Copy<T>>(
    mut value: T, lower: T, upper: T
) -> T {
    value %= upper;
    if value < lower {
        value = lower;
    }
    value
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
    let owner = starknet::get_contract_address();

    let contract = declare("PwnHub").unwrap();
    let (hub_address, _) = contract.deploy(@array![owner.into()]).unwrap();
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
    let (registry_address, _) = contract.deploy(@array![owner.into()]).unwrap();
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

    mock_call(loan_token_address, selector!("owner_of"), lender_address, 1);

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

pub(crate) fn loan_token_mint(
    loan_token: ContractAddress, receiver: ContractAddress, loan_contract: ContractAddress, id: u256
) {
    let mut id_serialized: Array<felt252> = array![];
    id.serialize(ref id_serialized);

    let mut receiver_serialized: Array<felt252> = array![];
    receiver.serialize(ref receiver_serialized);
    store(
        loan_token,
        map_entry_address(selector!("ERC721_owners"), id_serialized.span(),),
        receiver_serialized.span()
    );
    let new_balance: u256 = 1;
    let mut balance_serialized: Array<felt252> = array![];
    new_balance.serialize(ref balance_serialized);
    store(
        loan_token,
        map_entry_address(selector!("ERC721_balances"), receiver_serialized.span(),),
        balance_serialized.span()
    );
    store(
        loan_token,
        map_entry_address(
            selector!("loan_contract"),
            array![TryInto::<u256, felt252>::try_into(id).unwrap()].span()
        ),
        array![loan_contract.into()].span()
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

pub(crate) fn erc721_read_owner(erc721: ContractAddress, id: u256) -> ContractAddress {
    let mut serialized_loan_id: Array<felt252> = array![];
    id.serialize(ref serialized_loan_id);
    TryInto::<
        felt252, ContractAddress
    >::try_into(
        *load(erc721, map_entry_address(selector!("ERC721_owners"), serialized_loan_id.span()), 1)
            .at(0)
    )
        .unwrap()
}

pub(crate) fn _get_extension_hash(
    address: ContractAddress, extension: types::ExtensionProposal
) -> felt252 {
    let hash_elements: Array<felt252> = array![
        PwnSimpleLoan::BASE_DOMAIN_SEPARATOR, address.into()
    ];
    let domain_separator_hash = poseidon_hash_span(hash_elements.span());
    let hash_elements: Array<felt252> = array![
        1901,
        domain_separator_hash,
        PwnSimpleLoan::EXTENSION_PROPOSAL_TYPEHASH,
        extension.loan_id,
        extension.compensation_address.into(),
        extension.compensation_amount.try_into().expect('get_extension_hash'),
        extension.duration.into(),
        extension.expiration.into(),
        extension.proposer.into(),
        extension.nonce_space,
        extension.nonce
    ];
    poseidon_hash_span(hash_elements.span())
}

pub(crate) fn store_loan(address: ContractAddress, loan_id: felt252, loan: types::Loan) {
    let mut serialized_loan: Array<felt252> = array![];
    loan.serialize(ref serialized_loan);
    store(
        address,
        map_entry_address(selector!("loans"), array![loan_id].span()),
        serialized_loan.span()
    );
}

pub(crate) fn assert_loan_eq(address: ContractAddress, loan_id: felt252, loan: types::Loan) {
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
    use core::integer::BoundedInt;
    use core::option::OptionTrait;
    use core::serde::Serde;
    use core::traits::Into;
    use core::traits::TryInto;
    use openzeppelin::token::{
        erc20::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
        erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait}
    };

    use pwn::loan::lib::fee_calculator;
    use snforge_std::{
        cheat_caller_address, CheatSpan, mock_call, load, store, map_entry_address, spy_events,
        EventSpy, EventSpyTrait, EventSpyAssertionsTrait,
    };
    use starknet::ContractAddress;
    use super::super::simple_loan_proposal_test::E40;
    use super::{
        PwnSimpleLoan, IPwnSimpleLoanDispatcher, IPwnSimpleLoanDispatcherTrait,
        IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait, IPwnHubDispatcherTrait, MultiToken,
        types::{CallerSpec, LenderSpec, ProposalSpec}, pwn_hub_tags, erc20_mint, assert_loan_eq,
        setup, Setup, bound
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
    #[ignore] // expectCall eq needed
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
        duration = bound(duration, 0, PwnSimpleLoan::MIN_LOAN_DURATION);

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

        accruing_interest_APR =
            bound(
                accruing_interest_APR,
                PwnSimpleLoan::MAX_ACCRUING_INTEREST_APR + 1,
                BoundedInt::max()
            );

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
    // fn test_should_call_permit_when_provided() {
    //     assert(true, '');
    // }

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
        let collateral = setup.t20;
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
        loan_amount = bound(loan_amount, 1, E40);
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
        fee = bound(fee, 0, 9999);
        loan_amount = bound(loan_amount, 1, E40);
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
    use core::integer::BoundedInt;
    use core::traits::Into;
    use core::traits::TryInto;
    use openzeppelin::token::{
        erc20::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
        erc721::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait},
        erc1155::interface::{ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait},
    };
    use pwn::loan::lib::fee_calculator;
    use pwn::loan::vault::pwn_vault::PwnVaultComponent;

    use snforge_std::{
        declare, store, load, map_entry_address, cheat_caller_address, cheat_block_timestamp_global,
        mock_call, spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait, stop_mock_call,
        CheatSpan,
        signature::{
            KeyPairTrait, SignerTrait, KeyPair,
            stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
        },
    };
    use starknet::ContractAddress;

    use super::super::simple_loan_proposal_test::E40;
    use super::{
        types, MultiToken, erc20_mint, erc721_mint, poseidon_hash_span, store_loan, PwnSimpleLoan,
        IPwnSimpleLoanDispatcherTrait, IPwnLoanDispatcherTrait, U8IntoCategory, Setup,
        assert_loan_eq, E20, DAY, loan_token_mint, bound
    };

    fn setup() -> Setup {
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

        mock_call(
            setup.loan_token.contract_address,
            selector!("owner_of"),
            setup.lender.contract_address,
            BoundedInt::max()
        );

        erc20_mint(setup.t20.contract_address, new_lender, E20);
        erc20_mint(setup.t20.contract_address, setup.lender.contract_address, E20);
        erc20_mint(setup.t20.contract_address, setup.loan.contract_address, E20);
        store_loan(setup.t20.contract_address, REFINANCING_LOAN_ID, setup.simple_loan);

        loan_token_mint(
            setup.loan_token.contract_address,
            setup.lender.contract_address,
            setup.loan.contract_address,
            REFINANCING_LOAN_ID.into()
        );
        store_loan(setup.loan.contract_address, REFINANCING_LOAN_ID, setup.simple_loan);

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
        category = bound(category, 0, 3);
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
    fn test_should_delete_loan_when_loan_owner_is_original_lender() {
        let setup = setup();
        assert_eq!(
            setup.simple_loan.original_lender,
            ERC721ABIDispatcher { contract_address: setup.loan_token.contract_address }
                .owner_of(REFINANCING_LOAN_ID.into()),
            "loan_owner not equals to original lender"
        );
        assert_loan_eq(setup.loan.contract_address, REFINANCING_LOAN_ID, setup.simple_loan);
        setup
            .loan
            .create_loan(
                setup.proposal_spec,
                setup.lender_spec,
                setup.caller_spec,
                Option::Some(array!['lil extra'])
            );
        assert_loan_eq(setup.loan.contract_address, REFINANCING_LOAN_ID, Default::default());
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

    //#[test]
    //#[ignore] // when call fails reverts the whole tx
    //fn test_should_update_loan_data_when_loan_owner_is_original_lender_when_direct_repayment_fails() {
    //    let setup = setup();
    //    let mut terms = setup.refinanced_loan_terms;
    //    terms.credit.amount = setup.simple_loan.principal_amount - 1;
    //    mock_call(
    //        setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
    //    );
    //
    //    erc20_mint(setup.t20.contract_address, setup.lender.contract_address, BoundedInt::max());
    //
    //    setup
    //        .loan
    //        .create_loan(
    //            setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
    //        );
    //
    //    let mut simple_loan = setup.simple_loan;
    //    simple_loan.status = 3;
    //    simple_loan
    //        .fixed_interest_amount = setup
    //        .loan
    //        .get_loan_repayment_amount(REFINANCING_LOAN_ID)
    //        - simple_loan.principal_amount;
    //    simple_loan.accruing_interest_APR = 0;
    //    assert_loan_eq(setup.loan.contract_address, REFINANCING_LOAN_ID, simple_loan);
    //}

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
        fee = bound(fee, 1, 9999);

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

    #[test]
    fn test_fuzz_should_transfer_common_to_vault_when_lender_original_lender_when_different_source_of_funds(
        _source_of_funds: u128
    ) {
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        let mut _source_of_funds: felt252 = _source_of_funds.into();
        if _source_of_funds == 0 {
            _source_of_funds = 1;
        }

        let mut source_of_funds: ContractAddress = _source_of_funds.try_into().unwrap();
        if source_of_funds == setup.simple_loan.original_source_of_funds {
            source_of_funds = (_source_of_funds + 1).try_into().unwrap();
        }
        let lender_spec = types::LenderSpec { source_of_funds: setup.lender2.contract_address };
        let mut terms = setup.refinanced_loan_terms;
        terms.lender = setup.lender2.contract_address;
        terms.lender_spec_hash = setup.loan.get_lender_spec_hash(lender_spec);

        simple_loan.original_lender = setup.lender2.contract_address;
        simple_loan.original_source_of_funds = source_of_funds;
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
        let prev_bal = setup.t20.balance_of(source_of_funds);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let curr_bal = setup.t20.balance_of(source_of_funds);
        assert_eq!(prev_bal + common, curr_bal, "source_of_funds balance mismatch!");
    }

    //#[test]
    //#[ignore] // conditionally assert or remove
    //fn test_fuzz_should_not_transfer_common_to_vault_when_lender_loan_owner_when_lender_original_lender_when_same_source_of_funds(
    //    source_of_funds_flag: u8
    //) {
    //    let setup = setup();
    //    let mut simple_loan = setup.simple_loan;
    //    
    //    let source_of_funds = if source_of_funds_flag % 2 == 1{
    //        setup.lender2.contract_address
    //    } else {
    //        setup.source_of_funds
    //    };
    //
    //    let lender_spec = types::LenderSpec { source_of_funds: source_of_funds};
    //    let mut terms = setup.refinanced_loan_terms;
    //    terms.lender = setup.lender2.contract_address;
    //    terms.lender_spec_hash = setup.loan.get_lender_spec_hash(lender_spec);
    //    simple_loan.original_lender = setup.lender2.contract_address;
    //    simple_loan.original_source_of_funds = source_of_funds;
    //    store_loan(setup.loan.contract_address, REFINANCING_LOAN_ID, simple_loan);
    //    mock_call(
    //        setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
    //    );
    //    mock_call(
    //        setup.loan_token.contract_address,
    //        selector!("owner_of"),
    //        setup.lender2.contract_address,
    //        1
    //    );
    //    let repayment = setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
    //    let common = if terms.credit.amount < repayment {
    //        terms.credit.amount
    //    } else {
    //        repayment
    //    };
    //    let original_balance_lender = setup.t20.balance_of(setup.lender2.contract_address);
    //    let original_balance_source_of_funds = setup.t20.balance_of(source_of_funds);
    //    setup
    //        .loan
    //        .create_loan(
    //            setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
    //        );
    //    let current_balance_source_of_funds = setup.t20.balance_of(source_of_funds);
    //    let current_balance_lender = setup.t20.balance_of(setup.lender2.contract_address);
    //    assert_eq!(original_balance_source_of_funds + common, current_balance_source_of_funds, "source_of_funds balance mismatch!");
    //    assert_ge!(original_balance_lender, current_balance_lender, "Transferred common from lender to vault");
    //}

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

    //#[test]
    //#[ignore]
    //fn test_fuzz_should_try_claim_repaid_loan_full_amount_when_should_transfer_common(
    //    _loan_owner: u128
    //) {
    //    let setup = setup();
    //    let mut _loan_owner: felt252 = _loan_owner.into();
    //    let mut loan_owner: ContractAddress = _loan_owner.try_into().unwrap();
    //    while loan_owner == starknet::contract_address_const::<0>()
    //        || loan_owner == setup
    //            .lender
    //            .contract_address {
    //                _loan_owner += 1;
    //                loan_owner = _loan_owner.try_into().unwrap();
    //            };
    //    let mut simple_loan = setup.simple_loan;
    //    simple_loan.original_lender = loan_owner;
    //    store_loan(setup.loan.contract_address, REFINANCING_LOAN_ID, simple_loan);
    //    mock_call(setup.loan_token.contract_address, selector!("owner_of"), loan_owner, 1);
    //    let original_balance = setup.t20.balance_of(loan_owner);
    //    setup
    //        .loan
    //        .create_loan(
    //            setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
    //        );
    //    let current_balance = setup.t20.balance_of(loan_owner);
    //    assert_eq!(original_balance, current_balance);
    //}

    #[test]
    fn test_fuzz_should_try_claim_repaid_loan_shortage_amount_when_should_not_transfer_common(
        mut shortage: u256
    ) {
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.principal_amount = setup.refinanced_loan_terms.credit.amount + 1;
        store_loan(setup.loan.contract_address, REFINANCING_LOAN_ID, simple_loan);
        let loan_repayment_amount = setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        shortage = bound(shortage, 0, loan_repayment_amount - 1);
        erc20_mint(setup.t20.contract_address, setup.borrower.contract_address, shortage);
        let mut terms = setup.refinanced_loan_terms;
        terms.credit.amount = loan_repayment_amount - shortage;
        mock_call(
            setup.proposal_contract, selector!("accept_proposal"), (setup.proposal_hash, terms), 1
        );
        let original_balance = setup.t20.balance_of(setup.borrower.contract_address);
        let original_balance_lender = setup.t20.balance_of(setup.lender.contract_address);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, setup.lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let current_balance = setup.t20.balance_of(setup.borrower.contract_address);
        let current_balance_lender = setup.t20.balance_of(setup.lender.contract_address);
        assert_eq!(
            original_balance_lender + shortage, current_balance_lender, "Lender balance mismatch!"
        );
        assert_eq!(original_balance - shortage, current_balance, "Shortage not transferred");
    }

    // #[test]
    // #[ignore]
    // fn test_should_not_fail_when_try_claim_repaid_loan_fails() {
    //     assert(true, '');
    // }

    #[test]
    fn test_fuzz_should_repay_original_loan(
        mut days: u64,
        mut principal: u256,
        mut fixed_interest: u256,
        mut interest_APR: u32,
        mut refinance_amount: u256
    ) {
        let setup = setup();
        days = bound(days, 0, setup.loan_duration_days - 1);
        principal = bound(principal, 1, E40);
        fixed_interest = bound(fixed_interest, 0, E40);
        interest_APR = bound(interest_APR, 1, 16_000_000);

        let mut simple_loan = setup.simple_loan;
        simple_loan.principal_amount = principal;
        simple_loan.fixed_interest_amount = fixed_interest;
        simple_loan.accruing_interest_APR = interest_APR;
        store_loan(setup.loan.contract_address, REFINANCING_LOAN_ID, simple_loan);

        cheat_block_timestamp_global(simple_loan.start_timestamp + days * DAY);
        let loan_repayment_amount = setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        refinance_amount %= BoundedInt::max() - loan_repayment_amount - setup.t20.total_supply();
        if refinance_amount == 0 {
            refinance_amount = 1;
        }
        let new_lender = setup.lender2.contract_address;
        let mut lender_spec = setup.lender_spec;
        lender_spec.source_of_funds = new_lender;
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
        erc20_mint(setup.t20.contract_address, new_lender, refinance_amount);

        if loan_repayment_amount > refinance_amount {
            erc20_mint(
                setup.t20.contract_address,
                setup.borrower.contract_address,
                loan_repayment_amount - refinance_amount
            );
        }

        let original_balance = setup.t20.balance_of(setup.lender.contract_address);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let current_balance = setup.t20.balance_of(setup.lender.contract_address);
        assert_eq!(current_balance, original_balance + loan_repayment_amount);
    }

    #[test]
    fn test_fuzz_should_collect_protocol_fee(
        mut days: u64,
        mut principal: u256,
        mut fixed_interest: u256,
        mut interest_APR: u32,
        mut refinance_amount: u256,
        mut fee: u16
    ) {
        let setup = setup();
        days = bound(days, 0, setup.loan_duration_days - 1);
        principal = bound(principal, 1, E40);
        fixed_interest = bound(fixed_interest, 0, E40);
        interest_APR = bound(interest_APR, 1, 16_000_000);

        let mut simple_loan = setup.simple_loan;
        simple_loan.principal_amount = principal;
        simple_loan.fixed_interest_amount = fixed_interest;
        simple_loan.accruing_interest_APR = interest_APR;
        store_loan(setup.loan.contract_address, REFINANCING_LOAN_ID, simple_loan);

        cheat_block_timestamp_global(simple_loan.start_timestamp + days * DAY);
        let loan_repayment_amount = setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        fee = bound(fee, 1, 9999);
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

        let original_balance = setup.t20.balance_of(setup.fee_collector);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let current_balance = setup.t20.balance_of(setup.fee_collector);
        assert_eq!(original_balance + fee_amount, current_balance, "Protocol fees not collected");
    }

    #[test]
    fn test_fuzz_should_transfer_surplus_to_borrower(mut refinance_amount: u256) {
        let setup = setup();
        let loan_repayment_amount = setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        refinance_amount =
            bound(
                refinance_amount,
                loan_repayment_amount + 1,
                BoundedInt::max() - loan_repayment_amount - setup.t20.total_supply()
            );

        let surplus = refinance_amount - loan_repayment_amount;
        let new_lender = setup.lender2.contract_address;
        let lender_spec = types::LenderSpec { source_of_funds: new_lender };
        let mut terms = setup.refinanced_loan_terms;
        terms.credit.amount = refinance_amount;
        terms.lender = new_lender;
        terms.lender_spec_hash = setup.loan.get_lender_spec_hash(lender_spec);
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
        erc20_mint(setup.t20.contract_address, new_lender, refinance_amount);

        let original_balance = setup.t20.balance_of(setup.borrower.contract_address);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let current_balance = setup.t20.balance_of(setup.borrower.contract_address);
        assert_eq!(
            original_balance + surplus, current_balance, "Surplus not transfered to borrower"
        );
    }

    #[test]
    fn test_fuzz_should_transfer_shortage_from_borrower(mut refinance_amount: u256) {
        let setup = setup();
        let loan_repayment_amount = setup.loan.get_loan_repayment_amount(REFINANCING_LOAN_ID);
        refinance_amount = bound(refinance_amount, 1, loan_repayment_amount - 1);
        let contribution = loan_repayment_amount - refinance_amount;
        let new_lender = setup.lender2.contract_address;
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
        erc20_mint(setup.t20.contract_address, new_lender, refinance_amount);

        let original_balance = setup.t20.balance_of(setup.borrower.contract_address);
        setup
            .loan
            .create_loan(
                setup.proposal_spec, lender_spec, setup.caller_spec, Option::Some(array![])
            );
        let current_balance = setup.t20.balance_of(setup.borrower.contract_address);
        assert_eq!(
            original_balance - contribution, current_balance, "Shortage not taken from borrower"
        );
    }
}

mod repay_loan {
    use openzeppelin::token::erc20::interface::ERC20ABIDispatcherTrait;
    use openzeppelin::token::erc721::interface::ERC721ABIDispatcherTrait;
    use pwn::loan::terms::simple::loan::pwn_simple_loan::PwnSimpleLoan;
    use snforge_std::{
        cheat_caller_address, CheatSpan, cheat_block_timestamp_global, mock_call, store,
        map_entry_address, spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait
    };
    use super::super::simple_loan_proposal_test::E40;
    use super::{
        Setup, store_loan, IPwnSimpleLoanDispatcherTrait, DAY, erc20_mint, erc721_mint,
        assert_loan_eq, erc721_read_owner, loan_token_mint, bound
    };

    fn setup() -> Setup {
        let setup = super::setup();
        store_loan(setup.loan.contract_address, setup.loan_id, setup.simple_loan);
        cheat_caller_address(
            setup.t721.contract_address, setup.borrower.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.t721.transfer_from(setup.borrower.contract_address, setup.loan.contract_address, 2);
        loan_token_mint(
            setup.loan_token.contract_address,
            setup.lender.contract_address,
            setup.loan.contract_address,
            setup.loan_id.into()
        );
        setup
    }

    #[test]
    #[should_panic(expected: "Loan does not exist")]
    fn test_should_fail_when_loan_does_not_exist() {
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.status = 0;
        store_loan(setup.loan.contract_address, setup.loan_id, simple_loan);
        setup.loan.repay_loan(setup.loan_id, 0);
    }

    #[test]
    #[should_panic(expected: "Loan is not running")]
    fn test_fuzz_should_fail_when_loan_is_not_running(mut status: u8) {
        let setup = setup();
        if status == 0 || status == 2 {
            status += 1;
        }
        let mut simple_loan = setup.simple_loan;
        simple_loan.status = status;
        store_loan(setup.loan.contract_address, setup.loan_id, simple_loan);
        setup.loan.repay_loan(setup.loan_id, 0);
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_loan_is_defaulted() {
        let setup = setup();
        cheat_block_timestamp_global(setup.simple_loan.default_timestamp);
        setup.loan.repay_loan(setup.loan_id, 0);
    }

    // #[test]
    // #[ignore]
    // fn test_fuzz_should_fail_when_invalid_permit_owner_when_permit_provided() {
    //     assert(true, '');
    // }
    // 
    // #[test]
    // #[ignore]
    // fn test_fuzz_should_fail_when_invalid_permit_asset_when_permit_provided() {
    //     assert(true, '');
    // }
    // 
    // #[test]
    // #[ignore]
    // fn test_should_call_permit_when_permit_provided() {
    //     assert(true, '');
    // }

    #[test]
    fn test_fuzz_should_update_loan_data_when_loan_owner_is_not_original_lender(
        mut days: u64, mut principal: u256, mut fixed_interest: u256, mut interest_APR: u32
    ) {
        let setup = setup();
        mock_call(
            setup.loan_token.contract_address,
            selector!("owner_of"),
            starknet::contract_address_const::<'notOriginalLender'>(),
            1
        );

        days = bound(days, 0, setup.loan_duration_days - 1);
        principal = bound(principal, 1, E40);
        fixed_interest = bound(fixed_interest, 0, E40);
        interest_APR = bound(interest_APR, 1, 16_000_000);

        let mut simple_loan = setup.simple_loan;
        simple_loan.principal_amount = principal;
        simple_loan.fixed_interest_amount = fixed_interest;
        simple_loan.accruing_interest_APR = interest_APR;
        store_loan(setup.loan.contract_address, setup.loan_id, simple_loan);

        cheat_block_timestamp_global(simple_loan.start_timestamp + days * DAY);
        let loan_repayment_amount = setup.loan.get_loan_repayment_amount(setup.loan_id);
        erc20_mint(
            setup.t20.contract_address, setup.borrower.contract_address, loan_repayment_amount
        );
        cheat_caller_address(
            setup.loan.contract_address, setup.borrower.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.repay_loan(setup.loan_id, 0);

        simple_loan.status = 3;
        simple_loan.fixed_interest_amount = loan_repayment_amount - principal;
        simple_loan.accruing_interest_APR = 0;
        assert_loan_eq(setup.loan.contract_address, setup.loan_id, simple_loan);
    }

    #[test]
    fn test_should_delete_loan_data_when_loan_owner_is_original_lender() {
        let setup = setup();
        assert_loan_eq(setup.loan.contract_address, setup.loan_id, setup.simple_loan);
        setup.loan.repay_loan(setup.loan_id, 0);
        assert_loan_eq(setup.loan.contract_address, setup.loan_id, Default::default());
    }

    #[test]
    fn test_should_burn_loan_token_when_loan_owner_is_original_lender() {
        let setup = setup();
        let original_owner = erc721_read_owner(
            setup.loan_token.contract_address, setup.loan_id.into()
        );
        assert_eq!(
            original_owner, setup.simple_loan.original_lender, "loan_owner is not original lender"
        );
        setup.loan.repay_loan(setup.loan_id, 0);
        let current_owner = erc721_read_owner(
            setup.loan_token.contract_address, setup.loan_id.into()
        );
        assert_eq!(
            current_owner, starknet::contract_address_const::<0>(), "Loan token didn't burnt"
        );
    }

    #[test]
    fn test_fuzz_should_transfer_repaid_amount_to_vault(
        mut days: u64, mut principal: u256, mut fixed_interest: u256, mut interest_APR: u32
    ) {
        let setup = setup();
        days = bound(days, 0, setup.loan_duration_days - 1);
        principal = bound(principal, 1, E40);
        fixed_interest = bound(fixed_interest, 0, E40);
        interest_APR = bound(interest_APR, 1, 16_000_000);

        let mut simple_loan = setup.simple_loan;
        simple_loan.principal_amount = principal;
        simple_loan.fixed_interest_amount = fixed_interest;
        simple_loan.accruing_interest_APR = interest_APR;
        store_loan(setup.loan.contract_address, setup.loan_id, simple_loan);

        cheat_block_timestamp_global(simple_loan.start_timestamp + days * DAY);
        let loan_repayment_amount = setup.loan.get_loan_repayment_amount(setup.loan_id);
        erc20_mint(
            setup.t20.contract_address, setup.borrower.contract_address, loan_repayment_amount
        );
        let original_balance = setup.t20.balance_of(setup.borrower.contract_address);
        cheat_caller_address(
            setup.loan.contract_address, setup.borrower.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.repay_loan(setup.loan_id, 0);
        let current_balance = setup.t20.balance_of(setup.borrower.contract_address);
        assert_eq!(
            original_balance - loan_repayment_amount,
            current_balance,
            "Repaid amount havent transferred from borrower to vault"
        )
    }

    #[test]
    fn test_should_transfer_collateral_to_borrower() {
        let setup = setup();
        let original_owner = erc721_read_owner(
            setup.simple_loan.collateral.asset_address, setup.simple_loan.collateral.id.into()
        );
        assert_eq!(
            original_owner, setup.loan.contract_address, "Vault is not the owner of collateral"
        );
        setup.loan.repay_loan(setup.loan_id, 0);
        let current_owner = erc721_read_owner(
            setup.simple_loan.collateral.asset_address, setup.simple_loan.collateral.id.into()
        );
        assert_eq!(
            current_owner,
            setup.borrower.contract_address,
            "Borrower is not the owner of colleteral"
        );
    }

    #[test]
    fn test_should_emit_loan_paid_back() {
        let setup = setup();
        let mut spy = spy_events();
        setup.loan.repay_loan(setup.loan_id, 0);
        spy
            .assert_emitted(
                @array![
                    (
                        setup.loan.contract_address,
                        PwnSimpleLoan::Event::LoanPaidBack(
                            PwnSimpleLoan::LoanPaidBack { loan_id: setup.loan_id }
                        )
                    )
                ]
            );
    }

    #[test]
    fn test_should_emit_loan_claimed_when_loan_owner_is_original_lender() {
        let setup = setup();
        let mut spy = spy_events();
        setup.loan.repay_loan(setup.loan_id, 0);
        spy
            .assert_emitted(
                @array![
                    (
                        setup.loan.contract_address,
                        PwnSimpleLoan::Event::LoanClaimed(
                            PwnSimpleLoan::LoanClaimed { loan_id: setup.loan_id, defaulted: false }
                        )
                    )
                ]
            );
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
        IPwnSimpleLoanDispatcherTrait, DAY, E18, bound
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
        days = bound(days, 0, 2 * setup.loan_duration_days);
        principal = bound(principal, 1, E40);
        fixed_interest = bound(fixed_interest, 0, E40);

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
        minutes = bound(minutes, 0, 2 * setup.loan_duration_days * 24 * 60);
        principal = bound(principal, 1, E40);
        fixed_interest = bound(fixed_interest, 0, E40);
        interest_APR = bound(interest_APR, 1, 16_000_000);

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
                PwnSimpleLoan::ACCRUING_INTEREST_APR_DENOMINATOR.into()
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
    use core::array::ArrayTrait;
    use core::option::OptionTrait;
    use core::serde::Serde;
    use pwn::loan::terms::simple::loan::pwn_simple_loan::PwnSimpleLoan;
    use snforge_std::{
        store, load, map_entry_address, cheat_block_timestamp_global, cheat_caller_address,
        CheatSpan, spy_events, EventSpy, EventSpyTrait, EventSpyAssertionsTrait
    };
    use starknet::ContractAddress;
    use super::super::simple_loan_proposal_test::E40;
    use super::{
        Setup, IPwnLoanDispatcher, IPwnSimpleLoanDispatcherTrait, ERC721ABIDispatcher,
        ERC721ABIDispatcherTrait, ERC20ABIDispatcher, ERC20ABIDispatcherTrait, assert_loan_eq,
        store_loan, erc721_mint, erc20_mint, erc721_read_owner, loan_token_mint, bound
    };


    fn setup() -> Setup {
        let mut setup = super::setup();
        setup.simple_loan.status = 3;
        store_loan(setup.loan.contract_address, setup.loan_id, setup.simple_loan);
        cheat_caller_address(
            setup.t721.contract_address, setup.borrower.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.t721.transfer_from(setup.borrower.contract_address, setup.loan.contract_address, 2);
        loan_token_mint(
            setup.loan_token.contract_address,
            setup.lender.contract_address,
            setup.loan.contract_address,
            setup.loan_id.into()
        );
        setup
    }

    #[test]
    #[should_panic(expected: "Caller is not the loan token holder")]
    fn test_fuzz_should_fail_when_caller_is_not_loan_token_holder(_caller: u128) {
        let setup = setup();
        let _caller: felt252 = _caller.into();
        let mut caller: ContractAddress = _caller.try_into().unwrap();
        if caller == setup.lender.contract_address {
            caller = (_caller + 1).try_into().unwrap();
        }
        cheat_caller_address(setup.loan.contract_address, caller, CheatSpan::TargetCalls(1));
        setup.loan.claim_loan(setup.loan_id);
    }

    #[test]
    #[should_panic(expected: "Loan does not exist")]
    fn test_should_fail_when_loan_does_not_exist() {
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.status = 0;
        store_loan(setup.loan.contract_address, setup.loan_id, simple_loan);
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.claim_loan(setup.loan_id);
    }

    #[test]
    #[should_panic(expected: "Loan is running")]
    fn test_should_fail_when_loan_is_not_repaid_nor_expired() {
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.status = 2;
        store_loan(setup.loan.contract_address, setup.loan_id, simple_loan);
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.claim_loan(setup.loan_id);
    }

    #[test]
    fn test_should_pass_when_loan_is_repaid() {
        let setup = setup();
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.claim_loan(setup.loan_id);
    }

    #[test]
    fn test_should_pass_when_loan_is_defaulted() {
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.status = 2;
        store_loan(setup.loan.contract_address, setup.loan_id, simple_loan);
        cheat_block_timestamp_global(setup.simple_loan.default_timestamp);
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.claim_loan(setup.loan_id);
    }

    #[test]
    fn test_should_delete_loan_data() {
        let setup = setup();
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.claim_loan(setup.loan_id);
        assert_loan_eq(setup.loan.contract_address, setup.loan_id, Default::default());
    }

    #[test]
    fn test_should_burn_loan_token() {
        let setup = setup();
        let mut serialized_loan_id: Array<felt252> = array![];
        Into::<felt252, u256>::into(setup.loan_id).serialize(ref serialized_loan_id);
        let curr_owner = erc721_read_owner(setup.loan_token.contract_address, setup.loan_id.into());
        assert_eq!(setup.lender.contract_address, curr_owner);
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.claim_loan(setup.loan_id);
        let curr_owner = erc721_read_owner(setup.loan_token.contract_address, setup.loan_id.into());
        assert_eq!(curr_owner, starknet::contract_address_const::<0>(), "Loan Token didn't burnt");
    }

    #[test]
    fn test_fuzz_should_transfer_repaid_amount_to_lender_when_loan_is_repaid(
        mut principal: u256, mut fixed_interest: u256
    ) {
        principal = bound(principal, 1, E40);
        fixed_interest = bound(fixed_interest, 0, E40);
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.principal_amount = principal;
        simple_loan.fixed_interest_amount = fixed_interest;
        simple_loan.accruing_interest_APR = 0;
        let loan_repayment_amount = setup.loan.get_loan_repayment_amount(setup.loan_id);
        let lender = setup.lender.contract_address;
        erc20_mint(setup.t20.contract_address, setup.loan.contract_address, loan_repayment_amount);
        let original_balance = setup.t20.balance_of(lender);
        cheat_caller_address(setup.loan.contract_address, lender, CheatSpan::TargetCalls(1));
        setup.loan.claim_loan(setup.loan_id);
        let current_balance = setup.t20.balance_of(lender);
        assert_eq!(
            original_balance + loan_repayment_amount, current_balance, "Lender balance mismatch"
        );
    }

    #[test]
    fn test_should_transfer_collateral_to_lender_when_loan_is_defaulted() {
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.status = 2;
        store_loan(setup.loan.contract_address, setup.loan_id, simple_loan);
        cheat_block_timestamp_global(setup.simple_loan.default_timestamp);
        let previous_owner = setup.t721.owner_of(setup.simple_loan_terms.collateral.id.into());
        assert_eq!(
            previous_owner,
            setup.loan.contract_address,
            "Simple loan is not the owner of colleteral"
        );
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.claim_loan(setup.loan_id);
        let current_owner = setup.t721.owner_of(setup.simple_loan_terms.collateral.id.into());
        assert_eq!(
            current_owner, setup.lender.contract_address, "Collateral not transferred to lender"
        );
    }

    #[test]
    fn test_should_emit_loan_claimed_when_repaid() {
        let setup = setup();
        let mut spy = spy_events();
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.claim_loan(setup.loan_id);
        spy
            .assert_emitted(
                @array![
                    (
                        setup.loan.contract_address,
                        PwnSimpleLoan::Event::LoanClaimed(
                            PwnSimpleLoan::LoanClaimed { loan_id: setup.loan_id, defaulted: false }
                        )
                    )
                ]
            );
    }

    #[test]
    fn test_should_emit_loan_claimed_when_defaulted() {
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.status = 2;
        store_loan(setup.loan.contract_address, setup.loan_id, simple_loan);
        cheat_block_timestamp_global(setup.simple_loan.default_timestamp);
        let mut spy = spy_events();
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.claim_loan(setup.loan_id);
        spy
            .assert_emitted(
                @array![
                    (
                        setup.loan.contract_address,
                        PwnSimpleLoan::Event::LoanClaimed(
                            PwnSimpleLoan::LoanClaimed { loan_id: setup.loan_id, defaulted: true }
                        )
                    )
                ]
            );
    }
}

mod try_claim_repaid_loan {
    use core::array::ArrayTrait;
    use core::integer::BoundedInt;
    use core::option::OptionTrait;
    use core::serde::Serde;
    use core::traits::TryInto;
    use openzeppelin::token::{
        erc721::interface::ERC721ABIDispatcherTrait, erc20::ERC20ABIDispatcherTrait
    };
    use pwn::loan::terms::simple::loan::pwn_simple_loan::PwnSimpleLoan::{
        hubContractMemberStateTrait, loan_tokenContractMemberStateTrait,
        configContractMemberStateTrait, revoked_nonceContractMemberStateTrait,
        category_registryContractMemberStateTrait
    };
    use pwn::loan::terms::simple::loan::pwn_simple_loan::{
        PwnSimpleLoan, PwnSimpleLoan::{PrivateTrait}
    };
    use snforge_std::{
        cheat_caller_address, CheatSpan, store, map_entry_address, mock_call, spy_events, EventSpy,
        EventSpyTrait, EventSpyAssertionsTrait
    };

    use starknet::ContractAddress;
    use super::{
        Setup, IPwnSimpleLoanDispatcherTrait, store_loan, assert_loan_eq, erc721_read_owner,
        erc721_mint, erc20_mint, IPwnHubDispatcherTrait, pwn_hub_tags, loan_token_mint
    };

    const CREDIT_AMOUNT: u256 = 100;

    fn setup() -> (Setup, PwnSimpleLoan::ContractState) {
        let mut setup = super::setup();
        setup.simple_loan.status = 3;
        let mut contract_test_state = PwnSimpleLoan::contract_state_for_testing();
        store_loan(starknet::get_contract_address(), setup.loan_id, setup.simple_loan);

        contract_test_state.hub.write(setup.hub);
        contract_test_state.loan_token.write(setup.loan_token);
        contract_test_state.config.write(setup.config);
        contract_test_state.revoked_nonce.write(setup.nonce);
        contract_test_state.category_registry.write(setup.registry);
        setup.hub.set_tag(starknet::get_contract_address(), pwn_hub_tags::ACTIVE_LOAN, true);

        cheat_caller_address(
            setup.t20.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.t20.approve(starknet::get_contract_address(), BoundedInt::max());

        cheat_caller_address(
            setup.t20.contract_address, setup.borrower.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.t20.approve(starknet::get_contract_address(), BoundedInt::max());

        cheat_caller_address(
            setup.t721.contract_address, setup.borrower.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.t721.approve(starknet::get_contract_address(), 2);
        cheat_caller_address(
            setup.t721.contract_address, setup.borrower.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.t721.transfer_from(setup.borrower.contract_address, setup.loan.contract_address, 2);
        loan_token_mint(
            setup.loan_token.contract_address,
            setup.lender.contract_address,
            starknet::get_contract_address(),
            setup.loan_id.into()
        );
        (setup, contract_test_state)
    }

    #[test]
    fn test_fuzz_should_not_proceed_when_loan_not_in_repaid_state(mut status: u8) {
        status %= 3;
        let (setup, mut contract_state) = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.status = status;
        store_loan(starknet::get_contract_address(), setup.loan_id, simple_loan);
        contract_state
            ._try_claim_repaid_loan(setup.loan_id, CREDIT_AMOUNT, setup.lender.contract_address);
        // loan_not_deleted means not proceed
        assert_loan_eq(starknet::get_contract_address(), setup.loan_id, simple_loan);
    }

    #[test]
    fn test_fuzz_should_not_proceed_when_original_lender_not_equal_to_loan_owner(
        _loan_owner: u128
    ) {
        let (setup, mut contract_state) = setup();
        let mut _loan_owner: felt252 = _loan_owner.into();
        let mut loan_owner: ContractAddress = _loan_owner.try_into().unwrap();
        if loan_owner == setup.lender.contract_address {
            loan_owner = (_loan_owner + 1).try_into().unwrap();
        }

        contract_state._try_claim_repaid_loan(setup.loan_id, CREDIT_AMOUNT, loan_owner);
        // loan_not_deleted means not proceed
        assert_loan_eq(starknet::get_contract_address(), setup.loan_id, setup.simple_loan);
    }

    #[test]
    fn test_should_burn_loan_token() {
        let (setup, mut contract_state) = setup();
        println!("this address {:?}", starknet::get_contract_address());
        let curr_owner = erc721_read_owner(setup.loan_token.contract_address, setup.loan_id.into());
        assert_eq!(curr_owner, setup.lender.contract_address);
        contract_state
            ._try_claim_repaid_loan(setup.loan_id, CREDIT_AMOUNT, setup.lender.contract_address);
        let curr_owner = erc721_read_owner(setup.loan_token.contract_address, setup.loan_id.into());
        assert_eq!(curr_owner, starknet::contract_address_const::<0>(), "Loan Token didn't burnt");
    }

    #[test]
    fn test_should_delete_loan_data() {
        let (setup, mut contract_state) = setup();
        assert_loan_eq(starknet::get_contract_address(), setup.loan_id, setup.simple_loan);
        contract_state
            ._try_claim_repaid_loan(setup.loan_id, CREDIT_AMOUNT, setup.lender.contract_address);
        assert_loan_eq(starknet::get_contract_address(), setup.loan_id, Default::default());
    }

    #[test]
    fn test_should_not_call_transfer_when_credit_amount_is_zero() {
        let (setup, mut contract_state) = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.original_source_of_funds = setup.source_of_funds;
        store_loan(starknet::get_contract_address(), setup.loan_id, simple_loan);
        mock_call(setup.config.contract_address, selector!("get_pool_adapter"), 0, 1);
        let original_balance = setup.t20.balance_of(setup.source_of_funds);
        // should revert with INVALID_SOURCE_OF_FUNDS error if proceed to transfer
        contract_state._try_claim_repaid_loan(setup.loan_id, 0, setup.lender.contract_address);
        let current_balance = setup.t20.balance_of(setup.source_of_funds);
        assert_eq!(current_balance, original_balance, "Balance mismatch!");
    }

    #[test]
    fn test_should_transfer_to_original_lender_when_source_of_funds_equal_to_original_lender() {
        let (setup, mut contract_state) = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.original_source_of_funds = setup.lender.contract_address;
        store_loan(starknet::get_contract_address(), setup.loan_id, simple_loan);
        let original_balance = setup.t20.balance_of(setup.lender.contract_address);
        contract_state
            ._try_claim_repaid_loan(setup.loan_id, CREDIT_AMOUNT, setup.lender.contract_address);
        let current_balance = setup.t20.balance_of(setup.lender.contract_address);
        assert_eq!(
            original_balance + CREDIT_AMOUNT,
            current_balance,
            "Havent transferred the credit amount"
        );
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_pool_adapter_not_registered_when_source_of_funds_not_equal_to_original_lender() {
        let (setup, mut contract_state) = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.original_source_of_funds = setup.source_of_funds;
        store_loan(starknet::get_contract_address(), setup.loan_id, simple_loan);
        mock_call(setup.config.contract_address, selector!("get_pool_adapter"), 0, 1);
        contract_state
            ._try_claim_repaid_loan(setup.loan_id, CREDIT_AMOUNT, setup.lender.contract_address);
    }

    #[test]
    fn test_should_transfer_amount_to_pool_adapter_when_source_of_funds_not_equal_to_original_lender() {
        let (setup, mut contract_state) = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.original_source_of_funds = setup.source_of_funds;
        store_loan(starknet::get_contract_address(), setup.loan_id, simple_loan);
        let original_balance = setup.t20.balance_of(setup.source_of_funds);
        contract_state
            ._try_claim_repaid_loan(setup.loan_id, CREDIT_AMOUNT, setup.lender.contract_address);
        let current_balance = setup.t20.balance_of(setup.source_of_funds);
        assert_eq!(
            original_balance + CREDIT_AMOUNT,
            current_balance,
            "Havent transferred the credit amount to pool"
        );
    }

    #[test] // duplicate with above, no expectCall
    fn test_should_call_supply_on_pool_adapter_when_source_of_funds_not_equal_to_original_lender() {
        let (setup, mut contract_state) = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.original_source_of_funds = setup.source_of_funds;
        store_loan(starknet::get_contract_address(), setup.loan_id, simple_loan);
        let original_balance = setup.t20.balance_of(setup.source_of_funds);
        contract_state
            ._try_claim_repaid_loan(setup.loan_id, CREDIT_AMOUNT, setup.lender.contract_address);
        let current_balance = setup.t20.balance_of(setup.source_of_funds);
        assert_eq!(
            original_balance + CREDIT_AMOUNT,
            current_balance,
            "Havent transferred the credit amount to pool"
        );
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_transfer_fails_when_source_of_funds_equal_to_original_lender() {
        let (setup, mut contract_state) = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.original_source_of_funds = setup.lender.contract_address;
        store_loan(starknet::get_contract_address(), setup.loan_id, simple_loan);
        let mut serialized_u256: Array<felt252> = array![];
        0_u256.serialize(ref serialized_u256);
        store(
            setup.t20.contract_address,
            map_entry_address(
                selector!("ERC20_balances"), array![starknet::get_contract_address().into()].span()
            ),
            serialized_u256.span()
        );
        contract_state
            ._try_claim_repaid_loan(setup.loan_id, CREDIT_AMOUNT, setup.lender.contract_address);
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_transfer_fails_when_source_of_funds_not_equal_to_original_lender() {
        let (setup, mut contract_state) = setup();
        let mut simple_loan = setup.simple_loan;
        simple_loan.original_source_of_funds = setup.source_of_funds;
        store_loan(starknet::get_contract_address(), setup.loan_id, simple_loan);
        let mut serialized_u256: Array<felt252> = array![];
        0_u256.serialize(ref serialized_u256);
        store(
            setup.t20.contract_address,
            map_entry_address(
                selector!("ERC20_balances"), array![starknet::get_contract_address().into()].span()
            ),
            serialized_u256.span()
        );
        contract_state
            ._try_claim_repaid_loan(setup.loan_id, CREDIT_AMOUNT, setup.lender.contract_address);
    }

    #[test]
    fn test_should_emit_loan_claimed() {
        let (setup, mut contract_state) = setup();
        let mut spy = spy_events();
        contract_state
            ._try_claim_repaid_loan(setup.loan_id, CREDIT_AMOUNT, setup.lender.contract_address);
        spy
            .assert_emitted(
                @array![
                    (
                        starknet::get_contract_address(),
                        PwnSimpleLoan::Event::LoanClaimed(
                            PwnSimpleLoan::LoanClaimed { loan_id: setup.loan_id, defaulted: false }
                        )
                    )
                ]
            );
    }
}

mod make_extension_proposal {
    use core::option::OptionTrait;
    use core::poseidon::poseidon_hash_span;
    use core::traits::TryInto;
    use pwn::loan::terms::simple::loan::pwn_simple_loan::PwnSimpleLoan;
    use snforge_std::{
        cheat_caller_address, CheatSpan, load, spy_events, EventSpy, EventSpyTrait,
        EventSpyAssertionsTrait, map_entry_address
    };
    use starknet::ContractAddress;
    use super::{IPwnSimpleLoanDispatcherTrait, Setup, setup, _get_extension_hash};

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_caller_not_proposer(_caller: u128) {
        let setup = setup();
        let _caller: felt252 = _caller.into();
        let mut caller: ContractAddress = _caller.try_into().unwrap();
        if caller == setup.extension.proposer {
            caller = (_caller + 1).try_into().unwrap();
        }
        cheat_caller_address(setup.loan.contract_address, caller, CheatSpan::TargetCalls(1));
        setup.loan.make_extension_proposal(setup.extension);
    }

    #[test]
    fn test_should_store_made_flag() {
        let setup = setup();
        cheat_caller_address(
            setup.loan.contract_address, setup.extension.proposer, CheatSpan::TargetCalls(1)
        );
        setup.loan.make_extension_proposal(setup.extension);
        let extension_hash = _get_extension_hash(setup.loan.contract_address, setup.extension);
        let is_made_value: bool = (*load(
            setup.loan.contract_address,
            map_entry_address(selector!("extension_proposal_made"), array![extension_hash].span()),
            1
        )
            .at(0)) == 1;
        assert!(is_made_value, "Not stored made flag");
    }

    #[test]
    fn test_should_emit_extension_proposal_made() {
        let setup = setup();
        let extension_hash = _get_extension_hash(setup.loan.contract_address, setup.extension);
        let mut spy = spy_events();
        cheat_caller_address(
            setup.loan.contract_address, setup.extension.proposer, CheatSpan::TargetCalls(1)
        );
        setup.loan.make_extension_proposal(setup.extension);
        spy
            .assert_emitted(
                @array![
                    (
                        setup.loan.contract_address,
                        PwnSimpleLoan::Event::ExtensionProposalMade(
                            PwnSimpleLoan::ExtensionProposalMade {
                                extension_hash: extension_hash,
                                proposer: setup.extension.proposer,
                                extension_proposal: setup.extension,
                            }
                        )
                    )
                ]
            );
    }
}

mod extend_loan {
    use core::array::ArrayTrait;
    use core::option::OptionTrait;
    use core::traits::Into;
    use core::traits::TryInto;
    use pwn::loan::lib::signature_checker;
    use pwn::loan::terms::simple::loan::pwn_simple_loan::PwnSimpleLoan;
    use snforge_std::{
        declare, ContractClassTrait, cheat_block_timestamp_global, cheat_caller_address_global,
        CheatSpan,
        signature::{
            KeyPair, KeyPairTrait, SignerTrait,
            stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
        },
    };
    use super::{
        ERC20ABIDispatcher, ERC20ABIDispatcherTrait, IPwnSimpleLoanDispatcher,
        IPwnSimpleLoanDispatcherTrait, IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait,
        ERC721ABIDispatcher, ERC721ABIDispatcherTrait, pwn_hub_tags,
        types::{CallerSpec, LenderSpec, ProposalSpec}, ContractAddress, types::{ExtensionProposal},
        IPwnHubDispatcher, IPwnHubDispatcherTrait, mock_call, spy_events, EventSpy, EventSpyTrait,
        EventSpyAssertionsTrait, assert_loan_eq, setup, store_loan, Setup, cheat_caller_address,
        erc20_mint
    };

    const MIN_EXTENSION_DURATION: u64 = 86400; // 1 day
    const MAX_EXTENSION_DURATION: u64 = 86400 * 90; // 90 days

    #[test]
    #[should_panic]
    fn test_should_fail_when_loan_does_not_exist() {
        let setup = setup();
        let mut extension = setup.extension;
        extension.loan_id = 0;

        setup.loan.extend_loan(extension, signature_checker::Signature { r: 0, s: 0 });
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_loan_is_repaid() {
        let setup = setup();
        let mut loan = setup.simple_loan;
        loan.status = 3; // Repaid status
        store_loan(setup.loan.contract_address, setup.extension.loan_id, loan);
        setup.loan.extend_loan(setup.extension, signature_checker::Signature { r: 0, s: 0 });
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_invalid_signature_when_eoa(random_private_key: felt252) {
        let setup = setup();
        let hash = setup.loan.get_extension_hash(setup.extension);
        let mut key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(random_private_key);
        if key_pair.public_key.try_into().unwrap() == setup.borrower.contract_address {
            key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(random_private_key + 1);
        }
        mock_call(setup.nonce.contract_address, selector!("is_nonce_usable"), true, 1);
        let (r, s): (felt252, felt252) = key_pair.sign(hash).unwrap();
        cheat_caller_address_global(setup.lender.contract_address);
        store_loan(setup.loan.contract_address, setup.extension.loan_id, setup.simple_loan);
        cheat_caller_address_global(setup.lender.contract_address);
        setup.loan.extend_loan(setup.extension, signature_checker::Signature { r: r, s: s });
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_offer_expirated(mut expiration: u64) {
        let setup = setup();
        let timestamp: u64 = 300;

        // Set block timestamp
        cheat_block_timestamp_global(timestamp);

        // Bound expiration between 0 and timestamp
        if expiration > timestamp {
            expiration = timestamp;
        }

        let mut extension = setup.extension;
        extension.expiration = expiration;

        // Create a loan
        store_loan(setup.loan.contract_address, setup.extension.loan_id, setup.simple_loan);

        // Mock the extension proposal being made
        mock_call(setup.loan.contract_address, selector!("extension_proposal_made"), true, 1);
        mock_call(setup.nonce.contract_address, selector!("is_nonce_usable"), true, 1);
        mock_call(
            setup.extension.proposer, selector!("is_valid_signature"), starknet::VALIDATED, 1
        );

        // Expect the transaction to revert with 'Expired' error
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.extend_loan(extension, signature_checker::Signature { r: 0, s: 0 });
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_offer_nonce_not_usable() {
        let setup = setup();
        let mut extension = setup.extension;
        // Create a loan
        store_loan(setup.loan.contract_address, setup.extension.loan_id, setup.simple_loan);
        // Expect the transaction to revert with 'Nonce not usable' error
        let hash = setup.loan.get_extension_hash(setup.extension);
        let (r, s): (felt252, felt252) = setup.borrower_key_pair.sign(hash).unwrap();
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.extend_loan(extension, signature_checker::Signature { r: r, s: s });
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_caller_is_not_borrower_nor_loan_owner(_caller: u128) {
        let setup = setup();
        let mut extension = setup.extension;
        let caller_spec: CallerSpec = Default::default();
        let lender_spec = setup.lender_spec;
        let proposal_spec = setup.proposal_spec;
        let loan_id = setup
            .loan
            .create_loan(
                proposal_spec, lender_spec, caller_spec, Option::Some(array!['lil extra'])
            );

        // Generate a caller address that's different from borrower and lender
        let mut caller: ContractAddress = Into::<u128, felt252>::into(_caller).try_into().unwrap();
        if caller == setup.borrower.contract_address || caller == setup.lender.contract_address {
            caller = Into::<u128, felt252>::into(_caller + 1).try_into().unwrap();
        }
        extension.loan_id = loan_id;
        mock_call(setup.nonce.contract_address, selector!("is_nonce_usable"), true, 1);
        mock_call(extension.proposer, selector!("is_valid_signature"), starknet::VALIDATED, 1);
        // Set the caller address for the next call
        cheat_caller_address_global(caller);
        setup.loan.extend_loan(extension, signature_checker::Signature { r: 0, s: 0 });
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_caller_is_borrower_and_proposer_is_not_loan_owner(_caller: u128) {
        let setup = setup();
        let mut extension = setup.extension;
        let caller_spec: CallerSpec = Default::default();
        let lender_spec = setup.lender_spec;
        let proposal_spec = setup.proposal_spec;
        let loan_id = setup
            .loan
            .create_loan(
                proposal_spec, lender_spec, caller_spec, Option::Some(array!['lil extra'])
            );

        // Generate a caller address that's different from borrower and lender
        let mut caller: ContractAddress = Into::<u128, felt252>::into(_caller).try_into().unwrap();
        if caller == setup.lender.contract_address {
            caller = Into::<u128, felt252>::into(_caller + 1).try_into().unwrap();
        }
        extension.loan_id = loan_id;
        extension.proposer = caller;
        mock_call(setup.nonce.contract_address, selector!("is_nonce_usable"), true, 1);
        mock_call(caller, selector!("is_valid_signature"), starknet::VALIDATED, 1);
        // Set the caller address for the next call
        cheat_caller_address_global(setup.borrower.contract_address);
        setup.loan.extend_loan(extension, signature_checker::Signature { r: 0, s: 0 });
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_caller_is_loan_owner_and_proposer_is_not_borrower(
        _proposer: u128
    ) {
        let setup = setup();
        let mut extension = setup.extension;
        let caller_spec: CallerSpec = Default::default();
        let lender_spec = setup.lender_spec;
        let proposal_spec = setup.proposal_spec;
        let loan_id = setup
            .loan
            .create_loan(
                proposal_spec, lender_spec, caller_spec, Option::Some(array!['lil extra'])
            );

        // Generate a caller address that's different from borrower and lender
        let mut proposer: ContractAddress = Into::<u128, felt252>::into(_proposer)
            .try_into()
            .unwrap();
        if proposer == setup.borrower.contract_address {
            proposer = Into::<u128, felt252>::into(_proposer + 1).try_into().unwrap();
        }
        extension.loan_id = loan_id;
        extension.proposer = proposer;
        mock_call(setup.nonce.contract_address, selector!("is_nonce_usable"), true, 1);
        mock_call(proposer, selector!("is_valid_signature"), starknet::VALIDATED, 1);
        // Set the caller address for the next call
        cheat_caller_address_global(setup.lender.contract_address);
        setup.loan.extend_loan(extension, signature_checker::Signature { r: 0, s: 0 });
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_extension_duration_less_than_min(duration: u64) {
        let setup = setup();
        let mut extension = setup.extension;
        let caller_spec: CallerSpec = Default::default();
        let lender_spec = setup.lender_spec;
        let proposal_spec = setup.proposal_spec;
        let loan_id = setup
            .loan
            .create_loan(
                proposal_spec, lender_spec, caller_spec, Option::Some(array!['lil extra'])
            );

        extension.loan_id = loan_id;
        extension
            .duration =
                if duration < MIN_EXTENSION_DURATION {
                    duration
                } else {
                    MIN_EXTENSION_DURATION - 1
                };
        let hash = setup.loan.get_extension_hash(extension);
        let (r, s): (felt252, felt252) = setup.borrower_key_pair.sign(hash).unwrap();
        mock_call(setup.nonce.contract_address, selector!("is_nonce_usable"), true, 1);
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.extend_loan(extension, signature_checker::Signature { r, s });
    }

    #[test]
    #[should_panic]
    fn test_fuzz_should_fail_when_extension_duration_more_than_max(duration: u64) {
        let setup = setup();
        let mut extension = setup.extension;
        let caller_spec: CallerSpec = Default::default();
        let lender_spec = setup.lender_spec;
        let proposal_spec = setup.proposal_spec;
        let loan_id = setup
            .loan
            .create_loan(
                proposal_spec, lender_spec, caller_spec, Option::Some(array!['lil extra'])
            );

        extension.loan_id = loan_id;
        extension
            .duration =
                if duration > MAX_EXTENSION_DURATION {
                    duration
                } else {
                    MAX_EXTENSION_DURATION + 1
                };
        let hash = setup.loan.get_extension_hash(extension);
        let (r, s): (felt252, felt252) = setup.borrower_key_pair.sign(hash).unwrap();
        mock_call(setup.nonce.contract_address, selector!("is_nonce_usable"), true, 1);

        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.extend_loan(extension, signature_checker::Signature { r, s });
    }

    #[test]
    fn test_fuzz_should_revoke_extension_nonce(nonce_space: felt252, nonce: felt252) {
        let setup = setup();
        let mut extension = setup.extension;
        let caller_spec: CallerSpec = Default::default();
        let lender_spec = setup.lender_spec;
        let proposal_spec = setup.proposal_spec;
        let loan_id = setup
            .loan
            .create_loan(
                proposal_spec, lender_spec, caller_spec, Option::Some(array!['lil extra'])
            );

        extension.loan_id = loan_id;
        extension.nonce_space = nonce_space;
        extension.nonce = nonce;
        extension.compensation_amount = 0;
        let hash = setup.loan.get_extension_hash(extension);
        let (r, s): (felt252, felt252) = setup.borrower_key_pair.sign(hash).unwrap();
        setup.hub.set_tag(setup.lender.contract_address, pwn_hub_tags::ACTIVE_LOAN, true);
        mock_call(setup.nonce.contract_address, selector!("is_nonce_usable"), true, 1);

        cheat_caller_address_global(setup.lender.contract_address);
        setup.loan.extend_loan(extension, signature_checker::Signature { r, s });
        // assert to check if the nonce was revoked
        assert!(
            setup
                .nonce
                .is_nonce_revoked(extension.proposer, extension.nonce_space, extension.nonce),
            "Nonce not revoked!"
        );
    }

    #[test]
    fn test_fuzz_should_update_loan_data(_duration: u64) {
        let setup = setup();
        let mut extension = setup.extension;
        let caller_spec: CallerSpec = Default::default();
        let lender_spec = setup.lender_spec;
        let proposal_spec = setup.proposal_spec;
        let loan_id = setup
            .loan
            .create_loan(
                proposal_spec, lender_spec, caller_spec, Option::Some(array!['lil extra'])
            );

        extension.loan_id = loan_id;
        let extension_duration = if _duration > MAX_EXTENSION_DURATION {
            MAX_EXTENSION_DURATION
        } else if _duration < MIN_EXTENSION_DURATION {
            MIN_EXTENSION_DURATION
        } else {
            _duration
        };
        extension.duration = extension_duration;
        let hash = setup.loan.get_extension_hash(extension);
        let (r, s): (felt252, felt252) = setup.borrower_key_pair.sign(hash).unwrap();
        setup.hub.set_tag(setup.lender.contract_address, pwn_hub_tags::ACTIVE_LOAN, true);
        mock_call(setup.nonce.contract_address, selector!("is_nonce_usable"), true, 1);

        // Approve the loan contract to transfer the compensation amount to lender
        cheat_caller_address(
            setup.t20.contract_address, setup.borrower.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.t20.approve(setup.loan.contract_address, extension.compensation_amount);

        let prev_loan_details = setup.loan.get_loan(loan_id);
        let mut spy = spy_events();
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.extend_loan(extension, signature_checker::Signature { r, s });
        // Check event emmission
        let loan_details = setup.loan.get_loan(loan_id);
        spy
            .assert_emitted(
                @array![
                    (
                        setup.loan.contract_address,
                        PwnSimpleLoan::Event::LoanExtended(
                            PwnSimpleLoan::LoanExtended {
                                loan_id: loan_id,
                                original_default_timestamp: prev_loan_details.default_timestamp,
                                extended_default_timestamp: loan_details.default_timestamp
                            }
                        )
                    )
                ]
            );
        // assert to check if the nonce was revoked
        assert!(
            setup
                .nonce
                .is_nonce_revoked(extension.proposer, extension.nonce_space, extension.nonce),
            "Nonce not revoked!"
        );
        // Check using asserts that the loan data is updated
        assert!(
            loan_details.default_timestamp == prev_loan_details.default_timestamp
                + extension_duration,
            "Updated timestamp"
        );
    }

    #[test]
    fn test_should_not_transfer_credit_when_amount_zero() {
        let setup = setup();
        let mut extension = setup.extension;
        let caller_spec: CallerSpec = Default::default();
        let lender_spec = setup.lender_spec;
        let proposal_spec = setup.proposal_spec;
        let loan_id = setup
            .loan
            .create_loan(
                proposal_spec, lender_spec, caller_spec, Option::Some(array!['lil extra'])
            );

        extension.loan_id = loan_id;
        extension.compensation_amount = 0;
        let hash = setup.loan.get_extension_hash(extension);
        let (r, s): (felt252, felt252) = setup.borrower_key_pair.sign(hash).unwrap();
        mock_call(setup.nonce.contract_address, selector!("is_nonce_usable"), true, 1);

        let prev_lender_balance = setup.t20.balance_of(setup.lender.contract_address);
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.extend_loan(extension, signature_checker::Signature { r, s });
        let curr_lender_balance = setup.t20.balance_of(setup.lender.contract_address);
        assert!(
            prev_lender_balance == curr_lender_balance, "Credit transferred when amount is zero!"
        );
    }

    #[test]
    fn test_should_not_transfer_credit_when_address_zero() {
        let setup = setup();
        let mut extension = setup.extension;
        let caller_spec: CallerSpec = Default::default();
        let lender_spec = setup.lender_spec;
        let proposal_spec = setup.proposal_spec;
        let loan_id = setup
            .loan
            .create_loan(
                proposal_spec, lender_spec, caller_spec, Option::Some(array!['lil extra'])
            );

        extension.loan_id = loan_id;
        // Set zero address for compensation is zero
        extension.compensation_address = starknet::contract_address_const::<0>();
        let hash = setup.loan.get_extension_hash(extension);
        let (r, s): (felt252, felt252) = setup.borrower_key_pair.sign(hash).unwrap();
        mock_call(setup.nonce.contract_address, selector!("is_nonce_usable"), true, 1);

        let prev_lender_balance = setup.t20.balance_of(setup.lender.contract_address);
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.extend_loan(extension, signature_checker::Signature { r, s });
        let curr_lender_balance = setup.t20.balance_of(setup.lender.contract_address);
        assert!(
            prev_lender_balance == curr_lender_balance, "Credit transferred when amount is zero!"
        );
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_invalid_compensation_asset() {
        let setup = setup();
        let mut extension = setup.extension;
        let caller_spec: CallerSpec = Default::default();
        let lender_spec = setup.lender_spec;
        let proposal_spec = setup.proposal_spec;
        let loan_id = setup
            .loan
            .create_loan(
                proposal_spec, lender_spec, caller_spec, Option::Some(array!['lil extra'])
            );

        extension.loan_id = loan_id;
        // Set zero address for compensation is zero
        extension.compensation_address = starknet::contract_address_const::<'incorrect_address'>();
        let hash = setup.loan.get_extension_hash(extension);
        let (r, s): (felt252, felt252) = setup.borrower_key_pair.sign(hash).unwrap();
        mock_call(setup.nonce.contract_address, selector!("is_nonce_usable"), true, 1);
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.extend_loan(extension, signature_checker::Signature { r, s });
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
    fn test_fuzz_should_transfer_compensation_when_defined(_amount: u128) {
        let setup = setup();
        let mut extension = setup.extension;
        let caller_spec: CallerSpec = Default::default();
        let lender_spec = setup.lender_spec;
        let proposal_spec = setup.proposal_spec;
        let loan_id = setup
            .loan
            .create_loan(
                proposal_spec, lender_spec, caller_spec, Option::Some(array!['lil extra'])
            );

        extension.loan_id = loan_id;
        extension.compensation_amount = _amount.try_into().unwrap();
        let hash = setup.loan.get_extension_hash(extension);
        let (r, s): (felt252, felt252) = setup.borrower_key_pair.sign(hash).unwrap();
        setup.hub.set_tag(setup.lender.contract_address, pwn_hub_tags::ACTIVE_LOAN, true);
        mock_call(setup.nonce.contract_address, selector!("is_nonce_usable"), true, 1);

        // Previous balance of the lender
        let prev_lender_balance = setup.t20.balance_of(setup.lender.contract_address);

        erc20_mint(
            setup.t20.contract_address,
            setup.borrower.contract_address,
            extension.compensation_amount
        );
        // Approve the loan contract to transfer the compensation amount to lender
        cheat_caller_address(
            setup.t20.contract_address, setup.borrower.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.t20.approve(setup.loan.contract_address, extension.compensation_amount);

        let _ = setup.loan.get_loan(loan_id);
        cheat_caller_address(
            setup.loan.contract_address, setup.lender.contract_address, CheatSpan::TargetCalls(1)
        );
        setup.loan.extend_loan(extension, signature_checker::Signature { r, s });

        // Current balance of the lender
        assert!(
            setup.t20.balance_of(setup.lender.contract_address) == prev_lender_balance
                + extension.compensation_amount,
            "Compensation not transferred!"
        );
    }
}

mod get_extension_hash {
    use pwn::loan::terms::simple::loan::interface::IPwnSimpleLoanDispatcherTrait;
    use super::{setup, _get_extension_hash};

    #[test]
    fn test_should_return_extension_hash() {
        let setup = setup();
        let actual = setup.loan.get_extension_hash(setup.extension);
        let expected = _get_extension_hash(setup.loan.contract_address, setup.extension);
        assert_eq!(actual, expected, "extension hash does not match");
    }
}

mod get_loan {
    use core::array::ArrayTrait;
    use core::option::OptionTrait;
    use core::traits::{Into, TryInto};
    use pwn::loan::lib::signature_checker;
    use pwn::loan::terms::simple::loan::pwn_simple_loan::PwnSimpleLoan;
    use pwn::multitoken::library::{
        MultiToken, MultiToken::Asset, MultiToken::Category, MultiToken::AssetTrait
    };
    use snforge_std::{
        declare, ContractClassTrait, cheat_block_timestamp_global, cheat_caller_address_global,
        CheatSpan,
        signature::{
            KeyPair, KeyPairTrait, SignerTrait,
            stark_curve::{StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl},
        },
    };
    use super::{
        ERC20ABIDispatcher, ERC20ABIDispatcherTrait, IPwnSimpleLoanDispatcher,
        IPwnSimpleLoanDispatcherTrait, IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait,
        ERC721ABIDispatcher, ERC721ABIDispatcherTrait, pwn_hub_tags, erc721_mint,
        types::{CallerSpec, LenderSpec, ProposalSpec}, ContractAddress, types::{ExtensionProposal},
        IPwnHubDispatcher, IPwnHubDispatcherTrait, mock_call, spy_events, EventSpy, EventSpyTrait,
        EventSpyAssertionsTrait, assert_loan_eq, setup, store_loan, Setup, cheat_caller_address,
        erc20_mint
    };

    const MIN_EXTENSION_DURATION: u64 = 86400; // 1 day
    const MAX_EXTENSION_DURATION: u64 = 86400 * 90; // 90 days

    pub const REFINANCING_LOAN_ID: felt252 = 44;
    const MAX_TIMESTAMP: u64 = 1099511627775; // 2^40 - 1, maximum value for u40

    #[test]
    fn test_fuzz_should_return_static_loan_data(
        _start_timestamp: u64,
        _default_timestamp: u64,
        _accruing_interest_apr: u32,
        _fixed_interest_amount: u128,
        _asset_address: felt252,
        _principal_amount: u128,
        _collateral_amount: felt252
    ) {
        let setup = setup();
        let accruing_interest_APR = if _accruing_interest_apr > 16_000_000 {
            16_000_000
        } else {
            _accruing_interest_apr
        };

        let principal_amount: u256 = _principal_amount.try_into().unwrap();
        let fixed_interest_amount: u256 = _fixed_interest_amount.try_into().unwrap();
        // let credit_address: ContractAddress = _credit_address.try_into().unwrap();
        let mut simple_loan = setup.simple_loan;
        simple_loan.start_timestamp = _start_timestamp;
        simple_loan.default_timestamp = _default_timestamp;
        simple_loan.accruing_interest_APR = accruing_interest_APR;
        simple_loan.fixed_interest_amount = fixed_interest_amount;
        simple_loan.principal_amount = principal_amount;
        let collateral_amount: u256 = Into::<felt252, u256>::into(_collateral_amount);
        simple_loan.collateral.amount = collateral_amount;

        erc721_mint(setup.loan_token.contract_address, setup.lender.contract_address, 1);
        store_loan(setup.loan.contract_address, 1, simple_loan);

        // Set the block timestamp
        super::cheat_block_timestamp_global(_start_timestamp);

        // Get the loan data
        let loan_data = setup.loan.get_loan(1);
        assert_eq!(loan_data.start_timestamp, _start_timestamp, "Start timestamp mismatch!");
        assert_eq!(loan_data.default_timestamp, _default_timestamp, "Default timestamp mismatch!");
        assert_eq!(
            loan_data.accruing_interest_APR,
            accruing_interest_APR,
            "Accruing interest APR mismatch!"
        );
        assert_eq!(
            loan_data.fixed_interest_amount,
            fixed_interest_amount,
            "Fixed interest amount mismatch!"
        );
    }

    #[test]
    fn test_should_return_correct_status() {
        // Create a mock loan
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        // Store the loan
        erc721_mint(setup.loan_token.contract_address, setup.lender.contract_address, 1);
        store_loan(setup.loan.contract_address, 1, simple_loan);
        let loan_data_1 = setup.loan.get_loan(1);
        assert!(loan_data_1.status == 2, "Loan status is 2");

        // Set the block timestamp to the default timestamp
        cheat_block_timestamp_global(simple_loan.default_timestamp);
        // Get the loan data
        let loan_data_2 = setup.loan.get_loan(1);
        assert!(loan_data_2.status == 4, "Loan status is 1");

        // Set loan status to 3
        simple_loan.status = 3;
        store_loan(setup.loan.contract_address, 1, simple_loan);
        let loan_data_3 = setup.loan.get_loan(1);
        assert!(loan_data_3.status == 3, "Loan status is 3");
    }

    #[test]
    fn test_fuzz_should_return_loan_token_owner(_loan_owner: u128) {
        // Create a mock loan
        let setup = setup();
        let mut simple_loan = setup.simple_loan;
        let loan_owner: felt252 = _loan_owner.try_into().unwrap();
        let loan_owner_address: ContractAddress = loan_owner.try_into().unwrap();
        simple_loan.original_source_of_funds = loan_owner_address;
        simple_loan.original_lender = loan_owner_address;
        // Store the loan
        mock_call(setup.loan_token.contract_address, selector!("owner_of"), loan_owner_address, 1);
        store_loan(setup.loan.contract_address, 1, simple_loan);
        let loan_data_1 = setup.loan.get_loan(1);
        assert_eq!(loan_data_1.loan_owner, loan_owner_address, "Loan token owner mismatch!");
    }

    #[test]
    fn test_fuzz_should_return_repayment_amount(
        _days: u64,
        _principal_amount: u128,
        _accruing_interest_apr: u32,
        _fixed_interest_amount: u128
    ) {
        let setup = setup();
        // Bounds
        let days = core::cmp::min(_days, setup.loan_duration_days);
        let principal_amount: u256 = _principal_amount.into();
        let accruing_interest_apr = core::cmp::min(_accruing_interest_apr, 16_000_000);
        let fixed_interest_amount: u256 = _fixed_interest_amount.into();

        // Create a mock loan
        let mut loan = setup.simple_loan;
        loan.accruing_interest_APR = accruing_interest_apr;
        loan.fixed_interest_amount = fixed_interest_amount;
        loan.principal_amount = principal_amount;

        mock_call(
            setup.loan_token.contract_address,
            selector!("owner_of"),
            setup.borrower.contract_address,
            1
        );
        store_loan(setup.loan.contract_address, 1, loan);

        super::cheat_block_timestamp_global(
            loan.start_timestamp + days * MIN_EXTENSION_DURATION
        ); // 86400 seconds in a day

        let loan_details = setup.loan.get_loan(1);
        let expected_repayment = setup.loan.get_loan_repayment_amount(1);
        assert_eq!(loan_details.repayment_amount, expected_repayment, "Repayment amount mismatch");
    }

    #[test]
    fn test_should_return_empty_loan_data_for_non_existing_loan() {
        let setup = setup();
        let non_existing_loan_id = setup.loan_id + 1;

        let loan_details = setup.loan.get_loan(non_existing_loan_id);

        let zero_address: ContractAddress = starknet::contract_address_const::<0>();

        assert_eq!(loan_details.status, 0, "Status should be None for non-existing loan");
        assert_eq!(loan_details.start_timestamp, 0, "Start timestamp should be 0");
        assert_eq!(loan_details.default_timestamp, 0, "Default timestamp should be 0");
        assert_eq!(loan_details.borrower, zero_address, "Borrower should be zero address");
        assert_eq!(
            loan_details.original_lender, zero_address, "Original lender should be zero address"
        );
        assert_eq!(loan_details.loan_owner, zero_address, "Loan owner should be zero address");
        assert_eq!(loan_details.accruing_interest_APR, 0, "Accruing interest APR should be 0");
        assert_eq!(loan_details.fixed_interest_amount, 0, "Fixed interest amount should be 0");
        assert_eq!(
            loan_details.credit.asset_address, zero_address, "Credit asset address should be zero"
        );
        assert_eq!(loan_details.credit.amount, 0, "Credit amount should be 0");
        assert_eq!(loan_details.collateral.id, 0, "Collateral ID should be 0");
        assert_eq!(loan_details.collateral.amount, 0, "Collateral amount should be 0");
        assert_eq!(
            loan_details.original_source_of_funds,
            zero_address,
            "Original source of funds should be zero address"
        );
        assert_eq!(loan_details.repayment_amount, 0, "Repayment amount should be 0");
    }
}

mod loan_metadata_uri {
    use core::clone::Clone;
    use snforge_std::mock_call;
    use super::{setup, IPwnSimpleLoanDispatcherTrait};

    #[test]
    fn test_should_return_correct_value() {
        let setup = setup();
        let mut token_uri: ByteArray = "test.uri.xyz";
        mock_call(
            setup.config.contract_address, selector!("loan_metadata_uri"), token_uri.clone(), 1
        );
        let mut uri = setup.loan.get_loan_metadata_uri();
        assert_eq!(token_uri, uri, "Returned URI does not match");
        token_uri = "test2.uri.xyz";
        mock_call(
            setup.config.contract_address, selector!("loan_metadata_uri"), token_uri.clone(), 1
        );
        uri = setup.loan.get_loan_metadata_uri();
        assert_eq!(token_uri, uri, "Returned URI does not match");
    }
}

mod get_state_fingerprint {
    use core::array::ArrayTrait;
    use core::poseidon::poseidon_hash_span;
    use core::serde::Serde;
    use pwn::loan::terms::simple::loan::interface::IPwnSimpleLoanDispatcherTrait;
    use snforge_std::cheat_block_timestamp_global;
    use super::store_loan;

    #[test]
    fn test_should_return_zero_if_loan_does_not_exist() {
        let setup = super::setup();
        let fingerprint = setup.loan.get_state_fingerprint(setup.loan_id);
        assert_eq!(fingerprint, 0, "State fingerprint not zero");
    }

    #[test]
    fn test_should_update_state_fingerprint_when_loan_defaulted() {
        let setup = super::setup();
        store_loan(setup.loan.contract_address, setup.loan_id, setup.simple_loan);
        cheat_block_timestamp_global(setup.simple_loan.default_timestamp - 1);
        let mut serialized_u256: Array<felt252> = array![];
        setup.simple_loan.fixed_interest_amount.serialize(ref serialized_u256);
        setup.simple_loan.accruing_interest_APR.serialize(ref serialized_u256);
        let mut expected: Array<felt252> = array![2, setup.simple_loan.default_timestamp.into()];
        expected.append_span(serialized_u256.span());
        assert_eq!(
            setup.loan.get_state_fingerprint(setup.loan_id), poseidon_hash_span(expected.span())
        );
        let mut expected: Array<felt252> = array![4, setup.simple_loan.default_timestamp.into()];
        expected.append_span(serialized_u256.span());
        cheat_block_timestamp_global(setup.simple_loan.default_timestamp);
        assert_eq!(
            setup.loan.get_state_fingerprint(setup.loan_id), poseidon_hash_span(expected.span())
        );
    }

    #[test]
    fn test_fuzz_should_return_correct_state_fingerprint(
        fixed_interest_amount: u256, accruing_interest_APR: u32
    ) {
        let mut setup = super::setup();
        setup.simple_loan.fixed_interest_amount = fixed_interest_amount;
        setup.simple_loan.accruing_interest_APR = accruing_interest_APR;
        store_loan(setup.loan.contract_address, setup.loan_id, setup.simple_loan);
        let mut serialized_u256: Array<felt252> = array![];
        setup.simple_loan.fixed_interest_amount.serialize(ref serialized_u256);
        setup.simple_loan.accruing_interest_APR.serialize(ref serialized_u256);
        let mut expected: Array<felt252> = array![2, setup.simple_loan.default_timestamp.into()];
        expected.append_span(serialized_u256.span());
        assert_eq!(
            setup.loan.get_state_fingerprint(setup.loan_id), poseidon_hash_span(expected.span())
        );
    }
}
