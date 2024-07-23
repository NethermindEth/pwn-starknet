use core::debug;
use openzeppelin::token::erc20::ERC20Component::{ERC20CamelOnlyImpl, ERC20Impl};
use openzeppelin::token::erc20::ERC20Component::{ERC20MetadataImpl, InternalImpl as erc20_internal};
use openzeppelin::token::erc20::ERC20Component;
use openzeppelin::token::erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};
use openzeppelin::token::erc721::ERC721Component::{
    ERC721MetadataImpl, InternalImpl as erc721_internal
};
use openzeppelin::token::erc721::ERC721Component::{ERC721CamelOnlyImpl, ERC721Impl};
use openzeppelin::token::erc721::ERC721Component;
use openzeppelin::token::erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait};
use pwn::interfaces::pool_adapter::{IPoolAdapterDispatcher, IPoolAdapterDispatcherTrait};
use pwn::loan::vault::pwn_vault::{
    PwnVaultComponent, PwnVaultComponent::InternalImpl as pwn_internal
};
use pwn::mocks::erc20::ERC20Mock;
use pwn::mocks::erc721::ERC721Mock;
use pwn::mocks::pool_adapter::MockPoolAdapter;
use pwn::mocks::pwn_vault::PwnVaultTestContract;
use pwn::mocks::pwn_vault::{IPwnVaultTestContractDispatcher, IPwnVaultTestContractDispatcherTrait};
use pwn::multitoken::library::{
    MultiToken, MultiToken::Asset, MultiToken::Category, MultiToken::AssetTrait
};

use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    CheatSpan, cheat_caller_address, spy_events, mock_call, EventSpy, EventSpyTrait,
    EventSpyAssertionsTrait
};
use starknet::ContractAddress;

use super::super::integration::base_integration_test::{erc20_mint, erc721_mint};

fn ALICE() -> ContractAddress {
    starknet::contract_address_const::<'Alice'>()
}

fn BOB() -> ContractAddress {
    starknet::contract_address_const::<'Bob'>()
}

fn deploy() -> (
    IPwnVaultTestContractDispatcher, ERC721ABIDispatcher, ERC20ABIDispatcher, IPoolAdapterDispatcher
) {
    // Deployments
    let pwn_vault = declare("PwnVaultTestContract").unwrap();
    let (vault_contract, _) = pwn_vault.deploy(@array![]).unwrap();
    let erc721 = declare("ERC721Mock").unwrap();
    let (erc721_contract, _) = erc721.deploy(@array![]).unwrap();
    let erc20 = declare("ERC20Mock").unwrap();
    let (erc20_contract, _) = erc20.deploy(@array![]).unwrap();
    let pool_adapter = declare("MockPoolAdapter").unwrap();
    let (pool_adapter_contract, _) = pool_adapter.deploy(@array![]).unwrap();
    // Dispatchers
    let vault_dispatcher = IPwnVaultTestContractDispatcher { contract_address: vault_contract };
    let erc721dispatcher = ERC721ABIDispatcher { contract_address: erc721_contract };
    let erc20dispatcher = ERC20ABIDispatcher { contract_address: erc20_contract };
    let pool_adapter_dispatcher = IPoolAdapterDispatcher {
        contract_address: pool_adapter_contract
    };
    // Return dispatchers
    (vault_dispatcher, erc721dispatcher, erc20dispatcher, pool_adapter_dispatcher)
}

fn pool_setup() -> (
    IPwnVaultTestContractDispatcher,
    ContractAddress,
    ERC20ABIDispatcher,
    IPoolAdapterDispatcher,
    ContractAddress,
    Asset
) {
    let (vault, _, erc20, pool_adapter) = deploy();
    let ALICE: ContractAddress = ALICE();
    let pool: ContractAddress = starknet::contract_address_const::<'pool'>();

    let asset: Asset = Asset {
        category: Category::ERC20, asset_address: erc20.contract_address, id: 0, amount: 1000
    };

    erc20_mint(erc20.contract_address, vault.contract_address, asset.amount);

    (vault, pool, erc20, pool_adapter, ALICE, asset)
}

mod pwn_vault_pull_test {
    use pwn::multitoken::library::{
        MultiToken, MultiToken::Asset, MultiToken::Category, MultiToken::AssetTrait
    };
    use super::{
        ERC721ABIDispatcher, ERC721ABIDispatcherTrait, PwnVaultTestContract, deploy, ALICE, BOB,
        store, map_entry_address, CheatSpan, cheat_caller_address, mock_call, spy_events,
        EventSpyTrait, EventSpyAssertionsTrait, ContractAddress, IPwnVaultTestContractDispatcher,
        IPwnVaultTestContractDispatcherTrait, PwnVaultComponent
    };

    #[test]
    fn test_should_call_transfer_from_from_origin_to_vault() {
        let (vault, erc721, _, _) = deploy();
        let ALICE: ContractAddress = ALICE();
        super::erc721_mint(
            erc721.contract_address, ALICE, 42
        ); // Alice got minted an ERC721 token with id 42

        assert!(erc721.owner_of(42) == ALICE, "Token ID 42 owner is not Alice");

        cheat_caller_address(erc721.contract_address, ALICE, CheatSpan::TargetCalls(1));
        erc721.approve(vault.contract_address, 42);

        assert!(
            erc721.get_approved(42) == vault.contract_address, "Vault is approved for transfer"
        );

        let asset: Asset = Asset {
            category: Category::ERC721, asset_address: erc721.contract_address, id: 42, amount: 0
        };

        let mut spy = spy_events();
        vault.pull(asset, ALICE);
        spy
            .assert_emitted(
                @array![
                    (
                        vault.contract_address,
                        PwnVaultComponent::Event::VaultPull(
                            PwnVaultComponent::VaultPull { asset: asset, origin: ALICE }
                        )
                    )
                ]
            );
    }
    #[test]
    #[should_panic]
    fn test_should_fail_when_incomplete_transaction() {
        let (vault, erc721, _, _) = deploy();
        let ALICE: ContractAddress = ALICE();
        mock_call(erc721.contract_address, selector!("transferFrom"), true, 1);
        let asset: Asset = Asset {
            category: Category::ERC721, asset_address: erc721.contract_address, id: 42, amount: 1
        };
        vault.pull(asset, ALICE);
    }
}

mod pwn_vault_push_test {
    use pwn::loan::vault::pwn_vault::PwnVaultComponent;
    use pwn::multitoken::library::{
        MultiToken, MultiToken::Asset, MultiToken::Category, MultiToken::AssetTrait
    };
    use super::{
        ERC721ABIDispatcher, ERC721ABIDispatcherTrait, PwnVaultTestContract, deploy, ALICE, BOB,
        CheatSpan, cheat_caller_address, mock_call, spy_events, EventSpyTrait,
        EventSpyAssertionsTrait, ContractAddress, IPwnVaultTestContractDispatcher,
        IPwnVaultTestContractDispatcherTrait
    };

    #[test]
    fn test_should_call_safe_transfer_from_from_vault_to_beneficiary() {
        let (vault, erc721, _, _) = deploy();
        let ALICE: ContractAddress = ALICE();
        super::erc721_mint(
            erc721.contract_address, vault.contract_address, 42
        ); // Vault got minted an ERC721 token with id 42
        assert!(erc721.owner_of(42) == vault.contract_address, "Token ID 42 owner is not Vault");

        let asset: Asset = Asset {
            category: Category::ERC721, asset_address: erc721.contract_address, id: 42, amount: 1
        };

        let mut spy = spy_events();
        vault.push(asset, ALICE);
        spy
            .assert_emitted(
                @array![
                    (
                        vault.contract_address,
                        PwnVaultComponent::Event::VaultPush(
                            PwnVaultComponent::VaultPush { asset: asset, beneficiary: ALICE }
                        )
                    )
                ]
            );
        assert!(erc721.balance_of(ALICE) == 1, "Alice balance not updated");
        assert!(erc721.owner_of(42) == ALICE, "Token ID 42 owner is not Alice");
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_incomplete_transaction() {
        let (vault, erc721, _, _) = deploy();
        let ALICE: ContractAddress = ALICE();
        let asset: Asset = Asset {
            category: Category::ERC721, asset_address: erc721.contract_address, id: 42, amount: 1
        };

        mock_call(erc721.contract_address, selector!("transferFrom"), true, 1);

        vault.push(asset, ALICE);
    }
}

mod pwn_vault_push_from_test {
    use pwn::loan::vault::pwn_vault::PwnVaultComponent;
    use pwn::multitoken::library::{
        MultiToken, MultiToken::Asset, MultiToken::Category, MultiToken::AssetTrait
    };
    use super::{
        ERC721ABIDispatcher, ERC721ABIDispatcherTrait, PwnVaultTestContract, deploy, ALICE, BOB,
        CheatSpan, cheat_caller_address, mock_call, spy_events, EventSpyTrait,
        EventSpyAssertionsTrait, ContractAddress, IPwnVaultTestContractDispatcher,
        IPwnVaultTestContractDispatcherTrait
    };

    #[test]
    fn test_should_call_safe_transfer_from_from_origin_to_beneficiary() {
        let (vault, erc721, _, _) = deploy();
        let ALICE: ContractAddress = ALICE();
        let BOB: ContractAddress = BOB();
        super::erc721_mint(
            erc721.contract_address, ALICE, 42
        ); // Alice got minted an ERC721 token with id 42
        cheat_caller_address(erc721.contract_address, ALICE, CheatSpan::TargetCalls(1));
        erc721.approve(vault.contract_address, 42);

        assert!(erc721.owner_of(42) == ALICE, "Token ID 42 owner is not Alice");
        assert!(
            erc721.get_approved(42) == vault.contract_address, "Vault is not approved for transfer"
        );

        let asset: Asset = Asset {
            category: Category::ERC721, asset_address: erc721.contract_address, id: 42, amount: 1
        };

        let mut spy = spy_events();
        vault.push_from(asset, ALICE, BOB);
        spy
            .assert_emitted(
                @array![
                    (
                        vault.contract_address,
                        PwnVaultComponent::Event::VaultPushFrom(
                            PwnVaultComponent::VaultPushFrom {
                                asset: asset, origin: ALICE, beneficiary: BOB
                            }
                        )
                    )
                ]
            );
        assert!(erc721.owner_of(42) == BOB, "Token ID 42 owner is not Bob");
        assert!(erc721.balance_of(BOB) == 1, "Bob's balance not updated");
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_incomplete_transaction() {
        let (vault, erc721, _, _) = deploy();
        let ALICE: ContractAddress = ALICE();
        let BOB: ContractAddress = BOB();
        mock_call(erc721.contract_address, selector!("transferFrom"), true, 1);
        let asset: Asset = Asset {
            category: Category::ERC721, asset_address: erc721.contract_address, id: 42, amount: 1
        };
        vault.push_from(asset, ALICE, BOB);
    }
}

mod pwn_vault_withdraw_from_pool_test {
    use pwn::loan::vault::pwn_vault::PwnVaultComponent;
    use pwn::multitoken::library::{
        MultiToken, MultiToken::Asset, MultiToken::Category, MultiToken::AssetTrait
    };
    use super::{
        ERC20ABIDispatcher, ERC20ABIDispatcherTrait, declare, PwnVaultTestContract, MockPoolAdapter,
        deploy, ALICE, BOB, CheatSpan, cheat_caller_address, mock_call, spy_events, EventSpyTrait,
        EventSpyAssertionsTrait, ContractAddress, IPwnVaultTestContractDispatcher,
        IPwnVaultTestContractDispatcherTrait, IPoolAdapterDispatcher, IPoolAdapterDispatcherTrait
    };

    #[test]
    fn test_should_call_withdraw_on_pool_adapter() {
        let (vault, pool, erc20, pool_adapter, ALICE, asset) = super::pool_setup();

        let mut spy = spy_events();
        super::erc20_mint(erc20.contract_address, pool, asset.amount);
        assert!(asset.balance_of(pool) == asset.amount, "Amount transferred to pool");
        cheat_caller_address(erc20.contract_address, pool, CheatSpan::TargetCalls(1));
        erc20.approve(pool_adapter.contract_address, asset.amount);
        vault.withdraw_from_pool(asset, pool_adapter, pool, ALICE);
        // Check event emission
        spy
            .assert_emitted(
                @array![
                    (
                        vault.contract_address,
                        PwnVaultComponent::Event::PoolWithdraw(
                            PwnVaultComponent::PoolWithdraw {
                                asset: asset,
                                pool_adapter: pool_adapter.contract_address,
                                pool: pool,
                                owner: ALICE
                            }
                        )
                    )
                ]
            );
        assert!(erc20.balance_of(pool) == 0, "Amount not transferred from pool");
        assert!(erc20.balance_of(ALICE) == asset.amount, "Amount not transferred to Alice");
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_incomplete_transaction() {
        let (vault, pool, _, pool_adapter, ALICE, asset) = super::pool_setup();
        // mock transfer call
        mock_call(asset.asset_address, selector!("transfer"), true, 1);
        mock_call(asset.asset_address, selector!("transferFrom"), true, 1);
        vault.withdraw_from_pool(asset, pool_adapter, pool, ALICE);
    }
}

mod pwn_vault_supply_to_pool_test {
    use pwn::loan::vault::pwn_vault::PwnVaultComponent;
    use pwn::multitoken::library::{
        MultiToken, MultiToken::Asset, MultiToken::Category, MultiToken::AssetTrait
    };
    use super::{
        ERC20ABIDispatcher, ERC20ABIDispatcherTrait, declare, PwnVaultTestContract, MockPoolAdapter,
        deploy, ALICE, BOB, CheatSpan, cheat_caller_address, mock_call, spy_events, EventSpyTrait,
        EventSpyAssertionsTrait, ContractAddress, IPwnVaultTestContractDispatcher,
        IPwnVaultTestContractDispatcherTrait, IPoolAdapterDispatcher, IPoolAdapterDispatcherTrait
    };

    #[test]
    fn test_should_transfer_asset_to_pool_adapter() {
        let (vault, pool, erc20, pool_adapter, ALICE, asset) = super::pool_setup();
        let mut spy = spy_events();

        vault.supply_to_pool(asset, pool_adapter, pool, ALICE);

        // Check that the asset was transferred to the pool adapter
        assert!(erc20.balance_of(pool) == asset.amount, "Asset not transferred to pool adapter");

        spy
            .assert_emitted(
                @array![
                    (
                        vault.contract_address,
                        PwnVaultComponent::Event::PoolSupply(
                            PwnVaultComponent::PoolSupply {
                                asset: asset,
                                pool_adapter: pool_adapter.contract_address,
                                pool: pool,
                                owner: ALICE
                            }
                        )
                    )
                ]
            );
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_incomplete_transaction() {
        let (vault, pool, _, pool_adapter, ALICE, asset) = super::pool_setup();
        // mock transfer call
        mock_call(asset.asset_address, selector!("transfer"), true, 2);
        vault.supply_to_pool(asset, pool_adapter, pool, ALICE);
    }
}

