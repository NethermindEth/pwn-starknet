use core::debug;
use openzeppelin::token::erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};
use openzeppelin::token::erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait};
use pwn::interfaces::pool_adapter::{IPoolAdapterDispatcher, IPoolAdapterDispatcherTrait};
use pwn::mocks::mock_erc20::MockERC20;
use pwn::mocks::mock_erc721::MockERC721;
use pwn::mocks::mock_pool_adapter::MockPoolAdapter;
use pwn::mocks::mock_vault::PwnVaultTestContract;
use pwn::mocks::mock_vault::{
    IMockPwnVaultTestContractDispatcher, IMockPwnVaultTestContractDispatcherTrait
};

use snforge_std::{
    declare, ContractClassTrait, store, load, map_entry_address, start_cheat_caller_address,
    CheatSpan, cheat_caller_address, spy_events, mock_call, EventSpy, EventSpyTrait,
    EventSpyAssertionsTrait
};
use starknet::ContractAddress;

#[starknet::interface]
trait IERC20Mock<TState> {
    fn mint(ref self: TState, recipient: ContractAddress, amount: u256);
}

#[starknet::interface]
trait IERC7210Mock<TState> {
    fn mint(ref self: TState, recipient: ContractAddress, tokenId: u256);
}

fn ALICE() -> ContractAddress {
    starknet::contract_address_const::<'Alice'>()
}

fn BOB() -> ContractAddress {
    starknet::contract_address_const::<'Bob'>()
}

fn deploy() -> (
    starknet::ContractAddress,
    starknet::ContractAddress,
    starknet::ContractAddress,
    starknet::ContractAddress
) {
    let vault = declare("PwnVaultTestContract").unwrap();
    let (vault_contract, _) = vault.deploy(@array![]).unwrap();
    let erc721 = declare("MockERC721").unwrap();
    let (erc721_contract, _) = erc721.deploy(@array![]).unwrap();
    let erc20 = declare("MockERC20").unwrap();
    let (erc20_contract, _) = erc20.deploy(@array![]).unwrap();
    let pool_adapter = declare("MockPoolAdapter").unwrap();
    let (pool_adapter_contract, _) = pool_adapter.deploy(@array![]).unwrap();
    (vault_contract, erc721_contract, erc20_contract, pool_adapter_contract)
}

fn mint_erc20(contract_address: ContractAddress, recipient: ContractAddress, amount: u256) {
    IERC20MockDispatcher { contract_address }.mint(recipient, amount);
}

fn mint_erc721(contract_address: ContractAddress, recipient: ContractAddress, tokenId: u256) {
    IERC7210MockDispatcher { contract_address }.mint(recipient, tokenId);
}

mod pwn_vault_pull_test {
    use pwn::loan::vault::pwn_vault::PwnVaultComponent;
    use pwn::multitoken::library::{
        MultiToken, MultiToken::Asset, MultiToken::Category, MultiToken::AssetTrait
    };
    use super::{
        ERC721ABIDispatcher, ERC721ABIDispatcherTrait, PwnVaultTestContract, deploy, ALICE, BOB,
        mint_erc721, CheatSpan, cheat_caller_address, mock_call, spy_events, EventSpyTrait,
        EventSpyAssertionsTrait, ContractAddress, IMockPwnVaultTestContractDispatcher,
        IMockPwnVaultTestContractDispatcherTrait
    };

    #[test]
    fn test_should_call_transfer_from_from_origin_to_vault() {
        let (vault, erc721, _, _) = deploy();
        let ALICE: ContractAddress = ALICE();
        mint_erc721(erc721, ALICE, 42); // Alice got minted an ERC721 token with id 42
        let erc721dispatcher = ERC721ABIDispatcher { contract_address: erc721 };

        assert!(erc721dispatcher.owner_of(42) == ALICE, "Token ID 42 owner is not Alice");

        cheat_caller_address(erc721, ALICE, CheatSpan::TargetCalls(1));
        erc721dispatcher.approve(vault, 42);

        assert!(erc721dispatcher.get_approved(42) == vault, "Vault is approved for transfer");

        let asset: Asset = Asset {
            category: Category::ERC721, asset_address: erc721, id: 42, amount: 0
        };

        let mut spy = spy_events();
        let vaultDispatcher = IMockPwnVaultTestContractDispatcher { contract_address: vault };
        vaultDispatcher.pull(asset, ALICE);
        spy
            .assert_emitted(
                @array![
                    (
                        vault,
                        PwnVaultComponent::Event::VaultPull(
                            PwnVaultComponent::VaultPull { asset: asset, origin: ALICE }
                        )
                    )
                ]
            );
        assert!(erc721dispatcher.balance_of(vault) == 1, "Vault balance not updated");
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_incomplete_transaction_1() {
        let (vault, erc721, _, _) = deploy();
        let ALICE: ContractAddress = ALICE();
        mock_call(erc721, selector!("transferFrom"), true, 1);
        let asset: Asset = Asset {
            category: Category::ERC721, asset_address: erc721, id: 42, amount: 1
        };
        let vaultDispatcher = IMockPwnVaultTestContractDispatcher { contract_address: vault };
        vaultDispatcher.pull(asset, ALICE);
    }
}

mod pwn_vault_push_test {
    use pwn::loan::vault::pwn_vault::PwnVaultComponent;
    use pwn::multitoken::library::{
        MultiToken, MultiToken::Asset, MultiToken::Category, MultiToken::AssetTrait
    };
    use super::{
        ERC721ABIDispatcher, ERC721ABIDispatcherTrait, PwnVaultTestContract, deploy, ALICE, BOB,
        mint_erc721, CheatSpan, cheat_caller_address, mock_call, spy_events, EventSpyTrait,
        EventSpyAssertionsTrait, ContractAddress, IMockPwnVaultTestContractDispatcher,
        IMockPwnVaultTestContractDispatcherTrait
    };

    #[test]
    fn test_should_call_safe_transfer_from_from_vault_to_beneficiary() {
        let (vault, erc721, _, _) = deploy();
        let ALICE: ContractAddress = ALICE();
        mint_erc721(erc721, vault, 42); // Vault got minted an ERC721 token with id 42
        let erc721dispatcher = ERC721ABIDispatcher { contract_address: erc721 };

        assert!(erc721dispatcher.owner_of(42) == vault, "Token ID 42 owner is not Vault");

        let asset: Asset = Asset {
            category: Category::ERC721, asset_address: erc721, id: 42, amount: 1
        };

        let vaultDispatcher = IMockPwnVaultTestContractDispatcher { contract_address: vault };
        vaultDispatcher.push(asset, ALICE);

        assert!(erc721dispatcher.balance_of(ALICE) == 1, "Alice balance not updated");
        assert!(erc721dispatcher.owner_of(42) == ALICE, "Token ID 42 owner is not Alice");
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_incomplete_transaction() {
        let (vault, erc721, _, _) = deploy();
        let ALICE: ContractAddress = ALICE();
        let asset: Asset = Asset {
            category: Category::ERC721, asset_address: erc721, id: 42, amount: 1
        };

        mock_call(erc721, selector!("transferFrom"), true, 1);

        let vaultDispatcher = IMockPwnVaultTestContractDispatcher { contract_address: vault };
        vaultDispatcher.push(asset, ALICE);
    }

    #[test]
    fn test_should_emit_event_vault_push() {
        let (vault, erc721, _, _) = deploy();
        let ALICE: ContractAddress = ALICE();
        mint_erc721(erc721, vault, 42); // Vault got minted an ERC721 token with id 42

        let asset: Asset = Asset {
            category: Category::ERC721, asset_address: erc721, id: 42, amount: 1
        };

        let mut spy = spy_events();
        let vaultDispatcher = IMockPwnVaultTestContractDispatcher { contract_address: vault };
        vaultDispatcher.push(asset, ALICE);
        spy
            .assert_emitted(
                @array![
                    (
                        vault,
                        PwnVaultComponent::Event::VaultPush(
                            PwnVaultComponent::VaultPush { asset: asset, beneficiary: ALICE }
                        )
                    )
                ]
            );
    }
}

mod pwn_vault_push_from_test {
    use pwn::loan::vault::pwn_vault::PwnVaultComponent;
    use pwn::multitoken::library::{
        MultiToken, MultiToken::Asset, MultiToken::Category, MultiToken::AssetTrait
    };
    use super::{
        ERC721ABIDispatcher, ERC721ABIDispatcherTrait, PwnVaultTestContract, deploy, ALICE, BOB,
        mint_erc721, CheatSpan, cheat_caller_address, mock_call, spy_events, EventSpyTrait,
        EventSpyAssertionsTrait, ContractAddress, IMockPwnVaultTestContractDispatcher,
        IMockPwnVaultTestContractDispatcherTrait
    };

    #[test]
    fn test_should_call_safe_transfer_from_from_origin_to_beneficiary() {
        let (vault, erc721, _, _) = deploy();
        let ALICE: ContractAddress = ALICE();
        let BOB: ContractAddress = BOB();
        mint_erc721(erc721, ALICE, 42); // Alice got minted an ERC721 token with id 42
        let erc721dispatcher = ERC721ABIDispatcher { contract_address: erc721 };

        cheat_caller_address(erc721, ALICE, CheatSpan::TargetCalls(1));
        erc721dispatcher.approve(vault, 42);

        assert!(erc721dispatcher.owner_of(42) == ALICE, "Token ID 42 owner is not Alice");
        assert!(erc721dispatcher.get_approved(42) == vault, "Vault is not approved for transfer");

        let asset: Asset = Asset {
            category: Category::ERC721, asset_address: erc721, id: 42, amount: 1
        };

        let mut spy = spy_events();
        let vaultDispatcher = IMockPwnVaultTestContractDispatcher { contract_address: vault };
        vaultDispatcher.push_from(asset, ALICE, BOB);
        spy
            .assert_emitted(
                @array![
                    (
                        vault,
                        PwnVaultComponent::Event::VaultPushFrom(
                            PwnVaultComponent::VaultPushFrom {
                                asset: asset, origin: ALICE, beneficiary: BOB
                            }
                        )
                    )
                ]
            );
        assert!(erc721dispatcher.owner_of(42) == BOB, "Token ID 42 owner is not Bob");
        assert!(erc721dispatcher.balance_of(BOB) == 1, "Bob's balance not updated");
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_incomplete_transaction() {
        let (vault, erc721, _, _) = deploy();
        let ALICE: ContractAddress = ALICE();
        let BOB: ContractAddress = BOB();
        mock_call(erc721, selector!("transferFrom"), true, 1);
        let asset: Asset = Asset {
            category: Category::ERC721, asset_address: erc721, id: 42, amount: 1
        };
        let vaultDispatcher = IMockPwnVaultTestContractDispatcher { contract_address: vault };
        vaultDispatcher.push_from(asset, ALICE, BOB);
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
        EventSpyAssertionsTrait, ContractAddress, IMockPwnVaultTestContractDispatcher,
        IMockPwnVaultTestContractDispatcherTrait, IPoolAdapterDispatcher,
        IPoolAdapterDispatcherTrait
    };

    fn setup() -> (
        ContractAddress, ContractAddress, ContractAddress, ContractAddress, ContractAddress, Asset
    ) {
        let (vault, _, erc20, pool_adapter) = deploy();
        let ALICE: ContractAddress = ALICE();
        let pool: ContractAddress = starknet::contract_address_const::<'pool'>();

        let asset: Asset = Asset {
            category: Category::ERC20, asset_address: erc20, id: 0, amount: 1000
        };

        (vault, pool, erc20, pool_adapter, ALICE, asset)
    }

    #[test]
    fn test_should_call_withdraw_on_pool_adapter() {
        let (vault, pool, erc20, pool_adapter, ALICE, asset) = setup();

        let mut spy = spy_events();
        let vaultDispatcher = IMockPwnVaultTestContractDispatcher { contract_address: vault };
        let poolAdapterDispatcher = IPoolAdapterDispatcher { contract_address: pool_adapter };
        super::mint_erc20(erc20, pool, asset.amount);
        let erc20dispatcher = ERC20ABIDispatcher { contract_address: erc20 };
        assert!(asset.balance_of(pool) == asset.amount, "Amount transferred to pool");
        cheat_caller_address(erc20, pool, CheatSpan::TargetCalls(1));
        erc20dispatcher.approve(pool_adapter, asset.amount);
        vaultDispatcher.withdraw_from_pool(asset, poolAdapterDispatcher, pool, ALICE);
        // Check event emission
        spy
            .assert_emitted(
                @array![
                    (
                        vault,
                        PwnVaultComponent::Event::PoolWithdraw(
                            PwnVaultComponent::PoolWithdraw {
                                asset: asset, pool_adapter: pool_adapter, pool: pool, owner: ALICE
                            }
                        )
                    )
                ]
            );
        assert!(erc20dispatcher.balance_of(pool) == 0, "Amount not transferred from pool");
        assert!(
            erc20dispatcher.balance_of(ALICE) == asset.amount, "Amount not transferred to Alice"
        );
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_incomplete_transaction() {
        let (vault, pool, _, pool_adapter, ALICE, asset) = setup();
        // mock transfer call
        mock_call(asset.asset_address, selector!("transfer"), true, 1);
        mock_call(asset.asset_address, selector!("transferFrom"), true, 1);

        let vaultDispatcher = IMockPwnVaultTestContractDispatcher { contract_address: vault };
        let poolAdapterDispatcher = IPoolAdapterDispatcher { contract_address: pool_adapter };

        vaultDispatcher.withdraw_from_pool(asset, poolAdapterDispatcher, pool, ALICE);
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
        EventSpyAssertionsTrait, ContractAddress, IMockPwnVaultTestContractDispatcher,
        IMockPwnVaultTestContractDispatcherTrait, IPoolAdapterDispatcher,
        IPoolAdapterDispatcherTrait
    };

    fn setup() -> (
        ContractAddress, ContractAddress, ContractAddress, ContractAddress, ContractAddress, Asset
    ) {
        let (vault, _, erc20, pool_adapter) = deploy();
        let ALICE: ContractAddress = ALICE();
        let pool: ContractAddress = starknet::contract_address_const::<'pool'>();

        let asset: Asset = Asset {
            category: Category::ERC20, asset_address: erc20, id: 0, amount: 1000
        };

        super::mint_erc20(erc20, vault, asset.amount);

        (vault, pool, erc20, pool_adapter, ALICE, asset)
    }

    #[test]
    fn test_should_transfer_asset_to_pool_adapter() {
        let (vault, pool, erc20, pool_adapter, ALICE, asset) = setup();

        let vaultDispatcher = IMockPwnVaultTestContractDispatcher { contract_address: vault };
        let poolAdapterDispatcher = IPoolAdapterDispatcher { contract_address: pool_adapter };
        let erc20dispatcher = ERC20ABIDispatcher { contract_address: erc20 };

        let mut spy = spy_events();

        vaultDispatcher.supply_to_pool(asset, poolAdapterDispatcher, pool, ALICE);

        // Check that the asset was transferred to the pool adapter
        assert!(
            erc20dispatcher.balance_of(pool) == asset.amount,
            "Asset not transferred to pool adapter"
        );

        spy
            .assert_emitted(
                @array![
                    (
                        vault,
                        PwnVaultComponent::Event::PoolSupply(
                            PwnVaultComponent::PoolSupply {
                                asset: asset, pool_adapter: pool_adapter, pool: pool, owner: ALICE
                            }
                        )
                    )
                ]
            );
    }

    #[test]
    #[should_panic]
    fn test_should_fail_when_incomplete_transaction() {
        let (vault, pool, _, pool_adapter, ALICE, asset) = setup();

        // mock transfer call
        mock_call(asset.asset_address, selector!("transfer"), true, 2);

        let vaultDispatcher = IMockPwnVaultTestContractDispatcher { contract_address: vault };
        let poolAdapterDispatcher = IPoolAdapterDispatcher { contract_address: pool_adapter };

        vaultDispatcher.supply_to_pool(asset, poolAdapterDispatcher, pool, ALICE);
    }
}
