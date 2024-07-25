//! The `PwnVaultComponent` module provides vault functionalities within the Simple Loan 
//! contract on the Starknet platform. This component manages the transfer and storage of 
//! multi-token assets, including ERC20, ERC721, and ERC1155 tokens.
//!
//! # Features
//! 
//! - **Vault Operations**: Provides functions to pull, push, and transfer assets to and 
//!   from the vault, ensuring secure and controlled asset management.
//! - **Pool Operations**: Facilitates interactions with liquidity pools, allowing assets 
//!   to be supplied or withdrawn.
//! - **Event Emissions**: Emits events for various actions, such as pulling, pushing, and 
//!   interacting with pools, to ensure transparency and traceability.
//! - **Error Handling**: Defines specific errors to handle unsupported or incomplete 
//!   operations.
//!
//! # Components
//! 
//! - `Err`: Module containing error handling functions for unsupported or incomplete 
//!   transfer operations.
//!
//! # Constants
//! 
//! This module currently does not define specific constants but integrates directly with 
//! other components and modules.
//!
//! The `PwnVaultComponent` is designed to integrate seamlessly with the Simple Loan 
//! contract, providing essential vault functionalities that ensure secure asset management 
//! and interaction with external liquidity pools. This component is a critical part of the 
//! broader PWN ecosystem on Starknet, facilitating secure and efficient loan operations.

#[starknet::component]
pub mod PwnVaultComponent {
    use pwn::interfaces::pool_adapter::{IPoolAdapterDispatcher, IPoolAdapterDispatcherTrait};
    use pwn::multitoken::library::{MultiToken, MultiToken::AssetTrait};
    use starknet::ContractAddress;

    #[storage]
    struct Storage {}

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        VaultPull: VaultPull,
        VaultPush: VaultPush,
        VaultPushFrom: VaultPushFrom,
        PoolWithdraw: PoolWithdraw,
        PoolSupply: PoolSupply,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VaultPull {
        pub asset: MultiToken::Asset,
        pub origin: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VaultPush {
        pub asset: MultiToken::Asset,
        pub beneficiary: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct VaultPushFrom {
        pub asset: MultiToken::Asset,
        pub origin: ContractAddress,
        pub beneficiary: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct PoolWithdraw {
        pub asset: MultiToken::Asset,
        pub pool_adapter: ContractAddress,
        pub pool: ContractAddress,
        pub owner: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    pub struct PoolSupply {
        pub asset: MultiToken::Asset,
        pub pool_adapter: ContractAddress,
        pub pool: ContractAddress,
        pub owner: ContractAddress
    }

    pub mod Err {
        pub fn UNSUPPORTED_TRANSFER_FUNCTION() {
            panic!("PWN Vault: Unsupported transfer function");
        }
        pub fn INCOMPLETE_TRANSFER() {
            panic!("PWN Vault: Incomplete transfer");
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>
    > of InternalTrait<TContractState> {
        /// Pulls the specified `asset` from the `origin` address into the contract's vault.
        /// This function emits a `VaultPull` event upon successful transfer.
        /// 
        /// - `asset`: The asset to be transferred.
        /// - `origin`: The address from which the asset is pulled.
        fn _pull(
            ref self: ComponentState<TContractState>,
            asset: MultiToken::Asset,
            origin: ContractAddress
        ) {
            let this_address = starknet::get_contract_address();
            let original_balance = asset.balance_of(this_address);

            asset.transfer_asset_from(origin, this_address, false);
            self._check_transfer(asset, original_balance, this_address, true);

            self.emit(VaultPull { asset, origin });
        }

        /// Pushes the specified `asset` to the `beneficiary` address from the contract's vault.
        /// This function emits a `VaultPush` event upon successful transfer.
        /// 
        /// - `asset`: The asset to be transferred.
        /// - `beneficiary`: The address receiving the asset.
        fn _push(
            ref self: ComponentState<TContractState>,
            asset: MultiToken::Asset,
            beneficiary: ContractAddress
        ) {
            let original_balance = asset.balance_of(beneficiary);
            asset.transfer_asset_from(starknet::get_contract_address(), beneficiary, false);
            self._check_transfer(asset, original_balance, beneficiary, true);

            self.emit(VaultPush { asset, beneficiary });
        }

        /// Transfers the specified `asset` from the `origin` address to the `beneficiary` address.
        /// This function emits a `VaultPushFrom` event upon successful transfer.
        /// 
        /// - `asset`: The asset to be transferred.
        /// - `origin`: The address from which the asset is transferred.
        /// - `beneficiary`: The address receiving the asset.
        fn _push_from(
            ref self: ComponentState<TContractState>,
            asset: MultiToken::Asset,
            origin: ContractAddress,
            beneficiary: ContractAddress
        ) {
            let original_balance = asset.balance_of(beneficiary);
            asset.transfer_asset_from(origin, beneficiary, false);
            self._check_transfer(asset, original_balance, beneficiary, true);
            self.emit(VaultPushFrom { asset, origin, beneficiary });
        }

        /// Withdraws the specified `asset` from a liquidity pool using the provided `pool_adapter`.
        /// The withdrawn assets are transferred to the `owner` address.
        /// This function emits a `PoolWithdraw` event upon successful withdrawal.
        /// 
        /// - `asset`: The asset to be withdrawn.
        /// - `pool_adapter`: The adapter for the liquidity pool.
        /// - `pool`: The address of the liquidity pool.
        /// - `owner`: The address to receive the withdrawn asset.
        fn _withdraw_from_pool(
            ref self: ComponentState<TContractState>,
            asset: MultiToken::Asset,
            pool_adaptor: IPoolAdapterDispatcher,
            pool: ContractAddress,
            owner: ContractAddress
        ) {
            let original_balance = asset.balance_of(owner);
            pool_adaptor.withdraw(pool, owner, asset.asset_address, asset.amount);
            self._check_transfer(asset, original_balance, owner, true);

            self
                .emit(
                    PoolWithdraw { asset, pool_adapter: pool_adaptor.contract_address, pool, owner }
                );
        }

        /// Supplies the specified `asset` to a liquidity pool using the provided `pool_adapter`.
        /// The asset is transferred from the contract's address to the pool, with the `owner` address
        /// specified as the owner of the supplied asset.
        /// This function emits a `PoolSupply` event upon successful supply.
        /// 
        /// - `asset`: The asset to be supplied.
        /// - `pool_adapter`: The adapter for the liquidity pool.
        /// - `pool`: The address of the liquidity pool.
        /// - `owner`: The address associated with the supplied asset.
        fn _supply_to_pool(
            ref self: ComponentState<TContractState>,
            asset: MultiToken::Asset,
            pool_adaptor: IPoolAdapterDispatcher,
            pool: ContractAddress,
            owner: ContractAddress
        ) {
            let this_address = starknet::get_contract_address();
            let original_balance = asset.balance_of(this_address);
            asset.transfer_asset_from(this_address, pool_adaptor.contract_address, false);
            pool_adaptor.supply(pool, owner, asset.asset_address, asset.amount);

            self._check_transfer(asset, original_balance, this_address, false);

            self
                .emit(
                    PoolSupply { asset, pool_adapter: pool_adaptor.contract_address, pool, owner }
                );
        }

        /// Checks the balance of the `checked_address` after a transfer operation to ensure 
        /// the transfer was successful. If the balance does not match the expected value, 
        /// an `INCOMPLETE_TRANSFER` error is thrown.
        /// 
        /// - `asset`: The asset being checked.
        /// - `original_balance`: The balance before the transfer.
        /// - `checked_address`: The address whose balance is being checked.
        /// - `check_increasing_balance`: If `true`, expects the balance to increase; if `false`, expects the balance to decrease.
        fn _check_transfer(
            ref self: ComponentState<TContractState>,
            asset: MultiToken::Asset,
            original_balance: u256,
            checked_address: ContractAddress,
            check_increasing_balance: bool
        ) {
            let expected_balance = if check_increasing_balance {
                original_balance + asset.get_transfer_amount()
            } else {
                original_balance - asset.get_transfer_amount()
            };
            if expected_balance != asset.balance_of(checked_address) {
                Err::INCOMPLETE_TRANSFER();
            }
        }
    }
// NOTE: hooks part skipped for now until we think about a way to have similar functionality 
}
