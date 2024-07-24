use core::starknet::event;
use pwn::interfaces::pool_adapter::{IPoolAdapterDispatcher, IPoolAdapterDispatcherTrait};
use pwn::loan::vault::pwn_vault::PwnVaultComponent;
use pwn::multitoken::library::{MultiToken, MultiToken::AssetTrait};
use starknet::ContractAddress;

#[starknet::interface]
pub trait IPwnVaultTestContract<TState> {
    fn pull(ref self: TState, asset: MultiToken::Asset, origin: ContractAddress);
    fn push(ref self: TState, asset: MultiToken::Asset, beneficiary: ContractAddress);
    fn push_from(
        ref self: TState,
        asset: MultiToken::Asset,
        origin: ContractAddress,
        beneficiary: ContractAddress
    );
    fn withdraw_from_pool(
        ref self: TState,
        asset: MultiToken::Asset,
        pool_adaptor: IPoolAdapterDispatcher,
        pool: ContractAddress,
        owner: ContractAddress
    );
    fn supply_to_pool(
        ref self: TState,
        asset: MultiToken::Asset,
        pool_adaptor: IPoolAdapterDispatcher,
        pool: ContractAddress,
        owner: ContractAddress
    );
}

#[starknet::contract]
pub mod PwnVaultTestContract {
    use super::{
        IPwnVaultTestContract, IPoolAdapterDispatcher, MultiToken, PwnVaultComponent,
        ContractAddress
    };

    component!(path: PwnVaultComponent, storage: PwnVaultStorage, event: PwnVaultEvent);
    impl PwnVaultImpl = PwnVaultComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        PwnVaultStorage: PwnVaultComponent::Storage
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        PwnVaultEvent: PwnVaultComponent::Event
    }

    // External functions that call internal component functions
    #[abi(embed_v0)]
    impl PwnVaultTestContractImpl of super::IPwnVaultTestContract<ContractState> {
        fn pull(ref self: ContractState, asset: MultiToken::Asset, origin: ContractAddress) {
            self.PwnVaultStorage._pull(asset, origin);
        }

        fn push(ref self: ContractState, asset: MultiToken::Asset, beneficiary: ContractAddress) {
            self.PwnVaultStorage._push(asset, beneficiary);
        }

        fn push_from(
            ref self: ContractState,
            asset: MultiToken::Asset,
            origin: ContractAddress,
            beneficiary: ContractAddress
        ) {
            self.PwnVaultStorage._push_from(asset, origin, beneficiary);
        }

        fn withdraw_from_pool(
            ref self: ContractState,
            asset: MultiToken::Asset,
            pool_adaptor: IPoolAdapterDispatcher,
            pool: ContractAddress,
            owner: ContractAddress
        ) {
            self.PwnVaultStorage._withdraw_from_pool(asset, pool_adaptor, pool, owner);
        }

        fn supply_to_pool(
            ref self: ContractState,
            asset: MultiToken::Asset,
            pool_adaptor: IPoolAdapterDispatcher,
            pool: ContractAddress,
            owner: ContractAddress
        ) {
            self.PwnVaultStorage._supply_to_pool(asset, pool_adaptor, pool, owner);
        }
    }
}
