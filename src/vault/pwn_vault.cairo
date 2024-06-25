use pwn::interfaces::pool_adapter::IPoolAdapterDispatcher;
use pwn::multitoken::library::MultiToken;
use starknet::ContractAddress;

#[starknet::interface]
trait IPwnVault<TState> {
    fn _pull(ref self: TState, asset: MultiToken::Asset, origin: ContractAddress);
    fn _push(ref self: TState, asset: MultiToken::Asset, beneficiary: ContractAddress);
    fn _push_from(
        ref self: TState,
        asset: MultiToken::Asset,
        origin: ContractAddress,
        beneficiary: ContractAddress
    );
    fn _withdraw_from_pool(
        ref self: TState,
        asset: MultiToken::Asset,
        pool_adaptor: IPoolAdapterDispatcher,
        pool: ContractAddress,
        owner: ContractAddress
    );
    fn _supply_to_pool(
        ref self: TState,
        asset: MultiToken::Asset,
        pool_adaptor: IPoolAdapterDispatcher,
        pool: ContractAddress,
        owner: ContractAddress
    );
    fn _check_transfer(
        ref self: TState,
        original_balanance: u256,
        checked_address: ContractAddress,
        check_increasing_balance: bool
    );
}

#[starknet::component]
pub mod PwnVaultComponent {
    use pwn::interfaces::pool_adapter::{IPoolAdapterDispatcher, IPoolAdapterDispatcherTrait};
    use pwn::multitoken::library::MultiToken;
    use starknet::ContractAddress;

    #[storage]
    struct Storage {}

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        VaultPull: VaultPull,
        VaultPush: VaultPush,
        VaultPushFrom: VaultPushFrom,
        PoolWithdraw: PoolWithdraw,
        PoolSupply: PoolSupply,
    }

    #[derive(Drop, starknet::Event)]
    struct VaultPull {
        asset: MultiToken::Asset,
        origin: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct VaultPush {
        asset: MultiToken::Asset,
        beneficiary: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct VaultPushFrom {
        asset: MultiToken::Asset,
        origin: ContractAddress,
        beneficiary: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct PoolWithdraw {
        asset: MultiToken::Asset,
        pool_adapter: ContractAddress,
        pool: ContractAddress,
        owner: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    struct PoolSupply {
        asset: MultiToken::Asset,
        pool_adapter: ContractAddress,
        pool: ContractAddress,
        owner: ContractAddress
    }

    pub mod Err {
        fn UNSUPPORTED_TRANSFER_FUNCTION() {
            panic!("Unsupported trasfer function");
        }
        fn UNCOMPLETE_TRANSFER() {
            panic!("Uncomplete transfer");
        }
    }

    #[embeddable_as(PwnVaultImpl)]
    impl PwnVault<
        TContractState, +HasComponent<TContractState>
    > of super::IPwnVault<ComponentState<TContractState>> {
        fn _pull(
            ref self: ComponentState<TContractState>,
            asset: MultiToken::Asset,
            origin: ContractAddress
        ) {}

        fn _push(
            ref self: ComponentState<TContractState>,
            asset: MultiToken::Asset,
            beneficiary: ContractAddress
        ) {}

        fn _push_from(
            ref self: ComponentState<TContractState>,
            asset: MultiToken::Asset,
            origin: ContractAddress,
            beneficiary: ContractAddress
        ) {}

        fn _withdraw_from_pool(
            ref self: ComponentState<TContractState>,
            asset: MultiToken::Asset,
            pool_adaptor: IPoolAdapterDispatcher,
            pool: ContractAddress,
            owner: ContractAddress
        ) {}

        fn _supply_to_pool(
            ref self: ComponentState<TContractState>,
            asset: MultiToken::Asset,
            pool_adaptor: IPoolAdapterDispatcher,
            pool: ContractAddress,
            owner: ContractAddress
        ) {}

        fn _check_transfer(
            ref self: ComponentState<TContractState>,
            original_balanance: u256,
            checked_address: ContractAddress,
            check_increasing_balance: bool
        ) {}
    }
}
