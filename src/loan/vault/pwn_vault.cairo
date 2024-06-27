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
    use pwn::multitoken::library::{MultiToken, MultiToken::AssetTrait};
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
        pub fn UNSUPPORTED_TRANSFER_FUNCTION() {
            panic!("Unsupported trasfer function");
        }
        pub fn INCOMPLETE_TRANSFER() {
            panic!("Uncomplete transfer");
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>
    > of InternalTrait<TContractState> {
        fn _pull(
            ref self: ComponentState<TContractState>,
            asset: MultiToken::Asset,
            origin: ContractAddress
        ) {
            let this_address = starknet::get_contract_address();
            let original_balance = asset.balance_of(this_address);

            asset.transfer_asset_from(origin, this_address, false);
            self._check_transfer(asset, original_balance, origin, false);

            self.emit(VaultPull { asset, origin });
        }

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

        fn _check_transfer(
            ref self: ComponentState<TContractState>,
            asset: MultiToken::Asset,
            original_balanance: u256,
            checked_address: ContractAddress,
            check_increasing_balance: bool
        ) {
            let expected_balance = if check_increasing_balance {
                original_balanance + asset.amount
            } else {
                original_balanance - asset.amount
            };

            if expected_balance != asset.balance_of(checked_address) {
                Err::INCOMPLETE_TRANSFER();
            }
        }
    }
// NOTE: hooks part skipped for now until we think about a way to have similar functionality 
}