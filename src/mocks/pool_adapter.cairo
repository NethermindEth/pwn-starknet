use starknet::ContractAddress;

#[starknet::interface]
pub trait IPoolAdapter<TContractState> {
    fn withdraw(
        ref self: TContractState,
        pool: ContractAddress,
        owner: ContractAddress,
        asset: ContractAddress,
        amount: u256
    );
    fn supply(
        ref self: TContractState,
        pool: ContractAddress,
        owner: ContractAddress,
        asset: ContractAddress,
        amount: u256
    );
}

#[starknet::contract]
pub mod MockPoolAdapter {
    use openzeppelin::token::erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};
    use super::{ContractAddress, IPoolAdapter};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl MockPoolAdapterImpl of IPoolAdapter<ContractState> {
        fn withdraw(
            ref self: ContractState,
            pool: ContractAddress,
            owner: ContractAddress,
            asset: ContractAddress,
            amount: u256
        ) {
            let erc20 = ERC20ABIDispatcher { contract_address: asset };
            erc20.transferFrom(pool, owner, amount);
        }

        fn supply(
            ref self: ContractState,
            pool: ContractAddress,
            owner: ContractAddress,
            asset: ContractAddress,
            amount: u256
        ) {
            let erc20 = ERC20ABIDispatcher { contract_address: asset };
            erc20.transfer(pool, amount);
        }
    }
}
