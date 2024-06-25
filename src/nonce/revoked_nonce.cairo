use starknet::ContractAddress;

#[starknet::interface]
pub trait IRevokedNonce<TState> {
    fn revoke_nonce(
        ref self: TState,
        nonce_space: Option<felt252>,
        owner: Option<ContractAddress>,
        nonce: felt252
    );
    fn revoke_nonces(ref self: TState, nonces: Array<felt252>);
    fn revoke_nonce_space(ref self: TState) -> felt252;
    fn is_nonce_revoked(
        self: @TState, owner: Option<ContractAddress>, nonce_space: Option<felt252>, nonce: felt252
    ) -> bool;
    fn is_nonce_usable(
        self: @TState, owner: Option<ContractAddress>, nonce_space: Option<felt252>, nonce: felt252
    ) -> bool;
    fn current_nonce_space(self: @TState) -> felt252;
}

#[starknet::contract]
mod RevokedNonce {
    use pwn::hub::interface::{IPwnHubDispatcher, IPwnHubDispatcherTrait};
    use super::{ContractAddress, IRevokedNonce};

    #[storage]
    struct Storage {
        access_tag: felt252,
        hub: IPwnHubDispatcher,
        revoked_nonce: LegacyMap::<(ContractAddress, felt252, felt252), bool>,
        nonce_space: LegacyMap::<ContractAddress, felt252>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        NonceRevoked: NonceRevoked,
        NonceSpaceRevoked: NonceSpaceRevoked,
    }

    #[derive(Drop, starknet::Event)]
    struct NonceRevoked {
        owner: ContractAddress,
        nonce_space: felt252,
        nonce: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct NonceSpaceRevoked {
        owner: ContractAddress,
        nonce_space: felt252,
    }

    pub mod Err {
        fn NONCE_ALREADY_REVOKED(
            addr: super::ContractAddress, nonce_space: felt252, nonce: felt252
        ) {
            panic!(
                "Nonce already revoked. Address: {:?}, Nonce Space: {}, Nonce: {}",
                addr,
                nonce_space,
                nonce
            );
        }
        fn NONCE_NOT_USABLE(addr: super::ContractAddress, nonce_space: felt252, nonce: felt252) {
            panic!(
                "Nonce not usable. Address: {:?}, Nonce Space: {}, Nonce: {}",
                addr,
                nonce_space,
                nonce
            );
        }
    }

    #[constructor]
    fn constructor(ref self: ContractState, hub: ContractAddress, access_tag: felt252) {}

    #[abi(embed_v0)]
    impl RevokedNonceImpl of IRevokedNonce<ContractState> {
        fn revoke_nonce(
            ref self: ContractState,
            nonce_space: Option<felt252>,
            owner: Option<ContractAddress>,
            nonce: felt252
        ) {}

        fn revoke_nonces(ref self: ContractState, nonces: Array<felt252>) {}

        fn revoke_nonce_space(ref self: ContractState) -> felt252 {
            0
        }

        fn is_nonce_revoked(
            self: @ContractState,
            owner: Option<ContractAddress>,
            nonce_space: Option<felt252>,
            nonce: felt252
        ) -> bool {
            true
        }

        fn is_nonce_usable(
            self: @ContractState,
            owner: Option<ContractAddress>,
            nonce_space: Option<felt252>,
            nonce: felt252
        ) -> bool {
            true
        }

        fn current_nonce_space(self: @ContractState) -> felt252 {
            0
        }
    }
}
