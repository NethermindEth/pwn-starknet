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
        self: @TState, owner: ContractAddress, nonce_space: felt252, nonce: felt252
    ) -> bool;
    fn is_nonce_usable(
        self: @TState, owner: ContractAddress, nonce_space: felt252, nonce: felt252
    ) -> bool;
    fn current_nonce_space(self: @TState) -> felt252;
}

#[starknet::contract]
pub mod RevokedNonce {
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
        pub fn NONCE_ALREADY_REVOKED(
            addr: super::ContractAddress, nonce_space: felt252, nonce: felt252
        ) {
            panic!(
                "Nonce already revoked. Address: {:?}, Nonce Space: {}, Nonce: {}",
                addr,
                nonce_space,
                nonce
            );
        }
        pub fn NONCE_NOT_USABLE(
            addr: super::ContractAddress, nonce_space: felt252, nonce: felt252
        ) {
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
        ) {
            let caller = starknet::get_caller_address();

            match nonce_space {
                Option::Some(nonce_space) => {
                    match owner {
                        Option::Some(owner) => { self._revoke_nonce(nonce_space, owner, nonce); },
                        Option::None => { self._revoke_nonce(nonce_space, caller, nonce); },
                    }
                },
                Option::None => {
                    self._revoke_nonce(self.nonce_space.read(caller), caller, nonce);
                },
            }
        }

        fn revoke_nonces(ref self: ContractState, nonces: Array<felt252>) {
            let caller = starknet::get_caller_address();
            let nonce_space = self.nonce_space.read(caller);

            let len = nonces.len();
            let mut i = 0;
            while i < len {
                self._revoke_nonce(nonce_space, caller, *nonces.at(i));
            }
        }

        fn revoke_nonce_space(ref self: ContractState) -> felt252 {
            let caller = starknet::get_caller_address();

            self
                .emit(
                    NonceSpaceRevoked { owner: caller, nonce_space: self.nonce_space.read(caller), }
                );

            let current_nonce_space = self.nonce_space.read(caller);
            self.nonce_space.write(caller, current_nonce_space + 1);

            current_nonce_space + 1
        }

        fn is_nonce_revoked(
            self: @ContractState, owner: ContractAddress, nonce_space: felt252, nonce: felt252
        ) -> bool {
            self.revoked_nonce.read((owner, nonce_space, nonce))
        }

        fn is_nonce_usable(
            self: @ContractState, owner: ContractAddress, nonce_space: felt252, nonce: felt252
        ) -> bool {
            if self.nonce_space.read(owner) != nonce_space {
                return false;
            }

            !self.revoked_nonce.read((owner, nonce_space, nonce))
        }

        fn current_nonce_space(self: @ContractState) -> felt252 {
            self.nonce_space.read(starknet::get_caller_address())
        }
    }

    #[generate_trait]
    impl Private of PrivateTrait {
        fn _revoke_nonce(
            ref self: ContractState, nonce_space: felt252, owner: ContractAddress, nonce: felt252
        ) {
            if self.revoked_nonce.read((owner, nonce_space, nonce)) {
                Err::NONCE_ALREADY_REVOKED(owner, nonce_space, nonce);
            }
            self.revoked_nonce.write((owner, nonce_space, nonce), true);
            self.emit(NonceRevoked { owner, nonce_space, nonce, });
        }
    }
}
