use starknet::ContractAddress;

#[starknet::interface]
pub trait IRevokedNonce<TState> {
    fn revoke_nonce(
        ref self: TState,
        owner: Option<ContractAddress>,
        nonce_space: Option<felt252>,
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
    fn current_nonce_space(self: @TState, owner: ContractAddress) -> felt252;
}

#[starknet::contract]
pub mod RevokedNonce {
    use pwn::hub::pwn_hub::{IPwnHubDispatcher, IPwnHubDispatcherTrait};
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
    pub enum Event {
        NonceRevoked: NonceRevoked,
        NonceSpaceRevoked: NonceSpaceRevoked,
    }

    #[derive(Drop, starknet::Event)]
    pub struct NonceRevoked {
        pub owner: ContractAddress,
        pub nonce_space: felt252,
        pub nonce: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct NonceSpaceRevoked {
        pub owner: ContractAddress,
        pub nonce_space: felt252,
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
        pub fn ADDRESS_MISSING_TAG(addr: super::ContractAddress, access_tag: felt252) {
            panic!("Address missing tag. Address: {:?}, Tag: {}", addr, access_tag);
        }
    }

    #[constructor]
    fn constructor(ref self: ContractState, hub: ContractAddress, access_tag: felt252) {
        self.hub.write(IPwnHubDispatcher { contract_address: hub });
        self.access_tag.write(access_tag);
    }

    #[abi(embed_v0)]
    impl RevokedNonceImpl of IRevokedNonce<ContractState> {
        fn revoke_nonce(
            ref self: ContractState,
            owner: Option<ContractAddress>,
            nonce_space: Option<felt252>,
            nonce: felt252
        ) {
            let caller = starknet::get_caller_address();

            match nonce_space {
                Option::Some(nonce_space) => {
                    match owner {
                        Option::Some(owner) => {
                            let access_tag = self.access_tag.read();
                            if !self.hub.read().has_tag(caller, access_tag) {
                                Err::ADDRESS_MISSING_TAG(caller, access_tag);
                            }
                            self._revoke_nonce(owner, nonce_space, nonce);
                        },
                        Option::None => { self._revoke_nonce(caller, nonce_space, nonce); },
                    }
                },
                Option::None => {
                    match owner {
                        Option::Some(owner) => {
                            let nonce_space = self.nonce_space.read(owner);

                            let access_tag = self.access_tag.read();
                            if !self.hub.read().has_tag(caller, access_tag) {
                                Err::ADDRESS_MISSING_TAG(caller, access_tag);
                            }
                            self._revoke_nonce(owner, nonce_space, nonce);
                        },
                        Option::None => {
                            let nonce_space = self.nonce_space.read(caller);
                            self._revoke_nonce(caller, nonce_space, nonce);
                        },
                    }
                },
            }
        }

        fn revoke_nonces(ref self: ContractState, nonces: Array<felt252>) {
            let caller = starknet::get_caller_address();
            let nonce_space = self.nonce_space.read(caller);

            let len = nonces.len();
            let mut i = 0;
            while i < len {
                self._revoke_nonce(caller, nonce_space, *nonces.at(i));
                i += 1;
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

        fn current_nonce_space(self: @ContractState, owner: ContractAddress) -> felt252 {
            self.nonce_space.read(owner)
        }
    }

    #[generate_trait]
    impl Private of PrivateTrait {
        fn _revoke_nonce(
            ref self: ContractState, owner: ContractAddress, nonce_space: felt252, nonce: felt252
        ) {
            if self.revoked_nonce.read((owner, nonce_space, nonce)) {
                Err::NONCE_ALREADY_REVOKED(owner, nonce_space, nonce);
            }
            self.revoked_nonce.write((owner, nonce_space, nonce), true);
            self.emit(NonceRevoked { owner, nonce_space, nonce, });
        }
    }
}
