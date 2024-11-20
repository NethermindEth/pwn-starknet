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
    fn hub(self: @TState) -> ContractAddress;
    fn access_tag(self: @TState) -> felt252;
}

//! The `RevokedNonce` module provides functionality for managing and verifying revoked nonces 
//! . It plays a crucial role in maintaining the integrity and 
//! security of blockchain interactions by preventing the reuse of nonces. This module integrates 
//! with the `pwn_hub` system for access control and tagging, enabling fine-grained permission 
//! management.
//!
//! # Key Features
//! 
//! - **Nonce Revocation**: Allows revoking specific nonces or entire nonce spaces for an owner, 
//!   preventing their reuse and ensuring secure transaction handling.
//! - **Nonce Verification**: Provides mechanisms to check if a nonce is revoked or usable, 
//!   ensuring that transactions cannot be replayed.
//! - **Access Control**: Utilizes the `pwn_hub` system for managing permissions, ensuring that 
//!   only authorized addresses can perform specific actions related to nonce management.
//!
//! # Components
//! 
//! - **Storage**: Defines the storage structure for managing revoked nonces and nonce spaces, 
//!   including maps for revoked nonces and nonce spaces.
//! - **Events**: Includes events such as `NonceRevoked` and `NonceSpaceRevoked` for tracking 
//!   nonce management actions and changes in nonce spaces.
//! - **Errors**: Provides error handling for common issues, such as already revoked nonces and 
//!   unauthorized actions, helping to prevent misuse and errors in nonce management.
//!
//! This module is part of a broader system for managing nonces and access control in the Starknet 
//! environment. It provides essential security features for decentralized applications, ensuring 
//! that nonces are used securely and cannot be reused in unauthorized transactions.
//!
//! # Constants
//! 
//! - **CATEGORY_NOT_REGISTERED**: A constant used to denote a non-registered category in the 
//!   category registry.
//!
//! The `RevokedNonce` module is critical for ensuring secure and reliable transaction processing 
//! in decentralized applications built on Starknet, providing robust nonce management and 
//! verification capabilities.

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
        /// This function ensures that the nonce cannot be reused in future transactions, providing 
        /// protection against replay attacks.
        /// 
        /// # Parameters
        /// 
        /// - `owner`: The address of the owner for whom the nonce should be revoked. If `None`, the caller 
        ///   is used as the owner.
        /// - `nonce_space`: The specific nonce space in which the nonce should be revoked. If `None`, the 
        ///   current nonce space of the owner or caller is used.
        /// - `nonce`: The specific nonce to be revoked.
        /// 
        /// # Behavior
        /// 
        /// - If the `owner` is specified, the function will check if the caller has the necessary 
        ///   `access_tag` to revoke the nonce for the specified owner. If the caller lacks the required 
        ///   access, the function will trigger an error.
        /// - If the `nonce_space` is not specified, the function will use the current nonce space of the 
        ///   owner or caller to revoke the nonce.
        /// - The function checks if the nonce is already revoked, and if so, triggers an error to prevent 
        ///   double revocation.
        /// 
        /// This function emits a `NonceRevoked` event upon successful revocation of the nonce.
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

        /// Revokes a list of nonces for the caller in the current nonce space.
        /// This function iterates through the provided array of nonces and revokes each one, ensuring
        /// they cannot be reused in future transactions.
        ///
        /// # Parameters
        ///
        /// - `nonces`: An array of nonces to be revoked.
        ///
        /// # Behavior
        ///
        /// - The function retrieves the current nonce space for the caller and revokes each nonce
        ///   provided in the array. If a nonce is already revoked, it will trigger an error.
        /// 
        /// This function is useful for revoking multiple nonces in a single transaction.
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

        /// Revokes the current nonce space for the caller and increments it by one.
        /// This function is used to invalidate all nonces in the current nonce space, effectively
        /// resetting the nonce usage for the caller.
        ///
        /// # Returns
        ///
        /// - The new nonce space value.
        ///
        /// # Behavior
        ///
        /// - The function emits a `NonceSpaceRevoked` event, indicating the revocation of the nonce space.
        /// - It then increments the nonce space by one and returns the new value.
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

        /// Checks if a specific nonce has been revoked for a given owner and nonce space.
        /// This function returns a boolean indicating whether the specified nonce is revoked.
        ///
        /// # Parameters
        ///
        /// - `owner`: The address of the owner.
        /// - `nonce_space`: The nonce space of the owner.
        /// - `nonce`: The specific nonce to check.
        ///
        /// # Returns
        ///
        /// - `true` if the nonce is revoked, otherwise `false`.
        ///
        /// This function is useful for verifying the status of a nonce before attempting to use it.
        fn is_nonce_revoked(
            self: @ContractState, owner: ContractAddress, nonce_space: felt252, nonce: felt252
        ) -> bool {
            self.revoked_nonce.read((owner, nonce_space, nonce))
        }

        /// Checks if a specific nonce is usable for a given owner and nonce space.
        /// This function returns a boolean indicating whether the nonce can be used.
        ///
        /// # Parameters
        ///
        /// - `owner`: The address of the owner.
        /// - `nonce_space`: The nonce space of the owner.
        /// - `nonce`: The specific nonce to check.
        ///
        /// # Returns
        ///
        /// - `true` if the nonce is usable, otherwise `false`.
        ///
        /// This function considers a nonce usable if it is not revoked and if the nonce space matches
        /// the current nonce space for the owner.
        fn is_nonce_usable(
            self: @ContractState, owner: ContractAddress, nonce_space: felt252, nonce: felt252
        ) -> bool {
            if self.nonce_space.read(owner) != nonce_space {
                return false;
            }

            !self.revoked_nonce.read((owner, nonce_space, nonce))
        }

        /// Retrieves the current nonce space for a specified owner.
        /// This function returns the nonce space associated with the owner, which is used to manage
        /// nonces for replay protection.
        ///
        /// # Parameters
        ///
        /// - `owner`: The address of the owner.
        ///
        /// # Returns
        ///
        /// - The current nonce space of the owner.
        fn current_nonce_space(self: @ContractState, owner: ContractAddress) -> felt252 {
            self.nonce_space.read(owner)
        }

        fn hub(self: @ContractState) -> ContractAddress {
            self.hub.read().contract_address
        }

        fn access_tag(self: @ContractState) -> felt252 {
            self.access_tag.read()
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
