use starknet::ContractAddress;

#[starknet::interface]
pub trait IPwnHub<TState> {
    fn set_tag(ref self: TState, address: ContractAddress, tag: felt252, has_tag: bool);
    fn set_tags(
        ref self: TState, addresses: Array<ContractAddress>, tags: Array<felt252>, has_tag: bool
    );
    fn has_tag(ref self: TState, address: ContractAddress, tag: felt252) -> bool;
}

//! The `PwnHub` module provides a robust tagging system for contracts within the Starknet 
//! ecosystem. This module leverages OpenZeppelin's `Ownable` component to ensure secure 
//! ownership management.
//! 
//! # Features
//! 
//! - **Ownable Component**: Ensures that only the contract owner can perform sensitive 
//!   operations such as setting tags.
//! - **Tag Management**: Provides functionality to set and manage tags for contracts, allowing 
//!   for efficient categorization and identification.
//! - **Batch Tagging**: Supports setting multiple tags for multiple addresses in a single 
//!   operation.
//! 
//! # Components
//! 
//! - `OwnableComponent`: Provides ownership control with the ability to transfer ownership in a 
//!   two-step process.
//! - `Storage`: Defines the storage structure for the module, including a map for storing tags 
//!   and the ownable substorage.
//! - `Event`: Defines events emitted by the contract, including tag updates.
//! - `Err`: Contains error handling functions for invalid input data such as mismatched array 
//!   lengths.
//! 
//! # Constants
//! 
//! This module does not define any constants but relies on secure and efficient internal logic 
//! for its operations.
//! 
//! # Interface
//! 
//! The `IPwnHub` trait provides the interface for interacting with the PwnHub contract, 
//! including functions for setting and checking tags.
//! 
//! This module integrates seamlessly with other components of the Starknet ecosystem, providing 
//! a flexible and secure tagging system.

#[starknet::contract]
pub mod PwnHub {
    use openzeppelin_access::ownable::ownable::OwnableComponent::InternalTrait;
    use openzeppelin_access::ownable::ownable::OwnableComponent;
    use starknet::storage::Map;
    use super::ContractAddress;

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableTwoStepMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;


    #[storage]
    struct Storage {
        tags: Map<(ContractAddress, felt252), bool>,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        TagSet: TagSet,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    pub struct TagSet {
        pub contract: ContractAddress,
        pub tag: felt252,
        pub has_tag: bool,
    }

    mod Err {
        pub fn INVALID_INPUT_DATA(addresses_len: usize, tags_len: usize) {
            panic!(
                "Invalid input data: addresses array length is {}, tags array length is {}",
                addresses_len,
                tags_len
            );
        }
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        self.ownable.initializer(starknet::get_caller_address());
    }

    #[abi(embed_v0)]
    impl PwnHubImpl of super::IPwnHub<ContractState> {
        /// Sets a tag for a specific contract address.
        ///
        /// # Arguments
        ///
        /// - `address`: The address of the contract to be tagged.
        /// - `tag`: The tag to be set.
        /// - `has_tag`: A boolean indicating if the tag should be set or removed.
        ///
        /// # Requirements
        ///
        /// - Only the contract owner can call this function.
        fn set_tag(ref self: ContractState, address: ContractAddress, tag: felt252, has_tag: bool) {
            self.ownable.assert_only_owner();
            self.tags.write((address, tag), has_tag);

            self.emit(TagSet { contract: address, tag, has_tag, });
        }

        /// Sets multiple tags for multiple contract addresses.
        ///
        /// # Arguments
        ///
        /// - `addresses`: An array of contract addresses to be tagged.
        /// - `tags`: An array of tags to be set.
        /// - `has_tag`: A boolean indicating if the tags should be set or removed.
        ///
        /// # Requirements
        ///
        /// - Only the contract owner can call this function.
        /// - The length of `addresses` and `tags` must be equal.
        fn set_tags(
            ref self: ContractState,
            addresses: Array<ContractAddress>,
            tags: Array<felt252>,
            has_tag: bool
        ) {
            self.ownable.assert_only_owner();
            let tags_len = tags.len();

            if addresses.len() != tags_len {
                Err::INVALID_INPUT_DATA(addresses.len(), tags_len);
            }

            let mut i = 0;
            while i < tags_len {
                let contract = *addresses.at(i);
                let tag = *tags.at(i);
                self.set_tag(contract, tag, has_tag);

                self.emit(TagSet { contract, tag, has_tag, });

                i += 1;
            };
        }

        /// Checks if a specific contract address has a given tag.
        ///
        /// # Arguments
        ///
        /// - `address`: The address of the contract to check.
        /// - `tag`: The tag to check for.
        ///
        /// # Returns
        ///
        /// - A boolean indicating whether the contract has the tag.
        fn has_tag(
            ref self: ContractState, address: ContractAddress, tag: felt252
        ) -> bool { // Implementation
            self.tags.read((address, tag))
        }
    }
}
