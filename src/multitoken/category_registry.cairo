use starknet::ContractAddress;

#[starknet::interface]
pub trait IMultiTokenCategoryRegistry<TState> {
    fn register_category_value(ref self: TState, asset_address: ContractAddress, category: u8);
    fn unregister_category_value(ref self: TState, asset_address: ContractAddress);
    fn registered_category_value(self: @TState, asset_address: ContractAddress) -> u8;
}

//! The `MultiTokenCategoryRegistry` module provides a mechanism for managing and categorizing
//! multi-token assets . This module allows the registration and 
//! unregistration of category values for specific asset addresses, facilitating the organization 
//! and classification of assets.
//!
//! # Features
//! 
//! - **Category Registration**: Allows the owner of the contract to register category values for 
//!   specific asset addresses, enabling structured categorization of assets.
//! - **Category Unregistration**: Provides functionality for unregistering category values,
//!   allowing for dynamic reclassification of assets as needed.
//! - **Category Query**: Supports querying the registered category value for a given asset 
//!   address, with special handling for unregistered categories.
//! 
//! # Components
//! 
//! - `OwnableComponent`: Ensures that only the owner can modify category registrations, providing 
//!   access control for critical operations.
//! - `SRC5Component`: Integrates with the SRC5 interface standard for introspection capabilities.
//! - `Err`: Contains error handling functions for invalid operations, such as attempting to use 
//!   reserved category values.
//! 
//! # Constants
//! 
//! - `CATEGORY_NOT_REGISTERED`: A constant representing the value used to denote that an asset 
//!   does not have a registered category.
//! 
//! This module is designed to provide a flexible and secure system for managing multi-token 
//! asset categories, with robust access control and event-driven architecture to support 
//! integrations and monitoring .

#[starknet::contract]
pub mod MultiTokenCategoryRegistry {
    use openzeppelin::access::ownable::OwnableComponent;
    use openzeppelin::access::ownable::ownable::OwnableComponent::InternalTrait;
    use openzeppelin::introspection::src5::SRC5Component;
    use starknet::{ContractAddress, get_caller_address};

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);

    #[abi(embed_v0)]
    impl OwnableMixinImpl = OwnableComponent::OwnableMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        registered_category: Map::<ContractAddress, u8>,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        CategoryRegistered: CategoryRegistered,
        CategoryUnregistered: CategoryUnregistered,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
    }

    #[derive(Drop, starknet::Event)]
    pub struct CategoryRegistered {
        #[key]
        pub asset_address: ContractAddress,
        #[key]
        pub category: u8,
    }

    #[derive(Drop, starknet::Event)]
    pub struct CategoryUnregistered {
        #[key]
        pub asset_address: ContractAddress,
    }

    pub mod Err {
        pub fn RESERVED_CATEGORY_VALUE() {
            panic!("Cannot use reserved category value");
        }
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
        self.ownable.initializer(starknet::get_caller_address());
    }

    pub const CATEGORY_NOT_REGISTERED: u8 = 255;

    #[abi(embed_v0)]
    impl IMultiTokenCategoryRegistry of super::IMultiTokenCategoryRegistry<ContractState> {
        /// Registers a category value for a given asset address. Only the contract owner
        /// is authorized to call this function. It ensures that the category value is not
        /// set to a reserved value (e.g., `CATEGORY_NOT_REGISTERED`).
        ///
        /// # Arguments
        ///
        /// * `asset_address` - The address of the asset to register.
        /// * `category` - The category value to assign to the asset.
        ///
        /// # Panics
        ///
        /// Panics if the caller is not the contract owner or if the `category` is set
        /// to the reserved value `CATEGORY_NOT_REGISTERED`.
        fn register_category_value(
            ref self: ContractState, asset_address: ContractAddress, category: u8
        ) {
            self.ownable.assert_only_owner();

            if category == CATEGORY_NOT_REGISTERED {
                Err::RESERVED_CATEGORY_VALUE();
            }

            self.registered_category.write(asset_address, category + 1);

            self.emit(CategoryRegistered { asset_address, category, });
        }

        /// Unregisters the category value for a given asset address, effectively
        /// resetting it to an unregistered state. This function is restricted to
        /// the contract owner.
        ///
        /// # Arguments
        ///
        /// * `asset_address` - The address of the asset to unregister.
        fn unregister_category_value(ref self: ContractState, asset_address: ContractAddress) {
            self.ownable.assert_only_owner();

            self.registered_category.write(asset_address, 0);

            self.emit(CategoryUnregistered { asset_address, });
        }

        /// Retrieves the registered category value for a given asset address.
        /// If the asset does not have a registered category, the function returns
        /// `CATEGORY_NOT_REGISTERED`.
        ///
        /// # Arguments
        ///
        /// * `asset_address` - The address of the asset to query.
        ///
        /// # Returns
        ///
        /// The category value associated with the asset, or `CATEGORY_NOT_REGISTERED`
        /// if no category is registered.
        fn registered_category_value(self: @ContractState, asset_address: ContractAddress) -> u8 {
            let category: u8 = self.registered_category.read(asset_address);

            if category == 0 {
                return CATEGORY_NOT_REGISTERED;
            }

            category - 1
        }
    }
}
// NOTE: ERC165 supportsInterface is not implemented in this contract


