//! The `PwnConfig` module provides a comprehensive configuration management system for the Pwn 
//! protocol. This module integrates with OpenZeppelin's `Ownable` 
//! and `Initializable` components to manage ownership and initialization processes securely 
//! and efficiently.
//! 
//! # Features
//! 
//! - **Ownable Component**: Ensures that critical functions can only be executed by the contract 
//!   owner.
//! - **Initializable Component**: Manages the initialization process, ensuring the contract can 
//!   only be initialized once.
//! - **Fee Management**: Allows the contract owner to set and update fees associated with the 
//!   protocol.
//! - **Fee Collector Management**: Allows setting and updating of the fee collector address.
//! - **LOAN Metadata URI Management**: Supports setting and updating metadata URIs for loan 
//!   contracts.
//! - **Registry Management**: Allows registration of state fingerprint computers and pool 
//!   adapters, ensuring they support the specified assets.
//! 
//! # Components
//! 
//! - `OwnableComponent`: Provides ownership control with the ability to transfer ownership in a 
//!   two-step process.
//! - `InitializableComponent`: Manages contract initialization with checks to ensure it occurs 
//!   only once.
//! - `Storage`: Defines the storage structure for the module, including fee, fee collector, 
//!   metadata URIs, and registries.
//! - `Event`: Defines events emitted by the contract, including updates to fees, fee collectors, 
//!   and metadata URIs.
//! - `Err`: Contains error handling functions for invalid operations such as setting an invalid 
//!   fee or zero addresses.
//! 
//! # Constants
//! 
//! - `VERSION`: The current version of the module.
//! - `MAX_FEE`: The maximum allowable fee, set to 10% (1000 basis points).
#[starknet::contract]
pub mod PwnConfig {
    use core::clone::Clone;
    use openzeppelin::access::ownable::ownable::OwnableComponent;
    use openzeppelin::security::initializable::InitializableComponent;
    use openzeppelin::upgrades::{interface::IUpgradeable, upgradeable::UpgradeableComponent};
    use pwn::config::interface::IPwnConfig;
    use pwn::interfaces::{
        pool_adapter::IPoolAdapterDispatcher,
        fingerprint_computer::{
            IStateFingerpringComputerDispatcher, IStateFingerpringComputerDispatcherTrait
        }
    };
    use starknet::ContractAddress;

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: InitializableComponent, storage: initializable, event: InitializableEvent);
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    #[abi(embed_v0)]
    impl OwnableTwoStepImpl = OwnableComponent::OwnableTwoStepImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl InitializableTwoStepImpl =
        InitializableComponent::InitializableImpl<ContractState>;
    impl InitializableInternalImpl = InitializableComponent::InternalImpl<ContractState>;

    impl UpgreadeableInternalImpl = UpgradeableComponent::InternalImpl<ContractState>;
    
    const VERSION: felt252 = '1.2';
    pub const MAX_FEE: u16 = 1000; // 10%

    #[storage]
    struct Storage {
        fee: u16,
        fee_collector: ContractAddress,
        loan_metadata_uri: LegacyMap::<ContractAddress, ByteArray>,
        sf_computer_registry: LegacyMap::<ContractAddress, ContractAddress>,
        pool_adapter_registry: LegacyMap::<ContractAddress, ContractAddress>,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        initializable: InitializableComponent::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        FeeUpdated: FeeUpdated,
        FeeCollectorUpdated: FeeCollectorUpdated,
        LOANMetadataUriUpdated: LOANMetadataUriUpdated,
        DefaultLOANMetadataUriUpdated: DefaultLOANMetadataUriUpdated,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        InitializableEvent: InitializableComponent::Event,
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    pub struct FeeUpdated {
        pub old_fee: u16,
        pub new_fee: u16,
    }

    #[derive(Drop, starknet::Event)]
    pub struct FeeCollectorUpdated {
        pub old_fee_collector: ContractAddress,
        pub new_fee_collector: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LOANMetadataUriUpdated {
        pub loan_contract: ContractAddress,
        pub new_uri: ByteArray,
    }

    #[derive(Drop, starknet::Event)]
    pub struct DefaultLOANMetadataUriUpdated {
        pub new_uri: ByteArray,
    }

    mod Err {
        pub fn INVALID_COMPUTER_CONTRACT(
            computer: super::ContractAddress, asset: super::ContractAddress
        ) {
            panic!("FingerpringComputer {:?} does not support asset {:?}", computer, asset);
        }
        pub fn INVALID_FEE_VALUE(fee: u16, limit: u16) {
            panic!("Fee value {:?} is invalid. Must be less than or equal to {:?}", fee, limit);
        }
        pub fn ZERO_FEE_COLLECTOR() {
            panic!("Fee collector cannot be zero address");
        }
        pub fn ZERO_LOAN_CONTRACT() {
            panic!("LOAN contract cannot be zero address");
        }
    }

    #[abi(embed_v0)]
    impl PwnConfigImpl of IPwnConfig<ContractState> {
        /// Initializes the PwnConfig contract with the provided owner, fee, and fee collector address.
        ///
        /// # Arguments
        ///
        /// - `owner`: The address of the contract owner.
        /// - `fee`: The initial fee to be set.
        /// - `fee_collector`: The address where the fees will be collected.
        ///
        /// # Requirements
        ///
        /// - `owner` must not be the zero address.
        ///
        /// # Actions
        ///
        /// - Initializes the `OwnableComponent` with the provided owner address.
        /// - Sets the fee collector address using `_set_fee_collector`.
        /// - Sets the fee using `_set_fee`.
        /// - Initializes the `InitializableComponent`.
        fn initialize(
            ref self: ContractState,
            owner: ContractAddress,
            fee: u16,
            fee_collector: ContractAddress
        ) {
            assert!(
                owner != starknet::contract_address_const::<0>(), "Owner cannot be zero address"
            );
            self.ownable.initializer(owner);
            self._set_fee_collector(fee_collector);
            self._set_fee(fee);
            self.initializable.initialize();
        }

        fn get_max_fee(self: @ContractState) -> u16 {
            MAX_FEE
        }

        /// Sets the fee for the PwnConfig contract.
        ///
        /// # Arguments
        ///
        /// - `fee`: The new fee to be set.
        ///
        /// # Requirements
        ///
        /// - Only the contract owner can call this function.
        fn set_fee(ref self: ContractState, fee: u16) {
            self.ownable.assert_only_owner();
            self._set_fee(fee);
        }

        /// Retrieves the current fee of the PwnConfig contract.
        ///
        /// # Returns
        ///
        /// - The current fee as a `u16`.
        fn get_fee(self: @ContractState) -> u16 {
            self.fee.read()
        }

        /// Sets the fee collector address for the PwnConfig contract.
        ///
        /// # Arguments
        ///
        /// - `fee_collector`: The new fee collector address.
        ///
        /// # Requirements
        ///
        /// - Only the contract owner can call this function.
        fn set_fee_collector(ref self: ContractState, fee_collector: ContractAddress) {
            self.ownable.assert_only_owner();
            self._set_fee_collector(fee_collector);
        }

        /// Retrieves the current fee collector address of the PwnConfig contract.
        ///
        /// # Returns
        ///
        /// - The current fee collector address as a `ContractAddress`.
        fn get_fee_collector(self: @ContractState) -> ContractAddress {
            self.fee_collector.read()
        }

        /// Sets the metadata URI for a specific loan contract.
        ///
        /// # Arguments
        ///
        /// - `loan_contract`: The address of the loan contract.
        /// - `metadata_uri`: The metadata URI to be set.
        ///
        /// # Requirements
        ///
        /// - Only the contract owner can call this function.
        /// - `loan_contract` must not be the zero address.
        fn set_loan_metadata_uri(
            ref self: ContractState, loan_contract: ContractAddress, metadata_uri: ByteArray
        ) {
            self.ownable.assert_only_owner();
            let metadata_copy = metadata_uri.clone();
            if loan_contract == starknet::contract_address_const::<0>() {
                Err::ZERO_LOAN_CONTRACT();
            }

            self.loan_metadata_uri.write(loan_contract, metadata_uri);

            self.emit(LOANMetadataUriUpdated { loan_contract, new_uri: metadata_copy });
        }

        /// Sets the default metadata URI for loan contracts.
        ///
        /// # Arguments
        ///
        /// - `metadata_uri`: The default metadata URI to be set.
        ///
        /// # Requirements
        ///
        /// - Only the contract owner can call this function.
        fn set_default_loan_metadata_uri(ref self: ContractState, metadata_uri: ByteArray) {
            self.ownable.assert_only_owner();
            let metadata_copy = metadata_uri.clone();
            self.loan_metadata_uri.write(starknet::contract_address_const::<0>(), metadata_uri);

            self.emit(DefaultLOANMetadataUriUpdated { new_uri: metadata_copy });
        }

        /// Registers a state fingerprint computer for a specific asset.
        ///
        /// # Arguments
        ///
        /// - `asset`: The address of the asset.
        /// - `computer`: The address of the state fingerprint computer.
        ///
        /// # Requirements
        ///
        /// - Only the contract owner can call this function.
        /// - If `computer` is not the zero address, it must support the specified asset.
        fn register_state_fingerprint_computer(
            ref self: ContractState, asset: ContractAddress, computer: ContractAddress
        ) {
            self.ownable.assert_only_owner();
            if computer != starknet::contract_address_const::<0>() {
                let computer_dispatcher = IStateFingerpringComputerDispatcher {
                    contract_address: computer
                };
                if !computer_dispatcher.supports_token(asset) {
                    Err::INVALID_COMPUTER_CONTRACT(computer, asset);
                }
            }

            self.sf_computer_registry.write(asset, computer);
        }

        /// Registers a pool adapter for a specific pool.
        ///
        /// # Arguments
        ///
        /// - `pool`: The address of the pool.
        /// - `adapter`: The address of the pool adapter.
        ///
        /// # Requirements
        ///
        /// - Only the contract owner can call this function.
        fn register_pool_adapter(
            ref self: ContractState, pool: ContractAddress, adapter: ContractAddress
        ) {
            self.ownable.assert_only_owner();
            self.pool_adapter_registry.write(pool, adapter);
        }

        /// Retrieves the state fingerprint computer for a specific asset.
        ///
        /// # Arguments
        ///
        /// - `asset`: The address of the asset.
        ///
        /// # Returns
        ///
        /// - The `IStateFingerpringComputerDispatcher` for the asset.
        fn get_state_fingerprint_computer(
            self: @ContractState, asset: ContractAddress
        ) -> IStateFingerpringComputerDispatcher {
            let computer = self.sf_computer_registry.read(asset);

            IStateFingerpringComputerDispatcher { contract_address: computer }
        }

        /// Retrieves the pool adapter for a specific pool.
        ///
        /// # Arguments
        ///
        /// - `pool`: The address of the pool.
        ///
        /// # Returns
        ///
        /// - The `IPoolAdapterDispatcher` for the pool.
        fn get_pool_adapter(self: @ContractState, pool: ContractAddress) -> IPoolAdapterDispatcher {
            let pool_adapter = self.pool_adapter_registry.read(pool);

            IPoolAdapterDispatcher { contract_address: pool_adapter }
        }

        /// Retrieves the metadata URI for a specific loan contract.
        ///
        /// # Arguments
        ///
        /// - `loan_contract`: The address of the loan contract.
        ///
        /// # Returns
        ///
        /// - The metadata URI as a `ByteArray`.
        fn loan_metadata_uri(self: @ContractState, loan_contract: ContractAddress) -> ByteArray {
            let uri = self.loan_metadata_uri.read(loan_contract);

            if uri.len() == 0 {
                return self.loan_metadata_uri.read(starknet::contract_address_const::<0>());
            }

            uri
        }
    }


    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState>{
        /// Replaces the contract's class hash with `new_class_hash`.
        ///
        /// # Arguments
        ///
        /// - `new_class_hash`: class_hash of the new implementation.
        ///
        /// # Requirements
        ///
        /// - `new_class_hash` is not zero.
        /// - Only the contract owner can call this function.
        fn upgrade(ref self: ContractState, new_class_hash: starknet::ClassHash) {
            self.ownable.assert_only_owner();
            self.upgradeable.upgrade(new_class_hash);
        }
    }

    #[generate_trait]
    impl Private of PrivateTrait {
        fn _set_fee(ref self: ContractState, fee: u16) {
            if (fee > MAX_FEE) {
                Err::INVALID_FEE_VALUE(fee, MAX_FEE);
            }

            let old_fee = self.fee.read();
            self.fee.write(fee);

            self.emit(FeeUpdated { old_fee, new_fee: fee });
        }

        fn _set_fee_collector(ref self: ContractState, fee_collector: ContractAddress) {
            if fee_collector == starknet::contract_address_const::<0>() {
                Err::ZERO_FEE_COLLECTOR();
            }

            let old_fee_collector = self.fee_collector.read();
            self.fee_collector.write(fee_collector);

            self.emit(FeeCollectorUpdated { old_fee_collector, new_fee_collector: fee_collector });
        }
    }
}
