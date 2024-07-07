#[starknet::contract]
pub mod PwnConfig {
    use core::clone::Clone;
    use openzeppelin::access::ownable::ownable::OwnableComponent;
    use openzeppelin::security::initializable::InitializableComponent;
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

    #[abi(embed_v0)]
    impl OwnableTwoStepImpl = OwnableComponent::OwnableTwoStepImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl InitializableTwoStepImpl =
        InitializableComponent::InitializableImpl<ContractState>;
    impl InitializableInternalImpl = InitializableComponent::InternalImpl<ContractState>;

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

        fn set_fee(ref self: ContractState, fee: u16) {
            self.ownable.assert_only_owner();
            self._set_fee(fee);
        }

        fn get_fee(self: @ContractState) -> u16 {
            self.fee.read()
        }


        fn set_fee_collector(ref self: ContractState, fee_collector: ContractAddress) {
            self.ownable.assert_only_owner();
            self._set_fee_collector(fee_collector);
        }

        fn get_fee_collector(self: @ContractState) -> ContractAddress {
            self.fee_collectior.read()
        }

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

        fn set_default_loan_metadata_uri(ref self: ContractState, metadata_uri: ByteArray) {
            self.ownable.assert_only_owner();
            let metadata_copy = metadata_uri.clone();
            self.loan_metadata_uri.write(starknet::contract_address_const::<0>(), metadata_uri);

            self.emit(DefaultLOANMetadataUriUpdated { new_uri: metadata_copy });
        }


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

        fn register_pool_adapter(
            ref self: ContractState, pool: ContractAddress, adapter: ContractAddress
        ) {
            self.ownable.assert_only_owner();
            self.pool_adapter_registry.write(pool, adapter);
        }

        fn get_state_fingerprint_computer(
            ref self: ContractState, asset: ContractAddress
        ) -> IStateFingerpringComputerDispatcher {
            let computer = self.sf_computer_registry.read(asset);

            IStateFingerpringComputerDispatcher { contract_address: computer }
        }

        fn get_pool_adapter(self: @ContractState, pool: ContractAddress) -> IPoolAdapterDispatcher {
            let pool_adapter = self.pool_adapter_registry.read(pool);

            IPoolAdapterDispatcher { contract_address: pool_adapter }
        }

        fn loan_metadata_uri(self: @ContractState, loan_contract: ContractAddress) -> ByteArray {
            let uri = self.loan_metadata_uri.read(loan_contract);

            if uri.len() == 0 {
                return self.loan_metadata_uri.read(starknet::contract_address_const::<0>());
            }

            uri
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
