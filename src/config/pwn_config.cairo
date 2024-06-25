#[starknet::contract]
mod PwnConfig {
    use pwn::config::interface::IPwnConfig;
    use starknet::ContractAddress;

    const VERSION: felt252 = '1.2';
    const MAX_FEE: u16 = 1000; // 10%

    #[storage]
    struct Storage {
        fee: u16,
        fee_collectior: ContractAddress,
        loan_metadata_uri: LegacyMap::<ContractAddress, ByteArray>,
        sf_computer_registry: LegacyMap::<ContractAddress, ContractAddress>,
        pool_adapter_registry: LegacyMap::<ContractAddress, ContractAddress>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        FeeUpdated: FeeUpdated,
        FeeCollectorUpdated: FeeCollectorUpdated,
        LOANMetadataUriUpdated: LOANMetadataUriUpdated,
        DefaultLOANMetadataUriUpdated: DefaultLOANMetadataUriUpdated,
    }

    #[derive(Drop, starknet::Event)]
    struct FeeUpdated {
        old_fee: u16,
        new_fee: u16,
    }

    #[derive(Drop, starknet::Event)]
    struct FeeCollectorUpdated {
        old_fee_collector: ContractAddress,
        new_fee_collector: ContractAddress,
    }

    #[derive(Drop, starknet::Event)]
    struct LOANMetadataUriUpdated {
        loan_contract: ContractAddress,
        new_uri: ByteArray,
    }

    #[derive(Drop, starknet::Event)]
    struct DefaultLOANMetadataUriUpdated {
        new_uri: ByteArray,
    }

    mod Err {
        fn INVALID_COMPUTER_CONTRACT(
            computer: super::ContractAddress, asset: super::ContractAddress
        ) {
            panic!("FingerpringComputer {:?} does not support asset {:?}", computer, asset);
        }
        fn INVALID_FEE_VALUE(fee: u16, limit: u256) {
            panic!("Fee value {:?} is invalid. Must be less than or equal to {:?}", fee, limit);
        }
        fn ZERO_FEE_COLLECTOR() {
            panic!("Fee collector cannot be zero address");
        }
        fn ZERO_LOAN_CONTRACT() {
            panic!("LOAN contract cannot be zero address");
        }
    }

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[abi(embed_v0)]
    impl PwnConfigImpl of IPwnConfig<ContractState> {
        fn initialize(
            ref self: ContractState,
            owner: ContractAddress,
            fee: u16,
            fee_collector: ContractAddress
        ) { // Implementation
        }

        fn set_fee(ref self: ContractState, fee: u16) { // Implementation
        }


        fn set_fee_collector(
            ref self: ContractState, fee_collector: ContractAddress
        ) { // Implementation
        }

        fn set_loan_metadata_uri(
            ref self: ContractState, loan_contract: ContractAddress, metadata_uri: felt252
        ) { // Implementation
        }

        fn set_default_loan_metadata_uri(
            ref self: ContractState, metadata_uri: felt252
        ) { // Implementation
        }


        fn register_state_fingerprint_computer(
            ref self: ContractState, asset: ContractAddress, computer: ContractAddress
        ) { // Implementation
        }

        fn register_pool_adapter(
            ref self: ContractState, pool: ContractAddress, adapter: ContractAddress
        ) { // Implementation
        }

        fn get_state_fingerprint_computer(
            ref self: ContractState, asset: ContractAddress
        ) -> ContractAddress {
            // Implementation
            starknet::contract_address_const::<0>()
        }

        fn get_pool_adapter(self: @ContractState, pool: ContractAddress) -> ContractAddress {
            // Implementation
            starknet::contract_address_const::<0>()
        }

        fn loan_metadata_uri(self: @ContractState, loan_contract: ContractAddress) -> felt252 {
            // Implementation
            0
        }
    }

    #[generate_trait]
    impl Private of PrivateTrait {
        fn _set_fee(fee: u16) { // Implementation
        }

        fn _set_fee_collector(fee_collector: ContractAddress) { // Implementation
        }
    }
}
