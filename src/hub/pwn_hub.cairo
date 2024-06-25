#[starknet::contract]
mod PwnHub {
    use pwn::hub::interface::IPwnHub;
    use starknet::ContractAddress;

    #[storage]
    struct Storage {
        // NOTE: This is temporarely set to felt252 instead of ByteArray since ByteArray
        // is not supported as storage key, MUST EXPLORE ALT SOLUTIONS.
        tags: LegacyMap::<(ContractAddress, felt252), bool>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        TagSet: TagSet,
    }

    #[derive(Drop, starknet::Event)]
    struct TagSet {
        contract: ContractAddress,
        tag: ByteArray,
        has_tag: bool,
    }

    #[abi(embed_v0)]
    impl PwnHubImpl of IPwnHub<ContractState> {
        fn set_tag(
            ref self: ContractState, address: ContractAddress, tag: felt252, hash_tag: bool
        ) { // Implementation
        }

        fn set_tags(
            ref self: ContractState,
            addresses: Array<ContractAddress>,
            tags: Array<felt252>,
            hash_tag: bool
        ) { // Implementation
        }

        fn has_tag(
            ref self: ContractState, address: ContractAddress, tag: felt252
        ) -> bool { // Implementation
            true
        }
    }
}
