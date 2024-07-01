use starknet::ContractAddress;

#[starknet::interface]
pub trait IPwnHub<TState> {
    fn set_tag(ref self: TState, address: ContractAddress, tag: felt252, has_tag: bool);
    fn set_tags(
        ref self: TState, addresses: Array<ContractAddress>, tags: Array<felt252>, has_tag: bool
    );
    fn has_tag(ref self: TState, address: ContractAddress, tag: felt252) -> bool;
}


#[starknet::contract]
pub mod PwnHub {
    use openzeppelin::access::ownable::ownable::OwnableComponent::InternalTrait;
    use openzeppelin::access::ownable::ownable::OwnableComponent;
    use super::ContractAddress;

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableTwoStepMixinImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;


    #[storage]
    struct Storage {
        tags: LegacyMap::<(ContractAddress, felt252), bool>,
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
        fn set_tag(ref self: ContractState, address: ContractAddress, tag: felt252, has_tag: bool) {
            self.ownable.assert_only_owner();
            self.tags.write((address, tag), has_tag);

            self.emit(TagSet { contract: address, tag, has_tag, });
        }

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

        fn has_tag(
            ref self: ContractState, address: ContractAddress, tag: felt252
        ) -> bool { // Implementation
            self.tags.read((address, tag))
        }
    }
}
