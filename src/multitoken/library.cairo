pub mod MultiToken {
    use core::integer::BoundedInt;
    use core::option::OptionTrait;
    use pwn::ContractAddressDefault;
    use starknet::ContractAddress;


    #[derive(Copy, Default, Drop, Serde, starknet::Store)]
    pub enum Category {
        #[default]
        ERC20,
        ERC721,
        ERC1155,
    }

    #[derive(Default, Drop, Serde, starknet::Store)]
    pub struct Asset {
        pub category: Category,
        pub asset_address: ContractAddress,
        pub id: felt252,
        pub amount: u256
    }

    pub mod Err {
        fn UNSUPPORTED_CATEGORY(category_value: u8) {
            panic!("Unsupported category value: {}", category_value);
        }
    }

    pub fn ERC20(asset_address: ContractAddress, amount: u256) -> Asset {
        Asset { category: Category::ERC20, asset_address, id: 0.try_into().unwrap(), amount }
    }

    pub fn ERC721(asset_address: ContractAddress, id: felt252) -> Asset {
        Asset { category: Category::ERC721, asset_address, id, amount: 1.try_into().unwrap() }
    }

    pub fn ERC1155(asset_address: ContractAddress, id: felt252, amount: Option<u256>) -> Asset {
        match amount {
            Option::Some(amount) => Asset {
                category: Category::ERC1155, asset_address, id, amount
            },
            Option::None => Asset { category: Category::ERC1155, asset_address, id, amount: 0 }
        }
    }

    // NOTE: here we don't need interal func since we don't have safe transfer on starknet
    // use pattern matching as above to handle different category
    pub fn transfer_asset_from(
        asset: Asset, source: ContractAddress, dest: ContractAddress, is_safe: bool
    ) {}

    pub fn get_transfer_amount(asset: Asset) {}

    //  NOTE: tranferFromCallData not needed

    pub fn permit(
        asset: Asset,
        owner: ContractAddress,
        spender: ContractAddress,
        amount: u256,
        permit_data: felt252
    ) {}

    pub fn balance_of(asset: Asset, target: ContractAddress) -> u256 {
        0
    }

    pub fn approve_asset(asset: Asset, target: ContractAddress) {}

    // NOTE: we dont't check interface id since no token uses it on Starket

    pub fn check_format(asset: Asset) -> bool {
        true
    }

    pub fn is_same_as(asset: Asset, other: Asset) -> bool {
        true
    }
}
