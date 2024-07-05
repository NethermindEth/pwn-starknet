pub mod MultiToken {
    use core::integer::BoundedInt;
    use core::option::OptionTrait;
    use core::traits::Into;
    use openzeppelin::token::erc1155::interface::{ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait};
    use openzeppelin::token::erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};
    use openzeppelin::token::erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait};
    use pwn::ContractAddressDefault;
    use pwn::multitoken::category_registry::{
        IMultitokenCategoryRegistryDispatcher, IMultitokenCategoryRegistryDispatcherTrait
    };
    use starknet::ContractAddress;
    use super::{CategoryIntoU8, CategoryEq};

    // NOTE: tokens standard interface id are pretty inconsistent on Starknet at the moment due to frequent updates
    // the interface_id below are based on the full OpenZeppelin interfaces (named as ABI)
    const ERC20_INTERFACE_ID: felt252 =
        0x3d21dcd478803698af065a01681e1f1801a5b80c367ecb5561fbf10b416756e;
    const ERC721_INTERFACE_ID: felt252 =
        0x2c8b9553a387f54d6021766166528967ac9bb9393acf1c47678b9eea63dda07;
    const ERC1155_INTERFACE_ID: felt252 =
        0xcd38fd6bb8f64dd3988ff3ae65d0cd040c95aaad81b509a1f4f0b3e40adf88;

    const CATEGORY_NOT_REGISTERED: u8 = 255;

    #[derive(Copy, Debug, Default, Drop, Serde, starknet::Store)]
    pub enum Category {
        #[default]
        ERC20,
        ERC721,
        ERC1155,
    }

    #[derive(Copy, Default, Drop, Serde, starknet::Store)]
    pub struct Asset {
        pub category: Category,
        pub asset_address: ContractAddress,
        pub id: felt252,
        pub amount: u256
    }

    pub mod Err {
        pub fn UNSUPPORTED_CATEGORY(category_value: super::Category) {
            panic!("Unsupported category");
        }
    }

    pub fn ERC20(asset_address: ContractAddress, amount: u256) -> Asset {
        Asset { category: Category::ERC20, asset_address, id: 0.try_into().unwrap(), amount }
    }

    pub fn ERC721(asset_address: ContractAddress, id: felt252) -> Asset {
        Asset { category: Category::ERC721, asset_address, id, amount: 0.try_into().unwrap() }
    }

    pub fn ERC1155(asset_address: ContractAddress, id: felt252, amount: Option<u256>) -> Asset {
        match amount {
            Option::Some(amount) => Asset {
                category: Category::ERC1155, asset_address, id, amount
            },
            Option::None => Asset { category: Category::ERC1155, asset_address, id, amount: 0 }
        }
    }

    #[generate_trait]
    pub impl AssetImpl of AssetTrait {
        // NOTE: here we don't need interal func since we don't have safe transfer on starknet
        // use pattern matching as above to handle different category
        fn transfer_asset_from(
            self: @Asset, source: ContractAddress, dest: ContractAddress, is_safe: bool
        ) {
            _transfer_asset_from(*self, source, dest, is_safe);
        }

        fn get_transfer_amount(asset: @Asset) {}

        //  NOTE: tranferFromCallData not needed

        // NOTE: permit standard not available on starknet

        fn balance_of(self: @Asset, target: ContractAddress) -> u256 {
            match self.category {
                Category::ERC20 => {
                    ERC20ABIDispatcher { contract_address: *self.asset_address }.balanceOf(target)
                },
                Category::ERC721 => {
                    ERC721ABIDispatcher { contract_address: *self.asset_address }.balanceOf(target)
                },
                Category::ERC1155 => {
                    ERC1155ABIDispatcher { contract_address: *self.asset_address }
                        .balanceOf(target, (*self.id).into())
                }
            }
        }

        fn approve_asset(self: @Asset, target: ContractAddress) {
            match self.category {
                Category::ERC20 => {
                    ERC20ABIDispatcher { contract_address: *self.asset_address }
                        .approve(target, *self.amount);
                },
                Category::ERC721 => {
                    ERC721ABIDispatcher { contract_address: *self.asset_address }
                        .approve(target, (*self.id).into())
                },
                Category::ERC1155 => {
                    ERC1155ABIDispatcher { contract_address: *self.asset_address }
                        .setApprovalForAll(target, true)
                }
            }
        }

        // NOTE: we dont't check interface id since no token uses it on Starket
        fn is_valid(self: @Asset, registry: Option<ContractAddress>) -> bool {
            match registry {
                Option::Some(registry) => _check_category(*self, registry) && _check_format(*self),
                Option::None => _check_category_via_rsc5(*self) && _check_format(*self)
            }
        }

        fn is_same_as(self: @Asset, other: Asset) -> bool {
            *self.category == other.category
                && *self.asset_address == other.asset_address
                && *self.id == other.id
        }
    }

    fn _transfer_asset_from(
        asset: Asset, source: ContractAddress, dest: ContractAddress, is_safe: bool
    ) {
        let this_address = starknet::get_contract_address();

        match asset.category {
            Category::ERC20 => {
                if source == this_address {
                    ERC20ABIDispatcher { contract_address: asset.asset_address }
                        .transferFrom(asset.asset_address, dest, asset.amount);
                } else {
                    ERC20ABIDispatcher { contract_address: asset.asset_address }
                        .transferFrom(source, dest, asset.amount);
                }
            },
            Category::ERC721 => {
                if !is_safe {
                    ERC721ABIDispatcher { contract_address: asset.asset_address }
                        .transferFrom(source, dest, asset.id.into());
                } else {
                    ERC721ABIDispatcher { contract_address: asset.asset_address }
                        .safeTransferFrom(source, dest, asset.id.into(), array![''].span());
                }
            },
            Category::ERC1155 => {
                let amount = if asset.amount == 0 {
                    1
                } else {
                    asset.amount
                };

                ERC1155ABIDispatcher { contract_address: asset.asset_address }
                    .safeTransferFrom(source, dest, asset.id.into(), amount, array![''].span());
            }
        }
    }

    fn _check_category(asset: Asset, registry: ContractAddress) -> bool {
        let category_value = IMultitokenCategoryRegistryDispatcher { contract_address: registry }
            .registered_category_value(asset.asset_address);
        if category_value != CATEGORY_NOT_REGISTERED {
            return asset.category.into() == category_value;
        }

        _check_category_via_rsc5(asset)
    }

    fn _check_category_via_rsc5(asset: Asset) -> bool {
        match asset.category {
            Category::ERC20 => {
                // NOTE: we don't check interface id since no token uses it on Starket
                // and if supports_interface() is not present the call will revert.
                return false;
            },
            Category::ERC721 => {
                return ERC721ABIDispatcher { contract_address: asset.asset_address }
                    .supports_interface(ERC721_INTERFACE_ID);
            },
            Category::ERC1155 => {
                return ERC1155ABIDispatcher { contract_address: asset.asset_address }
                    .supports_interface(ERC1155_INTERFACE_ID);
            }
        }
    }

    fn _check_format(asset: Asset) -> bool {
        match asset.category {
            Category::ERC20 => { if asset.id != 0 {
                return false;
            } },
            Category::ERC721 => { if asset.amount != 0 {
                return false;
            } },
            Category::ERC1155 => {}
        }

        true
    }
}

impl CategoryIntoU8 of Into<MultiToken::Category, u8> {
    fn into(self: MultiToken::Category) -> u8 {
        match self {
            MultiToken::Category::ERC20 => 0,
            MultiToken::Category::ERC721 => 1,
            MultiToken::Category::ERC1155 => 2,
        }
    }
}

impl CategoryEq of PartialEq<MultiToken::Category> {
    fn eq(lhs: @MultiToken::Category, rhs: @MultiToken::Category) -> bool {
        let lhs: u8 = (*lhs).into();
        let rhs: u8 = (*rhs).into();
        lhs == rhs
    }
    fn ne(lhs: @MultiToken::Category, rhs: @MultiToken::Category) -> bool {
        !(*lhs == *rhs)
    }
}
// NOTE: not sure if _transfer_with_calldata makes sense on starknet


