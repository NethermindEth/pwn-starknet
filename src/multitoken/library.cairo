//! The `MultiToken` module provides a unified interface for handling different types
//! of token assets (ERC20, ERC721, ERC1155) . This module
//! abstracts the details of different token standards, allowing for unified operations
//! like transferring tokens, checking balances, and verifying token formats.
//!
//! # Features
//!
//! - **Unified Token Handling**: Supports operations on ERC20, ERC721, and ERC1155 tokens,
//!   including transferring assets, checking balances, and approvals.
//! - **Category Management**: Provides functionality for registering and verifying token
//!   categories using a category registry or standard interface checks.
//! - **Safe Transfers**: Ensures safe transfers for ERC721 and ERC1155 tokens, complying
//!   with respective token standards.
//! - **Custom Errors**: Provides specific error messages for unsupported categories or
//!   invalid operations.
//!
//! # Constants
//!
//! - `ERC20_INTERFACE_ID`: The interface ID for ERC20 tokens, based on the full OpenZeppelin ABI.
//! - `ERC721_INTERFACE_ID`: The interface ID for ERC721 tokens, based on the full OpenZeppelin ABI.
//! - `ERC1155_INTERFACE_ID`: The interface ID for ERC1155 tokens, based on the full OpenZeppelin ABI.
//! - `CATEGORY_NOT_REGISTERED`: A sentinel value indicating that a token category is not registered.
//!
//! # Structures
//!
//! - `Category`: An enum representing the type of token (ERC20, ERC721, ERC1155).
//! - `Asset`: A struct representing a token asset, including its category, address, ID, and amount.
//!
//! # Modules
//!
//! - `Err`: Contains error handling functions for various invalid operations or unsupported categories.
//!
//! This module is designed to provide a robust and flexible framework for interacting with
//! multiple token standards on Starknet, simplifying the management of different asset types.

pub mod MultiToken {
    use core::integer::BoundedInt;
    use core::option::OptionTrait;
    use core::traits::Into;
    use openzeppelin::token::erc1155::interface::{ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait};
    use openzeppelin::token::erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};
    use openzeppelin::token::erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait};
    use pwn::ContractAddressDefault;
    use pwn::multitoken::category_registry::{
        IMultiTokenCategoryRegistryDispatcher, IMultiTokenCategoryRegistryDispatcherTrait
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

    /// Represents the category of a token in the .
    ///
    /// This enum categorizes tokens into three main standards:
    /// - `ERC20`: For fungible tokens adhering to the ERC20 standard.
    /// - `ERC721`: For non-fungible tokens (NFTs) adhering to the ERC721 standard.
    /// - `ERC1155`: For multi-token standard that supports both fungible and non-fungible tokens.
    ///
    /// The `default` attribute is set to `ERC20`, indicating that if no category is specified,
    /// the token will be treated as an ERC20 token.
    #[derive(Copy, Debug, Default, Drop, Serde, starknet::Store)]
    pub enum Category {
        #[default]
        ERC20,
        ERC721,
        ERC1155,
    }

    #[derive(Copy, Debug, Default, Drop, Serde, starknet::Store)]
    pub struct Asset {
        /// The category of the asset, indicating the type of token (ERC20, ERC721, ERC1155).
        pub category: Category,
        /// The contract address where the asset is located.
        pub asset_address: ContractAddress,
        /// The unique identifier for the asset. For ERC20 tokens, this is typically `0`.
        /// For ERC721 tokens, this is the specific token ID. For ERC1155 tokens, this represents
        /// the specific asset ID within the contract.
        pub id: felt252,
        /// The amount of the asset. For ERC20 tokens, this represents the quantity of tokens.
        /// For ERC721 tokens, this is usually `1` since ERC721 represents unique tokens.
        /// For ERC1155 tokens, this indicates the quantity of the specific asset.
        pub amount: u256
    }


    pub mod Err {
        pub fn UNSUPPORTED_CATEGORY(category_value: super::Category) {
            panic!("Unsupported category");
        }
    }

    pub fn ERC20(asset_address: ContractAddress, amount: u256) -> Asset {
        Asset { category: Category::ERC20, asset_address, id: 0, amount }
    }

    pub fn ERC721(asset_address: ContractAddress, id: felt252) -> Asset {
        Asset { category: Category::ERC721, asset_address, id, amount: 0 }
    }

    pub fn ERC1155(asset_address: ContractAddress, id: felt252, amount: Option<u256>) -> Asset {
        match amount {
            Option::Some(amount) => Asset {
                category: Category::ERC1155, asset_address, id, amount
            },
            Option::None => Asset { category: Category::ERC1155, asset_address, id, amount: 0 }
        }
    }

    /// Implementation of the `AssetTrait` for the `Asset` struct, providing
    /// functionality to interact with and manage various types of token assets
    /// (ERC20, ERC721, ERC1155) .
    #[generate_trait]
    pub impl AssetImpl of AssetTrait {
        /// Transfers the asset from the `source` address to the `dest` address.
        /// The `is_safe` parameter indicates whether to use a safe transfer method.
        /// This function utilizes the `_transfer_asset_from` internal function to
        /// handle the transfer operation based on the asset's category.
        ///
        /// # Parameters
        /// - `self`: The asset being transferred.
        /// - `source`: The address from which the asset is transferred.
        /// - `dest`: The destination address for the transfer.
        /// - `is_safe`: A boolean indicating if a safe transfer method should be used.
        fn transfer_asset_from(
            self: @Asset, source: ContractAddress, dest: ContractAddress, is_safe: bool
        ) {
            _transfer_asset_from(*self, source, dest, is_safe);
        }

        /// Retrieves the amount of the asset being transferred. For ERC20 tokens, this
        /// returns the `amount` field. For ERC721 tokens, this always returns `1` as
        /// each token is unique. For ERC1155 tokens, this returns the `amount` if
        /// specified, otherwise `1`.
        ///
        /// # Returns
        /// The amount of the asset being transferred.
        fn get_transfer_amount(self: @Asset) -> u256 {
            if *self.category == Category::ERC20 {
                return *self.amount;
            } else if *self.category == Category::ERC1155 && *self.amount > 0 {
                return *self.amount;
            } else {
                return 1;
            }
        }

        /// Retrieves the balance of the asset for a given `target` address. It checks
        /// the category of the asset and calls the appropriate balance query function
        /// for ERC20, ERC721, or ERC1155 tokens.
        ///
        /// # Parameters
        /// - `self`: The asset being queried.
        /// - `target`: The address for which the balance is being queried.
        ///
        /// # Returns
        /// The balance of the asset for the specified target address.
        fn balance_of(self: @Asset, target: ContractAddress) -> u256 {
            if *self.category != Category::ERC20
                && *self.category != Category::ERC721
                && *self.category != Category::ERC1155 {
                Err::UNSUPPORTED_CATEGORY(*self.category);
            }
            if *self.category == Category::ERC20 {
                return ERC20ABIDispatcher { contract_address: *self.asset_address }
                    .balance_of(target);
            } else if *self.category == Category::ERC721 {
                let owner = ERC721ABIDispatcher { contract_address: *self.asset_address }
                    .owner_of((*self.id).into());
                if owner == target {
                    return 1;
                } else {
                    return 0;
                }
            } else {
                return ERC1155ABIDispatcher { contract_address: *self.asset_address }
                    .balance_of(target, (*self.id).into());
            }
        }

        /// Approves the `target` address to transfer the asset. The approval mechanism
        /// differs based on the asset category, utilizing the appropriate approval
        /// function for ERC20, ERC721, and ERC1155 tokens.
        ///
        /// # Parameters
        /// - `self`: The asset being approved.
        /// - `target`: The address being approved for transfer.
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

        /// Checks if the asset is valid based on its category and format. It first tries
        /// to verify the category using a provided registry, if available, or otherwise
        /// falls back to category checks via SRC5 interfaces.
        ///
        /// # Parameters
        /// - `self`: The asset being validated.
        /// - `registry`: An optional registry contract address for category validation.
        ///
        /// # Returns
        /// A boolean indicating whether the asset is valid.
        fn is_valid(self: @Asset, registry: Option<ContractAddress>) -> bool {
            match registry {
                Option::Some(registry) => _check_category(*self, registry) && _check_format(*self),
                Option::None => _check_category_via_src5(*self) && _check_format(*self)
            }
        }

        /// Compares the current asset with another asset to determine if they are the
        /// same. This comparison includes checking the category, asset address, and
        /// asset ID.
        ///
        /// # Parameters
        /// - `self`: The current asset.
        /// - `other`: The other asset to compare against.
        ///
        /// # Returns
        /// A boolean indicating whether the two assets are the same.
        fn is_same_as(self: @Asset, other: Asset) -> bool {
            *self.category == other.category
                && *self.asset_address == other.asset_address
                && *self.id == other.id
        }
    }

    fn _transfer_asset_from(
        asset: Asset, source: ContractAddress, dest: ContractAddress, is_safe: bool
    ) {
        if asset.category != Category::ERC20
            && asset.category != Category::ERC721
            && asset.category != Category::ERC1155 {
            Err::UNSUPPORTED_CATEGORY(asset.category);
        }

        let this_address = starknet::get_contract_address();

        match asset.category {
            Category::ERC20 => {
                if source == this_address {
                    ERC20ABIDispatcher { contract_address: asset.asset_address }
                        .transfer(dest, asset.amount);
                } else {
                    ERC20ABIDispatcher { contract_address: asset.asset_address }
                        .transfer_from(source, dest, asset.amount);
                }
            },
            Category::ERC721 => {
                if !is_safe {
                    ERC721ABIDispatcher { contract_address: asset.asset_address }
                        .transfer_from(source, dest, asset.id.into());
                } else {
                    ERC721ABIDispatcher { contract_address: asset.asset_address }
                        .safe_transfer_from(source, dest, asset.id.into(), array![].span());
                }
            },
            Category::ERC1155 => {
                let amount = if asset.amount == 0 {
                    1
                } else {
                    asset.amount
                };
                ERC1155ABIDispatcher { contract_address: asset.asset_address }
                    .safe_transfer_from(source, dest, asset.id.into(), amount, array![].span());
            }
        }
    }

    fn _check_category(asset: Asset, registry: ContractAddress) -> bool {
        let category_value = IMultiTokenCategoryRegistryDispatcher { contract_address: registry }
            .registered_category_value(asset.asset_address);
        if category_value != CATEGORY_NOT_REGISTERED {
            return asset.category.into() == category_value;
        }

        _check_category_via_src5(asset)
    }

    fn _check_category_via_src5(asset: Asset) -> bool {
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

    #[cfg(test)]
    mod test {
        use snforge_std::mock_call;
        use super::AssetTrait;
        // CHECK FORMAT

        #[test]
        fn test_check_format_should_return_false_when_erc20_with_non_zero_id(
            id: felt252, amount: u256
        ) {
            if (id == 0) {
                return;
            }

            let token = starknet::contract_address_const::<'TOKEN'>();
            let mut asset = super::ERC20(token, amount);
            asset.id = id;

            assert_eq!(super::_check_format(asset), false);
        }

        #[test]
        fn test_check_format_should_return_true_when_erc20_with_zero_id(amount: u256) {
            let token = starknet::contract_address_const::<'TOKEN'>();
            let asset = super::ERC20(token, amount);

            assert_eq!(super::_check_format(asset), true);
        }

        #[test]
        fn test_check_format_should_return_false_when_erc721_with_non_zero_amount(
            id: felt252, amount: u256
        ) {
            if (amount == 0) {
                return;
            }

            let token = starknet::contract_address_const::<'TOKEN'>();
            let mut asset = super::ERC721(token, id);
            asset.amount = 1;

            assert_eq!(super::_check_format(asset), false);
        }

        #[test]
        fn test_check_format_should_return_true_when_erc721_with_zero_amount(id: felt252) {
            let token = starknet::contract_address_const::<'TOKEN'>();
            let mut asset = super::ERC721(token, id);

            assert_eq!(super::_check_format(asset), true);
        }

        #[test]
        fn test_check_format_should_return_true_when_erc1155(id: felt252, amount: u256) {
            let token = starknet::contract_address_const::<'TOKEN'>();
            let asset = super::ERC1155(token, id, Option::Some(amount));

            assert_eq!(super::_check_format(asset), true);
        }

        // CHECK CATEGORY

        #[test]
        fn test_check_category_should_return_true_when_category_registered(category: u8) {
            let category = match (category % 3) {
                0 => super::Category::ERC20,
                1 => super::Category::ERC721,
                2 => super::Category::ERC1155,
                _ => panic!("Invalid category")
            };

            let token = starknet::contract_address_const::<'TOKEN'>();
            let registry = starknet::contract_address_const::<'REGISTRY'>();
            let asset = super::Asset { category: category, asset_address: token, id: 0, amount: 0 };

            mock_call(registry, selector!("registered_category_value"), category, 1);
            assert_eq!(super::_check_category(asset, registry), true);
        }

        #[test]
        fn test_check_category_should_return_false_when_different_category_registered(
            _category: u8
        ) {
            let category = match (_category % 3) {
                0 => super::Category::ERC20,
                1 => super::Category::ERC721,
                2 => super::Category::ERC1155,
                _ => panic!("Invalid category")
            };

            let different_category = match (_category % 3) {
                0 => super::Category::ERC721,
                1 => super::Category::ERC1155,
                2 => super::Category::ERC20,
                _ => panic!("Invalid category")
            };

            let token = starknet::contract_address_const::<'TOKEN'>();
            let registry = starknet::contract_address_const::<'REGISTRY'>();
            let asset = super::Asset { category: category, asset_address: token, id: 0, amount: 0 };

            mock_call(registry, selector!("registered_category_value"), different_category, 1);
            assert_eq!(super::_check_category(asset, registry), false);
        }

        #[test]
        fn test_check_category_should_return_true_when_category_not_registered_when_check_via_src5_returns_true(
            category: u8,
        ) {
            let category = match (category % 3) {
                0 => super::Category::ERC20,
                1 => super::Category::ERC721,
                2 => super::Category::ERC1155,
                _ => panic!("Invalid category")
            };
            let token = starknet::contract_address_const::<'TOKEN'>();
            let registry = starknet::contract_address_const::<'REGISTRY'>();

            let asset = super::Asset { category: category, asset_address: token, id: 0, amount: 0 };

            let category_not_registered = 255;
            mock_call(registry, selector!("registered_category_value"), category_not_registered, 1);

            mock_call(token, selector!("supports_interface"), super::ERC1155_INTERFACE_ID, 2);
            mock_call(token, selector!("supports_interface"), super::ERC721_INTERFACE_ID, 2);

            assert_eq!(
                super::_check_category(asset, registry), super::_check_category_via_src5(asset)
            );
        }

        // CHECK CATEGORY VIA SRC5

        #[test]
        fn test_check_category_via_src5_should_return_false_when_erc20_when_src5_supports_erc721() {
            let token = starknet::contract_address_const::<'TOKEN'>();
            let asset = super::ERC20(token, 0);

            mock_call(token, selector!("supports_interface"), super::ERC721_INTERFACE_ID, 1);
            assert_eq!(super::_check_category_via_src5(asset), false);
        }

        #[test]
        fn test_check_category_via_src5_should_return_false_when_erc20_when_src5_supports_erc1155() {
            let token = starknet::contract_address_const::<'TOKEN'>();
            let asset = super::ERC20(token, 0);

            mock_call(token, selector!("supports_interface"), super::ERC1155_INTERFACE_ID, 1);
            assert_eq!(super::_check_category_via_src5(asset), false);
        }

        #[test]
        fn test_check_category_via_src5_should_return_false_when_erc20() {
            let token = starknet::contract_address_const::<'TOKEN'>();
            let asset = super::ERC20(token, 0);

            assert_eq!(super::_check_category_via_src5(asset), false);
        }

        #[test]
        fn test_check_category_via_src5_should_return_true_when_erc721() {
            let token = starknet::contract_address_const::<'TOKEN'>();
            let asset = super::ERC721(token, 0);

            mock_call(token, selector!("supports_interface"), super::ERC721_INTERFACE_ID, 1);
            assert_eq!(super::_check_category_via_src5(asset), true);
        }

        #[test]
        fn test_check_category_via_src5_should_return_true_when_erc1155() {
            let token = starknet::contract_address_const::<'TOKEN'>();
            let asset = super::ERC1155(token, 0, Option::Some(0));

            mock_call(token, selector!("supports_interface"), super::ERC1155_INTERFACE_ID, 1);
            assert_eq!(super::_check_category_via_src5(asset), true);
        }
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

