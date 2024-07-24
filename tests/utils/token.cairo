use starknet::ContractAddress;
use snforge_std::{store, map_entry_address};
use openzeppelin::token::{
    erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
    erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait},
    erc1155::interface::{ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait}
};

pub(crate) fn erc20_mint(erc20: ContractAddress, receiver: ContractAddress, amount: u256) {
    let current_balance = ERC20ABIDispatcher { contract_address: erc20 }.balance_of(receiver);
    let total_supply = ERC20ABIDispatcher { contract_address: erc20 }.total_supply();

    store(
        erc20,
        map_entry_address(selector!("ERC20_total_supply"), array![].span(),),
        array![(total_supply + amount).try_into().unwrap()].span()
    );
    store(
        erc20,
        map_entry_address(selector!("ERC20_balances"), array![receiver.into()].span(),),
        array![(current_balance + amount).try_into().unwrap()].span()
    );
}

pub fn erc721_mint(erc721: ContractAddress, receiver: ContractAddress, id: u256) {
    let mut id_serialized: Array<felt252> = array![];
    id.serialize(ref id_serialized);

    let mut receiver_serialized: Array<felt252> = array![];
    receiver.serialize(ref receiver_serialized);
    store(
        erc721,
        map_entry_address(selector!("ERC721_owners"), id_serialized.span(),),
        receiver_serialized.span()
    );
    let new_balance: u256 = 1;
    let mut balance_serialized: Array<felt252> = array![];
    new_balance.serialize(ref balance_serialized);
    store(
        erc721,
        map_entry_address(selector!("ERC721_balances"), receiver_serialized.span(),),
        balance_serialized.span()
    );
}


pub(crate) fn erc1155_mint(
    erc1155: ContractAddress, receiver: ContractAddress, id: u256, amount: u256
) {
    let mut serialized: Array<felt252> = array![];
    id.serialize(ref serialized);
    receiver.serialize(ref serialized);

    store(
        erc1155,
        map_entry_address(selector!("ERC1155_balances"), serialized.span(),),
        array![amount.try_into().unwrap()].span()
    );
}

pub fn erc20_approve(erc20: ContractAddress, owner: ContractAddress, spender: ContractAddress, amount: u256) {
    store(
        erc20,
        map_entry_address(selector!("ERC20_allowances"), array![owner.into(), spender.into()].span(),),
        array![amount.try_into().unwrap()].span()
    );
}

pub fn erc721_approve(erc721: ContractAddress, spender: ContractAddress, id: u256) {
    let mut id_serialized: Array<felt252> = array![];
    id.serialize(ref id_serialized);

    let mut spender_serialized: Array<felt252> = array![];
    spender.serialize(ref spender_serialized);
    store(
        erc721,
        map_entry_address(selector!("ERC721_token_approvals"), id_serialized.span(),),
        spender_serialized.span()
    );
}

pub fn erc1155_approve(erc1155: ContractAddress, owner: ContractAddress, spender: ContractAddress) {
    let mut owner_serialized = array![];
    owner.serialize(ref owner_serialized);

    let mut spender_serialized = array![];
    spender.serialize(ref spender_serialized);

    store(
        erc1155,
        map_entry_address(selector!("ERC1155_operator_approvals"), array![owner.into(), spender.into()].span(),),
        array![true.try_into().unwrap()].span()
    );
}