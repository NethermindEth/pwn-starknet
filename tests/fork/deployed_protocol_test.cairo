use core::result::ResultTrait;
use core::traits::Into;
use openzeppelin::access::ownable::interface::{IOwnableDispatcher, IOwnableDispatcherTrait};
use openzeppelin::account::interface::{IPublicKeyDispatcher, IPublicKeyDispatcherTrait};
use openzeppelin::token::{
    erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
    erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait},
    erc1155::interface::{ERC1155ABIDispatcher, ERC1155ABIDispatcherTrait}
};
use pwn::config::interface::{IPwnConfigDispatcher, IPwnConfigDispatcherTrait};
use pwn::hub::{pwn_hub::{PwnHub, IPwnHubDispatcher, IPwnHubDispatcherTrait}, pwn_hub_tags};
use pwn::loan::lib::signature_checker::Signature;
use pwn::loan::terms::simple::loan::{
    interface::{IPwnSimpleLoanDispatcher, IPwnSimpleLoanDispatcherTrait},
    types::{LenderSpec, ProposalSpec, CallerSpec}
};

use snforge_std::load;
use starknet::{ContractAddress, contract_address_const, ClassHash};
use super::super::integration::base_integration_test::{
    protocol_timelock, fee_collector, setup as super_setup
};

#[test]
#[fork("mainnet")]
fn test_deployed_protocol() {
    let deployment = super_setup();

    // CONFIG
    // - Check owner
    deployment.config.initialize(protocol_timelock(), 32, fee_collector());
    let config_owner = load(deployment.config.contract_address, selector!("Ownable_owner"), 1);
    assert!((*config_owner.at(0)) == protocol_timelock().into(), "PwnConfig: Owner mismatch");
    // - feeCollector is set
    assert!(
        deployment.config.get_fee_collector() == fee_collector(),
        "PwnConfig: Fee collector mismatch"
    );

    // CATEGORY REGISTRY
    // - Check owner
    let registry_owner = load(deployment.registry.contract_address, selector!("Ownable_owner"), 1);
    assert!(
        (*registry_owner.at(0)) == starknet::get_contract_address().into(),
        "PwnRegistry: Owner mismatch"
    );

    // HUB
    // - Check owner
    let hub_owner = load(deployment.hub.contract_address, selector!("Ownable_owner"), 1);
    assert!(
        (*hub_owner.at(0)) == starknet::get_contract_address().into(), "Pwnhub: Owner mismatch"
    );

    // HUB TAGS
    // - simple loan
    assert!(
        deployment.hub.has_tag(deployment.loan.contract_address, pwn_hub_tags::ACTIVE_LOAN),
        "Simple loan should have ACTIVE_LOAN tag"
    );
    // - simple loan simple proposal
    assert!(
        deployment
            .hub
            .has_tag(deployment.proposal_simple.contract_address, pwn_hub_tags::NONCE_MANAGER),
        "Simple loan simple proposal should have NONCE_MANAGER tag"
    );
    assert!(
        deployment
            .hub
            .has_tag(deployment.proposal_simple.contract_address, pwn_hub_tags::LOAN_PROPOSAL),
        "Simple loan simple proposal should have LOAN_PROPOSAL tag"
    );
    // - simple loan list proposal
    assert!(
        deployment
            .hub
            .has_tag(deployment.proposal_list.contract_address, pwn_hub_tags::NONCE_MANAGER),
        "Simple loan list proposal should have NONCE_MANAGER tag"
    );
    assert!(
        deployment
            .hub
            .has_tag(deployment.proposal_list.contract_address, pwn_hub_tags::LOAN_PROPOSAL),
        "Simple loan list proposal should have LOAN_PROPOSAL tag"
    );
    // - simple loan fungible proposal
    assert!(
        deployment
            .hub
            .has_tag(deployment.proposal_fungible.contract_address, pwn_hub_tags::NONCE_MANAGER),
        "Simple loan fungible proposal should have NONCE_MANAGER tag"
    );
    assert!(
        deployment
            .hub
            .has_tag(deployment.proposal_fungible.contract_address, pwn_hub_tags::LOAN_PROPOSAL),
        "Simple loan fungible proposal should have LOAN_PROPOSAL tag"
    );
    // - simple loan dutch auction proposal
    assert!(
        deployment
            .hub
            .has_tag(deployment.proposal_dutch.contract_address, pwn_hub_tags::NONCE_MANAGER),
        "Simple loan dutch auction proposal should have NONCE_MANAGER tag"
    );
    assert!(
        deployment
            .hub
            .has_tag(deployment.proposal_dutch.contract_address, pwn_hub_tags::LOAN_PROPOSAL),
        "Simple loan dutch auction proposal should have LOAN_PROPOSAL tag"
    );
}
