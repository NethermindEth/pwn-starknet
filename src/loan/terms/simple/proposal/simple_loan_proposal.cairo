use pwn::loan::lib::{signature_checker::Signature};
use pwn::loan::terms::simple::loan::types::Terms;
use starknet::{ContractAddress, ClassHash};

#[starknet::interface]
pub trait ISimpleLoanProposal<TState> {
    fn revoke_nonce(ref self: TState, nonce_space: felt252, nonce: felt252);
    fn get_multiproposal_hash(
        self: @TState, multiproposal: SimpleLoanProposalComponent::Multiproposal
    ) -> u256;
    fn DOMAIN_SEPARATOR(self: @TState) -> felt252;
    fn MULTIPROPOSAL_DOMAIN_SEPARATOR(self: @TState) -> u256;
    fn MULTIPROPOSAL_TYPEHASH(self: @TState) -> u256;
    fn VERSION(self: @TState) -> felt252;
}

#[starknet::interface]
pub trait ISimpleLoanAcceptProposal<TState> {
    fn accept_proposal(
        ref self: TState,
        acceptor: starknet::ContractAddress,
        refinancing_loan_id: felt252,
        proposal_data: Array<felt252>,
        proposal_inclusion_proof: Array<u256>,
        signature: Signature
    ) -> (felt252, Terms);
}

//! The `SimpleLoanProposalComponent` module is a component that provides essential functionality for creating, 
//! managing, and accepting loan proposals . It is shared between the four
//! proposal types.
//! This module is designed to facilitate a secure and efficient process for handling loan proposals 
//! through robust verification and hashing mechanisms.
//! 
//! # Features
//! 
//! - **Nonce Management**: Ability to revoke nonces to prevent replay attacks.
//! - **Multiproposal Hashing**: Compute unique hashes for multiproposals to ensure data integrity.
//! - **Proposal Acceptance**: Securely accept loan proposals with detailed verification processes 
//!   including signature checks, inclusion proof validation, and nonce management.
//! 
//! # Components
//! 
//! - `SimpleLoanProposalComponent`: The core component providing base functionality for loan 
//!   proposals.
//! - `Err`: Contains error handling functions for various invalid operations and input data.
//! 
//! # Constants
//! 
//! - `MULTIPROPOSAL_TYPEHASH`: The type hash for multiproposals.
//! - `BASE_DOMAIN_SEPARATOR`: The base domain separator used in hashing.
//! - `MULTIPROPOSAL_DOMAIN_SEPARATOR`: The domain separator for multiproposals.
//! 
//! This module is designed to provide a comprehensive framework for managing loan proposals, 
//! integrating seamlessly with other components to ensure secure and efficient loan transactions.
#[starknet::component]
pub mod SimpleLoanProposalComponent {
    use alexandria_math::keccak256::keccak256;
    use core::poseidon::poseidon_hash_span;
    use openzeppelin::account::interface::{ISRC6Dispatcher, ISRC6DispatcherTrait};
    use pwn::config::interface::{IPwnConfigDispatcher, IPwnConfigDispatcherTrait};
    use pwn::hub::{pwn_hub_tags, pwn_hub::{IPwnHubDispatcher, IPwnHubDispatcherTrait}};
    use pwn::interfaces::fingerprint_computer::{
        IStateFingerpringComputerDispatcher, IStateFingerpringComputerDispatcherTrait
    };
    use pwn::loan::lib::signature_checker;
    use pwn::loan::lib::{merkle_proof, merkle_proof::abi_encoded_packed};
    use pwn::nonce::revoked_nonce::{
        IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait, RevokedNonce
    };
    use super::{ContractAddress, ClassHash};

    pub const BASE_DOMAIN_SEPARATOR: felt252 =
        0x1bd2de01ef5d7c9a15011e481320b91a90156eb700f8a5a99a373fa2dea9b10;
    const MULTIPROPOSAL_DOMAIN_SEPARATOR: u256 =
        0xb1acfe094760154fa8ea8fc7c07e76f65332b482350070b57df884171f2ddb56;
    const MULTIPROPOSAL_TYPEHASH: u256 =
        0x73af92d8ed4d3261ba61cd686d2f8a9cceb2563cc7c4c5355eb121316fc5358d;
    const VERSION: felt252 = '1.2';

    #[derive(Drop, Serde)]
    pub struct Multiproposal {
        merkle_root: u256
    }

    /// `ProposalBase` represents the fundamental details of a loan proposal, 
    /// encapsulating the necessary information for processing and verification.
    #[derive(Drop)]
    pub struct ProposalBase {
        /// The address of the collateral.
        pub collateral_address: ContractAddress,
        /// The identifier of the collateral.
        pub collateral_id: felt252,
        /// Flag indicating whether to check the collateral's state fingerprint.
        pub check_collateral_state_fingerprint: bool,
        /// The state fingerprint of the collateral.
        pub collateral_state_fingerprint: felt252,
        /// The amount of credit involved in the proposal.
        pub credit_amount: u256,
        /// The available credit limit for the proposal.
        pub available_credit_limit: u256,
        /// The expiration timestamp of the proposal.
        pub expiration: u64,
        /// The address of the allowed acceptor for the proposal.
        pub allowed_acceptor: ContractAddress,
        /// The address of the proposer.
        pub proposer: ContractAddress,
        /// Boolean flag indicating whether the proposal is an offer.
        pub is_offer: bool,
        /// The ID of the refinancing loan, if applicable.
        pub refinancing_loan_id: felt252,
        /// The nonce space associated with the proposal.
        pub nonce_space: felt252,
        /// The nonce value for the proposal.
        pub nonce: felt252,
        /// The address of the loan contract.
        pub loan_contract: ContractAddress,
    }


    #[storage]
    struct Storage {
        hub: IPwnHubDispatcher,
        revoked_nonce: IRevokedNonceDispatcher,
        config: IPwnConfigDispatcher,
        proposal_made: LegacyMap::<felt252, bool>,
        credit_used: LegacyMap::<felt252, u256>,
        DOMAIN_SEPARATOR: felt252,
    }

    pub mod Err {
        pub fn CALLER_NOT_LOAN_CONTRACT(
            caller: super::ContractAddress, loan_contract: super::ContractAddress
        ) {
            panic!("Caller {:?} is not the loan contract {:?}", caller, loan_contract);
        }
        pub fn MISSING_STATE_FINGERPRINT_COMPUTER() {
            panic!("State fingerprint computer is not registered");
        }
        pub fn INVALID_COLLATERAL_STATE_FINGERPRINT(current: felt252, proposed: felt252) {
            panic!(
                "Invalid collateral state fingerprint. Current: {:?}, Proposed: {:?}",
                current,
                proposed
            );
        }
        pub fn CALLER_IS_NOT_STATED_PROPOSER(addr: super::ContractAddress) {
            panic!("Caller {:?} is not the stated proposer", addr);
        }
        pub fn ACCEPTOR_IS_PROPOSER(addr: super::ContractAddress) {
            panic!("Proposal acceptor {:?} is also the proposer", addr);
        }
        pub fn INVALID_REFINANCING_LOAN_ID(refinancing_loan_id: felt252) {
            panic!("Provided refinance loan ID {:?} cannot be used", refinancing_loan_id);
        }
        pub fn AVAILABLE_CREDIT_LIMIT_EXCEEDED(used: u256, limit: u256) {
            panic!("Available credit limit exceeded. Used: {}, Limit: {}", used, limit);
        }
        pub fn CALLER_NOT_ALLOWED_ACCEPTOR(
            current: super::ContractAddress, allowed: super::ContractAddress
        ) {
            panic!("Caller {:?} is not the allowed acceptor {:?}", current, allowed);
        }
        pub fn ADDRESS_MISSING_HUB_TAG(addr: super::ContractAddress, tag: felt252) {
            panic!("Address {:?} is missing a PWN Hub tag. Tag: {:?}", addr, tag);
        }
        pub fn EXPIRED(current_timestamp: u64, expiration: u64) {
            panic!("Expired. Current timestamp: {}, Expiration: {}", current_timestamp, expiration);
        }
    }

    #[embeddable_as(SimpleLoanProposalImpl)]
    impl SimpleLoanProposal<
        TContractState, +HasComponent<TContractState>,
    > of super::ISimpleLoanProposal<ComponentState<TContractState>> {
        /// Revokes a nonce to prevent its reuse, ensuring the uniqueness of operations.
        /// 
        /// # Parameters
        /// - `nonce_space`: The space in which the nonce is used.
        /// - `nonce`: The nonce value to be revoked.
        fn revoke_nonce(
            ref self: ComponentState<TContractState>, nonce_space: felt252, nonce: felt252
        ) {
            self
                .revoked_nonce
                .read()
                .revoke_nonce(
                    Option::Some(starknet::get_caller_address()), Option::Some(nonce_space), nonce
                );
        }

        /// Computes the hash for a multiproposal using the Keccac hash function.
        /// 
        /// # Parameters
        /// - `multiproposal`: The multiproposal data for which the hash is to be computed.
        /// 
        /// # Returns
        /// The computed hash value as `u256`.
        fn get_multiproposal_hash(
            self: @ComponentState<TContractState>, multiproposal: Multiproposal
        ) -> u256 {
            let hash_elements: Array<u256> = array![
                1901,
                MULTIPROPOSAL_DOMAIN_SEPARATOR.into(),
                MULTIPROPOSAL_TYPEHASH,
                multiproposal.merkle_root
            ];
            keccak256(abi_encoded_packed(hash_elements).span())
        }

        fn DOMAIN_SEPARATOR(self: @ComponentState<TContractState>) -> felt252 {
            self.DOMAIN_SEPARATOR.read()
        }

        fn MULTIPROPOSAL_DOMAIN_SEPARATOR(self: @ComponentState<TContractState>) -> u256 {
            MULTIPROPOSAL_DOMAIN_SEPARATOR
        }

        fn MULTIPROPOSAL_TYPEHASH(self: @ComponentState<TContractState>) -> u256 {
            MULTIPROPOSAL_TYPEHASH
        }

        fn VERSION(self: @ComponentState<TContractState>) -> felt252 {
            VERSION
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>,
    > of InternalTrait<TContractState> {
        fn _initialize(
            ref self: ComponentState<TContractState>,
            hub: ContractAddress,
            revoked_nonce: ContractAddress,
            config: ContractAddress,
            name: felt252,
            version: felt252
        ) {
            self.hub.write(IPwnHubDispatcher { contract_address: hub });
            self.revoked_nonce.write(IRevokedNonceDispatcher { contract_address: revoked_nonce });
            self.config.write(IPwnConfigDispatcher { contract_address: config });

            let hash_elements: Array<felt252> = array![
                BASE_DOMAIN_SEPARATOR,
                name.into(),
                version.into(),
                starknet::get_contract_address().into()
            ];
            let domain_separator = poseidon_hash_span(hash_elements.span());

            self.DOMAIN_SEPARATOR.write(domain_separator);
        }

        fn _get_proposal_hash(
            self: @ComponentState<TContractState>,
            proposal_type_hash: felt252,
            encoded_proposal: Array<felt252>
        ) -> felt252 {
            let mut hash_elements = encoded_proposal;
            hash_elements.append(1901);
            hash_elements.append(self.DOMAIN_SEPARATOR.read());
            hash_elements.append(proposal_type_hash);

            poseidon_hash_span(hash_elements.span())
        }

        fn _make_proposal(
            ref self: ComponentState<TContractState>,
            proposal_hash: felt252,
            proposer: ContractAddress
        ) {
            if starknet::get_caller_address() != proposer {
                Err::CALLER_IS_NOT_STATED_PROPOSER(starknet::get_caller_address());
            }

            self.proposal_made.write(proposal_hash, true);
        }

        fn _accept_proposal(
            ref self: ComponentState<TContractState>,
            acceptor: ContractAddress,
            refinancing_loan_id: felt252,
            proposal_hash: felt252,
            proposal_inclusion_proof: Array<u256>,
            signature: signature_checker::Signature,
            proposal: ProposalBase
        ) {
            let caller = starknet::get_caller_address();

            if caller != proposal.loan_contract {
                Err::CALLER_NOT_LOAN_CONTRACT(caller, proposal.loan_contract);
            }

            let has_tag = self
                .hub
                .read()
                .has_tag(proposal.loan_contract, pwn_hub_tags::ACTIVE_LOAN);
            if !has_tag {
                Err::ADDRESS_MISSING_HUB_TAG(proposal.loan_contract, pwn_hub_tags::ACTIVE_LOAN);
            }

            if proposal_inclusion_proof.len() == 0 {
                if !self.proposal_made.read(proposal_hash) {
                    if !self._is_valid_signature_now(proposal.proposer, proposal_hash, signature) {
                        signature_checker::Err::INVALID_SIGNATURE(proposal.proposer, proposal_hash);
                    }
                }
            } else {
                // TODO: verify inclusion proof type with the pwn team
                // bytes32 multiproposalHash = getMultiproposalHash(
                //     Multiproposal({
                //         multiproposalMerkleRoot: MerkleProof.processProofCalldata({
                //             proof: proposalInclusionProof,
                //             leaf: proposalHash
                //         })
                //     })
                // );
                let multiproposal_merkle_root = merkle_proof::process_proof(
                    proposal_inclusion_proof.span(), proposal_hash.into()
                );
                let multiproposal_hash = self
                    .get_multiproposal_hash(
                        Multiproposal { merkle_root: multiproposal_merkle_root }
                    );
                let multiproposal_hash_felt = poseidon_hash_span(
                    array![multiproposal_hash.low.into(), multiproposal_hash.high.into()].span()
                );
                if !self
                    ._is_valid_signature_now(
                        proposal.proposer, multiproposal_hash_felt, signature
                    ) {
                    signature_checker::Err::INVALID_SIGNATURE(
                        proposal.proposer, multiproposal_hash_felt
                    );
                }
            }

            if proposal.proposer == acceptor {
                Err::ACCEPTOR_IS_PROPOSER(acceptor);
            }

            if refinancing_loan_id == 0 {
                if proposal.refinancing_loan_id != 0 {
                    Err::INVALID_REFINANCING_LOAN_ID(proposal.refinancing_loan_id);
                }
            } else {
                if refinancing_loan_id != proposal.refinancing_loan_id {
                    if proposal.refinancing_loan_id != 0 || !proposal.is_offer {
                        Err::INVALID_REFINANCING_LOAN_ID(proposal.refinancing_loan_id);
                    }
                }
            }

            if starknet::get_block_timestamp() >= proposal.expiration {
                Err::EXPIRED(starknet::get_block_timestamp(), proposal.expiration);
            }

            if !self
                .revoked_nonce
                .read()
                .is_nonce_usable(proposal.proposer, proposal.nonce_space, proposal.nonce) {
                RevokedNonce::Err::NONCE_NOT_USABLE(
                    proposal.proposer, proposal.nonce_space, proposal.nonce
                );
            }

            if proposal.allowed_acceptor != starknet::contract_address_const::<0>()
                && acceptor != proposal.allowed_acceptor {
                Err::CALLER_NOT_ALLOWED_ACCEPTOR(acceptor, proposal.allowed_acceptor);
            }

            if proposal.available_credit_limit == 0 {
                self
                    .revoked_nonce
                    .read()
                    .revoke_nonce(
                        Option::Some(proposal.proposer),
                        Option::Some(proposal.nonce_space),
                        proposal.nonce
                    );
            } else if self.credit_used.read(proposal_hash)
                + proposal.credit_amount <= proposal.available_credit_limit {
                let credit_used = self.credit_used.read(proposal_hash);
                self.credit_used.write(proposal_hash, credit_used + proposal.credit_amount);
            } else {
                Err::AVAILABLE_CREDIT_LIMIT_EXCEEDED(
                    self.credit_used.read(proposal_hash), proposal.available_credit_limit
                );
            }

            if proposal.check_collateral_state_fingerprint {
                let mut current_fingerprint: felt252 = 0;
                let computer = IStateFingerpringComputerDispatcher {
                    contract_address: self
                        .config
                        .read()
                        .get_state_fingerprint_computer(proposal.collateral_address)
                        .contract_address
                };
                if computer.contract_address != starknet::contract_address_const::<0>() {
                    current_fingerprint = computer
                        .compute_state_fingerprint(
                            proposal.collateral_address, proposal.collateral_id
                        );
                } else {
                    Err::MISSING_STATE_FINGERPRINT_COMPUTER();
                }

                if proposal.collateral_state_fingerprint != current_fingerprint {
                    Err::INVALID_COLLATERAL_STATE_FINGERPRINT(
                        current_fingerprint, proposal.collateral_state_fingerprint
                    );
                }
            }
        }

        fn _is_valid_signature_now(
            self: @ComponentState<TContractState>,
            signer: ContractAddress,
            message_hash: felt252,
            signature: signature_checker::Signature
        ) -> bool {
            ISRC6Dispatcher { contract_address: signer }
                .is_valid_signature(
                    message_hash, array![signature.r, signature.s]
                ) == starknet::VALIDATED
        }
    }
}
