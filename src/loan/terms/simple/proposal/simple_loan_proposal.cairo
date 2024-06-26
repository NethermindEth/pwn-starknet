use starknet::{ContractAddress, ClassHash};

#[starknet::interface]
trait ISimpleLoanProposal<TState> {
    fn revoked_nonce(ref self: TState, nonce_space: felt252, nonce: felt252);
    // fn accept_proposal(ref self: TState, acceptor: ContractAddress, refinancing_loan_id: felt252, proposal_data: felt252, proposal_inclusion_proof: Array<u8>, signature: felt256) -> (felt252, PwnSimpleLoan);
    fn get_multiproposal_hash(self: @TState, multiproposal: ClassHash) -> felt252;
}

#[starknet::component]
pub mod SimpleLoanProposalComponent {
    use core::poseidon::poseidon_hash_span;
    use pwn::config::interface::{IPwnConfigDispatcher, IPwnConfigDispatcherTrait};
    use pwn::hub::{pwn_hub_tags, interface::{IPwnHubDispatcher, IPwnHubDispatcherTrait}};
    use pwn::interfaces::fingerprint_computer::{
        IStateFingerpringComputerDispatcher, IStateFingerpringComputerDispatcherTrait
    };
    use pwn::loan::lib::signature_checker;
    use pwn::nonce::revoked_nonce::{
        IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait, RevokedNonce
    };
    use super::{ContractAddress, ClassHash};

    const MULTIPROPOSAL_TYPEHASH: felt252 =
        0x03af92d8ed4d3261ba61cd686d2f8a9cceb2563cc7c4c5355eb121316fc5358d;
    const BASE_DOMAIN_SEPARATOR: felt252 =
        0x0373c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;
    const MULTIPROPOSAL_DOMAIN_SEPARATOR: felt252 =
        0x0341fc24aa498aaa42e724a6afc72d16d7b6c7a324a7efbcac56e17d75e6e678;

    #[derive(Drop)]
    struct Multiproposal {
        multiproposal_root_hash: felt252
    }

    #[derive(Drop)]
    pub struct ProposalBase {
        pub collateral_address: ContractAddress,
        pub collateral_id: felt252,
        pub check_collateral_state_fingerprint: bool,
        pub collateral_state_fingerprint: felt252,
        pub credit_amount: u256,
        pub available_credit_limit: u256,
        pub expiration: u64,
        pub allowed_acceptor: ContractAddress,
        pub proposer: ContractAddress,
        pub is_offer: bool,
        pub refinancing_loan_id: felt252,
        pub nonce_space: felt252,
        pub nonce: felt252,
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
        fn revoked_nonce(
            ref self: ComponentState<TContractState>, nonce_space: felt252, nonce: felt252
        ) {
            self
                .revoked_nonce
                .read()
                .revoke_nonce(
                    Option::Some(nonce_space), Option::Some(starknet::get_caller_address()), nonce
                );
        }

        fn get_multiproposal_hash(
            self: @ComponentState<TContractState>, multiproposal: ClassHash
        ) -> felt252 {
            let hash_elements: Array<felt252> = array![
                1901, MULTIPROPOSAL_DOMAIN_SEPARATOR, MULTIPROPOSAL_TYPEHASH, multiproposal.into()
            ];

            poseidon_hash_span(hash_elements.span())
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>,
    > of InternalTrait<TContractState> {
        // NOTE: This is the constuctor of the Solidity contract.
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

            let hash_eleements = array![BASE_DOMAIN_SEPARATOR, name, version];
            let domain_separator = poseidon_hash_span(hash_eleements.span());

            self.DOMAIN_SEPARATOR.write(domain_separator);
        }

        // NOTE: here will we use Poseidon hash function to hash the proposal data.
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
            proposal_inclusion_proof: Array<felt252>,
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
                    if !signature_checker::is_valid_signature_now(
                        proposal.proposer, proposal_hash, signature
                    ) {
                        signature_checker::Err::INVALID_SIGNATURE(proposal.proposer, proposal_hash);
                    }
                }
            } else {
                // TODO: verify inclusion proof type with the pwn team
                let multiproposal_hash = 0x0;
                if !signature_checker::is_valid_signature_now(
                    proposal.proposer, multiproposal_hash, signature
                ) {
                    signature_checker::Err::INVALID_SIGNATURE(
                        proposal.proposer, multiproposal_hash
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

            if self
                .revoked_nonce
                .read()
                .is_nonce_usable(
                    Option::Some(proposal.proposer),
                    Option::Some(proposal.nonce_space),
                    proposal.nonce
                ) {
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
                        Option::Some(proposal.nonce_space),
                        Option::Some(proposal.proposer),
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
                };
                if computer.contract_address == starknet::contract_address_const::<0>() {
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
    }
}
