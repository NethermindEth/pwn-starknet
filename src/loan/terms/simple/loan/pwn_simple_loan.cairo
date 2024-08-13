//! The `PwnSimpleLoan` module provides a streamlined loan management system within the Starknet 
//! ecosystem. This module integrates multiple components to offer a comprehensive solution for 
//! creating, managing, and settling loans.
//! 
//! # Features
//! 
//! - **Loan Creation**: Allows creation of loans with specific terms and lender specifications.
//! - **Loan Repayment**: Facilitates the repayment of loans, including handling of interest and 
//!   collateral management.
//! - **Loan Claiming**: Enables the claiming of loans, whether repaid or defaulted, and handles 
//!   the transfer of collateral or repayment assets.
//! - **Loan Extensions**: Supports the proposal and acceptance of loan extensions, with detailed 
//!   validation and error handling.
//! 
//! # Components
//! 
//! - `OwnableComponent`: Ensures ownership control for sensitive operations.
//! - `Err`: Contains error handling functions for invalid operations and input data.
//! 
//! # Constants
//! 
//! - `ACCRUING_INTEREST_APR_DECIMALS`: Sets the decimals for accruing interest APR calculation.
//! - `MIN_LOAN_DURATION`: The minimum duration for a loan in seconds.
//! - `MAX_ACCRUING_INTEREST_APR`: The maximum allowable APR for accruing interest.
//! - `MINUTE`: A constant representing one minute in seconds.
//! - `MIN_EXTENSION_DURATION`: The minimum duration for a loan extension in seconds.
//! - `MAX_EXTENSION_DURATION`: The maximum duration for a loan extension in seconds.
//! - `EXTENSION_PROPOSAL_TYPEHASH`: The type hash for extension proposals.
//! - `BASE_DOMAIN_SEPARATOR`: The base domain separator for hashing purposes.
//! 
//! This module is designed to provide a secure and flexible framework for managing simple loans, 
//! integrating seamlessly with other components.
#[starknet::contract]
pub mod PwnSimpleLoan {
    use core::poseidon::poseidon_hash_span;
    use openzeppelin::account::interface::{ISRC6Dispatcher, ISRC6DispatcherTrait};

    use openzeppelin::introspection::src5::SRC5Component;
    use openzeppelin::token::erc1155::{
        interface::IERC1155_RECEIVER_ID, erc1155_receiver::ERC1155ReceiverComponent
    };
    use openzeppelin::token::erc721::{
        erc721_receiver::{ERC721ReceiverComponent}, interface::IERC721_RECEIVER_ID
    };
    use openzeppelin::token::erc721::{interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait}};
    use pwn::ContractAddressDefault;
    use pwn::config::interface::{IPwnConfigDispatcher, IPwnConfigDispatcherTrait};
    use pwn::hub::pwn_hub::{IPwnHubDispatcher, IPwnHubDispatcherTrait};
    use pwn::hub::pwn_hub_tags;
    use pwn::loan::lib::{fee_calculator, math, signature_checker};
    use pwn::loan::terms::simple::loan::error::Err;
    use pwn::loan::terms::simple::loan::{
        types::{
            GetLoanReturnValue, CallerSpec, ExtensionProposal, LenderSpec, Loan, ProposalSpec, Terms
        },
        interface::IPwnSimpleLoan
    };
    use pwn::loan::terms::simple::proposal::simple_loan_proposal::{
        ISimpleLoanAcceptProposalDispatcher, ISimpleLoanAcceptProposalDispatcherTrait
    };
    use pwn::loan::terms::simple::proposal::simple_loan_proposal;
    use pwn::loan::token::pwn_loan::{IPwnLoanDispatcher, IPwnLoanDispatcherTrait};
    use pwn::loan::vault::permit::{Permit};
    use pwn::loan::vault::permit;
    use pwn::loan::vault::pwn_vault::PwnVaultComponent;
    use pwn::multitoken::category_registry::{
        IMultiTokenCategoryRegistryDispatcher, IMultiTokenCategoryRegistryDispatcherTrait
    };
    use pwn::multitoken::library::MultiToken::{Asset, AssetTrait, ERC20};
    use pwn::nonce::revoked_nonce::{
        RevokedNonce, IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait
    };
    use starknet::ContractAddress;

    component!(path: PwnVaultComponent, storage: vault, event: VaultEvent);
    component!(path: ERC721ReceiverComponent, storage: erc721, event: ERC721Event);
    component!(path: ERC1155ReceiverComponent, storage: erc1155, event: ERC1155Event);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);


    #[abi(embed_v0)]
    impl ERC721Impl = ERC721ReceiverComponent::ERC721ReceiverImpl<ContractState>;

    #[abi(embed_v0)]
    impl ERC1155Impl = ERC1155ReceiverComponent::ERC1155ReceiverImpl<ContractState>;

    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;
    impl SRC5InternalImpl = SRC5Component::InternalImpl<ContractState>;

    impl VaultImpl = PwnVaultComponent::InternalImpl<ContractState>;

    pub const ACCRUING_INTEREST_APR_DECIMALS: u16 = 100;
    pub const MIN_LOAN_DURATION: u64 = 600;
    pub const MAX_ACCRUING_INTEREST_APR: u32 = 160000;
    pub const MINUTE: u64 = 60;
    pub const MINUTES_IN_YEAR: u64 = 525_600;
    pub const ACCRUING_INTEREST_APR_DENOMINATOR: u64 = 5256000000;
    pub const VERSION: felt252 = '1.2';
    // @note: duration in seconds

    // @note: 1 day
    pub const MIN_EXTENSION_DURATION: u64 = 86400;
    // @note: 90 days 
    pub const MAX_EXTENSION_DURATION: u64 = 86400 * 90;

    pub const EXTENSION_PROPOSAL_TYPEHASH: felt252 =
        0x7e09d567c8fe43c280650abe4557a43fa693063ebc6c47ff3c585866507c732;

    pub const BASE_DOMAIN_SEPARATOR: felt252 =
        0x23b0e9af1d18f697d3e6d8bee3b1defcd47b5be37cf6d26fde2b5d5485065bc;

    #[storage]
    struct Storage {
        loans: LegacyMap::<felt252, Loan>,
        extension_proposal_made: LegacyMap::<felt252, bool>,
        domain_separator: felt252,
        hub: IPwnHubDispatcher,
        loan_token: IPwnLoanDispatcher,
        config: IPwnConfigDispatcher,
        revoked_nonce: IRevokedNonceDispatcher,
        category_registry: IMultiTokenCategoryRegistryDispatcher,
        #[substorage(v0)]
        vault: PwnVaultComponent::Storage,
        #[substorage(v0)]
        erc721: ERC721ReceiverComponent::Storage,
        #[substorage(v0)]
        erc1155: ERC1155ReceiverComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        LoanCreated: LoanCreated,
        LoanPaidBack: LoanPaidBack,
        LoanClaimed: LoanClaimed,
        LoanExtended: LoanExtended,
        ExtensionProposalMade: ExtensionProposalMade,
        VaultEvent: PwnVaultComponent::Event,
        #[flat]
        ERC721Event: ERC721ReceiverComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
        #[flat]
        ERC1155Event: ERC1155ReceiverComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LoanCreated {
        pub loan_id: felt252,
        pub proposal_hash: felt252,
        pub proposal_contract: ContractAddress,
        pub refinancing_loan_id: felt252,
        pub terms: Terms,
        pub lender_spec: LenderSpec,
        pub extra: Option<Array<felt252>>
    }

    #[derive(Drop, starknet::Event)]
    pub struct LoanPaidBack {
        pub loan_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LoanClaimed {
        pub loan_id: felt252,
        pub defaulted: bool
    }

    #[derive(Drop, starknet::Event)]
    pub struct LoanExtended {
        pub loan_id: felt252,
        pub original_default_timestamp: u64,
        pub extended_default_timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    pub struct ExtensionProposalMade {
        pub extension_hash: felt252,
        pub proposer: ContractAddress,
        pub extension_proposal: ExtensionProposal,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        hub: ContractAddress,
        loan_token: ContractAddress,
        config: ContractAddress,
        revoked_nonce: ContractAddress,
        category_registry: ContractAddress,
    ) {
        self.initializer(hub, loan_token, config, revoked_nonce, category_registry);
    }

    #[abi(embed_v0)]
    impl PwnSimpleLoanImpl of IPwnSimpleLoan<ContractState> {
        /// Creates a new loan with specified terms and lender specifications.
        ///
        /// # Arguments
        ///
        /// - `proposal_spec`: Specifications of the loan proposal.
        /// - `lender_spec`: Specifications provided by the lender.
        /// - `caller_spec`: Specifications related to the caller, such as nonce and refinancing.
        /// - `extra`: Additional data for the loan.
        ///
        /// # Returns
        ///
        /// - The unique identifier of the created loan as `felt252`.
        ///
        /// # Requirements
        ///
        /// - The proposal contract must have the `LOAN_PROPOSAL` tag.
        /// - The nonce must be revoked if specified.
        /// - If refinancing, the existing loan must be repayable.
        /// - Loan terms must meet duration and interest rate constraints.
        /// - Validity of assets must be checked.
        fn create_loan(
            ref self: ContractState,
            proposal_spec: ProposalSpec,
            lender_spec: LenderSpec,
            caller_spec: CallerSpec,
            extra: Option<Array<felt252>>
        ) -> felt252 {
            let caller = starknet::get_caller_address();
            if (!self
                .hub
                .read()
                .has_tag(proposal_spec.proposal_contract, pwn_hub_tags::LOAN_PROPOSAL)) {
                simple_loan_proposal::SimpleLoanProposalComponent::Err::ADDRESS_MISSING_HUB_TAG(
                    addr: proposal_spec.proposal_contract, tag: pwn_hub_tags::LOAN_PROPOSAL
                );
            }

            if (caller_spec.revoke_nonce) {
                self
                    .revoked_nonce
                    .read()
                    .revoke_nonce(
                        owner: Option::Some(caller),
                        nonce_space: Option::None,
                        nonce: caller_spec.nonce
                    );
            }

            if (caller_spec.refinancing_loan_id != 0) {
                let loan = self.loans.read(caller_spec.refinancing_loan_id);
                self._check_loan_can_be_repaid(loan.status, loan.default_timestamp);
            }

            let (proposal_hash, loan_terms) = ISimpleLoanAcceptProposalDispatcher {
                contract_address: proposal_spec.proposal_contract
            }
                .accept_proposal(
                    acceptor: caller,
                    refinancing_loan_id: caller_spec.refinancing_loan_id,
                    proposal_data: proposal_spec.proposal_data,
                    proposal_inclusion_proof: proposal_spec.proposal_inclusion_proof,
                    signature: proposal_spec.signature
                );

            let current_lender_spec_hash = self.get_lender_spec_hash(lender_spec.clone());
            if (caller != loan_terms.lender
                && loan_terms.lender_spec_hash != current_lender_spec_hash) {
                Err::INVALID_LENDER_SPEC_HASH(
                    current: loan_terms.lender_spec_hash, expected: current_lender_spec_hash
                );
            }

            if (loan_terms.duration < MIN_LOAN_DURATION) {
                Err::INVALID_DURATION(current: loan_terms.duration, limit: MIN_LOAN_DURATION);
            }

            if (loan_terms.accruing_interest_APR > MAX_ACCRUING_INTEREST_APR) {
                Err::INTEREST_APR_OUT_OF_BOUNDS(
                    current: loan_terms.accruing_interest_APR, limit: MAX_ACCRUING_INTEREST_APR
                );
            }

            if (caller_spec.refinancing_loan_id == 0) {
                self._check_valid_asset(loan_terms.credit);
                self._check_valid_asset(loan_terms.collateral);
            } else {
                self
                    ._check_refinance_loan_terms(
                        caller_spec.refinancing_loan_id, loan_terms.clone()
                    );
            }

            let loan_id = self
                ._create_loan(loan_terms: loan_terms.clone(), lender_spec: lender_spec.clone());
            self
                .emit(
                    LoanCreated {
                        loan_id,
                        proposal_hash,
                        proposal_contract: proposal_spec.proposal_contract,
                        refinancing_loan_id: caller_spec.refinancing_loan_id,
                        terms: loan_terms.clone(),
                        lender_spec: lender_spec.clone(),
                        extra
                    }
                );
            if (caller_spec.refinancing_loan_id == 0) {
                self._settle_new_loan(loan_terms, lender_spec);
            } else {
                self._update_repaid_loan(caller_spec.refinancing_loan_id);
                self
                    ._settle_loan_refinance(
                        refinancing_loan_id: caller_spec.refinancing_loan_id,
                        loan_terms: loan_terms,
                        lender_spec: lender_spec
                    );
            }

            loan_id
        }

        /// Repays an existing loan.
        ///
        /// # Arguments
        ///
        /// - `loan_id`: The unique identifier of the loan to be repaid.
        /// - `permit_data`: Data required for the repayment process.
        ///
        /// # Requirements
        ///
        /// - The loan must be in a state that allows repayment.
        /// - The caller must provide valid permit data.
        ///
        /// # Actions
        ///
        /// - Checks if the loan can be repaid.
        /// - Updates the loan status to repaid.
        /// - Pulls the repayment amount from the caller.
        /// - Pushes the collateral back to the borrower.
        /// - Attempts to claim the repaid loan for the loan token owner.
        fn repay_loan(ref self: ContractState, loan_id: felt252, permit_data: felt252) {
            let caller = starknet::get_caller_address();
            let loan = self.loans.read(loan_id);
            self._check_loan_can_be_repaid(loan.status, loan.default_timestamp);
            self._update_repaid_loan(loan_id);

            let repayment_amount = self.get_loan_repayment_amount(loan_id);
            self.vault._pull(ERC20(loan.credit_address, repayment_amount), caller);
            self.vault._push(loan.collateral, loan.borrower);
            self
                ._try_claim_repaid_loan(
                    loan_id,
                    repayment_amount,
                    ERC721ABIDispatcher {
                        contract_address: self.loan_token.read().contract_address
                    }
                        .owner_of(loan_id.try_into().expect('repay_loan'))
                );
        }

        /// Claims a loan, transferring collateral or repayment assets based on loan status.
        ///
        /// # Arguments
        ///
        /// - `loan_id`: The unique identifier of the loan to be claimed.
        ///
        /// # Requirements
        ///
        /// - The caller must be the loan token holder.
        /// - The loan must exist.
        /// - The loan must be either repaid, defaulted, or running and reached the default timestamp.
        ///
        /// # Actions
        ///
        /// - Validates the caller as the loan token holder.
        /// - Settles the loan claim based on its status.
        fn claim_loan(ref self: ContractState, loan_id: felt252) {
            let loan = self.loans.read(loan_id);
            let caller = starknet::get_caller_address();
            let loan_token_owner = ERC721ABIDispatcher {
                contract_address: self.loan_token.read().contract_address
            }
                .owner_of(loan_id.try_into().expect('claim_loan'));
            if (caller != loan_token_owner) {
                Err::CALLER_NOT_LOAN_TOKEN_HOLDER();
            }

            if (loan.status == 0) {
                Err::NON_EXISTING_LOAN();
            } else if (loan.status == 3) {
                self._settle_loan_claim(loan_id: loan_id, loan_owner: caller, defaulted: false);
            } else if (loan.status == 2
                && loan.default_timestamp <= starknet::get_block_timestamp()) {
                self._settle_loan_claim(loan_id: loan_id, loan_owner: caller, defaulted: true);
            } else {
                Err::LOAN_RUNNING();
            }
        }

        /// Makes an extension proposal for a loan.
        ///
        /// # Arguments
        ///
        /// - `extension`: The extension proposal details.
        ///
        /// # Requirements
        ///
        /// - The caller must be the proposer of the extension.
        ///
        /// # Actions
        ///
        /// - Validates the caller as the proposer.
        /// - Computes the extension hash and marks the proposal as made.
        /// - Emits an `ExtensionProposalMade` event.
        fn make_extension_proposal(ref self: ContractState, extension: ExtensionProposal) {
            let caller = starknet::get_caller_address();

            if (caller != extension.proposer) {
                Err::INVALID_EXTENSION_SIGNER(allowed: extension.proposer, current: caller);
            }

            let extension_hash = self.get_extension_hash(extension);
            self.extension_proposal_made.write(extension_hash, true);
            self
                .emit(
                    ExtensionProposalMade {
                        extension_hash, proposer: extension.proposer, extension_proposal: extension
                    }
                );
        }

        /// Extends a loan based on an extension proposal and a valid signature.
        ///
        /// # Arguments
        ///
        /// - `extension`: The extension proposal details.
        /// - `signature`: The signature for validating the extension.
        ///
        /// # Requirements
        ///
        /// - The loan must exist and not be repaid.
        /// - The extension proposal must be valid and not expired.
        /// - The nonce must be usable.
        /// - The caller must be either the loan owner or borrower, and the proposer must be the other party.
        /// - The extension duration must be within the allowed range.
        ///
        /// # Actions
        ///
        /// - Validates the extension proposal, signature, and nonce.
        /// - Updates the loan's default timestamp with the extension duration.
        /// - Emits a `LoanExtended` event.
        /// - If compensation is provided, it transfers the compensation to the loan owner.
        fn extend_loan(
            ref self: ContractState,
            extension: ExtensionProposal,
            signature: signature_checker::Signature,
        ) {
            let mut loan = self.loans.read(extension.loan_id);
            let caller = starknet::get_caller_address();

            if (loan.status == 0) {
                Err::NON_EXISTING_LOAN();
            }

            if (loan.status == 3) {
                Err::LOAN_REPAID();
            }

            let extension_hash = self.get_extension_hash(extension.clone());

            if (!self.extension_proposal_made.read(extension_hash)) {
                if (!self._is_valid_signature_now(extension.proposer, extension_hash, signature)) {
                    signature_checker::Err::INVALID_SIGNATURE(
                        signer: extension.proposer, digest: extension_hash
                    );
                }
            }

            let current_block_timestamp = starknet::get_block_timestamp();

            if (current_block_timestamp >= extension.expiration) {
                // @note: we shall move these error in a common place?
                simple_loan_proposal::SimpleLoanProposalComponent::Err::EXPIRED(
                    current_timestamp: starknet::get_block_timestamp(),
                    expiration: extension.expiration
                );
            }

            if (!self
                .revoked_nonce
                .read()
                .is_nonce_usable(extension.proposer, extension.nonce_space, extension.nonce)) {
                RevokedNonce::Err::NONCE_NOT_USABLE(
                    addr: extension.proposer,
                    nonce_space: extension.nonce_space,
                    nonce: extension.nonce
                );
            }
            let loan_owner = ERC721ABIDispatcher {
                contract_address: self.loan_token.read().contract_address
            }
                .owner_of(extension.loan_id.try_into().expect('extend_loan'));

            if (caller == loan_owner) {
                if (extension.proposer != loan.borrower) {
                    Err::INVALID_EXTENSION_SIGNER(
                        allowed: loan.borrower, current: extension.proposer
                    );
                }
            } else if (caller == loan.borrower) {
                if (extension.proposer != loan_owner) {
                    Err::INVALID_EXTENSION_SIGNER(
                        allowed: loan_owner, current: extension.proposer
                    );
                }
            } else {
                Err::INVALID_EXTENSION_CALLER();
            }

            if (extension.duration < MIN_EXTENSION_DURATION) {
                Err::INVALID_EXTENSION_DURATION(
                    duration: extension.duration, limit: MIN_EXTENSION_DURATION
                );
            }

            if (extension.duration > MAX_EXTENSION_DURATION) {
                Err::INVALID_EXTENSION_DURATION(
                    duration: extension.duration, limit: MAX_EXTENSION_DURATION
                );
            }

            self
                .revoked_nonce
                .read()
                .revoke_nonce(
                    owner: Option::Some(extension.proposer),
                    nonce_space: Option::Some(extension.nonce_space),
                    nonce: extension.nonce
                );

            let original_default_timestamp = loan.default_timestamp;
            loan.default_timestamp = original_default_timestamp + extension.duration;

            self
                .emit(
                    LoanExtended {
                        loan_id: extension.loan_id,
                        original_default_timestamp,
                        extended_default_timestamp: loan.default_timestamp
                    }
                );

            if (extension.compensation_address != Default::default()
                && extension.compensation_amount > 0) {
                let compensation = ERC20(
                    extension.compensation_address, extension.compensation_amount
                );

                self._check_valid_asset(compensation);

                self.vault._push_from(compensation, loan.borrower, loan_owner);
            }
            self.loans.write(extension.loan_id, loan);
        }

        /// Computes the hash of the lender's specifications.
        ///
        /// # Arguments
        ///
        /// - `calladata`: The lender's specifications.
        ///
        /// # Returns
        ///
        /// - The computed hash as `felt252`.
        fn get_lender_spec_hash(self: @ContractState, calladata: LenderSpec) -> felt252 {
            let hash_elements: Array<felt252> = array![
                calladata.source_of_funds.try_into().expect('get_lender_spec_hash')
            ];
            poseidon_hash_span(hash_elements.span())
        }

        /// Calculates the repayment amount for a specific loan.
        ///
        /// # Arguments
        ///
        /// - `loan_id`: The unique identifier of the loan.
        ///
        /// # Returns
        ///
        /// - The total repayment amount as `u256`.
        ///
        /// # Requirements
        ///
        /// - The loan must exist.
        fn get_loan_repayment_amount(self: @ContractState, loan_id: felt252) -> u256 {
            let loan = self.loans.read(loan_id);

            if (loan.status == 0) {
                return 0;
            }

            loan.principal_amount + self._loan_accrued_interest(loan)
        }

        /// Computes the hash of an extension proposal.
        ///
        /// # Arguments
        ///
        /// - `extension`: The extension proposal details.
        ///
        /// # Returns
        ///
        /// - The computed hash as `felt252`.
        fn get_extension_hash(self: @ContractState, extension: ExtensionProposal) -> felt252 {
            let domain_separator = self.domain_separator.read();

            let hash_elements: Array<felt252> = array![
                1901,
                domain_separator,
                EXTENSION_PROPOSAL_TYPEHASH,
                extension.loan_id,
                extension.compensation_address.try_into().expect('get_extension_hash'),
                extension.compensation_amount.try_into().expect('get_extension_hash'),
                extension.duration.into(),
                extension.expiration.into(),
                extension.proposer.try_into().expect('get_extension_hash'),
                extension.nonce_space,
                extension.nonce
            ];
            poseidon_hash_span(hash_elements.span())
        }

        /// Retrieves the details of a specific loan.
        ///
        /// # Arguments
        ///
        /// - `loan_id`: The unique identifier of the loan.
        ///
        /// # Returns
        ///
        /// - The loan details as `GetLoanReturnValue`.
        ///
        /// # Requirements
        ///
        /// - The loan must exist.
        fn get_loan(self: @ContractState, loan_id: felt252) -> GetLoanReturnValue {
            let loan = self.loans.read(loan_id);
            let loan_owner: ContractAddress = if (loan.status != 0) {
                ERC721ABIDispatcher { contract_address: self.loan_token.read().contract_address }
                    .owner_of(loan_id.try_into().expect('get_loan'))
            } else {
                Default::default()
            };
            let loan_return_value = GetLoanReturnValue {
                status: self._get_loan_status(loan_id),
                start_timestamp: loan.start_timestamp,
                default_timestamp: loan.default_timestamp,
                borrower: loan.borrower,
                original_lender: loan.original_lender,
                loan_owner,
                accruing_interest_APR: loan.accruing_interest_APR,
                fixed_interest_amount: loan.fixed_interest_amount,
                credit: ERC20(loan.credit_address, loan.principal_amount),
                collateral: loan.collateral,
                original_source_of_funds: loan.original_source_of_funds,
                repayment_amount: self.get_loan_repayment_amount(loan_id)
            };
            loan_return_value
        }

        /// Retrieves whether the extension proposal has been made or not.
        ///
        /// # Arguments
        ///
        /// - `extension_hash`: The unique identifier of the extension_proposal .
        ///
        /// # Returns
        ///
        /// - `true` if extension proposal corresponding to `extension_hash` has been made, `false`
        /// otherwise.
        fn get_extension_proposal_made(self: @ContractState, extension_hash: felt252) -> bool {
            self.extension_proposal_made.read(extension_hash)
        }

        /// Checks if a given asset is valid.
        ///
        /// # Arguments
        ///
        /// - `asset`: The asset to check.
        ///
        /// # Returns
        ///
        /// - `true` if the asset is valid, `false` otherwise.
        fn get_is_valid_asset(self: @ContractState, asset: Asset) -> bool {
            asset.is_valid(Option::Some(self.category_registry.read().contract_address))
        }

        /// Retrieves the metadata URI for the loan contract.
        ///
        /// # Returns
        ///
        /// - The metadata URI as a `ByteArray`.
        fn get_loan_metadata_uri(self: @ContractState) -> ByteArray {
            let this_contract = starknet::get_contract_address();
            self.config.read().loan_metadata_uri(this_contract)
        }

        /// Computes the state fingerprint for a loan token.
        ///
        /// # Arguments
        ///
        /// - `token_id`: The unique identifier of the loan token.
        ///
        /// # Returns
        ///
        /// - The computed state fingerprint as `felt252`.
        ///
        /// # Requirements
        ///
        /// - The loan must exist.
        fn get_state_fingerprint(self: @ContractState, token_id: felt252) -> felt252 {
            let loan = self.loans.read(token_id);
            if (loan.status == 0) {
                return 0;
            }

            let hash_elements: Array<felt252> = array![
                self._get_loan_status(token_id).into(),
                loan.default_timestamp.into(),
                loan.fixed_interest_amount.low.into(),
                loan.fixed_interest_amount.high.into(),
                loan.accruing_interest_APR.into()
            ];
            poseidon_hash_span(hash_elements.span())
        }

        fn ACCRUING_INTEREST_APR_DECIMALS(self: @ContractState) -> u16 {
            ACCRUING_INTEREST_APR_DECIMALS
        }

        fn ACCRUING_INTEREST_APR_DENOMINATOR(self: @ContractState) -> u64 {
            ACCRUING_INTEREST_APR_DENOMINATOR
        }

        fn DOMAIN_SEPARATOR(self: @ContractState) -> felt252 {
            self.domain_separator.read()
        }

        fn EXTENSION_PROPOSAL_TYPEHASH(self: @ContractState) -> felt252 {
            EXTENSION_PROPOSAL_TYPEHASH
        }

        fn MAX_ACCRUING_INTEREST_APR(self: @ContractState) -> u32 {
            MAX_ACCRUING_INTEREST_APR
        }

        fn MINUTES_IN_YEAR(self: @ContractState) -> u64 {
            MINUTES_IN_YEAR
        }

        fn MAX_EXTENSION_DURATION(self: @ContractState) -> u64 {
            MAX_EXTENSION_DURATION
        }

        fn MIN_EXTENSION_DURATION(self: @ContractState) -> u64 {
            MIN_EXTENSION_DURATION
        }

        fn MIN_LOAN_DURATION(self: @ContractState) -> u64 {
            MIN_LOAN_DURATION
        }

        fn VERSION(self: @ContractState) -> felt252 {
            VERSION
        }
    }

    #[generate_trait]
    pub impl Private of PrivateTrait {
        fn initializer(
            ref self: ContractState,
            hub: ContractAddress,
            loan_token: ContractAddress,
            config: ContractAddress,
            revoked_nonce: ContractAddress,
            category_registry: ContractAddress
        ) {
            let hub_dispatcher = IPwnHubDispatcher { contract_address: hub };
            let loan_token_dispatcher = IPwnLoanDispatcher { contract_address: loan_token };
            let config_dispatcher = IPwnConfigDispatcher { contract_address: config };
            let revoked_nonce_dispatcher = IRevokedNonceDispatcher {
                contract_address: revoked_nonce
            };
            let category_registry_dispatcher = IMultiTokenCategoryRegistryDispatcher {
                contract_address: category_registry
            };
            self.hub.write(hub_dispatcher);
            self.loan_token.write(loan_token_dispatcher);
            self.config.write(config_dispatcher);
            self.revoked_nonce.write(revoked_nonce_dispatcher);
            self.category_registry.write(category_registry_dispatcher);
            let hash_elements: Array<felt252> = array![
                BASE_DOMAIN_SEPARATOR, starknet::get_contract_address().into()
            ];
            let domain_separator = poseidon_hash_span(hash_elements.span());
            self.domain_separator.write(domain_separator);
            self.src5.register_interface(IERC1155_RECEIVER_ID);
            self.src5.register_interface(IERC721_RECEIVER_ID);
        }

        fn _check_permit(ref self: ContractState, credit_address: ContractAddress, permit: Permit) {
            let caller = starknet::get_caller_address();
            if (permit.asset != Default::default()) {
                if (permit.owner != caller) {
                    permit::Err::InvalidPermitOwner(current: permit.owner, expected: caller);
                }
                if (permit.asset != credit_address) {
                    permit::Err::InvalidPermitAsset(
                        current: permit.asset, expected: credit_address
                    );
                }
            }
        }

        fn _check_refinance_loan_terms(
            ref self: ContractState, loan_id: felt252, loan_terms: Terms
        ) {
            let loan = self.loans.read(loan_id);

            if (loan.credit_address != loan_terms.credit.asset_address
                || loan_terms.credit.amount == 0) {
                Err::REFINANCE_CREDIT_MISMATCH();
            }

            if (loan.collateral.category != loan_terms.collateral.category
                || loan.collateral.asset_address != loan_terms.collateral.asset_address
                || loan.collateral.id != loan_terms.collateral.id
                || loan.collateral.amount != loan_terms.collateral.amount) {
                Err::REFINANCE_COLLATERAL_MISMATCH();
            }

            if (loan.borrower != loan_terms.borrower) {
                Err::REFINANCE_BORROWER_MISMATCH(
                    currrent_borrower: loan.borrower, new_borrower: loan_terms.borrower
                );
            }
        }

        fn _create_loan(
            ref self: ContractState, loan_terms: Terms, lender_spec: LenderSpec
        ) -> felt252 {
            let loan_id = self.loan_token.read().mint(loan_terms.lender);
            let current_timestamp = starknet::get_block_timestamp();
            let loan = Loan {
                status: 2,
                credit_address: loan_terms.credit.asset_address,
                original_source_of_funds: lender_spec.source_of_funds,
                start_timestamp: current_timestamp,
                default_timestamp: current_timestamp + loan_terms.duration,
                borrower: loan_terms.borrower,
                original_lender: loan_terms.lender,
                accruing_interest_APR: loan_terms.accruing_interest_APR,
                fixed_interest_amount: loan_terms.fixed_interest_amount,
                principal_amount: loan_terms.credit.amount,
                collateral: loan_terms.collateral
            };
            self.loans.write(loan_id, loan);
            loan_id
        }

        fn _settle_new_loan(ref self: ContractState, loan_terms: Terms, lender_spec: LenderSpec) {
            self.vault._pull(loan_terms.collateral, loan_terms.borrower);
            if (lender_spec.source_of_funds != loan_terms.lender) {
                self._withdraw_credit_from_pool(loan_terms.credit, loan_terms, lender_spec);
            }
            let (fee_amount, new_loan_amount) = fee_calculator::calculate_fee_amount(
                self.config.read().get_fee(), loan_terms.credit.amount
            );

            let mut credit_helper = loan_terms.credit;

            if (fee_amount > 0) {
                credit_helper.amount = fee_amount.try_into().expect('_settle_new_loan');
                self
                    .vault
                    ._push_from(
                        credit_helper, loan_terms.lender, self.config.read().get_fee_collector()
                    );
            }

            credit_helper.amount = new_loan_amount;
            self.vault._push_from(credit_helper, loan_terms.lender, loan_terms.borrower);
        }

        fn _settle_loan_refinance(
            ref self: ContractState,
            refinancing_loan_id: felt252,
            loan_terms: Terms,
            lender_spec: LenderSpec
        ) {
            let loan = self.loans.read(refinancing_loan_id);
            let erc721_dispatcher = ERC721ABIDispatcher {
                contract_address: self.loan_token.read().contract_address
            };
            let loan_owner = erc721_dispatcher
                .owner_of(refinancing_loan_id.try_into().expect('_settle_loan_refinance'));
            let repayment_amount = self.get_loan_repayment_amount(refinancing_loan_id);
            let (fee_amount, new_loan_amount) = fee_calculator::calculate_fee_amount(
                self.config.read().get_fee(), loan_terms.credit.amount
            );

            let common = if (repayment_amount > new_loan_amount) {
                new_loan_amount
            } else {
                repayment_amount
            };

            let surplus = if (new_loan_amount > repayment_amount) {
                new_loan_amount - repayment_amount
            } else {
                0
            };

            let shortage = if (surplus > 0) {
                0
            } else {
                repayment_amount - new_loan_amount
            };

            let should_transfer_common = loan_terms.lender != loan_owner
                || (loan.original_lender == loan_owner
                    && loan.original_source_of_funds != lender_spec.source_of_funds);

            let mut credit_helper = loan_terms.credit;

            if (lender_spec.source_of_funds != loan_terms.lender) {
                credit_helper.amount = fee_amount + surplus;
                if (should_transfer_common) {
                    credit_helper.amount += common;
                }
                self._withdraw_credit_from_pool(credit_helper, loan_terms, lender_spec);
            }

            if (fee_amount > 0) {
                credit_helper.amount = fee_amount;
                self
                    .vault
                    ._push_from(
                        credit_helper, loan_terms.lender, self.config.read().get_fee_collector()
                    );
            }

            if (should_transfer_common) {
                credit_helper.amount = common;
                self.vault._pull(credit_helper, loan_terms.lender);
            }

            if (surplus > 0) {
                credit_helper.amount = surplus;
                self.vault._push_from(credit_helper, loan_terms.lender, loan_terms.borrower);
            } else if (shortage > 0) {
                credit_helper.amount = shortage;
                self.vault._pull(credit_helper, loan_terms.borrower);
            }
            let credit_amount = shortage + if (should_transfer_common) {
                common
            } else {
                0
            };
            self
                ._try_claim_repaid_loan(
                    loan_id: refinancing_loan_id,
                    credit_amount: credit_amount,
                    loan_owner: loan_owner
                );
        }

        fn _withdraw_credit_from_pool(
            ref self: ContractState, credit: Asset, loan_terms: Terms, lender_spec: LenderSpec
        ) {
            let pool_adapter = self.config.read().get_pool_adapter(lender_spec.source_of_funds);
            if (pool_adapter.contract_address == Default::default()) {
                Err::INVALID_SOURCE_OF_FUNDS(source_of_funds: lender_spec.source_of_funds);
            }
            if (credit.amount > 0) {
                self
                    .vault
                    ._withdraw_from_pool(
                        credit, pool_adapter, lender_spec.source_of_funds, loan_terms.lender
                    );
            }
        }

        fn _check_loan_can_be_repaid(ref self: ContractState, status: u8, default_timestamp: u64) {
            if (status == 0) {
                Err::NON_EXISTING_LOAN();
            }
            if (status != 2) {
                Err::LOAN_NOT_RUNNING();
            }
            let current_timestamp = starknet::get_block_timestamp();
            if (default_timestamp <= current_timestamp) {
                Err::LOAN_DEFAULTED(default_timestamp);
            }
        }

        fn _update_repaid_loan(ref self: ContractState, loan_id: felt252) {
            let mut loan = self.loans.read(loan_id);
            loan.status = 3;
            loan.fixed_interest_amount = self._loan_accrued_interest(loan.clone());
            loan.accruing_interest_APR = 0;
            self.loans.write(loan_id, loan);
            self.emit(LoanPaidBack { loan_id });
        }

        fn _loan_accrued_interest(self: @ContractState, loan: Loan) -> u256 {
            if (loan.accruing_interest_APR == 0) {
                return loan.fixed_interest_amount;
            }
            let current_timestamp = starknet::get_block_timestamp();
            let accuring_minutes: u64 = (current_timestamp - loan.start_timestamp) / MINUTE;
            let interest_amount: u256 = (accuring_minutes * loan.accruing_interest_APR.into())
                .into();
            let accured_interest = math::mul_div(
                loan.principal_amount, interest_amount, ACCRUING_INTEREST_APR_DENOMINATOR.into()
            );
            loan.fixed_interest_amount + accured_interest
        }

        fn _settle_loan_claim(
            ref self: ContractState, loan_id: felt252, loan_owner: ContractAddress, defaulted: bool
        ) {
            let loan = self.loans.read(loan_id);
            let asset = match defaulted {
                true => loan.collateral,
                false => ERC20(loan.credit_address, self.get_loan_repayment_amount(loan_id))
            };
            self._delete_loan(loan_id);
            self.emit(LoanClaimed { loan_id, defaulted });
            self.vault._push(asset, loan_owner);
        }

        fn _delete_loan(ref self: ContractState, loan_id: felt252) {
            self.loan_token.read().burn(loan_id);
            let loan = Loan {
                status: Default::default(),
                credit_address: Default::default(),
                original_source_of_funds: Default::default(),
                start_timestamp: Default::default(),
                default_timestamp: Default::default(),
                borrower: Default::default(),
                original_lender: Default::default(),
                accruing_interest_APR: Default::default(),
                fixed_interest_amount: Default::default(),
                principal_amount: Default::default(),
                collateral: Default::default(),
            };
            self.loans.write(loan_id, loan);
        }

        fn _get_loan_status(self: @ContractState, loan_id: felt252) -> u8 {
            let loan = self.loans.read(loan_id);
            let current_timestamp = starknet::get_block_timestamp();
            if (loan.status == 2 && loan.default_timestamp <= current_timestamp) {
                return 4;
            }
            loan.status
        }

        fn _check_valid_asset(ref self: ContractState, asset: Asset) {
            if (!self.get_is_valid_asset(asset)) {
                Err::INVALID_MULTITOKEN_ASSET(
                    category: asset.category.into(),
                    address: asset.asset_address,
                    id: asset.id,
                    amount: asset.amount
                );
            }
        }

        fn _try_claim_repaid_loan(
            ref self: ContractState,
            loan_id: felt252,
            credit_amount: u256,
            loan_owner: ContractAddress
        ) {
            let loan = self.loans.read(loan_id);

            if (loan.status != 3 || loan.original_lender != loan_owner) {
                return;
            }

            let destination_of_funds = loan.original_source_of_funds;

            let repayment_credit = ERC20(loan.credit_address, credit_amount);

            self._delete_loan(loan_id);

            self.emit(LoanClaimed { loan_id, defaulted: false });

            if (credit_amount == 0) {
                return;
            }

            if (destination_of_funds == loan_owner) {
                self.vault._push(repayment_credit, loan_owner);
            } else {
                let pool_adapter = self.config.read().get_pool_adapter(destination_of_funds);
                if (pool_adapter.contract_address == Default::default()) {
                    Err::INVALID_SOURCE_OF_FUNDS(source_of_funds: destination_of_funds);
                }
                self
                    .vault
                    ._supply_to_pool(
                        repayment_credit, pool_adapter, destination_of_funds, loan_owner
                    );
            }
        }

        fn _is_valid_signature_now(
            self: @ContractState,
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
