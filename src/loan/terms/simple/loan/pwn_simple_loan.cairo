#[starknet::contract]
mod PwnSimpleLoan {
    use openzeppelin::token::erc721::{interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait}};
    use pwn::ContractAddressDefault;
    use pwn::config::interface::{IPwnConfigDispatcher, IPwnConfigDispatcherTrait};
    use pwn::hub::pwn_hub::{IPwnHubDispatcher, IPwnHubDispatcherTrait};
    use pwn::hub::pwn_hub_tags;
    use pwn::loan::lib::{fee_calculator, math, signature_checker};
    use pwn::loan::terms::simple::loan::error;
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
        IMultitokenCategoryRegistryDispatcher, IMultitokenCategoryRegistryDispatcherTrait
    };
    use pwn::multitoken::library::MultiToken::Asset;
    use pwn::multitoken::library::MultiToken::AssetTrait;
    use pwn::multitoken::library::MultiToken::ERC20;
    use pwn::nonce::revoked_nonce::RevokedNonce;
    use pwn::nonce::revoked_nonce::{IRevokedNonceDispatcher, IRevokedNonceDispatcherTrait};
    use starknet::ContractAddress;

    component!(path: PwnVaultComponent, storage: vault, event: VaultEvent);

    const ACCRUING_INTEREST_APR_DECIMALS: u256 = 100;
    const MIN_LOAN_DURATION: u64 = 600;
    const MAX_ACCRUING_INTEREST_APR: u32 = 160000;

    // @note: duration in seconds

    // @note: 1 day
    const MIN_EXTENSION_DURATION: u64 = 86400;
    // @note: 90 days 
    const MAX_EXTENSION_DURATION: u64 = 86400 * 90;

    #[storage]
    struct Storage {
        loans: LegacyMap::<felt252, Loan>,
        extension_proposal_made: LegacyMap::<felt252, bool>,
        hub: IPwnHubDispatcher,
        loan_token: IPwnLoanDispatcher,
        config: IPwnConfigDispatcher,
        revoked_nonce: IRevokedNonceDispatcher,
        category_registry: IMultitokenCategoryRegistryDispatcher,
        #[substorage(v0)]
        vault: PwnVaultComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        LoanCreated: LoanCreated,
        LoanPaidBack: LoanPaidBack,
        LoanClaimed: LoanClaimed,
        LoanExtended: LoanExtended,
        ExtensionProposalMade: ExtensionProposalMade,
        VaultEvent: PwnVaultComponent::Event
    }

    #[derive(Drop, starknet::Event)]
    struct LoanCreated {
        loan_id: felt252,
        proposal_hash: felt252,
        proposal_contract: ContractAddress,
        refinancing_loan_id: felt252,
        terms: Terms,
        lender_spec: LenderSpec,
        extra: Array<felt252>
    }

    #[derive(Drop, starknet::Event)]
    struct LoanPaidBack {
        loan_id: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct LoanClaimed {
        loan_id: felt252,
        defaulted: bool
    }

    #[derive(Drop, starknet::Event)]
    struct LoanExtended {
        loan_id: felt252,
        original_default_timestamp: u64,
        extended_default_timestamp: u64,
    }

    #[derive(Drop, starknet::Event)]
    struct ExtensionProposalMade {
        extension_hash: felt252,
    // proposer: ContractAddress,
    // extension_proposal: ExtensionProposal,
    }

    #[constructor]
    fn constructor(
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
        let revoked_nonce_dispatcher = IRevokedNonceDispatcher { contract_address: revoked_nonce };
        let category_registry_dispatcher = IMultitokenCategoryRegistryDispatcher {
            contract_address: category_registry
        };
        self.hub.write(hub_dispatcher);
        self.loan_token.write(loan_token_dispatcher);
        self.config.write(config_dispatcher);
        self.revoked_nonce.write(revoked_nonce_dispatcher);
        self.category_registry.write(category_registry_dispatcher);
    }

    impl IPwnVault = PwnVaultComponent::InternalImpl<ContractState>;

    #[abi(embed_v0)]
    impl PwnSimpleLoanImpl of IPwnSimpleLoan<ContractState> {
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
                // @note: we shall move these error in a common place?
                simple_loan_proposal::SimpleLoanProposalComponent::Err::ADDRESS_MISSING_HUB_TAG(
                    addr: proposal_spec.proposal_contract, tag: pwn_hub_tags::LOAN_PROPOSAL
                );
            }

            if (caller_spec.revoke_nonce) {
                self
                    .revoked_nonce
                    .read()
                    .revoke_nonce(
                        nonce_space: Option::None,
                        owner: Option::Some(caller),
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

            if (caller != loan_terms.lender
                && loan_terms.lender_spec_hash != self.get_lender_spec_hash(lender_spec.clone())) {
                // @note: solidity code has current and expected in the error as well, similar to the INTEREST_APR_OUT_OF_BOUNDS error below
                error::Err::INVALID_LENDER_SPEC_HASH();
            }

            if (loan_terms.duration < MIN_LOAN_DURATION) {
                // @note: solidity code has current and limit in the error as well, similar to the INTEREST_APR_OUT_OF_BOUNDS error below
                error::Err::INVALID_DURATION();
            }

            if (loan_terms.accruing_interest_APR > MAX_ACCRUING_INTEREST_APR) {
                error::Err::INTEREST_APR_OUT_OF_BOUNDS(
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
                    Event::LoanCreated(
                        LoanCreated {
                            loan_id: loan_id,
                            proposal_hash: proposal_hash,
                            proposal_contract: proposal_spec.proposal_contract,
                            refinancing_loan_id: caller_spec.refinancing_loan_id,
                            terms: loan_terms.clone(),
                            lender_spec: lender_spec.clone(),
                            extra: extra.unwrap()
                        }
                    )
                );

            // @dev: abi.decode needs to implemented here for permit data
            // if (caller_spec.permit_data.len() > 0) {// some abi decode happening here
            // }

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

        fn repay_loan(ref self: ContractState, loan_id: felt252, permit_data: felt252) {
            let caller = starknet::get_caller_address();
            let loan = self.loans.read(loan_id);
            self._check_loan_can_be_repaid(loan.status, loan.default_timestamp);

            self._update_repaid_loan(loan_id);

            // @dev: abi.decode needs to be handled for permit data

            let repayment_amount = self.get_loan_repayment_amount(loan_id);
            self.vault._pull(ERC20(loan.credit_address, repayment_amount), caller);

            self.vault._push(loan.collateral, loan.borrower);

            self
                .try_claim_repaid_loan(
                    loan_id,
                    repayment_amount,
                    ERC721ABIDispatcher {
                        contract_address: self.loan_token.read().contract_address
                    }
                        .owner_of(loan_id.try_into().unwrap())
                );
        }

        fn claim_loan(ref self: ContractState, loan_id: felt252) {
            let loan = self.loans.read(loan_id);
            let caller = starknet::get_caller_address();
            let loan_token_owner = ERC721ABIDispatcher {
                contract_address: self.loan_token.read().contract_address
            }
                .owner_of(loan_id.try_into().unwrap());

            if (caller != loan_token_owner) {
                error::Err::CALLER_NOT_LOAN_TOKEN_HOLDER();
            }

            if (loan.status == 0) {
                error::Err::NON_EXISTING_LOAN();
            } else if (loan.status == 3) {
                self._settle_loan_claim(loan_id: loan_id, loan_owner: caller, defaulted: false);
            } else if (loan.status == 2
                && loan.default_timestamp <= starknet::get_block_timestamp()) {
                self._settle_loan_claim(loan_id: loan_id, loan_owner: caller, defaulted: true);
            } else {
                error::Err::LOAN_RUNNING();
            }
        }

        fn try_claim_repaid_loan(
            ref self: ContractState,
            loan_id: felt252,
            credit_amount: u256,
            loan_owner: ContractAddress
        ) {
            if (starknet::get_caller_address() != starknet::get_contract_address()) {
                error::Err::CALLER_NOT_VAULT();
            }

            let loan = self.loans.read(loan_id);

            if (loan.status != 3 || loan.original_lender != loan_owner) {
                return;
            }

            let destination_of_funds = loan.original_source_of_funds;

            let repayment_credit = ERC20(loan.credit_address, credit_amount);

            self._delete_loan(loan_id);

            self.emit(Event::LoanClaimed(LoanClaimed { loan_id: loan_id, defaulted: false }));

            if (credit_amount == 0) {
                return;
            }

            if (destination_of_funds == loan_owner) {
                self.vault._push(repayment_credit, loan_owner);
            } else {
                let pool_adapter = self.config.read().get_pool_adapter(destination_of_funds);
                if (pool_adapter.contract_address == Default::default()) {
                    error::Err::INVALID_SOURCE_OF_FUNDS(source_of_funds: destination_of_funds);
                }

                self
                    .vault
                    ._supply_to_pool(
                        repayment_credit, pool_adapter, destination_of_funds, loan_owner
                    );
            }
        }

        fn make_extension_proposal(ref self: ContractState, extension: ExtensionProposal) {
            let caller = starknet::get_caller_address();

            if (caller != extension.proposer) {
                error::Err::INVALID_EXTENSION_SINGNER(allowed: extension.proposer, current: caller);
            }

            let extension_hash = self.get_extension_hash(extension);
            self.extension_proposal_made.write(extension_hash, true);
            self
                .emit(
                    Event::ExtensionProposalMade(
                        ExtensionProposalMade { extension_hash: extension_hash }
                    )
                );
        }

        fn extend_loan(
            ref self: ContractState,
            extension: ExtensionProposal,
            signature: signature_checker::Signature,
            permit_data: Permit
        ) {
            let mut loan = self.loans.read(extension.loan_id);
            let caller = starknet::get_caller_address();

            if (loan.status == 0) {
                error::Err::NON_EXISTING_LOAN();
            }

            if (loan.status == 3) {
                error::Err::LOAN_REPAID();
            }

            let extension_hash = self.get_extension_hash(extension.clone());

            if (!self.extension_proposal_made.read(extension_hash)) {
                if (!signature_checker::is_valid_signature_now(
                    extension.proposer, extension_hash, signature
                )) {
                    signature_checker::Err::INVALID_SIGNATURE(
                        signer: extension.proposer, digest: extension_hash
                    );
                }
            }

            let current_block_timestamp = starknet::get_block_timestamp();

            if (current_block_timestamp >= extension.expiration) { // revert expired
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
                .owner_of(extension.loan_id.try_into().unwrap());

            if (caller == loan_owner) {
                if (extension.proposer != loan.borrower) {
                    error::Err::INVALID_EXTENSION_SINGNER(
                        allowed: loan.borrower, current: extension.proposer
                    );
                }
            } else if (caller == loan.borrower) {
                if (extension.proposer != loan_owner) {
                    error::Err::INVALID_EXTENSION_SINGNER(
                        allowed: loan_owner, current: extension.proposer
                    );
                }
            } else {
                error::Err::INVALID_EXTENSION_CALLER();
            }

            if (extension.duration < MIN_EXTENSION_DURATION) {
                error::Err::INVALID_EXTENSION_DURATION(
                    duration: extension.duration, limit: MIN_EXTENSION_DURATION
                );
            }

            if (extension.duration > MAX_EXTENSION_DURATION) {
                error::Err::INVALID_EXTENSION_DURATION(
                    duration: extension.duration, limit: MAX_EXTENSION_DURATION
                );
            }

            self
                .revoked_nonce
                .read()
                .revoke_nonce(
                    nonce_space: Option::Some(extension.nonce_space),
                    owner: Option::Some(extension.proposer),
                    nonce: extension.nonce
                );

            let original_default_timestamp = loan.default_timestamp;
            loan.default_timestamp = original_default_timestamp + extension.duration;

            self
                .emit(
                    Event::LoanExtended(
                        LoanExtended {
                            loan_id: extension.loan_id,
                            original_default_timestamp: original_default_timestamp,
                            extended_default_timestamp: loan.default_timestamp
                        }
                    )
                );

            if (extension.compensation_address != Default::default()
                && extension.compensation_amount > 0) {
                let compensation = ERC20(
                    extension.compensation_address, extension.compensation_amount
                );

                self._check_valid_asset(compensation);

                self._check_permit(extension.compensation_address, permit_data);

                // @dev add _try_permit here.
                // self._try_p

                self.vault._push_from(compensation, loan.borrower, loan_owner);
            }
            self.loans.write(extension.loan_id, loan);
        }

        fn get_lender_spec_hash(self: @ContractState, calladata: LenderSpec) -> felt252 {
            // posedian hash?
            0
        }

        fn get_loan_repayment_amount(self: @ContractState, loan_id: felt252) -> u256 {
            let loan = self.loans.read(loan_id);

            if (loan.status == 0) {
                return 0;
            }

            loan.principal_amount + self._loan_accrued_interest(loan)
        }

        fn get_extension_hash(self: @ContractState, extension: ExtensionProposal) -> felt252 {
            // hash again?
            0
        }

        fn get_loan(self: @ContractState, loan_id: felt252) -> GetLoanReturnValue {
            let loan = self.loans.read(loan_id);
            let loan_owner: ContractAddress = if (loan.status != 0) {
                ERC721ABIDispatcher { contract_address: self.loan_token.read().contract_address }
                    .owner_of(loan_id.try_into().unwrap())
            } else {
                Default::default()
            };
            let loan_return_value = GetLoanReturnValue {
                status: self._get_loan_status(loan_id),
                start_timestamp: loan.start_timestamp,
                default_timestamp: loan.default_timestamp,
                borrower: loan.borrower,
                original_lender: loan.original_lender,
                loan_owner: loan_owner,
                accruing_interest_APR: loan.accruing_interest_APR,
                fixed_interest_amount: loan.fixed_interest_amount,
                credit: ERC20(loan.credit_address, loan.principal_amount),
                collateral: loan.collateral,
                original_source_of_funds: loan.original_source_of_funds,
                repayment_amount: self.get_loan_repayment_amount(loan_id)
            };
            loan_return_value
        }

        fn get_is_valid_asset(self: @ContractState, asset: Asset) -> bool {
            asset.is_valid(Option::Some(self.category_registry.read().contract_address))
        }

        fn get_loan_metadata_uri(self: @ContractState) -> ByteArray {
            let this_contract = starknet::get_contract_address();
            self.config.read().loan_metadata_uri(this_contract)
        }

        fn get_state_fingerprint(self: @ContractState) -> felt252 {
            0
        }
    }

    #[generate_trait]
    impl Private of PrivateTrait {
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
                error::Err::REFINANCE_CREDIT_MISMATCH();
            }

            if (loan.collateral.category != loan_terms.collateral.category
                || loan.collateral.asset_address != loan_terms.collateral.asset_address
                || loan.collateral.id != loan_terms.collateral.id
                || loan.collateral.amount != loan_terms.collateral.amount) {
                error::Err::REFINANCE_COLLATERAL_MISMATCH();
            }

            if (loan.borrower != loan_terms.borrower) {
                error::Err::REFINANCE_BORROWER_MISMATCH(
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
                credit_helper.amount = fee_amount.try_into().unwrap();
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
            // @note: owner_of needs u256 and here the id is in felt252
            let loan_owner = erc721_dispatcher.owner_of(refinancing_loan_id.try_into().unwrap());
            let repayment_amount = self.get_loan_repayment_amount(refinancing_loan_id);
            let (fee_amount, new_loan_amount) = fee_calculator::calculate_fee_amount(
                self.config.read().get_fee(), loan_terms.credit.amount
            );
            let fee_amount: u256 = fee_amount.into();
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
            // @note: in solidity this was in try catch? shall we have it in match or something?
            // like Ok and error?
            self
                .try_claim_repaid_loan(
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
                error::Err::INVALID_SOURCE_OF_FUNDS(source_of_funds: lender_spec.source_of_funds);
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
                error::Err::NON_EXISTING_LOAN();
            }

            if (status != 2) {
                error::Err::LOAN_NOT_RUNNING();
            }
            let current_timestamp = starknet::get_block_timestamp();
            if (default_timestamp <= current_timestamp) {
                error::Err::LOAN_DEFAULTED(default_timestamp);
            }
        }

        fn _update_repaid_loan(ref self: ContractState, loan_id: felt252) {
            let mut loan = self.loans.read(loan_id);
            loan.status = 3;
            loan.fixed_interest_amount = self._loan_accrued_interest(loan.clone());
            loan.accruing_interest_APR = 0;
            self.loans.write(loan_id, loan);
            self.emit(Event::LoanPaidBack(LoanPaidBack { loan_id: loan_id }));
        }

        fn _loan_accrued_interest(self: @ContractState, loan: Loan) -> u256 {
            if (loan.accruing_interest_APR == 0) {
                return loan.fixed_interest_amount;
            }
            let current_timestamp = starknet::get_block_timestamp();
            // @note: here the timestamps are all in u64 and the loan.accruing_interest_APR is in u32
            //        we can change either one and then in order to use mul_div we need everyting in u256
            let accuring_minutes: u32 = ((current_timestamp - loan.start_timestamp) / 60)
                .try_into()
                .unwrap();
            let interest_amount: u256 = (loan.accruing_interest_APR * accuring_minutes)
                .try_into()
                .unwrap();
            let accured_interest = math::mul_div(
                loan.principal_amount, interest_amount, ACCRUING_INTEREST_APR_DECIMALS
            );
            loan.fixed_interest_amount + accured_interest
        }

        fn _settle_loan_claim(
            ref self: ContractState, loan_id: felt252, loan_owner: ContractAddress, defaulted: bool
        ) {
            let loan = self.loans.read(loan_id);
            let asset = match defaulted {
                true => loan.collateral,
                false => ERC20(
                    loan.credit_address, self.get_loan_repayment_amount(loan_id)
                ) // @note: needs to be updated
            };
            self._delete_loan(loan_id);
            self.emit(Event::LoanClaimed(LoanClaimed { loan_id: loan_id, defaulted: defaulted }));
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
                error::Err::INVALID_MULTITOKEN_ASSET(
                    category: asset.category.into(),
                    address: asset.asset_address,
                    id: asset.id,
                    amount: asset.amount
                );
            }
        }
    }
}
