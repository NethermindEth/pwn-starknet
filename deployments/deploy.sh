#!/bin/bash

ACTIVE_LOAN=0x0256ea094d7a53440eef11fa42b63159fbf703b4ee579494a6ae85afc5603594

# Load the addresses from the declared-classes.txt file based on STARKNET_NETWORK
declare -A class_hashes
declare -A addresses

input_file="deployments/$STARKNET_NETWORK/declared-classes.txt"

while IFS= read -r line; do
    contract_name=$(echo "$line" | cut -d ':' -f 1 | xargs)
    class_hash=$(echo "$line" | cut -d ' ' -f 2 | xargs)

    class_hashes["$contract_name"]=$class_hash
done < "$input_file"

hub_class_hash=${class_hashes["PwnHub"]}
echo "PwnHub class hash: $hub_class_hash"
config_class_hash=${class_hashes["PwnConfig"]}
echo "PwnConfig class hash: $config_class_hash"
nonce_class_hash=${class_hashes["RevokedNonce"]}
simple_loan_simple_proposal_class_hash=${class_hashes["SimpleLoanSimpleProposal"]}
simple_loan_fungible_proposal_class_hash=${class_hashes["SimpleLoanFungibleProposal"]}
simple_loan_dutch_auction_proposal_class_hash=${class_hashes["SimpleLoanDutchAuctionProposal"]}
simple_loan_list_proposal_class_hash=${class_hashes["SimpleLoanListProposal"]}
pwn_loan_class_hash=${class_hashes["PwnLoan"]}
multi_token_category_registry_class_hash=${class_hashes["MultiTokenCategoryRegistry"]}
pwn_simple_loan_class_hash=${class_hashes["PwnSimpleLoan"]}

# Determine the file path for the output based on the STARKNET_NETWORK environment variable
output_dir="deployments/$STARKNET_NETWORK"
output_file="$output_dir/deployed-contracts.txt"

# Create the directory if it doesn't exist
mkdir -p "$output_dir"

# Remove existing deployed-contracts.txt file if it exists
rm -f "$output_file"

# Deploy each contract and save the address
# PwnHub
echo "Deploying PwnHub..."
hub_address=$(starkli deploy "$hub_class_hash" -w)
echo "PwnHub: $hub_address" >> "$output_file"
echo "PwnHub address: $hub_address"
echo " "

# PwnConfig 
echo "Deploying PwnConfig..."
config_address=$(starkli deploy "$config_class_hash"  -w)
echo "PwnConfig: $config_address" >> "$output_file"
echo "PwnConfig address: $config_address"
echo " "

# RevokedNonce
echo "Deploying RevokedNonce..."
nonce_address=$(starkli deploy "$nonce_class_hash" "$hub_address" "$ACTIVE_LOAN"  -w)
echo "RevokedNonce: $nonce_address" >> "$output_file"
echo "RevokedNonce address: $nonce_address"
echo " "

# SimpleLoanSimpleProposal
echo "Deploying SimpleLoanSimpleProposal..."
proposal_simple_address=$(starkli deploy "$simple_loan_simple_proposal_class_hash" "$hub_address" "$nonce_address" "$config_address" -w)
echo "SimpleLoanSimpleProposal: $proposal_simple_address" >> "$output_file"
echo "SimpleLoanSimpleProposal address: $proposal_simple_address"
echo " "

# SimpleLoanFungibleProposal
echo "Deploying SimpleLoanFungibleProposal..."
proposal_fungible_address=$(starkli deploy "$simple_loan_fungible_proposal_class_hash" "$hub_address" "$nonce_address" "$config_address" -w)
echo "SimpleLoanFungibleProposal: $proposal_fungible_address" >> "$output_file"
echo "SimpleLoanFungibleProposal address: $proposal_fungible_address"
echo " "

# SimpleLoanDutchAuctionProposal
echo "Deploying SimpleLoanDutchAuctionProposal..."
proposal_dutch_address=$(starkli deploy "$simple_loan_dutch_auction_proposal_class_hash" "$hub_address" "$nonce_address" "$config_address" -w)
echo "SimpleLoanDutchAuctionProposal: $proposal_dutch_address" >> "$output_file"
echo "SimpleLoanDutchAuctionProposal address: $proposal_dutch_address"
echo " "

# SimpleLoanListProposal
echo "Deploying SimpleLoanListProposal..."
proposal_list_address=$(starkli deploy "$simple_loan_list_proposal_class_hash" "$hub_address" "$nonce_address" "$config_address" -w)
echo "SimpleLoanListProposal: $proposal_list_address" >> "$output_file"
echo "SimpleLoanListProposal address: $proposal_list_address"
echo " "

# PwnLoan
echo "Deploying PwnLoan..."
loan_token_address=$(starkli deploy "$pwn_loan_class_hash" "$hub_address"  -w)
echo "PwnLoan: $loan_token_address" >> "$output_file"
echo "PwnLoan address: $loan_token_address"
echo " "

# MultiTokenCategoryRegistry
echo "Deploying MultiTokenCategoryRegistry..."
registry_address=$(starkli deploy "$multi_token_category_registry_class_hash"  -w)
echo "MultiTokenCategoryRegistry: $registry_address" >> "$output_file"
echo "MultiTokenCategoryRegistry address: $registry_address"
echo " "

# PwnSimpleLoan
echo "Deploying PwnSimpleLoan..."
loan_address=$(starkli deploy "$pwn_simple_loan_class_hash" "$hub_address" "$loan_token_address" "$config_address" "$nonce_address" "$registry_address"  -w)
echo "PwnSimpleLoan: $loan_address" >> "$output_file"
echo "PwnSimpleLoan address: $loan_address"
echo " "
