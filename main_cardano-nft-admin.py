#!/usr/bin/env python3
import math
import logging
import sqlite3

import config

'''
Possible actions from the CLI:
    - Setup randomized data
    - Apply vanity policy ID data
    - Vend
        - Process payment and mint
        - Process payment and send out
        - Refund erroneous and oversupplied transactions
        - Support both a single wallet (mvp) and one wallet per purchase
        - Handle reservations
    - Mint once
    - Refresh metadata

'''

logging.basicConfig(format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=config.LOG_LEVEL)
logger = logging.getLogger(__name__)

def main():
    pass

def mint(tx_ins, assets, wallet, excess_addr=''):
    '''
    Mints a single transaction

    ...

    Parameters
    ----------
    tx_in : list of strings
        A list of transactions to be consumed for the minting transaction
    assets: list of dicts in the form {'policyId':'', 'assetName':'', 'amount':0, 'metadata':{}, 'addr':''} # << Maybe standardize this into a data class
    wallet: Instance of a Wallet class
    excess_addr: str
        The address where all leftover assets should be sent to

    Returns
    -------
    ???
    '''
    # High level flow:
    #   1. Create transaction with zero fees
    #   2. Calculate the fee
    #   3. Create transaction with correct fees
    #   4. Sign the transaction
    #   5. Submit the Transaction

    # Detailled flow:
    #   1. Create transaction with zero fees
    #   1.1 Extract all assets contained in the tx_ins
    #   1.2 Extract target wallets from assets
    #   1.3 Calculate the minADA required for each recipient
    #   1.4 Check if the policy has "invalid-before" or "invalid-hereafter"
    #   1.5 If input and output assets are not the same, add minting information
    #   1.6 The minting information must be readable from the database and made accessible to the cli via files
    #   1.7 Write the transaction to a file 
    #
    #   2. Calculate the fee
    #   2.1 Call the appropriate cli function and read out the stdout
    #
    #   3. Create the transaction with correct fees
    #   3.1 See "1. Create transaction with zero fees" but with fees
    #
    #   4. Sign the transaction
    #   4.1 Provide the policy script and key as files
    #   4.1 Provide the payment key as a file
    #   4.3 Call the cli method to sign using the former
    #
    #   5. Submit the Transaction
    #   5.1 Call submit using the CLI
    #   5.2 Validate the output
    pass

def vend():
    pass

#############
### UTILS ###
#############

def calculate_min_ada(assets):
    '''
    Calculates the minADA for 
    assets = [
        {'name':'ASSETNAME', 'policyID':''}
    ]
    '''
    policy_hash_size = 28       # Shelley and Goguen value
    bytes_in_word = 8           # required to round bytes up to the next word
    ada_per_utxo_word = 37037   # Min ADA per WORD
    min_ada = 1000000           # One full ADA as base minimum in a transaction

    policyid_amount = len(set([asset['policyID'] for asset in assets]))

    utxo_words = (policyid_amount * 12)
    for asset in assets:
        utxo_words += len(asset['name']) + policy_hash_size
    
    # Round up to the nearest full word
    utxo_words = 6 + math.floor((utxo_words + (bytes_in_word - 1)) / bytes_in_word)

    # Calculate how many lovelaces this locks
    lovelaces = utxo_words * ada_per_utxo_word
    nft_ada = min_ada + lovelaces

    return nft_ada

if __name__ == '__main__':
        main()
