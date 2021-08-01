#!/usr/bin/env python3

# TODO:
#   - Separate Policy into Keys, Policy and Keys X Policy with the policy ID
#   - Add documentation
#   - refactor into multiple files, this is getting out of hand.
#   - start to persist data in a database
#   - implement the setup function
#   - Avoid pitfall: Refunding the vending system's own transaction
#   - requirements.txt

import os
import itertools
import json
import math
import logging
import sqlite3
import subprocess

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import relationship
from sqlalchemy.orm import declarative_base

import config
import utils
from models.NFT import NFT
from models.Policy import Policy
from models.Project import Project
from models.RelSaleSizeProject import RelSaleSizeProject
from models.Reserve import Reserve
from models.SaleSize import SaleSize
from models.Wallet import Wallet
from models.base import Base

"""
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
    - Refresh metadata (re-mint)
    - Burn
    - istanciate wallet instance as files
"""

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=config.LOG_LEVEL,
)
logger = logging.getLogger(__name__)


def main():
    setup()

    wallet = create_wallet()

    input(f"Send funds to this address: {wallet.payment_addr}")


    protocol = get_network_protocol()
    print("Protocol:", json.dumps(protocol, indent=4))

    policy = create_policy_keys()
    print("Policy Keys:", policy)

    policy = create_policy_script(policy, before=43380124)
    print("Policy script:", policy)

    policy.policy_id = calculate_policy_id(policy)
    print("Policy ID:", policy.policy_id)

    mint(
        [
            {
                "policyId": policy.policy_id,
                "assetName": "TestCoin",
                "amount": 1,
                "metadata": {"some_metadata": "value"},
                "addr": "addr_test1qqkjpcvjxwttvznw04psr3darq8nr7yme7xk22a432uey50x4vrecn8ys8mdy4jp6xclnxet9h89pyrf2k5gtdnvtjasglwj3q",
            }
        ],
        wallet,
        policy,
        excess_addr="addr_test1qqkjpcvjxwttvznw04psr3darq8nr7yme7xk22a432uey50x4vrecn8ys8mdy4jp6xclnxet9h89pyrf2k5gtdnvtjasglwj3q",
    )


def setup():
    # Create the working directory if it does not exist
    if not os.path.exists(config.WORKING_DIRECTORY):
        os.makedirs(config.WORKING_DIRECTORY)

def calculate_policy_id(policy):
    # The main data we'll return as output
    policy_id = ""

    # To avoid collisions a large random hexstring is prepended to filenames
    random_id = utils.create_random_id()

    with open(f"{config.WORKING_DIRECTORY}/{random_id}_policy.script", "w") as f_out:
        print(policy.policy_script, file=f_out)

    completed = subprocess.run(
        [
            config.CLI_PATH,
            "transaction",
            "policyid",
            "--script-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_policy.script",
        ],
        check=True,
        env=get_execution_environment(),
        capture_output=True,
    )

    policy_id = completed.stdout.decode().strip()

    # CLEANUP
    cleanup_files = ["policy.script"]
    cleanup(random_id, cleanup_files)

    return policy_id


def get_network_protocol():
    protocol = {}

    random_id = utils.create_random_id()

    completed = subprocess.run(
        [
            config.CLI_PATH,
            "query",
            "protocol-parameters",
            "--out-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_protocol.json",
            *get_network_param(),
        ],
        check=True,
        env=get_execution_environment(),
    )

    with open(f"{config.WORKING_DIRECTORY}/{random_id}_protocol.json") as f_in:
        protocol = json.load(f_in)

    # CLEANUP
    cleanup_files = ["protocol.json"]
    cleanup(random_id, cleanup_files)

    return protocol


def query_wallet(wallet):
    utxos = {}

    random_id = utils.create_random_id()

    try:
        completed = subprocess.run(
            [
                config.CLI_PATH,
                "query",
                "utxo",
                "--address",
                wallet["payment_addr"],
                "--out-file",
                f"{config.WORKING_DIRECTORY}/{random_id}_utxos.json",
                *get_network_param(),
            ],
            check=True,
            env=get_execution_environment(),
        )
    except subprocess.CalledProcessError as exception:
        logger.critical(
            "Could not query wallet. Do you have permission to access the node.socket?"
        )
        if not config.MAINNET:
            logger.warn("This could be caused by a mismatch in testnet magic")
        raise exception

    with open(f"{config.WORKING_DIRECTORY}/{random_id}_utxos.json") as f_in:
        utxos = json.load(f_in)

    # CLEANUP
    cleanup_files = ["utxos.json"]
    cleanup(random_id, cleanup_files)

    return utxos


def create_policy_script(old_policy, before=-1, after=-1):
    policy = Policy(id=old_policy.id, policy_vkey=old_policy.policy_vkey, policy_skey=old_policy.policy_skey)

    # Main data structure to be filled using CLI commands
    policy_script = {
        "type": "all",
        "scripts": [],
    }

    # To avoid collisions a large random hexstring is prepended to filenames
    random_id = utils.create_random_id()

    if not before < 0:
        policy_script["scripts"].append({"slot": before, "type": "before"})
        policy.before = before

    if not after < 0:
        policy_script["scripts"].append({"slot": before, "type": "after"})
        policy.after = after

    keyHash = ""

    with open(f"{config.WORKING_DIRECTORY}/{random_id}_policy.vkey", "w") as f_out:
        print(policy.policy_vkey, file=f_out)


    subprocess.run(
        [
            config.CLI_PATH,
            "address",
            "key-hash",
            "--payment-verification-key-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_policy.vkey",
            "--out-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_policy.hash",
        ],
        check=True,
        env=get_execution_environment(),
    )

    with open(f"{config.WORKING_DIRECTORY}/{random_id}_policy.hash") as f_in:
        keyHash = f_in.read().strip()

    policy_script["scripts"].append({"keyHash": keyHash, "type": "sig"})

    policy.policy_script = json.dumps(policy_script, indent=4)

    # CLEANUP
    cleanup_files = ["policy.vkey", "policy.hash"]
    cleanup(random_id, cleanup_files)

    return policy


def create_wallet():
    # Main data structure to be filled using CLI commands
    wallet = Wallet()

    # To avoid collisions a large random hexstring is prepended to filenames
    random_id = utils.create_random_id()

    # Create Staking Keys
    logger.debug(f"Start generating staking keys for ID {random_id}")
    completed = subprocess.run(
        [
            config.CLI_PATH,
            "stake-address",
            "key-gen",
            "--verification-key-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_stake.vkey",
            "--signing-key-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_stake.skey",
        ],
        check=True,
        env=get_execution_environment(),
    )
    with open(f"{config.WORKING_DIRECTORY}/{random_id}_stake.vkey") as f_in:
        wallet.staking_vkey = json.load(f_in)
    with open(f"{config.WORKING_DIRECTORY}/{random_id}_stake.skey") as f_in:
        wallet.staking_skey = json.load(f_in)
    logger.debug(f"End generating staking keys for ID {random_id}")

    # Generate payment keys
    logger.debug(f"Start generating payment keys for ID {random_id}")
    completed = subprocess.run(
        [
            config.CLI_PATH,
            "address",
            "key-gen",
            "--verification-key-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_payment.vkey",
            "--signing-key-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_payment.skey",
        ],
        check=True,
        env=get_execution_environment(),
    )
    with open(f"{config.WORKING_DIRECTORY}/{random_id}_payment.vkey") as f_in:
        wallet.payment_vkey = json.load(f_in)
    with open(f"{config.WORKING_DIRECTORY}/{random_id}_payment.skey") as f_in:
        wallet.payment_skey = json.load(f_in)
    logger.debug(f"End generating payment keys for ID {random_id}")

    # Generate payment address
    logger.debug(f"Start generating payment address for ID {random_id}")
    completed = subprocess.run(
        [
            config.CLI_PATH,
            "address",
            "build",
            "--payment-verification-key-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_payment.vkey",
            "--stake-verification-key-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_stake.vkey",
            "--out-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_payment.addr",
            *get_network_param(),
        ],
        check=True,
        env=get_execution_environment(),
    )
    with open(f"{config.WORKING_DIRECTORY}/{random_id}_payment.addr") as f_in:
        wallet.payment_addr = f_in.read().strip()
    logger.debug(f"End generating payment address for ID {random_id}")

    # CLEANUP
    cleanup_files = [
        "payment.vkey",
        "payment.skey",
        "payment.addr",
        "stake.vkey",
        "stake.skey",
    ]
    cleanup(random_id, cleanup_files)

    return wallet


def create_policy_keys():
    # Main data structure to be filled using CLI commands
    policy = Policy()

    # To avoid collisions a large random hexstring is prepended to filenames
    random_id = utils.create_random_id()

    logger.debug(f"Start generating policy keys ID {random_id}")
    completed = subprocess.run(
        [
            config.CLI_PATH,
            "address",
            "key-gen",
            "--verification-key-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_policy.vkey",
            "--signing-key-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_policy.skey",
        ],
        check=True,
        env=get_execution_environment(),
    )
    with open(f"{config.WORKING_DIRECTORY}/{random_id}_policy.vkey") as f_in:
        policy.policy_vkey = f_in.read()
    with open(f"{config.WORKING_DIRECTORY}/{random_id}_policy.skey") as f_in:
        policy.policy_skey = f_in.read()
    logger.debug(f"End generating payment address for ID {random_id}")

    # CLEANUP
    cleanup_files = ["policy.skey", "policy.vkey"]
    cleanup(random_id, cleanup_files)

    return policy


def mint(assets, wallet, policy, tx_ins=[], excess_addr=""):
    """
    Mints a single transaction

    ...

    Parameters
    ----------
    assets: list of dicts in the form {'policyId':'', 'assetName':'', 'amount':0, 'metadata':{}, 'addr':''} # << Maybe standardize this into a data class
    wallet: Instance of a Wallet class / datastructure
        Transactions from this wallet will be consumed to mint and send the tokens
    tx_in : list of strings (optional)
        A list of transactions to be consumed for the minting transaction
        For some NFTs it may be required to consume the incoming transactions.
        In this case only the selected transactions will be consumed.
        Otherwise any amount of transactions may be used.

        Right now optimizing the reduction of transaction cost will not be focussed due to higher priority tasks.
        This may result in undesirable consumption of transactions.
        It could be possible that transactions are bundled which each contain one native token and its min-ADA value which could significantly increase the amount of data in the transaction.
    excess_addr: str (optional)
        The address where all leftover assets should be sent to

    Returns
    -------
    ???
    """
    # High level flow:
    #   1. Create transaction with zero fees
    #   2. Calculate the fee
    #   3. Create transaction with correct fees
    #   4. Sign the transaction
    #   5. Submit the Transaction

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

    # To avoid collisions a large random hexstring is prepended to filenames
    random_id = utils.create_random_id()

    minting_input_transactions = []
    # Get the wallet's TX_INs if tx_in is unspecified
    if tx_ins:
        minting_input_transactions = tx_ins
    else:
        minting_input_transactions = [
            tx for tx in query_wallet({"payment_addr": wallet.payment_addr})
        ]

    # Calculate the TX_OUTs
    # 1. list all available resources (lovelaces and tokens)
    available_resources = {}
    utxos = query_wallet({"payment_addr": wallet.payment_addr})
    for tx in utxos:
        if tx not in minting_input_transactions:
            continue
        for asset in utxos[tx]["value"]:
            if asset == "lovelace":
                if not "lovelace" in available_resources:
                    available_resources["lovelace"] = 0
                available_resources["lovelace"] += utxos[tx]["value"]["lovelace"]
            else:
                for token_name in utxos[tx]["value"][asset]:
                    if not f"{asset}.{token_name}" in available_resources:
                        available_resources[f"{asset}.{token_name}"] = 0
                    available_resources[f"{asset}.{token_name}"] += utxos[tx]["value"][
                        asset
                    ][token_name]

    # 2. for all assets required, add the 'amount' to the available resources
    # {'policyId':'', 'assetName':'', 'amount':0, 'metadata':{}, 'addr':''}
    for asset in assets:
        if not f'{asset["policyId"]}.{asset["assetName"]}' in available_resources:
            available_resources[f'{asset["policyId"]}.{asset["assetName"]}'] = 0

        available_resources[f'{asset["policyId"]}.{asset["assetName"]}'] += asset[
            "amount"
        ]
    # 3. list all the output addresses and assign the resources to be sent there
    out_addresses = set(asset["addr"] for asset in assets)
    tx_out = {}
    for addr in out_addresses:
        tx_out[addr] = {}
        for asset in assets:
            if asset["addr"] == addr:
                if not f'{asset["policyId"]}.{asset["assetName"]}' in tx_out[addr]:
                    tx_out[addr][f'{asset["policyId"]}.{asset["assetName"]}'] = 0
                tx_out[addr][f'{asset["policyId"]}.{asset["assetName"]}'] += asset[
                    "amount"
                ]
                available_resources[
                    f'{asset["policyId"]}.{asset["assetName"]}'
                ] -= asset["amount"]

    # 4. calculate the min ada for each address
    for addr in tx_out:
        addr_assets = []
        for asset in tx_out[addr]:
            addr_assets.append(
                {"name": asset.split(".")[1], "policyID": asset.split(".")[0]}
            )
        if not "lovelace" in tx_out[addr]:
            tx_out[addr]["lovelace"] = 0
        min_ada = calculate_min_ada(addr_assets)
        tx_out[addr]["lovelace"] += min_ada
        available_resources["lovelace"] -= min_ada

    empty_resources = []
    for resource in available_resources:
        if available_resources[resource] <= 0:
            empty_resources.append(asset)

    for resource in empty_resources:
        del available_resources[resource]

    # 5. unless an excess addr is specified, all remaining tokens and lovelaces go back to the wallet
    if not excess_addr:
        excess_addr = wallet.payment_addr

    if not excess_addr in tx_out:
        tx_out[excess_addr] = {}
    for resource in available_resources:
        if not resource in tx_out[excess_addr]:
            tx_out[excess_addr][resource] = 0
        tx_out[excess_addr][resource] += available_resources[resource]

    tx_out_formatted = []
    for addr in tx_out:
        tx_out_formatted.append("--tx-out")
        resourcestring = ""
        for resource in tx_out[addr]:
            if resource == "lovelace":
                resourcestring = f"{addr}+{tx_out[addr][resource]}" + resourcestring
            else:
                resourcestring = (
                    resourcestring + f"+{tx_out[addr][resource]} {resource}"
                )
        tx_out_formatted.append(resourcestring)

    metadata = {"721": {"version": 1}}
    for asset in assets:
        if not asset["policyId"] in metadata:
            metadata["721"][asset["policyId"]] = {}
        metadata["721"][asset["policyId"]][asset["assetName"]] = asset["metadata"]
    with open(f"{config.WORKING_DIRECTORY}/{random_id}_metadata.json", "w") as f_out:
        json.dump(metadata, f_out, indent=4)

    with open(f"{config.WORKING_DIRECTORY}/{random_id}_policy.script", "w") as f_out:
        print(policy.policy_script, file=f_out)

    process_parameters = [
        config.CLI_PATH,
        "transaction",
        "build-raw",
        "--fee",
        "0",  # Set fees to zero in order to calculate them in the next step
        *list(
            itertools.chain.from_iterable(
                ["--tx-in", tx_in] for tx_in in minting_input_transactions
            )
        ),
        *tx_out_formatted,
        *list(
            itertools.chain.from_iterable(
                [
                    [
                        "--mint",
                        f'{asset["amount"]} {asset["policyId"]}.{asset["assetName"]}',
                    ]
                    for asset in assets
                ]
            )
        ),
        "--out-file",
        f"{config.WORKING_DIRECTORY}/{random_id}_free_tx.raw",
    ]
    if len(assets):
        process_parameters += [
            "--minting-script-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_policy.script",
            "--metadata-json-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_metadata.json",
        ]
        for script in json.loads(policy.policy_script)["scripts"]:
            if script["type"] == "before":
                process_parameters.append("--invalid-hereafter")
                process_parameters.append(str(script["slot"]))
            if script["type"] == "after":
                process_parameters.append("--invalid-before")
                process_parameters.append(str(script["slot"]))

    completed = subprocess.run(
        process_parameters,
        check=True,
        env=get_execution_environment(),
        capture_output=True,
    )

    tx_fee = calculate_fee(
        tx_out_count=len(tx_out),
        tx_in_count=len(minting_input_transactions),
        random_id=random_id,
    )

    tx_out[excess_addr]["lovelace"] -= tx_fee

    tx_out_formatted = []
    for addr in tx_out:
        tx_out_formatted.append("--tx-out")
        resourcestring = ""
        for resource in tx_out[addr]:
            if resource == "lovelace":
                resourcestring = f"{addr}+{tx_out[addr][resource]}" + resourcestring
            else:
                resourcestring = (
                    resourcestring + f"+{tx_out[addr][resource]} {resource}"
                )
        tx_out_formatted.append(resourcestring)

    process_parameters = [
        config.CLI_PATH,
        "transaction",
        "build-raw",
        "--fee",
        str(tx_fee),  # Set fees to zero in order to calculate them in the next step
        *list(
            itertools.chain.from_iterable(
                ["--tx-in", tx_in] for tx_in in minting_input_transactions
            )
        ),
        *tx_out_formatted,
        *list(
            itertools.chain.from_iterable(
                [
                    [
                        "--mint",
                        f'{asset["amount"]} {asset["policyId"]}.{asset["assetName"]}',
                    ]
                    for asset in assets
                ]
            )
        ),
        "--out-file",
        f"{config.WORKING_DIRECTORY}/{random_id}_tx.raw",
    ]
    if len(assets):
        process_parameters += [
            "--minting-script-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_policy.script",
            "--metadata-json-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_metadata.json",
        ]
        for script in json.loads(policy.policy_script)["scripts"]:
            if script["type"] == "before":
                process_parameters.append("--invalid-hereafter")
                process_parameters.append(str(script["slot"]))
            if script["type"] == "after":
                process_parameters.append("--invalid-before")
                process_parameters.append(str(script["slot"]))

    completed = subprocess.run(
        process_parameters,
        check=True,
        env=get_execution_environment(),
        capture_output=True,
    )

    with open(f"{config.WORKING_DIRECTORY}/{random_id}_payment.skey", "w") as f_out:
        json.dump(wallet.payment_skey, f_out, indent=4)

    with open(f"{config.WORKING_DIRECTORY}/{random_id}_policy.skey", "w") as f_out:
        print(policy.policy_skey, file=f_out)

    completed = subprocess.run(
        [
            config.CLI_PATH,
            "transaction",
            "sign",
            "--signing-key-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_payment.skey",
            "--signing-key-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_policy.skey",
            *get_network_param(),
            "--tx-body-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_tx.raw",
            "--out-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_signed_tx.raw",
        ],
        check=True,
        env=get_execution_environment(),
    )

    completed = subprocess.run(
        [
            config.CLI_PATH,
            "transaction",
            "submit",
            "--tx-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_signed_tx.raw",
            *get_network_param(),
        ],
        check=True,
        env=get_execution_environment(),
    )

    # CLEANUP
    cleanup_files = [
        "free_tx.raw",
        "tx.raw",
        "signed_tx.raw",
        "metadata.json",
        "policy.script",
        "payment.skey",
        "policy.skey",
    ]
    # cleanup(random_id, cleanup_files)

    pass


def calculate_fee(tx_out_count, tx_in_count, random_id):
    protocol = get_network_protocol()
    with open(f"{config.WORKING_DIRECTORY}/{random_id}_protocol.json", "w") as f_out:
        json.dump(protocol, f_out, indent=4)

    completed = subprocess.run(
        [
            config.CLI_PATH,
            "transaction",
            "calculate-min-fee",
            "--tx-body-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_free_tx.raw",
            "--tx-in-count",
            str(tx_in_count),
            "--tx-out-count",
            str(tx_out_count),
            "--witness-count",
            "1",  # for now no multisig
            *get_network_param(),
            "--protocol-params-file",
            f"{config.WORKING_DIRECTORY}/{random_id}_protocol.json",
        ],
        check=True,
        env=get_execution_environment(),
        capture_output=True,
    )

    cleanup_files = ["protocol.json"]
    cleanup(random_id, cleanup_files)

    return int(completed.stdout.decode().split()[0])


def vend():
    pass


#############
### UTILS ###
#############


def get_network_param():
    network_param = []

    # Depending on the configuration we'll either need to provide:
    # the "--mainnet" flag or
    # the "--testnet-magic TESTNETMAGIC" parameter
    if config.MAINNET:
        network_param = ["--mainnet"]
    else:
        network_param = ["--testnet-magic", str(config.TESTNET_MAGIC)]

    return network_param


def cleanup(random_id, cleanup_files):
    logger.debug(f"Start cleanup for ID {random_id}")
    for cleanup_file in cleanup_files:
        try:
            os.remove(f"{config.WORKING_DIRECTORY}/{random_id}_{cleanup_file}")
        except FileNotFoundError:
            logger.error(
                f"Failed to delete {config.WORKING_DIRECTORY}/{random_id}_{cleanup_file} : FileNotFound"
            )
    logger.debug(f"End cleanup for ID {random_id}")

def get_execution_environment():
    env = os.environ.copy()
    env["CARDANO_NODE_SOCKET_PATH"] = config.NODE_IPC
    return env


def calculate_min_ada(assets):
    # TODO Accept a list of NFT classes
    """
    Calculates the minADA for 
    assets = [
        {'name':'ASSETNAME', 'policyID':''}
    ]
    """
    policy_hash_size = 28  # Shelley and Goguen value
    bytes_in_word = 8  # required to round bytes up to the next word
    ada_per_utxo_word = 37037  # Min ADA per WORD
    min_ada = 1000000  # One full ADA as base minimum in a transaction

    policyid_amount = len(set([asset["policyID"] for asset in assets]))

    utxo_words = policyid_amount * 12
    for asset in assets:
        utxo_words += len(asset["name"]) + policy_hash_size

    # Round up to the nearest full word
    utxo_words = 6 + math.floor((utxo_words + (bytes_in_word - 1)) / bytes_in_word)

    # Calculate how many lovelaces this locks
    lovelaces = utxo_words * ada_per_utxo_word
    nft_ada = min_ada + lovelaces

    return nft_ada


if __name__ == "__main__":
    main()
