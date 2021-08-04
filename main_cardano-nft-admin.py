#!/usr/bin/env python3

# TODO:
#   - Separate Policy into Keys, Policy and Keys X Policy with the policy ID
#   - Add documentation
#   - refactor into multiple files, this is getting out of hand.
#   - start to persist data in a database
#   - implement the setup function
#   - Avoid pitfall: Refunding the vending system's own transaction
#   - requirements.txt
#   - Refactor NFTs to "asset" which have a max amount and an amount of already minted tokens
#           This will help to support FT projects, too

import os
import time
import itertools
import json
import math
import logging
import sqlite3
import subprocess
import random

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import relationship
from sqlalchemy.orm import declarative_base

import config
import utils
from models.Mint import Mint
from models.Token import Token
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
    engine = create_engine(config.DB_CONNECTION_STRING, echo=False)
    setup(engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    print("Creating wallet")
    wallet = create_wallet()

    print("Creating policy keys")
    policy = create_policy_keys()

    print("Creating policy")
    policy = create_policy_script(policy, before=38848203) # mainnet, end of august '21
    policy.policy_id = calculate_policy_id(policy)
    print("Policy ID:", policy.policy_id)

    for salesize in [1, 3, 10]:
        if not session.query(SaleSize).filter(SaleSize.amount == salesize).count():
            session.add(SaleSize(amount=salesize))

    session.add(wallet)
    session.add(policy)
    session.commit()
    # The above code tests if the creation of the files still works

    wallet = session.query(Wallet).filter(Wallet.id == 1).first()
    policy = session.query(Policy).filter(Policy.id == 1).first()

    if not session.query(Project).filter(Project.project_name.like("%My Project%")).count():
        project = Project(policy_id=policy.id, wallet_id=wallet.id, project_name="This is My Project Number One", dynamic=False, lock_sales=False, price=88000000)
    else:
        project = session.query(Project).filter(Project.project_name.like("%My Project%")).first()

    for salesize in [1, 3, 10]:
        salesize = session.query(SaleSize).filter(SaleSize.amount == salesize).first()
        if not session.query(RelSaleSizeProject).filter(RelSaleSizeProject.project_id == project.id).filter(RelSaleSizeProject.salesize_id == salesize.id).count():
            project_salesize = RelSaleSizeProject(project_id=project.id, salesize_id=salesize.id)
            session.add(project_salesize)
    session.commit()

    session.add(project)
    session.commit()


    assets = []
    mint_idx = 0
    for k in range(3):
        asset_name = f'sometoken{k+1:02d}'
        if not session.query(Token).filter(Token.project_id==project.id).filter(Token.asset_name==asset_name).count():
            asset = Token()
            asset.asset_name = asset_name
            asset.minted = 0
            asset.max_mints = 1
            asset.token_metadata = json.dumps({
                "name": "Some Token",
                "ID": f"{k+1}/20",
            })
            asset.project_id = project.id # replaces policy ID, policy is attainable via project
            asset.sent_out = 0
            asset.start_idx = mint_idx
            asset.start_idx = mint_idx + asset.max_mints - 1
            mint_idx += asset.max_mints
            session.add(asset)
        else:
            asset = session.query(Token).filter(Token.project_id==project.id).filter(Token.asset_name==asset_name).first()
        assets.append(asset)
    session.commit()

    mintages = []
    for asset in assets:
        mintage = Mint()
        mintage.token_id = asset.id
        mintage.amount = 1
        mintage.addr = 'addr_test1qq6szayuhmlh3pt2jvtw50zlpvmxmlfndfr5s86ls90aynhx4vrecn8ys8mdy4jp6xclnxet9h89pyrf2k5gtdnvtjaslxgsc0'
        mintage.in_progress = False
        mintage.completed = False
        session.add(mintage)
        mintages.append(mintage)
    session.commit()


    free_tokens = session.query(Token).filter(Token.project_id==project.id).filter(Token.sent_out < Token.max_mints).filter(Token.id.not_in(session.query(Reserve).with_entities(Reserve.token_id).filter(Reserve.project_id == project.id))).all()

    reserve = Reserve()
    reserve.project_id = project.id
    reserve.dust = random.randint(2000000, 4000000) # TODO make sure that's not an already occupied value
    reserve.token_id = random.choice(free_tokens).id
    session.add(reserve)
    session.commit()

    free_tokens = session.query(Token).filter(Token.project_id==project.id).filter(Token.sent_out < Token.max_mints).filter(Token.id.not_in(session.query(Reserve).with_entities(Reserve.token_id).filter(Reserve.project_id == project.id))).all()
    print("free tokens:", free_tokens)

    print(f"Send funds to this address: \n{wallet.payment_addr}")
    import time
    while not query_wallet(wallet):
        time.sleep(1)
        print('.', end='', flush=True)
    print()

    try:
        re_mint(
            assets,
            wallet,
            policy,
            excess_addr="addr_test1qq6szayuhmlh3pt2jvtw50zlpvmxmlfndfr5s86ls90aynhx4vrecn8ys8mdy4jp6xclnxet9h89pyrf2k5gtdnvtjaslxgsc0",
        )
    except subprocess.CalledProcessError: # If the minting fails, send the ADA to the target wallet as a failsafe
        mint(
            [],
            wallet,
            policy,
            excess_addr="addr_test1qq6szayuhmlh3pt2jvtw50zlpvmxmlfndfr5s86ls90aynhx4vrecn8ys8mdy4jp6xclnxet9h89pyrf2k5gtdnvtjaslxgsc0",
        )

def re_mint(assets, wallet, policy, excess_addr=""):
    if not excess_addr:
        excess_addr = wallet.payment_addr

    redirected_assets = []
    for asset in assets:
        copied_asset = asset.copy()
        copied_asset['addr'] = wallet.payment_addr
        redirected_assets.append(copied_asset)

    print("Waiting for ADA input to mint")
    while not query_wallet(wallet):
        print('.', end='', flush=True)
        time.sleep(1)
    print()
    print("Minting with new metadata!")
    mint(redirected_assets, wallet, policy, excess_addr=wallet.payment_addr)

    print("Waiting for transaction to go through...")
    remint_tx_found = False
    while not remint_tx_found:
        print('.', end='', flush=True)
        time.sleep(1)
        utxos = query_wallet(wallet)
        for tx in utxos:
            if policy.policy_id in utxos[tx]["value"]:
                if all(asset['assetName'] in utxos[tx]["value"][policy.policy_id] for asset in assets):
                    remint_tx_found = True
    print()
    print("Burning minted tokens")

    burn_assets = []
    for asset in redirected_assets:
        burn_asset = asset.copy()
        burn_asset['amount'] = -1 * asset['amount']
        burn_asset['addr'] = excess_addr
        burn_assets.append(burn_asset)

    mint(burn_assets, wallet, policy, excess_addr=excess_addr)

def setup(engine):
    # Create the working directory if it does not exist
    if not os.path.exists(config.WORKING_DIRECTORY):
        os.makedirs(config.WORKING_DIRECTORY)
    Base.metadata.create_all(engine)

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
                wallet.payment_addr,
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
        policy.before = int(before)

    if not after < 0:
        policy_script["scripts"].append({"slot": before, "type": "after"})
        policy.after = int(after)

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
        wallet.staking_vkey = f_in.read()
    with open(f"{config.WORKING_DIRECTORY}/{random_id}_stake.skey") as f_in:
        wallet.staking_skey = f_in.read()
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
        wallet.payment_vkey = f_in.read()
    with open(f"{config.WORKING_DIRECTORY}/{random_id}_payment.skey") as f_in:
        wallet.payment_skey = f_in.read()
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
            tx for tx in query_wallet(wallet)
        ]

    # Calculate the TX_OUTs
    # 1. list all available resources (lovelaces and tokens)
    available_resources = {}
    utxos = query_wallet(wallet)
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
            empty_resources.append(resource)

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
                if tx_out[addr][resource] > 0:
                    resourcestring = (
                        resourcestring + f"+{tx_out[addr][resource]} {resource}"
                    )
        tx_out_formatted.append(resourcestring)

    metadata = {"721": {"version": 1}}
    for asset in assets:
        if not asset["policyId"] in metadata["721"]:
            metadata["721"][asset["policyId"]] = {}
        metadata["721"][asset["policyId"]][asset["assetName"]] = asset["metadata"]
    with open(f"{config.WORKING_DIRECTORY}/{random_id}_metadata.json", "w") as f_out:
        json.dump(metadata, f_out, indent=4)

    with open(f"{config.WORKING_DIRECTORY}/{random_id}_policy.script", "w") as f_out:
        print(policy.policy_script, file=f_out)

    minting_string = ''
    for asset in assets:
        if not minting_string:
            minting_string = f'{asset["amount"]} {asset["policyId"]}.{asset["assetName"]}'
        else:
            minting_string += f'+{asset["amount"]:d} {asset["policyId"]}.{asset["assetName"]}'
        
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
        "--out-file",
        f"{config.WORKING_DIRECTORY}/{random_id}_free_tx.raw",
    ]
    if len(assets):
        process_parameters += [
            "--mint",
            minting_string,
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
                if tx_out[addr][resource] > 0:
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
        "--out-file",
        f"{config.WORKING_DIRECTORY}/{random_id}_tx.raw",
    ]
    if len(assets):
        process_parameters += [
            "--mint",
            minting_string,
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
        print(wallet.payment_skey, file=f_out)

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
