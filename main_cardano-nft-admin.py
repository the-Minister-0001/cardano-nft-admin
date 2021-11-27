#!/usr/bin/env python3

# TODO:
#   - Don't pass assets to minting, pass mintages # TODO TODO TODO
#       -> This will be the most important change
#   - Add documentation
#   - refactor into multiple files, this is getting out of hand.
#   - extend the setup function
#   - Avoid pitfall: Refunding the vending system's own transaction
#   - requirements.txt
#   - passing session seems dirty, there must be a better way
#       -> Create "get_session" or something like that just like the network params
#   - I'm probably using sqlalchemy not according to best practices, I'll need to clean that up
# BUG TODO:
#   - Burning one if there are multiple instances of a token seems to not work?

import os
import copy
import time
import itertools
import json
import math
import logging
import sqlite3
import subprocess
import random
from bdb import BdbQuit

import sqlalchemy
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
        project = Project(policy_id=policy.id, wallet_id=wallet.id, project_name="This is My Project Number One", dynamic=False, lock_sales=False, price=5*10**6)
    else:
        project = session.query(Project).filter(Project.project_name.like("%My Project%")).first()
    session.add(project)
    session.commit()

    for salesize in [1, 3, 10]:
        salesize = session.query(SaleSize).filter(SaleSize.amount == salesize).first()
        if not session.query(RelSaleSizeProject).filter(RelSaleSizeProject.project_id == project.id).filter(RelSaleSizeProject.salesize_id == salesize.id).count():
            project_salesize = RelSaleSizeProject(project_id=project.id, salesize_id=salesize.id)
            session.add(project_salesize)
    session.commit()



    assets = []
    mint_idx = 0
    for k in range(8):
        asset_name = f'OriginalLuckiestCharm{k+1:02d}' # also Custom Charm
        if not session.query(Token).filter(Token.project_id==project.id).filter(Token.asset_name==asset_name).count():
            asset = Token()
            asset.asset_name = asset_name
            asset.minted = 0
            asset.max_mints = 1
            asset.token_metadata = json.dumps({
                "name": "The Luckiest Charm [{k+1:02d}/88]",
                "88888888": "88888888",
                "image": "ipfs://QmVTzyMsAs2oToJB6J6TapTjXhBTD8BvqnD7KX5tSYxqiY",
                " copyright": "88888888-id.com 2021",
                "type": "The original luckiest charm", #or customizable
                "publisher": "[the Minister]#0001",
                "ID": f"{k+1}",
            })
            asset.project_id = project.id # replaces policy ID, policy is attainable via project
            asset.sent_out = 0
            asset.start_idx = mint_idx
            asset.end_idx = mint_idx + asset.max_mints - 1
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


    project_tokens = session.query(Token).filter(Token.project_id==project.id).filter(Token.sent_out < Token.max_mints)
    reserved_tokens = session.query(Mint).filter(Mint.id.in_(session.query(Reserve).with_entities(Reserve.mintage_id).filter(Reserve.project_id == project.id))).with_entities(Mint.token_id)
    free_tokens = project_tokens.filter(Token.id.not_in(reserved_tokens)).all()

    if len(free_tokens) > 2: # leave at least one token with no reservation
        reserve = Reserve()
        reserve.project_id = project.id
        reserve.dust = random.randint(3500000, 6000000) # TODO make sure that's not an already occupied value
        print(f"Added one reserve for {reserve.dust/1000000:.6f} ADA")
        reserve.mintage_id = random.choice(mintages).id
        session.add(reserve)#let's try no reserves first
        session.commit()

    project_tokens = session.query(Token).filter(Token.project_id==project.id).filter(Token.sent_out < Token.max_mints)
    reserved_tokens = session.query(Mint).filter(Mint.id.in_(session.query(Reserve).with_entities(Reserve.mintage_id).filter(Reserve.project_id == project.id))).with_entities(Mint.token_id)
    free_tokens = project_tokens.filter(Token.id.not_in(reserved_tokens)).all()

    #vend(project, session);return

    print(f"Send funds to this address: \n{wallet.payment_addr}")
    import time
    while not query_wallet(wallet):
        time.sleep(1)
        print('.', end='', flush=True)
    print()

    try:
        re_mint(
            mintages,
            wallet,
            policy,
            excess_addr="addr_test1qq6szayuhmlh3pt2jvtw50zlpvmxmlfndfr5s86ls90aynhx4vrecn8ys8mdy4jp6xclnxet9h89pyrf2k5gtdnvtjaslxgsc0",
            session=session,
        )
    except subprocess.CalledProcessError: # If the minting fails, send the ADA to the target wallet as a failsafe
        mint(
            [],
            wallet,
            policy,
            excess_addr="addr_test1qq6szayuhmlh3pt2jvtw50zlpvmxmlfndfr5s86ls90aynhx4vrecn8ys8mdy4jp6xclnxet9h89pyrf2k5gtdnvtjaslxgsc0",
            session=session,
        )

def vend(project, session):
    interrupted = False
    handled_transactions = []
    while not interrupted:
        try:
            handled_transactions = handle_vending(project, session, handled_transactions)
            time.sleep(1)
        except KeyboardInterrupt:
            interrupted = True
        except BdbQuit:
            raise
        except Exception: # TODO This is bad but the sale must be possible to recover from anything right now
            logger.exception("Exception in vending")

def handle_vending(project, session, handled_transactions):
    # WARNING: This swallows NFTs if people send them. Cleaning this up will require manual work
    # This behaviour is accepted for now

    refund_threshhold = 2000000 # if people send less than this, don't refund

    project_wallet = session.query(Wallet).filter(Wallet.id == project.wallet_id).first()
    sale_size_ids = session.query(RelSaleSizeProject).filter(RelSaleSizeProject.project_id == project.id).with_entities(RelSaleSizeProject.salesize_id)
    sale_sizes = session.query(SaleSize).filter(SaleSize.id.in_(sale_size_ids)).all()

    excess_addr = project_wallet.payment_addr
    if config.EXCESS_ADDR:
        excess_addr = config.EXCESS_ADDR

    logger.info(f"Vending, send ADA to {project_wallet.payment_addr}")
    project_policy = session.query(Policy).filter(Policy.id == project.policy_id).first()
    reservations_dust = [dust[0] for dust in session.query(Reserve).filter(Reserve.project_id == project.id).with_entities(Reserve.dust).all()]
    print("Dust reservations:", *[f'{d/1000000:.6f}' for d in reservations_dust])
    utxos = query_wallet(project_wallet)
    utxo_list = []

    for utxo in utxos:
        utxo_dict = utxos[utxo]
        utxo_dict['tx'] = utxo
        utxo_dict['block_id'] = get_tx_block_id(utxo_dict['tx'])
        utxo_list.append(utxo_dict)

    new_handled_transactions = []
    for handled_transaction in handled_transactions:
        if handled_transaction in utxos:
            new_handled_transactions.append(handled_transaction)
    handled_transactions = new_handled_transactions

    utxo_list = sorted(utxo_list, key=lambda x: x['block_id'])

    valid_purchases = [project.price * sale_size.amount for sale_size in sale_sizes]
    if not len(valid_purchases):
        print("Didn't find valid purchases, retrying")
        return handled_transactions

    liquidity_txs = []
    for utxo in utxo_list:
        origin_txs = get_transaction_inputs(utxo['tx'][:utxo['tx'].find('#')])
        if any([tx == project_wallet.payment_addr for tx in origin_txs]):
            liquidity_txs.append(utxo)

    for utxo in utxo_list:
        # Ignore a bunch of stuff to stop weirdness from happening

        # If the block ID is -1 then the dbsinc didn't catch up with that one yet
        if utxo['block_id'] < 0:
            continue

        # If I handled that transaction but the chain didn't update yet, ignore it
        if utxo['tx'] in handled_transactions:
            continue

        # If the origin transactions can't be determined it might be a syncing lag
        # Ignore that TX for now and handle it once the data is there
        origin_txs = get_transaction_inputs(utxo['tx'][:utxo['tx'].find('#')])
        if not origin_txs:
            print("Could not find origin tx")
            continue

        # If the transaction originated from the project wallet, ignore it
        if any([tx == project_wallet.payment_addr for tx in origin_txs]):
            continue # ignore transactions from self

        print(json.dumps(utxo, indent=4))
        # If people throw NFTs into the transaction just ignore it and wait for them to contact you
        # This can be done on accident or on purpose and really mess with things
        # If the min_ada is <1 ADA + fee for the return this could break the system
        lovelace = utxo['value']['lovelace']
        if len(utxo['value']) > 1: # user didn't just send ADA
            if lovelace < refund_threshhold:
                print("Junk TX with Token, doing nothing.")
                handled_transactions.append(utxo['tx'])
            else:
                print("Attempting to refund")
                if origin_txs:
                    try:
                        mint([], project_wallet, project_policy, excess_addr=origin_txs[0], tx_ins=[utxo['tx']], session=session)
                    except KeyboardInterrupt:
                        raise
                    except BdbQuit:
                        raise
                    except Exception: # TODO THIS IS BAD
                        print("Refund failed, ignoring.")
                        pass
                    handled_transactions.append(utxo['tx'])
                    continue

        elif lovelace in valid_purchases: # purchasing an allowed amount for regular prices
            amount = int(lovelace/project.price)
            print("Found valid purchase of this amount:", amount)
            project_tokens = session.query(Token).filter(Token.project_id==project.id).filter(Token.sent_out < Token.max_mints)
            reserved_tokens = session.query(Mint).filter(Mint.id.in_(session.query(Reserve).with_entities(Reserve.mintage_id).filter(Reserve.project_id == project.id)))
            reserved_amount = sum(mintage.amount for mintage in reserved_tokens.all())
            reserved_tokens_ids = reserved_tokens.with_entities(Mint.token_id)
            free_tokens = project_tokens.filter(Token.id.not_in(reserved_tokens_ids)).all()

            tokens_sent_out = sum(token.sent_out for token in project_tokens.all())
            max_tokens = sum(token.max_mints for token in project_tokens.all())
            buyable_tokens = min(max_tokens - (tokens_sent_out + reserved_amount), amount)

            max_idx = max(token.end_idx for token in project_tokens.all())
            min_idx = min(token.start_idx for token in project_tokens.all())
            mintages = []
            while len(mintages) < buyable_tokens:
                if config.RANDOMIZE:
                    random_token_index = random.randint(min_idx, max_idx)
                    token_type = session.query(Token).filter(Token.start_idx <= random_token_index).filter(Token.end_idx >= random_token_index).first()
                    if (token_type.start_idx + token_type.sent_out + reserved_amount) > random_token_index: # this token has been minted
                        continue
                else:
                    tokens = session.query(Token).filter(Token.sent_out < 1).order_by(Token.id.asc()).all()
                    unused_tokens = []
                    for token in tokens:
                        already_included = False
                        for mintage in mintages:
                            if token.id == mintage.token_id:
                                already_included = True
                        if not already_included: unused_tokens.append(token)
                    token_type = unused_tokens[0]
                reserved_amount = 0
                for reservation in reserved_tokens.all():
                    if reservation.token_id == token_type.id:
                        reserved_amount += reservation.amount # TODO use a proper DB query instead of this junk
                else:
                    # TODO check if this one is reserved
                    session.commit()
                    mintage = Mint()
                    mintage.token_id = token_type.id
                    mintage.amount = 1
                    mintage.addr = origin_txs[0]
                    mintage.in_progress = True
                    mintage.completed = False
                    session.add(mintage)
                    session.commit()
                    mintages.append(mintage)
        
            # Don't try to mint if there is nothing to mint
            if buyable_tokens:
                mint(mintages, project_wallet, project_policy, tx_ins=[utxo['tx']], excess_addr=excess_addr, session=session, apply_royalties=True)
                for mintage in mintages:
                    token = session.query(Token).filter(Token.id==mintage.token_id).first()
                    token.sent_out += 1
                session.commit()

            handled_transactions.append(utxo['tx'])
                
            refund_amount = project.price * (amount - buyable_tokens)
            if refund_amount and buyable_tokens > 0:
                print("Utxos:")
                print(json.dumps(utxos, indent=4))
                print()
                print("Liquidity TXs:")
                for ltx in liquidity_txs:
                    print(ltx)
                mint([], project_wallet, project_policy, [ltx['tx'] for ltx in liquidity_txs], session=session, extra_lovelace=refund_amount, extra_addr=origin_txs[0])
            elif refund_amount and buyable_tokens == 0:
                print("Sold Out! Refunding")
                if origin_txs:
                    mint([], project_wallet, project_policy, excess_addr=origin_txs[0], tx_ins=[utxo['tx']], session=session)
                    handled_transactions.append(utxo['tx'])
            break
        elif lovelace in reservations_dust:
            print("Found reservation transaction")
            reservation = session.query(Reserve).filter(Reserve.dust == lovelace).filter(Reserve.project_id == project.id).first()
            reserved_mintage = session.query(Mint).filter(Mint.id == reservation.mintage_id).first()
            reservation_token = session.query(Token).filter(Token.id == reserved_mintage.token_id).first()
            reserved_mintage.addr = origin_txs[0]
            reserved_mintage.in_progress = True
            mint([reserved_mintage], project_wallet, project_policy, tx_ins=[utxo['tx']], excess_addr=excess_addr, session=session, apply_royalties=True)
            reserved_mintage.completed = True
            reservation_token.minted += reserved_mintage.amount
            reservation_token.sent_out += reserved_mintage.amount
            session.delete(reservation)
            session.commit()
            handled_transactions.append(utxo['tx'])
            break
        else: # incorrect amount of ada
            print("Found incorrect amount...")
            print("Got:", lovelace)
            print("Acceptable:", *valid_purchases)
            if lovelace < refund_threshhold:
                print("Junk TX, doing nothing.")
                handled_transactions.append(utxo['tx'])
            else:
                print("Refunding")
                if origin_txs:
                    mint([], project_wallet, project_policy, excess_addr=origin_txs[0], tx_ins=[utxo['tx']], session=session)
                    handled_transactions.append(utxo['tx'])
            break
    return handled_transactions
            
        
def get_tx_block_id(tx):
    block_id = -1
    engine = create_engine(config.DBSYNC_CONNECTION_STRING)
    if '#' in tx:
        tx = tx[:tx.find('#')]
    statement = sqlalchemy.text("""select block_id from tx where tx.hash = :txid;""")
    with engine.connect() as con:
        rs = con.execute(statement, txid=bytearray.fromhex(tx)).first()

    if len(rs):
       block_id = rs.block_id
    return block_id

def re_mint(mintages, wallet, policy, excess_addr="", session=None):
    if not excess_addr:
        if config.EXCESS_ADDR:
            excess_addr = config.EXCESS_ADDR
        else:
            excess_addr = wallet.payment_addr

    redirected_mintages = []
    for mintage in mintages:
        detached_mintage = session.query(Mint).filter(Mint.id == mintage.id).first()
        detached_mintage.addr = wallet.payment_addr
        redirected_mintages.append(detached_mintage)

    print("Waiting for ADA input to mint")
    while not query_wallet(wallet):
        print('.', end='', flush=True)
        time.sleep(1)
    print()
    print("Minting with new metadata!")
    mint(redirected_mintages, wallet, policy, excess_addr=excess_addr, session=session)

    print("Waiting for transaction to go through...")
    remint_tx_found = False
    while not remint_tx_found:
        print('.', end='', flush=True)
        time.sleep(1)
        utxos = query_wallet(wallet)
        for tx in utxos:
            if policy.policy_id in utxos[tx]["value"]:
                asset_names = [return_object[0] for return_object in session.query(Token).filter(Token.id.in_([mintage.token_id for mintage in mintages])).with_entities(Token.asset_name).all()] # TODO this is ugly, split into understandable chunks
                if all(asset_name in utxos[tx]["value"][policy.policy_id] for asset_name in asset_names):
                    remint_tx_found = True
    print()
    print("Burning minted tokens")

    burn_mintages = []
    for mintage in redirected_mintages:
        burn_mintage = session.query(Mint).filter(Mint.id == mintage.id).first()
        burn_mintage.amount = -1 * mintage.amount
        burn_mintage.addr = excess_addr
        burn_mintages.append(burn_mintage)

    mint(burn_mintages, wallet, policy, excess_addr=excess_addr, session=session)

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


def mint(mintages, wallet, policy, tx_ins=[], excess_addr="", session=None, extra_lovelace=0, extra_addr="", apply_royalties=False):
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
        for policy_id in utxos[tx]["value"]:
            if policy_id == "lovelace":
                if not "lovelace" in available_resources:
                    available_resources["lovelace"] = 0
                available_resources["lovelace"] += utxos[tx]["value"]["lovelace"]
            else:
                for token_name in utxos[tx]["value"][policy_id]:
                    if not f"{policy_id}.{token_name}" in available_resources:
                        available_resources[f"{policy_id}.{token_name}"] = 0
                    available_resources[f"{policy_id}.{token_name}"] += utxos[tx]["value"][
                        policy_id
                    ][token_name]

    # 2. for all assets required, add the 'amount' to the available resources
    # {'policyId':'', 'assetName':'', 'amount':0, 'metadata':{}, 'addr':''}
    for mintage in mintages:
        asset = session.query(Token).filter(Token.id == mintage.token_id).first()
        asset_policy = get_asset_policy(asset.id, session) #TODO query policy ID
        if not f'{asset_policy.policy_id}.{asset.asset_name}' in available_resources:
            available_resources[f'{asset_policy.policy_id}.{asset.asset_name}'] = 0

        available_resources[f'{asset_policy.policy_id}.{asset.asset_name}'] += mintage.amount
    # 3. list all the output addresses and assign the resources to be sent there
    out_addresses = set(mintage.addr for mintage in mintages)
    tx_out = {}
    for addr in out_addresses:
        tx_out[addr] = {}
        for mintage in mintages:
            if mintage.addr == addr:
                asset = session.query(Token).filter(Token.id == mintage.token_id).first()
                asset_policy = get_asset_policy(asset.id, session) #TODO query policy ID
                if not f'{asset_policy.policy_id}.{asset.asset_name}' in tx_out[addr]:
                    tx_out[addr][f'{asset_policy.policy_id}.{asset.asset_name}'] = 0
                tx_out[addr][f'{asset_policy.policy_id}.{asset.asset_name}'] += mintage.amount
                available_resources[
                    f'{asset_policy.policy_id}.{asset.asset_name}'
                ] -= mintage.amount

    # 4. calculate the min ada for each address
    for addr in tx_out:
        addr_assets = []
        for asset in tx_out[addr]:
            if asset == 'lovelace': continue
            addr_assets.append(
                {"name": asset.split(".")[1], "policyID": asset.split(".")[0]}
            )
        if not "lovelace" in tx_out[addr]:
            tx_out[addr]["lovelace"] = 0
        min_ada = calculate_min_ada(addr_assets)
        tx_out[addr]["lovelace"] += min_ada
        available_resources["lovelace"] -= min_ada

    if apply_royalties:
        for royalty in config.ROYALTIES:
            tx_out[royalty[0]] = tx_out.get(royalty[0], {})
            tx_out[royalty[0]]['lovelace'] = int(tx_out[royalty[0]].get('lovelace', 0) + royalty[1] * 1000000 * len(mintages))
            available_resources['lovelace'] -= int(royalty[1] * 1000000 * len(mintages))

    if extra_lovelace and extra_addr and extra_lovelace >= 10**6:
        if not extra_addr in tx_out:
            tx_out[extra_addr] = {'lovelace':0}
        tx_out[extra_addr]['lovelace'] += extra_lovelace
        available_resources['lovelace'] -= extra_lovelace
        print("Added extra lovelace")


    empty_resources = []
    for resource in available_resources:
        if available_resources[resource] <= 0:
            empty_resources.append(resource)

    for resource in empty_resources:
        del available_resources[resource]

    # 5. unless an excess addr is specified, all remaining tokens and lovelaces go back to the wallet
    if not excess_addr:
        if config.EXCESS_ADDR:
            excess_addr = config.EXCESS_ADDR
        else:
            excess_addr = wallet.payment_addr
        # TODO: Only add an excess if there's at least 1 ADA plus fee in the available_resources
        # Otherwise just add the remaining dust to some random output_tx

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
    for mintage in mintages:
        asset = session.query(Token).filter(Token.id == mintage.token_id).first()
        asset_policy = get_asset_policy(asset.id, session) #TODO query policy ID
        if not asset_policy.policy_id in metadata["721"]:
            metadata["721"][asset_policy.policy_id] = {}
        metadata["721"][asset_policy.policy_id][asset.asset_name] = json.loads(asset.token_metadata)
    with open(f"{config.WORKING_DIRECTORY}/{random_id}_metadata.json", "w") as f_out:
        json.dump(metadata, f_out, indent=4)

    with open(f"{config.WORKING_DIRECTORY}/{random_id}_policy.script", "w") as f_out:
        print(policy.policy_script, file=f_out)

    minting_string = ''
    for mintage in mintages:
        asset = session.query(Token).filter(Token.id == mintage.token_id).first()
        asset_policy = get_asset_policy(asset.id, session) #TODO query policy ID
        if not minting_string:
            minting_string = f'{mintage.amount} {asset_policy.policy_id}.{asset.asset_name}'
        else:
            minting_string += f'+{mintage.amount:d} {asset_policy.policy_id}.{asset.asset_name}'
        # TODO this could be done with '+'.join, right?
        
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
    if len(mintages):
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
    if len(mintages):
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


def get_asset_policy(asset_id, session):
    asset = session.query(Token).filter(Token.id == asset_id).first()
    project = session.query(Project).filter(Project.id == asset.project_id).first()
    policy = session.query(Policy).filter(Policy.id == project.policy_id).first()
    return policy

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

    utxo_words = len(assets) * 12 
    for asset in assets:
        utxo_words += len(asset["name"])
    utxo_words += policyid_amount * policy_hash_size

    # Round up to the nearest full word
    utxo_words = 6 + math.floor((utxo_words + (bytes_in_word - 1)) / bytes_in_word)

    # Calculate how many lovelaces this locks
    lovelaces = utxo_words * ada_per_utxo_word
    nft_ada = min_ada + lovelaces

    return nft_ada

def get_transaction_inputs(tx_id):
    tx_in_addrs = []
    engine = create_engine(config.DBSYNC_CONNECTION_STRING)
    statement = sqlalchemy.text("""select tx_out.* from tx_out inner join tx_in on tx_out.tx_id = tx_in.tx_out_id inner join tx on tx.id = tx_in.tx_in_id and tx_in.tx_out_index = tx_out.index where tx.hash = :txid;""")
    with engine.connect() as con:
        for result in con.execute(statement, txid=bytearray.fromhex(tx_id)).all():
            tx_in_addrs.append(result.address)
    return tx_in_addrs


if __name__ == "__main__":
    main()
