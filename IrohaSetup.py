import binascii

import grpc
from grpc._channel import _InactiveRpcError

from utilities.errorCodes2Hr import get_proper_functions_for_commands
import os
import json
from datetime import datetime
from iroha import Iroha, IrohaCrypto, IrohaGrpc

IROHA_HOST_ADDR = '127.0.0.1'
IROHA_PORT = os.getenv('IROHA_PORT', '50051')
ADMIN_ACCOUNT_ID = os.getenv('ADMIN_ACCOUNT_ID', 'admin@test')
ADMIN_PRIVATE_KEY = os.getenv('ADMIN_PRIVATE_KEY', 'f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70')
IROHA_DOMAIN = "test"


def initialize():
    return Iroha(ADMIN_ACCOUNT_ID), IrohaGrpc(f"{IROHA_HOST_ADDR}:{IROHA_PORT}")


def send_transaction_and_print_status(transaction):
    hex_hash = binascii.hexlify(IrohaCrypto.hash(transaction))
    creator_id = transaction.payload.reduced_payload.creator_account_id
    commands = get_commands_from_tx(transaction)
    print(f'Transaction "{commands}",'
          f' hash = {hex_hash}, creator = {creator_id}')
    try:
        net.send_tx(transaction)
    except grpc._channel._InactiveRpcError:
        print("[ERROR] Cannot connect to server")
        return
    for i, status in enumerate(net.tx_status_stream(transaction)):
        status_name, status_code, error_code = status
        print(f"{i}: status_name={status_name}, status_code={status_code}, "
              f"error_code={error_code}")
        if status_name in ('STATEFUL_VALIDATION_FAILED', 'STATELESS_VALIDATION_FAILED', 'REJECTED'):
            error_code_hr = get_proper_functions_for_commands(commands)(error_code)
            raise RuntimeError(f"{status_name} failed on tx: "
                               f"{transaction} due to reason {error_code}: "
                               f"{error_code_hr}")


def get_commands_from_tx(transaction):
    commands_from_tx = []
    for command in transaction.payload.reduced_payload.__getattribute__("commands"):
        listed_fields = command.ListFields()
        commands_from_tx.append(listed_fields[0][0].name)
    return commands_from_tx


# This function generates a private/public key pair using the IrohaCrypto module.
# If the key files already exist, it reads the values from them.
def key_setup(account_id):
    private_key_file = f'{account_id}-keypair.priv'
    public_key_file = f'{account_id}-keypair.pub'

    if os.path.exists(private_key_file) and os.path.exists(public_key_file):
        with open(private_key_file, 'rb') as f:
            private_key = f.read()
        with open(public_key_file, 'rb') as f:
            public_key = f.read()
    else:
        private_key = IrohaCrypto.private_key()
        public_key = IrohaCrypto.derive_public_key(private_key)
        with open(private_key_file, 'wb') as f:
            f.write(private_key)
        with open(public_key_file, 'wb') as f:
            f.write(public_key)
    return private_key, public_key


def create_account_drone(drone_id):
    priv, pub = key_setup(drone_id)
    tx = iroha.transaction([
        iroha.command('CreateAccount', account_name=drone_id, domain_id=IROHA_DOMAIN, public_key=pub)
    ])
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    send_transaction_and_print_status(tx)
    return


def create_account_gateway(gateway_id):
    priv, pub = key_setup(gateway_id)
    tx = iroha.transaction([
        iroha.command('CreateAccount', account_name=gateway_id, domain_id=IROHA_DOMAIN, public_key=pub)
    ])
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    send_transaction_and_print_status(tx)
    return


def push_to_iroha(telemetry, drone_id):
    now = datetime.now()
    telemetry['timestamp'] = now.strftime('%Y-%m-%d %H:%M:%S')

    tx = iroha.transaction([
        iroha.command('SetAccountDetail', account_id=drone_id, key='telemetry', value=json.dumps(telemetry))
    ])
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    send_transaction_and_print_status(tx)


iroha, net = initialize()
