import binascii
import time
import grpc

from utilities.errorCodes2Hr import get_proper_functions_for_commands
import os
from datetime import datetime
from iroha import Iroha, IrohaGrpc, IrohaCrypto

IROHA_HOST_ADDR = '192.168.0.199'
IROHA_PORT = '50051'
IROHA_DOMAIN = "test"
DEBUG = False


def send_transaction_and_print_status(transaction):
    hex_hash = binascii.hexlify(IrohaCrypto.hash(transaction))
    creator_id = transaction.payload.reduced_payload.creator_account_id
    commands = get_commands_from_tx(transaction)
    print(f'[{creator_id}] Transaction "{commands}", hash = {hex_hash}') if DEBUG else None
    try:
        net.send_tx(transaction)
        time_start = time.perf_counter()
    except grpc.RpcError:
        print("[ERROR] Cannot connect to server")
        return
    for i, status in enumerate(net.tx_status_stream(transaction)):
        status_name, status_code, error_code = status
        if status_name == "STATELESS_VALIDATION_SUCCESS":
            print(f"[{creator_id}] Transaction validated at {time.perf_counter() - time_start}")
        if status_name == "COMMITTED":
            time_end = round((time.perf_counter() - time_start) * 1000) / 1000
            print(f"[{creator_id}] Transaction took: {time_end} seconds")
            return

        if status_name in ('STATEFUL_VALIDATION_FAILED', 'STATELESS_VALIDATION_FAILED', 'REJECTED'):
            error_code_hr = get_proper_functions_for_commands(commands)(error_code)
            raise RuntimeError(f"{status_name} failed on tx: "
                               f"{transaction} due to reason {error_code}: "
                               f"{error_code_hr}")

        print(f"    {i}: Status={status_name} SC={status_code} EC={error_code}") if DEBUG else None


def get_commands_from_tx(transaction):
    commands_from_tx = []
    for command in transaction.payload.reduced_payload.__getattribute__("commands"):
        listed_fields = command.ListFields()
        commands_from_tx.append(listed_fields[0][0].name)
    return commands_from_tx


# This function generates a private/public key pair using the IrohaCrypto module.
# If the key files already exist, it reads the values from them.
def get_keys(account_id):
    print(f"[{account_id}] Looking for keys -> ", end="") if DEBUG else None
    private_key_file = f'Keys/{account_id}@{IROHA_DOMAIN}.priv'
    public_key_file = f'Keys/{account_id}@{IROHA_DOMAIN}.pub'

    if os.path.exists(private_key_file) and os.path.exists(public_key_file):
        print("Found keys") if DEBUG else None
        with open(private_key_file, 'rb') as f:
            private_key = f.read()
        with open(public_key_file, 'rb') as f:
            public_key = f.read()
    else:
        print("Generating new keys") if DEBUG else None
        private_key = IrohaCrypto.private_key()
        public_key = IrohaCrypto.derive_public_key(private_key)
        with open(private_key_file, 'wb') as f:
            f.write(private_key)
        with open(public_key_file, 'wb') as f:
            f.write(public_key)
    return private_key, public_key


def store_telemetry_data(telemetry, drone_id, gateway_id):
    print(f"[{gateway_id}@{IROHA_DOMAIN}] is storing info from {drone_id}")
    telemetry['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    priv, pub = get_keys(gateway_id)
    iroha_gateway = Iroha(f"{gateway_id}@{IROHA_DOMAIN}")

    commands = []
    for key, value in telemetry.items():
        commands.append(iroha_gateway.command('SetAccountDetail', account_id=f"{drone_id}@{IROHA_DOMAIN}", key=key,
                                              value=str(value)))
    tx = iroha_gateway.transaction(commands)
    IrohaCrypto.sign_transaction(tx, priv)
    send_transaction_and_print_status(tx)
    return


def get_device_details(device_id, gateway_id):
    print(f"[{device_id}] Looking for details -> ", end="")
    iroha_gateway = Iroha(f"{gateway_id}@{IROHA_DOMAIN}")
    priv, pub = get_keys(gateway_id)
    query = iroha_gateway.query('GetAccountDetail', account_id=f"{device_id}@{IROHA_DOMAIN}")
    IrohaCrypto.sign_query(query, priv)
    response = net.send_query(query)
    detail = response.account_detail_response.detail
    print(detail) if detail else print("No Details!")


net = IrohaGrpc(f"{IROHA_HOST_ADDR}:{IROHA_PORT}")
