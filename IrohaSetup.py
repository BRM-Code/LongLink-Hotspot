import binascii
import socket
import time
import grpc
import os
from iroha import Iroha, IrohaGrpc, IrohaCrypto

IROHA_HOST_ADDR = socket.gethostbyname("bullet.local")
IROHA_PORT = '50051'
IROHA_DOMAIN = "test"
DEBUG = False
net = IrohaGrpc
tx_time_data = {}
tx_list_length_data = []


def send_transaction_and_print_status(transaction):
    hex_hash = binascii.hexlify(IrohaCrypto.hash(transaction))
    creator_id = transaction.payload.reduced_payload.creator_account_id
    commands = get_commands_from_tx(transaction)
    print(f'[{creator_id}] Transaction "{commands}", hash = {hex_hash}') if DEBUG else None
    try:
        net.send_tx(transaction, timeout=10)
    except grpc._channel._InactiveRpcError:
        print("TX Timed out!")
        return
    tx_time_data[hex_hash] = time.time()


def check_on_transactions(tx_list: list):
    target_no = len(tx_list)
    print(f"Checking {target_no} Tx_list")
    tx_list_length_data.append(target_no)
    curr_no = 0
    for tx in tx_list:
        for status, code1 in enumerate(net.tx_status(tx)):
            if code1 == "COMMITTED":
                hex_hash = binascii.hexlify(IrohaCrypto.hash(tx))
                print(f"Confirmed {hex_hash}")
                curr_no += 1
                tx_list.remove(tx)
                tx_time_data[hex_hash] = time.time() - tx_time_data[hex_hash]
            else:
                print(f"status {code1}, {status}")

    if curr_no == target_no:
        print("All tx in list were confirmed")
    else:
        print(f"{curr_no}/{target_no} transactions committed")
    return tx_list


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


def store_telemetry_data(telemetry: dict[str:str], uav_id: str, gateway_id: str):
    print(f"[{gateway_id}@{IROHA_DOMAIN}] is storing info from {uav_id}")
    telemetry['timestamp'] = time.time()
    priv, pub = get_keys(gateway_id)
    iroha_gateway = Iroha(f"{gateway_id}@{IROHA_DOMAIN}")

    commands = []
    for key, value in telemetry.items():
        commands.append(iroha_gateway.command('SetAccountDetail', account_id=f"{uav_id}@{IROHA_DOMAIN}", key=key,
                                              value=str(value)))
    tx = iroha_gateway.transaction(commands)
    IrohaCrypto.sign_transaction(tx, priv)
    send_transaction_and_print_status(tx)
    return tx


def get_device_details(device_id, gateway_id):
    print(f"[{device_id}] Looking for details -> ", end="")
    iroha_gateway = Iroha(f"{gateway_id}@{IROHA_DOMAIN}")
    priv, pub = get_keys(gateway_id)
    query = iroha_gateway.query('GetAccountDetail', account_id=f"{device_id}@{IROHA_DOMAIN}")
    IrohaCrypto.sign_query(query, priv)
    response = net.send_query(query)
    detail = response.account_detail_response.detail
    print(detail) if detail else print("No Details!")


def iroha_connect():
    global net
    print(f"[System] Connecting to Iroha...", end="")
    try:
        net = IrohaGrpc(f"{IROHA_HOST_ADDR}:{IROHA_PORT}")
    except IrohaGrpc.RpcError:
        print(f"[ERROR] Iroha not found on {IROHA_HOST_ADDR}:{IROHA_PORT}")
    print("Connected!")
