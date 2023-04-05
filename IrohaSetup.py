import binascii
import grpc

from utilities.errorCodes2Hr import get_proper_functions_for_commands
import os
from datetime import datetime
from iroha import Iroha, IrohaGrpc, IrohaCrypto, primitive_pb2

IROHA_HOST_ADDR = 'localhost'
IROHA_PORT = '50051'
IROHA_DOMAIN = "test"
ADMIN_ACCOUNT_ID = f'admin@{IROHA_DOMAIN}'
ADMIN_PRIVATE_KEY = 'f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70'
iroha_admin = Iroha(ADMIN_ACCOUNT_ID)


def initialize():
    return IrohaGrpc(f"{IROHA_HOST_ADDR}:{IROHA_PORT}")


def send_transaction_and_print_status(transaction):
    hex_hash = binascii.hexlify(IrohaCrypto.hash(transaction))
    creator_id = transaction.payload.reduced_payload.creator_account_id
    commands = get_commands_from_tx(transaction)
    print(f'Transaction "{commands}",'
          f' hash = {hex_hash}, creator = {creator_id}')
    try:
        net.send_tx(transaction)
    except grpc.RpcError:
        print("[ERROR] Cannot connect to server")
        return
    for i, status in enumerate(net.tx_status_stream(transaction)):
        status_name, status_code, error_code = status
        print(f"    {i}: status_name={status_name}, status_code={status_code}, "
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
def get_keys(account_id):
    print(f"[{account_id}] Looking for keys -> ", end="")
    private_key_file = f'{account_id}@{IROHA_DOMAIN}.priv'
    public_key_file = f'{account_id}@{IROHA_DOMAIN}.pub'

    if os.path.exists(private_key_file) and os.path.exists(public_key_file):
        print("Found keys")
        with open(private_key_file, 'rb') as f:
            private_key = f.read()
        with open(public_key_file, 'rb') as f:
            public_key = f.read()
    else:
        print("Generating new keys")
        private_key = IrohaCrypto.private_key()
        public_key = IrohaCrypto.derive_public_key(private_key)
        with open(private_key_file, 'wb') as f:
            f.write(private_key)
        with open(public_key_file, 'wb') as f:
            f.write(public_key)
    return private_key, public_key


def create_account(device_id):
    print(f"[{device_id}] Checking account -> ", end="")
    priv, pub = get_keys(device_id)
    tx = iroha_admin.transaction([
        iroha_admin.command('CreateAccount', account_name=device_id, domain_id=IROHA_DOMAIN,
                            public_key=pub)
    ])
    IrohaCrypto.sign_transaction(tx, ADMIN_PRIVATE_KEY)
    try:
        send_transaction_and_print_status(tx)
        print("Created account for device")
    except RuntimeError:
        print("Account already exists")
        return


def store_telemetry_data(telemetry, drone_id, gateway_id):
    print(f"[{gateway_id}] is storing info from {drone_id}")
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


def create_domain(default_role='user'):
    print(f"Creating Domain : {IROHA_DOMAIN}")
    commands = [iroha_admin.command('CreateDomain', domain_id=IROHA_DOMAIN, default_role=default_role), ]
    tx = IrohaCrypto.sign_transaction(iroha_admin.transaction(commands), ADMIN_PRIVATE_KEY)
    send_transaction_and_print_status(tx)


def uav_allow_gateway(drone_id, gateway_id):
    print(f"[{drone_id}] is allowing details from {gateway_id}")
    priv, pub = get_keys(drone_id)
    tx = iroha_admin.transaction([
        iroha_admin.command('GrantPermission', account_id=f'{gateway_id}@{IROHA_DOMAIN}',
                            permission=primitive_pb2.can_set_my_account_detail)
    ], creator_account=f"{drone_id}@{IROHA_DOMAIN}")
    IrohaCrypto.sign_transaction(tx, priv)
    send_transaction_and_print_status(tx)


def get_device_details(device_id):
    print(f"[{device_id}] Looking for details -> ", end="")
    query = iroha_admin.query('GetAccountDetail', account_id=f"{device_id}@{IROHA_DOMAIN}")
    IrohaCrypto.sign_query(query, ADMIN_PRIVATE_KEY)
    response = net.send_query(query)
    detail = response.account_detail_response.detail
    print(detail) if detail else print("No Details!")


net = initialize()
