import asyncio
import binascii
import os
import socket
import time

from iroha import Iroha, IrohaGrpc, IrohaCrypto

IROHA_HOST_ADDR = socket.gethostbyname("bullet.local")
IROHA_PORT = '50051'
IROHA_DOMAIN = "test"
DEBUG = False

net = IrohaGrpc
tx_time_data = {}
tx_list_length_data = []


# These three functions below are used to measure the time taken for a transaction to be committed
# They are definitely not the best solution, but are more accurate than previous attempts
async def enqueue_items(queue, generator):
    try:
        async for item in generator:
            await queue.put(item)
    except StopAsyncIteration:
        pass
    finally:
        await queue.put(None)  # Signal the end of the items


async def iterate_async(generator):
    for item in generator:
        yield item


async def get_status_stream(transaction):
    time_start = time.time()
    queue = asyncio.Queue()

    # Start enqueueing items onto the queue
    enqueue_task = asyncio.create_task(enqueue_items(queue, iterate_async(net.tx_status_stream(transaction))))

    while True:
        item = await queue.get()
        if item is None:
            break  # End of items
        status_name, status_code, error_code = item
        if status_name == "STATELESS_VALIDATION_SUCCESS":
            print(f"Transaction validated at {time.time() - time_start}")
        if status_name == "COMMITTED":
            time_end = round((time.time() - time_start) * 1000) / 1000
            hex_hash = binascii.hexlify(IrohaCrypto.hash(transaction))
            print(f"[{hex_hash}] Transaction took: {time_end} seconds")
            tx_time_data[hex_hash] = time.time() - tx_time_data[hex_hash]
            enqueue_task.cancel()  # Cancel the enqueue task
            return


def send_transaction_and_print_status(transaction):
    try:
        net.send_tx(transaction)
    except IrohaGrpc.RpcError:
        print("[ERROR] Cannot connect to server")
        return
    asyncio.run(get_status_stream(transaction))


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


# Store telemetry data as account details on the blockchain
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


# Returns the details of a device on the chain, given the gateway has the permissions to view them
def get_device_details(device_id, gateway_id):
    print(f"[{device_id}] Looking for details -> ", end="")
    iroha_gateway = Iroha(f"{gateway_id}@{IROHA_DOMAIN}")
    priv, pub = get_keys(gateway_id)
    query = iroha_gateway.query('GetAccountDetail', account_id=f"{device_id}@{IROHA_DOMAIN}")
    IrohaCrypto.sign_query(query, priv)
    response = net.send_query(query=query)
    detail = response.account_detail_response.detail
    print(detail) if detail else print("No Details!")


# Set up the Iroha net connection
def iroha_connect():
    global net
    print(f"[System] Connecting to Iroha...", end="")
    try:
        net = IrohaGrpc(f"{IROHA_HOST_ADDR}:{IROHA_PORT}")
    except IrohaGrpc.RpcError:
        print(f"[ERROR] Iroha not found on {IROHA_HOST_ADDR}:{IROHA_PORT}")
    print("Connected!")
