import base64
import json
import socket
import struct
import sys
import time
import csv
from Crypto.Cipher import AES

print("     __                      __    _       __         __  __      __                   __ \n"
      "    / /   ____  ____  ____ _/ /   (_)___  / /__      / / / /___  / /__________  ____  / /_\n"
      "   / /   / __ \/ __ \/ __ `/ /   / / __ \/ //_/_____/ /_/ / __ \/ __/ ___/ __ \/ __ \/ __/\n"
      "  / /___/ /_/ / / / / /_/ / /___/ / / / / ,< /_____/ __  / /_/ / /_(__  ) /_/ / /_/ / /_  \n"
      " /_____/\____/_/ /_/\__, /_____/_/_/ /_/_/|_|     /_/ /_/\____/\__/____/ .___/\____/\__/  \n"
      "                   /____/                                             /_/             ")
from IrohaSetup import store_telemetry_data, iroha_connect, tx_time_data, check_on_transactions

DEBUG = False
TESTING = False
ENCRYPTED_PACKETS = True
ACKNOWLEDGING_PACKETS = False
received_ok = False
IROHA_ACTIVATED = True
last_token = []
ack_wait = []  # UAVs awaiting ACK

server_address = ('localhost', 1730)
down_address = ('localhost', 1735)
new_downlink_address = ('', 0)
ack_timer = 0
packet_timer = 0
known_uav_keys = {'u1': (
    bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C]),
    bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))}
uav_pk_count = {'u1': 0}
packet_time_data = {}
ack_time_data = {}
last_telemetry = None
packet_loss_counter = 0
PREDICTED_PACKET_LENGTH = 400

PROTOCOL_VERSION = 0x02
PUSH_DATA_ID = 0x00
PUSH_ACK_ID = 0x01
PULL_DATA_ID = 0x02
PULL_ACK_ID = 0x04
TX_ACK = 0x05

ACK_RATIO = 8
GATEWAY_ID = "g1"
tx_list = []


def listen_for_data(listen_socket):
    while True:
        try:
            return listen_socket.recvfrom(PREDICTED_PACKET_LENGTH)
        except socket.error or socket.timeout:
            pass


def sort_packet(packet, address):
    global received_ok
    if packet[3] == PUSH_DATA_ID:
        packet_forwarder_ack(packet[1:3], PUSH_ACK_ID, address)
        data_packet(packet)
        return

    elif packet[3] == PULL_DATA_ID:
        packet_forwarder_ack(packet[1:3], PULL_ACK_ID, address)
        if not received_ok:
            print(f"[System] OK to send packets")
            received_ok = True
            if TESTING:
                test_tx_params()
        return

    elif packet[3] == TX_ACK:
        return


def data_packet(rec_packet):
    global ack_timer
    global packet_timer
    global ACK_RATIO
    global packet_loss_counter
    global tx_list
    print("[PK] Received a packet -> ", end="") if DEBUG else None
    packet = json.loads(rec_packet[12:].decode('utf-8'))
    if 'stat' in packet:
        print("stat packet!") if DEBUG else None
    elif 'rxpk' in packet:
        print("transmission packet!") if DEBUG else None
        now = time.time()
        if ENCRYPTED_PACKETS:
            # Checking if packet is from known UAV
            base1 = base64.b64decode(packet['rxpk'][0]['data'])
            try:
                raw_packet = base1.decode('utf-8')
            except UnicodeDecodeError:
                print("[PK] unable to decode UAV_ID, packet likely not for me!")
                return

            # Extract UAV ID
            uav_id = raw_packet[1:3]

            # Check if UAV is known to the system
            if uav_id not in known_uav_keys:
                print(f"[PK] unable to find UAV_ID '{uav_id}', packet likely not for me!")
                return

            #  Check if the packet is an ACK packet
            if ACKNOWLEDGING_PACKETS or uav_id in ack_wait:
                data_list = raw_packet.split(' ')
                try:
                    if int(data_list[1]) == 7:
                        ack_time_data[now] = now - ack_timer
                        print(f"[PK] Received ACK from {uav_id} it took {round(ack_time_data[now], 2)} seconds")
                        # ACK messages aren't encrypted
                        print(f"Last ACK RSSI = {data_list[3]}")
                        if data_list[2] == ACK_RATIO:
                            print(f"Updating ACK_RATIO from {ACK_RATIO} to {data_list[2]}")
                            ACK_RATIO = int(data_list[2])
                        ack_wait.remove(uav_id)
                        tx_list = check_on_transactions(tx_list)
                        return
                except IndexError:
                    print(f"[PK] Expecting ACK from {uav_id}, Got normal packet instead")
                    ack_wait.remove(uav_id)
                    uav_pk_count[uav_id] = 0
                    packet_loss_counter += 1

            # Record Packet time
            if packet_timer > 0:
                packet_time_data[now] = now - packet_timer
                print(f"[PK] time between packets {round(packet_time_data[now], 2)}")
            packet_timer = now

            # increment packet counter
            uav_pk_count[uav_id] += 1

            # It is so now we attempt decrypt
            # Remove UAV_ID to allow decryption
            base1 = raw_packet.replace(uav_id, '').encode('utf-8')
            base2 = base64.b64decode(base1)
            uav_key_iv = known_uav_keys[uav_id]
            try:
                cipher = AES.new(uav_key_iv[0], AES.MODE_CBC, uav_key_iv[1])
                data_decoded = cipher.decrypt(base2)
            except ValueError:
                print(f"[PK][{uav_id}] ERROR: data couldn't be decrypted, likely not for me or key/iv incorrect")
                return
        else:
            # Only need to base54 decode once
            data_decoded = base64.b64decode(packet['rxpk'][0]['data'])
            uav_id = data_decoded[1:3].decode('utf-8')
            data_decoded = data_decoded.decode('utf-8').replace(uav_id, '').encode('utf-8')

        data_list = str(data_decoded[1:-14].decode('utf-8')).split(' ')
        print(f"Data extracted: {data_list}") if DEBUG else None
        try:
            uav_id, tele = process_telemetry(uav_id, data_list)
            if IROHA_ACTIVATED:
                tx = store_telemetry_data(tele, uav_id, GATEWAY_ID)
                tx_list.append(tx)
            if ACKNOWLEDGING_PACKETS or uav_pk_count[uav_id] == ACK_RATIO:
                uav_pk_count[uav_id] = 0
                ack_wait.append(uav_id)
                send_downlink_packet(uplink_ack(uav_id, packet['rxpk'][0]))
        except RuntimeWarning:
            print(f"[PK] Data failed to be processed, Data = {data_decoded}")
    else:
        print("[Error] Unknown packet type!")


def packet_forwarder_ack(token, identifier, address):
    push_ack = bytes([2, token[0], token[1], identifier])
    uplink_socket.sendto(push_ack, address)


def send_downlink_packet(txpk):
    global new_downlink_address
    global ack_timer
    global tx_list
    json_data = json.dumps({"txpk": txpk})

    token = b"\x12\x34"
    packet_identifier = 0x03
    packet_data = json_data.encode()
    packet_size = len(packet_data)
    packet = struct.pack("!B 2s B {0}s".format(packet_size), PROTOCOL_VERSION, token, packet_identifier, packet_data)
    last_token.append(token)

    # Send the packet to the packet forwarder
    print("[System] Sending Downlink") if DEBUG or TESTING else None

    if new_downlink_address[1] == 0:
        rec_packet, address = listen_for_data(downlink_socket)
        new_downlink_address = address
    else:
        address = new_downlink_address

    ack_tx_pck = time.time()
    downlink_socket.sendto(packet, address)
    while True:
        rec_packet, address = listen_for_data(downlink_socket)
        if rec_packet[3] == 0x05:
            print(f"Received TX_PCK ACK {rec_packet[12:].decode('utf-8')}"
                  f"took {round((time.time() - ack_tx_pck), 2)} seconds")
            ack_timer = time.time()
            break


def uplink_ack(uav_id, packet):
    print(f"[ACK] Sending ACK to {uav_id}")
    status = 1  # TODO: Maybe send the UAV back some useful information here
    ack = f"{uav_id}{GATEWAY_ID}{status}".encode('utf-8')
    ack_encoded = base64.b64encode(ack).decode('utf-8')

    txpk = {
        'imme': True,  # Send packet immediately
        'freq': packet["freq"],  # downlink_packet['freq'],  # TX central frequency in MHz
        'rfch': 0,  # downlink_packet['rfch'],  # Concentrator "RF chain" used for TX
        'powe': 20,  # TX output power in dBm
        'modu': 'LORA',  # Modulation identifier
        "datr": packet["datr"],  # LoRa data-rate identifier (eg. SF12BW500)
        'size': len(ack),  # RF packet payload size in bytes
        "codr": packet["codr"],  # LoRa ECC coding rate identifier
        "ipol": False,  # Lora modulation polarization inversion
        'data': ack_encoded  # Base64 encoded RF packet payload
    }
    return txpk


def test_tx_params():
    global TESTING
    print("[TESTING] Trying all combinations")
    datr_options = ['SF7BW125', 'SF8BW125', 'SF9BW125', 'SF10BW125', 'SF11BW125', 'SF12BW125', 'SF7BW250', 'SF8BW250',
                    'SF12BW250']
    codr_options = ['4/5', '4/6', '4/7', '4/8']
    freq_options = [868.5, 867.1, 867.3, 867.5]
    txpk = {
        'imme': True,  # Send packet immediately
        'rfch': 0,  # downlink_packet['rfch'],  # Concentrator "RF chain" used for TX
        'modu': 'LORA',  # Modulation identifier
        "ipol": False,  # Lora modulation polarization inversion
        'powe': 20
    }
    for freq in freq_options:
        print(f"Testing {freq}")
        for datr in datr_options:
            print(f"    Testing {datr}")
            for codr in codr_options:
                print(f"        Testing {codr}")
                txpk['datr'] = datr
                txpk['codr'] = codr
                txpk['freq'] = freq

                ack = f"{txpk['datr']} {txpk['codr']} {txpk['freq']} "  # f"{uav_id}{gateway_id}{status}"
                ack_encoded = base64.b64encode(ack.encode('utf-8')).decode('utf-8')

                txpk['data'] = ack_encoded
                txpk['size'] = len(ack_encoded.encode('utf-8'))
                send_downlink_packet(txpk)
                time.sleep(1)

    print("[TESTING] Testing complete")
    TESTING = False


def process_telemetry(uav_id, data_list):
    global packet_loss_counter
    print(f"Data Decoded = {data_list}") if DEBUG else None
    try:
        telemetry = {
            'Latitude': data_list[0][2:],
            'Longitude': data_list[1],
            'GroundSpeed': data_list[4],
            'Altitude': data_list[3],
            'Satellites': data_list[5],
            'SatFix': bool(data_list[11][0]),
            'Pitch': data_list[8],
            'Roll': data_list[9],
            'Heading': data_list[10],
            'Vbatt': data_list[2],
            'Consumption': data_list[6],
            'RSSI': data_list[7],
            'arm': bool(data_list[11][1])
        }
        packet_number = int(data_list[11][2])
        if not uav_pk_count[uav_id] == int(packet_number):
            # This indicates a packet has been dropped
            packet_loss_counter += abs(packet_number - uav_pk_count[uav_id])
            print(f"[PK ERROR] Packet No doesn't match {uav_pk_count[uav_id]} not {packet_number}, syncing...")
            uav_pk_count[uav_id] = packet_number
    except IndexError:
        raise RuntimeWarning(f"[ERROR] Data failed to be cast to a JSON!\nData Decoded = {data_list}")

    print(f"[PK] from {uav_id} count = {uav_pk_count[uav_id]}")
    print(f"Telemetry: {telemetry}") if DEBUG else None
    return uav_id, telemetry


def remove_duplicates(new_telemetry):
    global last_telemetry
    new_bytes = base64.b64decode(new_telemetry)
    old_bytes = base64.b64decode(last_telemetry)

    if new_bytes == old_bytes:
        return None

    new_dict = json.loads(new_bytes)
    old_dict = json.loads(old_bytes)

    deleted_key_count = 0

    for key in new_dict.keys():
        if key in old_dict and new_dict[key] == old_dict[key]:
            deleted_key_count += 1
            del new_dict[key]

    print(f"[PK] Removed {deleted_key_count} matching values!")
    last_telemetry = new_telemetry
    filtered_telemetry = json.dumps(new_dict)
    return base64.b64encode(filtered_telemetry.encode('utf-8')).decode('utf-8')


def startup_messages():
    global DEBUG
    if len(sys.argv) > 1 and bool(sys.argv[1]):
        print(f"[System] Debug: ON")
        DEBUG = True
    else:
        print(f"[System] Debug: OFF")
    print(f"[System] Encrypted packets = {ENCRYPTED_PACKETS}")
    print(f"[System] Acknowledging Packet mode {ACKNOWLEDGING_PACKETS}")
    print(f"[System] Gateway ID: {GATEWAY_ID}")
    print(f"[System] Iroha State: {IROHA_ACTIVATED}")


def packet_forwarder_setup():
    print("[System] Connecting to the packet forwarder...", end="")
    up_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up_socket.bind(server_address)
    up_socket.setblocking(True)
    up_socket.settimeout(0.3)

    down_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    down_socket.bind(down_address)
    down_socket.setblocking(True)
    down_socket.settimeout(0.3)
    print("Connected!")
    return up_socket, down_socket


iroha_connect() if IROHA_ACTIVATED else None
startup_messages()
uplink_socket, downlink_socket = packet_forwarder_setup()
while True:
    try:
        data, addr = listen_for_data(uplink_socket)
        sort_packet(data, addr)
    except KeyboardInterrupt:
        print("[System] Saving performance numbers:\n")
        print(f"[System] Packets Lost = {packet_loss_counter}")

        exit_time = f"{time.localtime().tm_hour}-{time.localtime().tm_min}"
        with open(f'logs/{exit_time}-Packet-times.csv', 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=packet_time_data.keys())
            writer.writeheader()
            writer.writerow(packet_time_data)
        print(f"File {exit_time}-Packet-times.csv Saved!")

        with open(f'logs/{exit_time}-ACK-times.csv', 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=ack_time_data.keys())
            writer.writeheader()
            writer.writerow(ack_time_data)
        print(f"File {exit_time}-ACK-times.csv Saved!")

        with open(f'logs/{exit_time}-TX-times.csv', 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=tx_time_data.keys())
            writer.writeheader()
            writer.writerow(tx_time_data)
        print(f"File {exit_time}-TX-times.csv Saved!")

        exit(1)
