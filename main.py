import base64
import json
import socket
import struct
import sys
import time
from Crypto.Cipher import AES

print("     __                      __    _       __         __  __      __                   __ \n"
      "    / /   ____  ____  ____ _/ /   (_)___  / /__      / / / /___  / /__________  ____  / /_\n"
      "   / /   / __ \/ __ \/ __ `/ /   / / __ \/ //_/_____/ /_/ / __ \/ __/ ___/ __ \/ __ \/ __/\n"
      "  / /___/ /_/ / / / / /_/ / /___/ / / / / ,< /_____/ __  / /_/ / /_(__  ) /_/ / /_/ / /_  \n"
      " /_____/\____/_/ /_/\__, /_____/_/_/ /_/_/|_|     /_/ /_/\____/\__/____/ .___/\____/\__/  \n"
      "                   /____/                                             /_/             ")
from IrohaSetup import store_telemetry_data, get_device_details, DEBUG, iroha_connect

TESTING = False
ENCRYPTED_PACKETS = True
ACKNOWLEDGING_PACKETS = True
received_ok = False
last_token = []
ack_wait = {}  # UAVs awaiting ACK
server_address = ('localhost', 1730)
Packet_timer = 0
known_uav_keys = {'u1': (
bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C]),
bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))}

PROTOCOL_VERSION = 0x02
PUSH_DATA_ID = 0x00
PUSH_ACK_ID = 0x01
PULL_DATA_ID = 0x02
PULL_ACK_ID = 0x04
TX_ACK = 0x05


def listen_for_data():
    while True:
        try:
            return hotspot_socket.recvfrom(1024)
        except socket.error:
            pass


def push_data_packet(rec_packet, address):
    global Packet_timer
    print("[PK] Received a packet -> ", end="") if DEBUG else None
    try:
        packet = json.loads(rec_packet[12:].decode('utf-8'))
        if 'stat' in packet:
            print("stat packet!") if DEBUG else None
        elif 'rxpk' in packet:
            print("transmission packet!") if DEBUG else None
            if ENCRYPTED_PACKETS:
                # Checking if packet is from known UAV
                base1 = base64.b64decode(packet['rxpk'][0]['data'])
                uav_id = base1[1:3].decode('utf-8')
                if uav_id not in known_uav_keys:
                    print(f"[PK] unable to find UAV with ID {uav_id}, packet likely not for me!")
                    return

                #  Check if the packet is an ACK packet
                if ACKNOWLEDGING_PACKETS and uav_id in ack_wait:
                    print(f"[PK] Received ACK from {uav_id} it took {round((time.time() - Packet_timer), 2)} seconds")
                    del ack_wait[uav_id]
                    return

                # It is so now we attempt decrypt
                # Remove UAV_ID to allow decryption
                base1 = base1.decode('utf-8').replace(uav_id, '').encode('utf-8')
                base2 = base64.b64decode(base1)
                uav_key_iv = known_uav_keys[uav_id]
                try:
                    cipher = AES.new(uav_key_iv[0], AES.MODE_CBC, uav_key_iv[1])
                    data_decoded = cipher.decrypt(base2)
                except ValueError:
                    print(f"[PK][{uav_id}] ERROR: data couldn't be decrypted, likely not for me or key/iv incorrect")
                    return
            else:
                data_decoded = base64.b64decode(packet['rxpk'][0]['data'])

            data_list = str(data_decoded[1:-14].decode('utf-8')).split(' ')

            print(f"Data extracted: {data_decoded}") if DEBUG else None
            try:
                uav_id, tele = process_telemetry(uav_id, data_list)
                if uav_id:
                    Packet_timer = time.time()
                # store_telemetry_data(tele, uav_id, gateway_id)
                # get_device_details(uav_id, gateway_id) if DEBUG else None
                if ACKNOWLEDGING_PACKETS:
                    send_downlink_packet(uplink_ack(uav_id), address)
                    ack_wait[uav_id] = 0
            except RuntimeWarning:
                print("[PK] Data failed to be processed")
                print(f"Data = {data_decoded}")
        else:
            print("[Error] Unknown packet type!")
    except json.JSONDecodeError:
        print('[Error] Invalid JSON received!')


def packet_forwarder_ack(token, identifier, address):
    push_ack = bytes([2, token[0], token[1], identifier])
    hotspot_socket.sendto(push_ack, address)


def send_downlink_packet(txpk, address):
    json_data = json.dumps({"txpk": txpk})

    token = b"\x12\x34"
    packet_identifier = 0x03
    packet_data = json_data.encode()
    packet_size = len(packet_data)

    packet = struct.pack("!B 2s B {0}s".format(packet_size), PROTOCOL_VERSION, token, packet_identifier, packet_data)
    last_token.append(token)

    # Send the packet to the packet forwarder
    print("[System] Sending Downlink") if DEBUG or TESTING else None
    while True:
        hotspot_socket.sendto(packet, address)
        #hotspot_socket.sendmsg(packet, address)
        rec_packet, address = listen_for_data()
        if rec_packet[3] == 0x05:
            print(f"Received TX_PCK ACK {rec_packet[12:].decode('utf-8')}")
            break
        time.sleep(0.1)
        print("Re-sending")


def uplink_ack(uav_id):
    print(f"[ACK] Sending ACK to {uav_id}")
    status = 1  # TODO: Maybe send the UAV back some useful information here
    ack = f"{uav_id}{gateway_id}{status}".encode('utf-8')
    ack_encoded = base64.b64encode(ack).decode('utf-8')

    txpk = {
        'imme': True,  # Send packet immediately
        'freq': 867.5,  # downlink_packet['freq'],  # TX central frequency in MHz
        'rfch': 0,  # downlink_packet['rfch'],  # Concentrator "RF chain" used for TX
        'powe': 20,  # TX output power in dBm
        'modu': 'LORA',  # Modulation identifier
        "datr": 'SF7BW125',  # LoRa data-rate identifier (eg. SF12BW500)
        'size': len(ack),  # RF packet payload size in bytes
        "codr": "4/5",  # LoRa ECC coding rate identifier
        "ipol": False,  # Lora modulation polarization inversion
        'data': ack_encoded  # Base64 encoded RF packet payload
    }
    return txpk


def test_tx_params(address):
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
                send_downlink_packet(txpk, address)
                time.sleep(1)

    print("[TESTING] Testing complete")
    TESTING = False


def process_telemetry(uav_id, data_list):
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
    except IndexError:
        raise RuntimeWarning(f"[ERROR] Data failed to be cast to a JSON!\nData Decoded = {data_list}")
    print(f"[{uav_id}] Telemetry: {telemetry}") if DEBUG else None
    print(f"[PK] from {uav_id} ")
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


if len(sys.argv) > 1 and bool(sys.argv[1]):
    print(f"[System] Debug: ON")
    DEBUG = True
else:
    print(f"[System] Debug: OFF")
print(f"[System] Encrypted packets = {ENCRYPTED_PACKETS}")
gateway_id = "g1"
print(f"[System] Gateway ID: {gateway_id}")
iroha_connect()
print("[System] Connecting to the packet forwarder...", end="")
hotspot_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
hotspot_socket.bind(server_address)
hotspot_socket.setblocking(False)

print("Connected!")
last_telemetry = None

while True:
    data, addr = listen_for_data()

    if data[3] == PUSH_DATA_ID:
        packet_forwarder_ack(data[1:3], PUSH_ACK_ID, addr)
        push_data_packet(data, addr)

    elif data[3] == PULL_DATA_ID:
        packet_forwarder_ack(data[1:3], PULL_ACK_ID, addr)
        if not received_ok:
            print(f"[System] OK to send packets")
            received_ok = True
            if TESTING:
                test_tx_params(addr)

    elif data[3] == TX_ACK:
        if data[1:3] in last_token:
            print("[PK] Packet sent OK")
            last_token.remove(data[1:3])
        else:
            print(f"[ERROR] Token not recognised {data[1:3]}")
