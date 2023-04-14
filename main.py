import base64
import json
import socket
import sys
import asyncio

print("     __                      __    _       __         __  __      __                   __ \n"
      "    / /   ____  ____  ____ _/ /   (_)___  / /__      / / / /___  / /__________  ____  / /_\n"
      "   / /   / __ \/ __ \/ __ `/ /   / / __ \/ //_/_____/ /_/ / __ \/ __/ ___/ __ \/ __ \/ __/\n"
      "  / /___/ /_/ / / / / /_/ / /___/ / / / / ,< /_____/ __  / /_/ / /_(__  ) /_/ / /_/ / /_  \n"
      " /_____/\____/_/ /_/\__, /_____/_/_/ /_/_/|_|     /_/ /_/\____/\__/____/ .___/\____/\__/  \n"
      "                   /____/                                             /_/             ")
from IrohaSetup import store_telemetry_data, get_device_details, DEBUG, connect


async def listen_push_data():
    print("[System] Started Listener")
    while True:
        data, address = hotspot_socket.recvfrom(1024)
        print("[PK] Received a packet -> ", end="")
        push_ack = None
        match data[3]:
            case 0x00:
                json_str = data[12:].decode('utf-8')
                try:
                    packet = json.loads(json_str)
                    if 'stat' in packet:
                        print("stat packet!")
                    elif 'rxpk' in packet:
                        print("transmission packet!")
                        data_decoded = base64.b64decode(packet['rxpk'][0]['data'])
                        print(f"Data extracted: {data_decoded}") if DEBUG else None
                        try:
                            uav_id, tele = process_telemetry(data_decoded)
                            store_telemetry_data(tele, uav_id, gateway_id)
                            get_device_details(uav_id, gateway_id) if DEBUG else None
                            send_downlink_packet(uplink_ack(packet['rxpk'][0], uav_id), address)
                        except RuntimeWarning:
                            print("[PK] Packet failed to be processed")
                    else:
                        print("[Error] Unknown packet type!")
                except json.JSONDecodeError:
                    print('[Error] Invalid JSON received!')

                token = data[1:3]
                push_ack = bytes([2, token[0], token[1], 0x01])

            case 0x02:
                print(f"PULL_DATA: Gateway-MAC = {data[4:11]}")
                token = data[1:3]
                push_ack = bytes([2, token[0], token[1], 0x04])

            case 0x05:
                print(f"TX_ACK: Token sent: {data[1:2]}")
                try:
                    json_str = data[12:].decode('utf-8')
                    print(f"[PK] ERROR: {json_str}")
                except IndexError:
                    print("[PK] Packet sent OK")

        # Send ACK to packet forwarder
        if push_ack:
            hotspot_socket.sendto(push_ack, address)


def send_downlink_packet(txpk, address):
    json_data = json.dumps({"txpk": txpk})

    # Create a PULL_RESP packet
    protocol_version = 2
    token = b"\x12\x34"
    packet_identifier = 0x03
    packet = bytes([protocol_version]) + token + bytes([packet_identifier]) + json_data.encode()

    # Send the packet to the packet forwarder
    print("[System] Sending PULL_RESP packet...", end="")
    hotspot_socket.sendto(packet, address)
    print("sent!")


def uplink_ack(downlink_packet, uav_id):
    print(downlink_packet)
    status = 1  # TODO: Maybe send the UAV back some useful information here
    ack = f"{uav_id}{gateway_id}{status}"
    ack_encoded = base64.b64encode(ack.encode('utf-8')).decode('utf-8')

    txpk = {
        'imme': True,  # Send packet immediately
        'freq': downlink_packet['freq'],  # TX central frequency in MHz
        'rfch': downlink_packet['rfch'],  # Concentrator "RF chain" used for TX
        'powe': 14,  # TX output power in dBm
        'modu': 'LORA',  # Modulation identifier
        "datr": 'SF11BW125',  # LoRa data-rate identifier (eg. SF12BW500)
        'size': sys.getsizeof(ack_encoded),  # RF packet payload size in bytes
        "codr": "4/6",  # LoRa ECC coding rate identifier
        "ipol": False,  # Lora modulation polarization inversion
        'data': ack_encoded  # Base64 encoded RF packet payload
    }
    return txpk


def process_telemetry(decoded_data):
    data_list = str(decoded_data[1:len(decoded_data)]).split(',')
    print(f"Data Decoded = {data_list}") if DEBUG else None
    try:
        uav_id = data_list[12][0:2]
        telemetry = {
            'Latitude': data_list[0][2:len(data_list[0])],
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
    return uav_id, telemetry


async def task_loop():
    packet_task = asyncio.create_task(listen_push_data())
    await packet_task


try:
    if bool(sys.argv[1]):
        print(f"[System] Debug: ON")
        DEBUG = True
except IndexError:
    print(f"[System] Debug: OFF")

gateway_id = "g1"
print(f"[System] Gateway ID: {gateway_id}")
connect()
print("[System] Connecting to the packet forwarder...", end="")
hotspot_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
hotspot_socket.bind(('localhost', 1730))
print("Connected!")

asyncio.run(task_loop())
