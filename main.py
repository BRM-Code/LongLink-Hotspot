import base64
import json
import socket
import sys
from IrohaSetup import store_telemetry_data, get_device_details, DEBUG


def listen_push_data():
    print("[System] Connecting to the packet forwarder...", end="")
    hotspot_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    hotspot_socket.bind(('localhost', 1730))
    print("Connected!")

    while True:
        data, address = hotspot_socket.recvfrom(1024)
        # check if the received packet is a PUSH_DATA packet
        if data[3] == 0x00:

            # Tell the packet-forwarder data arrived
            token = data[1:3]
            push_ack = bytes([2, token[0], token[1], 0x01])
            hotspot_socket.sendto(push_ack, address)

            print("[PK] Received a packet -> ", end="")
            json_str = data[12:].decode('utf-8')
            try:
                packet = json.loads(json_str)
                if 'stat' in packet:
                    print("stat packet!")
                elif 'rxpk' in packet:
                    print("transmission packet!")
                    data_decoded = base64.b64decode(packet['rxpk'][0]['data'])
                    print(f"Data extracted: {data_decoded}") if DEBUG else None
                    uav_id, tele = process_telemetry(data_decoded)
                    store_telemetry_data(tele, uav_id, gateway_id)
                    get_device_details(uav_id, gateway_id) if DEBUG else None
                else:
                    print("Error: Unknown packet type!")
            except json.JSONDecodeError:
                print('Error: Invalid JSON received!')


def process_telemetry(decoded_data):
    data_list = str(decoded_data[1:len(decoded_data)]).split(',')
    print(f"Data Decoded = {data_list}") if DEBUG else None
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
    print(f"[{uav_id}] Telemetry: {telemetry}") if DEBUG else None
    return uav_id, telemetry


icon = ("     __                      __    _       __         __  __      __                   __ \n"
        "    / /   ____  ____  ____ _/ /   (_)___  / /__      / / / /___  / /__________  ____  / /_\n"
        "   / /   / __ \/ __ \/ __ `/ /   / / __ \/ //_/_____/ /_/ / __ \/ __/ ___/ __ \/ __ \/ __/\n"
        "  / /___/ /_/ / / / / /_/ / /___/ / / / / ,< /_____/ __  / /_/ / /_(__  ) /_/ / /_/ / /_  \n"
        " /_____/\____/_/ /_/\__, /_____/_/_/ /_/_/|_|     /_/ /_/\____/\__/____/ .___/\____/\__/  \n"
        "                   /____/                                             /_/             ")
print(icon)

if len(sys.argv) > 1 and not sys.argv[1]:
    print(f"[System] Debug: ON")
    DEBUG = sys.argv[1]
else:
    print(f"[System] Debug: OFF")
gateway_id = "g1"
print(f"[System] Gateway ID: {gateway_id}")

while True:
    listen_push_data()
