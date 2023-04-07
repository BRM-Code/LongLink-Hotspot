import json
import time
import socket
from IrohaSetup import store_telemetry_data, get_device_details
from TelemetryFaker import generate_telemetry, convert_12bit


def listen_push_data():
    print("Connecting to the packet forwarder...")
    hotspot_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    hotspot_socket.bind(('localhost', 1700))

    while True:
        data, address = hotspot_socket.recvfrom(1024)
        # check if the received packet is a PUSH_DATA packet
        if data[3] == 0x00:
            print("Received a packet!")

            json_str = data[12:].decode('utf-8')
            try:
                json_obj = json.loads(json_str)
                print(json_obj)
            except json.JSONDecodeError:
                print('Error: Invalid JSON')

            token = data[1:3]
            push_ack = bytes([2, token[0], token[1], 0x01])
            hotspot_socket.sendto(push_ack, address)


drone_id = "u1"
gateway_id = "g1"

# create_domain("test1")
# drone_account = create_account(drone_id)
# gateway_account = create_account(gateway_id)

# grant_permission(drone_id)
# uav_allow_gateway(drone_id, gateway_id)

tele = None

while True:
    for i in range(10):
        get_device_details(drone_id)
        print(f"[{i}] Sending message")
        tele = generate_telemetry(tele)  # Will be replaced with actual telemetry from a UAV
        bit_tele = convert_12bit(tele)
        store_telemetry_data(bit_tele, drone_id, gateway_id)
        time.sleep(5)
