import time

from IrohaSetup import store_telemetry_data, get_device_details
from TelemetryFaker import generate_telemetry, convert_12bit

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
