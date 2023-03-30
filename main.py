import time

from TelemetryFaker import generate_telemetry, get_drone_id
from IrohaSetup import create_account, store_telemetry_data

drone_id = get_drone_id()
drone_account = create_account(drone_id)

tele = None

while True:
    for i in range(10):
        print(f"[{i}] Sending message")
        tele = generate_telemetry(tele)  # Will be replaced with actual telemetry from a UAV
        store_telemetry_data(tele, drone_id)
        time.sleep(5)
