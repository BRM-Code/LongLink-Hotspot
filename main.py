import time

from TelemetryFaker import generate_telemetry, get_drone_id
from IrohaSetup import create_account_drone, push_to_iroha

drone_id = get_drone_id()
drone_account = create_account_drone(drone_id)

tele = None

while True:
    for i in range(10):
        tele = generate_telemetry(tele)  # Will be replaced with actual telemetry from a UAV
        push_to_iroha(tele, drone_id)
        time.sleep(5)
