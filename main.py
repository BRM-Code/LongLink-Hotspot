from iroha import Iroha, IrohaCrypto, IrohaGrpc
from datetime import datetime
import json

PRIVATE_KEY = ""
DOMAIN = ""
SUPER_USER = "" # user with the privilege to add accounts to the chain


def initialize():
    iroha = Iroha(f'{SUSER}@{DOMAIN}')
    net = IrohaGrpc()


def create_account(drone_id, iroha, net):
    drone_account = f"{drone_id}@{DOMAIN}"
    tx = iroha.transaction([
        iroha.command('CreateAccount', account_name=drone_id, domain_id=DOMAIN, public_key='')
    ])
    IrohaCrypto.sign_transaction(tx, PRIVATE_KEY)
    net.send_tx(tx)
    return drone_account


def push_to_iroha(latitude, longitude, ground_speed, altitude, satellites, sat_fix, pitch, roll, heading, vbatt,
                  consumption, rssi, arm, iroha, net, drone_account):
    now = datetime.now()
    telemetry_data = {
        'GPS Frame': {
            'Latitude': latitude,
            'Longitude': longitude,
            'GroundSpeed': ground_speed,
            'Altitude': altitude,
            'Satellites': satellites,
            'SatFix': sat_fix
        },
        'Attitude Frame': {
            'Pitch': pitch,
            'Roll': roll,
            'Heading': heading
        },
        'Status Frame': {
            'Vbatt': vbatt,
            'Consumption': consumption,
            'RSSI': rssi,
            'arm': arm
        },
        'timestamp': now.strftime('%Y-%m-%d %H:%M:%S')
    }
    telemetry_json = json.dumps(telemetry_data)
    tx = iroha.transaction([
        iroha.command('SetAccountDetail', account_id=drone_account, key='telemetry', value=telemetry_json)
    ])
    IrohaCrypto.sign_transaction(tx, PRIVATE_KEY)
    net.send_tx(tx)
