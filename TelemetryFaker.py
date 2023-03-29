import random


def generate_telemetry(last_telemetry=None):
    telemetry = {}

    if last_telemetry is not None:
        # Correlate with previous telemetry
        latitude, longitude = randomize_location(last_telemetry['GPS Frame']['Latitude'],
                                                 last_telemetry['GPS Frame']['Longitude'])
        ground_speed = randomize_value(last_telemetry['GPS Frame']['GroundSpeed'], 0.5)
        altitude = randomize_value(last_telemetry['GPS Frame']['Altitude'], 5)
        satellites = randomize_value(last_telemetry['GPS Frame']['Satellites'], 0.1)
        sat_fix = random.choice([True, False])

        pitch = randomize_value(last_telemetry['Attitude Frame']['Pitch'], 5)
        roll = randomize_value(last_telemetry['Attitude Frame']['Roll'], 5)
        heading = randomize_value(last_telemetry['Attitude Frame']['Heading'], 5)

        vbatt = randomize_value(last_telemetry['Status Frame']['Vbatt'], 0.05)
        consumption = randomize_value(last_telemetry['Status Frame']['Consumption'], 0.1)
        rssi = randomize_value(last_telemetry['Status Frame']['RSSI'], 0.1)
        arm = last_telemetry['Status Frame']['arm']

        telemetry['GPS Frame'] = {
            'Latitude': latitude,
            'Longitude': longitude,
            'GroundSpeed': ground_speed,
            'Altitude': altitude,
            'Satellites': satellites,
            'SatFix': sat_fix
        }

        telemetry['Attitude Frame'] = {
            'Pitch': pitch,
            'Roll': roll,
            'Heading': heading
        }

        telemetry['Status Frame'] = {
            'Vbatt': vbatt,
            'Consumption': consumption,
            'RSSI': rssi,
            'arm': arm
        }

    else:
        # Randomize all telemetry data
        telemetry['GPS Frame'] = {
            'Latitude': random.uniform(-90, 90),
            'Longitude': random.uniform(-180, 180),
            'GroundSpeed': randomize_value(5, 1),
            'Altitude': randomize_value(100, 10),
            'Satellites': randomize_value(10, 1),
            'SatFix': random.choice([True, False])
        }

        telemetry['Attitude Frame'] = {
            'Pitch': randomize_value(0, 5),
            'Roll': randomize_value(0, 5),
            'Heading': randomize_value(0, 5)
        }

        telemetry['Status Frame'] = {
            'Vbatt': randomize_value(12, 0.5),
            'Consumption': randomize_value(1, 0.1),
            'RSSI': randomize_value(-70, 2),
            'arm': random.choice([True, False])
        }

    return telemetry


def randomize_value(value, delta):
    return round(random.uniform(value - delta, value + delta), 2)


def randomize_location(latitude, longitude):
    delta = 0.0005  # About 50 meters
    return (
        randomize_value(latitude, delta),
        randomize_value(longitude, delta)
    )


def get_drone_id():
    return "TestUAV1"
