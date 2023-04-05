import random


def generate_telemetry(last_telemetry=None):
    print("Generating Telemetry")
    telemetry = {}

    if last_telemetry is not None:
        print("Correlating with previous telemetry")
        latitude, longitude = randomize_location(last_telemetry['Latitude'],
                                                 last_telemetry['Longitude'])
        ground_speed = randomize_value(last_telemetry['GroundSpeed'], 0.5)
        altitude = randomize_value(last_telemetry['Altitude'], 5)
        satellites = randomize_value(last_telemetry['Satellites'], 0.1)
        sat_fix = random.choice([True, False])

        pitch = randomize_value(last_telemetry['Pitch'], 5)
        roll = randomize_value(last_telemetry['Roll'], 5)
        heading = randomize_value(last_telemetry['Heading'], 5)

        vbatt = randomize_value(last_telemetry['Vbatt'], 0.05)
        consumption = randomize_value(last_telemetry['Consumption'], 0.1)
        rssi = randomize_value(last_telemetry['RSSI'], 0.1)
        arm = last_telemetry['arm']

        telemetry.update({
            'Latitude': latitude,
            'Longitude': longitude,
            'GroundSpeed': ground_speed,
            'Altitude': altitude,
            'Satellites': satellites,
            'SatFix': sat_fix,
            'Pitch': pitch,
            'Roll': roll,
            'Heading': heading,
            'Vbatt': vbatt,
            'Consumption': consumption,
            'RSSI': rssi,
            'arm': arm
        })

    else:
        # Randomize all telemetry data
        telemetry.update({
            'Latitude': random.uniform(-90, 90),
            'Longitude': random.uniform(-180, 180),
            'GroundSpeed': randomize_value(5, 1),
            'Altitude': randomize_value(100, 10),
            'Satellites': randomize_value(10, 1),
            'SatFix': random.choice([True, False]),
            'Pitch': randomize_value(0, 5),
            'Roll': randomize_value(0, 5),
            'Heading': randomize_value(0, 5),
            'Vbatt': randomize_value(12, 0.5),
            'Consumption': randomize_value(1, 0.1),
            'RSSI': randomize_value(-70, 2),
            'arm': random.choice([True, False])
        })

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
    return "testuav1"


def convert_12bit(dictionary):
    converted_dict = {}

    for key, value in dictionary.items():
        if isinstance(value, (int, float)):
            if 0 <= value <= 4095:
                converted_dict[key] = int(value)
            else:
                value_bin = format(int(value), '012b')
                for i in range(0, len(value_bin), 12):
                    partial_value_bin = value_bin[i:i+12]
                    partial_value = int(partial_value_bin, 2)
                    sub_key = f"{key}_{i//12}"
                    converted_dict[sub_key] = partial_value
        else:
            converted_dict[key] = value
    return converted_dict
