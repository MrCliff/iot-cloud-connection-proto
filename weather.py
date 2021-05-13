#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
from datetime import tzinfo
import smbus2
import bme280

import json

I2C_PORT = 1
BME280_ADDRESS = 0x76


def init_sensors():
    global bus
    global calibration_params

    bus = smbus2.SMBus(I2C_PORT)
    calibration_params = bme280.load_calibration_params(bus, BME280_ADDRESS)


def print_data(data):
    # the compensated_reading class has the following attributes
    print(data.id)
    print(data.timestamp)
    print('{} °C'.format(data.temperature))
    print('{} hPa'.format(data.pressure))
    print('{} %rH'.format(data.humidity))
    
    # there is a handy string representation too
    print(data)
    print(temperature_to_json(data))
    print(pressure_to_json(data))
    print(humidity_to_json(data))


def temperature_to_json(data):
    return to_json(data.timestamp, data.temperature, '°C')


def pressure_to_json(data):
    return to_json(data.timestamp, data.pressure, 'hPa')


def humidity_to_json(data):
    return to_json(data.timestamp, data.humidity, '%rH')


def to_json(timestamp, value, unit):
    return json.dumps(
        {
            "timestamp": timestamp.astimezone().isoformat(),
            "value": value,
            "unit": unit
        }
    )


def main():
    init_sensors()

    try:
        while True:
            # the sample method will take a single reading and return a
            # compensated_reading object
            data = bme280.sample(bus, BME280_ADDRESS, calibration_params)
            print_data(data)
            
            time.sleep(1)
    except KeyboardInterrupt:
        print('Stopped')


if __name__ == "__main__":
    main()
