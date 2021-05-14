#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import time
from datetime import tzinfo
import smbus2
import bme280

import json
from uuid import uuid4

# AWS specific
from awscrt import io, mqtt
from awsiot import mqtt_connection_builder

I2C_PORT = 1
BME280_ADDRESS = 0x76

def init_arg_parser():
    parser = argparse.ArgumentParser(description="Periodically measure some weather parameters and send " +
                                     "them to cloud services using MQTT.")

    # AWS specific
    parser.add_argument('--endpoint', required=True, help="Your AWS IoT custom endpoint, not including a port. " +
                        "Ex: \"abcd123456wxyz-ats.iot.eu-west-1.amazonaws.com\"")
    parser.add_argument('--cert', required=True, help="File path to your client certificate, in PEM format.")
    parser.add_argument('--key', required=True, help="File path to your private key, in PEM format.")
    parser.add_argument('--root-ca', help="File path to root certificate authority, in PEM format. " +
                        "Necessary if MQTT server uses a certificate that's not already in " +
                        "your trust store.")
    parser.add_argument('--client-id', default=str(uuid4()), help="Client ID for MQTT connection.")
    parser.add_argument('--verbosity', choices=[x.name for x in io.LogLevel], default=io.LogLevel.NoLogs.name,
                        help="Logging level.")
    parser.add_argument('--log-file', default="stderr",
                        help="Log file location. Use 'stdout' or 'stderr' for stdout or stderr.")

    # General
    parser.add_argument('--msg-freq', default=5, help="Message frequency. Number of seconds to wait between measurements.")

    return parser


# AWS specifics START
class AWSCloud():
    '''
    Class for all AWS Cloud specific functionality.
    '''
    # TODO: Vaihda print-kutsut oikeaksi lokitukseksi.
    def __init__(self, args):
        self.cert = args.cert
        self.client_id = args.client_id
        self.endpoint = args.endpoint
        self.key = args.key
        self.log_file = args.log_file
        self.root_ca = args.root_ca
        self.verbosity = args.verbosity
        
        io.init_logging(getattr(io.LogLevel, self.verbosity), self.log_file)

        self.init_connection()


    def init_connection(self):
        event_loop_group = io.EventLoopGroup(1)
        host_resolver = io.DefaultHostResolver(event_loop_group)
        client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)

        self.mqtt_connection = mqtt_connection_builder.mtls_from_path(
            endpoint=self.endpoint,
            cert_filepath=self.cert,
            pri_key_filepath=self.key,
            client_bootstrap=client_bootstrap,
            ca_filepath=self.root_ca,
            on_connection_interrupted=self.on_connection_interrupted,
            on_connection_resumed=self.on_connection_resumed,
            client_id=self.client_id,
            clean_session=False,
            keep_alive_secs=6)


    def on_connection_interrupted(self, connection, error, **kwargs):
        '''
        Callback, when connection is accidentally lost.
        '''
        print("Connection interrupted. error: {}".format(error))


    def on_connection_resumed(self, connection, return_code, session_present, **kwargs):
        '''
        Callback, when an interrupted connection is re-established.
        '''
        print("Connection resumed. return_code: {} session_present: {}".format(return_code, session_present))


    def connect(self):
        print("Connecting to {} with client ID '{}'...".format(self.endpoint, self.client_id))
        connect_future = self.mqtt_connection.connect()

        # Future.result() waits until a result is available
        connect_future.result()
        print("Connected!")


    def disconnect(self):
        print("Disconnecting...")
        disconnect_future = self.mqtt_connection.disconnect()
        disconnect_future.result()
        print("Disconnected!")


    def send_message(self, topic, message):
        print("Publishing message to topic '{}': {}".format(topic, message))
        self.mqtt_connection.publish(
            topic=topic,
            payload=message,
            qos=mqtt.QoS.AT_MOST_ONCE)
# AWS specifics END


def init_sensors():
    bus = smbus2.SMBus(I2C_PORT)
    calibration_params = bme280.load_calibration_params(bus, BME280_ADDRESS)

    return bus, calibration_params


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


def send_data_to_aws(aws, data):
    aws.send_message("sensor/temperature", temperature_to_json(data))


def main(args):
    print("Args:", args)
    bus, calibration_params = init_sensors()

    aws = AWSCloud(args)
    aws.connect()

    try:
        while True:
            data = bme280.sample(bus, BME280_ADDRESS, calibration_params)
            print_data(data)
            send_data_to_aws(aws, data)
            
            time.sleep(args.msg_freq)
    except KeyboardInterrupt:
        pass
    finally:
        aws.disconnect()

    print("Stopped")


if __name__ == '__main__':
    args = init_arg_parser().parse_args()
    main(args)
