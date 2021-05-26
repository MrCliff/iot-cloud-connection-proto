#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import os
import time
from datetime import tzinfo
import smbus2
import bme280

import json
from uuid import uuid4

# AWS specific
from awscrt import io, mqtt
from awsiot import mqtt_connection_builder

# Azure specific
# Python Device SDK for IoT Hub:
# https://github.com/Azure/azure-iot-sdk-python
from azure.iot.device import IoTHubDeviceClient, Message

I2C_PORT = 1
BME280_ADDRESS = 0x76

MQTT_TOPIC_FORMAT = "dt/weather/{location}/{client_id}"

# Azure specific
# The device connection string to authenticate the device with your IoT hub.
# Using the Azure CLI:
# az iot hub device-identity show-connection-string --hub-name {your IoT Hub name} --device-id {your device id} --output table
AZURE_CONNECTION_STRING = "HostName={iot_hub_name}.azure-devices.net;DeviceId={device_id};SharedAccessKey={primary_key}"
AZURE_DEVICE_PRIMARY_KEY = os.getenv("AZURE_DEVICE_PRIMARY_KEY")


def init_arg_parser():
    parser = argparse.ArgumentParser(description="Periodically measure some weather parameters and send " +
                                     "them to different cloud services using MQTT. Where applicable, uses " +
                                     "MQTT topic of form \"" + MQTT_TOPIC_FORMAT + "\".")

    # AWS specific
    parser.add_argument('--endpoint', required=True, help="Your AWS IoT custom endpoint, not including a port. " +
                        "Ex: \"abcd123456wxyz-ats.iot.eu-west-1.amazonaws.com\"")
    parser.add_argument('--cert', required=True, help="File path to your client certificate, in PEM format.")
    parser.add_argument('--key', required=True, help="File path to your private key, in PEM format.")
    parser.add_argument('--root-ca', help="File path to root certificate authority, in PEM format. " +
                        "Necessary if MQTT server uses a certificate that's not already in " +
                        "your trust store.")
    parser.add_argument('--verbosity', choices=[x.name for x in io.LogLevel], default=io.LogLevel.NoLogs.name,
                        help="Logging level.")
    parser.add_argument('--log-file', default="stderr",
                        help="Log file location. Use 'stdout' or 'stderr' for stdout or stderr.")
    parser.add_argument('--client-id', default=str(uuid4()), help="Client ID for MQTT connection.")

    # Azure specific
    parser.add_argument('--azure-iot-hub-name', required=True, help="Name of the Azure IoT Hub to which connect.")
    parser.add_argument('--azure-device-id', required=True, help="Azure device ID for MQTT connection.")

    # General
    parser.add_argument('--location', default="earth", help="Physical location of the weather sensor. This is used as " +
                        "part of the MQTT topic.")
    parser.add_argument('--msg-freq', default=5, help="Message frequency. Number of seconds to wait between measurements.")

    return parser


# AWS specifics START
class AWSClient():
    '''Class for all AWS Cloud specific functionality.'''
    # TODO: Vaihda print-kutsut oikeaksi lokitukseksi.
    def __init__(self, args):
        self.cert = args.cert
        self.client_id = args.client_id
        self.endpoint = args.endpoint
        self.key = args.key
        self.location = args.location
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
        '''Callback, when connection is accidentally lost.'''
        print("Connection interrupted. error: {}".format(error))


    def on_connection_resumed(self, connection, return_code, session_present, **kwargs):
        '''Callback, when an interrupted connection is re-established.'''
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

# Azure specifics START
class AzureClient():
    '''Class for all Azure Cloud specific functionality.'''
    # TODO: Vaihda print-kutsut oikeaksi lokitukseksi.
    def __init__(self, args):
        self.iot_hub_name = args.azure_iot_hub_name
        self.device_id = args.azure_device_id
        self.key = AZURE_DEVICE_PRIMARY_KEY
        self.location = args.location
        # self.log_file = args.log_file
        
        # io.init_logging(getattr(io.LogLevel, self.verbosity), self.log_file)

        self.init_connection()


    def init_connection(self):
        # event_loop_group = io.EventLoopGroup(1)
        # host_resolver = io.DefaultHostResolver(event_loop_group)
        # client_bootstrap = io.ClientBootstrap(event_loop_group, host_resolver)

        # self.mqtt_connection = mqtt_connection_builder.mtls_from_path(
        #     endpoint=self.endpoint,
        #     cert_filepath=self.cert,
        #     pri_key_filepath=self.key,
        #     client_bootstrap=client_bootstrap,
        #     ca_filepath=self.root_ca,
        #     on_connection_interrupted=self.on_connection_interrupted,
        #     on_connection_resumed=self.on_connection_resumed,
        #     client_id=self.client_id,
        #     clean_session=False,
        #     keep_alive_secs=6)

# TODO: siirrä seuraavat AzureClienttiin.
def iothub_client_init():
    # Create an IoT Hub client
    client = IoTHubDeviceClient.create_from_connection_string(CONNECTION_STRING)
    return client

def iothub_client_telemetry_sample_run():

    try:
        client = iothub_client_init()
        print ( "IoT Hub device sending periodic messages, press Ctrl-C to exit" )

        while True:
            # Build the message with simulated telemetry values.
            temperature = TEMPERATURE + (random.random() * 15)
            humidity = HUMIDITY + (random.random() * 20)
            msg_txt_formatted = MSG_TXT.format(temperature=temperature, humidity=humidity)
            message = Message(msg_txt_formatted)

            # Add a custom application property to the message.
            # An IoT hub can filter on these properties without access to the message body.
            if temperature > 30:
              message.custom_properties["temperatureAlert"] = "true"
            else:
              message.custom_properties["temperatureAlert"] = "false"

            # Send the message.
            print( "Sending message: {}".format(message) )
            client.send_message(message)
            print ( "Message successfully sent" )
            time.sleep(1)

    except KeyboardInterrupt:
        print ( "IoTHubClient sample stopped" )
# Azure specifics END


def init_sensors():
    bus = smbus2.SMBus(I2C_PORT)
    calibration_params = bme280.load_calibration_params(bus, BME280_ADDRESS)

    return bus, calibration_params


def print_data(args, data):
    # the compensated_reading class has the following attributes
    # print(data.id)
    # print(data.timestamp)
    # print('{} °C'.format(data.temperature))
    # print('{} hPa'.format(data.pressure))
    # print('{} %rH'.format(data.humidity))
    
    # there is a handy string representation too
    print(data)
    print(to_json(args.client_id, data))


def to_json(client_id, bme280data):
    '''Formats the given data into a JSON string.'''
    return json.dumps(
        {
            "device_id": client_id,
            # "timestamp": bme280data.timestamp.astimezone().isoformat(), # Human readable timestamp
            "timestamp": round(bme280data.timestamp.astimezone().timestamp() * 1000), # UTC timestamp in milliseconds
            "temperature": {
                "value": round(bme280data.temperature, 2), # Resolution: 0.01°C
                "unit": '°C'
            },
            "pressure": {
                "value": round(bme280data.pressure, 2), # Resolution: 0.18Pa
                "unit": 'hPa'
            },
            "humidity": {
                "value": round(bme280data.humidity, 3), # Resolution: 0.008%
                "unit": '%rH'
            }
        }
    )


def send_data_to_aws(aws, data):
    '''Sends the given data to AWS using the given AWSClient. The AWSClient
    should have connection open.

    Data is sent to a MQTT topic of form
    "dt/weather/<sensor-location>/<sensor-client-id>"

    '''
    aws.send_message(MQTT_TOPIC_FORMAT.format(location=aws.location, client_id=aws.client_id), to_json(aws.client_id, data))


def main(args):
    print("Args:", args)
    bus, calibration_params = init_sensors()

    aws = AWSClient(args)
    aws.connect()

    try:
        while True:
            data = bme280.sample(bus, BME280_ADDRESS, calibration_params)
            print_data(args, data)
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
