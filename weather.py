#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import os
import time
from datetime import tzinfo, datetime, timedelta
import asyncio
import smbus2
import bme280

import json
from uuid import uuid4

# AWS specific
# API: https://awslabs.github.io/aws-crt-python/
from awscrt import io, mqtt
# API: https://aws.github.io/aws-iot-device-sdk-python-v2/index.html
from awsiot import mqtt_connection_builder

# Azure specific
# Python Device SDK for IoT Hub:
# https://github.com/Azure/azure-iot-sdk-python
from azure.iot.device.aio import IoTHubDeviceClient
from azure.iot.device import Message

# GCP specific
import ssl
# API: https://eclipse.org/paho/clients/python/docs/
import paho.mqtt.client as paho_mqtt
import jwt

# General
DEFAULT_I2C_PORT = 1
DEFAULT_BME280_ADDRESS = 0x76

# AWS specific
AWS_MQTT_TOPIC_FORMAT = "dt/weather/{location}/{client_id}"

# Azure specific
AZURE_DEVICE_PRIMARY_KEY = os.getenv("AZURE_DEVICE_PRIMARY_KEY")


def init_arg_parser():
    parser = argparse.ArgumentParser(description="Periodically measure some weather parameters and send " +
                                     "them to different cloud services using MQTT.")

    # General
    parser.add_argument("--cloud-provider", choices=("aws", "azure", "gcp", "all"), default="all", help="Cloud provider to which to send data.")
    parser.add_argument("--location", default="earth", help="Physical location of the weather sensor.")
    parser.add_argument("--msg-freq", default=5, help="Message frequency. Number of seconds to wait between measurements.")
    parser.add_argument("--i2c-port", default=DEFAULT_I2C_PORT, type=int, help="The number of I2C port. Defaults to {}.".format(DEFAULT_I2C_PORT))
    parser.add_argument("--bme280-address", default=DEFAULT_BME280_ADDRESS, type=lambda x: int(x,0), help="The I2C address of BME280 sensor in the I2C bus. Defaults to 0x{:02X}.".format(DEFAULT_BME280_ADDRESS))

    # AWS specific
    parser.add_argument("--aws-endpoint", required=True, help="Your AWS IoT custom endpoint, not including a port. " +
                        "Ex: \"abcd123456wxyz-ats.iot.eu-west-1.amazonaws.com\"")
    parser.add_argument("--aws-client-id", default=str(uuid4()), help="Client ID for MQTT connection.")
    parser.add_argument("--aws-cert", required=True, help="File path to your client certificate to use with AWS, in PEM format.")
    parser.add_argument("--aws-key", required=True, help="File path to your private key to use with AWS, in PEM format.")
    parser.add_argument("--aws-root-ca", help="File path to AWS root certificate authority, in PEM format. " +
                        "Necessary if MQTT server uses a certificate that's not already in " +
                        "your trust store.")
    parser.add_argument("--aws-verbosity", choices=[x.name for x in io.LogLevel], default=io.LogLevel.NoLogs.name,
                        help="Logging level.")
    parser.add_argument("--aws-log-file", default="stderr",
                        help="Log file location. Use 'stdout' or 'stderr' for stdout or stderr.")

    # Azure specific
    parser.add_argument("--azure-iot-hub-name", required=True, help="Name of the Azure IoT Hub to which connect.")
    parser.add_argument("--azure-device-id", required=True, help="Azure device ID for MQTT connection.")

    # GCP specific
    parser.add_argument("--gcp-project-id", required=True, help="GCP project ID.")
    parser.add_argument("--gcp-cloud-region", default="europe-west1", help="GCP cloud region.")
    parser.add_argument("--gcp-registry-id", required=True, help="GCP Cloud IoT Core registry ID.")
    parser.add_argument("--gcp-device-id", required=True, help="GCP Cloud IoT Core device ID.")
    parser.add_argument("--gcp-key", required=True, help="File path to your private key to use with GCP, in PEM format.")
    parser.add_argument("--gcp-key-algorithm", choices=("RS256", "ES256"), required=True, help="Format of the private keys to use with GCP.")
    parser.add_argument("--gcp-root-ca", required=True, help="File path to GCP root CA (from https://pki.google.com/roots.pem)")
    parser.add_argument("--gcp-jwt-expires-minutes", default=20, type=int, help="Expiration time, in minutes, for JWT tokens.")
    parser.add_argument("--gcp-hostname", default="mqtt.googleapis.com", help="GCP Cloud IoT Core hostname.")
    parser.add_argument("--gcp-port", choices=(8883, 443), default=8883, type=int, help="GCP Cloud IoT Core port.")

    return parser


# AWS specifics START
class AWSClient():
    """Class for all AWS Cloud specific functionality."""
    # TODO: Change print calls to actual logging.
    def __init__(self, args):
        self.cert = args.aws_cert
        self.client_id = args.aws_client_id
        self.endpoint = args.aws_endpoint
        self.key = args.aws_key
        self.log_file = args.aws_log_file
        self.root_ca = args.aws_root_ca
        self.verbosity = args.aws_verbosity
        
        io.init_logging(getattr(io.LogLevel, self.verbosity), self.log_file)

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


    def connect(self):
        print("Connecting to {} with client ID '{}'...".format(self.endpoint, self.client_id))
        connect_future = self.mqtt_connection.connect()

        # Future.result() waits until a result is available
        connect_future.result()
        print("Connected to AWS!")


    def disconnect(self):
        print("Disconnecting from AWS...")
        disconnect_future = self.mqtt_connection.disconnect()
        disconnect_future.result()
        print("Disconnected from AWS!")


    def send_message(self, topic, message):
        print("Publishing message to AWS in topic '{}': {}".format(topic, message))
        self.mqtt_connection.publish(
            topic=topic,
            payload=message,
            qos=mqtt.QoS.AT_MOST_ONCE)


    ### Internal methods ###

    def on_connection_interrupted(self, connection, error, **kwargs):
        """Callback, when connection is accidentally lost."""
        print("Connection interrupted. error: {}".format(error))


    def on_connection_resumed(self, connection, return_code, session_present, **kwargs):
        """Callback, when an interrupted connection is re-established."""
        print("Connection resumed. return_code: {} session_present: {}".format(return_code, session_present))
# AWS specifics END

# Azure specifics START
class AzureClient():
    """Class for all Azure Cloud specific functionality."""
    # TODO: Change print calls to actual logging.
    def __init__(self, args):
        # The device connection string to authenticate the device with your IoT hub.
        # Using the Azure CLI:
        # az iot hub device-identity show-connection-string --hub-name {your IoT Hub name} --device-id {your device id} --output table
        self.AZURE_CONNECTION_STRING = "HostName={iot_hub_name}.azure-devices.net;DeviceId={device_id};SharedAccessKey={primary_key}"

        self.iot_hub_name = args.azure_iot_hub_name
        self.hostname = args.azure_iot_hub_name + ".azure-devices.net"
        self.device_id = args.azure_device_id
        self.key = AZURE_DEVICE_PRIMARY_KEY

        # formatted_conn_str = self.AZURE_CONNECTION_STRING.format(iot_hub_name=self.iot_hub_name,
        #                                                          device_id=self.device_id,
        #                                                          primary_key=self.key)
        # self.client = IoTHubDeviceClient.create_from_connection_string(formatted_conn_str)
        self.client = IoTHubDeviceClient.create_from_symmetric_key(self.key,
                                                                   self.hostname,
                                                                   self.device_id)


    async def connect(self):
        print("Connecting to host {} with device ID '{}'...".format(self.hostname, self.device_id))
        await self.client.connect()
        print("Connected to Azure!")


    async def disconnect(self):
        print("Disconnecting from Azure...")
        await self.client.disconnect()
        print("Disconnected from Azure!")


    async def send_message(self, custom_properties, json_message):
        message = Message(json_message, content_encoding="utf-8", content_type="application/json")
        message.custom_properties.update(custom_properties)

        print("Sending message to Azure: {}".format(message))
        await self.client.send_message(message)
# Azure specifics END

# GCP specifics START
class GCPClient():
    """Class for all Google Cloud Platform specific functionality."""
    # TODO: Change print calls to actual logging.
    def __init__(self, args):
        self.project_id       = args.gcp_project_id
        self.cloud_region     = args.gcp_cloud_region
        self.registry_id      = args.gcp_registry_id
        self.device_id        = args.gcp_device_id
        self.private_key_file = args.gcp_key
        self.algorithm        = args.gcp_key_algorithm
        self.ca_certs         = args.gcp_root_ca
        self.jwt_exp_minutes  = args.gcp_jwt_expires_minutes
        self.hostname         = args.gcp_hostname
        self.port             = args.gcp_port

        self.mqtt_topic = "/devices/{}/events".format(self.device_id)
        self.client_id = "projects/{}/locations/{}/registries/{}/devices/{}".format(
            self.project_id, self.cloud_region, self.registry_id, self.device_id
        )

        self.client = paho_mqtt.Client(client_id=self.client_id)

        # Enable SSL/TLS support.
        self.client.tls_set(ca_certs=self.ca_certs, tls_version=ssl.PROTOCOL_TLSv1_2)

        self.client.on_connect = self.on_connect
        self.client.on_disconnect = self.on_disconnect

        
    def connect(self):
        print("Connecting to host {}:{} with client ID '{}'...".format(self.hostname, self.port, self.client_id))

        # With Google Cloud IoT Core, the username field is ignored, and the
        # password field is used to transmit a JWT to authorize the device.
        self.client.username_pw_set(
            username="unused", password=self.create_jwt()
        )

        # Connect to the Google MQTT bridge.
        self.client.connect(self.hostname, self.port)
        self.client.loop_start()


    def disconnect(self):
        print("Disconnecting from GCP...")
        self.client.disconnect()
        self.client.loop_stop()


    def reconnect(self):
        self.disconnect()
        self.connect()

    
    def send_message(self, message):
        self.refresh_jwt_if_necessary()

        print("Sending message to GCP: {}".format(message))
        self.client.publish(self.mqtt_topic, message, qos=1)


    ### Internal methods ###

    def refresh_jwt_if_necessary(self):
        seconds_since_issue = (datetime.utcnow() - self.jwt_iat).seconds
        if seconds_since_issue > 60 * self.jwt_exp_minutes:
            print("Refreshing JWT after {}s".format(seconds_since_issue))
            self.reconnect()


    def on_connect(self, unused_client, unused_userdata, unused_flags, rc):
        """Callback for when a device connects."""
        print("on_connect", paho_mqtt.connack_string(rc))
        if rc == 0:
            print("Connected to GCP!")
        elif rc == 4:  # Bad (username or) password -> regenerate JWT
            print("Invalid JWT, regenerating JWT and reconnecting.")
            self.connect()


    def on_disconnect(self, unused_client, unused_userdata, rc):
        """Paho callback for when a device disconnects."""
        print("on_disconnect", self.error_str(rc))
        if rc == 0:
            print("Disconnected from GCP!")


    def error_str(self, rc):
        """Convert a Paho error to a human readable string."""
        return "{}: {}".format(rc, paho_mqtt.error_string(rc))


    def create_jwt(self):
        """Creates a JWT (https://jwt.io) to establish an MQTT connection.
        Returns:
            A JWT generated from the self.project_id and self.private_key_file,
            which expires in self.jwt_exp_minutes minutes.
        Raises:
            ValueError: If the self.private_key_file does not contain a known
            key.
        """
        
        token = {
            # The time that the token was issued at
            "iat": datetime.utcnow(),
            # The time the token expires.
            "exp": datetime.utcnow() + timedelta(minutes=self.jwt_exp_minutes),
            # The audience field should always be set to the GCP project id.
            "aud": self.project_id,
        }
        self.jwt_iat = token["iat"]
    
        # Read the private key file.
        with open(self.private_key_file, "r") as f:
            private_key = f.read()
            
            print(
                "Creating JWT using {} from private key file {}".format(
                    self.algorithm, self.private_key_file
                )
            )
            
            return jwt.encode(token, private_key, algorithm=self.algorithm)
# GCP specifics END

def init_sensors(args):
    bus = smbus2.SMBus(args.i2c_port)
    calibration_params = bme280.load_calibration_params(bus, args.bme280_address)

    return bus, calibration_params


def print_data(args, data):
    print(data)
    # print(to_json(args.client_id, args.location, data))


def to_json(device_id, location, bme280data):
    """Formats the given data into a JSON string."""
    utc_timestamp = round(bme280data.timestamp.astimezone().timestamp() * 1000) # UTC timestamp in milliseconds
    return json.dumps(
        {
            "id": str(utc_timestamp), # Row key for Azure
            "device_id": device_id,   # Partition key for AWS and Azure
            # "timestamp": bme280data.timestamp.astimezone().isoformat(), # Human readable timestamp
            "timestamp": utc_timestamp, # Sort key for AWS
            "location": location,
            "temperature": {
                "value": round(bme280data.temperature, 2), # Resolution: 0.01°C
                "unit": "°C"
            },
            "pressure": {
                "value": round(bme280data.pressure, 2), # Resolution: 0.18Pa
                "unit": "hPa"
            },
            "humidity": {
                "value": round(bme280data.humidity, 3), # Resolution: 0.008%
                "unit": "%rH"
            }
        }
    )


def send_data_to_aws(args, aws, data):
    """Sends the given data to AWS using the given AWSClient. The client
    should have connection open.

    Data is sent to a MQTT topic of form
    "dt/weather/<sensor-location>/<sensor-client-id>"
    """
    aws.send_message(AWS_MQTT_TOPIC_FORMAT.format(location=args.location, client_id=aws.client_id), to_json(aws.client_id, args.location, data))


async def send_data_to_azure(args, azure, data):
    """Sends the given data to Azure using the given AzureClient. The client
    should have connection open.
    """
    await azure.send_message({"location": args.location}, to_json(azure.device_id, args.location, data))


def send_data_to_gcp(args, gcp, data):
    """Sends the given data to GCP using the given GCPClient. The client
    should have connection open.
    """
    gcp.send_message(to_json(gcp.device_id, args.location, data))


async def main(args):
    # print("Args:", args)
    bus, calibration_params = init_sensors(args)

    cloud = args.cloud_provider
    
    if cloud == "aws" or cloud == "all":
        aws = AWSClient(args)
        aws.connect()
    if cloud == "azure" or cloud == "all":
        azure = AzureClient(args)
        await azure.connect()
    if cloud == "gcp" or cloud == "all":
        gcp = GCPClient(args)
        gcp.connect()
    
    try:
        while True:
            data = bme280.sample(bus, args.bme280_address, calibration_params)
            # print_data(args, data)
            if cloud == "aws" or cloud == "all":
                send_data_to_aws(args, aws, data)
            if cloud == "azure" or cloud == "all":
                await send_data_to_azure(args, azure, data)
            if cloud == "gcp" or cloud == "all":
                send_data_to_gcp(args, gcp, data)
            
            time.sleep(args.msg_freq)
    except KeyboardInterrupt:
        print("Stopping...")
    finally:
        if cloud == "aws" or cloud == "all":
            aws.disconnect()
        if cloud == "azure" or cloud == "all":
            await azure.disconnect()
        if cloud == "gcp" or cloud == "all":
            gcp.disconnect()

    print("Stopped")


if __name__ == "__main__":
    args = init_arg_parser().parse_args()
    asyncio.run(main(args))
