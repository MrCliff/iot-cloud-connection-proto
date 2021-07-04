#!/bin/bash

export AZURE_DEVICE_PRIMARY_KEY="<Symmetric IoT device authentication key from Azure>"

pipenv run python weather.py \
    --aws-endpoint <aws iot endpoint domain - AWS IoT/Settings/Endpoint> \
    --aws-client-id <aws iot client id of the device> \
    --aws-cert ~/certs/aws/device.pem.crt \
    --aws-key ~/certs/aws/private.pem.key \
    --aws-root-ca ~/certs/aws/Amazon-root-CA-1.pem \
    --aws-verbosity Fatal \
    --azure-iot-hub-name <azure iot hub name> \
    --azure-device-id <azure iot device id> \
    --gcp-project-id <gcp project id> \
    --gcp-registry-id <gcp cloud iot core registry id> \
    --gcp-device-id <gcp iot device id> \
    --gcp-key ~/certs/gcp/rsa_private.pem \
    --gcp-key-algorithm RS256 \
    --gcp-root-ca ~/certs/gcp/roots.pem \
    --cloud-provider all \
    --location finland
