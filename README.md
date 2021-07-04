# IoT cloud connection prototype

This project is a prototype script for testing IoT features of different
popular PaaS cloud services. The script collects data from BME280
temperature, humidity and air pressure sensor and sends the data
periodically to three cloud services using their IoT features. The cloud
services are *Amazon AWS*, *Microsoft Azure* and *Google Cloud*.

This prototype is part of my Master's thesis.


## Installation

The project uses [pipenv](https://pipenv.pypa.io/en/latest/). For
installation you need to run `pipenv install` in the root directory of
this project.


## Running the script

Example command for running the script is located in
`example_start.sh`. If Azure is used, the `AZURE_DEVICE_PRIMARY_KEY`
environment variable must be set to the symmetric IoT device
authentication key from Azure. Cloud provider is selected using argument
`--cloud-provider` with one of these values ["aws", "azure", "gcp",
"all"]. Only arguments of the selected provider must have valid values
even though some provider specific arguments are set as required.
