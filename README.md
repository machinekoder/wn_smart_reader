# Wiener Netze Smart Meter Reader

Reader software for the Wiener Netze smart meter based on https://gist.github.com/pocki80/941fa090a8d6269a9b3b68c195f8750f

I used this software on a Raspberry Pi with Loxberry installed (for Loxone Smart Home system) and a local MQTT broker.

As hardware I use a RS485 OP-400 optical probe from German Metering and a In-Circuit USB-RS485 converter. The probe
is powered via 5V from the Raspberry Pi. The connection is ~30m to my basement where the smart meter is installed. This is the reason
why I used a RS485 probe instead of a normal UART/TTL/USB probe.

## Installation

This is a very brief guide, modify it to your needs.

Clone the repository to your system. On the Loxberry this needs to go into
`/opt/loxberry/webfrontend/legacy/wn_meter_reader` to prevent deletion on updates.

First modify the config.py for your needs, particularly check the serial device file and fill in the MQTT credentials, 
as well as your AES key from Wiener Netze.

Use the `ls /dev/serial-by-id/` to find the correct device file.

`nano config.py`

Install the dependencies

```bash
sudo pip install -r requirements.txt
```

Create a systemd service

`nano /etc/systemd/system/readmeter.service`

```ini
[Unit]
Description=Service for reading the smart meter
After=syslog.target network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/loxberry/webfrontend/legacy/wn_meter_reader/readmeter.py
User=loxberry
LimitMEMLOCK=33554432
[Install]
WantedBy=multi-user.target
```

Enable the service

```bash
sudo systemctl daemon-reload
sudo systemctl start readmeter.service
sudo systemctl enable readmeter.service
sudo systemctl status readmeter.service
```
