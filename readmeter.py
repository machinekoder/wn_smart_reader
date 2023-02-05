import serial
import json
import paho.mqtt.client as mqtt
from time import sleep
import logging

from serial import SerialException

from decode_wn_isk_am550_smartmeter import (
    decode_packet,
    format_data,
    read_data,
)


class WienerMeterReader:
    MESSAGE_LENGTH = 105
    FIRSTBYTE = b'\x7e'
    SECONDBYTE = b'\xa0'
    MQTT_TOPIC = 'energy_meter'
    logger = logging.getLogger(__name__)

    def __init__(
        self,
        device='/dev/ttyUSB0',
        mqtt_username=None,
        mqtt_pw=None,
        aes_key=None,
        mqtt_keepalive=30,
        mqtt_host='localhost',
        mqtt_port=1883,
    ):
        self.serial = serial.Serial(
            device,
            baudrate=9600,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS,
            timeout=0.1,
            exclusive=True,
        )
        self._mqtt_client = mqtt.Client('readmeter', clean_session=True)
        if mqtt_pw and mqtt_username:
            self._mqtt_client.username_pw_set(username=mqtt_username, password=mqtt_pw)
        self._mqtt_client.will_set(
            f'{self.MQTT_TOPIC}/online', 'false', retain=True
        )
        self._mqtt_client.connect(
            host=mqtt_host, port=mqtt_port, keepalive=mqtt_keepalive
        )
        self._mqtt_client.publish(f"{self.MQTT_TOPIC}/online", 'true', retain=True)
        self._previous_byte = None
        self.receiving = False
        self._received_data = bytearray()
        self._pos = 0
        self._aes_key = aes_key

    def _read_all(self):
        while self.serial.in_waiting:
            try:
                current_byte = self.serial.read()
            except SerialException as e:
                self.logger.error(f"Error reading serial port {e}")
                continue
            if self.receiving:
                if self._pos < self.MESSAGE_LENGTH:
                    self._received_data += current_byte
                    self._pos += 1
                else:
                    decoded = decode_packet(self._received_data, key=self._aes_key)
                    if decoded:
                        data = read_data(decoded)
                        self.logger.info(format_data(data))
                        self._publish_data(data)
                    else:
                        self.logger.error("CRC error")
                    self.receiving = False
                    self._pos = 0
                    self._received_data = bytearray()
            elif (
                self._previous_byte == self.FIRSTBYTE
                and current_byte == self.SECONDBYTE
            ):
                self.receiving = True
                self._received_data = bytearray() + self.FIRSTBYTE + self.SECONDBYTE
                self._pos = 2
            self._previous_byte = current_byte

    def _publish_data(self, data):
        # remove individual time fields
        del data['t_dd']
        del data['t_mm']
        del data['t_yyyy']
        del data['t_hh']
        del data['t_mi']
        del data['t_ss']
        # publish message for each key/value pair
        for key, value in data.items():
            ret = self._mqtt_client.publish(f'{self.MQTT_TOPIC}/{key}', value)
            if ret[0]:
                self.logger.error(f"publishing mqtt message {key} failed")

    def loop(self):
        while True:
            self._read_all()
            sleep(0.5)

    def stop(self):
        self.serial.close()
        self._mqtt_client.publish(f"{self.MQTT_TOPIC}/online", 'false', retain=True)
        self._mqtt_client.disconnect()


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARNING)  # don't spam the console
    from config import config

    reader = WienerMeterReader(**config)
    try:
        reader.loop()
    except KeyboardInterrupt:
        reader.stop()
