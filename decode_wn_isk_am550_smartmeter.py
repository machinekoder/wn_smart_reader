# strongly based on: https://gist.github.com/pocki80/941fa090a8d6269a9b3b68c195f8750f
# use this to decode HDLC packets from a powergrid smartmeter.
# supported data sources so far:
#  'WN'   WienerNetze   ISKRAEMECO AM550 from D0 interface (infrared)
#  'KN'   KärntenNetz   ISKRAEMECO AM550 from P1 interface (RJ12)
#
# you might need to install pycryptodome:
# pip install pycryptodome


# paste your AES-key here
# in case of WienerNetze: can be found from WienerNetze Webportal https://www.wienernetze.at/wnapp/smapp/ -> Anlagedaten
# KEY = ""

# select ONE of the supported device codes: WN, KN!

# paste a full HDLC frame here: starting 7ea067 ending 7e
# in case of WienerNetze: should be 210 hex digits = 105 bytes = 0x69 -> length byte 3 shows 0x67
# device = 'WN'
# data = '7ea067cf022313fbf1e6e700db0844556677889900aa4f20888877775540d5496ab897685e9b7e469942209b881fe280526f77c9d1dee763afb463a9bbe88449cb3fe79725875de945a405cb0f3119d3e06e3c4790130a29bc090cdf4b323cd7019d628ca255fce57e'

# in case of KärntenNetz: should be 242 hex digits = 121 bytes = 0x79 -> length byte 3 shows 0x77
# device='KN'
# data='7ea077cf022313bb45e6e700db0844556677889900aa5f208888777755408e03e4b8976857817a5a975d209bc49fe2855265702ac9cce48cad9452674dd9b07ebe8d6ba115b768de47a801f9443e1cc825973b4796138611960f0cdf4d323ad789455f8aa25c5ce7aa15fca3eaa5171f74dff8b5592c62c57e'

# data string of WienerNetze explained:
# 7e         start-byte, hdlc opening flag
# a0         address field?
# 67         length field?
# cf         control field?
# 02         length field?
# 23         ?
# 13         frame type
# fbf1       crc16 from byte 2-7
# e6e700     some header?
# db         some header?
# 08         length of next field
# 44556677889900aa   systemTitle
# 4f         length of next field
# 20         security byte: encryption-only
# 88887777   invocation counter
# 5540d5496ab897685e9b7e469942209b881fe280526f77c9d1dee763afb463a9bbe88449cb3fe79725875de945a405cb0f3119d3e06e3c4790130a29bc090cdf4b323cd7019d628ca255 ciphertext
# fce5       crc16 from byte 2 until end of ciphertext
# 7e         end-byte

## lets go
import binascii
from datetime import datetime, timedelta

##CRC-STUFF BEGIN
CRC_INIT = 0xFFFF
POLYNOMIAL = 0x1021


def byte_mirror(c):
    c = (c & 0xF0) >> 4 | (c & 0x0F) << 4
    c = (c & 0xCC) >> 2 | (c & 0x33) << 2
    c = (c & 0xAA) >> 1 | (c & 0x55) << 1
    return c


def calc_crc16(data):
    crc = CRC_INIT
    for i in range(len(data)):
        c = byte_mirror(data[i]) << 8
        for j in range(8):
            if (crc ^ c) & 0x8000:
                crc = (crc << 1) ^ POLYNOMIAL
            else:
                crc = crc << 1
            crc = crc % 65536
            c = (c << 1) % 65536
    crc = 0xFFFF - crc
    return 256 * byte_mirror(crc // 256) + byte_mirror(crc % 256)


def verify_crc16(input, skip=0, last=2, cut=0):
    lenn = len(input)
    data = input[skip : lenn - last - cut]
    goal = input[lenn - last - cut : lenn - cut]
    if last == 0:
        return hex(calc_crc16(data))
    elif last == 2:
        return calc_crc16(data) == goal[0] * 256 + goal[1]
    return False


##CRC-STUFF DONE

##DECODE-STUFF BEGIN
from Crypto.Cipher import AES


def decode_packet(
    payload, key
):  ##expects input to be bytearray.fromhex(hexstring), full packet  "7ea067..7e"
    if verify_crc16(payload, 1, 2, 1):
        nonce = bytes(payload[14:22] + payload[24:28])  # systemTitle+invocation counter
        cipher = AES.new(
            binascii.unhexlify(key), AES.MODE_CTR, nonce=nonce, initial_value=2
        )
        return cipher.decrypt(payload[28:-3])
    else:
        return ''


##DECODE-STUFF DONE


def bytes_to_int(data):
    result = 0
    for b in data:
        result = result * 256 + b
    return result


def read_data(s, device='WN'):
    if device == 'WN':
        data = dict(
            a_in_wh=bytes_to_int(s[35:39]),  # +A Wh
            a_out_wh=bytes_to_int(s[40:44]),  # -A Wh
            r_in_varh=bytes_to_int(s[45:49]),  # +R varh
            r_out_varh=bytes_to_int(s[50:54]),  # -R varh
            p_in_w=bytes_to_int(s[55:59]),  # +P W
            p_out_w=bytes_to_int(s[60:64]),  # -P W
            q_in_var=bytes_to_int(s[65:69]),  # +Q var
            q_out_var=bytes_to_int(s[70:74]),  # -Q var
            t_yyyy=bytes_to_int(s[22:24]),
            t_mm=bytes_to_int(s[24:25]),
            t_dd=bytes_to_int(s[25:26]),
            t_hh=bytes_to_int(s[27:28]),
            t_mi=bytes_to_int(s[28:29]),
            t_ss=bytes_to_int(s[29:30]),
        )
    elif device == 'KN':
        data = dict(
            a_in_wh=bytes_to_int(s[57:61]),  # +A Wh
            a_out_wh=bytes_to_int(s[62:66]),  # -A Wh
            r_in_varh=bytes_to_int(s[67:71]),  # +R varh
            r_out_varh=bytes_to_int(s[72:76]),  # -R varh
            p_in_w=bytes_to_int(s[77:81]),  # +P W
            p_out_w=bytes_to_int(s[82:86]),  # -P W
            q_in_var=None,
            q_out_var=None,
            t_yyyy=bytes_to_int(s[51:53]),
            t_mm=bytes_to_int(s[53:54]),
            t_dd=bytes_to_int(s[54:55]),
            t_hh=bytes_to_int(s[45:46]),
            t_mi=bytes_to_int(s[46:47]),
            t_ss=bytes_to_int(s[47:48]),
        )
    else:
        print("Device type not recognized")
        return None
    utcoffset = int(datetime.utcnow().astimezone().utcoffset() / timedelta(hours=1))
    data[
        'timestamp'
    ] = f'{data["t_yyyy"]}-{data["t_mm"]:02d}-{data["t_dd"]:02d}T{data["t_hh"]-utcoffset:02d}:{data["t_mi"]:02d}:{data["t_ss"]:02d}Z'
    return data


def show_data(data: dict):
    print(
        "Output: %10.3fkWh, %10.3fkWh, %10.3fkvarh, %10.3fkvarh, %5dW, %5dW, %5dvar, %5dvar at %02d.%02d.%04d-%02d:%02d:%02d"
        % (
            data['a_in_wh'] / 1000.0,
            data['a_out_wh'] / 1000.0,
            data['r_in_varh'] / 1000.0,
            data['r_out_varh'] / 1000.0,
            data['p_in_w'],
            data['p_out_w'],
            data['q_in_var'],
            data['q_out_var'],
            data['t_dd'],
            data['t_mm'],
            data['t_yyyy'],
            data['t_hh'],
            data['t_mi'],
            data['t_ss'],
        )
    )


# dec=decode_packet(bytearray.fromhex(data))
# show_data(dec) if (dec) else 'CRC error'

# binascii.hexlify(dec)

# plaintext hex string of WienerNetze explained
# 0f                          start-byte?
# 0059a374                    packet number, appears to be IC+1 (faked in this example)
# 0c                          intro 12byte-timestamp
# 07e5 01 1b 03 10 0b 2d 00ffc400   timestamp: year,month,day,dow,hours,minutes,seconds
# 020909                      some header for the following 9-value-structure?
# 0c                          intro 12byte-timestamp
# 07e5 01 1b 03 10 0b 2d 00ffc400   timestamp: year,month,day,dow,hours,minutes,seconds
# 06                          intro 32bit-value
# 004484bc                    +A Wh
# 06                          intro 32bit-value
# 0000053e                    -A Wh
# 06                          intro 32bit-value
# 0001004b                    +R varh
# 06                          intro 32bit-value
# 001c20f1                    -R varh
# 06                          intro 32bit-value
# 00000176                    +P W
# 06                          intro 32bit-value
# 00000000                    -P W
# 06                          intro 32bit-value
# 00000000                    +Q var
# 06                          intro 32bit-value
# 000000f4                    -Q var

# plaintext hex string of KärntenNetz explained
# 0f
# 0002e9fa
# 0c
# 07e5 08 01 07 0c 05 32 00ff8880 # 01.08.2021 12:05:50
# 02 0c
# 0906 0006190900ff               # 0.6.25.9.0.255 Firmwareversion?
# 090d 31313231323731363030303030 # 1121271600000  S/N?
# 0904 0c053200                   # 12:05:50.000   Time
# 0905 07e5080100                 # 01.Aug.2021    Date
# 06 01fa3e2a                     # 33177130 +A Wh
# 06 00000000                     #     0000 -A Wh
# 06 0088de3d                     #  8969789 +R varh
# 06 00fd4489                     # 16598153 -R varh
# 06 00000c4d                     #     3149 +P W
# 06 00000000                     #     0000 -P W
# 0900                            # Customer info text
# 0900                            # Customer info code

