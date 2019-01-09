#!/usr/bin/python3
# coding: utf8

__version__ = "0.1"

import os, sys, re, importlib
import argparse
import hid
import signal
import struct
import datetime
import time
import faulthandler
import logging
import binascii
import string
from functools import reduce

XXD_SET = string.ascii_letters + string.digits + string.punctuation

logger = logging.getLogger('web-u2')
faulthandler.register(signal.SIGUSR1)

hid_ = None

def hexint(string):
    if string[0:2] == '0x' or string[0:2] == '0X':
        return int(string[2:], 16)
    else:
        return int(string)

def xxd(buf, stdout = False):
    xxd_str = ''
    i = 0
    while i < len(buf):
        if (i + 16) < len(buf):
            xxd_str += (' '.join(('%02x' % x) for x in buf[i:i+16])) + '\t' + (''.join((chr(x) if chr(x) in XXD_SET else '.') for x in buf[i:i+16]))
        else:
            xxd_str += (' '.join(('%02x' % x) for x in buf[i:len(buf)])) + '   ' * (16 - (len(buf) - i)) + '\t' + (''.join((chr(x) if chr(x) in XXD_SET else '.') for x in buf[i:len(buf)]))
        xxd_str += '\n'
        i += 16
    xxd_str += '-------- end --------'

    if stdout:
        print(xxd_str)
    else:
        return 'Hexdump: \n' + xxd_str

def usb_read(r, read_size):
    buf = b''
    try:
        buf = r.read(read_size)
        buf = bytes(buf)
    except usb.core.USBError:
        return b''
    return buf

def usb_write(w, write_buf):
    w.write(write_buf)

def csum(pkt):
    return 0xff & reduce((lambda x, y: x + y), pkt)

def body_csum(pkt):
    return csum(pkt[8:62])

def total_csum(pkt):
    return 0xff & (body_csum(pkt) + csum(pkt[0:8]))

def check_packet(pkt):
    if len(pkt) != 64:
        return False
    if (pkt[0] == 0xff) and (pkt[1] == 0x55) and (pkt[62] == body_csum(pkt)) and (pkt[63] == total_csum(pkt)):
        return True
    else:
         return False

def build_packet(cmd_id, arg):
    pkt = bytearray(64)
    pkt[0] = 0xff
    pkt[1] = 0x55

    pkt[8] = 0xff & cmd_id 
    pkt[9] = 0xff & len(arg)
    if len(arg) > 0:
        for i in range(min(len(arg), 52)):
            pkt[10+i] = arg[i]

    pkt[62] = csum(pkt[8:62])
    pkt[63] = 0xff & (csum(pkt[8:62]) + csum(pkt[0:8]))

    return bytes(pkt)

def init_webu2(h):
    pkt1 = build_packet(0x0a, binascii.unhexlify('dc30000824'))
    pkt2 = build_packet(0x0a, binascii.unhexlify('0040000801'))
    pkt3 = build_packet(0x0a, binascii.unhexlify('00f8010804'))

    h.write(pkt1)
    buf = h.read(0x40)
    print(check_packet(buf))
    xxd(buf, True)

    h.write(pkt2)
    buf = h.read(0x40)
    print(check_packet(buf))
    xxd(buf, True)

    h.write(pkt3)
    buf = h.read(0x40)
    print(check_packet(buf))
    xxd(buf, True)

def parse_response(buf):
    if not check_packet(buf):
        return
    ts = buf[2:8]
    cmd = buf[8]
    arglen = buf[9]
    arg = buf[10:10 + arglen]

    if cmd == 0x1a:
        results = struct.unpack('<fffffffffff', bytes(arg))
        # Voltage, Current, Current, ?, Wattage, D+ Voltage, D- Voltage, Internal Temperature, ?, ?, ?
        print(' '.join(['{:.05f}'.format(x) for x in results]))

def run_webu2(h):
    pkt1 = build_packet(0x03, b'')
    pkt2 = build_packet(0x1a, binascii.unhexlify('0a'))
    h.write(pkt1)
    buf = h.read(0x40)
    xxd(buf, True)

    h.write(pkt2)
    while True:
        buf = h.read(0x40)
        if len(buf) == 0x40:
            parse_response(buf)
            #xxd(buf, True)
        else:
            h.write(pkt2)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Processes input data from WEB-U2 USB power meter.')
    parser.add_argument('-D', '--debug', help='Print debug information, mostly hexdumps.', action='store_true')

    usb_group = parser.add_argument_group('USB device settings')
    usb_group.add_argument('-v', '--vendor', help='Override USB vendor ID', type=hexint)
    usb_group.add_argument('-p', '--product', help='Override USB product ID', type=hexint)
    usb_group.add_argument('-a', '--address', help='Specify USB device address (bus:address) with multiple WEB-U2', type=str)

    #data_group = parser.add_argument_group('Data settings')
    #data_group.add_argument('-P', '--port', help='Change UDP port to emit GSMTAP packets', type=int, default=4729)
    #data_group.add_argument('--port-up', help='Change UDP port to emit user plane packets', type=int, default=47290)
    #data_group.add_argument('-H', '--hostname', help='Change host name/IP to emit GSMTAP packets', type=str, default='127.0.0.1')
    #data_group.add_argument('--port-sim2', help='Change UDP port to emit GSMTAP packets for SIM 2', type=int, default=4729)
    #data_group.add_argument('--port-up-sim2', help='Change UDP port to emit user plane packets for SIM 2', type=int, default=47290)
    #data_group.add_argument('--hostname-sim2', help='Change host name/IP to emit GSMTAP packets for SIM 2', type=str, default='127.0.0.2')

    args = parser.parse_args()
    hid_dev = None

    # Device preparation
    if args.address:
        # Use WEB-U2 at specified address
        print('Trying HID device at address %s' % (args.address))
        usb_bus, usb_device = args.address.split(':')
        usb_bus = int(usb_bus, base=10)
        usb_device = int(usb_device, base=10)
        addr_format = '{:04x}:{:04x}:00'.format(usb_bus, usb_device).encode('utf-8')

        for d in hid.enumerate():
            if d.path == addr.format:
                hid_dev = d
                break
    else:
        # USB VID:PID = 0716:5030
        # Use first HID device with that VID:PID
        try:
            h = hid.device()
            h.open(0x0716, 0x5030)
        except OSError as e:
            print("Error locating WEB-U2 device: %s" % e)
            sys.exit(0)

    print("Found WEB-U2 device")
    print("Manufacturer: %s" % h.get_manufacturer_string())
    print("Product: %s" % h.get_product_string())
    print("Serial: %s" % h.get_serial_number_string())

    init_webu2(h)
    h.set_nonblocking(1)
    run_webu2(h)
