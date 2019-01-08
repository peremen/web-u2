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

XXD_SET = string.ascii_letters + string.digits + string.punctuation

logger = logging.getLogger('web-u2')
faulthandler.register(signal.SIGUSR1)

hid_ = None

def sigint_handler(signal, frame):
    global hid_dev
    usb.util.dispose_resources(self.hid_dev)
    sys.exit(0)

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

def init_webu2(h):

    pkt1 = binascii.unhexlify(b'ff55f67eea9f52870a05dc300008241000004e010000000020cf4e0168fe120050aa00100100000020cf4e010000000000000000b4fc1200cd1200102ecf537d')
    pkt2 = binascii.unhexlify(b'ff55f67eea9f52870a0500400008011a1a1a1a1a1a1a1a1a1a1ab48e493c1a1a351a1a1a3c1a1a1afd29fdfdf0c8b79aa2400a6a883c0000000000000000c1eb')
    pkt3 = binascii.unhexlify(b'ff55f688ea9f5c870a0500f80108041a1a1a1a1a1a1a1a1a1a1ab48e493c1a1a351a1a1a3c1a1a1afd29fdfdf0c8b79aa2400a6a883c00000000000000007dbb')

    h.write(pkt1)
    buf = h.read(0x40)
    xxd(buf, True)

    h.write(pkt2)
    buf = h.read(0x40)
    xxd(buf, True)

    h.write(pkt3)
    buf = h.read(0x40)
    xxd(buf, True)

def run_webu2(h):
    pkt1 = binascii.unhexlify(b'ff5511f1e9ac29d70300000020cf7e01000000000000000088f11200cd1200102ecf7e01acf212004030001048610010ffffffff88f112003210001020cf1803')
    h.write(pkt1)
    buf = h.read(0x40)
    xxd(buf, True)

    pkt2 = binascii.unhexlify(b'ff5511056aac3dd71a010a75d2be0de0d000fd6330e31f000000000000000000000000000000000000000000dcfee6022637239744ffe602bd06ca75d0004fe3')
    h.write(pkt2)
    buf = h.read(0x40)
    xxd(buf, True)

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
            print(e)
            sys.exit(0)

    print("Found WEB-U2 device")
    print("Manufacturer: %s" % h.get_manufacturer_string())
    print("Product: %s" % h.get_product_string())
    print("Serial: %s" % h.get_serial_number_string())

    init_webu2(h)
    #run_webu2(h)
