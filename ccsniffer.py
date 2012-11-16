#!/usr/bin/env python

"""

   ccsniffer - a python module to connect to the CC2531emk USB dongle
   Copyright (C) 2012 Christian Panton <christian@panton.org> 
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

"""

import sys
import time
import errno
import threading
import binascii

import usb.core
import usb.util


class CC2531:

    DEFAULT_CHANNEL = 0x0b # 11

    DATA_EP = 0x83
    DATA_TIMEOUT = 2500

    DIR_OUT = 0x40
    DIR_IN  = 0xc0

    GET_IDENT = 0xc0 
    SET_POWER = 0xc5 
    GET_POWER = 0xc6

    SET_START = 0xd0 # bulk in starts
    SET_STOP  = 0xd1 # bulk in stops
    SET_CHAN  = 0xd2 # 0x0d (idx 0) + data)0x00 (idx 1)

    def __init__(self, callback, channel = DEFAULT_CHANNEL):

        self.dev = None
        self.channel = channel
        self.callback = callback
        self.thread = None
        self.running = False

        try:
            self.dev = usb.core.find(idVendor=0x0451, idProduct=0x16ae)
        except usb.core.USBError:
            raise OSError("Permission denied, you need to add an udev rule for this device", errno=errno.EACCES)
    
        if self.dev is None:
            raise IOError("Device not found")

        # set default config
        self.dev.set_configuration()

        # get name from USB descriptor
        self.name = usb.util.get_string(self.dev, 256, 2)

        # get identity from Firmware command
        self.ident = self.dev.ctrl_transfer(CC2531.DIR_IN, CC2531.GET_IDENT, 0, 0, 256)

        # power on radio, wIndex = 4
        self.dev.ctrl_transfer(CC2531.DIR_OUT, CC2531.SET_POWER, wIndex=4)

        while True:
            # check if powered up
            power_status = self.dev.ctrl_transfer(CC2531.DIR_IN, CC2531.GET_POWER, 0, 0, 1)
            if power_status[0] == 4: break
            time.sleep(0.1)

        # unknown command, doesnt seem to matter
        # self.dev.ctrl_transfer(CC2531.DIR_OUT, 0xc9)
            
        self.set_channel(channel)

        

    def __del__(self):
        if self.dev:
            # power off radio, wIndex = 0
            self.dev.ctrl_transfer(self.DIR_OUT, self.SET_POWER, wIndex=0)
        

    def start(self):
        # start sniffing
        self.running = True
        self.dev.ctrl_transfer(CC2531.DIR_OUT, CC2531.SET_START)
        self.thread = threading.Thread(target=self.recv)
        self.thread.daemon = True
        self.thread.start()


    def stop(self):
        # end sniffing
        self.running = False
        self.thread.join()
        self.dev.ctrl_transfer(CC2531.DIR_OUT, CC2531.SET_STOP)

    def recv(self):

        while self.running:
            ret = self.dev.read(CC2531.DATA_EP, 4096, 0, CC2531.DATA_TIMEOUT)
            if ret[0] == 0:
                packet = self.parse_packet(ret)
                if packet:
                    self.callback(packet)


    def set_channel(self, channel):

        was_running = self.running

        if channel >= 11 and channel <= 26:

            if self.running:
                self.stop()

            self.channel = channel
            
            # set channel command
            self.dev.ctrl_transfer(CC2531.DIR_OUT, CC2531.SET_CHAN, 0, 0, [channel])
            self.dev.ctrl_transfer(CC2531.DIR_OUT, CC2531.SET_CHAN, 0, 1, [0x00])

            if was_running:
                self.start()
    
        else:
            raise ValueError("Channel must be between 11 and 26")




    def parse_packet(self, packet):

        packetlen = packet[1]

        if len(packet) - 3 != packetlen:
            return None

        # unknown header produced by the radio chip
        header = packet[3:7].tostring()

        # the data in the payload
        payload = packet[8:-2].tostring()

        # length of the payload
        payloadlen = packet[7] - 2 # without fcs

        if len(payload) != payloadlen:
            return None

        # current time
        timestamp = time.gmtime()

        # used to derive other values
        fcs1, fcs2 = packet[-2:]

        # rssi is the signed value at fcs1
        rssi    = (fcs1 + 2**7) % 2**8 - 2**7  - 73

        # crc ok is the 7th bit in fcs2
        crc_ok  = fcs2 & (1 << 7) > 0

        # correlation value is the unsigned 0th-6th bit in fcs2
        corr    = fcs2 & 0x7f

        return Packet(timestamp, self.channel, header, payload, rssi, crc_ok, corr)


    def __repr__(self):

        if self.dev:
            return "%s <Channel: %d>" % (self.name, self.channel)
        else:
            return "Not connected"



class Packet:

    def __init__(self, timestamp, channel, header, payload, rssi, crc_ok, correlation):
        self.timestamp = timestamp
        self.channel = channel
        self.header = header
        self.payload = payload
        self.rssi = rssi
        self.crc_ok = crc_ok
        self.correlation = correlation

    def __repr__(self):
        
        ret = []
        ret.append("Channel:     %d" % self.channel)
        ret.append("Timestamp:   %s" % time.strftime("%H:%M:%S", self.timestamp))
        ret.append("Header:      %s" % binascii.hexlify(self.header))
        ret.append("RSSI:        %d" % self.rssi)
        ret.append("CRC OK:      %s" % self.crc_ok)
        ret.append("Correlation: %d" % self.correlation)
        ret.append("Payload:     %s" % binascii.hexlify(self.payload))

        return "\n".join(ret)



if __name__ == "__main__":

    def callback(packet):
        print "-"*30
        print packet
        print "-"*30

    sniffer = CC2531(callback)
    
    print sniffer
    sniffer.start()
    time.sleep(10)
    sniffer.stop()
