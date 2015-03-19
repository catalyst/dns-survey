#!/usr/bin/env python
#
# Copyright (c) 2015 Catalyst.net Ltd
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Raw socket DNS sniffer. Designed to run on python 2.5 thru 2.7.
Scapy's `sniff' function is too slow on embedded devices, this approach uses considerably less CPU (for some reason).

Michael Fincham <michael.fincham@catalyst.net.nz>
"""

import socket
import struct
import binascii
import ctypes

class DnsSniffer(object):

    # this is the filter for 'udp and src port 53' in tcpdump's filter language
    BPF_FILTER = [
        # (000) ldh      [12]
        ( 0x28, 0, 0, 0x0000000c ),
        # (001) jeq      #0x86dd          jt 2  jf 6
        ( 0x15, 0, 4, 0x000086dd ),
        # (002) ldb      [20]
        ( 0x30, 0, 0, 0x00000014 ),
        # (003) jeq      #0x11            jt 4  jf 15
        ( 0x15, 0, 11, 0x00000011 ),
        # (004) ldh      [54]
        ( 0x28, 0, 0, 0x00000036 ),
        # (005) jeq      #0x35            jt 14 jf 15
        ( 0x15, 8, 9, 0x00000035 ),
        # (006) jeq      #0x800           jt 7  jf 15
        ( 0x15, 0, 8, 0x00000800 ),
        # (007) ldb      [23]
        ( 0x30, 0, 0, 0x00000017 ),
        # (008) jeq      #0x11            jt 9  jf 15
        ( 0x15, 0, 6, 0x00000011 ),
        # (009) ldh      [20]
        ( 0x28, 0, 0, 0x00000014 ),
        # (010) jset     #0x1fff          jt 15 jf 11
        ( 0x45, 4, 0, 0x00001fff ),
        # (011) ldxb     4*([14]&0xf)
        ( 0xb1, 0, 0, 0x0000000e ),
        # (012) ldh      [x + 14]
        ( 0x48, 0, 0, 0x0000000e ),
        # (013) jeq      #0x35            jt 14 jf 15
        ( 0x15, 0, 1, 0x00000035 ),
        # (014) ret      #262144
        ( 0x6, 0, 0, 0x00040000 ),
        # (015) ret      #0
        ( 0x6, 0, 0, 0x00000000 ),
    ]

    SO_ATTACH_FILTER = 26

    def __init__(self):
        self.raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) # ETH_P_ALL

        # convert the filter program to a binary and apply it to the socket
        bpf_binary = ctypes.create_string_buffer(''.join(struct.pack("HBBI", *e) for e in DnsSniffer.BPF_FILTER))
        bpf_binary_address = ctypes.addressof(bpf_binary)
        bpf_filter_program = struct.pack('HL', len(DnsSniffer.BPF_FILTER), bpf_binary_address)
        self.raw.setsockopt(socket.SOL_SOCKET, DnsSniffer.SO_ATTACH_FILTER, bpf_filter_program)

    def sniff(self):
        while True:
            packet = self.raw.recvfrom(2048)[0]
            yield packet
