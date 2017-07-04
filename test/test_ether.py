# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright © 2016. Benoit Michau. ANSSI.
# *
# * This program is free software: you can redistribute it and/or modify
# * it under the terms of the GNU General Public License version 2 as published
# * by the Free Software Foundation. 
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# * GNU General Public License for more details. 
# *
# * You will find a copy of the terms and conditions of the GNU General Public
# * License version 2 in the "license.txt" file or
# * see http://www.gnu.org/licenses/ or write to the Free Software Foundation,
# * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
# *
# *--------------------------------------------------------
# * File Name : test/test_ether.py
# * Created : 2016-04-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from timeit   import timeit
from binascii import unhexlify

from pycrate_ether.Ethernet import *
from pycrate_ether.ARP      import *
from pycrate_ether.IP       import *
from pycrate_ether.PCAP     import *

# enable TCP / UDP checksum calculation
TCP._CS_OFF = False
UDP._CS_OFF = False

# Some examples of Ethernet / ARP or IPv4 packets
eth_arp = unhexlify(b'22334455667700112233445508060001080006040002001122334455c0a8000a223344556677c0a80001')
eth_ipv4_udp_dns = unhexlify(b'0011223344552233445566770800450000469f4900003f115b02c0a80001c0a8000a0035cac100325d3f9ccd818000010001000000000469657466036f72670000010001c00c00010001000006f40004041fc62c')
eth_ipv4_tcp_http = unhexlify(b'2233445566770011223344550800450001de94f4400040061928c0a8000a041fc62ccd460050418754bcd7b1410e8018001c929e00000101080a017ec07206520e5d474554202f20485454502f312e310d0a486f73743a20696574662e6f72670d0a557365722d4167656e743a204d6f7a696c6c612f352e3020285831313b205562756e74753b204c696e7578207838365f36343b2072763a34362e3029204765636b6f2f32303130303130312046697265666f782f34362e300d0a4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c2a2f2a3b713d302e380d0a4163636570742d4c616e67756167653a20656e2d55532c656e3b713d302e350d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a436f6f6b69653a207374796c6553686565743d310d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a49662d4d6f6469666965642d53696e63653a204d6f6e2c2032352041707220323031362032303a32323a353620474d540d0a49662d4e6f6e652d4d617463683a2022343736372d353331353466313233393865632d677a6970220d0a43616368652d436f6e74726f6c3a206d61782d6167653d300d0a0d0a')
# TODO: add some IPv6 packets
#
eth_frames = (eth_arp, eth_ipv4_udp_dns, eth_ipv4_tcp_http)


def test_ip(eth_frames=eth_frames):
    for f in eth_frames:
        pkt = EthernetPacket()
        pkt.from_bytes(f)
        pkt.reautomate()
        assert( pkt.to_bytes() == f )

def test_eth(eth_frames=eth_frames):
    for f in eth_frames:
        pkt = EthernetPacket()
        pkt.from_bytes(f)

def test_perf_ip(eth_frames=eth_frames):
    
    print('[+] instantiating and parsing Ethernet frames')
    Ta = timeit(test_eth, number=100)
    print('test_eth: {0:.4f}'.format(Ta))
    
    print('[+] regenerating Ethernet frames')
    pkt = EthernetPacket()
    pkt.from_bytes(eth_ipv4_udp_dns)
    pkt.reautomate()
    Tb = timeit(pkt.to_bytes, number=100)
    pkt.from_bytes(eth_ipv4_tcp_http)
    pkt.reautomate()
    Tc = timeit(pkt.to_bytes, number=100)
    print('pkt.to_bytes: {0:.4f}'.format(Tb+Tc))

