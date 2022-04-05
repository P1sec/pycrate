# −*− coding: UTF−8 −*−
#/**
# * Software Name : pycrate 
# * Version : 0.4
# *
# * Copyright 2016. Benoit Michau. ANSSI.
# *
# * This library is free software; you can redistribute it and/or
# * modify it under the terms of the GNU Lesser General Public
# * License as published by the Free Software Foundation; either
# * version 2.1 of the License, or (at your option) any later version.
# *
# * This library is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * Lesser General Public License for more details.
# *
# * You should have received a copy of the GNU Lesser General Public
# * License along with this library; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
# * MA 02110-1301  USA
# *
# *--------------------------------------------------------
# * File Name : pycrate_ether/PCAP.py
# * Created : 2016-04-27
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

from pycrate_core.elt import Envelope, REPR_RAW, REPR_HEX, REPR_BIN
from pycrate_core.base import *
from pycrate_core.repr import *

# pcap headers format:
# from http://wiki.wireshark.org/Development/LibpcapFileFormat

LinkType_dict = {
    0 : 'NULL',
    1 : 'ETHERNET',
    3 : 'AX25',
    6 : 'IEEE802_5',
    7 : 'ARCNET_BSD',
    8 : 'SLIP',
    9 : 'PPP',
    10 : 'FDDI',
    50 : 'PPP_HDLC',
    51 : 'PPP_ETHER',
    100 : 'ATM_RFC1483',
    101 : 'RAW',
    104 : 'C_HDLC',
    105 : 'IEEE802_11',
    107 : 'FRELAY',
    108 : 'LOOP',
    113 : 'LINUX_SLL',
    114 : 'LTALK',
    117 : 'PFLOG',
    119 : 'IEEE802_11_PRISM',
    122 : 'IP_OVER_FC',
    123 : 'SUNATM',
    127 : 'IEEE802_11_RADIOTAP',
    129 : 'ARCNET_LINUX',
    138 : 'APPLE_IP_OVER_IEEE1394',
    139 : 'MTP2_WITH_PHDR',
    140 : 'MTP2',
    141 : 'MTP3',
    142 : 'SCCP',
    143 : 'DOCSIS',
    144 : 'LINUX_IRDA',
    163 : 'IEEE802_11_AVS',
    165 : 'BACNET_MS_TP',
    166 : 'PPP_PPPD',
    169 : 'GPRS_LLC',
    170 : 'GPF_T',
    171 : 'GPF_F',
    177 : 'LINUX_LAPD',
    187 : 'BLUETOOTH_HCI_H4',
    189 : 'USB_LINUX',
    192 : 'PPI',
    195 : 'IEEE802_15_4',
    196 : 'SITA',
    197 : 'ERF',
    201 : 'BLUETOOTH_HCI_H4_WITH_PHDR',
    202 : 'AX25_KISS',
    203 : 'LAPD',
    204 : 'PPP_WITH_DIR',
    205 : 'C_HDLC_WITH_DIR',
    206 : 'FRELAY_WITH_DIR',
    209 : 'IPMB_LINUX',
    215 : 'IEEE802_15_4_NONASK_PHY',
    220 : 'USB_LINUX_MMAPPED',
    224 : 'FC_2',
    225 : 'FC_2_WITH_FRAME_DELIMS',
    226 : 'IPNET',
    227 : 'CAN_SOCKETCAN',
    228 : 'IPV4',
    229 : 'IPV6',
    230 : 'IEEE802_15_4_NOFCS',
    231 : 'DBUS',
    235 : 'DVB_CI',
    236 : 'MUX27010',
    237 : 'STANAG_5066_D_PDU',
    239 : 'NFLOG',
    240 : 'NETANALYZER',
    241 : 'NETANALYZER_TRANSPARENT',
    242 : 'IPOIB',
    243 : 'MPEG_2_TS',
    244 : 'NG40',
    245 : 'NFC_LLCP',
    247 : 'INFINIBAND',
    248 : 'SCTP',
    249 : 'USBPCAP',
    250 : 'RTAC_SERIAL',
    251 : 'BLUETOOTH_LE_LL',
    253 : 'NETLINK',
    254 : 'BLUETOOTH_LINUX_MONITOR',
    255 : 'BLUETOOTH_BREDR_BB',
    256 : 'BLUETOOTH_LE_LL_WITH_PHDR',
    257 : 'PROFIBUS_DL',
    258 : 'PKTAP',
    259 : 'EPON',
    260 : 'IPMI_HPM_2',
    261 : 'ZWAVE_R1_R2',
    262 : 'ZWAVE_R3',
    263 : 'WATTSTOPPER_DLM',
    264 : 'ISO_14443'
    }

class pcap_hdr(Envelope):
    _GEN = (
        Uint32LE('magic_number', val=0xa1b2c3d4, rep=REPR_HEX),
        Uint16LE('version_major', val=2),
        Uint16LE('version_minor', val=4),
        Int32LE('thiszone'), # GMT to local time correction
        Uint32LE('sigfigs'), # accuracy of timestamp
        Uint32LE('snaplen', val=0xffff), # max length of captured packets
        Uint32LE('network', dic=LinkType_dict) # data link type
        )

class pcaprec_hdr(Envelope):
    _GEN = (
        Uint32LE('ts_sec'), # timestamp seconds
        Uint32LE('ts_usec'), # timestamp microseconds
        Uint32LE('len_incl'), # number of octets of packet saved in file
        Uint32LE('len_orig') # actual length of packet
        )

class pcap_hdr_be(Envelope):
    _GEN = (
        Uint32('magic_number', val=0xa1b2c3d4, rep=REPR_HEX),
        Uint16('version_major', val=2),
        Uint16('version_minor', val=4),
        Int32('thiszone'), # GMT to local time correction
        Uint32('sigfigs'), # accuracy of timestamp
        Uint32('snaplen', val=0xffff), # max length of captured packets
        Uint32('network', dic=LinkType_dict) # data link type
        )

class pcaprec_hdr_be(Envelope):
    _GEN = (
        Uint32('ts_sec'), # timestamp seconds
        Uint32('ts_usec'), # timestamp microseconds
        Uint32('len_incl'), # number of octets of packet saved in file
        Uint32('len_orig') # actual length of packet
        )

