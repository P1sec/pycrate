# −*− coding: UTF−8 −*−
#/**
# * Software Name : pycrate 
# * Version : 0.2
# *
# * Copyright 2016. Benoit Michau. ANSSI.
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# * 
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# * 
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# * 02110-1301, USA.
# *
# *--------------------------------------------------------
# * File Name : pycrate_ether/IP.py
# * Created : 2016-04-27
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

from socket import inet_aton, inet_ntoa, AF_INET, AF_INET6
from struct import pack
from array import array
try:
    from socket import inet_pton, inet_ntop
except ImportError:
    try:
        from win_inet_pton import inet_pton, inet_ntop
    except ImportError:
        print('[pycrate_ether/IP.py] inet_pton() and inet_ntop() not available')

from pycrate_core.utils import reverse_dict
from pycrate_core.elt import Envelope, Array, REPR_RAW, REPR_HEX, REPR_BIN
from pycrate_core.base import *
from pycrate_core.repr import *


#------------------------------------------------------------------------------#
# code borrowed from scapy:
# see scapy code at https://github.com/secdev/scapy/blob/master/scapy/utils.py
# see http://www.secdev.org/projects/scapy for more informations
# Copyright (C) Philippe Biondi <phil@secdev.org>
# This program is published under a GPLv2 license

if pack('H', 1) == b'\0\x01': # big endian
    def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += b'\0'
        s = sum(array('H', pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return s & 0xffff
else:
    def checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += b'\0'
        s = sum(array('H', pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s
        return (((s>>8)&0xff)|s<<8) & 0xffff

# End-Of-Scapy
#------------------------------------------------------------------------------#


IPProt_dict = {
    0 : 'HOPOPT',
    1 : 'ICMP',
    2 : 'IGMP',
    3 : 'GGP',
    4 : 'IP',
    5 : 'ST',
    6 : 'TCP',
    7 : 'CBT',
    8 : 'EGP',
    9 : 'IGP',
    10 : 'BBN-RCC-MON',
    11 : 'NVP-II',
    12 : 'PUP',
    13 : 'ARGUS',
    14 : 'EMCON',
    15 : 'XNET',
    16 : 'CHAOS',
    17 : 'UDP',
    18 : 'MUX',
    19 : 'DCN-MEAS',
    20 : 'HMP',
    21 : 'PRM',
    22 : 'XNS-IDP',
    23 : 'TRUNK-1',
    24 : 'TRUNK-2',
    25 : 'LEAF-1',
    26 : 'LEAF-2',
    27 : 'RDP',
    28 : 'IRTP',
    29 : 'ISO-TP4',
    30 : 'NETBLT',
    31 : 'MFE-NSP',
    32 : 'MERIT-INP',
    33 : 'DCCP',
    34 : '3PC',
    35 : 'IDPR',
    36 : 'XTP',
    37 : 'DDP',
    38 : 'IDPR-CMTP',
    39 : 'TP++',
    40 : 'IL',
    41 : 'IPv6',
    42 : 'SDRP',
    43 : 'IPv6-Route',
    44 : 'IPv6-Frag',
    45 : 'IDRP',
    46 : 'RSVP',
    47 : 'GRE',
    48 : 'DSR',
    49 : 'BNA',
    50 : 'ESP',
    51 : 'AH',
    52 : 'I-NLSP',
    53 : 'SWIPE',
    54 : 'NARP',
    55 : 'MOBILE',
    56 : 'TLSP',
    57 : 'SKIP',
    58 : 'IPv6-ICMP',
    59 : 'IPv6-NoNxt',
    60 : 'IPv6-Opts',
    61 : 'any',
    62 : 'CFTP',
    63 : 'any',
    64 : 'SAT-EXPAK',
    65 : 'KRYPTOLAN',
    66 : 'RVD',
    67 : 'IPPC',
    68 : 'any',
    69 : 'SAT-MON',
    70 : 'VISA',
    71 : 'IPCV',
    72 : 'CPNX',
    73 : 'CPHB',
    74 : 'WSN',
    75 : 'PVP',
    76 : 'BR-SAT-MON',
    77 : 'SUN-ND',
    78 : 'WB-MON',
    79 : 'WB-EXPAK',
    80 : 'ISO-IP',
    81 : 'VMTP',
    82 : 'SECURE-VMTP',
    83 : 'VINES',
    84 : 'TTP',
    85 : 'NSFNET-IGP',
    86 : 'DGP',
    87 : 'TCF',
    88 : 'EIGRP',
    89 : 'OSPFIGP',
    90 : 'Sprite-RPC',
    91 : 'LARP',
    92 : 'MTP',
    93 : 'AX.25',
    94 : 'IPIP',
    95 : 'MICP',
    96 : 'SCC-SP',
    97 : 'ETHERIP',
    98 : 'ENCAP',
    99 : 'any',
    100 : 'GMTP',
    101 : 'IFMP',
    102 : 'PNNI',
    103 : 'PIM',
    104 : 'ARIS',
    105 : 'SCPS',
    106 : 'QNX',
    107 : 'A/N',
    108 : 'IPComp',
    109 : 'SNP',
    110 : 'Compaq-Peer',
    111 : 'IPX-in-IP',
    112 : 'VRRP',
    113 : 'PGM',
    114 : 'any',
    115 : 'L2TP',
    116 : 'DDX',
    117 : 'IATP',
    118 : 'STP',
    119 : 'SRP',
    120 : 'UTI',
    121 : 'SMP',
    122 : 'SM',
    123 : 'PTP',
    124 : 'ISIS',
    125 : 'FIRE',
    126 : 'CRTP',
    127 : 'CRUDP',
    128 : 'SSCOPMCE',
    129 : 'IPLT',
    130 : 'SPS',
    131 : 'PIPE',
    132 : 'SCTP',
    133 : 'FC',
    134 : 'RSVP-E2E-IGNORE',
    135 : 'Mobility',
    136 : 'UDPLite',
    137 : 'MPLS-in-IP',
    138 : 'manet',
    139 : 'HIP',
    140 : 'Shim6',
    253 : 'Experimentation',
    254 : 'Experimentation',
    255 : 'Reserved'
    }

IPProtRev_dict = reverse_dict(IPProt_dict)
    
IPv4Opt_dict = {
    0: 'EndofOptions',
    1: 'NoOperation',
    7: 'RecordRoute',
    10: 'ExperimentalMeasurement',
    11: 'MTUProbe',
    12: 'MTUReply',
    15: 'ENCODE',
    25: 'Quick-Start',
    30: 'RFC3692-styleExperiment',
    68: 'TimeStamp',
    82: 'Traceroute',
    94: 'RFC3692-styleExperiment',
    130: 'Security',
    131: 'LooseSourceRoute',
    133: 'ExtendedSecurity',
    134: 'CommercialSecurity',
    136: 'StreamID',
    137: 'StrictSourceRoute',
    142: 'ExpermentalAccessControl',
    144: 'IMITrafficDescriptor',
    145: 'ExtendedInternetProtocol',
    147: 'AddressExtension',
    148: 'RouterAlert',
    149: 'SelectiveDirectedBroadcast',
    151: 'DynamicPacketState',
    152: 'UpstreamMulticastPkt',
    158: 'RFC3692-styleExperiment',
    205: 'ExperimentalFlowControl',
    222: 'RFC3692-styleExperiment',
    }

IPv4Preced_dict = {
    0 : 'Routine',
    1 : 'Priority',
    2 : 'Immediate',
    3 : 'Flash',
    4 : 'Flash Override',
    5 : 'CRITIC/ECP',
    6 : 'Internetwork Control',
    7 : 'Network Control'
    }

class IPv4Option(Envelope):
    _GEN = (
        Uint8('CCN', dic=IPv4Opt_dict),
        Uint8('len'), # trans and val automated
        Buf('val', val=b'') # trans and bl automated
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_transauto(self._set_trans)
        self[1].set_valauto(self._set_len_val)
        self[2].set_transauto(self._set_trans)
        self[2].set_blauto(self._set_val_bl)
    
    def _set_trans(self):
        if self[0].get_val() in (0, 1):
            return True
        else:
            return False
    
    def _set_len_val(self):
        return 2 + self[2].get_len()
    
    def _set_val_bl(self):
        return max(0, 8 * (self[1].get_val()-2))

class IPv4Options(Envelope):
    _GEN = (
        Array('opts', GEN=IPv4Option()),
        Buf('pad') # bl automated
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_blauto(self._set_pad_bl)
    
    def _set_pad_bl(self):
        opts_ext = self[0].get_bl() % 32
        if opts_ext:
            return 32 - opts_ext
        else:
            return 0

class IPv4(Envelope):
    _GEN = (
        Uint('vers', val=4, bl=4),
        Uint('hdr_wlen', bl=4), # val automated
        Uint('precedence', bl=3, dic=IPv4Preced_dict),
        Uint('delay', bl=1, dic={0:'Normal', 1:'Low'}),
        Uint('throughput', bl=1, dic={0:'Normal', 1:'High'}),
        Uint('reliab', bl=1, dic={0:'Normal', 1:'High'}),
        Uint('res_1', bl=2, rep=REPR_BIN),
        Uint16('len'), # val automated, unless initialized to fixed value
        Uint16('id'),
        Uint('res_2', bl=1, rep=REPR_BIN),
        Uint('DF', bl=1, dic={0:'may fragment', 1:'do not fragment'}),
        Uint('MF', bl=1, dic={0:'last fragment', 1:'more fragment'}),
        Uint('frag_off', bl=13),
        Uint8('TTL', val=24),
        Uint8('proto', dic=IPProt_dict), # val automated, unless initialized to fixed value
        Uint16('hdr_cs', rep=REPR_HEX), # val automated
        Buf('src', val=b'\x7f\0\0\x01', bl=32, rep=REPR_HEX),
        Buf('dst', val=b'\x7f\0\0\x01', bl=32, rep=REPR_HEX),
        Buf('opt', val=b''), # bl automated
        )
    def __init__(self, *args, **kwargs):
        # enable to pass IPv4 addr in human-readable format
        if 'val' in kwargs:
            if 'src' in kwargs['val'] and len(kwargs['val']['src']) > 4:
                try:
                    kwargs['val']['src'] = inet_aton(kwargs['val']['src'])
                except:
                    pass
            if 'dst' in kwargs['val'] and len(kwargs['val']['dst']) > 4:
                try:
                    kwargs['val']['dst'] = inet_aton(kwargs['val']['dst'])
                except:
                    pass
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(self._set_hdrwlen_val)
        if 'val' not in kwargs or 'len' not in kwargs['val']:
            self[7].set_valauto(self._set_len_val)
        if 'val' not in kwargs or 'proto' not in kwargs['val']:
            self[14].set_valauto(self._set_prot_val)
        self[15].set_valauto(self.checksum)
        self[18].set_blauto(self._set_opt_bl)
    
    def _set_hdrwlen_val(self):
        return 5 + (self[18].get_len() // 4)
    
    def _set_len_val(self):
        pay = self.get_payload()
        if pay is not None:
            return 20 + self[18].get_len() + pay.get_len()
        else:
            return 20 + self[18].get_len()
    
    def _set_prot_val(self):
        pay = self.get_payload()
        if pay is not None and pay[0]._name in IPProtRev_dict:
            return IPProtRev_dict[pay[0]._name]
        else:
            return 0xff
    
    def checksum(self):
        return checksum(self[:15].to_bytes() + b'\0\0' + self[16:].to_bytes())
    
    def _set_opt_bl(self):
        return max(0, 32 * (self[1].get_val()-5))
    
    def _from_char(self, char):
        Envelope._from_char(self, char)
        opts_buf = self[18].get_val()
        if opts_buf:
            opts = IPv4Options()
            opts.from_bytes(opts_buf)
            if opts.to_bytes() == opts_buf:
                self.replace(self[18], opts)


class ICMP(Envelope):
    _GEN = (
        Uint8('type', val=8),
        Uint8('code'),
        Uint16('cs', rep=REPR_HEX), # val automated
        Buf('data', val=b'\0\0coucou')
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(self.checksum)
    
    def checksum(self):
        cs_old = self[2]._val
        self[2]._val = 0
        icmp = self.to_bytes()
        self[2]._val = cs_old
        return checksum(icmp)


class IPv6(Envelope):
    _GEN = (
        Uint('vers', val=6, bl=4),
        Uint8('class'),
        Uint('flow', bl=20, rep=REPR_HEX),
        Uint16('plen'), # val automated, unless initialized to fixed value
        Uint8('next', dic=IPProt_dict), # val automated, unless initialized to fixed value
        Uint8('hop_limit', val=24),
        Buf('src', val=15*b'\0'+b'\x01', bl=128, rep=REPR_HEX),
        Buf('dst', val=15*b'\0'+b'\x01', bl=128, rep=REPR_HEX)
        )
    def __init__(self, *args, **kwargs):
        # enable to pass IPv4 addr in human-readable format
        if 'val' in kwargs:
            if 'src' in kwargs['val'] and len(kwargs['val']['src']) != 16:
                try:
                    kwargs['val']['src'] = inet_pton(AF_INET6, kwargs['val']['src'])
                except:
                    pass
            if 'dst' in kwargs['val'] and len(kwargs['val']['dst']) != 16:
                try:
                    kwargs['val']['dst'] = inet_pton(AF_INET6, kwargs['val']['dst'])
                except:
                    pass
        Envelope.__init__(self, *args, **kwargs)
        if 'val' not in kwargs or 'plen' not in kwargs['val']:
            self[3].set_valauto(self._set_plen_val)
        if 'val' not in kwargs or 'next' not in kwargs['val']:
            self[4].set_valauto(self._set_next_val)
    
    def _set_plen_val(self):
        pay = self.get_payload()
        if pay is not None:
            return pay.get_len()
        else:
            return 0
    
    def _set_next_val(self):
        pay = self.get_payload()
        if pay is not None and pay[0]._name in IPProtRev_dict:
            return IPProtRev_dict[pay[0]._name]
        else:
            return 0xff


class UDP(Envelope):
    _CS_OFF = False # for checksum offload
    _GEN = (
        Uint16('src'),
        Uint16('dst'),
        Uint16('len'), # val automated, unless initialized to fixed value
        Uint16('cs', rep=REPR_HEX) # val automated
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        if 'val' not in kwargs or 'len' not in kwargs['val']:
            self[2].set_valauto(self._set_len_val)
        self[3].set_valauto(self.checksum)
    
    def _set_len_val(self):
        pay = self.get_payload()
        if pay is not None:
            return 8 + pay.get_len()
        else:
            return 8
    
    def checksum(self):
        if self._CS_OFF:
            return 0
        # get UDP and payload buffer
        pay = self.get_payload()
        if pay is not None:
            udp = b''.join((self[:3].to_bytes(),
                            b'\0\0',
                            pay.to_bytes()))
        else:
            udp = self[:3].to_bytes() + b'\0\0'
        # get pseudo hdr buffer
        ludp =  len(udp)
        hdr = self.get_header()
        if hdr is not None:
            # keep only src addr, dst addr and prot
            vers = hdr[0].get_val()
            if vers == 4:
                phdr = b''.join((hdr[16].to_bytes(),
                                 hdr[17].to_bytes(),
                                 b'\0\x11',
                                 pack('>H', ludp)))
            elif vers == 6:
                # WNG: in case of IPv6 routing header, dst addr is incorrect
                phdr = b''.join((hdr[6].to_bytes(),
                                 hdr[7].to_bytes(),
                                 b'\0\x11',
                                 pack('>H', ludp)))
            else:
                phdr = b''
        else:
            phdr = b''
        # compute checksum
        return checksum(b''.join((phdr, udp)))


class TCP(Envelope):
    _CS_OFF = False # for checksum offload
    _GEN = (
        Uint16('src'),
        Uint16('dst'),
        Uint32('seq'),
        Uint32('ack'),
        Uint('off', bl=4), # val automated, unless initialized to fixed value
        Uint('res', bl=3, rep=REPR_BIN),
        Uint('NS', bl=1),
        Uint('CWR', bl=1),
        Uint('ECE', bl=1),
        Uint('URG', bl=1),
        Uint('ACK', bl=1),
        Uint('PSH', bl=1),
        Uint('RST', bl=1),
        Uint('SYN', bl=1),
        Uint('FIN', bl=1),
        Uint16('win', val=8192),
        Uint16('cs', rep=REPR_HEX), # val automated
        Uint16('urg'),
        Buf('opt', val=b'') # bl automated
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        if 'val' not in kwargs or 'off' not in kwargs['val']:
            self[4].set_valauto(self._set_off_val)
        self[16].set_valauto(self.checksum)
        self[18].set_blauto(self._set_opt_bl)
    
    def _set_off_val(self):
        return 5 + (self[18].get_len() // 4)
    
    def checksum(self):
        if self._CS_OFF:
            return 0
        # get TCP and payload buffer
        pay = self.get_payload()
        if pay is not None:
            tcp = b''.join((self[:16].to_bytes(),
                            b'\0\0',
                            self[17:].to_bytes(),
                            pay.to_bytes()))
        else:
            tcp = b''.join((self[:16].to_bytes(),
                            b'\0\0',
                            self[17:].to_bytes()))
        # get pseudo hdr buffer
        ltcp =  len(tcp)
        hdr = self.get_header()
        if hdr is not None:
            # keep only src addr, dst addr and prot
            vers = hdr[0].get_val()
            if vers == 4:
                phdr = b''.join((hdr[16].to_bytes(),
                                 hdr[17].to_bytes(),
                                 b'\0\x06',
                                 pack('>H', ltcp)))
            elif vers == 6:
                # WNG: in case of IPv6 routing header, dst addr is incorrect
                phdr = b''.join((hdr[6].to_bytes(),
                                 hdr[7].to_bytes(),
                                 b'\0\x06',
                                 pack('>H', ltcp)))
            else:
                phdr = b''
        else:
            phdr = b''
        # compute checksum
        return checksum(phdr + tcp)
    
    def _set_opt_bl(self):
        return max(0, 32 * (self[4].get_val()-5))

