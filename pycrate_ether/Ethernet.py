# −*− coding: UTF−8 −*−
#/**
# * Software Name : pycrate 
# * Version : 0.4
# *
# * Copyright 2016. Benoit Michau. ANSSI.
# * Copyright 2020. Benoit Michau. P1Sec.
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
# * File Name : pycrate_ether/Ethernet.py
# * Created : 2016-04-27
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

from pycrate_core.utils import reverse_dict
from pycrate_core.elt import Envelope, REPR_RAW, REPR_HEX, REPR_BIN
from pycrate_core.base import *
from pycrate_core.repr import *

# EthernetPacket decoder requires basic L2 / L3 objects for decoding
from .IP    import IPv4, ICMP, IPv6, UDP, TCP
from .SCTP  import SCTP
from .ARP   import ARP


EtherType_dict = {
    0x0800 : 'IPv4',
    0x0806 : 'ARP',
    0x0842 : 'WakeOnLAN',
    0x22F3 : 'TRILL',
    0x6003 : 'DECnet',
    0x8035 : 'RARP',
    0x809B : 'AppleTalk',
    0x80F3 : 'AppleTalkARP',
    0x8100 : 'VLAN',
    0x8137 : 'IPX',
    0x8204 : 'QNXQnet',
    0x86DD : 'IPv6',
    0x8808 : 'EthFlowCtrl',
    0x8819 : 'CobraNet',
    0x8847 : 'MPLS',
    0x8848 : 'MPLSMulticast',
    0x8863 : 'PPPoEDiscovery',
    0x8864 : 'PPPoESession',
    0x8870 : 'JumboFrames',
    0x887B : 'HomePlug',
    0x888E : 'EAP',
    0x8892 : 'PROFINET',
    0x889A : 'HyperSCSI',
    0x88A2 : 'ATAoE',
    0x88A4 : 'EtherCAT',
    0x88A8 : 'IEEE8021ad',
    0x88AB : 'Powerlink',
    0x88CC : 'LLDP',
    0x88CD : 'SERCOS_III',
    0x88E1 : 'HomePlugAV',
    0x88E3 : 'MediaRedundancyProtocol',
    0x88E5 : 'IEEE8021ae',
    0x88E7 : 'IEEE8021ah',
    0x88F7 : 'IEEE1588',
    0x8902 : 'IEEE8021ag',
    0x8906 : 'FCoE',
    0x8914 : 'FCoEInitialization',
    0x8915 : 'RoCE',
    0x891D : 'TTE',
    0x892F : 'HSR',
    0x9000 : 'EthernetConfigTest'
    }

EtherTypeRev_dict = reverse_dict(EtherType_dict)

# For Ethernet / VLAN automatic type setting:
# it is required that the payload has one of the EtherType_dict value 
# as name attribute
 
class Ethernet(Envelope):
    _GEN = (
        Buf('dst', val=6*b'\0', bl=48, rep=REPR_HEX),
        Buf('src', val=6*b'\0', bl=48, rep=REPR_HEX),
        Uint16('type', rep=REPR_HEX) # val automated
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(self._set_type_val)
    
    def _set_type_val(self):
        pay = self.get_payload()
        if pay is not None and pay[0]._name in EtherTypeRev_dict:
            return EtherTypeRev_dict[pay[0]._name]
        else:
            return 0

class VLAN(Envelope):
    _GEN = (
        Uint('pcp', desc='Priority Code Point', bl=3),
        Uint('cfi', desc='Canonical Format Indicator', bl=1),
        Uint('vid', desc='VLAN identifier', bl=12),
        Uint16('type', rep=REPR_HEX) # val automated
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[3].get_valauto(self._set_type_val)
    
    def _set_type_val(self):
        pay = self.get_payload()
        if pay is not None and pay[0]._name in EtherTypeRev_dict:
            return EtherTypeRev_dict[pay[0]._name]
        else:
            return 0


# EthernetPacket is a basic decoder which handles multiple stacked layers:
# Ethernet (/VLAN) /ARP
#                  /IPv4 /ICMP
#                        /UDP
#                        /TCP
#                        /SCTP
#                  /IPv6 /UDP
#                        /TCP
#                        /SCTP

class EthernetPacket(Envelope):
    
    _GEN = (
        Ethernet(),
        )
    
    def _from_char(self, char):
        self.__init__()
        # Ethernet layer
        self[0]._from_char(char)
        typ = self[0][2].get_val()
        hier = 1
        # potential VLAN layer
        if typ == 0x8100:
            vlan = VLAN(hier=hier)
            hier += 1
            vlan._from_char(char)
            self.append(vlan)
            typ = vlan[3]._val
        # ARP or IP layer
        if typ == 0x0806:
            arp = ARP(hier=hier)
            hier += 1
            arp._from_char(char)
            self.append(arp)
            return
        elif typ == 0x0800:
            ip = IPv4(hier=hier)
            hier += 1
            typ = ip[14]
        elif typ == 0x86DD:
            ip = IPv6(hier=hier)
            hier += 1
            typ = ip[4]
        ip._from_char(char)
        self.append(ip)
        typ = typ._val
        # ICMP, UDP, TCP or SCTP layer
        if typ == 1:
            icmp = ICMP(hier=hier)
            hier += 1
            icmp._from_char(char)
            self.append(icmp)
            return
        elif typ == 6:
            tcp = TCP(hier=hier)
            hier += 1
            tcp._from_char(char)
            self.append(tcp)
        elif typ == 17:
            udp = UDP(hier=hier)
            hier += 1
            udp._from_char(char)
            self.append(udp)
        elif typ == 132:
            sctp = SCTP(hier=hier)
            hier += 1
            sctp._from_char(char)
            self.append(sctp)
        # remaining higher layer undecoded data
        if char.len_byte():
            data = Buf('Data', hier=hier)
            hier += 1
            data._from_char(char)
            if isinstance(self[-1], IPv4):
                # remove the proto field automation
                self[-1]['proto'].set_valauto(None)
            elif isinstance(self[-1], IPv6):
                # remove the next field automation
                self[-1]['next'].set_valauto(None)
            self.append(data)

