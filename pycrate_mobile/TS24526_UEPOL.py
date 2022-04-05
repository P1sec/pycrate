# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2019. Benoit Michau. P1Sec.
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
# * File Name : pycrate_mobile/TS24526_UEPOL.py
# * Created : 2019-12-05
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'URSPRules',
    'URSPRule',
    'ANDSPInfos',
    'ANDSPInfo',
    'N3AN',
    'WLANSPRule',
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.526: User Equipment (UE) policies for 5G System (5GS)
# release 16 (g10)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from pycrate_ether.IP       import IPProt_dict
from pycrate_ether.Ethernet import EtherType_dict

from .TS24008_IE import (
    PLMN, 
    )
from .TS24501_IE import (
    DNN, _SSCMode_dict, SNSSAI, PDUSessType, FGSTAIList, 
    )


#------------------------------------------------------------------------------#
# Encoding of UE policy part type URSP
# TS 24.526, section 5.2
#------------------------------------------------------------------------------#

# Table 5.2.1, Traffic descriptor component type identifier
_TrafficDescCompType_dict = {
    1   : 'Match-all type',
    8   : 'OS Id + OS App Id type',
    16  : 'IPv4 remote address type',
    17  : 'IPv4 local address type',
    33  : 'IPv6 remote address/prefix length type',
    35  : 'IPv6 local address/prefix length type',
    48  : 'Protocol identifier/Next header type',
    64  : 'Single local port type',
    65  : 'Local port range type',
    80  : 'Single remote port type',
    81  : 'Remote port range type',
    96  : 'Security parameter index type',
    112 : 'Type of service/Traffic class type',
    128 : 'Flow label type',
    129 : 'Destination MAC address type',
    130 : 'Source MAC address type',
    131 : '802.1Q C-TAG VID type',
    132 : '802.1Q S-TAG VID type',
    133 : '802.1Q C-TAG PCP/DEI type',
    134 : '802.1Q S-TAG PCP/DEI type',
    135 : 'Ethertype type',
    136 : 'DNN type',
    144 : 'Connection capabilities type',
    145 : 'Destination FQDN',
    160 : 'OS App Id type'
    }

_TrafficDescConCap_dict = {
    1 : 'IMS',
    2 : 'MMS',
    4 : 'SUPL',
    8 : 'Internet'
    }


class _TrafficDescCompOSAppId(Envelope):
    _GEN = (
        Buf('OS_UUID', bl=128, rep=REPR_HEX),
        Uint8('LenAppId'),
        Buf('AppId')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: self[1].get_val()<<3)


class _TrafficDescCompIPv4(Envelope):
    _GEN = (
        Buf('Addr', bl=32, rep=REPR_HEX),
        Buf('Mask', bl=32, rep=REPR_HEX)
        )


class _TrafficDescCompIPv6(Envelope):
    _GEN = (
        Buf('Addr', bl=128, rep=REPR_HEX),
        Uint8('Pref')
        )


class _TrafficDescCompPortRange(Envelope):
    _GEN = (
        Uint16('Low'),
        Uint16('High')
        )


class _TrafficDescCompTrafficClass(Envelope):
    _GEN = (
        Uint8('Class'),
        Uint8('Mask')
        )


class _TrafficDescCompFlowLabel(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Value', bl=20, rep=REPR_HEX)
        )


class _TrafficDescCompVID(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Value', bl=12)
        )


class _TrafficDescCompPCPDEI(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('PCP', bl=3),
        Uint('DEI', bl=1)
        )


class _TrafficDescCompConCap(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('Caps', GEN=Uint8('Cap', dic=_TrafficDescConCap_dict))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_val())


class _TrafficDescCompFQDN(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('Value', val=b'')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


class _TrafficDescCompAppId(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('AppId')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


class TrafficDescComp(Envelope):
    _GEN = (
        Uint8('Type', dic=_TrafficDescCompType_dict),
        Alt('Value', GEN={
            1   : Buf('none', bl=0),
            8   : _TrafficDescCompOSAppId('OSAppId'),
            16  : _TrafficDescCompIPv4('IPv4'),
            17  : _TrafficDescCompIPv4('IPv4'),
            33  : _TrafficDescCompIPv6('IPv6Pref'),
            35  : _TrafficDescCompIPv6('IPv6Pref'),
            48  : Uint8('ProtId', dic=IPProt_dict),
            64  : Uint16('Port'),
            65  : _TrafficDescCompPortRange('PortRange'),
            80  : Uint16('Port'),
            81  : _TrafficDescCompPortRange('PortRange'),
            96  : Uint32('SPI', rep=REPR_HEX),
            112 : _TrafficDescCompTrafficClass('TrafficClass'),
            128 : _TrafficDescCompFlowLabel('FlowLabel'),
            129 : Buf('MACDest', bl=48, rep=REPR_HEX),
            130 : Buf('MACSrc', bl=48, rep=REPR_HEX),
            131 : _TrafficDescCompVID('CTagVID'),
            132 : _TrafficDescCompVID('STagVID'),
            133 : _TrafficDescCompPCPDEI('CTagPCPDEI'),
            134 : _TrafficDescCompPCPDEI('STagPCPDEI'),
            135 : Uint16('EtherType', dic=EtherType_dict),
            136 : DNN(),
            144 : _TrafficDescCompConCap('ConCap'),
            145 : _TrafficDescCompFQDN('FQDN'),
            160 : _TrafficDescCompAppId('AppId')
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )


# Table 5.2.1, SSC Mode Type
class _RouteSelectDescCompSSCMode(Envelope):
    _GEN = (
        Uint('spare', bl=5),
        Uint('Value', bl=3, dict=_SSCMode_dict)
        )


# Table 5.2.1, preferred access type type
class _RouteSelectDescCompAccessType(Envelope):
    _GEN = (
        Uint('spare', bl=6),
        Uint('Value', bl=2, dic={1:'3GPP access', 2:'non-3GPP access'})
        )


# Table 5.2.1, time window type
class _RouteSelectDescCompTimeWin(Envelope):
    _GEN = (
        Uint32('Second'),
        Uint32('Fraction')
        )


# Table 5.2.2: Location criteria
class _LocAreaEUTRACellID(Envelope):
    _GEN = (
        PLMN(),
        Buf('EUTRACellID', bl=28, rep=REPR_HEX),
        Uint('spare', bl=4, rep=REPR_HEX)
        )


class _LocAreaCompEUtra(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('CellIDs', GEN=_LocAreaEUTRACellID('EUTRACellID'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_num())


class _LocAreaEUTRACellID(Envelope):
    _GEN = (
        PLMN(),
        Buf('NRCellID', bl=36, rep=REPR_HEX),
        Uint('spare', bl=4, rep=REPR_HEX)
        )


class _LocAreaCompNR(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('CellIDs', GEN=_LocAreaEUTRACellID('NRCellID'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_num())


class _LocAreaGNID(Envelope):
    _GEN = (
        PLMN(),
        Buf('gNBID', bl=32, rep=REPR_HEX)
        )


class _LocAreaCompGNID(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('gNBIDs', GEN=_LocAreaGNID('gNBID'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_num())
        self[1].set_numauto(lambda: self[0].get_num())


# Figure 5.2.6: Location area
_RouteSelectLocAreaType_dict = {
    1 : 'E-UTRA cell identities list',
    2 : 'NR cell identities list',
    3 : 'Global RAN node identities list',
    4 : 'TAI list'
    }


class _LocAreaComp(Envelope):
    _GEN = (
        Uint8('Type', dic=_RouteSelectLocAreaType_dict),
        Alt('Cont', GEN={
            1 : _LocAreaCompEUtra('EUTRACellIDs'),
            2 : _LocAreaCompNR('NRCellIDs'),
            3 : _LocAreaCompGNID('gNBIDs'),
            4 : FGSTAIList()
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )


# Figure 5.2.5: Location criteria
class _RouteSelectDescCompLocArea(Sequence):
    _GEN = _LocAreaComp('LocAreaComp')


# Table 5.2.1, Route selection descriptor component type identifier
_RouteSelectDescCompType_dict = {
    1   : 'SSC mode',
    2   : 'S-NSSAI',
    4   : 'DNN',
    8   : 'PDU session type',
    16  : 'Preferred access type',
    17  : 'Multi-access preference',
    128 : 'Time window',
    64  : 'Location criteria',
    32  : 'Non-seamless non-3GPP offload indication'
    }


class RouteSelectDescComp(Envelope):
    _GEN = (
        Uint8('Type', dic=_RouteSelectDescCompType_dict),
        Alt('Value', GEN={
            1   : _RouteSelectDescCompSSCMode('SSCMode'),
            2   : SNSSAI(),
            4   : DNN(),
            8   : PDUSessType(),
            16  : _RouteSelectDescCompAccessType('AccessType'),
            17  : Buf('none', bl=0),
            32  : Buf('none', bl=0),
            64  : _RouteSelectDescCompLocArea('LocArea'),
            128 : _RouteSelectDescCompTimeWin('TimeWin')
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )


# Figure 5.2.4: Route selection descriptor
class RouteSelectDesc(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Precedence'),
        Uint16('LenCont'),
        Sequence('Cont', GEN=RouteSelectDescComp())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 3 + self[3].get_len())
        self[2].set_valauto(lambda: self[3].get_len())
        self[3].set_blauto(lambda: self[2].get_val())


# Figure 5.2.2: URSP rule
class URSPRule(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Precedence'),
        Uint16('LenTrafficDesc'),
        Sequence('TrafficDesc', GEN=TrafficDescComp()),
        Uint16('LenRouteSelectDescList'),
        Sequence('RouteSelectDescList', GEN=RouteSelectDesc())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 5 + self[3].get_len() + self[5].get_len())
        self[2].set_valauto(lambda: self[3].get_len())
        self[3].set_blauto(lambda: self[2].get_val())
        self[4].set_valauto(lambda: self[5].get_len())
        self[5].set_blauto(lambda: self[4].get_val())


# Figure 5.2.1: UE policy part contents including one or more URSP rules
class URSPRules(Sequence):
    _GEN = URSPRule()


#------------------------------------------------------------------------------#
# Encoding of UE policy part type ANDSP
# TS 24.526, section 5.3
#------------------------------------------------------------------------------#

# Figure 5.3.2.4g: Selection criteria sub entry {selection criteria set type = minimum backhaul threshold}
class _WLANSelectionCriteriaMinBack(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('ULBInd', bl=1),
        Uint('DLBInd', bl=1),
        Uint('NetworkType', bl=2, dic={0:'home', 1:'roaming'}),
        Uint32('DLBW'),
        Uint32('ULBW')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['DLBW'].set_transauto(lambda: self['DLBInd'].get_val() == 0)
        self['ULBW'].set_transauto(lambda: self['ULBInd'].get_val() == 0)


# Figure 5.3.2.4f: Selection criteria sub entry {selection criteria set type = SP exclusion list}
class _WLANSelectionCriteriaSPExcl(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('SSID')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_val())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


# Figure 5.3.2.4e: Selection criteria sub entry {selection criteria set type = required protocol port tuple}
class _WLANSelectionCriteriaPortTuple(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint8('PortId', dic=IPProt_dict),
        Uint8('LenPort'),
        Buf('Port', val=b'\0\1', rep=REPR_HEX), # see WiFi Alliance HotSpot 2.0
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 2 + self[3].get_len())
        self[2].set_valauto(lambda: self[3].get_len())
        self[3].set_blauto(lambda: self[2].get_val()<<3)


# Figure 5.3.2.4d: Selection criteria sub entry {selection criteria set type = preferred roaming partner list}
class _WLANSelectionCriteriaPrefRoam(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint8('Priority'),
        Uint8('LenFQDN'),
        Buf('FQDNMatch', rep=REPR_HEX), # see WiFi Alliance HotSpot 2.0
        Uint8('LenCountry'),
        Buf('Country', rep=REPR_HEX), # see WiFi Alliance HotSpot 2.0
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 3 + self['LenFQDN'].get_val() + self['LenCountry'].get_val())
        self[2].set_valauto(lambda: self[3].get_len())
        self[3].set_blauto(lambda: self[2].get_val()<<3)
        self[4].set_valauto(lambda: self[5].get_len())
        self[5].set_blauto(lambda: self[4].get_val()<<3)


# Figure 5.3.2.4c: Selection criteria sub entry {selection criteria set type = preferred SSID list}
class _WLANSelectionCriteriaPrefSSID(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint8('WLANPriority'),
        Uint('spare', bl=6),
        Uint('HESSIDInd', bl=1),
        Uint('SSIDInd', bl=1),
        Envelope('SSID', GEN=(
            Uint8('Len'),
            Buf('Value', val=b'', rep=REPR_HEX))
            ),
        Buf('HESSID', bl=48, rep=REPR_HEX) # MAC addr
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 2 + self[5].get_len() + self[6].get_len())
        self['SSID'].set_transauto(lambda: self['SSIDInd'].get_val() == 0)
        self['HESSID'].set_transauto(lambda: self['HESSIDInd'].get_val() == 0)
        # SSID internal automation
        self['SSID'][0].set_valauto(lambda: self['SSID'][1].get_len())
        self['SSID'][1].set_blauto(lambda: self['SSID'][0].get_val()<<3)


# Figure 5.3.2.4b
_WLANSelCritType_dict = {
    1 : 'preferred SSID list',
    2 : 'preferred roaming partner list',
    3 : 'required protocol port tuple',
    4 : 'SP exclusion list',
    5 : 'minimum backhaul threshold'
    }


class _WLANSelectionCriteriaSet(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint('Type', bl=4, dic=_WLANSelCritType_dict),
        Uint('Num', bl=4),
        Sequence('SubEntries', GEN=Alt('CriteriaSubEntry', GEN={
            1 : _WLANSelectionCriteriaPrefSSID('PrefSSID'),
            2 : _WLANSelectionCriteriaPrefRoam('PrefRoaming'),
            3 : _WLANSelectionCriteriaPortTuple('RequiredProtocolPort'),
            4 : _WLANSelectionCriteriaSPExcl('SPExcl'),
            5 : _WLANSelectionCriteriaMinBack('MinBackhaulThres')},
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env().get_env()['Type'].get_val()))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[3].get_len())
        self[2].set_valauto(lambda: self[3].get_num())
        self[3].set_numauto(lambda: self[2].get_val())
        self[3].set_blauto(lambda: (self[0].get_val()-1)<<3)


# Table 5.3.2.1: WLANSP information element, Home network ind
_HomeNetworkInd_dict = {
    0 : 'all WLANs could match this selection criteria entry',
    1 : 'only the WLANs that are operated by the home operator could match this selection criteria entry'
    }


# Figure 5.3.2.4a
class _WLANSelectionCriteriaEntry(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint('spare', bl=1),
        Uint('MaxBSSLoadInd', bl=1),
        Uint('HomeNetworkInd', bl=1, dic=_HomeNetworkInd_dict),
        Uint('CriteriaPriority', bl=5),
        Uint16('MaxBSSLoad'),
        Sequence('CriteriaSets', GEN=_WLANSelectionCriteriaSet('CriteriaSet'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 3 + self[6].get_len() if self[2].get_val() == 1 else 1 + self[6].get_len())
        self[5].set_transauto(lambda: self[2].get_val() == 0)
        self[6].set_blauto(lambda: ((self[0].get_val()-3)<<3) if self[2].get_val() == 1 else ((self[0].get_val()-1)<<3))


# Figure 5.3.2.4
class _WLANSelectionCriteria(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Num'),
        Sequence('Entries', GEN=_WLANSelectionCriteriaEntry('CriteriaEntry'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[1].set_valauto(lambda: self[2].get_num())
        self[2].set_numauto(lambda: self[1].get_val())


# Figure 5.3.2.11c: Location field {entry type= WLAN location}
_LocFieldType_dict = {
    1 : 'TAC',
    2 : 'EUTRA CellID',
    4 : 'NR CellID',
    129 : 'HESSID',
    130 : 'SSID',
    132 : 'BSSID'
    }

class _LocFieldWLAN(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint8('Type', dic=_LocFieldType_dict),
        Alt('Cont', GEN={
            129 : Buf('HESSID', bl=48, rep=REPR_HEX),
            130 : Buf('SSID', rep=REPR_HEX),
            132 : Buf('BSSID', bl=48, rep=REPR_HEX),
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val()
            )
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[2].set_blauto(lambda: self[0].get_val() - 1)


# Figure 5.3.2.11b: Location field {entry type= 3GPP location}
class _LocField3GPP(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint8('Type', dic=_LocFieldType_dict),
        Alt('Cont', GEN={
            #1 : Buf('TAC'), # WNG: a TAC is not 8 bits (but 16 in 4G and 24 in 5G) !
            #2 : Uint16('EUTRACellID'), # WNG: a LTE CellID is not 16 bits (but 28) !
            #4 : Uint24('NRCellID'), # WNG: a NR CellID is not 24 bits (but 36) !
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val()
            )
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[2].set_blauto(lambda: self[0].get_val() - 1)


# Figure 5.3.2.11a: Location field {entry type= Geo location}
class _LocFieldGeo(Envelope):
    _GEN = (
        Uint32('Lat'),
        Uint32('Long'),
        Uint16('Radius')
        )


# Figure 5.3.2.10a: Location sub entry {entry type= WLAN location or Geo location}
class _LocSubentryGeo(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Num'),
        Sequence('Fields', GEN=_LocFieldGeo('LocGeo'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[1].set_valauto(lambda: self[2].get_num())
        self[2].set_numauto(lambda: self[1].get_val())


# Figure 5.3.2.10a: Location sub entry {entry type= WLAN location or Geo location}
class _LocSubentryWLAN(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Num'),
        Sequence('Fields', GEN=_LocFieldWLAN('LocWLAN'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[1].set_valauto(lambda: self[2].get_num())
        self[2].set_numauto(lambda: self[1].get_val())


# Figure 5.3.2.10: Location sub entry {entry type= 3GPP location}
class _LocSubentry3GPP(Envelope):
    _GEN = (
        Uint16('Len'),
        PLMN(),
        Uint8('Num'), # optional
        Sequence('Fields', GEN=_LocField3GPP('Loc3GPP'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 4 + self[3].get_len())
        self[2].set_valauto(lambda: self[3].get_num())
        self[3].set_numauto(lambda: self[2].get_val())


# Figure 5.3.2.6: Location entry
class LocationEntry(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint('Type', bl=2, dic={1:'3GPP', 2:'WLAN', 3:'Geo'}),
        Uint('Num', bl=6),
        Sequence('SubEntries', GEN=Alt('LocationSubEntry', GEN={
            # TODO: verify Type values
            1 : _LocSubentry3GPP('SubEntry3GPP'),
            2 : _LocSubentryWLAN('SubEntryWLAN'),
            3 : _LocSubentryGeo('SubEntryGeo')
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env().get_env()['Type'].get_val()))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[3].get_len())
        self[2].set_valauto(lambda: self[3].get_num())
        self[3].set_numauto(lambda: self[2].get_val())
        self[3].set_blauto(lambda: (self[0].get_val()-1)<<3)


# Figure 5.3.2.5: Validity area
class _WLANValidityArea(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Num'),
        Sequence('Entries', GEN=LocationEntry())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[1].set_valauto(lambda: self[2].get_num())
        self[2].set_numauto(lambda: self[1].get_val())




# Figure 5.3.2.20: ToD sub field {field type = "day of the week"}
class _TimeOfDayDay(Envelope):
    _GEN = (
        Uint('spare', val=1, bl=1),
        Uint('Mon', bl=1),
        Uint('Tue', bl=1),
        Uint('Wed', bl=1),
        Uint('Thu', bl=1),
        Uint('Fri', bl=1),
        Uint('Sat', bl=1),
        Uint('Sun', bl=1)
        )


# Figure 5.3.2.17: ToD sub field
_TimeOfDayFieldType_dict = {
    1 : 'time start',
    2 : 'time stop',
    4 : 'date start',
    8 : 'date stop',
    16 : 'day of the week'
    }

class _TimeOfDayField(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint8('Type', dic=_TimeOfDayFieldType_dict),
        Alt('Cont', GEN={
            1 : Buf('TimeStart'),
            2 : Buf('TimeStop'),
            4 : Buf('DateStart'),
            8 : Buf('DateStop'),
            16 : _TimeOfDayDay('DayOfWeek')
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env().get_env()['Type'].get_val())
        )


# Figure 5.3.2.16: Time of day sub field
class _TimeOfDayEntry(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Num'),
        Sequence('Fields', GEN=_TimeOfDayField('TimeOfDayField'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[1].set_valauto(lambda: self[2].get_num())
        self[2].set_numauto(lambda: self[1].get_val())


# Figure 5.3.2.15: Time of day
class _WLANTimeOfDay(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Num'),
        Sequence('Entries', GEN=_TimeOfDayEntry('TimeOfDayEntry'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[2].get_len())
        self[1].set_valauto(lambda: self[2].get_num())
        self[2].set_numauto(lambda: self[1].get_val())


# Figure 5.3.2.3
class WLANSPRule(Envelope):
    _GEN = (
        Uint16('Len'),
        Uint8('Id'),
        Uint8('Priority'),
        Uint('Roaming', bl=1, dic={0:'rule only valid when UE is not roaming', 1:'rule only valid when UE is roaming'}),
        Uint('ValidityAreaInd', bl=1),
        Uint('3GPPLocInd', bl=1),
        Uint('WLANLocInd', bl=1),
        Uint('GeoLocInd', bl=1),
        Uint('TimeOfDayInd', bl=1),
        Uint('spare', bl=2),
        _WLANSelectionCriteria('SelectionCriteria'),
        _WLANValidityArea('ValidityArea'), # optional
        _WLANTimeOfDay('TimeOfDay') # optional
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 3 + self['SelectionCriteria'].get_len() + \
                                    self['ValidityArea'].get_len() + self['TimeOfDay'].get_len())
        #self['ValidityArea'].set_transauto(lambda: self['ValidityAreaInd'].get_val() == 0)
        self['ValidityArea'].set_transauto(lambda: self['GeoLocInd'].get_val() == 0)
        self['TimeOfDay'].set_transauto(lambda: self['TimeOfDayInd'].get_val() == 0)


# Figure 5.3.3.2.2: N3AN node selection information entry
_N3ANNodeSelFQDNFmt_dict = {
    0 : 'Operator identifier based ePDG FQDN format or operator identifier based N3IWF FQDN',
    1 : 'Tracking/location area identity based ePDG FQDN format or tracking area identity based N3IWF FQDN format'
    }

class _N3ANNodeSelEntry(Envelope):
    _GEN = (
        Uint8('Len', val=4),
        PLMN(),
        Uint('FQDNFormat', bl=2, dic=_N3ANNodeSelFQDNFmt_dict),
        Uint('Preference', bl=1, dic={0:'N3IWF is preferred', 1:'ePDG is preferred'}),
        Uint('Priority', bl=5)
        )


# Figure 5.3.3.2.1: Content of N3AN node selection information
class _N3ANNodeSelInfo(Envelope):
    _GEN = (
        Uint16('Len'),
        Sequence('Entries', GEN=_N3ANNodeSelEntry('N3ANNodeSelEntry'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


# Table 5.3.3.3.1: Home N3IWF identifier entry (type = IP address type)
# Table 5.3.3.3.2: Home N3IWF identifier entry (type = FQDN)
class _HomeN3IWFIdentEntry(Envelope):
    _GEN = (
        Uint8('Type', val=1, dic={1:'IPv4', 2:'IPv6', 3:'IPv4v6', 4:'FQDN'}),
        Alt('', GEN={
            1 : Buf('IPv4', bl=32, rep=REPR_HEX),
            2 : Buf('IPv6', bl=128, rep=REPR_HEX),
            3 : Envelope('IPv4v6', GEN=(
                    Buf('IPv4', bl=32, rep=REPR_HEX),
                    Buf('IPv6', bl=128, rep=REPR_HEX))
                ),
            4 : _TrafficDescCompFQDN('FQDN')
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )


# Figure 5.3.3.3.1: Content of home N3IWF identifier configuration
class _HomeN3IWFIdentConfig(Envelope):
    _GEN = (
        Uint8('Type', val=1),
        Uint16('Len'),
        Sequence('Entries', GEN=_HomeN3IWFIdentEntry('HomeN3IWFIdentEntry'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: self[1].get_val()<<3)


# Figure 5.3.3.4.1: Content of home ePDG identifier configuration
class _HomeEPDGIdentConfig(Envelope):
    _GEN = (
        Uint8('Type', val=2),
        Uint16('Len'),
        Sequence('Entries', GEN=_HomeN3IWFIdentEntry('HomeEPDGIdentEntry'))
        ) 


# Figure 5.3.3.1.1: ANDSP info containing N3AN node configuration information
class N3AN(Envelope):
    _GEN = (
        _N3ANNodeSelInfo('N3ANNodeSelInfo'),
        _HomeN3IWFIdentConfig('HomeN3IWFIdentConfig'),
        _HomeEPDGIdentConfig('HomeEPDGIdentConfig')
        )


# Figure 5.3.2.1
_ANDSPInfoType_dict = {
    0 : 'Reserved',
    1 : 'WLANSP',
    2 : 'N3AN node configuration information'
    }

# Figure 5.3.1.3: ANDSP Info
class ANDSPInfo(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Type', bl=4, dic=_ANDSPInfoType_dict),
        Uint16('Len'),
        Alt('Cont', GEN={
            1: Sequence('WLANSPRules', GEN=WLANSPRule()),
            2: N3AN()
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: self[3].get_len())
        self[3].set_blauto(lambda: self[2].get_val()<<3)


# Figure 5.3.1.2: ANDSP contents
class ANDSPInfos(Sequence):
    _GEN = ANDSPInfo()

