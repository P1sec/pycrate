# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2022. Benoit Michau. P1Sec.
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
# * File Name : pycrate_mobile/TS29060_GTP.py
# * Created : 2022-02-10
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/


#__all__ = [
#    ]


from enum import IntEnum

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *


#------------------------------------------------------------------------------#
# 3GPP TS 29.060: GPRS Tunnelling Protocol (GTP) across the Gn and Gp interface
# release 16 (h10)
# i.e. SGSN - GGSN interface
#------------------------------------------------------------------------------#

#------------------------------------------------------------------------------#
# GTP Extension Header
# TS 29.060, section 6.1
#------------------------------------------------------------------------------#

GTPNextExtHeader_dict = {
    0   : 'No more extension headers',
    1   : 'MBMS support indication',
    2   : 'MS Info Change Reporting support indication',
    32  : 'Reserved - User Plane only',
    64  : 'Reserved - User Plane only',
    129 : 'Reserved - User Plane only',
    130 : 'PDCP PDU Number',
    193 : 'Suspend Request',
    194 : 'Suspend Response'
    }


# buffer that makes the Extension Header 32-bit-aligned
class BufAligned(Buf):
    
    _rep = REPR_HEX
    
    PAD = b'\0'
    
    def set_val(self, val):
        pad_len = -(len(val)+2) % 4
        if pad_len:
            Buf.set_val(self, val + pad_len*self.PAD)
        else:
            Buf.set_val(self, val)


# prototype for the content of a generic Ext Header
class GTPHdrExtCont(Envelope):
    _GEN = (
        BufAligned('Value', val=b'\0\0', rep=REPR_HEX),
        )
    
    _ID = 1
    
    def __init__(self, *args, **kwargs):
        if 'ID' in kwargs:
            self._ID = kwargs['ID']
            del kwargs['ID']
        Envelope.__init__(self, *args, **kwargs)
    
    def clone(self):
        c = Envelope.clone(self)
        c._ID = self._ID
        return c


# All defined Ext Header
GTPHdrExtCont_dict = {
    1   : GTPHdrExtCont('MBMSSupportInd', val=[b'\xff\xff'], ID=1),
    2   : GTPHdrExtCont('MSInfoChangeReportSupportInd', val=[b'\xff\xff'], ID=2),
    130 : GTPHdrExtCont('PDCPPDUNumber', Gen=(
            Uint16('Value', val=0),
            ), ID=130),
    193 : GTPHdrExtCont('SuspendRequest', val=[b'\xff\xff'], ID=193),
    194 : GTPHdrExtCont('SuspendResponse', val=[b'\xff\xff'], ID=194),
    }


class GTPHdrExt(Envelope):
    _ExtCont = GTPHdrExtCont_dict
    
    _GEN  = (
        Uint8('Len'),
        GTPHdrExtCont('Content', rep=REPR_HEX),
        Uint8('NextExt', dic=GTPNextExtHeader_dict)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: (2 + self[1].get_len()) >> 2)
        self[1].set_blauto(lambda: self._get_cont_len())
        self[2].set_valauto(lambda: self._get_ne())
    
    def _get_cont_len(self):
        return max(0, (self[0].get_val()*32) - 16)
    
    def _get_ne(self):
        n = self.get_next()
        if n:
            return n[1]._ID
        else:
            return 0
    
    def set_val(self, val):
        self._set_cont_cls()
        Envelope.set_val(self, val)
    
    def _from_char(self, char):
        self._set_cont_cls()
        Envelope._from_char(self, char)
    
    def _set_cont_cls(self):
        ne = 1
        if self._env:
            p = self.get_prev()
            if p:
                # get NextExt from previous GTPHdrExt
                ne = p['NextExt'].get_val()
            elif self._env._env:
                # get NextExt from GTPHdrOpt
                ne = self._env._env[9]['NextExt'].get_val()
        if ne in self._ExtCont:
            Cont = self._ExtCont[ne].clone()
            Cont.set_blauto(lambda: self._get_cont_len())
            self.replace(self[1], Cont)


#------------------------------------------------------------------------------#
# GTP header
# TS 29.060, section 6
#------------------------------------------------------------------------------#

class GTPHdrExtList(Sequence):
    _GEN = GTPHdrExt()
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self.set_val(None)
        l = 0
        p = self.get_prev()
        if not p:
            return
        l += 1
        self.set_num(l)
        self[-1]._from_char(char)
        while self[-1]['NextExt'].get_val() != 0:
            l += 1
            self.set_num(l)
            self[-1]._from_char(char)


class GTPHdrOpt(Envelope):
    _GEN = (
        Uint16('SeqNum'),
        Uint8('NPDUNum'),
        Uint8('NextExt')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NextExt'].set_valauto(lambda: self._get_ne())
    
    def _get_ne(self):
        n = self.get_next()
        if isinstance(n, GTPHdrExtList) and n.get_num():
            return n[0][1]._ID
        else:
            return 0


ProtType_dict = {
    0 : 'GTP prime',
    1 : 'GTP',          # the one for GTP-U
    }


class GTPType(IntEnum):
    EchoReq                         = 1
    EchoResp                        = 2
    VersionNotSupported             = 3
    NodeAliveReq                    = 4
    NodeAliveResp                   = 5
    RedirectionReq                  = 6
    RedirectionResp                 = 7
    CreatePDPCtxtReq                = 16
    CreatePDPCtxtResp               = 17
    UpdatePDPCtxtReq                = 18
    UpdatePDPCtxtResp               = 19
    DeletePDPCtxtReq                = 20
    DeletePDPCtxtResp               = 21
    InitiatePDPCtxtActivationReq    = 22
    InitiatePDPCtxtActivationResp   = 23
    ErrorIndication                 = 26
    PDUNotifReq                     = 27
    PDUNotifResp                    = 28
    PDUNotifRejectReq               = 29
    PDUNotifRejectResp              = 30
    SupportedExtHeadersNotif        = 31
    SendRouteingInfoforGPRSReq      = 32
    SendRouteingInfoforGPRSResp     = 33
    FailureReportReq                = 34
    FailureReportResp               = 35
    NoteMSGPRSPresentReq            = 36
    NoteMSGPRSPresentResp           = 37
    IdentificationReq               = 48
    IdentificationResp              = 49
    SGSNCtxtReq                     = 50
    SGSNCtxtResp                    = 51
    SGSNCtxtAck                     = 52
    ForwardRelocationReq            = 53
    ForwardRelocationResp           = 54
    ForwardRelocationComplete       = 55
    RelocationCancelReq             = 56
    RelocationCancelResp            = 57
    ForwardSRNSCtxt                 = 58
    ForwardRelocationCompleteAck    = 59
    ForwardSRNSCtxtAck              = 60
    UERegistrationQueryReq          = 61
    UERegistrationQueryResp         = 62
    RANInfoRelay                    = 70
    MBMSNotifReq                    = 96
    MBMSNotifResp                   = 97
    MBMSNotifRejectReq              = 98
    MBMSNotifRejectResp             = 99
    CreateMBMSCtxtReq               = 100
    CreateMBMSCtxtResp              = 101
    UpdateMBMSCtxtReq               = 102
    UpdateMBMSCtxtResp              = 103
    DeleteMBMSCtxtReq               = 104
    DeleteMBMSCtxtResp              = 105
    MBMSRegistrationReq             = 112
    MBMSRegistrationResp            = 113
    MBMSDeRegistrationReq           = 114
    MBMSDeRegistrationResp          = 115
    MBMSSessionStartReq             = 116
    MBMSSessionStartResp            = 117
    MBMSSessionStopReq              = 118
    MBMSSessionStopResp             = 119
    MBMSSessionUpdateReq            = 120
    MBMSSessionUpdateResp           = 121
    MSInfoChangeNotifReq            = 128
    MSInfoChangeNotifResp           = 129
    DataRecordTransferReq           = 240
    DataRecordTransferResp          = 241
    EndMarker                       = 254
    GPDU                            = 255

GTPType_dict = {e.value: e.name for e in GTPType}


class GTPHdr(Envelope):
    _GEN = (
        Uint('Version', val=1, bl=3),               # 1 for GTP 29.060
        Uint('PT', val=1, bl=1, dic=ProtType_dict), # 1 for GTP 29.060
        Uint('spare', bl=1),
        Uint('E', bl=1),
        Uint('S', bl=1),
        Uint('PN', bl=1),
        Uint8('Type', val=GTPType.EchoReq.value, dic=GTPType_dict),
        Uint16('Len'),
        Uint32('TEID', rep=REPR_HEX),
        GTPHdrOpt(hier=1),      # optional
        GTPHdrExtList(hier=1)   # optional
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self._get_len())
        self['GTPHdrOpt'].set_transauto(lambda: False if (self[3]() or self[4]() or self[5]()) else True)
        self['GTPHdrExtList'].set_transauto(lambda: False if self[3]() else True)
    
    def _get_len(self):
        l = 0
        # get length of header optional and extended part
        if not self[9].get_trans():
            l +=4
        if self[10]._content:
            l += self[10].get_len()
        # get length of payload
        env = self.get_env()
        if env:
            for e in env._content[1:]:
                if not e.get_trans():
                    l += e.get_len()
        return l


#------------------------------------------------------------------------------#
# GTP Information Elements
# TS 29.060, section 7.7
#------------------------------------------------------------------------------#

GTPIEType_dict = {
    1   : ('TV', 1, 'Cause'),
    2   : ('TV', 8, 'International Mobile Subscriber Identity (IMSI)'),
    3   : ('TV', 6, 'Routeing Area Identity (RAI)'),
    4   : ('TV', 4, 'Temporary Logical Link Identity (TLLI)'),
    5   : ('TV', 4, 'Packet TMSI (P-TMSI)'),
    8   : ('TV', 1, 'Reordering Required'),
    9   : ('TV', 28, 'Authentication Triplet'),
    11  : ('TV', 1, 'MAP Cause'),
    12  : ('TV', 3, 'P-TMSI Signature'),
    13  : ('TV', 1, 'MS Validated'),
    14  : ('TV', 1, 'Recovery'),
    15  : ('TV', 1, 'Selection Mode'),
    16  : ('TV', 4, 'Tunnel Endpoint Identifier Data I'),
    17  : ('TV', 4, 'Tunnel Endpoint Identifier Control Plane'),
    18  : ('TV', 5, 'Tunnel Endpoint Identifier Data II'),
    19  : ('TV', 1, 'Teardown Ind'),
    20  : ('TV', 1, 'NSAPI'),
    21  : ('TV', 1, 'RANAP Cause'),
    22  : ('TV', 9, 'RAB Context'),
    23  : ('TV', 1, 'Radio Priority SMS'),
    24  : ('TV', 1, 'Radio Priority'),
    25  : ('TV', 2, 'Packet Flow Id'),
    26  : ('TV', 2, 'Charging Characteristics'),
    27  : ('TV', 2, 'Trace Reference'),
    28  : ('TV', 2, 'Trace Type'),
    29  : ('TV', 1, 'MS Not Reachable Reason'),
    127 : ('TV', 4, 'Charging ID'),
    128 : ('TLV', -1, 'End User Address'),
    129 : ('TLV', -1, 'MM Context'),
    130 : ('TLV', -1, 'PDP Context'),
    131 : ('TLV', -1, 'Access Point Name'),
    132 : ('TLV', -1, 'Protocol Configuration Options'),
    133 : ('TLV', -1, 'GSN Address'),
    134 : ('TLV', -1, 'MS International PSTN/ISDN Number (MSISDN)'),
    135 : ('TLV', -1, 'Quality of Service Profile'),
    136 : ('TLV', -1, 'Authentication Quintuplet'),
    137 : ('TLV', -1, 'Traffic Flow Template'),
    138 : ('TLV', -1, 'Target Identification'),
    139 : ('TLV', -1, 'UTRAN Transparent Container'),
    140 : ('TLV', -1, 'RAB Setup Information'),
    141 : ('TLV', -1, 'Extension Header Type List'),
    142 : ('TLV', -1, 'Trigger Id'),
    143 : ('TLV', -1, 'OMC Identity'),
    144 : ('TLV', -1, 'RAN Transparent Container'),
    145 : ('TLV', 0, 'PDP Context Prioritization'),
    146 : ('TLV', -1, 'Additional RAB Setup Information'),
    147 : ('TLV', -1, 'SGSN Number'),
    148 : ('TLV', 1, 'Common Flags'),
    149 : ('TLV', 1, 'APN Restriction'),
    150 : ('TLV', 1, 'Radio Priority LCS'),
    151 : ('TLV', 1, 'RAT Type'),
    152 : ('TLV', -1, 'User Location Information'),
    153 : ('TLV', 1, 'MS Time Zone'),
    154 : ('TLV', 8, 'IMEI(SV)'),
    155 : ('TLV', -1, 'CAMEL Charging Information Container'),
    156 : ('TLV', -1, 'MBMS UE Context'),
    157 : ('TLV', 6, 'Temporary Mobile Group Identity (TMGI)'),
    158 : ('TLV', -1, 'RIM Routing Address'),
    159 : ('TLV', -1, 'MBMS Protocol Configuration Options'),
    160 : ('TLV', -1, 'MBMS Service Area'),
    161 : ('TLV', -1, 'Source RNC PDCP context info'),
    162 : ('TLV', 9, 'Additional Trace Info'),
    163 : ('TLV', 1, 'Hop Counter'),
    164 : ('TLV', 3, 'Selected PLMN ID'),
    165 : ('TLV', 1, 'MBMS Session Identifier'),
    166 : ('TLV', 1, 'MBMS 2G/3G Indicator'),
    167 : ('TLV', 1, 'Enhanced NSAPI'),
    168 : ('TLV', 3, 'MBMS Session Duration'),
    169 : ('TLV', 8, 'Additional MBMS Trace Info'),
    170 : ('TLV', 1, 'MBMS Session Repetition Number'),
    171 : ('TLV', 1, 'MBMS Time To Data Transfer'),
    173 : ('TLV', -1, 'BSS Container'),
    174 : ('TLV', 17, 'Cell Identification'),
    175 : ('TLV', 9, 'PDU Numbers'),
    176 : ('TLV', 1, 'BSSGP Cause'),
    177 : ('TLV', -1, 'Required MBMS bearer capabilities'),
    178 : ('TLV', 1, 'RIM Routing Address Discriminator'),
    179 : ('TLV', -1, 'List of set-up PFCs'),
    180 : ('TLV', -1, 'PS Handover XID Parameters'),
    181 : ('TLV', 1, 'MS Info Change Reporting Action'),
    182 : ('TLV', -1, 'Direct Tunnel Flags'),
    183 : ('TLV', 1, 'Correlation-ID'),
    184 : ('TLV', 1, 'Bearer Control Mode'),
    185 : ('TLV', -1, 'MBMS Flow Identifier'),
    186 : ('TLV', -1, 'MBMS IP Multicast Distribution'),
    187 : ('TLV', 1, 'MBMS Distribution Acknowledgement'),
    188 : ('TLV', 1, 'Reliable INTER RAT HANDOVER INFO'),
    189 : ('TLV', 2, 'RFSP Index'),
    190 : ('TLV', -1, 'Fully Qualified Domain Name (FQDN)'),
    191 : ('TLV', 1, 'Evolved Allocation/Retention Priority I'),
    192 : ('TLV', 2, 'Evolved Allocation/Retention Priority II'),
    193 : ('TLV', -1, 'Extended Common Flags'),
    194 : ('TLV', 8, 'User CSG Information (UCI)'),
    195 : ('TLV', -1, 'CSG Information Reporting Action'),
    196 : ('TLV', 4, 'CSG ID'),
    197 : ('TLV', 1, 'CSG Membership Indication (CMI)'),
    198 : ('TLV', 8, 'Aggregate Maximum Bit Rate (AMBR)'),
    199 : ('TLV', -1, 'UE Network Capability'),
    200 : ('TLV', -1, 'UE-AMBR'),
    201 : ('TLV', 9, 'APN-AMBR with NSAPI'),
    202 : ('TLV', -1, 'GGSN Back-Off Time'),
    203 : ('TLV', -1, 'Signalling Priority Indication'),
    204 : ('TLV', -1, 'Signalling Priority Indication with NSAPI'),
    205 : ('TLV', 1, 'Higher bitrates than 16 Mbps flag'),
    207 : ('TLV', -1, 'Additional MM context for SRVCC'),
    208 : ('TLV', -1, 'Additional flags for SRVCC'),
    209 : ('TLV', -1, 'STN-SR'),
    210 : ('TLV', -1, 'C-MSISDN'),
    211 : ('TLV', -1, 'Extended RANAP Cause'),
    212 : ('TLV', -1, 'eNodeB ID'),
    213 : ('TLV', 2, 'Selection Mode with NSAPI'),
    214 : ('TLV', -1, 'ULI Timestamp'),
    215 : ('TLV', -1, 'Local Home Network ID (LHN-ID) with NSAPI'),
    216 : ('TLV', -1, 'CN Operator Selection Entity'),
    217 : ('TLV', -1, 'UE Usage Type'),
    218 : ('TLV', -1, 'Extended Common Flags II'),
    219 : ('TLV', -1, 'Node Identifier'),
    220 : ('TLV', -1, 'CIoT Optimizations Support Indication'),
    221 : ('TLV', -1, 'SCEF PDN Connection'),
    222 : ('TLV', 1, 'IOV_updates counter'),
    223 : ('TLV', -1, 'Mapped UE Usage Type'),
    224 : ('TLV', -1, 'UP Function Selection Indication Flags'),
    238 : ('TLV', -1, 'Special IE type for IE Type Extension'),
    251 : ('TLV', -1, 'Charging Gateway Address'),
    255 : ('TLV', -1, 'Private Extension'),
    }

GTPIETagDesc_dict = {k: v[2] for k, v in GTPIEType_dict.items()} 


class GTPIETV(Envelope):
    """GTPv1-C Information Element in Tag-Value format, with fixed length
    """
    
    _GEN = (
        Uint8('Type', val=1, dic=GTPIETagDesc_dict),
        Buf('Data', bl=8, rep=REPR_HEX)
        )


class GTPIETLV(Envelope):
    """GTPv1-C Information Element in Tag-Length-Value format
    """
    
    _GEN = (
        Uint8('Type', val=128, dic=GTPIETagDesc_dict),
        Uint16('Len'),
        Uint16('TypeExt'), # present if Type == 238
        Buf('Data', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self._set_len())
        self[2].set_transauto(lambda: self[0].get_val() != 238)
        self[3].set_blauto(lambda: self._set_dat_len())
    
    def _set_len(self):
        if self[0].get_val() == 238:
            # extended type
            return 2 + self[3].get_len()
        else:
            return self[3].get_len()
    
    def _set_dat_len(self):
        if self[0].get_val() == 238:
            # extended type
            return (self[0][1].get_val()-2) << 3
        else:
            return self[0][1].get_val() << 3



