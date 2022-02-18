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

from pycrate_core.utils     import *
from pycrate_core.elt       import *
from pycrate_core.base      import *
from pycrate_core.utils     import PycrateErr
from pycrate_core.charpy    import CharpyErr


#------------------------------------------------------------------------------#
# 3GPP TS 29.060: GPRS Tunnelling Protocol (GTP) across the Gn and Gp interface
# release 16 (h10)
# i.e. SGSN - GGSN interface
#------------------------------------------------------------------------------#

class GTPDecErr(PycrateErr):
    pass


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
        if self.get_trans():
            return
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
    ErrorInd                        = 26
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
    
    ENV_SEL_TRANS = False
    
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
        GTPHdrOpt(),      # optional
        GTPHdrExtList()   # optional
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
    0   : ('TV', -1, 'Reserved', 'Reserved'),
    1   : ('TV', 1, 'Cause', 'Cause'),
    2   : ('TV', 8, 'International Mobile Subscriber Identity (IMSI)', 'IMSI'),
    3   : ('TV', 6, 'Routeing Area Identity (RAI)', 'RAI'),
    4   : ('TV', 4, 'Temporary Logical Link Identity (TLLI)', 'TLLI'),
    5   : ('TV', 4, 'Packet TMSI (P-TMSI)', 'PTMSI'),
    8   : ('TV', 1, 'Reordering Required', 'ReorderingRequired'),
    9   : ('TV', 28, 'Authentication Triplet', 'AuthentTriplet'),
    11  : ('TV', 1, 'MAP Cause', 'MAPCause'),
    12  : ('TV', 3, 'P-TMSI Signature', 'PTMSISignature'),
    13  : ('TV', 1, 'MS Validated', 'MSValidated'),
    14  : ('TV', 1, 'Recovery', 'Recovery'),
    15  : ('TV', 1, 'Selection Mode', 'SelectionMode'),
    16  : ('TV', 4, 'Tunnel Endpoint Identifier Data I', 'TEIDDataI'),
    17  : ('TV', 4, 'Tunnel Endpoint Identifier Control Plane', 'TEIDCP'),
    18  : ('TV', 5, 'Tunnel Endpoint Identifier Data II', 'TEIDDataII'),
    19  : ('TV', 1, 'Teardown Ind', 'TeardownInd'),
    20  : ('TV', 1, 'NSAPI', 'NSAPI'),
    21  : ('TV', 1, 'RANAP Cause', 'RANAPCause'),
    22  : ('TV', 9, 'RAB Context', 'RABContext'),
    23  : ('TV', 1, 'Radio Priority SMS', 'RadioPrioritySMS'),
    24  : ('TV', 1, 'Radio Priority', 'RadioPriority'),
    25  : ('TV', 2, 'Packet Flow Id', 'PacketFlowId'),
    26  : ('TV', 2, 'Charging Characteristics', 'ChargingCharacteristics'),
    27  : ('TV', 2, 'Trace Reference', 'TraceReference'),
    28  : ('TV', 2, 'Trace Type', 'TraceType'),
    29  : ('TV', 1, 'MS Not Reachable Reason', 'MSNotReachableReason'),
    127 : ('TV', 4, 'Charging ID', 'ChargingID'),
    128 : ('TLV', -1, 'End User Address', 'EndUserAddr'),
    129 : ('TLV', -1, 'MM Context', 'MMContext'),
    130 : ('TLV', -1, 'PDP Context', 'PDPContext'),
    131 : ('TLV', -1, 'Access Point Name', 'APN'),
    132 : ('TLV', -1, 'Protocol Configuration Options', 'PCO'),
    133 : ('TLV', -1, 'GSN Address', 'GSNAddr'),
    134 : ('TLV', -1, 'MS International PSTN/ISDN Number (MSISDN)', 'MSISDN'),
    135 : ('TLV', -1, 'Quality of Service Profile', 'QoSProfile'),
    136 : ('TLV', -1, 'Authentication Quintuplet', 'AuthentQuintuplet'),
    137 : ('TLV', -1, 'Traffic Flow Template', 'TFT'),
    138 : ('TLV', -1, 'Target Identification', 'TargetIdent'),
    139 : ('TLV', -1, 'UTRAN Transparent Container', 'UTRANTransparentContainer'),
    140 : ('TLV', -1, 'RAB Setup Information', 'RABSetupInfo'),
    141 : ('TLV', -1, 'Extension Header Type List', 'ExtHeaderTypeList'),
    142 : ('TLV', -1, 'Trigger Id', 'TriggerId'),
    143 : ('TLV', -1, 'OMC Identity', 'OMCIdentity'),
    144 : ('TLV', -1, 'RAN Transparent Container', 'RANTransparentContainer'),
    145 : ('TLV', 0, 'PDP Context Prioritization', 'PDPContextPrioritization'),
    146 : ('TLV', -1, 'Additional RAB Setup Information', 'AdditionalRABSetupInfo'),
    147 : ('TLV', -1, 'SGSN Number', 'SGSNNumber'),
    148 : ('TLV', 1, 'Common Flags', 'CommonFlags'),
    149 : ('TLV', 1, 'APN Restriction', 'APNRestriction'),
    150 : ('TLV', 1, 'Radio Priority LCS', 'RadioPriorityLCS'),
    151 : ('TLV', 1, 'RAT Type', 'RATType'),
    152 : ('TLV', -1, 'User Location Information', 'UserLocationInfo'),
    153 : ('TLV', 1, 'MS Time Zone', 'MSTimeZone'),
    154 : ('TLV', 8, 'IMEI(SV)', 'IMEI'),
    155 : ('TLV', -1, 'CAMEL Charging Information Container', 'CAMELChargingInfoContainer'),
    156 : ('TLV', -1, 'MBMS UE Context', 'MBMSUEContext'),
    157 : ('TLV', 6, 'Temporary Mobile Group Identity (TMGI)', 'TMGI'),
    158 : ('TLV', -1, 'RIM Routing Address', 'RIMRoutingAddr'),
    159 : ('TLV', -1, 'MBMS Protocol Configuration Options', 'MBMSPCO'),
    160 : ('TLV', -1, 'MBMS Service Area', 'MBMSServiceArea'),
    161 : ('TLV', -1, 'Source RNC PDCP context info', 'SourceRNCPDCPContextInfo'),
    162 : ('TLV', 9, 'Additional Trace Info', 'AdditionalTraceInfo'),
    163 : ('TLV', 1, 'Hop Counter', 'HopCounter'),
    164 : ('TLV', 3, 'Selected PLMN ID', 'SelectedPLMNID'),
    165 : ('TLV', 1, 'MBMS Session Identifier', 'MBMSSessionIdent'),
    166 : ('TLV', 1, 'MBMS 2G/3G Indicator', 'MBMS2G3GIndicator'),
    167 : ('TLV', 1, 'Enhanced NSAPI', 'EnhancedNSAPI'),
    168 : ('TLV', 3, 'MBMS Session Duration', 'MBMSSessionDuration'),
    169 : ('TLV', 8, 'Additional MBMS Trace Info', 'AdditionalMBMSTraceInfo'),
    170 : ('TLV', 1, 'MBMS Session Repetition Number', 'MBMSSessionRepetitionNumber'),
    171 : ('TLV', 1, 'MBMS Time To Data Transfer', 'MBMSTimeToDataTransfer'),
    173 : ('TLV', -1, 'BSS Container', 'BSSContainer'),
    174 : ('TLV', 17, 'Cell Identification', 'CellIdent'),
    175 : ('TLV', 9, 'PDU Numbers', 'PDUNumbers'),
    176 : ('TLV', 1, 'BSSGP Cause', 'BSSGPCause'),
    177 : ('TLV', -1, 'Required MBMS bearer capabilities', 'RequiredMBMSBearerCap'),
    178 : ('TLV', 1, 'RIM Routing Address Discriminator', 'RIMRoutingAddrDiscriminator'),
    179 : ('TLV', -1, 'List of set-up PFCs', 'ListOfSetupPFCs'),
    180 : ('TLV', -1, 'PS Handover XID Parameters', 'PSHandoverXIDParameters'),
    181 : ('TLV', 1, 'MS Info Change Reporting Action', 'MSInfoChangeReportingAction'),
    182 : ('TLV', -1, 'Direct Tunnel Flags', 'DirectTunnelFlags'),
    183 : ('TLV', 1, 'Correlation-ID', 'CorrelationID'),
    184 : ('TLV', 1, 'Bearer Control Mode', 'BearerControlMode'),
    185 : ('TLV', -1, 'MBMS Flow Identifier', 'MBMSFlowIdent'),
    186 : ('TLV', -1, 'MBMS IP Multicast Distribution', 'MBMSIPMulticastDistribution'),
    187 : ('TLV', 1, 'MBMS Distribution Acknowledgement', 'MBMSDistributionAck'),
    188 : ('TLV', 1, 'Reliable INTER RAT HANDOVER INFO', 'ReliableInterRATHandoverInfo'),
    189 : ('TLV', 2, 'RFSP Index', 'RFSPIndex'),
    190 : ('TLV', -1, 'Fully Qualified Domain Name (FQDN)', 'FQDN'),
    191 : ('TLV', 1, 'Evolved Allocation/Retention Priority I', 'EvolvedAllocationRetentionPriorityI'),
    192 : ('TLV', 2, 'Evolved Allocation/Retention Priority II', 'EvolvedAllocationRetentionPriorityII'),
    193 : ('TLV', -1, 'Extended Common Flags', 'ExtCommonFlags'),
    194 : ('TLV', 8, 'User CSG Information (UCI)', 'UCI'),
    195 : ('TLV', -1, 'CSG Information Reporting Action', 'CSGInfoReportingAction'),
    196 : ('TLV', 4, 'CSG ID', 'CSGID'),
    197 : ('TLV', 1, 'CSG Membership Indication (CMI)', 'CMI'),
    198 : ('TLV', 8, 'Aggregate Maximum Bit Rate (AMBR)', 'AMBR'),
    199 : ('TLV', -1, 'UE Network Capability', 'UENetworkCap'),
    200 : ('TLV', -1, 'UE-AMBR', 'UEAMBR'),
    201 : ('TLV', 9, 'APN-AMBR with NSAPI', 'APNAMBRWithNSAPI'),
    202 : ('TLV', -1, 'GGSN Back-Off Time', 'GGSNBackOffTime'),
    203 : ('TLV', -1, 'Signalling Priority Indication', 'SignallingPriorityInd'),
    204 : ('TLV', -1, 'Signalling Priority Indication with NSAPI', 'SignallingPriorityIndWithNSAPI'),
    205 : ('TLV', 1, 'Higher bitrates than 16 Mbps flag', 'HigherBitratesThan16MbpsFlag'),
    207 : ('TLV', -1, 'Additional MM context for SRVCC', 'AdditionalMMContextForSRVCC'),
    208 : ('TLV', -1, 'Additional flags for SRVCC', 'AdditionalFlagsForSRVCC'),
    209 : ('TLV', -1, 'STN-SR', 'STNSR'),
    210 : ('TLV', -1, 'C-MSISDN', 'CMSISDN'),
    211 : ('TLV', -1, 'Extended RANAP Cause', 'ExtRANAPCause'),
    212 : ('TLV', -1, 'eNodeB ID', 'ENodeBID'),
    213 : ('TLV', 2, 'Selection Mode with NSAPI', 'SelectionModeWithNSAPI'),
    214 : ('TLV', -1, 'ULI Timestamp', 'ULITimestamp'),
    215 : ('TLV', -1, 'Local Home Network ID (LHN-ID) with NSAPI', 'LocalHomeNetworkIDWithNSAPI'),
    216 : ('TLV', -1, 'CN Operator Selection Entity', 'CNOperatorSelectionEntity'),
    217 : ('TLV', -1, 'UE Usage Type', 'UEUsageType'),
    218 : ('TLV', -1, 'Extended Common Flags II', 'ExtCommonFlagsII'),
    219 : ('TLV', -1, 'Node Identifier', 'NodeIdent'),
    220 : ('TLV', -1, 'CIoT Optimizations Support Indication', 'CIoTOptimizationsSupportInd'),
    221 : ('TLV', -1, 'SCEF PDN Connection', 'SCEFPDNConnection'),
    222 : ('TLV', 1, 'IOV_updates counter', 'IOVUpdatesCounter'),
    223 : ('TLV', -1, 'Mapped UE Usage Type', 'MappedUEUsageType'),
    224 : ('TLV', -1, 'UP Function Selection Indication Flags', 'UPFSelectionIndFlags'),
    238 : ('TLV', -1, 'Special IE type for IE Type Extension', 'IETypeExt'),
    251 : ('TLV', -1, 'Charging Gateway Address', 'ChargingGatewayAddr'),
    255 : ('TLV', -1, 'Private Extension', 'PrivateExt')
    }

GTPIEType = IntEnum('GTPIEType', {v[3]: k for k, v in GTPIEType_dict.items()})
GTPIETypeDesc_dict = {k: v[2] for k, v in GTPIEType_dict.items()} 


class _GTPIE(Envelope):
    """parent class for all GTPv1-C Information Element
    """
    
    '''
    def set_val(self, val):
        if self._trans:
            self._trans = False
        Envelope.set_val(self, val)
    '''

class GTPIETV(_GTPIE):
    """GTPv1-C Information Element in Tag-Value format, with fixed length
    """
    
    _GEN = (
        Uint8('Type', val=1, dic=GTPIETypeDesc_dict),
        Buf('Data', bl=8, rep=REPR_HEX)
        )
    
    def get_type(self):
        return self[0].get_val()


class GTPIETLV(_GTPIE):
    """GTPv1-C Information Element in Tag-Length-Value format
    """
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint8('Type', val=128, dic=GTPIETypeDesc_dict),
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
            return (self[1].get_val()-2) << 3
        else:
            return self[1].get_val() << 3
    
    def get_type(self):
        typ = self[0].get_val()
        if typ == 238:
            return self[2].get_val()
        else:
            return typ


def _get_type_from_char(char):
    typ = char.to_uint(8)
    if typ == 238:
        char._cur += 24
        typ = char.to_uint(16)
        char._cur -= 24
    return typ


class GTPIEs(Envelope):
    """GTPv1-C sequence of Information Elements
    """
    
    _GEN = ()
    
    # this is to not show transparent (optional / conditional) IEs when they are not set
    ENV_SEL_TRANS = False
    
    # this is to raise in case a mandatory IE is not found during the decoding
    VERIF_MAND = True
    
    def _from_char(self, char):
        if self.get_trans():
            return
        #
        # go over all defined IE in the content 1 by 1
        # checking against the type decoded
        # and jumping over optional / conditional IE not present
        i, len_cont = 0, len(self._content)
        while char.len_byte() >= 1 and i < len_cont:
            ie = self._content[i]
            try:
                typ = _get_type_from_char(char)
            except CharpyErr:
                break
            else:
                if ie.get_type() == typ:
                    if ie._trans:
                        ie._trans = False
                    ie._from_char(char)
                elif not ie._trans and self.VERIF_MAND:
                    # mandatory IE
                    raise(GTPDecErr('Missing mandatory GTP IE type %i' % ie.get_type()))
                i += 1
        #
        if i < len_cont-1 and self.VERIF_MAND:
            # verify if some trailing mandatory IE have been ignored
            for ie in self._content[i:]:
                if not ie._trans:
                    raise(GTPDecErr('Missing mandatory GTP IE type %i' % ie.get_type()))
        #
        # additional decoding for more undefined GTPIETLV 
        while char.len_bit() >= 24:
            ie = GTPIETLV()
            try:
                ie._from_char(char)
            except CharpyErr:
                # end of the parsing
                break
            else:
                self.append(ie)


#------------------------------------------------------------------------------#
# GTP Message
# TS 29.060, section 7
#------------------------------------------------------------------------------#

class GTPMsg(Envelope):
    """parent class for all GTPv1-C messages
    """
    
    _GEN = (
        GTPHdr(),
        GTPIEs(hier=1)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_blauto(lambda: self._get_ies_len())
    
    def _get_ies_len(self):
        l = self[0]['Len'].get_val()
        if not self[0]['GTPHdrOpt'].get_trans():
            l -=4
        if self[0]['GTPHdrExtList']._content:
            l -= self[0]['GTPHdrExtList'].get_len()
        if l < 0:
            return 0
        else:
            return l << 3


#------------------------------------------------------------------------------#
# 7.2 Path Management Messages
#------------------------------------------------------------------------------#

# Echo Request

class EchoReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.EchoReq.value}),
        GTPIEs(GEN=(
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Echo Response

class EchoResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.EchoResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Version Not Supported

class VersionNotSupported(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.VersionNotSupported.value}),
        )


# Supported Extension Headers Notification

class SupportedExtHeadersNotif(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.SupportedExtHeadersNotif.value}),
        GTPIEs(GEN=(
            GTPIETLV('ExtHeaderTypeList', val={'Type': GTPIEType.ExtHeaderTypeList.value}),
            ), hier=1)
        )


#------------------------------------------------------------------------------#
# 7.3 Tunnel Management Messages
#------------------------------------------------------------------------------#
# interface between SGSN and GGSN

# Create PDP Context Request

class CreatePDPCtxtReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.CreatePDPCtxtReq.value}),
        GTPIEs(GEN=(
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
            GTPIETV('RAI', val={'Type': GTPIEType.RAI.value}, bl={'Data': 48}, trans=True),
            GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
            GTPIETV('SelectionMode', val={'Type': GTPIEType.SelectionMode.value}, bl={'Data': 8}, trans=True),
            GTPIETV('TEIDDataI', val={'Type': GTPIEType.TEIDDataI.value}, bl={'Data': 32}),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETV('NSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}),
            GTPIETV('LinkedNSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}, trans=True),
            GTPIETV('ChargingCharacteristics', val={'Type': GTPIEType.ChargingCharacteristics.value}, bl={'Data': 16}, trans=True),
            GTPIETV('TraceReference', val={'Type': GTPIEType.TraceReference.value}, bl={'Data': 16}, trans=True),
            GTPIETV('TraceType', val={'Type': GTPIEType.TraceType.value}, bl={'Data': 16}, trans=True),
            GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}, trans=True),
            GTPIETLV('APN', val={'Type': GTPIEType.APN.value}, trans=True),
            GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
            GTPIETLV('SGSNAddrForSignalling', val={'Type': GTPIEType.GSNAddr.value}),
            GTPIETLV('SGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}),
            GTPIETLV('MSISDN', val={'Type': GTPIEType.MSISDN.value}, trans=True),
            GTPIETLV('QoSProfile', val={'Type': GTPIEType.QoSProfile.value}),
            GTPIETLV('TFT', val={'Type': GTPIEType.TFT.value}, trans=True),
            GTPIETLV('TriggerId', val={'Type': GTPIEType.TriggerId.value}, trans=True),
            GTPIETLV('OMCIdentity', val={'Type': GTPIEType.OMCIdentity.value}, trans=True),
            GTPIETLV('CommonFlags', val={'Type': GTPIEType.CommonFlags.value}, trans=True),
            GTPIETLV('APNRestriction', val={'Type': GTPIEType.APNRestriction.value}, trans=True),
            GTPIETLV('RATType', val={'Type': GTPIEType.RATType.value}, trans=True),
            GTPIETLV('UserLocationInfo', val={'Type': GTPIEType.UserLocationInfo.value}, trans=True),
            GTPIETLV('MSTimeZone', val={'Type': GTPIEType.MSTimeZone.value}, trans=True),
            GTPIETLV('IMEI', val={'Type': GTPIEType.IMEI.value}, trans=True),
            GTPIETLV('CAMELChargingInfoContainer', val={'Type': GTPIEType.CAMELChargingInfoContainer.value}, trans=True),
            GTPIETLV('AdditionalTraceInfo', val={'Type': GTPIEType.AdditionalTraceInfo.value}, trans=True),
            GTPIETLV('CorrelationID', val={'Type': GTPIEType.CorrelationID.value}, trans=True),
            GTPIETLV('EvolvedAllocationRetentionPriorityI', val={'Type': GTPIEType.EvolvedAllocationRetentionPriorityI.value}, trans=True),
            GTPIETLV('ExtCommonFlags', val={'Type': GTPIEType.ExtCommonFlags.value}, trans=True),
            GTPIETLV('UCI', val={'Type': GTPIEType.UCI.value}, trans=True),
            GTPIETLV('APNAMBR', val={'Type': GTPIEType.AMBR.value}, trans=True),
            GTPIETLV('SignallingPriorityInd', val={'Type': GTPIEType.SignallingPriorityInd.value}, trans=True),
            GTPIETLV('CNOperatorSelectionEntity', val={'Type': GTPIEType.CNOperatorSelectionEntity.value}, trans=True),
            GTPIETLV('MappedUEUsageType', val={'Type': GTPIEType.MappedUEUsageType.value}, trans=True),
            GTPIETLV('UPFSelectionIndFlags', val={'Type': GTPIEType.UPFSelectionIndFlags.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Create PDP Context Response

class CreatePDPCtxtResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.CreatePDPCtxtResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('ReorderingRequired', val={'Type': GTPIEType.ReorderingRequired.value}, bl={'Data': 8}, trans=True),
            GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
            GTPIETV('TEIDDataI', val={'Type': GTPIEType.TEIDDataI.value}, bl={'Data': 32}, trans=True),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETV('NSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}, trans=True),
            GTPIETV('ChargingID', val={'Type': GTPIEType.ChargingID.value}, bl={'Data': 32}, trans=True),
            GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}, trans=True),
            GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
            GTPIETLV('GGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('GGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('AltGGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('AltGGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('QoSProfile', val={'Type': GTPIEType.QoSProfile.value}, trans=True),
            GTPIETLV('ChargingGatewayAddr', val={'Type': GTPIEType.ChargingGatewayAddr.value}, trans=True),
            GTPIETLV('AltChargingGatewayAddr', val={'Type': GTPIEType.ChargingGatewayAddr.value}, trans=True),
            GTPIETLV('CommonFlags', val={'Type': GTPIEType.CommonFlags.value}, trans=True),
            GTPIETLV('APNRestriction', val={'Type': GTPIEType.APNRestriction.value}, trans=True),
            GTPIETLV('MSInfoChangeReportingAction', val={'Type': GTPIEType.MSInfoChangeReportingAction.value}, trans=True),
            GTPIETLV('BearerControlMode', val={'Type': GTPIEType.BearerControlMode.value}, trans=True),
            GTPIETLV('EvolvedAllocationRetentionPriorityI', val={'Type': GTPIEType.EvolvedAllocationRetentionPriorityI.value}, trans=True),
            GTPIETLV('ExtCommonFlags', val={'Type': GTPIEType.ExtCommonFlags.value}, trans=True),
            GTPIETLV('CSGInfoReportingAction', val={'Type': GTPIEType.CSGInfoReportingAction.value}, trans=True),
            GTPIETLV('APNAMBR', val={'Type': GTPIEType.AMBR.value}, trans=True),
            GTPIETLV('GGSNBackOffTime', val={'Type': GTPIEType.GGSNBackOffTime.value}, trans=True),
            GTPIETLV('ExtCommonFlagsII', val={'Type': GTPIEType.ExtCommonFlagsII.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# SGSN-Initiated Update PDP Context Request

class UpdatePDPCtxtReqSGSN(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.UpdatePDPCtxtReq.value}),
        GTPIEs(GEN=(
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
            GTPIETV('RAI', val={'Type': GTPIEType.RAI.value}, bl={'Data': 48}, trans=True),
            GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
            GTPIETV('TEIDDataI', val={'Type': GTPIEType.TEIDDataI.value}, bl={'Data': 32}),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETV('NSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}),
            GTPIETV('TraceReference', val={'Type': GTPIEType.TraceReference.value}, bl={'Data': 16}, trans=True),
            GTPIETV('TraceType', val={'Type': GTPIEType.TraceType.value}, bl={'Data': 16}, trans=True),
            GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
            GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}),
            GTPIETLV('SGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}),
            GTPIETLV('AltSGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('AltSGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('QoSProfile', val={'Type': GTPIEType.QoSProfile.value}),
            GTPIETLV('TFT', val={'Type': GTPIEType.TFT.value}, trans=True),
            GTPIETLV('TriggerId', val={'Type': GTPIEType.TriggerId.value}, trans=True),
            GTPIETLV('OMCIdentity', val={'Type': GTPIEType.OMCIdentity.value}, trans=True),
            GTPIETLV('CommonFlags', val={'Type': GTPIEType.CommonFlags.value}, trans=True),
            GTPIETLV('RATType', val={'Type': GTPIEType.RATType.value}, trans=True),
            GTPIETLV('UserLocationInfo', val={'Type': GTPIEType.UserLocationInfo.value}, trans=True),
            GTPIETLV('MSTimeZone', val={'Type': GTPIEType.MSTimeZone.value}, trans=True),
            GTPIETLV('AdditionalTraceInfo', val={'Type': GTPIEType.AdditionalTraceInfo.value}, trans=True),
            GTPIETLV('DirectTunnelFlags', val={'Type': GTPIEType.DirectTunnelFlags.value}, trans=True),
            GTPIETLV('EvolvedAllocationRetentionPriorityI', val={'Type': GTPIEType.EvolvedAllocationRetentionPriorityI.value}, trans=True),
            GTPIETLV('ExtCommonFlags', val={'Type': GTPIEType.ExtCommonFlags.value}, trans=True),
            GTPIETLV('UCI', val={'Type': GTPIEType.UCI.value}, trans=True),
            GTPIETLV('APNAMBR', val={'Type': GTPIEType.AMBR.value}, trans=True),
            GTPIETLV('SignallingPriorityInd', val={'Type': GTPIEType.SignallingPriorityInd.value}, trans=True),
            GTPIETLV('CNOperatorSelectionEntity', val={'Type': GTPIEType.CNOperatorSelectionEntity.value}, trans=True),
            GTPIETLV('IMEI', val={'Type': GTPIEType.IMEI.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# GGSN-Initiated Update PDP Context Request

class UpdatePDPCtxtReqGGSN(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.UpdatePDPCtxtReq.value}),
        GTPIEs(GEN=(
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
            GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
            GTPIETV('NSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}),
            GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}, trans=True),
            GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
            GTPIETLV('QoSProfile', val={'Type': GTPIEType.QoSProfile.value}, trans=True),
            GTPIETLV('TFT', val={'Type': GTPIEType.TFT.value}, trans=True),
            GTPIETLV('CommonFlags', val={'Type': GTPIEType.CommonFlags.value}, trans=True),
            GTPIETLV('APNRestriction', val={'Type': GTPIEType.APNRestriction.value}, trans=True),
            GTPIETLV('MSInfoChangeReportingAction', val={'Type': GTPIEType.MSInfoChangeReportingAction.value}, trans=True),
            GTPIETLV('DirectTunnelFlags', val={'Type': GTPIEType.DirectTunnelFlags.value}, trans=True),
            GTPIETLV('BearerControlMode', val={'Type': GTPIEType.BearerControlMode.value}, trans=True),
            GTPIETLV('EvolvedAllocationRetentionPriorityI', val={'Type': GTPIEType.EvolvedAllocationRetentionPriorityI.value}, trans=True),
            GTPIETLV('ExtCommonFlags', val={'Type': GTPIEType.ExtCommonFlags.value}, trans=True),
            GTPIETLV('CSGInfoReportingAction', val={'Type': GTPIEType.CSGInfoReportingAction.value}, trans=True),
            GTPIETLV('APNAMBR', val={'Type': GTPIEType.AMBR.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Update PDP Context Response sent by a GGSN

class UpdatePDPCtxtRespGGSN(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.UpdatePDPCtxtResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
            GTPIETV('TEIDDataI', val={'Type': GTPIEType.TEIDDataI.value}, bl={'Data': 32}, trans=True),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETV('ChargingID', val={'Type': GTPIEType.ChargingID.value}, bl={'Data': 32}, trans=True),
            GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
            GTPIETLV('GGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('GGSNAddressForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('AltGGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('AltGGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('QoSProfile', val={'Type': GTPIEType.QoSProfile.value}, trans=True),
            GTPIETLV('ChargingGatewayAddr', val={'Type': GTPIEType.ChargingGatewayAddr.value}, trans=True),
            GTPIETLV('AltChargingGatewayAddr', val={'Type': GTPIEType.ChargingGatewayAddr.value}, trans=True),
            GTPIETLV('CommonFlags', val={'Type': GTPIEType.CommonFlags.value}, trans=True),
            GTPIETLV('APNRestriction', val={'Type': GTPIEType.APNRestriction.value}, trans=True),
            GTPIETLV('BearerControlMode', val={'Type': GTPIEType.BearerControlMode.value}, trans=True),
            GTPIETLV('MSInfoChangeReportingAction', val={'Type': GTPIEType.MSInfoChangeReportingAction.value}, trans=True),
            GTPIETLV('EvolvedAllocationRetentionPriorityI', val={'Type': GTPIEType.EvolvedAllocationRetentionPriorityI.value}, trans=True),
            GTPIETLV('CSGInfoReportingAction', val={'Type': GTPIEType.CSGInfoReportingAction.value}, trans=True),
            GTPIETLV('APNAMBR', val={'Type': GTPIEType.AMBR.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Update PDP Context Response sent by a SGSN

class UpdatePDPCtxtRespSGSN(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.UpdatePDPCtxtResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
            GTPIETV('TEIDDataI', val={'Type': GTPIEType.TEIDDataI.value}, bl={'Data': 32}, trans=True),
            GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
            GTPIETLV('SGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('QoSProfile', val={'Type': GTPIEType.QoSProfile.value}, trans=True),
            GTPIETLV('UserLocationInfo', val={'Type': GTPIEType.UserLocationInfo.value}, trans=True),
            GTPIETLV('MSTimeZone', val={'Type': GTPIEType.MSTimeZone.value}, trans=True),
            GTPIETLV('DirectTunnelFlags', val={'Type': GTPIEType.DirectTunnelFlags.value}, trans=True),
            GTPIETLV('EvolvedAllocationRetentionPriorityI', val={'Type': GTPIEType.EvolvedAllocationRetentionPriorityI.value}, trans=True),
            GTPIETLV('APNAMBR', val={'Type': GTPIEType.AMBR.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Delete PDP Context Request

class DeletePDPCtxtReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.DeletePDPCtxtReq.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}, trans=True),
            GTPIETV('TeardownInd', val={'Type': GTPIEType.TeardownInd.value}, bl={'Data': 8}, trans=True),
            GTPIETV('NSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}),
            GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
            GTPIETLV('UserLocationInfo', val={'Type': GTPIEType.UserLocationInfo.value}, trans=True),
            GTPIETLV('MSTimeZone', val={'Type': GTPIEType.MSTimeZone.value}, trans=True),
            GTPIETLV('ExtCommonFlags', val={'Type': GTPIEType.ExtCommonFlags.value}, trans=True),
            GTPIETLV('ULITimestamp', val={'Type': GTPIEType.ULITimestamp.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Delete PDP Context Response

class DeletePDPCtxtResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.DeletePDPCtxtResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
            GTPIETLV('UserLocationInfo', val={'Type': GTPIEType.UserLocationInfo.value}, trans=True),
            GTPIETLV('MSTimeZone', val={'Type': GTPIEType.MSTimeZone.value}, trans=True),
            GTPIETLV('ULITimestamp', val={'Type': GTPIEType.ULITimestamp.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Error Indication

class ErrorInd(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.ErrorInd.value}),
        GTPIEs(GEN=(
            GTPIETV('TEIDDataI', val={'Type': GTPIEType.TEIDDataI.value}, bl={'Data': 32}),
            GTPIETLV('GTPUPeerAddr', val={'Type': GTPIEType.GSNAddr.value}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1),
        )


# PDU Notification Request

class PDUNotifReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.PDUNotifReq.value}),
        GTPIEs(GEN=(
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}),
            GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
            GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
            GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
            GTPIETLV('GGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# PDU Notification Response

class PDUNotifResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.PDUNotifResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# PDU Notification Reject Request

class PDUNotifRejectReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.PDUNotifRejectReq.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}),
            GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
            GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
            GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# PDU Notification Reject Response

class PDUNotifRejectResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.PDUNotifRejectResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Initiate PDP Context Activation Request

class InitiatePDPCtxtActivationReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.InitiatePDPCtxtActivationReq.value}),
        GTPIEs(GEN=(
            GTPIETV('LinkedNSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}),
            GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
            GTPIETLV('QoSProfile', val={'Type': GTPIEType.QoSProfile.value}),
            GTPIETLV('TFT', val={'Type': GTPIEType.TFT.value}, trans=True),
            GTPIETLV('CorrelationID', val={'Type': GTPIEType.CorrelationID.value}),
            GTPIETLV('EvolvedAllocationRetentionPriorityI', val={'Type': GTPIEType.EvolvedAllocationRetentionPriorityI.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Initiate PDP Context Activation Response

class InitiatePDPCtxtActivationResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.InitiatePDPCtxtActivationResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


#------------------------------------------------------------------------------#
# 7.4 Location Management Messages
#------------------------------------------------------------------------------#
# optional interface between HLR and GGSN within a PLMN
# Eventually supported through GTP / TCAP-MAP interworking

# Send Routeing Information for GPRS Request

class SendRouteingInfoforGPRSReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.SendRouteingInfoforGPRSReq.value}),
        GTPIEs(GEN=(
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Send Routeing Information for GPRS Response

class SendRouteingInfoforGPRSResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.SendRouteingInfoforGPRSResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}),
            GTPIETV('MAPCause', val={'Type': GTPIEType.MAPCause.value}, bl={'Data': 8}, trans=True),
            GTPIETV('MSNotReachableReason', val={'Type': GTPIEType.MSNotReachableReason.value}, bl={'Data': 8}, trans=True),
            GTPIETLV('GSNAddr', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Failure Report Request

class FailureReportReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.FailureReportReq.value}),
        GTPIEs(GEN=(
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Failure Report Response

class FailureReportResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.FailureReportResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('MAPCause', val={'Type': GTPIEType.MAPCause.value}, bl={'Data': 8}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Note MS Present Request

class NoteMSGPRSPresentReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.NoteMSGPRSPresentReq.value}),
        GTPIEs(GEN=(
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}),
            GTPIETLV('GSNAddr', val={'Type': GTPIEType.GSNAddr.value}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Note MS Present Response

class NoteMSGPRSPresentResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.NoteMSGPRSPresentResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


#------------------------------------------------------------------------------#
# 7.5 Mobility Management Messages
#------------------------------------------------------------------------------#
# interface between SGSNs within a PLMN

# Identification Request

class IdentificationReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.IdentificationReq.value}),
        GTPIEs(GEN=(
            GTPIETV('RAI', val={'Type': GTPIEType.RAI.value}, bl={'Data': 48}),
            GTPIETV('PTMSI', val={'Type': GTPIEType.PTMSI.value}, bl={'Data': 32}),
            GTPIETV('PTMSISignature', val={'Type': GTPIEType.PTMSISignature.value}, bl={'Data': 24}, trans=True),
            GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('HopCounter', val={'Type': GTPIEType.HopCounter.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Identification Response

class IdentificationResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.IdentificationResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
            GTPIETV('AuthentTriplet', val={'Type': GTPIEType.AuthentTriplet.value}, bl={'Data': 224}, trans=True),
            GTPIETLV('AuthentQuintuplet', val={'Type': GTPIEType.AuthentQuintuplet.value}, trans=True),
            GTPIETLV('UEUsageType', val={'Type': GTPIEType.UEUsageType.value}, trans=True),
            GTPIETLV('IOVUpdatesCounter', val={'Type': GTPIEType.IOVUpdatesCounter.value}, trans=True),
            ), hier=1)
        )


# SGSN Context Request

class SGSNCtxtReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.SGSNCtxtReq.value}),
        GTPIEs(GEN=(
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
            GTPIETV('RAI', val={'Type': GTPIEType.RAI.value}, bl={'Data': 48}),
            GTPIETV('TLLI', val={'Type': GTPIEType.TLLI.value}, trans=True),
            GTPIETV('PTMSI', val={'Type': GTPIEType.PTMSI.value}, bl={'Data': 32}, trans=True),
            GTPIETV('PTMSISignature', val={'Type': GTPIEType.PTMSISignature.value}, bl={'Data': 24}, trans=True),
            GTPIETV('MSValidated', val={'Type': GTPIEType.MSValidated.value}, bl={'Data': 8}, trans=True),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}),
            GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}),
            GTPIETLV('AltSGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('SGSNNumber', val={'Type': GTPIEType.SGSNNumber.value}, trans=True),
            GTPIETLV('RATType', val={'Type': GTPIEType.RATType.value}, trans=True),
            GTPIETLV('HopCounter', val={'Type': GTPIEType.HopCounter.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# SGSN Context Response

class SGSNCtxtResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.SGSNCtxtResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETV('RABContext', val={'Type': GTPIEType.RABContext.value}, bl={'Data': 72}, trans=True),
            GTPIETV('RadioPrioritySMS', val={'Type': GTPIEType.RadioPrioritySMS.value}, bl={'Data': 8}, trans=True),
            GTPIETV('RadioPriority', val={'Type': GTPIEType.RadioPriority.value}, bl={'Data': 8}, trans=True),
            GTPIETV('PacketFlowId', val={'Type': GTPIEType.PacketFlowId.value}, bl={'Data': 16}, trans=True),
            GTPIETV('ChargingCharacteristics', val={'Type': GTPIEType.ChargingCharacteristics.value}, bl={'Data': 16}, trans=True),
            GTPIETLV('RadioPriorityLCS', val={'Type': GTPIEType.RadioPriorityLCS.value}, trans=True),
            GTPIETLV('MMContext', val={'Type': GTPIEType.MMContext.value}, trans=True),
            GTPIETLV('PDPContext', val={'Type': GTPIEType.PDPContext.value}, trans=True),
            GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('PDPContextPrioritization', val={'Type': GTPIEType.PDPContextPrioritization.value}, trans=True),
            GTPIETLV('MBMSUEContext', val={'Type': GTPIEType.MBMSUEContext.value}, trans=True),
            GTPIETLV('SubscribedRFSPIndex', val={'Type': GTPIEType.RFSPIndex.value}, trans=True),
            GTPIETLV('RFSPIndex', val={'Type': GTPIEType.RFSPIndex.value}, trans=True),
            GTPIETLV('ColocatedGGSNPGWFQDN', val={'Type': GTPIEType.FQDN.value}, trans=True),
            GTPIETLV('EvolvedAllocationRetentionPriorityII', val={'Type': GTPIEType.EvolvedAllocationRetentionPriorityII.value}, trans=True),
            GTPIETLV('ExtCommonFlags', val={'Type': GTPIEType.ExtCommonFlags.value}, trans=True),
            GTPIETLV('UENetworkCap', val={'Type': GTPIEType.UENetworkCap.value}, trans=True),
            GTPIETLV('UEAMBR', val={'Type': GTPIEType.UEAMBR.value}, trans=True),
            GTPIETLV('APNAMBRWithNSAPI', val={'Type': GTPIEType.APNAMBRWithNSAPI.value}, trans=True),
            GTPIETLV('SignallingPriorityIndWithNSAPI', val={'Type': GTPIEType.SignallingPriorityIndWithNSAPI.value}, trans=True),
            GTPIETLV('HigherBitratesThan16MbpsFlag', val={'Type': GTPIEType.HigherBitratesThan16MbpsFlag.value}, trans=True),
            GTPIETLV('SelectionModeWithNSAPI', val={'Type': GTPIEType.SelectionModeWithNSAPI.value}, trans=True),
            GTPIETLV('LocalHomeNetworkIDWithNSAPI', val={'Type': GTPIEType.LocalHomeNetworkIDWithNSAPI.value}, trans=True),
            GTPIETLV('UEUsageType', val={'Type': GTPIEType.UEUsageType.value}, trans=True),
            GTPIETLV('ExtCommonFlagsII', val={'Type': GTPIEType.ExtCommonFlagsII.value}, trans=True),
            GTPIETLV('UESCEFPDNConnection', val={'Type': GTPIEType.SCEFPDNConnection.value}, trans=True),
            GTPIETLV('IOVUpdatesCounter', val={'Type': GTPIEType.IOVUpdatesCounter.value}, trans=True),
            GTPIETLV('AltGGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('AltGGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# SGSN Context Acknowledge

class SGSNCtxtAck(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.SGSNCtxtAck.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('TEIDDataII', val={'Type': GTPIEType.TEIDDataII.value}, bl={'Data': 40}, trans=True),
            GTPIETLV('SGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('SGSNNumber', val={'Type': GTPIEType.SGSNNumber.value}, trans=True),
            GTPIETLV('NodeIdent', val={'Type': GTPIEType.NodeIdent.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Forward Relocation Request

class ForwardRelocationReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.ForwardRelocationReq.value}),
        GTPIEs(GEN=(
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}),
            GTPIETV('RANAPCause', val={'Type': GTPIEType.RANAPCause.value}, bl={'Data': 8}),
            GTPIETV('PacketFlowId', val={'Type': GTPIEType.PacketFlowId.value}, bl={'Data': 16}, trans=True),
            GTPIETV('ChargingCharacteristics', val={'Type': GTPIEType.ChargingCharacteristics.value}, bl={'Data': 16}, trans=True),
            GTPIETLV('MMContext', val={'Type': GTPIEType.MMContext.value}),
            GTPIETLV('PDPContext', val={'Type': GTPIEType.PDPContext.value}, trans=True),
            GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('TargetIdent', val={'Type': GTPIEType.TargetIdent.value}),
            GTPIETLV('UTRANTransparentContainer', val={'Type': GTPIEType.UTRANTransparentContainer.value}),
            GTPIETLV('PDPContextPrioritization', val={'Type': GTPIEType.PDPContextPrioritization.value}, trans=True),
            GTPIETLV('MBMSUEContext', val={'Type': GTPIEType.MBMSUEContext.value}, trans=True),
            GTPIETLV('SelectedPLMNID', val={'Type': GTPIEType.SelectedPLMNID.value}, trans=True),
            GTPIETLV('BSSContainer', val={'Type': GTPIEType.BSSContainer.value}, trans=True),
            GTPIETLV('CellIdent', val={'Type': GTPIEType.CellIdent.value}, trans=True),
            GTPIETLV('BSSGPCause', val={'Type': GTPIEType.BSSGPCause.value}, trans=True),
            GTPIETLV('PSHandoverXIDParameters', val={'Type': GTPIEType.PSHandoverXIDParameters.value}, trans=True),
            GTPIETLV('DirectTunnelFlags', val={'Type': GTPIEType.DirectTunnelFlags.value}, trans=True),
            GTPIETLV('ReliableInterRATHandoverInfo', val={'Type': GTPIEType.ReliableInterRATHandoverInfo.value}, trans=True),
            GTPIETLV('SubscribedRFSPIndex', val={'Type': GTPIEType.RFSPIndex.value}, trans=True),
            GTPIETLV('RFSPIndex', val={'Type': GTPIEType.RFSPIndex.value}, trans=True),
            GTPIETLV('ColocatedGGSNPGWFQDN', val={'Type': GTPIEType.FQDN.value}, trans=True),
            GTPIETLV('EvolvedAllocationRetentionPriorityII', val={'Type': GTPIEType.EvolvedAllocationRetentionPriorityII.value}, trans=True),
            GTPIETLV('ExtCommonFlags', val={'Type': GTPIEType.ExtCommonFlags.value}, trans=True),
            GTPIETLV('CSGID', val={'Type': GTPIEType.CSGID.value}, trans=True),
            GTPIETLV('CMI', val={'Type': GTPIEType.CMI.value}, trans=True),
            GTPIETLV('UENetworkCap', val={'Type': GTPIEType.UENetworkCap.value}, trans=True),
            GTPIETLV('UEAMBR', val={'Type': GTPIEType.UEAMBR.value}, trans=True),
            GTPIETLV('APNAMBRWithNSAPI', val={'Type': GTPIEType.APNAMBRWithNSAPI.value}, trans=True),
            GTPIETLV('SignallingPriorityIndWithNSAPI', val={'Type': GTPIEType.SignallingPriorityIndWithNSAPI.value}, trans=True),
            GTPIETLV('HigherBitratesThan16MbpsFlag', val={'Type': GTPIEType.HigherBitratesThan16MbpsFlag.value}, trans=True),
            GTPIETLV('AdditionalMMContextForSRVCC', val={'Type': GTPIEType.AdditionalMMContextForSRVCC.value}, trans=True),
            GTPIETLV('AdditionalFlagsForSRVCC', val={'Type': GTPIEType.AdditionalFlagsForSRVCC.value}, trans=True),
            GTPIETLV('STNSR', val={'Type': GTPIEType.STNSR.value}, trans=True),
            GTPIETLV('CMSISDN', val={'Type': GTPIEType.CMSISDN.value}, trans=True),
            GTPIETLV('ExtRANAPCause', val={'Type': GTPIEType.ExtRANAPCause.value}, trans=True),
            GTPIETLV('ENodeBID', val={'Type': GTPIEType.ENodeBID.value}, trans=True),
            GTPIETLV('SelectionModeWithNSAPI', val={'Type': GTPIEType.SelectionModeWithNSAPI.value}, trans=True),
            GTPIETLV('UEUsageType', val={'Type': GTPIEType.UEUsageType.value}, trans=True),
            GTPIETLV('ExtCommonFlagsII', val={'Type': GTPIEType.ExtCommonFlagsII.value}, trans=True),
            GTPIETLV('UESCEFPDNConnection', val={'Type': GTPIEType.SCEFPDNConnection.value}, trans=True),
            GTPIETLV('AltGGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('AltGGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Forward Relocation Response

class ForwardRelocationResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.ForwardRelocationResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETV('TEIDDataII', val={'Type': GTPIEType.TEIDDataII.value}, bl={'Data': 40}, trans=True),
            GTPIETV('RANAPCause', val={'Type': GTPIEType.RANAPCause.value}, bl={'Data': 8}, trans=True),
            GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('SGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('UTRANTransparentContainer', val={'Type': GTPIEType.UTRANTransparentContainer.value}, trans=True),
            GTPIETLV('RABSetupInfo', val={'Type': GTPIEType.RABSetupInfo.value}, trans=True),
            GTPIETLV('AdditionalRABSetupInfo', val={'Type': GTPIEType.AdditionalRABSetupInfo.value}, trans=True),
            GTPIETLV('SGSNNumber', val={'Type': GTPIEType.SGSNNumber.value}, trans=True),
            GTPIETLV('BSSContainer', val={'Type': GTPIEType.BSSContainer.value}, trans=True),
            GTPIETLV('BSSGPCause', val={'Type': GTPIEType.BSSGPCause.value}, trans=True),
            GTPIETLV('ListOfSetupPFCs', val={'Type': GTPIEType.ListOfSetupPFCs.value}, trans=True),
            GTPIETLV('ExtRANAPCause', val={'Type': GTPIEType.ExtRANAPCause.value}, trans=True),
            GTPIETLV('NodeIdent', val={'Type': GTPIEType.NodeIdent.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Forward Relocation Complete

class ForwardRelocationComplete(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.ForwardRelocationComplete.value}),
        GTPIEs(GEN=(
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Relocation Cancel Request

class RelocationCancelReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.RelocationCancelReq.value}),
        GTPIEs(GEN=(
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
            GTPIETLV('IMEI', val={'Type': GTPIEType.IMEI.value}, trans=True),
            GTPIETLV('ExtCommonFlags', val={'Type': GTPIEType.ExtCommonFlags.value}, trans=True),
            GTPIETLV('ExtRANAPCause', val={'Type': GTPIEType.ExtRANAPCause.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Relocation Cancel Response

class RelocationCancelResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.RelocationCancelResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Forward Relocation Complete Acknowledge

class ForwardRelocationCompleteAck(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.ForwardRelocationCompleteAck.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Forward SRNS Context Acknowledge

class ForwardSRNSCtxtAck(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.ForwardSRNSCtxtAck.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Forward SRNS Context

class ForwardSRNSCtxt(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.ForwardSRNSCtxt.value}),
        GTPIEs(GEN=(
            GTPIETV('RABContext', val={'Type': GTPIEType.RABContext.value}, bl={'Data': 72}),
            GTPIETLV('SourceRNCPDCPContextInfo', val={'Type': GTPIEType.SourceRNCPDCPContextInfo.value}, trans=True),
            GTPIETLV('PDUNumbers', val={'Type': GTPIEType.PDUNumbers.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# RAN Information Relay

class RANInfoRelay(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.RANInfoRelay.value}),
        GTPIEs(GEN=(
            GTPIETLV('RANTransparentContainer', val={'Type': GTPIEType.RANTransparentContainer.value}),
            GTPIETLV('RIMRoutingAddr', val={'Type': GTPIEType.RIMRoutingAddr.value}, trans=True),
            GTPIETLV('RIMRoutingAddrDiscriminator', val={'Type': GTPIEType.RIMRoutingAddrDiscriminator.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


#------------------------------------------------------------------------------#
# 7.5A MBMS Messages
#------------------------------------------------------------------------------#
# optional interface between SGSN and GGSN within a PLMN

# 7.5A.1 UE Specific MBMS Messages

# MBMS Notification Request

class MBMSNotifReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MBMSNotifReq.value}),
        GTPIEs(GEN=(
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}),
            GTPIETV('NSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}),
            GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
            GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
            GTPIETLV('GGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}),
            GTPIETLV('MBMSPCO', val={'Type': GTPIEType.MBMSPCO.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# MBMS Notification Response

class MBMSNotifResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MBMSNotifResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# MBMS Notification Reject Request

class MBMSNotifRejectReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MBMSNotifRejectReq.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}),
            GTPIETV('NSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}),
            GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
            GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
            GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# MBMS Notification Reject Response

class MBMSNotifRejectResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MBMSNotifRejectResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Create MBMS Context Request

class CreateMBMSCtxtReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.CreateMBMSCtxtReq.value}),
        GTPIEs(GEN=(
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
            GTPIETV('RAI', val={'Type': GTPIEType.RAI.value}, bl={'Data': 48}),
            GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
            GTPIETV('SelectionMode', val={'Type': GTPIEType.SelectionMode.value}, bl={'Data': 8}, trans=True),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETV('TraceReference', val={'Type': GTPIEType.TraceReference.value}, bl={'Data': 16}, trans=True),
            GTPIETV('TraceType', val={'Type': GTPIEType.TraceType.value}, bl={'Data': 16}, trans=True),
            GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
            GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
            GTPIETLV('SGSNAddrForSignalling', val={'Type': GTPIEType.GSNAddr.value}),
            GTPIETLV('MSISDN', val={'Type': GTPIEType.MSISDN.value}, trans=True),
            GTPIETLV('TriggerId', val={'Type': GTPIEType.TriggerId.value}, trans=True),
            GTPIETLV('OMCIdentity', val={'Type': GTPIEType.OMCIdentity.value}, trans=True),
            GTPIETLV('RATType', val={'Type': GTPIEType.RATType.value}, trans=True),
            GTPIETLV('UserLocationInfo', val={'Type': GTPIEType.UserLocationInfo.value}, trans=True),
            GTPIETLV('MSTimeZone', val={'Type': GTPIEType.MSTimeZone.value}, trans=True),
            GTPIETLV('IMEI', val={'Type': GTPIEType.IMEI.value}, trans=True),
            GTPIETLV('MBMSPCO', val={'Type': GTPIEType.MBMSPCO.value}, trans=True),
            GTPIETLV('AdditionalTraceInfo', val={'Type': GTPIEType.AdditionalTraceInfo.value}, trans=True),
            GTPIETLV('EnhancedNSAPI', val={'Type': GTPIEType.EnhancedNSAPI.value}),
            GTPIETLV('AdditionalMBMSTraceInfo', val={'Type': GTPIEType.AdditionalMBMSTraceInfo.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Create MBMS Context Response

class CreateMBMSCtxtResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.CreateMBMSCtxtResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETV('ChargingID', val={'Type': GTPIEType.ChargingID.value}, bl={'Data': 32}, trans=True),
            GTPIETLV('GGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('AltGGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('ChargingGatewayAddr', val={'Type': GTPIEType.ChargingGatewayAddr.value}, trans=True),
            GTPIETLV('AltChargingGatewayAddr', val={'Type': GTPIEType.ChargingGatewayAddr.value}, trans=True),
            GTPIETLV('MBMSPCO', val={'Type': GTPIEType.MBMSPCO.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Update MBMS Context Request

class UpdateMBMSCtxtReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.UpdateMBMSCtxtReq.value}),
        GTPIEs(GEN=(
            GTPIETV('RAI', val={'Type': GTPIEType.RAI.value}, bl={'Data': 48}),
            GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETV('TraceReference', val={'Type': GTPIEType.TraceReference.value}, bl={'Data': 16}, trans=True),
            GTPIETV('TraceType', val={'Type': GTPIEType.TraceType.value}, bl={'Data': 16}, trans=True),
            GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('AltSGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('TriggerId', val={'Type': GTPIEType.TriggerId.value}, trans=True),
            GTPIETLV('OMCIdentity', val={'Type': GTPIEType.OMCIdentity.value}, trans=True),
            GTPIETLV('RATType', val={'Type': GTPIEType.RATType.value}, trans=True),
            GTPIETLV('UserLocationInfo', val={'Type': GTPIEType.UserLocationInfo.value}, trans=True),
            GTPIETLV('MSTimeZone', val={'Type': GTPIEType.MSTimeZone.value}, trans=True),
            GTPIETLV('AdditionalTraceInfo', val={'Type': GTPIEType.AdditionalTraceInfo.value}, trans=True),
            GTPIETLV('EnhancedNSAPI', val={'Type': GTPIEType.EnhancedNSAPI.value}),
            GTPIETLV('AdditionalMBMSTraceInfo', val={'Type': GTPIEType.AdditionalMBMSTraceInfo.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Update MBMS Context Response

class UpdateMBMSCtxtResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.UpdateMBMSCtxtResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETV('ChargingID', val={'Type': GTPIEType.ChargingID.value}, bl={'Data': 32}, trans=True),
            GTPIETLV('GGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('AltGGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('ChargingGatewayAddr', val={'Type': GTPIEType.ChargingGatewayAddr.value}, trans=True),
            GTPIETLV('AltChargingGatewayAddr', val={'Type': GTPIEType.ChargingGatewayAddr.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Delete MBMS Context Request

class DeleteMBMSCtxtReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.DeleteMBMSCtxtReq.value}),
        GTPIEs(GEN=(
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}, trans=True),
            GTPIETLV('APN', val={'Type': GTPIEType.APN.value}, trans=True),
            GTPIETLV('MBMSPCO', val={'Type': GTPIEType.MBMSPCO.value}, trans=True),
            GTPIETLV('EnhancedNSAPI', val={'Type': GTPIEType.EnhancedNSAPI.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# Delete MBMS Context Response

class DeleteMBMSCtxtResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.DeleteMBMSCtxtResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETLV('MBMSPCO', val={'Type': GTPIEType.MBMSPCO.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# 7.5A.2 Service Specific MBMS Messages

# MBMS Registration Request

class MBMSRegistrationReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MBMSRegistrationReq.value}),
        GTPIEs(GEN=(
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
            GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
            GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('AltSGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# MBMS Registration Response

class MBMSRegistrationResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MBMSRegistrationResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETLV('GGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('TMGI', val={'Type': GTPIEType.TMGI.value}, trans=True),
            GTPIETLV('RequiredMBMSBearerCap', val={'Type': GTPIEType.RequiredMBMSBearerCap.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# MBMS De-registration Request

class MBMSDeRegistrationReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MBMSDeRegistrationReq.value}),
        GTPIEs(GEN=(
            GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
            GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# MBMS De-registration Response

class MBMSDeRegistrationResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MBMSDeRegistrationResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# MBMS Session Start Request

class MBMSSessionStartReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MBMSSessionStartReq.value}),
        GTPIEs(GEN=(
            GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
            GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
            GTPIETLV('GGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('AltGGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('QoSProfile', val={'Type': GTPIEType.QoSProfile.value}),
            GTPIETLV('CommonFlags', val={'Type': GTPIEType.CommonFlags.value}),
            GTPIETLV('TMGI', val={'Type': GTPIEType.TMGI.value}),
            GTPIETLV('MBMSServiceArea', val={'Type': GTPIEType.MBMSServiceArea.value}),
            GTPIETLV('MBMSSessionIdent', val={'Type': GTPIEType.MBMSSessionIdent.value}, trans=True),
            GTPIETLV('MBMS2G3GIndicator', val={'Type': GTPIEType.MBMS2G3GIndicator.value}),
            GTPIETLV('MBMSSessionDuration', val={'Type': GTPIEType.MBMSSessionDuration.value}),
            GTPIETLV('MBMSSessionRepetitionNumber', val={'Type': GTPIEType.MBMSSessionRepetitionNumber.value}, trans=True),
            GTPIETLV('MBMSTimeToDataTransfer', val={'Type': GTPIEType.MBMSTimeToDataTransfer.value}),
            GTPIETLV('MBMSFlowIdent', val={'Type': GTPIEType.MBMSFlowIdent.value}, trans=True),
            GTPIETLV('MBMSIPMulticastDistribution', val={'Type': GTPIEType.MBMSIPMulticastDistribution.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# MBMS Session Start Response

class MBMSSessionStartResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MBMSSessionStartResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
            GTPIETV('TEIDDataI', val={'Type': GTPIEType.TEIDDataI.value}, bl={'Data': 32}, trans=True),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('SGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('AltSGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('MBMSDistributionAck', val={'Type': GTPIEType.MBMSDistributionAck.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# MBMS Session Stop Request

class MBMSSessionStopReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MBMSSessionStopReq.value}),
        GTPIEs(GEN=(
            GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
            GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
            GTPIETLV('MBMSFlowIdent', val={'Type': GTPIEType.MBMSFlowIdent.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# MBMS Session Stop Response

class MBMSSessionStopResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MBMSSessionStopResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# MBMS Session Update Request

class MBMSSessionUpdateReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MBMSSessionUpdateReq.value}),
        GTPIEs(GEN=(
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
            GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
            GTPIETLV('GGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('TMGI', val={'Type': GTPIEType.TMGI.value}),
            GTPIETLV('MBMSSessionDuration', val={'Type': GTPIEType.MBMSSessionDuration.value}),
            GTPIETLV('MBMSServiceArea', val={'Type': GTPIEType.MBMSServiceArea.value}),
            GTPIETLV('MBMSSessionIdent', val={'Type': GTPIEType.MBMSSessionIdent.value}, trans=True),
            GTPIETLV('MBMSSessionRepetitionNumber', val={'Type': GTPIEType.MBMSSessionRepetitionNumber.value}, trans=True),
            GTPIETLV('MBMSFlowIdent', val={'Type': GTPIEType.MBMSFlowIdent.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# MBMS Session Update Response

class MBMSSessionUpdateResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MBMSSessionUpdateResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('TEIDDataI', val={'Type': GTPIEType.TEIDDataI.value}, bl={'Data': 32}, trans=True),
            GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
            GTPIETLV('SGSNAddrForDataI', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


#------------------------------------------------------------------------------#
# 7.5B.1 MS Info Change Reporting Messages
#------------------------------------------------------------------------------#
# optional interface between SGSN and GGSN within a PLMN

# MS Info Change Notification Request

class MSInfoChangeNotifReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MSInfoChangeNotifReq.value}),
        GTPIEs(GEN=(
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
            GTPIETV('LinkedNSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}, trans=True),
            GTPIETLV('RATType', val={'Type': GTPIEType.RATType.value}),
            GTPIETLV('UserLocationInfo', val={'Type': GTPIEType.UserLocationInfo.value}, trans=True),
            GTPIETLV('IMEI', val={'Type': GTPIEType.IMEI.value}, trans=True),
            GTPIETLV('ExtCommonFlags', val={'Type': GTPIEType.ExtCommonFlags.value}, trans=True),
            GTPIETLV('UCI', val={'Type': GTPIEType.UCI.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


# MS Info Change Notification Response

class MSInfoChangeNotifResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'Type': GTPType.MSInfoChangeNotifResp.value}),
        GTPIEs(GEN=(
            GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
            GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
            GTPIETV('LinkedNSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}, trans=True),
            GTPIETLV('IMEI', val={'Type': GTPIEType.IMEI.value}, trans=True),
            GTPIETLV('MSInfoChangeReportingAction', val={'Type': GTPIEType.MSInfoChangeReportingAction.value}, trans=True),
            GTPIETLV('CSGInfoReportingAction', val={'Type': GTPIEType.CSGInfoReportingAction.value}, trans=True),
            GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
            ), hier=1)
        )


#------------------------------------------------------------------------------#
# General parser    
# TS 29.060, section 7.1
#------------------------------------------------------------------------------#

GTPDispatcherSGSN = {
    1 : EchoReq,
    2 : EchoResp,
    3 : VersionNotSupported,
    31 : SupportedExtHeadersNotif,
    16 : CreatePDPCtxtReq,
    17 : CreatePDPCtxtResp,
    #18 : UpdatePDPCtxtReqSGSN,
    18 : UpdatePDPCtxtReqGGSN,
    19 : UpdatePDPCtxtRespGGSN,
    #19 : UpdatePDPCtxtRespSGSN,
    20 : DeletePDPCtxtReq,
    21 : DeletePDPCtxtResp,
    26 : ErrorInd,
    27 : PDUNotifReq,
    28 : PDUNotifResp,
    29 : PDUNotifRejectReq,
    30 : PDUNotifRejectResp,
    22 : InitiatePDPCtxtActivationReq,
    23 : InitiatePDPCtxtActivationResp,
    32 : SendRouteingInfoforGPRSReq,
    33 : SendRouteingInfoforGPRSResp,
    34 : FailureReportReq,
    35 : FailureReportResp,
    36 : NoteMSGPRSPresentReq,
    37 : NoteMSGPRSPresentResp,
    48 : IdentificationReq,
    49 : IdentificationResp,
    50 : SGSNCtxtReq,
    51 : SGSNCtxtResp,
    52 : SGSNCtxtAck,
    53 : ForwardRelocationReq,
    54 : ForwardRelocationResp,
    55 : ForwardRelocationComplete,
    56 : RelocationCancelReq,
    57 : RelocationCancelResp,
    59 : ForwardRelocationCompleteAck,
    60 : ForwardSRNSCtxtAck,
    58 : ForwardSRNSCtxt,
    70 : RANInfoRelay,
    96 : MBMSNotifReq,
    97 : MBMSNotifResp,
    98 : MBMSNotifRejectReq,
    99 : MBMSNotifRejectResp,
    100 : CreateMBMSCtxtReq,
    101 : CreateMBMSCtxtResp,
    102 : UpdateMBMSCtxtReq,
    103 : UpdateMBMSCtxtResp,
    104 : DeleteMBMSCtxtReq,
    105 : DeleteMBMSCtxtResp,
    112 : MBMSRegistrationReq,
    113 : MBMSRegistrationResp,
    114 : MBMSDeRegistrationReq,
    115 : MBMSDeRegistrationResp,
    116 : MBMSSessionStartReq,
    117 : MBMSSessionStartResp,
    118 : MBMSSessionStopReq,
    119 : MBMSSessionStopResp,
    120 : MBMSSessionUpdateReq,
    121 : MBMSSessionUpdateResp,
    128 : MSInfoChangeNotifReq,
    129 : MSInfoChangeNotifResp,
    }


GTPCDispatcherGGSN = {
    1 : EchoReq,
    2 : EchoResp,
    3 : VersionNotSupported,
    31 : SupportedExtHeadersNotif,
    16 : CreatePDPCtxtReq,
    17 : CreatePDPCtxtResp,
    18 : UpdatePDPCtxtReqSGSN,
    #18 : UpdatePDPCtxtReqGGSN,
    #19 : UpdatePDPCtxtRespGGSN,
    19 : UpdatePDPCtxtRespSGSN,
    20 : DeletePDPCtxtReq,
    21 : DeletePDPCtxtResp,
    26 : ErrorInd,
    27 : PDUNotifReq,
    28 : PDUNotifResp,
    29 : PDUNotifRejectReq,
    30 : PDUNotifRejectResp,
    22 : InitiatePDPCtxtActivationReq,
    23 : InitiatePDPCtxtActivationResp,
    32 : SendRouteingInfoforGPRSReq,
    33 : SendRouteingInfoforGPRSResp,
    34 : FailureReportReq,
    35 : FailureReportResp,
    36 : NoteMSGPRSPresentReq,
    37 : NoteMSGPRSPresentResp,
    48 : IdentificationReq,
    49 : IdentificationResp,
    50 : SGSNCtxtReq,
    51 : SGSNCtxtResp,
    52 : SGSNCtxtAck,
    53 : ForwardRelocationReq,
    54 : ForwardRelocationResp,
    55 : ForwardRelocationComplete,
    56 : RelocationCancelReq,
    57 : RelocationCancelResp,
    59 : ForwardRelocationCompleteAck,
    60 : ForwardSRNSCtxtAck,
    58 : ForwardSRNSCtxt,
    70 : RANInfoRelay,
    96 : MBMSNotifReq,
    97 : MBMSNotifResp,
    98 : MBMSNotifRejectReq,
    99 : MBMSNotifRejectResp,
    100 : CreateMBMSCtxtReq,
    101 : CreateMBMSCtxtResp,
    102 : UpdateMBMSCtxtReq,
    103 : UpdateMBMSCtxtResp,
    104 : DeleteMBMSCtxtReq,
    105 : DeleteMBMSCtxtResp,
    112 : MBMSRegistrationReq,
    113 : MBMSRegistrationResp,
    114 : MBMSDeRegistrationReq,
    115 : MBMSDeRegistrationResp,
    116 : MBMSSessionStartReq,
    117 : MBMSSessionStartResp,
    118 : MBMSSessionStopReq,
    119 : MBMSSessionStopResp,
    120 : MBMSSessionUpdateReq,
    121 : MBMSSessionUpdateResp,
    128 : MSInfoChangeNotifReq,
    129 : MSInfoChangeNotifResp,
    }


ERR_GTP_BUF_TOO_SHORT = 1
ERR_GTP_BUF_INVALID   = 2
ERR_GTP_TYPE_NONEXIST = 3
ERR_GTP_MAND_IE_MISS  = 4


def parse_GTPC_SGSN(buf):
    """parses the buffer `buf' for GTPv1-C message as received by a SGSN
    and returns a 2-tuple:
    - GTPv1-C message structure, or None if parsing failed
    - parsing error code, 0 if parsing succeeded, > 0 otherwise
    """
    if len(buf) < 8:
        return None, ERR_GTP_BUF_TOO_SHORT
    if python_version < 3:
        typ = ord(buf[1])
    else:
        typ = buf[1]
    try:
        Msg = GTPDispatcherSGSN[typ]()
    except KeyError:
        return None, ERR_GTP_TYPE_NONEXIST
    try:
        Msg.from_bytes(buf)
    except GTPDecErr:
        GTPCIEs.VERIF_MAND = False
        Msg = Msg.__class__()
        try:
            Msg.from_bytes(buf)
            GTPCIEs.VERIF_MAND = True
        except Exception:
            GTPCIEs.VERIF_MAND = True
            return None, ERR_GTP_BUF_INVALID
        else:
            return Msg, ERR_GTP_MAND_IE_MISS
    except Exception:
        return None, ERR_GTP_BUF_INVALID
    else:
        return Msg, 0


def parse_GTPC_GGSN(buf):
    """parses the buffer `buf' for GTPv1-C message as received by a GGSN
    and returns a 2-tuple:
    - GTPv1-C message structure, or None if parsing failed
    - parsing error code, 0 if parsing succeeded, > 0 otherwise
    """
    if len(buf) < 8:
        return None, ERR_GTP_BUF_TOO_SHORT
    if python_version < 3:
        typ = ord(buf[1])
    else:
        typ = buf[1]
    try:
        Msg = GTPDispatcherGGSN[typ]()
    except KeyError:
        return None, ERR_GTP_TYPE_NONEXIST
    try:
        Msg.from_bytes(buf)
    except GTPDecErr:
        GTPCIEs.VERIF_MAND = False
        Msg = Msg.__class__()
        try:
            Msg.from_bytes(buf)
            GTPCIEs.VERIF_MAND = True
        except Exception:
            GTPCIEs.VERIF_MAND = True
            return None, ERR_GTP_BUF_INVALID
        else:
            return Msg, ERR_GTP_MAND_IE_MISS
    except Exception:
        return None, ERR_GTP_BUF_INVALID
    else:
        return Msg, 0

