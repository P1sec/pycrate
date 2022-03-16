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


from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
from enum   import IntEnum

from pycrate_core.utils     import *
from pycrate_core.elt       import *
from pycrate_core.base      import *
from pycrate_core.utils     import PycrateErr
from pycrate_core.charpy    import CharpyErr

from pycrate_mobile.TS29274_GTPC    import (
    PCO, MMContextQuintuplet, MMContextTriplet, MMContextMSNetCap, RNCID, SAI,
    CGI, RIMRoutingAddr, PDUNumbers as GTPv2PDUNumbers, AMBR, 
    AdditionalMMContextForSRVCC, STNSR, NodeIdent, MappedUEUsageType, 
    UPFunctionSelectionIndFlags
    )
from pycrate_mobile.TS29244_PFCP    import (
    _LU8V, _Timer, FQDN
    )
from pycrate_mobile.TS24008_IE      import (
    BufBCD, RAI, NSAPI, PDPAddr, CiphAlgo_dict, DRXParam, QoS, IPAddr, APN,
    TFT, _PDPTypeOrg_dict, _PDPTypeNum_dict, TimeZone, DLSavingTime, TMGI, PLMN,
    PacketFlowId
    )
from pycrate_mobile.TS24301_IE      import (
    UENetCap
    )
from pycrate_mobile.TS24007         import (
    TI
    )
from pycrate_mobile.TS29002_MAPIE   import (
    AddressString,
    )


#------------------------------------------------------------------------------#
# 3GPP TS 29.060: GPRS Tunnelling Protocol (GTP) across the Gn and Gp interface
# release 16 (h10)
# i.e. SGSN - GGSN interface
#------------------------------------------------------------------------------#


#------------------------------------------------------------------------------#
# Custom error handlers for decoding and encoding routines
#------------------------------------------------------------------------------#

class GTPDecErr(PycrateErr):
    pass


class GTPEncErr(PycrateErr):
    pass


#------------------------------------------------------------------------------#
# Cause
# TS 29.060, section 7.7.1
#------------------------------------------------------------------------------#

CauseReq_dict = {
    0 : 'Request IMSI',
    1 : 'Request IMEI',
    2 : 'Request IMSI and IMEI',
    3 : 'No identity needed',
    4 : 'MS Refuses',
    5 : 'MS is not GPRS Responding',
    6 : 'Reactivation Requested',
    7 : 'PDP address inactivity timer expires',
    8 : 'Network Failure',
    9 : 'QoS parameter mismatch',
    }

CauseResp_dict = {
    0 : 'Request accepted',
    1 : 'New PDP type due to network preference',
    2 : 'New PDP type due to single address bearer only',
    }

CauseRespRej_dict = {
    0 : 'Non-existent',
    1 : 'Invalid message format',
    2 : 'IMSI/IMEI not known',
    3 : 'MS is GPRS Detached',
    4 : 'MS is not GPRS Responding',
    5 : 'MS Refuses',
    6 : 'Version not supported ',
    7 : 'No resources available',
    8 : 'Service not supported',
    9 : 'Mandatory IE incorrect',
    10 : 'Mandatory IE missing',
    11 : 'Optional IE incorrect',
    12 : 'System failure',
    13 : 'Roaming restriction',
    14 : 'P-TMSI Signature mismatch',
    15 : 'GPRS connection suspended',
    16 : 'Authentication failure',
    17 : 'User authentication failed',
    18 : 'Context not found',
    19 : 'All dynamic PDP addresses are occupied',
    20 : 'No memory is available',
    21 : 'Relocation failure',
    22 : 'Unknown mandatory extension header',
    23 : 'Semantic error in the TFT operation',
    24 : 'Syntactic error in the TFT operation',
    25 : 'Semantic errors in packet filter(s)',
    26 : 'Syntactic errors in packet filter(s)',
    27 : 'Missing or unknown APN',
    28 : 'Unknown PDP address or PDP type',
    29 : 'PDP context without TFT already activated',
    30 : 'APN access denied – no subscription',
    31 : 'APN Restriction type incompatibility with currently active PDP Contexts',
    32 : 'MS MBMS Capabilities Insufficient',
    33 : 'Invalid Correlation-ID',
    34 : 'MBMS Bearer Context Superseded',
    35 : 'Bearer Control Mode violation',
    36 : 'Collision with network initiated request',
    37 : 'APN Congestion',
    38 : 'Bearer handling not supported',
    39 : '"Target access restricted for the subscriber"',
    40 : 'UE is temporarily not reachable due to power saving',
    41 : 'Relocation failure due to NAS message redirection',
    }


class Cause(Envelope):
    _GEN = (
        Uint('Resp', bl=1),
        Uint('Reject', bl=1),
        Uint('Value', bl=6)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Value'].set_dicauto(self._get_dict)
    
    def _get_dict(self):
        resp, rej = self[0].get_val(), self[1].get_val()
        if not resp:
            if not rej:
                return CauseReq_dict
            else:
                return {}
        else:
            if not rej:
                return CauseResp_dict
            else:
                return CauseRespRej_dict


#------------------------------------------------------------------------------#
# IMSI
# TS 29.060, section 7.7.2
#------------------------------------------------------------------------------#

class IMSI(BufBCD):
    _bl = 64


#------------------------------------------------------------------------------#
# TLLI
# TS 29.060, section 7.7.4
#------------------------------------------------------------------------------#

class TLLI(Uint32):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# P-TMSI
# TS 29.060, section 7.7.5
#------------------------------------------------------------------------------#

class PTMSI(Uint32):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# Reordering Required
# TS 29.060, section 7.7.6
#------------------------------------------------------------------------------#

class ReorderingRequired(Envelope):
    _GEN = (
        Uint('spare', val=0x7f, bl=7, rep=REPR_HEX),
        Uint('Value', bl=1),
        )


#------------------------------------------------------------------------------#
# Authentication Triplet
# TS 29.060, section 7.7.7
#------------------------------------------------------------------------------#

class AuthentTriplet(Envelope):
    _GEN = (
        Buf('RAND', bl=16<<3, rep=REPR_HEX),
        Buf('SRES', bl=4<<3, rep=REPR_HEX),
        Buf('Kc', bl=8<<3, rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# MAP Cause
# TS 29.060, section 7.7.8
#------------------------------------------------------------------------------#

class MAPCause(Uint8):
    pass


#------------------------------------------------------------------------------#
# P-TMSI Signature
# TS 29.060, section 7.7.9
#------------------------------------------------------------------------------#

class PTMSISignature(Uint24):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# MS Validated
# TS 29.060, section 7.7.10
#------------------------------------------------------------------------------#

class MSValidated(Envelope):
    _GEN = (
        Uint('spare', val=0x7f, bl=7, rep=REPR_HEX),
        Uint('Value', bl=1),
        )


#------------------------------------------------------------------------------#
# Recovery
# TS 29.060, section 7.7.11
#------------------------------------------------------------------------------#

class Recovery(Uint8):
    pass


#------------------------------------------------------------------------------#
# Selection Mode
# TS 29.060, section 7.7.12
#------------------------------------------------------------------------------#

_SelMode_dict = {
    0 : 'MS or network provided APN, subscribed verified',
    1 : 'MS provided APN, subscription not verified',
    2 : 'Network provided APN, subscription not verified',
    3 : 'For future use. Shall not be sent. If received, shall be interpreted as the value "2"',
    }


class SelectionMode(Envelope):
    _GEN = (
        Uint('spare', val=0x3f, bl=6, rep=REPR_HEX),
        Uint('Value', val=0, bl=2, dic=_SelMode_dict),
        )


#------------------------------------------------------------------------------#
# Tunnel Endpoint Identifier Data I
# TS 29.060, section 7.7.13
#------------------------------------------------------------------------------#

class TEIDDataI(Uint32):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# Tunnel Endpoint Identifier Control Plane
# TS 29.060, section 7.7.14
#------------------------------------------------------------------------------#

class TEIDCP(Uint32):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# Tunnel Endpoint Identifier Data II
# TS 29.060, section 7.7.15
#------------------------------------------------------------------------------#

class TEIDDataII(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=4, rep=REPR_HEX),
        Uint('NSAPI', val=5, bl=4),
        Uint32('Value', rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# Teardown Ind
# TS 29.060, section 7.7.16
#------------------------------------------------------------------------------#

class TeardownInd(Envelope):
    _GEN = (
        Uint('spare', val=0x7f, bl=7, rep=REPR_HEX),
        Uint('Value', bl=1),
        )


#------------------------------------------------------------------------------#
# RANAP Cause
# TS 29.060, section 7.7.18
#------------------------------------------------------------------------------#

class RANAPCause(Uint8):
    pass


#------------------------------------------------------------------------------#
# RAB Context
# TS 29.060, section 7.7.19
#------------------------------------------------------------------------------#

class RABContext(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=4, rep=REPR_HEX),
        Uint('NSAPI', val=5, bl=4),
        Uint16('DLGTPUSeqn'),
        Uint16('ULGTPUSeqn'),
        Uint16('DLPDCPSeqn'),
        Uint16('ULPDCPSeqn'),
        )


#------------------------------------------------------------------------------#
# Radio Priority SMS
# TS 29.060, section 7.7.20
#------------------------------------------------------------------------------#

class RadioPrioritySMS(Envelope):
    _GEN = (
        Uint('spare', val=0x1f, bl=5, rep=REPR_HEX),
        Uint('Value', bl=3),
        )


#------------------------------------------------------------------------------#
# Radio Priority
# TS 29.060, section 7.7.21
#------------------------------------------------------------------------------#

class RadioPriority(Envelope):
    _GEN = (
        Uint('NSAPI', val=5, bl=4),
        Uint('spare', val=0, bl=1),
        Uint('Value', bl=3),
        )


#------------------------------------------------------------------------------#
# Packet Flow Id
# TS 29.060, section 7.7.22
#------------------------------------------------------------------------------#

class PacketFlowId(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=4, rep=REPR_HEX),
        Uint('NSAPI', val=5, bl=4),
        Uint8('Value'),
        )


#------------------------------------------------------------------------------#
# Charging Characteristics
# TS 29.060, section 7.7.23
#------------------------------------------------------------------------------#

class ChargingCharacteristics(Uint16):
    _rep = REPR_BIN


#------------------------------------------------------------------------------#
# Trace Reference
# TS 29.060, section 7.7.24
#------------------------------------------------------------------------------#

class TraceReference(Uint16):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# Trace Type
# TS 29.060, section 7.7.25
#------------------------------------------------------------------------------#

class TraceType(Uint16):
    pass


#------------------------------------------------------------------------------#
# MS Not Reachable Reason
# TS 29.060, section 7.7.25A
#------------------------------------------------------------------------------#

class MSNotReachableReason(Uint8):
    pass


#------------------------------------------------------------------------------#
# Radio Priority LCS
# TS 29.060, section 7.7.25B
#------------------------------------------------------------------------------#

class RadioPriorityLCS(Envelope):
    _GEN = (
        Uint('spare', val=0x1f, bl=5, rep=REPR_HEX),
        Uint('Value', bl=3),
        )


#------------------------------------------------------------------------------#
# Charging ID
# TS 29.060, section 7.7.26
#------------------------------------------------------------------------------#

class ChargingID(Uint32):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# End User Address
# TS 29.060, section 7.7.27
#------------------------------------------------------------------------------#
# spare bits are different from the PDP Address of TS 24.008

class EndUserAddr(Envelope):
    _GEN = tuple(PDPAddr(val={'spare': 0b1111})._content)


#------------------------------------------------------------------------------#
# MM Context
# TS 29.060, section 7.7.28
#------------------------------------------------------------------------------#
# This structure is so convoluted and has been historically patched in a dirty way:
# it requires to check the SecurityMode value to determine the structure of previous bits...
# Here, we simply implement the structure for the 1st byte as spare and CKSN

_SecMode_dict = {
    0 : 'Used cipher value, UMTS Keys and Quintuplets',
    1 : 'GSM key and triplets',
    2 : 'UMTS key and quintuplets',
    3 : 'GSM key and quintuplets',
    }


class MMContextGSMTriplets(Envelope):
    _GEN = (
        Uint('NoVectors', bl=3),
        Uint('UsedCipher', bl=3, dic=CiphAlgo_dict),
        Buf('Kc', bl=64, rep=REPR_HEX),
        Sequence('Triplets', GEN=MMContextTriplet('Triplet')),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NoVectors'].set_valauto(lambda: self['Triplets'].get_num())
        self['Triplets'].set_numauto(lambda: self['NoVectors'].get_val())


class MMContextUMTSQuintuplets(Envelope):
    _GEN = (
        Uint('NoVectors', bl=3),
        Uint('spare', val=7, bl=3),
        Buf('CK', bl=128, rep=REPR_HEX),
        Buf('IK', bl=128, rep=REPR_HEX),
        Uint16('VectorsLen'), # absent if NoVectors == 0
        Sequence('Quintuplets', GEN=MMContextQuintuplet('Quintuplet')),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NoVectors'].set_valauto(lambda: self['Quintuplets'].get_num())
        self['VectorsLen'].set_transauto(lambda: True if self['NoVectors']() else False)
        self['VectorsLen'].set_valauto(lambda: self['Quintuplets'].get_len())
        self['Quintuplets'].set_numauto(lambda: self['NoVectors'].get_val())


class MMContextGSMQuintuplets(MMContextUMTSQuintuplets):
    _GEN = (
        Uint('NoVectors', bl=3),
        Uint('UsedCipher', bl=3, dic=CiphAlgo_dict),
        Buf('Kc', bl=64, rep=REPR_HEX),
        Uint16('VectorsLen'), # absent if NoVectors == 0
        Sequence('Quintuplets', GEN=MMContextQuintuplet('Quintuplet')),
        )


class MMContextUMTSQuintupletsUsedCipher(MMContextUMTSQuintuplets):
    _GEN = (
        Uint('NoVectors', bl=3),
        Uint('UsedCipher', bl=3, dic=CiphAlgo_dict),
        Buf('CK', bl=128, rep=REPR_HEX),
        Buf('IK', bl=128, rep=REPR_HEX),
        Uint16('VectorsLen'), # absent if NoVectors == 0
        Sequence('Quintuplets', GEN=MMContextQuintuplet('Quintuplet')),
        )


class MMContext(Envelope):
    _GEN = (
        Uint('spare', val=0x1f, bl=5, rep=REPR_HEX),
        Uint('CKSN', val=7, bl=3),
        Uint('SecurityMode', val=1, bl=2, dic=_SecMode_dict),
        Alt('SecContext', GEN={
            0 : MMContextUMTSQuintupletsUsedCipher('UMTSQuintupletsUsedCipher'),
            1 : MMContextGSMTriplets('GSMTriplets'),
            2 : MMContextUMTSQuintuplets('UMTSQuintuplets'),
            3 : MMContextGSMQuintuplets('GSMQuintuplets'),
            },
            sel=lambda self: self.get_env()['SecurityMode'].get_val()
        ),
        DRXParam(),
        MMContextMSNetCap('MSNetCap'),
        _LU8V('Container'),
        _LU8V('AccessRestrictionData'),
        )


#------------------------------------------------------------------------------#
# GSN Address
# TS 29.060, section 7.7.32
#------------------------------------------------------------------------------#
# IPv4 or IPv6 address

class GSNAddr(IPAddr):
    pass


#------------------------------------------------------------------------------#
# MS International PSTN/ISDN Number (MSISDN)
# TS 29.060, section 7.7.33
#------------------------------------------------------------------------------#

class MSISDN(AddressString):
    pass


#------------------------------------------------------------------------------#
# Quality of Service (QoS) Profile
# TS 29.060, section 7.7.34
#------------------------------------------------------------------------------#

class QoSProfile(Envelope):
    _GEN = (
        Uint8('AllocRetentPriority'),
        QoS()
        )


#------------------------------------------------------------------------------#
# PDP Context
# TS 29.060, section 7.7.29
#------------------------------------------------------------------------------#

class PDPContext(Envelope):
    _GEN = (
        Uint('EA', bl=1),
        Uint('VAA', bl=1),
        Uint('ASI', bl=1),
        Uint('Order', bl=1),
        Uint('NSAPI', val=5, bl=4),
        Uint('spare', val=0, bl=4, rep=REPR_HEX),
        Uint('SAPI', bl=4),
        Uint8('QoSSubLen'),
        QoSProfile('QoSSub'),
        Uint8('QoSReqLen'),
        QoSProfile('QoSReq'),
        Uint8('QoSNegLen'),
        QoSProfile('QoSNeg'),
        Uint16('SeqNumDL'),
        Uint16('SeqNumUL'),
        Uint8('SendNPDUNum'),
        Uint8('RecvNPDUNum'),
        TEIDCP('ULTEIDCP'),
        TEIDDataI('ULTEIDDataI'),
        Uint8('PDPCtxtID'),
        Uint('spare', val=0xf, bl=4, rep=REPR_HEX),
        Uint('PDPTypeOrg', val=1, bl=4, dic=_PDPTypeOrg_dict),
        Uint8('PDPType', val=33, dic=_PDPTypeNum_dict),
        _LU8V('PDPAddr'),
        GSNAddr('GSNAddrCP'),
        GSNAddr('GSNAddrUP'),
        Uint8('APNLen'),
        APN(),
        Uint('spare', val=0, bl=4, rep=REPR_HEX),
        TI(),
        Uint8('PDPType2', val=33, dic=_PDPTypeNum_dict),
        _LU8V('PDPAddr2'),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['QoSSubLen'].set_valauto(lambda: self['QoSSub'].get_len())
        self['QoSSub'].set_blauto(lambda: self['QoSSubLen'].get_val()<<3)
        self['QoSReqLen'].set_valauto(lambda: self['QoSReq'].get_len())
        self['QoSReq'].set_blauto(lambda: self['QoSReqLen'].get_val()<<3)
        self['QoSNegLen'].set_valauto(lambda: self['QoSNeg'].get_len())
        self['QoSNeg'].set_blauto(lambda: self['QoSNegLen'].get_val()<<3)
        self['APNLen'].set_valauto(lambda: self['APN'].get_len())
        self['APN'].set_blauto(lambda: self['APNLen'].get_val()<<3)



#------------------------------------------------------------------------------#
# 
# TS 29.060, section 7.7.35
#------------------------------------------------------------------------------#

class AuthentQuintuplet(MMContextQuintuplet):
    pass


#------------------------------------------------------------------------------#
# Target Identification
# TS 29.060, section 7.7.37
#------------------------------------------------------------------------------#

class TargetIdent(RNCID):
    pass


#------------------------------------------------------------------------------#
# RAB Setup Information
# TS 29.060, section 7.7.39
#------------------------------------------------------------------------------#

class RABSetupInfo(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=4, rep=REPR_HEX),
        Uint('NSAPI', val=5, bl=4),
        TEIDDataI(),
        IPAddr('RNCAddr'),
        )
    
    def set_val(self, val):
        if isinstance(val, (list, tuple)) and len(val) > 2:
            self['TEIDDataI'].set_trans(False)
            self['RNCAddr'].set_trans(False)
        elif isinstance(val, dict) and ('TEIDDataI' in val or 'RNCAddr' in val):
            self['TEIDDataI'].set_trans(False)
            self['RNCAddr'].set_trans(False)
        else:
            self['TEIDDataI'].set_trans(True)
            self['RNCAddr'].set_trans(True)
        Envelope.set_val(self, val)
    
    def _from_char(self, char):
        if char.len_byte() > 5:
            self['TEIDDataI'].set_trans(False)
            self['RNCAddr'].set_trans(False)
        else:
            self['TEIDDataI'].set_trans(True)
            self['RNCAddr'].set_trans(True)
        Envelope._from_char(self, char)


#------------------------------------------------------------------------------#
# Extension Header Type List
# TS 29.060, section 7.7.40
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


class ExtHeaderTypeList(Sequence):
    _GEN = Uint8('ExtType', dic=GTPNextExtHeader_dict)


#------------------------------------------------------------------------------#
# Charging Gateway Address
# TS 29.060, section 7.7.44
#------------------------------------------------------------------------------#

class ChargingGatewayAddr(IPAddr):
    pass


#------------------------------------------------------------------------------#
# Additional RAB Setup Information
# TS 29.060, section 7.7.45A
#------------------------------------------------------------------------------#

class AdditionalRABSetupInfo(RABSetupInfo):
    pass


#------------------------------------------------------------------------------#
# Private Extension
# TS 29.060, section 7.7.46
#------------------------------------------------------------------------------#

class PrivateExt(Envelope):
    _GEN = (
        Uint16('Id'),
        Buf('Val', val=b'', rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# SGSN Number
# TS 29.060, section 7.7.47
#------------------------------------------------------------------------------#

class SGSNNumber(Envelope):
    _GEN = tuple(AddressString(val={'NumType': 1, 'NumPlan': 1})._content)


#------------------------------------------------------------------------------#
# Common Flags
# TS 29.060, section 7.7.48
#------------------------------------------------------------------------------#

class CommonFlags(Envelope):
    _GEN = (
        Uint('DualAddrBearerFlag', bl=1),
        Uint('UpgradeQoSSupp', bl=1),
        Uint('NRSN', bl=1),
        Uint('NoQoSNegotiation', bl=1),
        Uint('MBMSCountingInfo', bl=1),
        Uint('RANProceduresReady', bl=1),
        Uint('MBMSServiceType', bl=1),
        Uint('ProhibitPayloadComp', bl=1)
        )


#------------------------------------------------------------------------------#
# APN Restriction
# TS 29.060, section 7.7.49
#------------------------------------------------------------------------------#

class APNRestriction(Uint8):
    _dic = {
        0 : 'no restriction',
        1 : 'public-1',
        2 : 'public-2',
        3 : 'private-1',
        4 : 'private-2',
        }


#------------------------------------------------------------------------------#
# RAT Type
# TS 29.060, section 7.7.50
#------------------------------------------------------------------------------#

class RATType(Uint8):
    _dic = {
        0 : 'reserved',
        1 : 'UTRAN',
        2 : 'GERAN',
        3 : 'WLAN',
        4 : 'GAN',
        5 : 'HSPA Evolution',
        6 : 'EUTRAN',
        }


#------------------------------------------------------------------------------#
# User Location Information (ULI)
# TS 29.060, section 7.7.51
#------------------------------------------------------------------------------#

class ULI(Envelope):
    _GEN = (
        Uint8('Type', dic={0: 'CGI', 1: 'SAI', 2: 'RAI'}),
        Alt('Loc', GEN={
            0 : CGI(),
            1 : SAI(),
            2 : RAI()},
            sel=lambda self: self.get_env()['Type'].get_val(),
            DEFAULT=Buf('Unk', val=b'', rep=REPR_HEX))
        )


#------------------------------------------------------------------------------#
# MS Time Zone
# TS 29.060, section 7.7.52
#------------------------------------------------------------------------------#

class MSTimeZone(Envelope):
    _GEN = (
        TimeZone(),
        DLSavingTime(),
        )


#------------------------------------------------------------------------------#
# International Mobile Equipment Identity (and Software Version) (IMEI(SV))
# TS 29.060, section 7.7.53
#------------------------------------------------------------------------------#

class IMEI(BufBCD):
    _bl = 64


#------------------------------------------------------------------------------#
# MBMS UE Context
# TS 29.060, section 7.7.55
#------------------------------------------------------------------------------#

class MBMSUEContext(Envelope):
    _GEN = (
        Uint('LinkedNSAPI', bl=4),
        Uint('spare', val=0, bl=4, rep=REPR_HEX),
        TEIDCP('ULTEIDCP'),
        Uint8('EnhancedNSAPI'),
        Uint('spare', val=0xf, bl=4, rep=REPR_HEX),
        Uint('PDPTypeOrg', val=1, bl=4, dic=_PDPTypeOrg_dict),
        Uint8('PDPType', val=33, dic=_PDPTypeNum_dict),
        _LU8V('PDPAddr'),
        Uint8('APNLen'),
        APN(),
        Uint('spare', val=0, bl=4, rep=REPR_HEX),
        TI()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['APNLen'].set_valauto(lambda: self['APN'].get_len())
        self['APN'].set_blauto(lambda: self['APNLen'].get_val()<<3)


#------------------------------------------------------------------------------#
# MBMS Protocol Configuration Options
# TS 29.060, section 7.7.58
#------------------------------------------------------------------------------#
# 8-bits spare field

class MBMSPCO(Uint8):
    pass


#------------------------------------------------------------------------------#
# MBMS Session Duration
# TS 29.060, section 7.7.59
#------------------------------------------------------------------------------#

class MBMSSessionDuration(Envelope):
    _GEN = (
        Uint('Sec', bl=17),
        Uint('Day', bl=7),
        )


#------------------------------------------------------------------------------#
# MBMS Service Area
# TS 29.060, section 7.7.60
#------------------------------------------------------------------------------#

class MBMSServiceArea(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('MBMSServiceAreaCodes', GEN=Uint16('SAC', rep=REPR_HEX)),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Num'].set_valauto(lambda: self['MBMSServiceAreaCodes'].get_num())
        self['MBMSServiceAreaCodes'].set_numauto(lambda: self['Num'].get_val())


#------------------------------------------------------------------------------#
# Additional Trace Info
# TS 29.060, section 7.7.62
#------------------------------------------------------------------------------#

class AdditionalTraceInfo(Envelope):
    _GEN = (
        Uint24('TraceRef2', rep=REPR_HEX),
        Uint16('TraceRecSessRef', rep=REPR_HEX),
        Uint8('GGSNTriggeringEvents', rep=REPR_HEX),
        Uint8('TraceDepth'),
        Uint8('ListOfInterfaces', rep=REPR_HEX),
        Uint8('TraceActivityCtrl', dic={1: 'activation', 0: 'deactivation'})
        )


#------------------------------------------------------------------------------#
# Hop Counter
# TS 29.060, section 7.7.63
#------------------------------------------------------------------------------#

class HopCounter(Uint8):
    pass


#------------------------------------------------------------------------------#
# Selected PLMN ID
# TS 29.060, section 7.7.64
#------------------------------------------------------------------------------#

class SelectedPLMNID(PLMN):
    pass


#------------------------------------------------------------------------------#
# MBMS Session Identifier
# TS 29.060, section 7.7.65
#------------------------------------------------------------------------------#

class MBMSSessionIdent(Uint8):
    pass


#------------------------------------------------------------------------------#
# MBMS 2G/3G Indicator
# TS 29.060, section 7.7.66
#------------------------------------------------------------------------------#

class MBMS2G3GInd(Uint8):
    _dic = {
        0 : '2G only',
        1 : '3G only',
        2 : '2G and 3G'
        }


#------------------------------------------------------------------------------#
# Enhanced NSAPI
# TS 29.060, section 7.7.67
#------------------------------------------------------------------------------#

class EnhancedNSAPI(Uint8):
    pass


#------------------------------------------------------------------------------#
# Additional MBMS Trace Info
# TS 29.060, section 7.7.68
#------------------------------------------------------------------------------#

class AdditionalMBMSTraceInfo(Envelope):
    _GEN = (
        Uint24('TraceRef2', rep=REPR_HEX),
        Uint16('TraceRecSessRef', rep=REPR_HEX),
        Uint8('BMSCTriggeringEvents', rep=REPR_HEX),
        Uint8('TraceDepth'),
        Uint8('ListOfInterfaces', rep=REPR_HEX),
        Uint8('TraceActivityCtrl', dic={1: 'activation', 0: 'deactivation'})
        )


#------------------------------------------------------------------------------#
# MBMS Session Repetition Number
# TS 29.060, section 7.7.69
#------------------------------------------------------------------------------#

class MBMSSessionRepetitionNumber(Uint8):
    pass


#------------------------------------------------------------------------------#
# MBMS Time To Data Transfer
# TS 29.060, section 7.7.70
#------------------------------------------------------------------------------#

class MBMSTimeToDataTransfer(Uint8):
    pass


#------------------------------------------------------------------------------#
# Cell Identification
# TS 29.060, section 7.7.73
#------------------------------------------------------------------------------#

class _CellID(Envelope):
    _GEN = (
        RAI(),
        Uint16('CellID', rep=REPR_HEX)
        )


class _RNCID(Envelope):
    _GEN = (
        RAI(),
        Uint16('RNCID', rep=REPR_HEX)
        )


class CellIdent(Envelope):
    _GEN = (
        _CellID('TargetCellID'),
        Uint8('SourceType', val=0, dic={0: 'Source Cell ID', 1: 'Source RNC-ID'}),
        Alt('Source', GEN={
            0 : _CellID('CellID'),
            1 : _RNCID('RNCID')},
            sel=lambda self: self.get_env()['SourceType'].get_type(),
            DEFAULT=Buf('Unk', val=b'', rep=REPR_HEX)
            ),
        )


#------------------------------------------------------------------------------#
# PDU Numbers
# TS 29.060, section 7.7.74
#------------------------------------------------------------------------------#

class PDUNumbers(Envelope):
    # do not keep the extendable bits from the GTPv2 structure
    _GEN = tuple(GTPv2PDUNumbers()._content[0:-1])


#------------------------------------------------------------------------------#
# BSSGP Cause
# TS 29.060, section 7.7.75
#------------------------------------------------------------------------------#

class BSSGPCause(Uint8):
    pass


#------------------------------------------------------------------------------#
# Required MBMS Bearer Capabilities
# TS 29.060, section 7.7.76
#------------------------------------------------------------------------------#

class RequiredMBMSBearerCap(String):
    CODEC = 'utf8'


#------------------------------------------------------------------------------#
# RIM Routing Address Discriminator
# TS 29.060, section 7.7.77
#------------------------------------------------------------------------------#

_RIMRoutingAddrDiscriminator_dict = {
    0 : 'A Cell Identifier is used to identify a GERAN cell',
    1 : 'An RNC identifier is used to identify a UTRAN RNC',
    2 : 'An eNB identifier is used to identify an E-UTRAN eNodeB or HeNB',
    3 : 'An eHRPD Sector ID is used to identify an eHRPD eAN'
    }


class RIMRoutingAddrDiscriminator(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=4, rep=REPR_HEX),
        Uint('Value', bl=4)
        )


#------------------------------------------------------------------------------#
# List of set-up PFCs
# TS 29.060, section 7.7.78
#------------------------------------------------------------------------------#

class ListOfSetupPFCs(Envelope):
    _GEN = (
        Uint8('Num'),
        Sequence('PFIs', GEN=PacketFlowId('PFI'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Num'].set_valauto(lambda: self['PFIs'].get_num())
        self['PFIs'].set_numauto(lambda: self['Num'].get_val())


#------------------------------------------------------------------------------#
# PS Handover XID Parameters
# TS 29.060, section 7.7.79
#------------------------------------------------------------------------------#

class PSHandoverXIDParams(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=4, rep=REPR_HEX),
        Uint('SAPI', bl=4),
        Uint8('XIDParamsLen'),
        Buf('XIDParams', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['XIDParamsLen'].set_valauto(lambda: self['XIDParams'].get_len())
        self['XIDParams'].set_blauto(lambda: self['XIDParamsLen'].get_val()<<3)


#------------------------------------------------------------------------------#
# MS Info Change Reporting Action
# TS 29.060, section 7.7.80
#------------------------------------------------------------------------------#

class MSInfoChangeReportingAction(Uint8):
    _dic = {
        0 : 'stop reporting',
        1 : 'start reporting SGI/SAI',
        2 : 'start reporting RAI',
        }


#------------------------------------------------------------------------------#
# Direct Tunnel Flags
# TS 29.060, section 7.7.81
#------------------------------------------------------------------------------#

class DirectTunnelFlags(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=5, rep=REPR_HEX),
        Uint('EI', bl=1),
        Uint('GCSI', bl=1),
        Uint('DTI', bl=1)
        )


#------------------------------------------------------------------------------#
# Correlation-ID
# TS 29.060, section 7.7.82
#------------------------------------------------------------------------------#

class CorrelationID(Uint8):
    pass


#------------------------------------------------------------------------------#
# Bearer Control Mode
# TS 29.060, section 7.7.83
#------------------------------------------------------------------------------#

class BearerControlMode(Uint8):
    _dic = {
        0 : 'MS only',
        1 : 'MS / NW'
        }


#------------------------------------------------------------------------------#
# MBMS Flow Identifier
# TS 29.060, section 7.7.84
#------------------------------------------------------------------------------#

class MBMSFlowIdent(Uint16):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# MBMS IP Multicast Distribution
# TS 29.060, section 7.7.85
#------------------------------------------------------------------------------#

_AddrType_dict = {
    0 : 'IPv4',
    1 : 'IPv6'
    }


class MBMSIPMulticastDistrib(Envelope):
    _GEN = (
        Uint32('CommonTEID', rep=REPR_HEX),
        Uint('DistribAddrType', bl=2, dic=_AddrType_dict),
        Uint('DistribAddrLen', bl=6),
        IPAddr('DitribAddr'),
        Uint('SrcAddrType', bl=2, dic=_AddrType_dict),
        Uint('SrcAddrLen', bl=6),
        IPAddr('SrcAddr'),
        Uint8('MBMSHCInd'),
        )
    
    def __init__(self, *args, **kwargs):
        self['DistribAddrLen'].set_valauto(lambda: self['DistribAddr'].get_len())
        self['DistribAddr'].set_blauto(lambda: self['DistribAddrLen'].get_val()<<3)
        self['SrcAddrLen'].set_valauto(lambda: self['SrcAddr'].get_len())
        self['SrcAddr'].set_blauto(lambda: self['SrcAddrLen'].get_val()<<3)


#------------------------------------------------------------------------------#
# MBMS Distribution Acknowledgement
# TS 29.060, section 7.7.86
#------------------------------------------------------------------------------#

_DistribInd_dict = {
    0 : 'no RNCs have accepted IP multicast distribution',
    1 : 'all RNCs have accepted IP multicast distribution',
    2 : 'some RNCs have accepted IP multicast distribution',
    3 : 'for future use'
    }


class MBMSDistribAck(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('Ind', bl=2, dic=_DistribInd_dict)
        )


#------------------------------------------------------------------------------#
# Reliable INTER RAT HANDOVER INFO
# TS 29.060, section 7.7.87
#------------------------------------------------------------------------------#

class ReliableInterRATHandoverInfo(Uint8):
    pass


#------------------------------------------------------------------------------#
# RFSP Index
# TS 29.060, section 7.7.88
#------------------------------------------------------------------------------#

class RFSPIndex(Uint16):
    pass


#------------------------------------------------------------------------------#
# Evolved Allocation/Retention Priority I
# TS 29.060, section 7.7.91
#------------------------------------------------------------------------------#

class EvolvedAllocationRetentionPriorityI(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('PCI', bl=1),
        Uint('PL', bl=4),
        Uint('spare', bl=1),
        Uint('PVI', bl=1)
        )


#------------------------------------------------------------------------------#
# Evolved Allocation/Retention Priority II
# TS 29.060, section 7.7.92
#------------------------------------------------------------------------------#

class EvolvedAllocationRetentionPriorityII(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('NSAPI', val=5, bl=4),
        Uint('spare', bl=1),
        Uint('PCI', bl=1),
        Uint('PL', bl=4),
        Uint('spare', bl=1),
        Uint('PVI', bl=1)
        )


#------------------------------------------------------------------------------#
# Extended Common Flags
# TS 29.060, section 7.7.93
#------------------------------------------------------------------------------#

class ExtCommonFlags(Envelope):
    _GEN = (
        Uint('UASI', bl=1),
        Uint('BDWI', bl=1),
        Uint('PCRI', bl=1),
        Uint('VB', bl=1),
        Uint('RetLoc', bl=1),
        Uint('CPSR', bl=1),
        Uint('CCRSI', bl=1),
        Uint('UnauthIMSI', bl=1)
        )


#------------------------------------------------------------------------------#
# User CSG Information (UCI)
# TS 29.060, section 7.7.94
#------------------------------------------------------------------------------#

class UCI(Envelope):
    _GEN = (
        PLMN(),
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('CSGID', bl=27, rep=REPR_HEX),
        Uint('AccessMode', bl=2, dic={0: 'closed mode', 1: 'hybrid mode'}),
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('CMI', bl=1, dic={0: 'CSG membership', 1: 'non-CSG membership'})
        )


#------------------------------------------------------------------------------#
# CSG Information Reporting Action
# TS 29.060, section 7.7.95
#------------------------------------------------------------------------------#

class CSGInfoReportingAction(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('UCUHC', bl=1),
        Uint('UCSHC', bl=1),
        Uint('UCCSG', bl=1)
        )


#------------------------------------------------------------------------------#
# CSG ID
# TS 29.060, section 7.7.96
#------------------------------------------------------------------------------#

class CSGID(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('Value', bl=27, rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# CSG Membership Indication (CMI)
# TS 29.060, section 7.7.97
#------------------------------------------------------------------------------#

class CMI(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('Value', bl=1, dic={0: 'CSG membership', 1: 'non-CSG membership'})
        )


#------------------------------------------------------------------------------#
# UE-AMBR
# TS 29.060, section 7.7.100
#------------------------------------------------------------------------------#

class UEAMBR(Envelope):
    _GEN = (
        Uint32('ULSubscribedUEAMBR'),
        Uint32('DLSubscribedUEAMBR'),
        Uint32('ULAuthorizedUEAMBR'),
        Uint32('DLAuthorizedUEAMBR'),
        )


#------------------------------------------------------------------------------#
# APN-AMBR with NSAPI
# TS 29.060, section 7.7.101
#------------------------------------------------------------------------------#

class APNAMBRWithNSAPI(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('NSAPI', val=5, bl=4),
        Uint32('ULAuthorizedAPNAMBR'),
        Uint32('DLAuthorizedAPNAMBR'),
        )


#------------------------------------------------------------------------------#
# GGSN Back-Off Time
# TS 29.060, section 7.7.102
#------------------------------------------------------------------------------#

class GGSNBackOffTime(_Timer):
    pass


#------------------------------------------------------------------------------#
# Signalling Priority Indication
# TS 29.060, section 7.7.103
#------------------------------------------------------------------------------#

class SignallingPriorityInd(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('LAPI', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Signalling Priority Indication with NSAPI
# TS 29.060, section 7.7.104
#------------------------------------------------------------------------------#

class SignallingPriorityIndWithNSAPI(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('NSAPI', val=5, bl=4),
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('LAPI', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Higher bitrates than 16 Mbps flag
# TS 29.060, section 7.7.105
#------------------------------------------------------------------------------#

class HigherBitratesThan16MbpsFlag(Uint8):
    pass


#------------------------------------------------------------------------------#
# Additional Flags For SRVCC
# TS 29.060, section 7.7.108
#------------------------------------------------------------------------------#

class AdditionalFlagsForSRVCC(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('ICS', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX)
        )

#------------------------------------------------------------------------------#
# C-MSISDN
# TS 29.060, section 7.7.110
#------------------------------------------------------------------------------#

class CMSISDN(BufBCD):
    pass


#------------------------------------------------------------------------------#
# Extended RANAP Cause
# TS 29.060, section 7.7.111
#------------------------------------------------------------------------------#

class ExtRANAPCause(Envelope):
    _GEN = (
        Uint16('Value', rep=REPR_HEX), # RANAP Cause IE, APER encoded
        Buf('ext', val=b'', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# eNodeB ID
# TS 29.060, section 7.7.112
#------------------------------------------------------------------------------#

class ENodeBID(Envelope):
    _GEN = (
        Uint8('Type', val=0, dic={0: 'macro eNB-ID', 1: 'home-eNB-ID'}),
        PLMN(),
        Uint('spare', bl=4, rep=REPR_HEX),
        Alt('ID', GEN={
            0 : Uint('MacroENBID', bl=20, rep=REPR_HEX),
            1 : Uint('HomeENBID', bl=28, rep=REPR_HEX)
            },
            sel=lambda self: self.get_env()['Type'].get_val(),
            DEFAULT=Buf('Unk', val=b'', rep=REPR_HEX)),
        Uint16('TAC', rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# Selection Mode with NSAPI
# TS 29.060, section 7.7.113
#------------------------------------------------------------------------------#

class SelectionModeWithNSAPI(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('NSAPI', val=5, bl=4),
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('Value', val=0, bl=2, dic=_SelMode_dict),
        )


#------------------------------------------------------------------------------#
# ULI Timestamp
# TS 29.060, section 7.7.114
#------------------------------------------------------------------------------#

class ULITimestamp(Envelope):
    _GEN = (
        Uint32('Value'),
        Buf('ext', val=b'', rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# Local Home Network ID (LHN-ID) with NSAPI
# TS 29.060, section 7.7.115
#------------------------------------------------------------------------------#

class LocalHomeNetworkIDWithNSAPI(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('NSAPI', val=5, bl=4),
        FQDN('LHNID'),
        )


#------------------------------------------------------------------------------#
# CN Operator Selection Entity
# TS 29.060, section 7.7.116
#------------------------------------------------------------------------------#

class CNOperatorSelectionEntity(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('Value', val=0, bl=2, dic={
            0: 'Serving Network has been selected by the UE',
            1: 'Serving Network has been selected by the network'}),
        Buf('ext', val=b'', rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# UE Usage Type
# TS 29.060, section 7.7.117
#------------------------------------------------------------------------------#

class UEUsageType(Uint32):
    pass


#------------------------------------------------------------------------------#
# Extended Common Flags II
# TS 29.060, section 7.7.118
#------------------------------------------------------------------------------#

class ExtCommonFlagsII(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('PMTSMI', bl=1),
        Uint('DTCI', bl=1),
        Uint('PNSI', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# CIoT Optimizations Support Indication
# TS 29.060, section 7.7.120
#------------------------------------------------------------------------------#

class CIoTOptimSupportInd(Envelope):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('SCNIPDN', bl=1),
        Uint('SGNIPDN ', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# SCEF PDN Connection
# TS 29.060, section 7.7.121
#------------------------------------------------------------------------------#

class SCEFPDNConnection(Envelope):
    _GEN = (
        Uint8('APNLen'),
        APN(),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('NSAPI', val=5, bl=4),
        Uint16('SCEFIDLen'),
        Buf('SCEFID'),
        Buf('ext', val=b'', rep=REPR_HEX),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['APNLen'].set_valauto(lambda: self['APN'].get_len())
        self['APN'].set_blauto(lambda: self['APNLen'].get_val()<<3)
        self['SCEFIDLen'].set_valauto(lambda: self['SCEFID'].get_len())
        self['SCEFID'].set_blauto(lambda: self['SCEFIDLen'].get_val()<<3)


#------------------------------------------------------------------------------#
# IOV_updates counter
# TS 29.060, section 7.7.122
#------------------------------------------------------------------------------#

class IOVUpdatesCounter(Uint8):
    pass


#------------------------------------------------------------------------------#
# UP Function Selection Indication Flags
# TS 29.060, section 7.7.124
#------------------------------------------------------------------------------#

class UPFSelectionIndFlags(Envelope):
    _GEN = (
        Uint('spare', bl=7, rep=REPR_HEX),
        Uint('DCNR', bl=1),
        Buf('ext', val=b'', rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# Address of Recommended Node
# TS 32.295, section 6.2.4.3
#------------------------------------------------------------------------------#

class RecommendedNodeAddr(IPAddr):
    pass


#------------------------------------------------------------------------------#
# Packet Transfer Command IE
# TS 32.295, section 6.2.4.5.2
#------------------------------------------------------------------------------#

class PacketTransferCmd(Uint8):
    _dic = {
        1 : 'Send Data Record Packet',
        2 : 'Send possibly duplicated Data Record Packet',
        3 : 'Cancel Data Record Packet',
        4 : 'Release Data Record Packet',
        }


#------------------------------------------------------------------------------#
# Data Record Packet IE
# TS 32.295, section 6.2.4.5.3
#------------------------------------------------------------------------------#

class _DataRecord(Envelope):
    
    _GEN = (
        Uint8('Len'),
        Buf('Val', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


class DataRecordPacket(Envelope):
    _GEN = (
        Uint8('Num'),
        Uint8('Fmt', dic={0: 'reserved', 1: 'ASN.1 BER', 2: 'ASN.1 UPER', 3: 'ASN.1 APER'}),
        Envelope('Vers', GEN=(
            Uint('AppID', val=1, bl=4, dic={1: 'charging'}),
            Uint('RelID', val=0, bl=4),
            Uint8('VersID', val=1),
            Uint8('RelIDExt', val=16)
            )),
        Sequence('Recs', GEN=_DataRecord('Rec'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Num'].set_valauto(lambda: self['Recs'].get_num())
        self['Recs'].set_numauto(lambda: self['Num'].get_val())


#------------------------------------------------------------------------------#
# Sequence Numbers of Released Packets IE
# TS 32.295, section 6.2.4.5.4
#------------------------------------------------------------------------------#

class SeqNumReleasedPackets(Array):
    _GEN = Uint16('SeqNum')


#------------------------------------------------------------------------------#
# Sequence Numbers of Cancelled Packets IE
# TS 32.295, section 6.2.4.5.5
#------------------------------------------------------------------------------#

class SeqNumCancelledPackets(Array):
    _GEN = Uint16('SeqNum')


#------------------------------------------------------------------------------#
# Requests Responded
# TS 32.295, section 6.2.4.6
#------------------------------------------------------------------------------#

class RequestsResponded(Array):
    _GEN = Uint16('SeqNum')


#------------------------------------------------------------------------------#
# GTP Information Elements, general section
# TS 29.060, section 7.7.0
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
    126 : ('TV', 1, 'Packet Transfer Command', 'PacketTransferCmd'),
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
    152 : ('TLV', -1, 'User Location Information', 'ULI'),
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
    166 : ('TLV', 1, 'MBMS 2G/3G Indicator', 'MBMS2G3GInd'),
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
    180 : ('TLV', -1, 'PS Handover XID Parameters', 'PSHandoverXIDParams'),
    181 : ('TLV', 1, 'MS Info Change Reporting Action', 'MSInfoChangeReportingAction'),
    182 : ('TLV', -1, 'Direct Tunnel Flags', 'DirectTunnelFlags'),
    183 : ('TLV', 1, 'Correlation-ID', 'CorrelationID'),
    184 : ('TLV', 1, 'Bearer Control Mode', 'BearerControlMode'),
    185 : ('TLV', -1, 'MBMS Flow Identifier', 'MBMSFlowIdent'),
    186 : ('TLV', -1, 'MBMS IP Multicast Distribution', 'MBMSIPMulticastDistrib'),
    187 : ('TLV', 1, 'MBMS Distribution Acknowledgement', 'MBMSDistribAck'),
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
    199 : ('TLV', -1, 'UE Network Capability', 'UENetCap'),
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
    220 : ('TLV', -1, 'CIoT Optimizations Support Indication', 'CIoTOptimSupportInd'),
    221 : ('TLV', -1, 'SCEF PDN Connection', 'SCEFPDNConnection'),
    222 : ('TLV', 1, 'IOV_updates counter', 'IOVUpdatesCounter'),
    223 : ('TLV', -1, 'Mapped UE Usage Type', 'MappedUEUsageType'),
    224 : ('TLV', -1, 'UP Function Selection Indication Flags', 'UPFSelectionIndFlags'),
    238 : ('TLV', -1, 'Special IE type for IE Type Extension', 'IETypeExt'),
    249 : ('TLV', -1, 'Sequence Numbers of Released Packets', 'SeqNumReleasedPackets'),
    250 : ('TLV', -1, 'Sequence Numbers of Cancelled Packets', 'SeqNumCancelledPackets'),
    251 : ('TLV', -1, 'Charging Gateway Address', 'ChargingGatewayAddr'),
    252 : ('TLV', -1, 'Data Record Packet', 'DataRecordPacket'),
    253 : ('TLV', -1, 'Requests Responded', 'RequestsResponded'),
    254 : ('TLV', -1, 'Recommended Node Address', 'RecommendedNodeAddr'),
    255 : ('TLV', -1, 'Private Extension', 'PrivateExt')
    }

# LUT for IE resolving (name: class)
GTPIELUT = {}
_globals = globals()
_undef   = {
    'Reserved',
    'UTRANTransparentContainer',
    'TriggerId',
    'OMCIdentity',
    'RANTransparentContainer',
    'PDPContextPrioritization',
    'CAMELChargingInfoContainer',
    'SourceRNCPDCPContextInfo',
    'BSSContainer',
    'IETypeExt',
    }
for k, infos in GTPIEType_dict.items():
    if infos[3] in _globals:
        GTPIELUT[k] = _globals[infos[3]]
    elif infos[3] not in _undef:
        print('warning: %s undefined' % infos[3])
del _globals, _undef
# enumeration for all IEs (name: type)
GTPIEType = IntEnum('GTPIEType', {v[3]: k for k, v in GTPIEType_dict.items()})
# dict for IE description (type: desc)
GTPIETypeDesc_dict = {k: v[2] for k, v in GTPIEType_dict.items()}



class _GTPIE(Envelope):
    """parent class for all GTPv1-C Information Element
    """
    
    # TODO: check how to switch optional IE to present when assigning them a value
    #       maybe do it at __init__, similar as with NAS IE in TS24007.py
    
    # those are required for the set_val() method
    _KW_STAT = set()
    _KW_STAT_LEN = 0
    
    def set_val(self, val):
        # remove the `Data' part from `val'
        val_data = None
        if isinstance(val, dict) and 'Data' in val and val['Data'] is not None:
            val_data = val['Data']
            val = dict(val)
            val['Data'] = None
        elif isinstance(val, (tuple, list)):
            if val[0] == 238 and len(val) == 1+self._KW_STAT_LEN and val[self._KW_STAT_LEN] is not None:
                val_data = val[self._KW_STAT_LEN]
                val = list(val)
                val[self._KW_STAT_LEN] = None
            elif len(val) == self._KW_STAT_LEN and val[self._KW_STAT_LEN-1] is not None:
                val_data = val[self._KW_STAT_LEN-1]
                val = list(val)
                val[self._KW_STAT_LEN-1] = None
        # set the 1st part of `val' without `Data'
        Envelope.set_val(self, val)
        #print('_GTPIE.set_val(%r), val_data: %r' % (val, val_data))
        if val_data is not None:
            # replace the `Data' buffer with the IE sub-structure
            typ = self.get_type()
            if typ in GTPIELUT:
                ie = GTPIELUT[typ]()
                if self['Data']._blauto and (not hasattr(ie, '_bl') or ie._bl is None):
                    ie._blauto = self['Data']._blauto
                ie._name = 'Data'
                try:
                    ie.set_val(val_data)
                except Exception:
                    self['Data'].set_val(val_data)
                else:
                    self.replace(self['Data'], ie)
            else:
                self['Data'].set_val(val_data)
        else:
            self['Data'].set_val(None)
    
    def _from_char(self, char):
        Envelope._from_char(self, char)
        # check if a sub-structure is available to replace the Data buffer
        typ = self.get_type()
        if typ in GTPIELUT:
            ie = GTPIELUT[typ]()
            try:
                ie.from_bytes(self['Data'].to_bytes())
            except PycrateErr:
                # TODO: it may be better to raise here...
                pass
            else:
                if self['Data']._blauto and (not hasattr(ie, '_bl') or ie._bl is None):
                    ie._blauto = self['Data']._blauto
                ie._name = 'Data'
                self.replace(self['Data'], ie)
    
    def set_ie_class(self):
        # this is to simply set the internal IE structure, if exists
        typ = self.get_type()
        try:
            ie = GTPIELUT[typ]()
        except KeyError:
            pass
        else:
            if self['Data']._blauto and (not hasattr(ie, '_bl') or ie._bl is None):
                ie._blauto = self['Data']._blauto
            ie._name = 'Data'
            self.replace(self['Data'], ie)


class GTPIETV(_GTPIE):
    """GTPv1-C Information Element in Tag-Value format, with fixed length
    """
    _KW_STAT     = {'Type'}
    _KW_STAT_LEN = 2
    
    _GEN = (
        Uint8('Type', val=1, dic=GTPIETypeDesc_dict),
        Buf('Data', bl=8, rep=REPR_HEX)
        )
    
    def get_type(self):
        return self[0].get_val()


class GTPIETLV(_GTPIE):
    """GTPv1-C Information Element in Tag-Length-Value format
    """
    _KW_STAT = {'Type', 'Len', 'TypeExt'}
    _KW_STAT_LEN = 3
    
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
    # this routine can raise, and needs to be used inside a try-except stmt
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
    
    # MAND and OPT attributes are set for each GTPIEs subclass
    MAND = set()
    OPT  = set()
    
    # this is to raise in case a mandatory IE is not found during the decoding
    VERIF_MAND = True
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
    
    def _from_char(self, char):
        if self.get_trans():
            return
        #
        # Go over all defined IE in the content 1 by 1
        # checking against the type decoded
        # jumping over optional / conditional IE not present
        # decoding as much PrivateExt as present (can be set mutliple times)
        #
        i, len_cont = 0, len(self._content)
        while char.len_byte() >= 1 and i < len_cont:
            ie = self._content[i]
            try:
                char_type = _get_type_from_char(char)
            except CharpyErr:
                # not enough buffer available
                break
            else:
                if char_type == ie.get_type():
                    if ie._trans:
                        # optional IE which is to be decoded
                        ie._trans = False
                    ie._from_char(char)
                elif ie._name in self.MAND and self.VERIF_MAND:
                    # mandatory IE which is not present
                    raise(GTPDecErr('Missing mandatory GTP IE %s, type %i' % (ie._name, ie.get_type())))
                if char_type != 255:
                    # PrivateExt IE is always the last defined IE
                    # and can be present multiple times,
                    # otherwise we go to the next IE
                    i += 1
        #
        if i < len_cont-1 and self.VERIF_MAND:
            # verify if some trailing mandatory IE have been ignored
            for ie in self._content[i:]:
                if ie.get_type() in self.MAND:
                    raise(GTPDecErr('Missing mandatory GTP IE %s, type %i' % (ie._name, ie.get_type())))
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
    
    def add_ie(self, ie_name, val=None):
        """add the IE with the given identifier `ie_name` and sets the value `val` 
        (raw bytes buffer or structured data) into its data part
        """
        ie = self[ie_name]
        if ie.get_trans():
            ie.set_trans(False)
        if val is not None:
            ie.set_val(val)
        else:
            ie.set_ie_class()
    
    def rem_ie(self, ie_name):
        """remove the IE with the given identifier `ie_name`
        """
        ie = self[ie_name]
        if not ie.get_trans():
            ie.set_trans(True)
    
    def init_ies(self, wopt=False, **kwargs):
        """initialize all IEs that are mandatory,
        adding optional ones if `wopt` is set,
        adding the private extension if `wpriv` is set
        """
        # clear the content first
        for ie in self._content:
            if ie._name in self.OPT and wopt:
                ie.set_trans(False)
            ie.set_ie_class()


#------------------------------------------------------------------------------#
# GTP Extension Header
# TS 29.060, section 6.1
#------------------------------------------------------------------------------#
# GTPNextExtHeader_dict: defined in 7.7.40 for the ExtHeaderTypeList IE

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
        Uint('PT', val=1, bl=1, dic=ProtType_dict), # 1 for GTP 29.060, 0 for GTP' 32.295
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
# GTP Message
# TS 29.060, section 7
#------------------------------------------------------------------------------#

class GTPMsg(Envelope):
    """parent class for all GTPv1-C messages
    """
    
    # MAND and OPT class attributes are generated when module is loaded
    # each one is a set listing IE types that are mandatory, respectively optional
    
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

class EchoReqIEs(GTPIEs):
    
    MAND = set()
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class EchoReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.EchoReq.value}),
        EchoReqIEs(hier=1),
        )


# Echo Response

class EchoRespIEs(GTPIEs):
    
    MAND = {
        'Recovery'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class EchoResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.EchoResp.value}),
        EchoRespIEs(hier=1),
        )


# Version Not Supported

class VersionNotSupportedIEs(GTPIEs):
    
    MAND = set()
    OPT  = set()
    
    _GEN = ()


class VersionNotSupported(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.VersionNotSupported.value}),
        VersionNotSupportedIEs(hier=1),
        )


# Supported Extension Headers Notification

class SupportedExtHeadersNotifIEs(GTPIEs):
    
    MAND = {
        'ExtHeaderTypeList'
        }
    OPT  = set()
    
    _GEN = (
        GTPIETLV('ExtHeaderTypeList', val={'Type': GTPIEType.ExtHeaderTypeList.value}),
        )


class SupportedExtHeadersNotif(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.SupportedExtHeadersNotif.value}),
        SupportedExtHeadersNotifIEs(hier=1),
        )


#------------------------------------------------------------------------------#
# 7.3 Tunnel Management Messages
#------------------------------------------------------------------------------#
# interface between SGSN and GGSN

# Create PDP Context Request

class CreatePDPCtxtReqIEs(GTPIEs):
    
    MAND = {
        'TEIDDataI',
        'NSAPI',
        'SGSNAddrForSignalling',
        'SGSNAddrForUserTraffic',
        'QoSProfile'
        }
    OPT  = {
        'IMSI',
        'RAI',
        'Recovery',
        'SelectionMode',
        'TEIDCP',
        'LinkedNSAPI',
        'ChargingCharacteristics',
        'TraceReference',
        'TraceType',
        'EndUserAddr',
        'APN',
        'PCO',
        'MSISDN',
        'TFT',
        'TriggerId',
        'OMCIdentity',
        'CommonFlags',
        'APNRestriction',
        'RATType',
        'ULI',
        'MSTimeZone',
        'IMEI',
        'CAMELChargingInfoContainer',
        'AdditionalTraceInfo',
        'CorrelationID',
        'EvolvedAllocationRetentionPriorityI',
        'ExtCommonFlags',
        'UCI',
        'APNAMBR',
        'SignallingPriorityInd',
        'CNOperatorSelectionEntity',
        'MappedUEUsageType',
        'UPFSelectionIndFlags',
        'PrivateExt'
        }
    
    _GEN = (
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
        GTPIETLV('ULI', val={'Type': GTPIEType.ULI.value}, trans=True),
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
        )


class CreatePDPCtxtReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.CreatePDPCtxtReq.value}),
        CreatePDPCtxtReqIEs(hier=1),
        )


# Create PDP Context Response

class CreatePDPCtxtRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'ReorderingRequired',
        'Recovery',
        'TEIDDataI',
        'TEIDCP',
        'NSAPI',
        'ChargingID',
        'EndUserAddr',
        'PCO',
        'GGSNAddrForControlPlane',
        'GGSNAddrForUserTraffic',
        'AltGGSNAddrForControlPlane',
        'AltGGSNAddrForUserTraffic',
        'QoSProfile',
        'ChargingGatewayAddr',
        'AltChargingGatewayAddr',
        'CommonFlags',
        'APNRestriction',
        'MSInfoChangeReportingAction',
        'BearerControlMode',
        'EvolvedAllocationRetentionPriorityI',
        'ExtCommonFlags',
        'CSGInfoReportingAction',
        'APNAMBR',
        'GGSNBackOffTime',
        'ExtCommonFlagsII',
        'PrivateExt'
        }
    
    _GEN = (
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
        )


class CreatePDPCtxtResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.CreatePDPCtxtResp.value}),
        CreatePDPCtxtRespIEs(hier=1),
        )


# SGSN-Initiated Update PDP Context Request

class UpdatePDPCtxtReqSGSNIEs(GTPIEs):
    
    MAND = {
        'TEIDDataI',
        'NSAPI',
        'SGSNAddrForControlPlane',
        'SGSNAddrForUserTraffic',
        'QoSProfile'
        }
    OPT  = {
        'IMSI',
        'RAI',
        'Recovery',
        'TEIDCP',
        'TraceReference',
        'TraceType',
        'PCO',
        'AltSGSNAddrForControlPlane',
        'AltSGSNAddrForUserTraffic',
        'TFT',
        'TriggerId',
        'OMCIdentity',
        'CommonFlags',
        'RATType',
        'ULI',
        'MSTimeZone',
        'AdditionalTraceInfo',
        'DirectTunnelFlags',
        'EvolvedAllocationRetentionPriorityI',
        'ExtCommonFlags',
        'UCI',
        'APNAMBR',
        'SignallingPriorityInd',
        'CNOperatorSelectionEntity',
        'IMEI',
        'PrivateExt'
        }
    
    _GEN = (
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
        GTPIETLV('ULI', val={'Type': GTPIEType.ULI.value}, trans=True),
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
        )


class UpdatePDPCtxtReqSGSN(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.UpdatePDPCtxtReq.value}),
        UpdatePDPCtxtReqSGSNIEs(hier=1),
        )


# GGSN-Initiated Update PDP Context Request

class UpdatePDPCtxtReqGGSNIEs(GTPIEs):
    
    MAND = {
        'NSAPI'
        }
    OPT  = {
        'IMSI',
        'Recovery',
        'EndUserAddr',
        'PCO',
        'QoSProfile',
        'TFT',
        'CommonFlags',
        'APNRestriction',
        'MSInfoChangeReportingAction',
        'DirectTunnelFlags',
        'BearerControlMode',
        'EvolvedAllocationRetentionPriorityI',
        'ExtCommonFlags',
        'CSGInfoReportingAction',
        'APNAMBR',
        'PrivateExt'
        }
    
    _GEN = (
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
        )


class UpdatePDPCtxtReqGGSN(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.UpdatePDPCtxtReq.value}),
        UpdatePDPCtxtReqGGSNIEs(hier=1),
        )


# Update PDP Context Response sent by a GGSN

class UpdatePDPCtxtRespGGSNIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'Recovery',
        'TEIDDataI',
        'TEIDCP',
        'ChargingID',
        'PCO',
        'GGSNAddrForControlPlane',
        'GGSNAddrForUserTraffic',
        'AltGGSNAddrForControlPlane',
        'AltGGSNAddrForUserTraffic',
        'QoSProfile',
        'ChargingGatewayAddr',
        'AltChargingGatewayAddr',
        'CommonFlags',
        'APNRestriction',
        'BearerControlMode',
        'MSInfoChangeReportingAction',
        'EvolvedAllocationRetentionPriorityI',
        'CSGInfoReportingAction',
        'APNAMBR',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
        GTPIETV('TEIDDataI', val={'Type': GTPIEType.TEIDDataI.value}, bl={'Data': 32}, trans=True),
        GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
        GTPIETV('ChargingID', val={'Type': GTPIEType.ChargingID.value}, bl={'Data': 32}, trans=True),
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
        GTPIETLV('BearerControlMode', val={'Type': GTPIEType.BearerControlMode.value}, trans=True),
        GTPIETLV('MSInfoChangeReportingAction', val={'Type': GTPIEType.MSInfoChangeReportingAction.value}, trans=True),
        GTPIETLV('EvolvedAllocationRetentionPriorityI', val={'Type': GTPIEType.EvolvedAllocationRetentionPriorityI.value}, trans=True),
        GTPIETLV('CSGInfoReportingAction', val={'Type': GTPIEType.CSGInfoReportingAction.value}, trans=True),
        GTPIETLV('APNAMBR', val={'Type': GTPIEType.AMBR.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class UpdatePDPCtxtRespGGSN(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.UpdatePDPCtxtResp.value}),
        UpdatePDPCtxtRespGGSNIEs(hier=1),
        )


# Update PDP Context Response sent by a SGSN

class UpdatePDPCtxtRespSGSNIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'Recovery',
        'TEIDDataI',
        'PCO',
        'SGSNAddrForUserTraffic',
        'QoSProfile',
        'ULI',
        'MSTimeZone',
        'DirectTunnelFlags',
        'EvolvedAllocationRetentionPriorityI',
        'APNAMBR',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
        GTPIETV('TEIDDataI', val={'Type': GTPIEType.TEIDDataI.value}, bl={'Data': 32}, trans=True),
        GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
        GTPIETLV('SGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('QoSProfile', val={'Type': GTPIEType.QoSProfile.value}, trans=True),
        GTPIETLV('ULI', val={'Type': GTPIEType.ULI.value}, trans=True),
        GTPIETLV('MSTimeZone', val={'Type': GTPIEType.MSTimeZone.value}, trans=True),
        GTPIETLV('DirectTunnelFlags', val={'Type': GTPIEType.DirectTunnelFlags.value}, trans=True),
        GTPIETLV('EvolvedAllocationRetentionPriorityI', val={'Type': GTPIEType.EvolvedAllocationRetentionPriorityI.value}, trans=True),
        GTPIETLV('APNAMBR', val={'Type': GTPIEType.AMBR.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class UpdatePDPCtxtRespSGSN(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.UpdatePDPCtxtResp.value}),
        UpdatePDPCtxtRespSGSNIEs(hier=1),
        )


# Delete PDP Context Request

class DeletePDPCtxtReqIEs(GTPIEs):
    
    MAND = {
        'NSAPI'
        }
    OPT  = {
        'Cause',
        'TeardownInd',
        'PCO',
        'ULI',
        'MSTimeZone',
        'ExtCommonFlags',
        'ULITimestamp',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}, trans=True),
        GTPIETV('TeardownInd', val={'Type': GTPIEType.TeardownInd.value}, bl={'Data': 8}, trans=True),
        GTPIETV('NSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}),
        GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
        GTPIETLV('ULI', val={'Type': GTPIEType.ULI.value}, trans=True),
        GTPIETLV('MSTimeZone', val={'Type': GTPIEType.MSTimeZone.value}, trans=True),
        GTPIETLV('ExtCommonFlags', val={'Type': GTPIEType.ExtCommonFlags.value}, trans=True),
        GTPIETLV('ULITimestamp', val={'Type': GTPIEType.ULITimestamp.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class DeletePDPCtxtReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.DeletePDPCtxtReq.value}),
        DeletePDPCtxtReqIEs(hier=1),
        )


# Delete PDP Context Response

class DeletePDPCtxtRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PCO',
        'ULI',
        'MSTimeZone',
        'ULITimestamp',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
        GTPIETLV('ULI', val={'Type': GTPIEType.ULI.value}, trans=True),
        GTPIETLV('MSTimeZone', val={'Type': GTPIEType.MSTimeZone.value}, trans=True),
        GTPIETLV('ULITimestamp', val={'Type': GTPIEType.ULITimestamp.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class DeletePDPCtxtResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.DeletePDPCtxtResp.value}),
        DeletePDPCtxtRespIEs(hier=1),
        )


# Error Indication

class ErrorIndIEs(GTPIEs):
    
    MAND = {
        'TEIDDataI',
        'GTPUPeerAddr'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('TEIDDataI', val={'Type': GTPIEType.TEIDDataI.value}, bl={'Data': 32}),
        GTPIETLV('GTPUPeerAddr', val={'Type': GTPIEType.GSNAddr.value}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class ErrorInd(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.ErrorInd.value}),
        ErrorIndIEs(hier=1),
        )


# PDU Notification Request

class PDUNotifReqIEs(GTPIEs):
    
    MAND = {
        'IMSI',
        'TEIDCP',
        'EndUserAddr',
        'APN',
        'GGSNAddrForControlPlane'
        }
    OPT  = {
        'PCO',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}),
        GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}),
        GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
        GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
        GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
        GTPIETLV('GGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class PDUNotifReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.PDUNotifReq.value}),
        PDUNotifReqIEs(hier=1),
        )


# PDU Notification Response

class PDUNotifRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class PDUNotifResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.PDUNotifResp.value}),
        PDUNotifRespIEs(hier=1),
        )


# PDU Notification Reject Request

class PDUNotifRejectReqIEs(GTPIEs):
    
    MAND = {
        'Cause',
        'TEIDCP',
        'EndUserAddr',
        'APN'
        }
    OPT  = {
        'PCO',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}),
        GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
        GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
        GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class PDUNotifRejectReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.PDUNotifRejectReq.value}),
        PDUNotifRejectReqIEs(hier=1),
        )


# PDU Notification Reject Response

class PDUNotifRejectRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class PDUNotifRejectResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.PDUNotifRejectResp.value}),
        PDUNotifRejectRespIEs(hier=1),
        )


# Initiate PDP Context Activation Request

class InitiatePDPCtxtActivationReqIEs(GTPIEs):
    
    MAND = {
        'LinkedNSAPI',
        'QoSProfile',
        'CorrelationID'
        }
    OPT  = {
        'PCO',
        'TFT',
        'EvolvedAllocationRetentionPriorityI',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('LinkedNSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}),
        GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
        GTPIETLV('QoSProfile', val={'Type': GTPIEType.QoSProfile.value}),
        GTPIETLV('TFT', val={'Type': GTPIEType.TFT.value}, trans=True),
        GTPIETLV('CorrelationID', val={'Type': GTPIEType.CorrelationID.value}),
        GTPIETLV('EvolvedAllocationRetentionPriorityI', val={'Type': GTPIEType.EvolvedAllocationRetentionPriorityI.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class InitiatePDPCtxtActivationReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.InitiatePDPCtxtActivationReq.value}),
        InitiatePDPCtxtActivationReqIEs(hier=1),
        )


# Initiate PDP Context Activation Response

class InitiatePDPCtxtActivationRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PCO',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('PCO', val={'Type': GTPIEType.PCO.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class InitiatePDPCtxtActivationResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.InitiatePDPCtxtActivationResp.value}),
        InitiatePDPCtxtActivationRespIEs(hier=1),
        )


#------------------------------------------------------------------------------#
# 7.4 Location Management Messages
#------------------------------------------------------------------------------#
# optional interface between HLR and GGSN within a PLMN
# Eventually supported through GTP / TCAP-MAP interworking

# Send Routeing Information for GPRS Request

class SendRouteingInfoforGPRSReqIEs(GTPIEs):
    
    MAND = {
        'IMSI'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class SendRouteingInfoforGPRSReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.SendRouteingInfoforGPRSReq.value}),
        SendRouteingInfoforGPRSReqIEs(hier=1),
        )


# Send Routeing Information for GPRS Response

class SendRouteingInfoforGPRSRespIEs(GTPIEs):
    
    MAND = {
        'Cause',
        'IMSI'
        }
    OPT  = {
        'MAPCause',
        'MSNotReachableReason',
        'GSNAddr',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}),
        GTPIETV('MAPCause', val={'Type': GTPIEType.MAPCause.value}, bl={'Data': 8}, trans=True),
        GTPIETV('MSNotReachableReason', val={'Type': GTPIEType.MSNotReachableReason.value}, bl={'Data': 8}, trans=True),
        GTPIETLV('GSNAddr', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class SendRouteingInfoforGPRSResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.SendRouteingInfoforGPRSResp.value}),
        SendRouteingInfoforGPRSRespIEs(hier=1),
        )


# Failure Report Request

class FailureReportReqIEs(GTPIEs):
    
    MAND = {
        'IMSI'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class FailureReportReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.FailureReportReq.value}),
        FailureReportReqIEs(hier=1),
        )


# Failure Report Response

class FailureReportRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'MAPCause',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('MAPCause', val={'Type': GTPIEType.MAPCause.value}, bl={'Data': 8}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class FailureReportResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.FailureReportResp.value}),
        FailureReportRespIEs(hier=1),
        )


# Note MS Present Request

class NoteMSGPRSPresentReqIEs(GTPIEs):
    
    MAND = {
        'IMSI',
        'GSNAddr'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}),
        GTPIETLV('GSNAddr', val={'Type': GTPIEType.GSNAddr.value}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class NoteMSGPRSPresentReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.NoteMSGPRSPresentReq.value}),
        NoteMSGPRSPresentReqIEs(hier=1),
        )


# Note MS Present Response

class NoteMSGPRSPresentRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class NoteMSGPRSPresentResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.NoteMSGPRSPresentResp.value}),
        NoteMSGPRSPresentRespIEs(hier=1),
        )


#------------------------------------------------------------------------------#
# 7.5 Mobility Management Messages
#------------------------------------------------------------------------------#
# interface between SGSNs within a PLMN

# Identification Request

class IdentificationReqIEs(GTPIEs):
    
    MAND = {
        'RAI',
        'PTMSI'
        }
    OPT  = {
        'PTMSISignature',
        'SGSNAddrForControlPlane',
        'HopCounter',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('RAI', val={'Type': GTPIEType.RAI.value}, bl={'Data': 48}),
        GTPIETV('PTMSI', val={'Type': GTPIEType.PTMSI.value}, bl={'Data': 32}),
        GTPIETV('PTMSISignature', val={'Type': GTPIEType.PTMSISignature.value}, bl={'Data': 24}, trans=True),
        GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('HopCounter', val={'Type': GTPIEType.HopCounter.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class IdentificationReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.IdentificationReq.value}),
        IdentificationReqIEs(hier=1),
        )


# Identification Response

class IdentificationRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'IMSI',
        'AuthentTriplet',
        'AuthentQuintuplet',
        'UEUsageType',
        'IOVUpdatesCounter'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
        GTPIETV('AuthentTriplet', val={'Type': GTPIEType.AuthentTriplet.value}, bl={'Data': 224}, trans=True),
        GTPIETLV('AuthentQuintuplet', val={'Type': GTPIEType.AuthentQuintuplet.value}, trans=True),
        GTPIETLV('UEUsageType', val={'Type': GTPIEType.UEUsageType.value}, trans=True),
        GTPIETLV('IOVUpdatesCounter', val={'Type': GTPIEType.IOVUpdatesCounter.value}, trans=True),
        )


class IdentificationResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.IdentificationResp.value}),
        IdentificationRespIEs(hier=1),
        )


# SGSN Context Request

class SGSNCtxtReqIEs(GTPIEs):
    
    MAND = {
        'RAI',
        'TEIDCP',
        'SGSNAddrForControlPlane'
        }
    OPT  = {
        'IMSI',
        'TLLI',
        'PTMSI',
        'PTMSISignature',
        'MSValidated',
        'AltSGSNAddrForControlPlane',
        'SGSNNumber',
        'RATType',
        'HopCounter',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
        GTPIETV('RAI', val={'Type': GTPIEType.RAI.value}, bl={'Data': 48}),
        GTPIETV('TLLI', val={'Type': GTPIEType.TLLI.value}, bl={'Data': 8}, trans=True),
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
        )


class SGSNCtxtReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.SGSNCtxtReq.value}),
        SGSNCtxtReqIEs(hier=1),
        )


# SGSN Context Response

class SGSNCtxtRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'IMSI',
        'TEIDCP',
        'RABContext',
        'RadioPrioritySMS',
        'RadioPriority',
        'PacketFlowId',
        'ChargingCharacteristics',
        'RadioPriorityLCS',
        'MMContext',
        'PDPContext',
        'SGSNAddrForControlPlane',
        'PDPContextPrioritization',
        'MBMSUEContext',
        'SubscribedRFSPIndex',
        'RFSPIndex',
        'ColocatedGGSNPGWFQDN',
        'EvolvedAllocationRetentionPriorityII',
        'ExtCommonFlags',
        'UENetCap',
        'UEAMBR',
        'APNAMBRWithNSAPI',
        'SignallingPriorityIndWithNSAPI',
        'HigherBitratesThan16MbpsFlag',
        'SelectionModeWithNSAPI',
        'LocalHomeNetworkIDWithNSAPI',
        'UEUsageType',
        'ExtCommonFlagsII',
        'UESCEFPDNConnection',
        'IOVUpdatesCounter',
        'AltGGSNAddrForControlPlane',
        'AltGGSNAddrForUserTraffic',
        'PrivateExt'
        }
    
    _GEN = (
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
        GTPIETLV('UENetCap', val={'Type': GTPIEType.UENetCap.value}, trans=True),
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
        )


class SGSNCtxtResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.SGSNCtxtResp.value}),
        SGSNCtxtRespIEs(hier=1),
        )


# SGSN Context Acknowledge

class SGSNCtxtAckIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'TEIDDataII',
        'SGSNAddrForUserTraffic',
        'SGSNNumber',
        'NodeIdent',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('TEIDDataII', val={'Type': GTPIEType.TEIDDataII.value}, bl={'Data': 40}, trans=True),
        GTPIETLV('SGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('SGSNNumber', val={'Type': GTPIEType.SGSNNumber.value}, trans=True),
        GTPIETLV('NodeIdent', val={'Type': GTPIEType.NodeIdent.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class SGSNCtxtAck(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.SGSNCtxtAck.value}),
        SGSNCtxtAckIEs(hier=1),
        )


# Forward Relocation Request

class ForwardRelocationReqIEs(GTPIEs):
    
    MAND = {
        'TEIDCP',
        'RANAPCause',
        'MMContext',
        'TargetIdent',
        'UTRANTransparentContainer'
        }
    OPT  = {
        'IMSI',
        'PacketFlowId',
        'ChargingCharacteristics',
        'PDPContext',
        'SGSNAddrForControlPlane',
        'PDPContextPrioritization',
        'MBMSUEContext',
        'SelectedPLMNID',
        'BSSContainer',
        'CellIdent',
        'BSSGPCause',
        'PSHandoverXIDParams',
        'DirectTunnelFlags',
        'ReliableInterRATHandoverInfo',
        'SubscribedRFSPIndex',
        'RFSPIndex',
        'ColocatedGGSNPGWFQDN',
        'EvolvedAllocationRetentionPriorityII',
        'ExtCommonFlags',
        'CSGID',
        'CMI',
        'UENetCap',
        'UEAMBR',
        'APNAMBRWithNSAPI',
        'SignallingPriorityIndWithNSAPI',
        'HigherBitratesThan16MbpsFlag',
        'AdditionalMMContextForSRVCC',
        'AdditionalFlagsForSRVCC',
        'STNSR',
        'CMSISDN',
        'ExtRANAPCause',
        'ENodeBID',
        'SelectionModeWithNSAPI',
        'UEUsageType',
        'ExtCommonFlagsII',
        'UESCEFPDNConnection',
        'AltGGSNAddrForControlPlane',
        'AltGGSNAddrForUserTraffic',
        'PrivateExt'
        }
    
    _GEN = (
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
        GTPIETLV('PSHandoverXIDParams', val={'Type': GTPIEType.PSHandoverXIDParams.value}, trans=True),
        GTPIETLV('DirectTunnelFlags', val={'Type': GTPIEType.DirectTunnelFlags.value}, trans=True),
        GTPIETLV('ReliableInterRATHandoverInfo', val={'Type': GTPIEType.ReliableInterRATHandoverInfo.value}, trans=True),
        GTPIETLV('SubscribedRFSPIndex', val={'Type': GTPIEType.RFSPIndex.value}, trans=True),
        GTPIETLV('RFSPIndex', val={'Type': GTPIEType.RFSPIndex.value}, trans=True),
        GTPIETLV('ColocatedGGSNPGWFQDN', val={'Type': GTPIEType.FQDN.value}, trans=True),
        GTPIETLV('EvolvedAllocationRetentionPriorityII', val={'Type': GTPIEType.EvolvedAllocationRetentionPriorityII.value}, trans=True),
        GTPIETLV('ExtCommonFlags', val={'Type': GTPIEType.ExtCommonFlags.value}, trans=True),
        GTPIETLV('CSGID', val={'Type': GTPIEType.CSGID.value}, trans=True),
        GTPIETLV('CMI', val={'Type': GTPIEType.CMI.value}, trans=True),
        GTPIETLV('UENetCap', val={'Type': GTPIEType.UENetCap.value}, trans=True),
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
        )


class ForwardRelocationReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.ForwardRelocationReq.value}),
        ForwardRelocationReqIEs(hier=1),
        )


# Forward Relocation Response

class ForwardRelocationRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'TEIDCP',
        'TEIDDataII',
        'RANAPCause',
        'SGSNAddrForControlPlane',
        'SGSNAddrForUserTraffic',
        'UTRANTransparentContainer',
        'RABSetupInfo',
        'AdditionalRABSetupInfo',
        'SGSNNumber',
        'BSSContainer',
        'BSSGPCause',
        'ListOfSetupPFCs',
        'ExtRANAPCause',
        'NodeIdent',
        'PrivateExt'
        }
    
    _GEN = (
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
        )


class ForwardRelocationResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.ForwardRelocationResp.value}),
        ForwardRelocationRespIEs(hier=1),
        )


# Forward Relocation Complete

class ForwardRelocationCompleteIEs(GTPIEs):
    
    MAND = set()
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class ForwardRelocationComplete(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.ForwardRelocationComplete.value}),
        ForwardRelocationCompleteIEs(hier=1),
        )


# Relocation Cancel Request

class RelocationCancelReqIEs(GTPIEs):
    
    MAND = set()
    OPT  = {
        'IMSI',
        'IMEI',
        'ExtCommonFlags',
        'ExtRANAPCause',
        'PrivateExt'
        }

    
    _GEN = (
        GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
        GTPIETLV('IMEI', val={'Type': GTPIEType.IMEI.value}, trans=True),
        GTPIETLV('ExtCommonFlags', val={'Type': GTPIEType.ExtCommonFlags.value}, trans=True),
        GTPIETLV('ExtRANAPCause', val={'Type': GTPIEType.ExtRANAPCause.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class RelocationCancelReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.RelocationCancelReq.value}),
        RelocationCancelReqIEs(hier=1),
        )



# Relocation Cancel Response

class RelocationCancelRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class RelocationCancelResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.RelocationCancelResp.value}),
        RelocationCancelRespIEs(hier=1),
        )


# Forward Relocation Complete Acknowledge

class ForwardRelocationCompleteAckIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class ForwardRelocationCompleteAck(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.ForwardRelocationCompleteAck.value}),
        ForwardRelocationCompleteAckIEs(hier=1),
        )


# Forward SRNS Context Acknowledge

class ForwardSRNSCtxtAckIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class ForwardSRNSCtxtAck(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.ForwardSRNSCtxtAck.value}),
        ForwardSRNSCtxtAckIEs(hier=1),
        )


# Forward SRNS Context

class ForwardSRNSCtxtIEs(GTPIEs):
    
    MAND = {
        'RABContext'
        }
    OPT  = {
        'SourceRNCPDCPContextInfo',
        'PDUNumbers',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('RABContext', val={'Type': GTPIEType.RABContext.value}, bl={'Data': 72}),
        GTPIETLV('SourceRNCPDCPContextInfo', val={'Type': GTPIEType.SourceRNCPDCPContextInfo.value}, trans=True),
        GTPIETLV('PDUNumbers', val={'Type': GTPIEType.PDUNumbers.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class ForwardSRNSCtxt(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.ForwardSRNSCtxt.value}),
        ForwardSRNSCtxtIEs(hier=1),
        )


# RAN Information Relay

class RANInfoRelayIEs(GTPIEs):
    
    MAND = {
        'RANTransparentContainer'
        }
    OPT  = {
        'RIMRoutingAddr',
        'RIMRoutingAddrDiscriminator',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETLV('RANTransparentContainer', val={'Type': GTPIEType.RANTransparentContainer.value}),
        GTPIETLV('RIMRoutingAddr', val={'Type': GTPIEType.RIMRoutingAddr.value}, trans=True),
        GTPIETLV('RIMRoutingAddrDiscriminator', val={'Type': GTPIEType.RIMRoutingAddrDiscriminator.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class RANInfoRelay(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.RANInfoRelay.value}),
        RANInfoRelayIEs(hier=1),
        )


# UE Registration Query Request

class UERegistrationQueryReqIEs(GTPIEs):
    
    MAND = {
        'IMSI'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class UERegistrationQueryReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.UERegistrationQueryReq.value}),
        UERegistrationQueryReqIEs(hier=1),
        )


# UE Registration Query Response

class UERegistrationQueryRespIEs(GTPIEs):
    
    MAND = {
        'Cause',
        'IMSI'
        }
    OPT  = {
        'SelectedPLMNID',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}),
        GTPIETLV('SelectedPLMNID', val={'Type': GTPIEType.SelectedPLMNID.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class UERegistrationQueryResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.UERegistrationQueryResp.value}),
        UERegistrationQueryRespIEs(hier=1),
        )


#------------------------------------------------------------------------------#
# 7.5A MBMS Messages
#------------------------------------------------------------------------------#
# optional interface between SGSN and GGSN within a PLMN

# 7.5A.1 UE Specific MBMS Messages

# MBMS Notification Request

class MBMSNotifReqIEs(GTPIEs):
    
    MAND = {
        'IMSI',
        'TEIDCP',
        'NSAPI',
        'EndUserAddr',
        'APN',
        'GGSNAddrForControlPlane'
        }
    OPT  = {
        'MBMSPCO',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}),
        GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}),
        GTPIETV('NSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}),
        GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
        GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
        GTPIETLV('GGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}),
        GTPIETLV('MBMSPCO', val={'Type': GTPIEType.MBMSPCO.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MBMSNotifReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MBMSNotifReq.value}),
        MBMSNotifReqIEs(hier=1),
        )


# MBMS Notification Response

class MBMSNotifRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MBMSNotifResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MBMSNotifResp.value}),
        MBMSNotifRespIEs(hier=1),
        )


# MBMS Notification Reject Request

class MBMSNotifRejectReqIEs(GTPIEs):
    
    MAND = {
        'Cause',
        'TEIDCP',
        'NSAPI',
        'EndUserAddr',
        'APN'
        }
    OPT  = {
        'SGSNAddrForControlPlane',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}),
        GTPIETV('NSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}),
        GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
        GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
        GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MBMSNotifRejectReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MBMSNotifRejectReq.value}),
        MBMSNotifRejectReqIEs(hier=1),
        )


# MBMS Notification Reject Response

class MBMSNotifRejectRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MBMSNotifRejectResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MBMSNotifRejectResp.value}),
        MBMSNotifRejectRespIEs(hier=1),
        )


# Create MBMS Context Request

class CreateMBMSCtxtReqIEs(GTPIEs):
    
    MAND = {
        'RAI',
        'EndUserAddr',
        'APN',
        'SGSNAddrForSignalling',
        'EnhancedNSAPI'
        }
    OPT  = {
        'IMSI',
        'Recovery',
        'SelectionMode',
        'TEIDCP',
        'TraceReference',
        'TraceType',
        'MSISDN',
        'TriggerId',
        'OMCIdentity',
        'RATType',
        'ULI',
        'MSTimeZone',
        'IMEI',
        'MBMSPCO',
        'AdditionalTraceInfo',
        'AdditionalMBMSTraceInfo',
        'PrivateExt'
        }
    
    _GEN = (
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
        GTPIETLV('ULI', val={'Type': GTPIEType.ULI.value}, trans=True),
        GTPIETLV('MSTimeZone', val={'Type': GTPIEType.MSTimeZone.value}, trans=True),
        GTPIETLV('IMEI', val={'Type': GTPIEType.IMEI.value}, trans=True),
        GTPIETLV('MBMSPCO', val={'Type': GTPIEType.MBMSPCO.value}, trans=True),
        GTPIETLV('AdditionalTraceInfo', val={'Type': GTPIEType.AdditionalTraceInfo.value}, trans=True),
        GTPIETLV('EnhancedNSAPI', val={'Type': GTPIEType.EnhancedNSAPI.value}),
        GTPIETLV('AdditionalMBMSTraceInfo', val={'Type': GTPIEType.AdditionalMBMSTraceInfo.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class CreateMBMSCtxtReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.CreateMBMSCtxtReq.value}),
        CreateMBMSCtxtReqIEs(hier=1),
        )


# Create MBMS Context Response

class CreateMBMSCtxtRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'Recovery',
        'TEIDCP',
        'ChargingID',
        'GGSNAddrForControlPlane',
        'AltGGSNAddrForControlPlane',
        'ChargingGatewayAddr',
        'AltChargingGatewayAddr',
        'MBMSPCO',
        'PrivateExt'
        }
    
    _GEN = (
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
        )


class CreateMBMSCtxtResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.CreateMBMSCtxtResp.value}),
        CreateMBMSCtxtRespIEs(hier=1),
        )


# Update MBMS Context Request

class UpdateMBMSCtxtReqIEs(GTPIEs):
    
    MAND = {
        'RAI',
        'EnhancedNSAPI'
        }
    OPT  = {
        'Recovery',
        'TEIDCP',
        'TraceReference',
        'TraceType',
        'SGSNAddrForControlPlane',
        'AltSGSNAddrForControlPlane',
        'TriggerId',
        'OMCIdentity',
        'RATType',
        'ULI',
        'MSTimeZone',
        'AdditionalTraceInfo',
        'AdditionalMBMSTraceInfo',
        'PrivateExt'
        }
    
    _GEN = (
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
        GTPIETLV('ULI', val={'Type': GTPIEType.ULI.value}, trans=True),
        GTPIETLV('MSTimeZone', val={'Type': GTPIEType.MSTimeZone.value}, trans=True),
        GTPIETLV('AdditionalTraceInfo', val={'Type': GTPIEType.AdditionalTraceInfo.value}, trans=True),
        GTPIETLV('EnhancedNSAPI', val={'Type': GTPIEType.EnhancedNSAPI.value}),
        GTPIETLV('AdditionalMBMSTraceInfo', val={'Type': GTPIEType.AdditionalMBMSTraceInfo.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class UpdateMBMSCtxtReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.UpdateMBMSCtxtReq.value}),
        UpdateMBMSCtxtReqIEs(hier=1),
        )


# Update MBMS Context Response

class UpdateMBMSCtxtRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'Recovery',
        'TEIDCP',
        'ChargingID',
        'GGSNAddrForControlPlane',
        'AltGGSNAddrForControlPlane',
        'ChargingGatewayAddr',
        'AltChargingGatewayAddr',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
        GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
        GTPIETV('ChargingID', val={'Type': GTPIEType.ChargingID.value}, bl={'Data': 32}, trans=True),
        GTPIETLV('GGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('AltGGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('ChargingGatewayAddr', val={'Type': GTPIEType.ChargingGatewayAddr.value}, trans=True),
        GTPIETLV('AltChargingGatewayAddr', val={'Type': GTPIEType.ChargingGatewayAddr.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class UpdateMBMSCtxtResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.UpdateMBMSCtxtResp.value}),
        UpdateMBMSCtxtRespIEs(hier=1),
        )


# Delete MBMS Context Request

class DeleteMBMSCtxtReqIEs(GTPIEs):
    
    MAND = set()
    OPT  = {
        'IMSI',
        'TEIDCP',
        'EndUserAddr',
        'APN',
        'MBMSPCO',
        'EnhancedNSAPI',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
        GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
        GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}, trans=True),
        GTPIETLV('APN', val={'Type': GTPIEType.APN.value}, trans=True),
        GTPIETLV('MBMSPCO', val={'Type': GTPIEType.MBMSPCO.value}, trans=True),
        GTPIETLV('EnhancedNSAPI', val={'Type': GTPIEType.EnhancedNSAPI.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class DeleteMBMSCtxtReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.DeleteMBMSCtxtReq.value}),
        DeleteMBMSCtxtReqIEs(hier=1),
        )


# Delete MBMS Context Response

class DeleteMBMSCtxtRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'MBMSPCO',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('MBMSPCO', val={'Type': GTPIEType.MBMSPCO.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class DeleteMBMSCtxtResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.DeleteMBMSCtxtResp.value}),
        DeleteMBMSCtxtRespIEs(hier=1),
        )


# 7.5A.2 Service Specific MBMS Messages

# MBMS Registration Request

class MBMSRegistrationReqIEs(GTPIEs):
    
    MAND = {
        'EndUserAddr',
        'APN'
        }
    OPT  = {
        'TEIDCP',
        'SGSNAddrForControlPlane',
        'AltSGSNAddrForControlPlane',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
        GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
        GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
        GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('AltSGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MBMSRegistrationReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MBMSRegistrationReq.value}),
        MBMSRegistrationReqIEs(hier=1),
        )


# MBMS Registration Response

class MBMSRegistrationRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'TEIDCP',
        'GGSNAddrForControlPlane',
        'TMGI',
        'RequiredMBMSBearerCap',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
        GTPIETLV('GGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('TMGI', val={'Type': GTPIEType.TMGI.value}, trans=True),
        GTPIETLV('RequiredMBMSBearerCap', val={'Type': GTPIEType.RequiredMBMSBearerCap.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MBMSRegistrationResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MBMSRegistrationResp.value}),
        MBMSRegistrationRespIEs(hier=1),
        )


# MBMS De-registration Request

class MBMSDeRegistrationReqIEs(GTPIEs):
    
    MAND = {
        'EndUserAddr',
        'APN'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
        GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MBMSDeRegistrationReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MBMSDeRegistrationReq.value}),
        MBMSDeRegistrationReqIEs(hier=1),
        )


# MBMS De-registration Response

class MBMSDeRegistrationRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MBMSDeRegistrationResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MBMSDeRegistrationResp.value}),
        MBMSDeRegistrationRespIEs(hier=1),
        )


# MBMS Session Start Request

class MBMSSessionStartReqIEs(GTPIEs):
    
    MAND = {
        'EndUserAddr',
        'APN',
        'QoSProfile',
        'CommonFlags',
        'TMGI',
        'MBMSServiceArea',
        'MBMS2G3GInd',
        'MBMSSessionDuration',
        'MBMSTimeToDataTransfer'
        }
    OPT  = {
        'Recovery',
        'TEIDCP',
        'GGSNAddrForControlPlane',
        'AltGGSNAddrForControlPlane',
        'MBMSSessionIdent',
        'MBMSSessionRepetitionNumber',
        'MBMSFlowIdent',
        'MBMSIPMulticastDistrib',
        'PrivateExt'
        }
    
    _GEN = (
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
        GTPIETLV('MBMS2G3GInd', val={'Type': GTPIEType.MBMS2G3GInd.value}),
        GTPIETLV('MBMSSessionDuration', val={'Type': GTPIEType.MBMSSessionDuration.value}),
        GTPIETLV('MBMSSessionRepetitionNumber', val={'Type': GTPIEType.MBMSSessionRepetitionNumber.value}, trans=True),
        GTPIETLV('MBMSTimeToDataTransfer', val={'Type': GTPIEType.MBMSTimeToDataTransfer.value}),
        GTPIETLV('MBMSFlowIdent', val={'Type': GTPIEType.MBMSFlowIdent.value}, trans=True),
        GTPIETLV('MBMSIPMulticastDistrib', val={'Type': GTPIEType.MBMSIPMulticastDistrib.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MBMSSessionStartReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MBMSSessionStartReq.value}),
        MBMSSessionStartReqIEs(hier=1),
        )


# MBMS Session Start Response

class MBMSSessionStartRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'Recovery',
        'TEIDDataI',
        'TEIDCP',
        'SGSNAddrForControlPlane',
        'SGSNAddrForUserTraffic',
        'AltSGSNAddrForUserTraffic',
        'MBMSDistribAck',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('Recovery', val={'Type': GTPIEType.Recovery.value}, bl={'Data': 8}, trans=True),
        GTPIETV('TEIDDataI', val={'Type': GTPIEType.TEIDDataI.value}, bl={'Data': 32}, trans=True),
        GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
        GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('SGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('AltSGSNAddrForUserTraffic', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('MBMSDistribAck', val={'Type': GTPIEType.MBMSDistribAck.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MBMSSessionStartResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MBMSSessionStartResp.value}),
        MBMSSessionStartRespIEs(hier=1),
        )


# MBMS Session Stop Request

class MBMSSessionStopReqIEs(GTPIEs):
    
    MAND = {
        'EndUserAddr',
        'APN'
        }
    OPT  = {
        'MBMSFlowIdent',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETLV('EndUserAddr', val={'Type': GTPIEType.EndUserAddr.value}),
        GTPIETLV('APN', val={'Type': GTPIEType.APN.value}),
        GTPIETLV('MBMSFlowIdent', val={'Type': GTPIEType.MBMSFlowIdent.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MBMSSessionStopReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MBMSSessionStopReq.value}),
        MBMSSessionStopReqIEs(hier=1),
        )


# MBMS Session Stop Response

class MBMSSessionStopRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MBMSSessionStopResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MBMSSessionStopResp.value}),
        MBMSSessionStopRespIEs(hier=1),
        )


# MBMS Session Update Request

class MBMSSessionUpdateReqIEs(GTPIEs):
    
    MAND = {
        'EndUserAddr',
        'APN',
        'TMGI',
        'MBMSSessionDuration',
        'MBMSServiceArea'
        }
    OPT  = {
        'TEIDCP',
        'GGSNAddrForControlPlane',
        'MBMSSessionIdent',
        'MBMSSessionRepetitionNumber',
        'MBMSFlowIdent',
        'PrivateExt'
        }
    
    _GEN = (
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
        )


class MBMSSessionUpdateReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MBMSSessionUpdateReq.value}),
        MBMSSessionUpdateReqIEs(hier=1),
        )


# MBMS Session Update Response

class MBMSSessionUpdateRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'TEIDDataI',
        'TEIDCP',
        'SGSNAddrForDataI',
        'SGSNAddrForControlPlane',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('TEIDDataI', val={'Type': GTPIEType.TEIDDataI.value}, bl={'Data': 32}, trans=True),
        GTPIETV('TEIDCP', val={'Type': GTPIEType.TEIDCP.value}, bl={'Data': 32}, trans=True),
        GTPIETLV('SGSNAddrForDataI', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('SGSNAddrForControlPlane', val={'Type': GTPIEType.GSNAddr.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MBMSSessionUpdateResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MBMSSessionUpdateResp.value}),
        MBMSSessionUpdateRespIEs(hier=1),
        )


#------------------------------------------------------------------------------#
# 7.5B.1 MS Info Change Reporting Messages
#------------------------------------------------------------------------------#
# optional interface between SGSN and GGSN within a PLMN

# MS Info Change Notification Request

class MSInfoChangeNotifReqIEs(GTPIEs):
    
    MAND = {
        'RATType'
        }
    OPT  = {
        'IMSI',
        'LinkedNSAPI',
        'ULI',
        'IMEI',
        'ExtCommonFlags',
        'UCI',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
        GTPIETV('LinkedNSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}, trans=True),
        GTPIETLV('RATType', val={'Type': GTPIEType.RATType.value}),
        GTPIETLV('ULI', val={'Type': GTPIEType.ULI.value}, trans=True),
        GTPIETLV('IMEI', val={'Type': GTPIEType.IMEI.value}, trans=True),
        GTPIETLV('ExtCommonFlags', val={'Type': GTPIEType.ExtCommonFlags.value}, trans=True),
        GTPIETLV('UCI', val={'Type': GTPIEType.UCI.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MSInfoChangeNotifReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MSInfoChangeNotifReq.value}),
        MSInfoChangeNotifReqIEs(hier=1),
        )


# MS Info Change Notification Response

class MSInfoChangeNotifRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'IMSI',
        'LinkedNSAPI',
        'IMEI',
        'MSInfoChangeReportingAction',
        'CSGInfoReportingAction',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('IMSI', val={'Type': GTPIEType.IMSI.value}, bl={'Data': 64}, trans=True),
        GTPIETV('LinkedNSAPI', val={'Type': GTPIEType.NSAPI.value}, bl={'Data': 8}, trans=True),
        GTPIETLV('IMEI', val={'Type': GTPIEType.IMEI.value}, trans=True),
        GTPIETLV('MSInfoChangeReportingAction', val={'Type': GTPIEType.MSInfoChangeReportingAction.value}, trans=True),
        GTPIETLV('CSGInfoReportingAction', val={'Type': GTPIEType.CSGInfoReportingAction.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class MSInfoChangeNotifResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 1, 'Type': GTPType.MSInfoChangeNotifResp.value}),
        MSInfoChangeNotifRespIEs(hier=1),
        )


#------------------------------------------------------------------------------#
# GTP' message type
# TS 32.295, section 6.2
#------------------------------------------------------------------------------#

# Node Alive Request

class NodeAliveReqIEs(GTPIEs):
    
    MAND = {
        'NodeAddr'
        }
    OPT  = {
        'AltNodeAddr',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETLV('NodeAddr', val={'Type': GTPIEType.ChargingGatewayAddr.value}),
        GTPIETLV('AltNodeAddr', val={'Type': GTPIEType.ChargingGatewayAddr.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class NodeAliveReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 0, 'Type': GTPType.NodeAliveReq.value}),
        NodeAliveReqIEs(hier=1),
        )


# Node Alive Response

class NodeAliveRespIEs(GTPIEs):
    
    MAND = set()
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class NodeAliveResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 0, 'Type': GTPType.NodeAliveResp.value}),
        NodeAliveRespIEs(hier=1),
        )



# Redirection Request

class RedirectionReqIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'RecommendedNodeAddr',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('RecommendedNodeAddr', val={'Type': GTPIEType.RecommendedNodeAddr.value}, trans=True),
        GTPIETLV('AltRecommendedNodeAddr', val={'Type': GTPIEType.RecommendedNodeAddr.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class RedirectionReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 0, 'Type': GTPType.RedirectionReq.value}),
        RedirectionReqIEs(hier=1),
        )


# Redirection Response

class RedirectionRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class RedirectionResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 0, 'Type': GTPType.RedirectionResp.value}),
        RedirectionRespIEs(hier=1),
        )


# Data Record Transfer Request

class DataRecordTransferReqIEs(GTPIEs):
    
    MAND = {
        'PacketTransferCmd'
        }
    OPT  = {
        'DataRecordPacket',
        'SeqNumReleasedPackets',
        'SeqNumCancelledPackets',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('PacketTransferCmd', val={'Type': GTPIEType.PacketTransferCmd.value}, bl={'Data': 8}),
        GTPIETLV('DataRecordPacket', val={'Type': GTPIEType.DataRecordPacket.value}, trans=True),
        GTPIETLV('SeqNumReleasedPackets', val={'Type': GTPIEType.SeqNumReleasedPackets.value}, trans=True),
        GTPIETLV('SeqNumCancelledPackets', val={'Type': GTPIEType.SeqNumCancelledPackets.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class DataRecordTransferReq(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 0, 'Type': GTPType.DataRecordTransferReq.value}),
        DataRecordTransferReqIEs(hier=1),
        )


# Data Record Transfer Response

class DataRecordTransferRespIEs(GTPIEs):
    
    MAND = {
        'Cause',
        'RequestsResponded'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPIEType.Cause.value}, bl={'Data': 8}),
        GTPIETLV('RequestsResponded', val={'Type': GTPIEType.RequestsResponded.value}),
        GTPIETLV('PrivateExt', val={'Type': GTPIEType.PrivateExt.value}, trans=True),
        )


class DataRecordTransferResp(GTPMsg):
    _GEN = (
        GTPHdr(val={'PT': 0, 'Type': GTPType.DataRecordTransferResp.value}),
        DataRecordTransferRespIEs(hier=1),
        )


#------------------------------------------------------------------------------#
# General parser    
# TS 29.060, section 7.1
#------------------------------------------------------------------------------#

INI_ANY  = 'Any'
INI_SGSN = 'SGSN'
INI_GGSN = 'GGSN'
INI_HLR  = 'HLR' # Actually, not directly the HLR, but the GTP-MAP converter in front of the HLR
INI_MME  = 'MME'
INI_CGF  = 'CGF' # Charging Gateway Function


# GTP-C v1 requests (code, initiator) / responses (code, initiator)
GTPReqResp = {
    #
    # error messages that could eventually come in reponse to any kind of request:
    # 3: VersionNotSupported
    # 26: ErrorInd
    # 31: SupportedExtHeadersNotif
    #
    # Path mgmt
    'Path': {
        (1, INI_ANY) : (2, INI_ANY),
        (3, INI_ANY) : (None, INI_ANY),
        (31, INI_ANY) : (None, INI_ANY),
        },
    #
    # Tunnel mgmt
    'Tun': {
        (16, INI_SGSN) : (17, INI_GGSN),
        (18, INI_SGSN) : (19, INI_GGSN),
        (18, INI_GGSN) : (19, INI_SGSN),
        (20, INI_SGSN) : (21, INI_GGSN),
        (22, INI_GGSN) : (23, INI_SGSN),
        (27, INI_GGSN) : (28, INI_SGSN),
        (29, INI_SGSN) : (30, INI_GGSN),
        },
    #
    # Location mgmt
    'Loc': {
        (32, INI_GGSN) : (33, INI_HLR),
        (34, INI_GGSN) : (35, INI_HLR),
        (36, INI_HLR)  : (37, INI_GGSN),
        },
    #
    # Mobility mgmt
    'Mob': {
        # Identity Req / Resp:
        (48, INI_SGSN) : (49, INI_SGSN),
        # SGSN Context transmission:
        #  Old SGSN  /  New SGSN
        #     == 50 (Req) ==>
        #    <== 51 (Res) ==
        #     == 52 (Ack) ==>
        (50, INI_SGSN) : (51, INI_SGSN),
        (51, INI_SGSN) : (52, INI_SGSN),
        # Forward Relocation (SRNS Relocation / PS handover):
        # Old SGSN  /  New SGSN
        #    == 53 (Req) ==>
        #   <== 54 (Res) ==
        #   <== 55 (Com) == (after SRNS relocation succeeded)
        #    == 59 (Ack) ==>
        (53, INI_SGSN) : (54, INI_SGSN),
        (55, INI_SGSN) : (59, INI_SGSN),
        # Relocation Cancel (SRNS Relocation / PS handover):
        # Old SGSN  /  New SGSN
        #   == 56 (Req) ==>
        #  <== 57 (Res) ==
        (56, INI_SGSN) : (57, INI_SGSN),
        # Forward SRNS Context (Hard handover + switch of SGSN):
        # Old SGSN  /  New SGSN
        #   == 58 (Req) ==>
        #  <== 60 (Ack) ==
        (58, INI_SGSN) : (60, INI_SGSN),
        # RAN Info Relay
        (70, INI_SGSN) : (None, INI_SGSN),
        # UE Reg Query
        (61, INI_SGSN) : (62, INI_MME),
        },
    #
    # UE-specific MBMS
    'MB_UE': {
        (96, INI_GGSN) : (97, INI_SGSN),
        (98, INI_SGSN) : (99, INI_GGSN),
        (100, INI_SGSN) : (101, INI_GGSN),
        (102, INI_SGSN) : (103, INI_GGSN),
        (104, INI_SGSN) : (105, INI_GGSN),
        },
    #
    # Service-specific MBMS
    'MB_Serv': {
        (112, INI_SGSN) : (113, INI_GGSN),
        (114, INI_SGSN) : (115, INI_GGSN),
        (114, INI_GGSN) : (115, INI_SGSN),
        (116, INI_GGSN) : (117, INI_SGSN),
        (118, INI_GGSN) : (119, INI_SGSN),
        (118, INI_SGSN) : (119, INI_GGSN),
        (120, INI_GGSN) : (121, INI_SGSN),
        },
    #
    # MS Info Change Reporting
    'MSInfo': {
        (128, INI_SGSN) : (129, INI_GGSN),
        },
    #
    # GTP'
    'GTPp': {
        (4, INI_ANY) : (5, INI_ANY),
        # Here, Any is for any function that can generates PS CDR
        (6, INI_CGF) : (7, INI_ANY),
        (240, INI_ANY) : (241, INI_CGF),
        },
    }

GTPReqResp_flat = {}
[GTPReqResp_flat.update(req_resp_d) for req_resp_d in GTPReqResp.values()]


GTPDispatcherSGSN = {
    # GTP
    # Path mgmt
    1 : EchoReq,
    2 : EchoResp,
    3 : VersionNotSupported,
    31 : SupportedExtHeadersNotif,
    #
    # Tunnel mgmt
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
    #
    # Location mgmt
    32 : SendRouteingInfoforGPRSReq,
    33 : SendRouteingInfoforGPRSResp,
    34 : FailureReportReq,
    35 : FailureReportResp,
    36 : NoteMSGPRSPresentReq,
    37 : NoteMSGPRSPresentResp,
    #
    # Mobility mgmt
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
    61 : UERegistrationQueryReq,
    62 : UERegistrationQueryResp,
    #
    # UE-related MBMS
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
    #
    # Service-related MBMS
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
    #
    # MS Info Change Reporting
    128 : MSInfoChangeNotifReq,
    129 : MSInfoChangeNotifResp,
    #
    # GTP'
    4 : NodeAliveReq,
    5 : NodeAliveResp,
    6 : RedirectionReq,
    7 : RedirectionResp,
    240 : DataRecordTransferReq,
    241 : DataRecordTransferResp,
    }


GTPDispatcherGGSN = {
    # GTP
    # Path mgmt
    1 : EchoReq,
    2 : EchoResp,
    3 : VersionNotSupported,
    31 : SupportedExtHeadersNotif,
    #
    # Tunnel mgmt
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
    #
    # Location mgmt
    32 : SendRouteingInfoforGPRSReq,
    33 : SendRouteingInfoforGPRSResp,
    34 : FailureReportReq,
    35 : FailureReportResp,
    36 : NoteMSGPRSPresentReq,
    37 : NoteMSGPRSPresentResp,
    #
    # Mobility mgmt
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
    61 : UERegistrationQueryReq,
    62 : UERegistrationQueryResp,
    #
    # UE-related MBMS
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
    #
    # Service-related MBMS
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
    #
    # MS Info Change Reporting
    128 : MSInfoChangeNotifReq,
    129 : MSInfoChangeNotifResp,
    #
    # GTP'
    4 : NodeAliveReq,
    5 : NodeAliveResp,
    6 : RedirectionReq,
    7 : RedirectionResp,
    240 : DataRecordTransferReq,
    241 : DataRecordTransferResp,
    }


ERR_GTP_BUF_TOO_SHORT = 1
ERR_GTP_BUF_INVALID   = 2
ERR_GTP_TYPE_NONEXIST = 3
ERR_GTP_MAND_IE_MISS  = 4


def parse_GTP_SGSN(buf):
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
        GTPIEs.VERIF_MAND = False
        Msg = Msg.__class__()
        try:
            Msg.from_bytes(buf)
            GTPIEs.VERIF_MAND = True
        except Exception:
            GTPIEs.VERIF_MAND = True
            return None, ERR_GTP_BUF_INVALID
        else:
            return Msg, ERR_GTP_MAND_IE_MISS
    except Exception:
        return None, ERR_GTP_BUF_INVALID
    else:
        return Msg, 0


def parse_GTP_GGSN(buf):
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
        GTPIEs.VERIF_MAND = False
        Msg = Msg.__class__()
        try:
            Msg.from_bytes(buf)
            GTPIEs.VERIF_MAND = True
        except Exception:
            GTPIEs.VERIF_MAND = True
            return None, ERR_GTP_BUF_INVALID
        else:
            return Msg, ERR_GTP_MAND_IE_MISS
    except Exception:
        return None, ERR_GTP_BUF_INVALID
    else:
        return Msg, 0


def parse_GTP(buf):
    """parses the buffer `buf' for GTPv1-C message and returns a 2-tuple:
    - GTPv1-C message structure, or None if parsing failed
    - parsing error code, 0 if parsing succeeded, > 0 otherwise
    
    Eventually tries both SGSN-initiated and GGSN-initiated structures for message types:
    18 : Update PDP Ctxt Req
    19 : Update PDP Ctxt Resp
    """
    # this is the best we can do
    Msg, Err = parse_GTP_SGSN(buf)
    if Err == 4 and Msg and Msg[0]['Type'].get_val() in {18, 19}:
        Msg, Err = parse_GTP_GGSN(buf)
    return Msg, Err



'''
# create sets listing mandatory and optional IEs under .MAND and .OPT class attributes
for disp in (GTPDispatcherSGSN, GTPDispatcherGGSN):
    for cls in disp.values():
        if hasattr(cls, 'MAND'):
            continue
        cls.MAND, cls.OPT = [], []
        for ie in cls._GEN[1]._content:
            if ie.get_trans():
                cls.OPT.append(ie._name)
            else:
                cls.MAND.append(ie._name)
        assert( len(cls.MAND) == len(set(cls.MAND)) and len(cls.OPT) == len(set(cls.OPT)) )


def inl(cls):
    
    def get_enum(en, i):
        for e in en:
            if e == i:
                return e
        assert()    
    
    # generate dedicated class GTPIEs
    print('class %sIEs(GTPIEs):' % cls.__name__)
    print('    ')
    print('    MAND = {\n        %s\n        }' % ',\n        '.join(map(repr, cls.MAND)))
    print('    OPT  = {\n        %s\n        }' % ',\n        '.join(map(repr, cls.OPT)))
    print('    ')
    print('    _GEN = (')
    for ie in cls._GEN[1]._content:
        if ie._trans:
            trans = ', trans=True'
        else:
            trans = ''
        if isinstance(ie, GTPIETV):
            print('        GTPIETV(\'%s\', val={\'Type\': %s.value}, bl={\'Data\': %i}%s),'\
                  % (ie._name, get_enum(GTPIEType, ie['Type']._val), ie['Data']._bl, trans))
        else:
            print('        GTPIETLV(\'%s\', val={\'Type\': %s.value}%s),'\
                  % (ie._name, get_enum(GTPIEType, ie['Type']._val), trans))
    print('        )\n\n')
    
    # generate msg class GTPMsg
    print('class %s(GTPMsg):' % cls.__name__)
    print('    _GEN = (')
    print('        GTPHdr(val={\'PT\': %i, \'Type\': %s.value}),'\
          % (cls._GEN[0]['PT']._val, get_enum(GTPType, cls._GEN[0]['Type']._val)))
    print('        %sIEs(hier=1),' % cls.__name__)
    print('        )\n\n')
'''
