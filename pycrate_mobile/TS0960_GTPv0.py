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
# * File Name : pycrate_mobile/TS0960_GTPv0.py
# * Created : 2022-10-28
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#__all__ = [
#    ]

from binascii import *
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
from enum   import IntEnum

from pycrate_core.utils     import *
from pycrate_core.elt       import *
from pycrate_core.base      import *
from pycrate_core.utils     import PycrateErr
from pycrate_core.charpy    import CharpyErr

from pycrate_mobile.TS29244_PFCP    import (
    _LU8V
    )
from pycrate_mobile.TS29274_GTPC    import (
    PCO,
    MMContextTriplet,
    MMContextMSNetCap
    )
from pycrate_mobile.TS29060_GTP     import (
    ProtType_dict,
    IMSI,
    RAI,
    TLLI,
    PTMSI,
    ReorderingRequired,
    AuthentTriplet,
    MAPCause,
    PTMSISignature,
    MSValidated,
    Recovery,
    SelectionMode,
    MSNotReachableReason,
    ChargingID,
    EndUserAddr,
    GSNAddr,
    MSISDN,
    _LU8IPAddr,
    ChargingGatewayAddr,
    PrivateExt,
    GTPIETV,
    GTPIETLV,
    GTPIEs
    )
from pycrate_mobile.TS24008_IE      import (
    BufBCD,
    #QoS,
    _DelayClass_dict,
    _ReliabClass_dict,
    _PeakTP_dict,
    _PrecedClass_dict,
    _MeanTP_dict,
    CiphAlgo_dict,
    DRXParam,
    _PDPTypeOrg_dict,
    _PDPTypeNum_dict,
    APN,
    ProtConfig,
    )
from pycrate_mobile.TS24007         import (
    TI
    )


#------------------------------------------------------------------------------#
# 3GPP TS 09.60: GPRS Tunnelling Protocol across the Gn and Gp Interface
# release 7 (7.9.0)
# i.e. 2G SGSN - GGSN interface
#------------------------------------------------------------------------------#

#------------------------------------------------------------------------------#
# GTPv0 Header
# TS 09.60, section 6
#------------------------------------------------------------------------------#

class TID(Envelope):
    """The TID contains a 15-digit IMSI with the NSAPI inserted in the first 4 bits
    of the last byte
    """
    
    _GEN = (
        BufBCD('Digits', val=b'\0\0\0\0\0\0\0', bl=56),
        Uint('NSAPI', val=0, bl=4),
        Uint('Digit15', bl=0)
        )
    
    def encode(self, imsi, nsapi=None):
        """sets the IMSI (15-digits str) and NSAPI (uint4) appropriately in the TID
        """
        self[0].set_val(imsi[:14])
        self[2].set_val(int(imsi[14:15]))
        if nsapi is not None:
            self[1].set_val(nsapi)
    
    def decode(self):
        """returns a 2-tuple (IMSI (15-digits str), NSAPI (uint4)) from the TID
        """
        return self[0].decode() + str(self[2].get_val()), self[1].get_val()
    
    def set_val(self, vals):
        if isinstance(vals, dict):
            if 'IMSI' in vals:
                if 'NSAPI' in vals:
                    self.encode(vals['IMSI'], vals['NSAPI'])
                else:
                    self.encode(vals['IMSI'])
                return
        Envelope.set_val(self, vals)
    
    def repr(self):
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        #
        return '<%s%s%s : %s>' % (self._name, desc, trans, '-'.join(self.decode()))
    
    __repr__ = repr


class GTPv0MsgType(IntEnum):
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
    CreateAAPDPCtxtReq              = 22
    CreateAAPDPCtxtResp             = 23
    DeleteAAPDPCtxtReq              = 24
    DeleteAAPDPCtxtResp             = 25
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
    DataRecordTransferReq           = 240
    DataRecordTransferResp          = 241
    TPDU                            = 255

GTPv0MsgType_dict = {e.value: e.name for e in GTPv0MsgType}


class GTPv0Hdr(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('Version', val=0, bl=3),               # 0 for GTP 09.60
        Uint('PT', val=1, bl=1, dic=ProtType_dict), # 1 for GTP 09.60, 0 for GTP' 12.15
        Uint('spare', val=0b111, bl=3),
        Uint('SNN', bl=1), # flag: SNDCP N-PDU Number interpreted or not
        Uint8('Type', val=GTPv0MsgType.EchoReq.value, dic=GTPv0MsgType_dict),
        Uint16('Len'),
        Uint16('SeqNum'),
        Uint16('FlowLabel', val=0, rep=REPR_HEX),
        Uint8('SNDCPNPDUNum', val=0xff),
        Uint24('spare', val=0xffffff, rep=REPR_HEX),
        TID(),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self._get_len())
    
    def _get_len(self):
        l = 0
        # get length of payload
        env = self.get_env()
        if env:
            for e in env._content[1:]:
                if not e.get_trans():
                    l += e.get_len()
        return l


#------------------------------------------------------------------------------#
# GTPv0 Signalling Plane
# TS 09.60, section 7
#------------------------------------------------------------------------------#

class GTPv0Msg(Envelope):
    """parent class for all GTPv0-C messages
    """
    
    # MAND and OPT class attributes are generated when module is loaded
    # each one is a set listing IE types that are mandatories, respectively optionals
    
    _GEN = (
        GTPv0Hdr(),
        GTPIEs(hier=1)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_blauto(lambda: self._get_ies_len())
    
    def _get_ies_len(self):
        return self[0]['Len'].get_val() << 3


#------------------------------------------------------------------------------#
# 7.9 Information elements
#------------------------------------------------------------------------------#
# 7.9.2: IMSI, same as TS 29.060
# 7.9.3: RAI, same as TS 29.060
# 7.9.4: TLLI, same as TS 29.060
# 7.9.5: P-TMSI, same as TS 29.060
# 7.9.7: ReorderingRequired, same as TS 29.060
# 7.9.8: AuthentTriplet, same as TS 29.060
# 7.9.9: MAPCause, same as TS 29.060
# 7.9.10: PTMSISignature, same as TS 29.060
# 7.9.11: MSValidated, same as TS 29.060
# 7.9.12: Recovery, same as TS 29.060
# 7.9.13: SelectionMode, same as TS 29.060
# 7.9.16A: MSNotReachableReason, same as TS 29.060
# 7.9.17: ChargingID, same as TS 29.060
# 7.9.18: EndUserAddr, same as TS 29.060
# 7.9.21: APN, same as TS 24.008
# 7.9.23: GSNAddr, same as TS 29.060
# 7.9.24: MSISDN, same as TS 29.060
# 7.9.25: ChargingGatewayAddr, same as TS 29.060
# 7.9.26: PrivateExt, same as TS 29.060

#------------------------------------------------------------------------------#
# Cause
# TS 09.60, section 7.9.1
#------------------------------------------------------------------------------#

CauseReq_dict = {
    0 : 'Request IMSI',
    1 : 'Request IMEI',
    2 : 'Request IMSI and IMEI',
    3 : 'No identity needed',
    4 : 'MS Refuses',
    5 : 'MS is not GPRS Responding'
    }

CauseResp_dict = {
    0 : 'Request accepted'
    }

CauseRespRej_dict = {
    0 : 'Non-existent',
    1 : 'Invalid message format',
    2 : 'IMSI not known',
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
    17 : 'User authentication failed'
    }


class Cause(Envelope):
    _GEN = (
        Uint('Resp', bl=1),
        Uint('Rej', bl=1),
        Uint('Val', bl=6)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Val'].set_dicauto(self._get_dict)
    
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
# Quality of Service (QoS) Profile
# TS 09.60, section 7.9.6
#------------------------------------------------------------------------------#
# bytes 2 to 4 of the QoS from 24.008

class QoSProfile(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('DelayClass', bl=3, dic=_DelayClass_dict),
        Uint('ReliabilityClass', bl=3, dic=_ReliabClass_dict), # 1
        Uint('PeakThroughput', bl=4, dic=_PeakTP_dict),
        Uint('spare', bl=1),
        Uint('PrecedenceClass', bl=3, dic=_PrecedClass_dict), # 2
        Uint('spare', bl=3),
        Uint('MeanThroughput', bl=5, dic=_MeanTP_dict) # 3
        )


#------------------------------------------------------------------------------#
# Flow Label Data I
# TS 09.60, section 7.9.14
#------------------------------------------------------------------------------#

class FlowLabelDataI(Uint16):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# Flow Label Signalling
# TS 09.60, section 7.9.15
#------------------------------------------------------------------------------#

class FlowLabelSig(Uint16):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# Flow Label Data II
# TS 09.60, section 7.9.16
#------------------------------------------------------------------------------#

class FlowLabelDataII(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=4, rep=REPR_HEX),
        Uint('NSAPI', val=5, bl=4),
        Uint16('Val', rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# MM Context
# TS 09.60, section 7.9.19
#------------------------------------------------------------------------------#

class MMContext(Envelope):
    _GEN = (
        Uint('spare', val=0x1f, bl=5, rep=REPR_HEX),
        Uint('CKSN', val=7, bl=3),
        Uint('spare', val=0b11, bl=2, rep=REPR_HEX),
        Uint('NoVectors', bl=3),
        Uint('UsedCipher', bl=3, dic=CiphAlgo_dict),
        Buf('Kc', bl=64, rep=REPR_HEX),
        Sequence('Triplets', GEN=MMContextTriplet('Triplet')),
        DRXParam(),
        MMContextMSNetCap('MSNetCap'),
        _LU8V('Container')
        )


#------------------------------------------------------------------------------#
# PDP Context
# TS 09.60, section 7.9.20
#------------------------------------------------------------------------------#

class PDPContext(Envelope):
    _GEN = (
        Uint('res', bl=1),
        Uint('VAA', bl=1),
        Uint('res', bl=1),
        Uint('Order', bl=1),
        Uint('NSAPI', val=5, bl=4),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('SAPI', bl=4),
        QoSProfile('QoSSub'),
        QoSProfile('QoSReq'),
        QoSProfile('QoSNeg'),
        Uint16('SeqNumDL'),
        Uint16('SeqNumUL'),
        Uint8('SendNPDUNum'),
        Uint8('RecvNPDUNum'),
        FlowLabelSig('ULFlowLabelSig'),
        Uint('spare', val=0xf, bl=4, rep=REPR_HEX),
        Uint('PDPTypeOrg', val=1, bl=4, dic=_PDPTypeOrg_dict),
        Uint8('PDPType', val=33, dic=_PDPTypeNum_dict),
        _LU8IPAddr('PDPAddr'),
        _LU8IPAddr('GSNAddrCP'),
        Uint8('APNLen'),
        APN(),
        Uint('spare', val=0, bl=4, rep=REPR_HEX),
        TI(),
        )


#------------------------------------------------------------------------------#
# All GTPv0 Information Elements
#------------------------------------------------------------------------------#

GTPv0IEType_dict = {
    0   : ('TV', -1, 'Reserved', 'Reserved'),
    1   : ('TV', 1, 'Cause', 'Cause'),
    2   : ('TV', 8, 'International Mobile Subscriber Identity (IMSI)', 'IMSI'),
    3   : ('TV', 6, 'Routeing Area Identity (RAI)', 'RAI'),
    4   : ('TV', 4, 'Temporary Logical Link Identity (TLLI)', 'TLLI'),
    5   : ('TV', 4, 'Packet TMSI (P-TMSI)', 'PTMSI'),
    6   : ('TV', 3, 'QoS Profile', 'QoSProfile'),
    8   : ('TV', 1, 'Reordering Required', 'ReorderingRequired'),
    9   : ('TV', 28, 'Authentication Triplet', 'AuthentTriplet'),
    11  : ('TV', 1, 'MAP Cause', 'MAPCause'),
    12  : ('TV', 3, 'P-TMSI Signature', 'PTMSISignature'),
    13  : ('TV', 1, 'MS Validated', 'MSValidated'),
    14  : ('TV', 1, 'Recovery', 'Recovery'),
    15  : ('TV', 1, 'Selection Mode', 'SelectionMode'),
    16  : ('TV', 2, 'Flow Label Data I', 'FlowLabelDataI'),
    17  : ('TV', 2, 'Flow Label Signalling', 'FlowLabelSig'),
    18  : ('TV', 3, 'Flow Label Data II', 'FlowLabelDataII'),
    19  : ('TV', 1, 'MS Not Reachable Reason', 'MSNotReachableReason'),
    127 : ('TV', 4, 'Charging ID', 'ChargingID'),
    128 : ('TLV', -1, 'End User Address', 'EndUserAddr'),
    129 : ('TLV', -1, 'MM Context', 'MMContext'),
    130 : ('TLV', -1, 'PDP Context', 'PDPContext'),
    131 : ('TLV', -1, 'Access Point Name', 'APN'),
    132 : ('TLV', -1, 'Protocol Configuration Options', 'PCO'),
    133 : ('TLV', -1, 'GSN Address', 'GSNAddr'),
    134 : ('TLV', -1, 'MS International PSTN/ISDN Number (MSISDN)', 'MSISDN'),
    251 : ('TLV', -1, 'Charging Gateway Address', 'ChargingGatewayAddr'),
    255 : ('TLV', -1, 'Private Extension', 'PrivateExt')
    }

# LUT for IE resolution (name: class)
GTPv0IELUT = {}
_globals = globals()
_undef   = {
    'Reserved'
    }
for k, infos in GTPv0IEType_dict.items():
    if infos[3] in _globals:
        GTPv0IELUT[k] = _globals[infos[3]]
    elif infos[3] not in _undef:
        print('warning: GTP v0 IE %s undefined' % infos[3])
del _globals, _undef
# enumeration for all IEs (name: type)
GTPv0IEType = IntEnum('GTPv0IEType', {v[3]: k for k, v in GTPv0IEType_dict.items()})
# dict for IE description (type: desc)
GTPv0IETypeDesc_dict = {k: v[2] for k, v in GTPv0IEType_dict.items()}


#------------------------------------------------------------------------------#
# 7.4 Path Management Messages
#------------------------------------------------------------------------------#

# Echo Request

class EchoReqIEs(GTPIEs):
    
    MAND = set()
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class EchoReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.EchoReq.value}),
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
        GTPIETV('Recovery', val={'Type': GTPv0IEType.Recovery.value}, bl={'Data': 8}),
        GTPIETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class EchoResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.EchoResp.value}),
        EchoRespIEs(hier=1),
        )


# Version Not Supported

class VersionNotSupportedIEs(GTPIEs):
    
    MAND = set()
    OPT  = set()
    
    _GEN = ()


class VersionNotSupported(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.VersionNotSupported.value}),
        VersionNotSupportedIEs(hier=1),
        )


#------------------------------------------------------------------------------#
# 7.5 Tunnel Management Messages
#------------------------------------------------------------------------------#

# Create PDP Context Request

class CreatePDPCtxtReqIEs(GTPIEs):
    
    MAND = {
        'QoSProfile',
        'SelectionMode',
        'FlowLabelDataI',
        'FlowLabelSig',
        'EndUserAddr',
        'APN',
        'SGSNAddrForSignalling',
        'SGSNAddrForUserTraffic',
        'MSISDN',
        }
    OPT  = {
        'Recovery',
        'PCO',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('QoSProfile', val={'Type': GTPv0IEType.QoSProfile.value}, bl={'Data': 24}),
        GTPIETV('Recovery', val={'Type': GTPv0IEType.Recovery.value}, bl={'Data': 8}, trans=True),
        GTPIETV('SelectionMode', val={'Type': GTPv0IEType.SelectionMode.value}, bl={'Data': 8}),
        GTPIETV('FlowLabelDataI', val={'Type': GTPv0IEType.FlowLabelDataI.value}, bl={'Data': 16}),
        GTPIETV('FlowLabelSig', val={'Type': GTPv0IEType.FlowLabelSig.value}, bl={'Data': 16}),
        GTPIETLV('EndUserAddr', val={'Type': GTPv0IEType.EndUserAddr.value}),
        GTPIETLV('APN', val={'Type': GTPv0IEType.APN.value}),
        GTPIETLV('PCO', val={'Type': GTPv0IEType.PCO.value}, trans=True),
        GTPIETLV('SGSNAddrForSignalling', val={'Type': GTPv0IEType.GSNAddr.value}),
        GTPIETLV('SGSNAddrForUserTraffic', val={'Type': GTPv0IEType.GSNAddr.value}),
        GTPIETLV('MSISDN', val={'Type': GTPv0IEType.MSISDN.value}),
        GTPIETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True)
        )


class CreatePDPCtxtReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.CreatePDPCtxtReq.value}),
        CreatePDPCtxtReqIEs(hier=1),
        )


# Create PDP Context Response

class CreatePDPCtxtRespIEs(GTPIEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'QoSProfile',
        'ReorderingRequired',
        'Recovery',
        'FlowLabelDataI',
        'FlowLabelSig',
        'ChargingID',
        'EndUserAddr',
        'PCO',
        'GGSNAddrForSignalling',
        'GGSNAddrForUserTraffic',
        'ChargingGatewayAddr',
        'PrivateExt'
        }
    
    _GEN = (
        GTPIETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPIETV('QoSProfile', val={'Type': GTPv0IEType.QoSProfile.value}, bl={'Data': 24}, trans=True),
        GTPIETV('ReorderingRequired', val={'Type': GTPv0IEType.ReorderingRequired.value}, bl={'Data': 8}, trans=True),
        GTPIETV('Recovery', val={'Type': GTPv0IEType.Recovery.value}, bl={'Data': 8}, trans=True),
        GTPIETV('FlowLabelDataI', val={'Type': GTPv0IEType.FlowLabelDataI.value}, bl={'Data': 16}, trans=True),
        GTPIETV('FlowLabelSig', val={'Type': GTPv0IEType.FlowLabelSig.value}, bl={'Data': 16}, trans=True),
        GTPIETV('ChargingID', val={'Type': GTPv0IEType.ChargingID.value}, bl={'Data': 32}, trans=True),
        GTPIETLV('EndUserAddr', val={'Type': GTPv0IEType.EndUserAddr.value}, trans=True),
        GTPIETLV('PCO', val={'Type': GTPv0IEType.PCO.value}, trans=True),
        GTPIETLV('GGSNAddrForSignalling', val={'Type': GTPv0IEType.GSNAddr.value}, trans=True),
        GTPIETLV('GGSNAddrForUserTraffic', val={'Type': GTPv0IEType.GSNAddr.value}, trans=True),
        GTPIETLV('ChargingGatewayAddr', val={'Type': GTPv0IEType.ChargingGatewayAddr.value}, trans=True),
        GTPIETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True)
        )


class CreatePDPCtxtResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.CreatePDPCtxtResp.value}),
        CreatePDPCtxtRespIEs(hier=1),
        )


