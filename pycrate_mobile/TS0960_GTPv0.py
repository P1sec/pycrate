# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.5
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
    GTPDecErr,
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
    PacketTransferCmd,
    SeqNumReleasedPackets,
    SeqNumCancelledPackets,
    RequestsResponded,
    _DataRecord,
    RecommendedNodeAddr,
    RequestsResponded,
    _GTPIE,
    GTPIETV,
    GTPIEs,
    ERR_GTP_BUF_TOO_SHORT,
    ERR_GTP_BUF_INVALID,
    ERR_GTP_TYPE_NONEXIST,
    ERR_GTP_MAND_IE_MISS
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
# and from TS 12.15, identical to TS 32.295:
# RecommendedNodeAddr
# PacketTransferCmd
# SeqNumReleasedPackets
# SeqNumCancelledPackets
# RequestsResponded

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
# Data Record Packet IE
# TS 12.15, section 7.3.4.5.4
#------------------------------------------------------------------------------#

class DataRecordPacket(Envelope):
    _GEN = (
        Uint8('Num'),
        Uint8('Fmt', dic={0: 'reserved', 1: 'ASN.1 BER', 2: 'ASN.1 UPER', 3: 'ASN.1 APER'}),
        Uint16('Vers'),
        Sequence('Recs', GEN=_DataRecord('Rec'))
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Num'].set_valauto(lambda: self['Recs'].get_num())
        self['Recs'].set_numauto(lambda: self['Num'].get_val())


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
    126 : ('TV', 1, 'Packet Transfer Command', 'PacketTransferCmd'),
    127 : ('TV', 4, 'Charging ID', 'ChargingID'),
    128 : ('TLV', -1, 'End User Address', 'EndUserAddr'),
    129 : ('TLV', -1, 'MM Context', 'MMContext'),
    130 : ('TLV', -1, 'PDP Context', 'PDPContext'),
    131 : ('TLV', -1, 'Access Point Name', 'APN'),
    132 : ('TLV', -1, 'Protocol Configuration Options', 'PCO'),
    133 : ('TLV', -1, 'GSN Address', 'GSNAddr'),
    134 : ('TLV', -1, 'MS International PSTN/ISDN Number (MSISDN)', 'MSISDN'),
    249 : ('TLV', -1, 'Sequence Numbers of Released Packets', 'SeqNumReleasedPackets'),
    250 : ('TLV', -1, 'Sequence Numbers of Cancelled Packets', 'SeqNumCancelledPackets'),
    251 : ('TLV', -1, 'Charging Gateway Address', 'ChargingGatewayAddr'),
    252 : ('TLV', -1, 'Data Record Packet', 'DataRecordPacket'),
    253 : ('TLV', -1, 'Requests Responded', 'RequestsResponded'),
    254 : ('TLV', -1, 'Recommended Node Address', 'RecommendedNodeAddr'),
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


class GTPv0IETV(GTPIETV):
    """GTPv0 Information Element in Tag-Value format, with fixed length
    
    The Data part is either a Buf object, or a dedicated object according to the 
    Type part.
    """
    
    _GEN = (
        Uint8('Type', val=1, dic=GTPv0IETypeDesc_dict),
        Buf('Data', bl=8, rep=REPR_HEX)
        )
    
    # inherited from GTPv0IETV:
    # _init_data_attr
    # get_type
    # _set_data_raw
    # _set_data_type
    # set_val
    # set_bl
    # _from_char
    
    def _set_data_cls(self):
        if not hasattr(self, '_data_cls'):
            self._init_data_attr()
        if self._data_cls is None:
            try:
                self._data_cls = GTPv0IELUT[self[0].get_val()]('Data')
            except KeyError:
                pass
        if self._data_cls is not None and self[1] != self._data_cls:
            self.replace(self[1], self._data_cls)


class GTPv0IETLV(_GTPIE):
    """GTPv0 Information Element in Tag-Length-Value format, with variable length
    
    The Data part is either a Buf object, or a dedicated object according to the
    Type part.
    """
    
    _GEN = (
        Uint8('Type', val=128, dic=GTPv0IETypeDesc_dict),
        Uint16('Len'),
        Buf('Data', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        if not hasattr(self[2], '_bl') or self[2]._bl is None:
            self[2].set_blauto(lambda: self[1].get_val()<<3)
    
    # common method with GTPv0IETV to get IE's type
    def get_type(self):
        return self[0].get_val()
    
    def _set_data_raw(self):
        if not hasattr(self, '_data_raw'):
            self._init_data_attr()
        if self._data_raw is None:
            self._data_raw = Buf('Data', rep=REPR_HEX)
            self._data_raw.set_blauto(lambda: self._get_data_len())
        if self[2] != self._data_raw:
            self.replace(self[2], self._data_raw)
    
    def _set_data_cls(self):
        if not hasattr(self, '_data_cls'):
            self._init_data_attr()
        if self._data_cls is None:
            try:
                self._data_cls = GTPv0IELUT[self[0].get_val()]('Data')
            except KeyError:
                pass
            else:
                if not hasattr(self._data_cls, '_bl') or self._data_cls._bl is None:
                    self._data_cls.set_blauto(lambda: self[1].get_val()<<3)
        if self._data_cls is not None and self[2] != self._data_cls:
            self.replace(self[2], self._data_cls)
    
    def _set_data_type(self, d, t):
        if t is not None:
            self[0].set_val(t)
        if isinstance(d, bytes_types):
            self._set_data_raw()
        else:
            self._set_data_cls()
        self[2].set_val(d)
    
    # set_val() method can be used with both type of values for Data:
    # - bytes, assigned to the Buf raw object
    # - dedicated type, assigned to the dedicated object
    def set_val(self, val):
        if isinstance(val, (tuple, list)) and 1<= len(val) <= 3:
            self[0].set_val(val[0])
            if len(val) > 1:
                self[1].set_val(val[1])
            if len(val) == 3:
                if isinstance(val[2], bytes_types):
                    self._set_data_raw()
                else:
                    self._set_data_cls()
                self[2].set_val(val[2])
            else:
                self._set_data_cls()
        elif isinstance(val, dict):
            if 'Data' in val:
                if 'Type' in val:
                    self._set_data_type(val['Data'], val['Type'])
                else:
                    self._set_data_type(val['Data'], None)
            else:
                Envelope.set_val(self, val)
                self._set_data_cls()
        else:
            Envelope.set_val(self, val)
    
    # _from_char() method attempts to decode Data with the dedicated object
    # and fallbacks to the Buf raw object if failing with the former.
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        self[1]._from_char(char)
        # 1st try decoding with the structured Data
        char_cur = char._cur
        self._set_data_cls()
        try:
            self[2]._from_char(char)
        except PycrateErr:
            # 2nd try decoding as raw Data
            char._cur = char_cur
            self._set_data_raw()
            self[2]._from_char(char)


class GTPv0IEs(GTPIEs):
    """GTPv0 sequence of Information Elements
    """
    
    _GEN = ()
    
    # restore default transparency behaviour
    ENV_SEL_TRANS = False
    
    # this is to raise in case a mandatory IE is not found during the decoding
    VERIF_MAND = True
    
    # This defines sets of mandatory or optional (whether conditional or not) 
    # GTPIE types
    MAND = set()
    OPT  = set()
    
    # unknown / proprietary additional IE
    _IE_unk = GTPv0IETLV
    
    # inherited from GTPv0IEs:
    # __init__
    # set_val
    # _from_char
    # add_ie
    # rem_ie
    # init_ies
    # chk_comp
    
    def _get_type_from_char(self, char):
        return char.to_uint(8)


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
        Uint('Digit15', val=0, bl=4)
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
        if isinstance(vals, (tuple, list)) and len(vals) in (1, 2) \
        and isinstance(vals[0], str_types):
            self.encode(*vals)
            return
        elif isinstance(vals, dict):
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
        imsi, nsapi = self.decode()
        return '<%s%s%s : %s - %s>' % (self._name, desc, trans, imsi, str(nsapi))
    
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
    GPDU                            = 255

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
        GTPv0IEs(hier=1)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_blauto(lambda: self._get_ies_len())
    
    def _get_ies_len(self):
        return self[0]['Len'].get_val() << 3


#------------------------------------------------------------------------------#
# 7.4 Path Management Messages
#------------------------------------------------------------------------------#

# Echo Request

class EchoReqIEs(GTPv0IEs):
    
    MAND = set()
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class EchoReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.EchoReq.value}),
        EchoReqIEs(hier=1),
        )


# Echo Response

class EchoRespIEs(GTPv0IEs):
    
    MAND = {
        'Recovery'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Recovery', val={'Type': GTPv0IEType.Recovery.value}, bl={'Data': 8}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class EchoResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.EchoResp.value}),
        EchoRespIEs(hier=1),
        )


# Version Not Supported

class VersionNotSupportedIEs(GTPv0IEs):
    
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

class CreatePDPCtxtReqIEs(GTPv0IEs):
    
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
        'RAI',
        'Recovery',
        'PCO',
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('RAI', val={'Type': GTPv0IEType.RAI.value}, bl={'Data': 48}, trans=True),
        GTPv0IETV('QoSProfile', val={'Type': GTPv0IEType.QoSProfile.value}, bl={'Data': 24}),
        GTPv0IETV('Recovery', val={'Type': GTPv0IEType.Recovery.value}, bl={'Data': 8}, trans=True),
        GTPv0IETV('SelectionMode', val={'Type': GTPv0IEType.SelectionMode.value}, bl={'Data': 8}),
        GTPv0IETV('FlowLabelDataI', val={'Type': GTPv0IEType.FlowLabelDataI.value}, bl={'Data': 16}),
        GTPv0IETV('FlowLabelSig', val={'Type': GTPv0IEType.FlowLabelSig.value}, bl={'Data': 16}),
        GTPv0IETLV('EndUserAddr', val={'Type': GTPv0IEType.EndUserAddr.value}),
        GTPv0IETLV('APN', val={'Type': GTPv0IEType.APN.value}),
        GTPv0IETLV('PCO', val={'Type': GTPv0IEType.PCO.value}, trans=True),
        GTPv0IETLV('SGSNAddrForSignalling', val={'Type': GTPv0IEType.GSNAddr.value}),
        GTPv0IETLV('SGSNAddrForUserTraffic', val={'Type': GTPv0IEType.GSNAddr.value}),
        GTPv0IETLV('MSISDN', val={'Type': GTPv0IEType.MSISDN.value}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True)
        )


class CreatePDPCtxtReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.CreatePDPCtxtReq.value}),
        CreatePDPCtxtReqIEs(hier=1),
        )


# Create PDP Context Response

class CreatePDPCtxtRespIEs(GTPv0IEs):
    
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
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETV('QoSProfile', val={'Type': GTPv0IEType.QoSProfile.value}, bl={'Data': 24}, trans=True),
        GTPv0IETV('ReorderingRequired', val={'Type': GTPv0IEType.ReorderingRequired.value}, bl={'Data': 8}, trans=True),
        GTPv0IETV('Recovery', val={'Type': GTPv0IEType.Recovery.value}, bl={'Data': 8}, trans=True),
        GTPv0IETV('FlowLabelDataI', val={'Type': GTPv0IEType.FlowLabelDataI.value}, bl={'Data': 16}, trans=True),
        GTPv0IETV('FlowLabelSig', val={'Type': GTPv0IEType.FlowLabelSig.value}, bl={'Data': 16}, trans=True),
        GTPv0IETV('ChargingID', val={'Type': GTPv0IEType.ChargingID.value}, bl={'Data': 32}, trans=True),
        GTPv0IETLV('EndUserAddr', val={'Type': GTPv0IEType.EndUserAddr.value}, trans=True),
        GTPv0IETLV('PCO', val={'Type': GTPv0IEType.PCO.value}, trans=True),
        GTPv0IETLV('GGSNAddrForSignalling', val={'Type': GTPv0IEType.GSNAddr.value}, trans=True),
        GTPv0IETLV('GGSNAddrForUserTraffic', val={'Type': GTPv0IEType.GSNAddr.value}, trans=True),
        GTPv0IETLV('ChargingGatewayAddr', val={'Type': GTPv0IEType.ChargingGatewayAddr.value}, trans=True),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True)
        )


class CreatePDPCtxtResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.CreatePDPCtxtResp.value}),
        CreatePDPCtxtRespIEs(hier=1),
        )


# Update PDP Context Request

class UpdatePDPCtxtReqIEs(GTPv0IEs):
    
    MAND = {
        'QoSProfile',
        'FlowLabelDataI',
        'FlowLabelSig',
        'SGSNAddrForSignalling',
        'SGSNAddrForUserTraffic',
        }
    OPT  = {
        'RAI',
        'Recovery',
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('RAI', val={'Type': GTPv0IEType.RAI.value}, bl={'Data': 48}, trans=True),
        GTPv0IETV('QoSProfile', val={'Type': GTPv0IEType.QoSProfile.value}, bl={'Data': 24}),
        GTPv0IETV('Recovery', val={'Type': GTPv0IEType.Recovery.value}, bl={'Data': 8}, trans=True),
        GTPv0IETV('FlowLabelDataI', val={'Type': GTPv0IEType.FlowLabelDataI.value}, bl={'Data': 16}),
        GTPv0IETV('FlowLabelSig', val={'Type': GTPv0IEType.FlowLabelSig.value}, bl={'Data': 16}),
        GTPv0IETLV('SGSNAddrForSignalling', val={'Type': GTPv0IEType.GSNAddr.value}),
        GTPv0IETLV('SGSNAddrForUserTraffic', val={'Type': GTPv0IEType.GSNAddr.value}),
        GTPv0IETLV('MSISDN', val={'Type': GTPv0IEType.MSISDN.value}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True)
        )


class UpdatePDPCtxtReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.UpdatePDPCtxtReq.value}),
        UpdatePDPCtxtReqIEs(hier=1),
        )


# Update PDP Context Response

class UpdatePDPCtxtRespIEs(GTPv0IEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'QoSProfile',
        'Recovery',
        'FlowLabelDataI',
        'FlowLabelSig',
        'ChargingID',
        'GGSNAddrForSignalling',
        'GGSNAddrForUserTraffic',
        'ChargingGatewayAddr',
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETV('QoSProfile', val={'Type': GTPv0IEType.QoSProfile.value}, bl={'Data': 24}, trans=True),
        GTPv0IETV('Recovery', val={'Type': GTPv0IEType.Recovery.value}, bl={'Data': 8}, trans=True),
        GTPv0IETV('FlowLabelDataI', val={'Type': GTPv0IEType.FlowLabelDataI.value}, bl={'Data': 16}, trans=True),
        GTPv0IETV('FlowLabelSig', val={'Type': GTPv0IEType.FlowLabelSig.value}, bl={'Data': 16}, trans=True),
        GTPv0IETV('ChargingID', val={'Type': GTPv0IEType.ChargingID.value}, bl={'Data': 32}, trans=True),
        GTPv0IETLV('GGSNAddrForSignalling', val={'Type': GTPv0IEType.GSNAddr.value}, trans=True),
        GTPv0IETLV('GGSNAddrForUserTraffic', val={'Type': GTPv0IEType.GSNAddr.value}, trans=True),
        GTPv0IETLV('ChargingGatewayAddr', val={'Type': GTPv0IEType.ChargingGatewayAddr.value}, trans=True),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True)
        )


class UpdatePDPCtxtResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.UpdatePDPCtxtResp.value}),
        UpdatePDPCtxtRespIEs(hier=1),
        )


# Delete PDP Context Request

class DeletePDPCtxtReqIEs(GTPv0IEs):
    
    MAND = set()
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class DeletePDPCtxtReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.DeletePDPCtxtReq.value}),
        DeletePDPCtxtReqIEs(hier=1),
        )


# Delete PDP Context Response

class DeletePDPCtxtRespIEs(GTPv0IEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True)
        )


class DeletePDPCtxtResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.DeletePDPCtxtResp.value}),
        DeletePDPCtxtRespIEs(hier=1),
        )


# Create AA PDP Context Request

class CreateAAPDPCtxtReqIEs(GTPv0IEs):
    
    MAND = {
        'QoSProfile',
        'SelectionMode',
        'FlowLabelDataI',
        'FlowLabelSig',
        'EndUserAddr',
        'APN',
        'SGSNAddrForSignalling',
        'SGSNAddrForUserTraffic'
        }
    OPT  = {
        'Recovery',
        'PCO',
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('QoSProfile', val={'Type': GTPv0IEType.QoSProfile.value}, bl={'Data': 24}),
        GTPv0IETV('Recovery', val={'Type': GTPv0IEType.Recovery.value}, bl={'Data': 8}, trans=True),
        GTPv0IETV('SelectionMode', val={'Type': GTPv0IEType.SelectionMode.value}, bl={'Data': 8}),
        GTPv0IETV('FlowLabelDataI', val={'Type': GTPv0IEType.FlowLabelDataI.value}, bl={'Data': 16}),
        GTPv0IETV('FlowLabelSig', val={'Type': GTPv0IEType.FlowLabelSig.value}, bl={'Data': 16}),
        GTPv0IETLV('EndUserAddr', val={'Type': GTPv0IEType.EndUserAddr.value}),
        GTPv0IETLV('APN', val={'Type': GTPv0IEType.APN.value}),
        GTPv0IETLV('PCO', val={'Type': GTPv0IEType.PCO.value}, trans=True),
        GTPv0IETLV('SGSNAddrForSignalling', val={'Type': GTPv0IEType.GSNAddr.value}),
        GTPv0IETLV('SGSNAddrForUserTraffic', val={'Type': GTPv0IEType.GSNAddr.value}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True)
        )


class CreateAAPDPCtxtReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.CreateAAPDPCtxtReq.value}),
        CreateAAPDPCtxtReqIEs(hier=1),
        )


# Create AA PDP Context Response

class CreateAAPDPCtxtRespIEs(GTPv0IEs):
    
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
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETV('QoSProfile', val={'Type': GTPv0IEType.QoSProfile.value}, bl={'Data': 24}, trans=True),
        GTPv0IETV('ReorderingRequired', val={'Type': GTPv0IEType.ReorderingRequired.value}, bl={'Data': 8}, trans=True),
        GTPv0IETV('Recovery', val={'Type': GTPv0IEType.Recovery.value}, bl={'Data': 8}, trans=True),
        GTPv0IETV('FlowLabelDataI', val={'Type': GTPv0IEType.FlowLabelDataI.value}, bl={'Data': 16}, trans=True),
        GTPv0IETV('FlowLabelSig', val={'Type': GTPv0IEType.FlowLabelSig.value}, bl={'Data': 16}, trans=True),
        GTPv0IETV('ChargingID', val={'Type': GTPv0IEType.ChargingID.value}, bl={'Data': 32}, trans=True),
        GTPv0IETLV('EndUserAddr', val={'Type': GTPv0IEType.EndUserAddr.value}, trans=True),
        GTPv0IETLV('PCO', val={'Type': GTPv0IEType.PCO.value}, trans=True),
        GTPv0IETLV('GGSNAddrForSignalling', val={'Type': GTPv0IEType.GSNAddr.value}, trans=True),
        GTPv0IETLV('GGSNAddrForUserTraffic', val={'Type': GTPv0IEType.GSNAddr.value}, trans=True),
        GTPv0IETLV('ChargingGatewayAddr', val={'Type': GTPv0IEType.ChargingGatewayAddr.value}, trans=True),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True)
        )


class CreateAAPDPCtxtResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.CreateAAPDPCtxtResp.value}),
        CreateAAPDPCtxtRespIEs(hier=1),
        )


# Delete AA PDP Context Request

class DeleteAAPDPCtxtReqIEs(GTPv0IEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True)
        )


class DeleteAAPDPCtxtReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.DeleteAAPDPCtxtReq.value}),
        DeleteAAPDPCtxtReqIEs(hier=1),
        )


# Delete AA PDP Context Response

class DeleteAAPDPCtxtRespIEs(GTPv0IEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True)
        )


class DeleteAAPDPCtxtResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.DeleteAAPDPCtxtResp.value}),
        DeleteAAPDPCtxtRespIEs(hier=1),
        )


# Error Indication

class ErrorIndIEs(GTPv0IEs):
    
    MAND = set()
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class ErrorInd(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.ErrorInd.value}),
        ErrorIndIEs(hier=1),
        )


# PDU Notification Request

class PDUNotifReqIEs(GTPv0IEs):
    
    MAND = {
        'EndUserAddr',
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETLV('EndUserAddr', val={'Type': GTPv0IEType.EndUserAddr.value}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class PDUNotifReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.PDUNotifReq.value}),
        PDUNotifReqIEs(hier=1),
        )


# PDU Notification Response

class PDUNotifRespIEs(GTPv0IEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class PDUNotifResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.PDUNotifResp.value}),
        PDUNotifRespIEs(hier=1),
        )


# PDU Notification Reject Request

class PDUNotifRejectReqIEs(GTPv0IEs):
    
    MAND = {
        'Cause',
        'EndUserAddr',
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETLV('EndUserAddr', val={'Type': GTPv0IEType.EndUserAddr.value}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class PDUNotifRejectReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.PDUNotifRejectReq.value}),
        PDUNotifRejectReqIEs(hier=1),
        )


# PDU Notification Reject Response

class PDUNotifRejectRespIEs(GTPv0IEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class PDUNotifRejectResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.PDUNotifRejectResp.value}),
        PDUNotifRejectRespIEs(hier=1),
        )


#------------------------------------------------------------------------------#
# 7.6 Location Management Messages
#------------------------------------------------------------------------------#
# optional interface between HLR and GGSN within a PLMN
# Eventually supported through GTP / TCAP-MAP interworking

# Send Routeing Information for GPRS Request

class SendRouteingInfoforGPRSReqIEs(GTPv0IEs):
    
    MAND = {
        'IMSI'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('IMSI', val={'Type': GTPv0IEType.IMSI.value}, bl={'Data': 64}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class SendRouteingInfoforGPRSReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.SendRouteingInfoforGPRSReq.value}),
        SendRouteingInfoforGPRSReqIEs(hier=1),
        )


# Send Routeing Information for GPRS Response

class SendRouteingInfoforGPRSRespIEs(GTPv0IEs):
    
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
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETV('IMSI', val={'Type': GTPv0IEType.IMSI.value}, bl={'Data': 64}),
        GTPv0IETV('MAPCause', val={'Type': GTPv0IEType.MAPCause.value}, bl={'Data': 8}, trans=True),
        GTPv0IETV('MSNotReachableReason', val={'Type': GTPv0IEType.MSNotReachableReason.value}, bl={'Data': 8}, trans=True),
        GTPv0IETLV('GSNAddr', val={'Type': GTPv0IEType.GSNAddr.value}, trans=True),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class SendRouteingInfoforGPRSResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.SendRouteingInfoforGPRSResp.value}),
        SendRouteingInfoforGPRSRespIEs(hier=1),
        )


# Failure Report Request

class FailureReportReqIEs(GTPv0IEs):
    
    MAND = {
        'IMSI'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('IMSI', val={'Type': GTPv0IEType.IMSI.value}, bl={'Data': 64}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class FailureReportReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.FailureReportReq.value}),
        FailureReportReqIEs(hier=1),
        )


# Failure Report Response

class FailureReportRespIEs(GTPv0IEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'MAPCause',
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETV('MAPCause', val={'Type': GTPv0IEType.MAPCause.value}, bl={'Data': 8}, trans=True),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class FailureReportResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.FailureReportResp.value}),
        FailureReportRespIEs(hier=1),
        )


# Note MS Present Request

class NoteMSGPRSPresentReqIEs(GTPv0IEs):
    
    MAND = {
        'IMSI',
        'GSNAddr'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('IMSI', val={'Type': GTPv0IEType.IMSI.value}, bl={'Data': 64}),
        GTPv0IETLV('GSNAddr', val={'Type': GTPv0IEType.GSNAddr.value}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class NoteMSGPRSPresentReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.NoteMSGPRSPresentReq.value}),
        NoteMSGPRSPresentReqIEs(hier=1),
        )


# Note MS Present Response

class NoteMSGPRSPresentRespIEs(GTPv0IEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class NoteMSGPRSPresentResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.NoteMSGPRSPresentResp.value}),
        NoteMSGPRSPresentRespIEs(hier=1),
        )


#------------------------------------------------------------------------------#
# 7.7 Mobility Management Messages
#------------------------------------------------------------------------------#
# interface between SGSNs within a PLMN

# Identification Request

class IdentificationReqIEs(GTPv0IEs):
    
    MAND = {
        'RAI',
        'PTMSI'
        }
    OPT  = {
        'PTMSISignature',
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('RAI', val={'Type': GTPv0IEType.RAI.value}, bl={'Data': 48}),
        GTPv0IETV('PTMSI', val={'Type': GTPv0IEType.PTMSI.value}, bl={'Data': 32}),
        GTPv0IETV('PTMSISignature', val={'Type': GTPv0IEType.PTMSISignature.value}, bl={'Data': 24}, trans=True),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class IdentificationReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.IdentificationReq.value}),
        IdentificationReqIEs(hier=1),
        )


# Identification Response

class IdentificationRespIEs(GTPv0IEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'IMSI',
        'AuthentTriplet',
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETV('IMSI', val={'Type': GTPv0IEType.IMSI.value}, bl={'Data': 64}, trans=True),
        GTPv0IETV('AuthentTriplet', val={'Type': GTPv0IEType.AuthentTriplet.value}, bl={'Data': 224}, trans=True),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class IdentificationResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.IdentificationResp.value}),
        IdentificationRespIEs(hier=1),
        )


# SGSN Context Request

class SGSNCtxtReqIEs(GTPv0IEs):
    
    MAND = {
        'RAI',
        'TLLI',
        'FlowLabelSig'
        }
    OPT  = {
        'IMSI',
        'PTMSISignature',
        'MSValidated',
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('IMSI', val={'Type': GTPv0IEType.IMSI.value}, bl={'Data': 64}, trans=True),
        GTPv0IETV('RAI', val={'Type': GTPv0IEType.RAI.value}, bl={'Data': 48}),
        GTPv0IETV('TLLI', val={'Type': GTPv0IEType.TLLI.value}, bl={'Data': 8}),
        GTPv0IETV('PTMSISignature', val={'Type': GTPv0IEType.PTMSISignature.value}, bl={'Data': 24}, trans=True),
        GTPv0IETV('MSValidated', val={'Type': GTPv0IEType.MSValidated.value}, bl={'Data': 8}, trans=True),
        GTPv0IETV('FlowLabelSig', val={'Type': GTPv0IEType.FlowLabelSig.value}, bl={'Data': 16}, trans=True),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class SGSNCtxtReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.SGSNCtxtReq.value}),
        SGSNCtxtReqIEs(hier=1),
        )


# SGSN Context Response

class SGSNCtxtRespIEs(GTPv0IEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'IMSI',
        'FlowLabelSig',
        'MMContext',
        'PDPContext',
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETV('IMSI', val={'Type': GTPv0IEType.IMSI.value}, bl={'Data': 64}, trans=True),
        GTPv0IETV('FlowLabelSig', val={'Type': GTPv0IEType.FlowLabelSig.value}, bl={'Data': 16}, trans=True),
        GTPv0IETLV('MMContext', val={'Type': GTPv0IEType.MMContext.value}, trans=True),
        GTPv0IETLV('PDPContext', val={'Type': GTPv0IEType.PDPContext.value}, trans=True),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class SGSNCtxtResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.SGSNCtxtResp.value}),
        SGSNCtxtRespIEs(hier=1),
        )


# SGSN Context Acknowledge

class SGSNCtxtAckIEs(GTPv0IEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'FlowLabelDataII',
        'SGSNAddrForUserTraffic',
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETV('FlowLabelDataII', val={'Type': GTPv0IEType.FlowLabelDataII.value}, bl={'Data': 24}, trans=True),
        GTPv0IETLV('SGSNAddrForUserTraffic', val={'Type': GTPv0IEType.GSNAddr.value}, trans=True),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class SGSNCtxtAck(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.SGSNCtxtAck.value}),
        SGSNCtxtAckIEs(hier=1),
        )


#------------------------------------------------------------------------------#
# 8 Transmission Plane
#------------------------------------------------------------------------------#

class GPDU(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 1, 'Type': GTPv0MsgType.GPDU.value}),
        Buf('TPDU', hier=1, rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# GTP' message type
# TS 12.15, section 7.3.4
#------------------------------------------------------------------------------#

# Node Alive Request

class NodeAliveReqIEs(GTPv0IEs):
    
    MAND = {
        'NodeAddr'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETLV('NodeAddr', val={'Type': GTPv0IEType.ChargingGatewayAddr.value}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class NodeAliveReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 0, 'Type': GTPv0MsgType.NodeAliveReq.value}),
        NodeAliveReqIEs(hier=1),
        )


# Node Alive Response

class NodeAliveRespIEs(GTPv0IEs):
    
    MAND = set()
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class NodeAliveResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 0, 'Type': GTPv0MsgType.NodeAliveResp.value}),
        NodeAliveRespIEs(hier=1),
        )



# Redirection Request

class RedirectionReqIEs(GTPv0IEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'RecommendedNodeAddr',
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETLV('RecommendedNodeAddr', val={'Type': GTPv0IEType.RecommendedNodeAddr.value}, trans=True),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class RedirectionReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 0, 'Type': GTPv0MsgType.RedirectionReq.value}),
        RedirectionReqIEs(hier=1),
        )


# Redirection Response

class RedirectionRespIEs(GTPv0IEs):
    
    MAND = {
        'Cause'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class RedirectionResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 0, 'Type': GTPv0MsgType.RedirectionResp.value}),
        RedirectionRespIEs(hier=1),
        )


# Data Record Transfer Request

class DataRecordTransferReqIEs(GTPv0IEs):
    
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
        GTPv0IETV('PacketTransferCmd', val={'Type': GTPv0IEType.PacketTransferCmd.value}, bl={'Data': 8}),
        GTPv0IETLV('DataRecordPacket', val={'Type': GTPv0IEType.DataRecordPacket.value}, trans=True),
        GTPv0IETLV('SeqNumReleasedPackets', val={'Type': GTPv0IEType.SeqNumReleasedPackets.value}, trans=True),
        GTPv0IETLV('SeqNumCancelledPackets', val={'Type': GTPv0IEType.SeqNumCancelledPackets.value}, trans=True),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class DataRecordTransferReq(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 0, 'Type': GTPv0MsgType.DataRecordTransferReq.value}),
        DataRecordTransferReqIEs(hier=1),
        )


# Data Record Transfer Response

class DataRecordTransferRespIEs(GTPv0IEs):
    
    MAND = {
        'Cause',
        'RequestsResponded'
        }
    OPT  = {
        'PrivateExt'
        }
    
    _GEN = (
        GTPv0IETV('Cause', val={'Type': GTPv0IEType.Cause.value}, bl={'Data': 8}),
        GTPv0IETLV('RequestsResponded', val={'Type': GTPv0IEType.RequestsResponded.value}),
        GTPv0IETLV('PrivateExt', val={'Type': GTPv0IEType.PrivateExt.value}, trans=True),
        )


class DataRecordTransferResp(GTPv0Msg):
    _GEN = (
        GTPv0Hdr(val={'PT': 0, 'Type': GTPv0MsgType.DataRecordTransferResp.value}),
        DataRecordTransferRespIEs(hier=1),
        )


#------------------------------------------------------------------------------#
# General parser    
#------------------------------------------------------------------------------#

INI_ANY  = 'Any'
INI_SGSN = 'SGSN'
INI_GGSN = 'GGSN'
INI_HLR  = 'HLR' # Actually, not directly the HLR, but the GTP-MAP converter in front of the HLR
INI_CGF  = 'CGF' # Charging Gateway Function


# GTP-C v0 requests (code, initiator) / responses (code, initiator)
GTPv0ReqResp = {
    #
    # error messages that could eventually come in reponse to any kind of request:
    # 3: VersionNotSupported
    # 26: ErrorInd
    #
    # Path mgmt
    'Path': {
        (1, INI_ANY) : (2, INI_ANY),
        (3, INI_ANY) : (None, INI_ANY),
        },
    #
    # Tunnel mgmt
    'Tun': {
        (16, INI_SGSN) : (17, INI_GGSN),
        (18, INI_SGSN) : (19, INI_GGSN),
        (18, INI_GGSN) : (19, INI_SGSN),
        (20, INI_SGSN) : (21, INI_GGSN),
        (22, INI_SGSN) : (23, INI_GGSN),
        (24, INI_SGSN) : (25, INI_SGSN),
        (24, INI_GGSN) : (25, INI_GGSN),
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
        },
    #
    # GPDU
    'UE': {
        (255, INI_SGSN) : (None, INI_GGSN),
        (255, INI_GGSN) : (None, INI_SGSN),
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

GTPv0ReqResp_flat = {}
[GTPv0ReqResp_flat.update(req_resp_d) for req_resp_d in GTPv0ReqResp.values()]


GTPv0Dispatcher = {
    # GTP
    # Path mgmt
    1 : EchoReq,
    2 : EchoResp,
    3 : VersionNotSupported,
    #
    # Tunnel mgmt
    16 : CreatePDPCtxtReq,
    17 : CreatePDPCtxtResp,
    18 : UpdatePDPCtxtReq,
    19 : UpdatePDPCtxtResp,
    20 : DeletePDPCtxtReq,
    21 : DeletePDPCtxtResp,
    22 : CreateAAPDPCtxtReq,
    23 : CreateAAPDPCtxtResp,
    24 : DeleteAAPDPCtxtReq,
    25 : DeleteAAPDPCtxtResp,
    26 : ErrorInd,
    27 : PDUNotifReq,
    28 : PDUNotifResp,
    29 : PDUNotifRejectReq,
    30 : PDUNotifRejectResp,
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
    #
    # GTP'
    4 : NodeAliveReq,
    5 : NodeAliveResp,
    6 : RedirectionReq,
    7 : RedirectionResp,
    240 : DataRecordTransferReq,
    241 : DataRecordTransferResp,
    #
    # User-Plane
    255 : GPDU,
    }


ERR_GTP_BUF_TOO_SHORT = 1
ERR_GTP_BUF_INVALID   = 2
ERR_GTP_TYPE_NONEXIST = 3
ERR_GTP_MAND_IE_MISS  = 4


def parse_GTPv0(buf):
    """parses the buffer `buf' for GTPv0 message as received by a SGSN or GGSN
    and returns a 2-tuple:
    - GTPv0 message structure, or None if parsing failed
    - parsing error code, 0 if parsing succeeded, > 0 otherwise
    """
    if len(buf) < 20:
        return None, ERR_GTP_BUF_TOO_SHORT
    typ = buf[1]
    try:
        Msg = GTPv0Dispatcher[typ]()
    except KeyError:
        return None, ERR_GTP_TYPE_NONEXIST
    try:
        Msg.from_bytes(buf)
    except GTPDecErr:
        GTPv0IEs.VERIF_MAND = False
        Msg = Msg.__class__()
        try:
            Msg.from_bytes(buf)
            GTPv0IEs.VERIF_MAND = True
        except Exception:
            GTPv0IEs.VERIF_MAND = True
            return None, ERR_GTP_BUF_INVALID
        else:
            return Msg, ERR_GTP_MAND_IE_MISS
    except Exception:
        return None, ERR_GTP_BUF_INVALID
    else:
        return Msg, 0

