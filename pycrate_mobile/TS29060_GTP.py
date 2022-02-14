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
}


class GTPIEHdr(Envelope):
    """GTPv1-C Information Element's header
    """
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint8('Type', val=0, dic=GTPIEType_dict),
        Uint16('Len'), # present if Type & 0x80 == 1
        Uint16('TypeExt'), # present if Type == 238
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        # TODO: verify if Len can be absent, or just fixed
        #self['Len'].set_transauto(lambda: not self['Type'].get_val() & 0x80)
        self['TypeExt'].set_transauto(lambda: self['Type'].get_val() != 238)


class GTPIE(Envelope):
    """GTPv1-C Information Element
    """
    
    _GEN = (
        GTPIEHdr(),
        Buf('GTPIEData', rep=REPR_HEX, hier=1)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0][1].set_valauto(lambda: self._get_len())
    
    def _get_len(self):
        l = 0
        if len(self._content) > 1:
            # IE data
            l += self._content[1].get_len()
        if self[0][0].get_val() == 254:
            # extended type
            l += 2
        return l


