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
# * File Name : pycrate_mobile/TS29281_GTPU.py
# * Created : 2019-07-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/


__all__ = [
    # GTPU extension headers
    'GTPUHdrExtAuto',
    'GTPUHdrExt3',
    'GTPUHdrExt32',
    'GTPUHdrExt64',
    'GTPUHdrExt129',
    'GTPUHdrExt131',
    'GTPUHdrExt132',
    'GTPUHdrExt133',
    'GTPUHdrExt192',
    # GTPU Messages
    'GTPUMsg',
    'GTPUEchoRequest',
    'GTPUEchoResponse',
    'GTPUErrorInd',
    'GTPUSuppExtHdrNotif',
    'GTPUEndMarker',
    'GPDU',
    # GTPU Message parser and associated errors
    'parse_GTPU',
    'ERR_GTPU_BUF_TOO_SHORT',
    'ERR_GTPU_BUF_INVALID',
    'ERR_GTPU_TYPE_NONEXIST'
    ]


#------------------------------------------------------------------------------#
# 3GPP TS 29.281: General Packet Radio System (GPRS) Tunnelling Protocol 
# User Plane (GTPv1-U)
# release 15 (f50)
#------------------------------------------------------------------------------#

from enum import IntEnum

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *


#------------------------------------------------------------------------------#
# GTP-U Extension Header
# TS 29.281, section 5.2
#------------------------------------------------------------------------------#

GTPUNextExtHeader_dict = {
    0 : 'No more extension headers',
    1 : 'Reserved - Control Plane only',
    2 : 'Reserved - Control Plane only',
    3 : 'Long PDCP PDU Number',
    32 : 'Service Class Indicator',
    64 : 'UDP source port of the triggering message',
    129 : 'RAN Container',
    130 : 'Long PDCP PDU Number',
    131 : 'Xw RAN Container',
    132 : 'NR RAN Container',
    133 : 'PDU Session Container',
    192 : 'PDCP PDU Number',
    193 : 'Reserved - Control Plane only',
    194 : 'Reserved - Control Plane only'
    }

# non-automated base class
class GTPUHdrExt(Envelope):
    _ID  = 0xff 
    _GEN = (
        Uint8('Len'),
        Buf('Content'),
        Uint8('NextExt', dic=GTPUNextExtHeader_dict)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[-1].set_valauto(lambda: self._get_next_hdr())
    
    def _get_next_hdr(self):
        n = self.get_next()
        if n and hasattr(n, '_ID'):
            return n._ID
        else:
            return 0


class BufAligned(Buf):
    PAD = b'\0'
    
    def set_val(self, val):
        pad_len = -(len(val)+2) % 4
        if pad_len:
            Buf.set_val(self, val + pad_len*self.PAD)
        else:
            Buf.set_val(self, val)


# automated base class
class GTPUHdrExtAuto(GTPUHdrExt):
    _ID  = 0xff 
    _GEN = (
        Uint8('Len'),
        BufAligned('Content', rep=REPR_HEX),
        Uint8('NextExt', dic=GTPUNextExtHeader_dict)
        )
    
    def __init__(self, *args, **kwargs):
        GTPUHdrExt.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: (2 + self[1].get_len()) >> 2)
        self[1].set_blauto(lambda: max(0, (self[0].get_val()*32) - 16))


#------------------------------------------------------------------------------#
# UDP Port
# TS 29.281, section 5.2.2.1
#------------------------------------------------------------------------------#

class GTPUHdrExt64(GTPUHdrExt):
    _ID  = 64
    _GEN = (
        Uint8('Len', val=1),
        Uint16('UDPPort'),
        Uint8('NextExt')
        )


#------------------------------------------------------------------------------#
# PDCP PDU Number
# TS 29.281, section 5.2.2.2
#------------------------------------------------------------------------------#

class GTPUHdrExt192(GTPUHdrExt):
    _ID  = 192
    _GEN = (
        Uint8('Len', val=1),
        Uint('PDCPPDUNumber', bl=15),
        Uint('spare', bl=1, rep=REPR_HEX),
        Uint8('NextExt')
        )


#------------------------------------------------------------------------------#
# Long PDCP PDU Number
# TS 29.281, section 5.2.2.2A
#------------------------------------------------------------------------------#

class GTPUHdrExt3(GTPUHdrExt):
    _ID  = 3
    _GEN = (
        Uint8('Len', val=2),
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('LongPDCPPDUNumber', bl=18),
        Uint24('spare', rep=REPR_HEX),
        Uint8('NextExt')
        )


#------------------------------------------------------------------------------#
# Service Class Indicator
# TS 29.281, section 5.2.2.3
#------------------------------------------------------------------------------#

class GTPUHdrExt32(GTPUHdrExt):
    _ID  = 32
    _GEN = (
        Uint8('Len', val=1),
        Uint8('ServiceClassInd'),
        Uint8('spare', rep=REPR_HEX),
        Uint8('NextExt')
        )


#------------------------------------------------------------------------------#
# RAN Container
# TS 29.281, section 5.2.2.4
#------------------------------------------------------------------------------#

class GTPUHdrExt129(GTPUHdrExtAuto):
    _ID  = 129
    _GEN = (
        Uint8('Len'),
        BufAligned('RANContainer', rep=REPR_HEX),
        Uint8('NextExt')
        )


#------------------------------------------------------------------------------#
# Xw RAN Container
# TS 29.281, section 5.2.2.5
#------------------------------------------------------------------------------#

class GTPUHdrExt131(GTPUHdrExtAuto):
    _ID  = 131
    _GEN = (
        Uint8('Len'),
        BufAligned('XwRANContainer', rep=REPR_HEX),
        Uint8('NextExt')
        )


#------------------------------------------------------------------------------#
# NR RAN Container
# TS 29.281, section 5.2.2.6
#------------------------------------------------------------------------------#

class GTPUHdrExt132(GTPUHdrExtAuto):
    _ID  = 132
    _GEN = (
        Uint8('Len'),
        BufAligned('NRRANContainer', rep=REPR_HEX),
        Uint8('NextExt')
        )


#------------------------------------------------------------------------------#
# PDU Session Container
# TS 29.281, section 5.2.2.7
#------------------------------------------------------------------------------#

class GTPUHdrExt133(GTPUHdrExtAuto):
    _ID  = 133
    _GEN = (
        Uint8('Len'),
        BufAligned('PDUSessionContainer', rep=REPR_HEX),
        Uint8('NextExt')
        )


#------------------------------------------------------------------------------#
# GTP-U header
# TS 29.281, section 5.1
#------------------------------------------------------------------------------#

# Warning: this GTPUHdrExtList is not friendly to build, as the user requires to
# explicitely add GTPUHdrExt.. into it when building a message

class GTPUHdrExtList(Envelope):
    _GEN = ()
    _HdrExt = {
        3 : GTPUHdrExt3,
        32 : GTPUHdrExt32,
        64 : GTPUHdrExt64,
        129 : GTPUHdrExt129,
        130 : GTPUHdrExt3,
        131 : GTPUHdrExt131,
        132 : GTPUHdrExt132,
        133 : GTPUHdrExt133,
        192 : GTPUHdrExt192
        }
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self.__init__()
        p = self.get_prev()
        if p and not p.get_trans():
            neid = p['NextExt'].get_val()
            while neid > 0 and char.len_bit() >= 32:
                ne = self._HdrExt.get(neid, GTPUHdrExtAuto)()
                ne._from_char(char)
                self.append(ne)
                neid = ne['NextExt'].get_val()


class GTPUHdrOpt(Envelope):
    _GEN = (
        Uint16('SeqNum'),
        Uint8('NPDUNum'),
        Uint8('NextExt')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[-1].set_valauto(lambda: self._get_next_hdr())
    
    def _get_next_hdr(self):
        n = self.get_next()
        if isinstance(n, GTPUHdrExtList) and len(n._content) and hasattr(n[0], '_ID'):
            return n[0]._ID
        else:
            return 0


ProtType_dict = {
    0 : 'GTP prime',
    1 : 'GTP',
    }

GTPUType_dict = {
    1   : 'Echo Request',
    2   : 'Echo Response',
    26  : 'Error Indication',
    31  : 'Supported Extension Headers Notification',
    253 : 'Tunnel Status',
    254 : 'End Marker',
    255 : 'G-PDU'
    }

class GTPUType(IntEnum):
    EchoRequest     = 1
    EchoResponse    = 2
    ErrorIndication = 26
    SupportedExtensionHeadersNotification = 31
    TunnelStatus    = 253
    EndMarker       = 254
    GPDU            = 255


class GTPUHdr(Envelope):
    _GEN = (
        Uint('Version', val=1, bl=3),
        Uint('PT', val=0, bl=1, dic=ProtType_dict),
        Uint('spare', bl=1),
        Uint('E', bl=1),
        Uint('S', bl=1),
        Uint('PN', bl=1),
        Uint8('Type', val=GTPUType.EchoRequest.value, dic=GTPUType_dict),
        Uint16('Len'),
        Uint32('TEID', rep=REPR_HEX),
        GTPUHdrOpt(hier=1),
        GTPUHdrExtList(hier=1)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[7].set_valauto(lambda: self._get_len())
        self[9].set_transauto(lambda: False if (self[3]() or self[4]() or self[5]()) else True)
        self[10].set_transauto(lambda: False if self[3]() else True)

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
# Information Element Types
# TS 29.281, section 8.1
#------------------------------------------------------------------------------#

class GTPUIE(Envelope):
    pass


#------------------------------------------------------------------------------#
# Recovery
# TS 29.281, section 8.2
#------------------------------------------------------------------------------#

class GTPUIERecovery(GTPUIE):
    _GEN = (
        Uint8('Type', val=14),
        Uint8('RestartCounter')
        )


#------------------------------------------------------------------------------#
# Tunnel Endpoint Identifier Data I
# TS 29.281, section 8.3
#------------------------------------------------------------------------------#

class GTPUIETEID(GTPUIE):
    _GEN = (
        Uint8('Type', val=16),
        Uint32('TEID', rep=REPR_HEX),
        )


#------------------------------------------------------------------------------#
# GTP-U Peer Address
# TS 29.281, section 8.4
#------------------------------------------------------------------------------#

class GTPUIEPeerAddr(GTPUIE):
    _GEN = (
        Uint8('Type', val=133),
        Uint16('Len', dic={4: 'IPv4', 16: 'IPv6'}),
        Buf('IP', rep=REPR_HEX),
        )
    
    def __init__(self, *args, **kwargs):
        GTPUIE.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: self[1].get_val()<<3)


#------------------------------------------------------------------------------#
# Extension Header Type List
# TS 29.281, section 8.5
#------------------------------------------------------------------------------#

class GTPUIEExtHdrList(GTPUIE):
    _GEN = (
        Uint8('Type', val=141),
        Uint8('Num'),
        Array('SupportedExtHdr', GEN=Uint8('ExtHdrType'))
        )
    
    def __init__(self, *args, **kwargs):
        GTPUIE.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_num())
        self[2].set_numauto(lambda: self[1].get_val())


#------------------------------------------------------------------------------#
# Private extension
# TS 29.281, section 8.6
#------------------------------------------------------------------------------#

class GTPUIEPrivateExt(GTPUIE):
    _GEN = (
        Uint8('Type', val=255),
        Uint16('Len'),
        Uint16('ExtId'),
        Buf('ExtVal', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        GTPUIE.__init__(self, *args, **kwargs)
        # WARNING: specification does not say how the length prefix is computed
        self[1].set_valauto(lambda: 2 + self[3].get_len())
        self[3].set_blauto(lambda: max(0, self[1].get_val()-2)<<3)


#------------------------------------------------------------------------------#
# GTP-U Messages
# TS 29.281, section 7
#------------------------------------------------------------------------------#

class GTPUMsg(Envelope):
    
    ENV_SEL_TRANS = False
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        if 'val' in kwargs:
            # in case some values target optional IE, make them non transparent
            for vid in kwargs['val'].keys():
                elt = self[vid]
                if elt and elt.get_trans():
                    elt.set_trans(False)
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self.__init__()
        # decode header
        self[0]._from_char(char)
        # decode IE(s)
        for ie in self._content[1:]:
            if not ie.get_trans():
                # mandatory IE
                ie._from_char(char)
            elif char.len_bit() >= 16:
                # optional IE
                ie.set_trans(False)
                ie._from_char(char)


#------------------------------------------------------------------------------#
# Echo Request
# TS 29.281, section 7.2.1
#------------------------------------------------------------------------------#

class GTPUEchoRequest(GTPUMsg):
    _GEN = (
        GTPUHdr(val={'Type': 1}),
        GTPUIEPrivateExt(hier=1, trans=True) # optional
        )


#------------------------------------------------------------------------------#
# Echo Response
# TS 29.281, section 7.2.2
#------------------------------------------------------------------------------#

class GTPUEchoResponse(GTPUMsg):
    _GEN = (
        GTPUHdr(val={'Type': 2}),
        GTPUIERecovery(hier=1),
        GTPUIEPrivateExt(hier=1, trans=True) # optional
        )


#------------------------------------------------------------------------------#
# Supported Extension Headers Notification
# TS 29.281, section 7.2.3
#------------------------------------------------------------------------------#

class GTPUSuppExtHdrNotif(GTPUMsg):
    _GEN = (
        GTPUHdr(val={'Type': 31}),
        GTPUIEExtHdrList(hier=1)
        )


#------------------------------------------------------------------------------#
# Error Indication
# TS 29.281, section 7.3.1
#------------------------------------------------------------------------------#

class GTPUErrorInd(GTPUMsg):
    _GEN = (
        GTPUHdr(val={'Type': 26}),
        GTPUIETEID(hier=1),
        GTPUIEPeerAddr(hier=1),
        GTPUIEPrivateExt(hier=1, trans=True) # optional
        )


#------------------------------------------------------------------------------#
# End Marker
# TS 29.281, section 7.3.2
#------------------------------------------------------------------------------#

class GTPUEndMarker(GTPUMsg):
    _GEN = (
        GTPUHdr(val={'Type': 254}),
        GTPUIEPrivateExt(hier=1, trans=True) # optional
        )


#------------------------------------------------------------------------------#
# Tunnel Status
# TS 29.281, section 7.3.3
#------------------------------------------------------------------------------#

class GTPUTunnelStatus(GTPUMsg):
    _GEN = (
        GTPUHdr(val={'Type': 253}),
        GTPUIEPrivateExt(hier=1, trans=True) # optional
        )


#------------------------------------------------------------------------------#
# General
# TS 29.281, section 7.1
#------------------------------------------------------------------------------#

class GPDU(Envelope):
    _GEN = (
        GTPUHdr(val={'Type': 255}),
        Buf('TPDU', hier=1, rep=REPR_HEX)
        )


GTPUDispatcher = {
    1   : GTPUEchoRequest,
    2   : GTPUEchoResponse,
    26  : GTPUErrorInd,
    31  : GTPUSuppExtHdrNotif,
    254 : GTPUEndMarker,
    255 : GPDU
}


ERR_GTPU_BUF_TOO_SHORT = 1
ERR_GTPU_BUF_INVALID   = 2
ERR_GTPU_TYPE_NONEXIST = 3


def parse_GTPU(buf):
    if len(buf) < 8:
        return None, ERR_GTPU_BUF_TOO_SHORT
    if python_version < 3:
        type = ord(buf[1])
    else:
        type = buf[1]
    try:
        Msg = GTPUDispatcher[type]()
    except KeyError:
        return None, ERR_GTPU_TYPE_NONEXIST
    try:
        Msg.from_bytes(buf)
    except Exception:
        return None, ERR_GTPU_BUF_INVALID
    else:
        return Msg, 0

