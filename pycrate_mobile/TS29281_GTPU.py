# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.5
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
    # GTPU Messages
    'GTPUEchoRequest',
    'GTPUEchoResponse',
    'GTPUErrorInd',
    'GTPUSuppExtHdrNotif',
    'GTPUEndMarker',
    'GTPUTunnelStatus',
    'GPDU',
    # GTPU Message parser and associated errors
    'GTPUDispatcher',
    'parse_GTPU',
    'ERR_GTPU_BUF_TOO_SHORT',
    'ERR_GTPU_BUF_INVALID',
    'ERR_GTPU_TYPE_NONEXIST'
    ]


#------------------------------------------------------------------------------#
# 3GPP TS 29.281: General Packet Radio System (GPRS) Tunnelling Protocol 
# User Plane (GTPv1-U)
# release 16 (h10)
#------------------------------------------------------------------------------#

from enum import IntEnum

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from pycrate_mobile.TS29060_GTP     import (
    # extension header
    BufAligned,
    GTPHdrExtCont,
    GTPHdrExt,
    # header
    GTPHdrExtList,
    GTPHdrOpt,
    ProtType_dict,
    GTPHdr
    )
from pycrate_mobile.TS38415_PDUSess import *


#------------------------------------------------------------------------------#
# GTP-U Extension Header
# TS 29.281, section 5.2
#------------------------------------------------------------------------------#

GTPUNextExtHeader_dict = {
    0   : 'No more extension headers',
    1   : 'Reserved - Control Plane only',
    2   : 'Reserved - Control Plane only',
    3   : 'Long PDCP PDU Number',
    32  : 'Service Class Indicator',
    64  : 'UDP source port of the triggering message',
    129 : 'RAN Container',
    130 : 'Long PDCP PDU Number',
    131 : 'Xw RAN Container',
    132 : 'NR RAN Container',
    133 : 'PDU Session Container',
    192 : 'PDCP PDU Number',
    193 : 'Reserved - Control Plane only',
    194 : 'Reserved - Control Plane only'
    }


class _LongPDCPPDUNumber(GTPHdrExtCont):
    _GEN = (
        Uint('spare', bl=6, rep=REPR_HEX),
        Uint('Value', bl=18),
        Uint24('spare', rep=REPR_HEX),
        )


# All defined Ext Header
GTPUHdrExtCont_dict = {
    3   : _LongPDCPPDUNumber('LongPDCPPDUNumber',
            ID=3),
    32  : GTPHdrExtCont('ServiceClassInd', GEN=(
            Uint8('Value'),
            Uint8('spare', rep=REPR_HEX),
            ), ID=32),
    64  : GTPHdrExtCont('UDPPort', GEN=(
            Uint16('Value'),
            ), ID=64),
    129 : GTPHdrExtCont('RANContainer',
            ID=129),
    130 : _LongPDCPPDUNumber('LongPDCPPDUNumber',
            ID=130),
    131 : GTPHdrExtCont('XwRANContainer', 
            ID=131),
    132 : GTPHdrExtCont('NRRANContainer',
            ID=132),
    133 : GTPHdrExtCont('PDUSessionContainer', GEN=PDUSessInfo._GEN,
            ID=133),
    192 : GTPHdrExtCont('PDCPPDUNumber', GEN=(
            Uint('Value', bl=15),
            Uint('spare', bl=1, rep=REPR_HEX),
            ), ID=192)
    }


# define a dedicated class for GTPU
class GTPUHdrExt(GTPHdrExt):
    _ExtCont = GTPUHdrExtCont_dict

# patch the next extension field dict
GTPUHdrExt._GEN[2]._dic = GTPUNextExtHeader_dict


#------------------------------------------------------------------------------#
# GTP-U header
# TS 29.281, section 5.1
#------------------------------------------------------------------------------#

# define a dedicated class for GTPU
class GTPUHdrExtList(GTPHdrExtList):
    _GEN = GTPUHdrExt()


class GTPUType(IntEnum):
    EchoReq                         = 1
    EchoResp                        = 2
    ErrorInd                        = 26
    SupportedExtensionHeadersNotif  = 31
    TunnelStatus                    = 253
    EndMarker                       = 254
    GPDU                            = 255

GTPUType_dict = {e.value: str(e) for e in GTPUType}


class GTPUHdr(GTPHdr):
    _GEN = (        
        Uint('Version', val=1, bl=3),               # 1 for GTP 29.060
        Uint('PT', val=1, bl=1, dic=ProtType_dict), # 1 for GTP 29.060
        Uint('spare', bl=1),
        Uint('E', bl=1),
        Uint('S', bl=1),
        Uint('PN', bl=1),
        Uint8('Type', val=GTPUType.EchoReq.value, dic=GTPUType_dict),
        Uint16('Len'),
        Uint32('TEID', rep=REPR_HEX),
        GTPHdrOpt('GTPUHdrOpt'), # optional
        GTPUHdrExtList()         # optional
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self._get_len())
        self['GTPUHdrOpt'].set_transauto(lambda: False if (self[3]() or self[4]() or self[5]()) else True)
        self['GTPUHdrExtList'].set_transauto(lambda: False if self[3]() else True)


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

class _GTPUMsg(Envelope):
    
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

class GTPUEchoRequest(_GTPUMsg):
    _GEN = (
        GTPUHdr(val={'Type': GTPUType.EchoReq.value}),
        GTPUIEPrivateExt(hier=1, trans=True) # optional
        )


#------------------------------------------------------------------------------#
# Echo Response
# TS 29.281, section 7.2.2
#------------------------------------------------------------------------------#

class GTPUEchoResponse(_GTPUMsg):
    _GEN = (
        GTPUHdr(val={'Type': GTPUType.EchoResp.value}),
        GTPUIERecovery(hier=1),
        GTPUIEPrivateExt(hier=1, trans=True) # optional
        )


#------------------------------------------------------------------------------#
# Supported Extension Headers Notification
# TS 29.281, section 7.2.3
#------------------------------------------------------------------------------#

class GTPUSuppExtHdrNotif(_GTPUMsg):
    _GEN = (
        GTPUHdr(val={'Type': GTPUType.SupportedExtensionHeadersNotif.value}),
        GTPUIEExtHdrList(hier=1)
        )


#------------------------------------------------------------------------------#
# Error Indication
# TS 29.281, section 7.3.1
#------------------------------------------------------------------------------#

class GTPUErrorInd(_GTPUMsg):
    _GEN = (
        GTPUHdr(val={'Type': GTPUType.ErrorInd.value}),
        GTPUIETEID(hier=1),
        GTPUIEPeerAddr(hier=1),
        GTPUIEPrivateExt(hier=1, trans=True) # optional
        )


#------------------------------------------------------------------------------#
# End Marker
# TS 29.281, section 7.3.2
#------------------------------------------------------------------------------#

class GTPUEndMarker(_GTPUMsg):
    _GEN = (
        GTPUHdr(val={'Type': GTPUType.EndMarker.value}),
        GTPUIEPrivateExt(hier=1, trans=True) # optional
        )


#------------------------------------------------------------------------------#
# Tunnel Status
# TS 29.281, section 7.3.3
#------------------------------------------------------------------------------#

class GTPUTunnelStatus(_GTPUMsg):
    _GEN = (
        GTPUHdr(val={'Type': GTPUType.TunnelStatus.value}),
        GTPUIEPrivateExt(hier=1, trans=True) # optional
        )


#------------------------------------------------------------------------------#
# General
# TS 29.281, section 7.1
#------------------------------------------------------------------------------#

class GPDU(Envelope):
    _GEN = (
        GTPUHdr(val={'Type': GTPUType.GPDU.value}),
        Buf('TPDU', hier=1, rep=REPR_HEX)
        )


GTPUDispatcher = {
    1   : GTPUEchoRequest,
    2   : GTPUEchoResponse,
    26  : GTPUErrorInd,
    31  : GTPUSuppExtHdrNotif,
    253 : GTPUTunnelStatus,
    254 : GTPUEndMarker,
    255 : GPDU,
    }


ERR_GTPU_BUF_TOO_SHORT = 1
ERR_GTPU_BUF_INVALID   = 2
ERR_GTPU_TYPE_NONEXIST = 3


def parse_GTPU(buf):
    """parses the buffer `buf' for GTP-U message and returns a 2-tuple:
    - GTP-U message structure, or None if parsing failed
    - parsing error code, 0 if parsing succeeded, > 0 otherwise
    """
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

