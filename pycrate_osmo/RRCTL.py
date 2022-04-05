# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2022. Vadim Yanitskiy
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
# * File Name : pycrate_osmo/RRCTL.py
# * Created : 2022-02-01
# * Authors : Vadim Yanitskiy
# *--------------------------------------------------------
#*/

import enum

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *
from pycrate_core.repr  import *

from pycrate_mobile.TS24008_IE import BufBCD

#------------------------------------------------------------------------------#
# Enumerations
#------------------------------------------------------------------------------#

class RRCTLMsgType(enum.IntEnum):
    ''' RRCTL message type '''
    Reset                       = 0x00
    ConnData                    = 0x01
    NetworkSearch               = 0x02
    NetworkSelect               = 0x03
    ConnEstabish                = 0x04
    ConnRelease                 = 0x05
    Paging                      = 0x06
    Param                       = 0x07
    SecMode                     = 0x08
    # RRCTL protocol extensions (0b11xxxx) follow
    ExtUSIM                     = 0x3e
    RFU                         = 0x3f # 0b111111

RRCTLMsgType_dict = { e.value : e.name for e in RRCTLMsgType }

class RRCTLMsgDisc(enum.IntEnum):
    ''' RRCTL message type discriminator '''
    Req                         = 0x00
    Ind                         = 0x01
    Cnf                         = 0x02 # a.k.a Res
    Res                         = 0x02 # a.k.a Cnf
    Err                         = 0x03

RRCTLMsgDisc_dict = { e.value : e.name for e in RRCTLMsgDisc }

class RRCTLConnEstCause(enum.IntEnum):
    ''' RRCTL connection establishment cause '''
    Emergency                   = 0x00
    HighPriorityAccess          = 0x01
    MT_Access                   = 0x02
    MO_Signalling               = 0x03
    MO_Data                     = 0x04
    DelayTolerantAccess_v1020   = 0x05
    MO_VoiceCall_v1280          = 0x06

RRCTLConnEstCause_dict = { e.value : e.name for e in RRCTLConnEstCause }

class RRCTLParamType(enum.IntEnum):
    ''' RRCTL parameter type for RRCTLMsgType.Param '''
    UEID                        = 0x00

RRCTLParamType_dict = { e.value : e.name for e in RRCTLParamType }

#------------------------------------------------------------------------------#
# RRCTL message payload
#------------------------------------------------------------------------------#

class PLMNInfo(Envelope):
    _GEN = (
        BufBCD('MCC', bl=16),
        BufBCD('MNC', bl=16),
        Uint16('TAC'),
        )

class PLMNSearchRes(Envelope):
    _GEN = (
        Uint8('NofPLMNs'),
        Array('PLMNs', GEN=PLMNInfo()),
        )

    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['NofPLMNs'].set_valauto(lambda: self['PLMNs'].get_num())
        self['PLMNs'].set_numauto(lambda: self['NofPLMNs'].get_val())

class PLMNSelectReq(Envelope):
    _GEN = (
        BufBCD('MCC', bl=16),
        BufBCD('MNC', bl=16),
        )

class ConnEstablishReq(Envelope):
    _GEN = (
        Uint8('Cause', dic=RRCTLConnEstCause_dict),
        Buf('PDU'),
        )

class ConnDataReqInd(Envelope):
    _GEN = (
        Uint32('LCID'),
        Buf('PDU'),
        )

class MMESubscrId(Envelope):
    _GEN = (
            Uint8('MMEC'),
            Uint32('M_TMSI'),
        )

class PagingInd(MMESubscrId):
    pass

class ParamReq(Envelope):
    _GEN = (
        Uint8('Type', dic=RRCTLParamType_dict),
        Uint8('Len'),
        Alt('Data', hier=1, GEN={
                RRCTLParamType.UEID : MMESubscrId()
            },
            sel=lambda self: self.get_env()['Type'].get_val())
        )

    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Data'].get_len())

class SecModeReq(Envelope):
    _GEN = (
        Uint('EEA', bl=3),
        Uint('EIA', bl=3),
        Uint('ResetTxCTR', bl=1),
        Uint('ResetRxCTR', bl=1),
        Buf('Spare', bl=24),
        Buf('KASME', bl=32 * 8), # optional
    )

    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        # KASME is absent when neither encryption nor integrity protection is active
        self['KASME'].set_transauto(lambda: not self['EEA']() and not self['EIA']())

#------------------------------------------------------------------------------#
# RRCTL protocol extensions
#------------------------------------------------------------------------------#

class L16V(Envelope):
    _GEN = (
        Uint16('L'),
        Buf('V'),
        )

    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['L'].set_valauto(lambda: self['V'].get_bl() >> 3)
        self['V'].set_blauto(lambda: self['L'].get_val() << 3)

class ExtUSIM:
    ''' RRCTL protocol extension for (U)SIM specific sommands '''
    class MsgType(enum.IntEnum):
        RawAPDU                     = 0x00
        ReadFile                    = 0x01
        UpdateFile                  = 0x02
        GenAuthVector               = 0x03
        Reserved                    = 0xff

    MsgType_dict = { e.value : e.name for e in MsgType }

    class RawAPDU(L16V):
        pass

    class ReadFileReq(Envelope):
        _GEN = (
            Uint16('DF'), # Dedicated File
            Uint16('EF'), # Elementary File
            )

    class ReadFileRes(L16V):
        pass

    class UpdateFileReq(Envelope):
        _GEN = (
            Uint16('DF'), # Dedicated File
            Uint16('EF'), # Elementary File
            L16V('Data'),
            )

    class GenAuthVectorReq(Envelope):
        _GEN = (
            Buf('Rand', bl=16 * 8),
            Buf('Autn', bl=16 * 8),
            BufBCD('MCC', bl=16),
            BufBCD('MNC', bl=16),
            )

    class GenAuthVectorRes(Envelope):
        _GEN = (
            Uint8('OutOfSync'),
            Uint8('KASMELen'),
            Buf('Spare', bl=16),
            Buf('KASME'),
            )

        def __init__(self, *args, **kwargs):
            Envelope.__init__(self, *args, **kwargs)
            self['KASMELen'].set_valauto(lambda: self['KASME'].get_bl() >> 3)
            self['KASME'].set_blauto(lambda: self['KASMELen'].get_val() << 3)

class ExtUSIMMsgReq(Envelope):
    _GEN = (
        Uint8('Type', dic=ExtUSIM.MsgType_dict),
        Buf('Spare', bl=24),
        Alt('Data', hier=1, GEN={
                ExtUSIM.MsgType.RawAPDU             : ExtUSIM.RawAPDU(),
                ExtUSIM.MsgType.ReadFile            : ExtUSIM.ReadFileReq(),
                ExtUSIM.MsgType.UpdateFile          : ExtUSIM.UpdateFileReq(),
                ExtUSIM.MsgType.GenAuthVector       : ExtUSIM.GenAuthVectorReq(),
            },
            sel=lambda self: self.get_env()['Type'].get_val())
        )

class ExtUSIMMsgRes(Envelope):
    _GEN = (
        Uint8('Type', dic=ExtUSIM.MsgType_dict),
        Buf('Spare', bl=24),
        Alt('Data', hier=1, GEN={
                ExtUSIM.MsgType.RawAPDU             : ExtUSIM.RawAPDU(),
                ExtUSIM.MsgType.ReadFile            : ExtUSIM.ReadFileRes(),
                ExtUSIM.MsgType.GenAuthVector       : ExtUSIM.GenAuthVectorRes(),
            },
            sel=lambda self: self.get_env()['Type'].get_val())
        )

#------------------------------------------------------------------------------#
# RRCTL message definition
#------------------------------------------------------------------------------#

class RRCTLMsgHdr(Envelope):
    ''' RRCTL message header '''
    _GEN = (
        Uint('Type', bl=6, dic=RRCTLMsgType_dict),
        Uint('Disc', bl=2, dic=RRCTLMsgDisc_dict),
        Uint('Spare', bl=8), # RFU
        Uint16('Len'),
        )

class RRCTLMsg(Envelope):
    _GEN = (
        RRCTLMsgHdr('Hdr'),
        Alt('Data', hier=1, GEN={
                (RRCTLMsgType.NetworkSearch,    RRCTLMsgDisc.Res) : PLMNSearchRes(),
                (RRCTLMsgType.NetworkSelect,    RRCTLMsgDisc.Req) : PLMNSelectReq(),
                (RRCTLMsgType.ConnEstabish,     RRCTLMsgDisc.Req) : ConnEstablishReq(),
                (RRCTLMsgType.ConnData,         RRCTLMsgDisc.Req) : ConnDataReqInd(),
                (RRCTLMsgType.ConnData,         RRCTLMsgDisc.Ind) : ConnDataReqInd(),
                (RRCTLMsgType.Paging,           RRCTLMsgDisc.Ind) : PagingInd(),
                (RRCTLMsgType.Param,            RRCTLMsgDisc.Req) : ParamReq(),
                (RRCTLMsgType.SecMode,          RRCTLMsgDisc.Req) : SecModeReq(),
                # RRCTL protocol extensions follow
                (RRCTLMsgType.ExtUSIM,          RRCTLMsgDisc.Req) : ExtUSIMMsgReq(),
                (RRCTLMsgType.ExtUSIM,          RRCTLMsgDisc.Res) : ExtUSIMMsgRes(),
            },
            sel=lambda self: (self.get_env()['Hdr']['Type'].get_val(),
                              self.get_env()['Hdr']['Disc'].get_val()))
        )

    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Hdr']['Len'].set_valauto(lambda: self['Data'].get_len())
        self['Data'].set_transauto(lambda: not self['Hdr']['Len'].get_val())

    def set_type(self, msg_type, msg_disc=RRCTLMsgDisc.Req):
        self['Hdr']['Type'].set_val(msg_type)
        self['Hdr']['Disc'].set_val(msg_disc)

    def match(self, msg_type, msg_disc):
        if self['Hdr']['Type'].get_val() != msg_type:
            return False
        if self['Hdr']['Disc'].get_val() != msg_disc:
            return False
        return True
