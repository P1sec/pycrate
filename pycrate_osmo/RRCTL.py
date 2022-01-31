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
        if self['Hdr']['Type'].get_val() is not msg_type:
            return False
        if self['Hdr']['Disc'].get_val() is not msg_disc:
            return False
        return True
