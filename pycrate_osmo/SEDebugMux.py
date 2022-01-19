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
# * File Name : pycrate_osmo/SEDebugMux.py
# * Created : 2022-01-08
# * Authors : Vadim Yanitskiy
# *--------------------------------------------------------
#*/

import enum
import crcmod

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *
from pycrate_core.repr  import *


class PascalString(Envelope):
    ''' A variable length string that is prefixed by a length field '''
    _GEN = (
        Uint8('L', desc='Length'),
        Buf('V', desc='Value')
        )

    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['L'].set_valauto(lambda: self['V'].get_bl() >> 3)
        self['V'].set_blauto(lambda: self['L'].get_val() << 3)

class DebugMuxMsgType(enum.Enum):
    ''' DebugMux message type '''
    Enquiry             = 0x65 # 'e'
    Ident               = 0x66 # 'f'
    Ping                = 0x67 # 'g'
    Pong                = 0x68 # 'h'

    DPAnnounce          = 0x69 # 'i'
    # TODO              = 0x6a # 'j'
    ConnEstablish       = 0x6b # 'k'
    ConnEstablished     = 0x6c # 'l'
    ConnTerminate       = 0x6d # 'm'
    ConnTerminated      = 0x6e # 'n'
    ConnData            = 0x6f # 'o'
    # TODO:             = 0x70 # 'p'
    Ack                 = 0x71 # 'q'

DebugMuxMsgType_dict = { e.value : e.name for e in DebugMuxMsgType }

class DebugMuxMsg(Alt):
    ''' DebugMux message, may be contained in a DebugMuxFrame '''
    class Ident(Envelope):
        ''' DebugMuxMsgType.Ident structure '''
        _GEN = (
            Buf('Magic', bl=32), # TODO: what's here?
            PascalString('Ident'),
            )

    class PingPong(PascalString):
        ''' DebugMuxMsgType.{Ping,Pong} structure '''

    class DPAnnounce(Envelope):
        ''' DebugMuxMsgType.DPAnnounce structure '''
        _GEN = (
            Uint16LE('DPRef'),
            PascalString('Name'),
            )

    class ConnEstablish(Envelope):
        ''' DebugMuxMsgType.ConnEstablish structure '''
        _GEN = (
            Uint16LE('DPRef'),
            )

    class ConnEstablished(Envelope):
        ''' DebugMuxMsgType.ConnEstablished structure '''
        _GEN = (
            Uint16LE('DPRef'),
            Uint16LE('ConnRef'),
            Uint16LE('DataBlockLimit'),
            )

    class ConnTerminate(Envelope):
        ''' DebugMuxMsgType.ConnTerminate structure '''
        _GEN = (
            Uint16LE('ConnRef'),
            )

    class ConnTerminated(Envelope):
        ''' DebugMuxMsgType.ConnTerminated structure '''
        _GEN = (
            Uint16LE('DPRef'),
            Uint16LE('ConnRef'),
            )

    class ConnData(Envelope):
        ''' DebugMuxMsgType.ConnData structure '''
        _GEN = (
            Uint16LE('ConnRef'),
            BufAuto('Data'),
            )

    # All currently known messages
    _GEN = {
        DebugMuxMsgType.Ident.value              : Ident(),
        DebugMuxMsgType.Ping.value               : PingPong(),
        DebugMuxMsgType.Pong.value               : PingPong(),
        DebugMuxMsgType.DPAnnounce.value         : DPAnnounce(),
        DebugMuxMsgType.ConnEstablish.value      : ConnEstablish(),
        DebugMuxMsgType.ConnEstablished.value    : ConnEstablished(),
        DebugMuxMsgType.ConnTerminate.value      : ConnTerminate(),
        DebugMuxMsgType.ConnTerminated.value     : ConnTerminated(),
        DebugMuxMsgType.ConnData.value           : ConnData(),
        }

class DebugMuxFrame(Envelope):
    ''' DebugMux frame, may contain a DebugMuxMsg '''
    _GEN = (
        Buf('Magic', desc='Start marker', val=b'\x42\x42', bl=16),
        Uint16LE('Length', desc='Message length'), # val automated
        Uint8('TxCount', desc='Number of messages sent'),
        Uint8('RxCount', desc='Number of messages received'),
        Uint8('MsgType', desc='Message type', dic=DebugMuxMsgType_dict),
        DebugMuxMsg('MsgData', sel=lambda self: self.get_env()['MsgType'].get_val()),
        Uint16LE('FCS', desc='Frame Check Sequence', rep=REPR_HEX) # val automated
        )

    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        
        # The 'Length' field indicates length of *all* fields following it
        self['Length'].set_valauto(lambda: 3 + self['MsgData'].get_len() + 2)
        self['MsgData'].set_blauto(lambda: (self['Length'].get_val() - 3 - 2) * 8)
        
        # Kudos to Stefan @Sec Zehl for finding the CRC function parameters
        self._fcs_func = crcmod.mkCrcFun(0x11021, rev=True, initCrc=0x0, xorOut=0xffff)
        self['FCS'].set_valauto(lambda: self._fcs_func(self[:-1].to_bytes()))
