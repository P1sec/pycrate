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
# * File Name : pycrate_mobile/TS31115.py
# * Created : 2019-07-19
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/
#
# Implement parts of 3GPP TS 31.115
# Secured packet structure for (Universal) Subscriber Identity Module (U)SIM Toolkit applications

from pycrate_mobile.TS102225 import *


# 4.2 Structure of the Command Packet contained in a Single Short Message Point to Point

class PacketCmdSMSPP(Envelope):
    _GEN = (
        Uint16('CmdPacketLen'),
        Uint8('CmdHeaderLen'),
        SPI(),
        KIc(),
        Alt('KID', GEN={
            0 : Uint8('NoIntegrity', val=0),
            1 : KID_RC(),
            2 : KID_CC(),
            3 : KID_DS()
            },
            DEFAULT=Uint8('NoIntegrity', val=0, bl=0),
            sel=lambda self: self.get_env()['SPI']['IntegrityType']()),
        Uint24('TAR', rep=REPR_HEX, dic=TAR_dict),
        Uint('CNTR', bl=40),
        Uint8('PCNTR'),
        Buf('IntegrityCheck', rep=REPR_HEX),
        Buf('Data', rep=REPR_HEX),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[1]() + self[-1].get_len())
        self[1].set_valauto(lambda: 13 + self[-2].get_len())
        self[-2].set_blauto(lambda: 8 * max(0, self[1]() - 13))
        self[-1].set_blauto(lambda: 8 * max(0, self[0]() - self[1]() - 1))


class PacketRespSMSPP(Envelope):
    _GEN = (
        Uint16('RespPacketLen'),
        Uint8('RespHeaderLen'),
        Uint24('TAR', rep=REPR_HEX, dic=TAR_dict),
        Uint('CNTR', bl=40),
        Uint8('PCNTR'),
        Uint8('Status', dic=RespStatus_dict),
        Buf('IntegrityCheck', rep=REPR_HEX),
        Buf('Data', rep=REPR_HEX),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: 1 + self[1]() + self[-1].get_len())
        self[1].set_valauto(lambda: 10 + self[-2].get_len())
        self[-2].set_blauto(lambda: 8 * max(0, self[1]() - 10))
        self[-1].set_blauto(lambda: 8 * max(0, self[0]() - self[1]() - 1))

