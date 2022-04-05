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
# * File Name : pycrate_mobile/TS24588_UEPOL.py
# * Created : 2019-12-18
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'V2XPInfos',
    'V2XPInfo',
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.588: Vehicle-to-Everything (V2X) services in 5G System (5GS); User Equipment (UE) policies
# draft release 16 (101)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *


#------------------------------------------------------------------------------#
# Encoding of V2X policy (V2XP) UE policy part
# TS 24.526, section 5.2
#------------------------------------------------------------------------------#

_V2XPInfoType_dict = {
    1 : 'UE policies for V2X communication over PC5',
    2 : 'UE policies for V2X communication over Uu'
    }

class V2XPInfo(Envelope):
    _GEN = (
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('Type', bl=4, dic=_V2XPInfoType_dict),
        Uint16('Len'),
        Alt('Cont', GEN={
            1 : Buf('PC5', val=b'', rep=REPR_HEX),
            2 : Buf('Uu', val=b'', rep=REPR_HEX)
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: self[3].get_len())
        self[3].set_blauto(lambda: self[2].get_val()<<3)


# Figure 5.2.1.2: V2XP contents
class V2XPInfos(Sequence):
    _GEN = V2XPInfo()

