# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright © 2017. Benoit Michau. ANSSI.
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# * 
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# * 
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# * 02110-1301, USA.
# *
# *--------------------------------------------------------
# * File Name : pycrate_mobile/NAS.py
# * Created : 2017-07-17
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.utils import *
if python_version < 3:
    from struct import unpack

from .TS24008_MM  import *
#from .TS24008_CC  import *
#from .TS24008_SMS import *
from .TS44018_RR import *

from .TS24008_GMM import *
#from .TS24008_SM  import *

#from .TS24008_EMM import *
#from .TS24008_ESM import *

NASMODispatcher = {
    5 : MMTypeClasses,
    6 : RRTypeClasses,
    8 : GMMTypeMOClasses
    }

NASMTDispatcher = {
    5 : MMTypeClasses,
    6 : RRTypeClasses,
    8 : GMMTypeMTClasses
    }


def parse_L3_MO(buf):
    if python_version < 3:
        try:
            pd, type = unpack('>BB', buf[:2])
        except:
            # error 111, unspecified protocol error
            return None, 111
    else:
        try:
            pd, type = buf[0], buf[1]
        except:
            # error 111, unspecified protocol error
            return None, 111
    pd &= 0xF
    if pd == 5:
        type &= 0x3f
    #elif pd == 8:
    #    pass
    #
    try:
        Msg = NASMODispatcher[pd][type]()
    except:
        # error 97, message type non-existent or not implemented
        return None, 97
    #
    try:
        Msg.from_bytes(buf)
    except:
        # error 96, invalid mandatory info
        return None, 96
    #
    return Msg, 0


def parse_L3_MT(buf):
    if python_version < 3:
        try:
            pd, type = unpack('>BB', buf[:2])
        except:
            # error 111, unspecified protocol error
            return None, 111
    else:
        try:
            pd, type = buf[0], buf[1]
        except:
            # error 111, unspecified protocol error
            return None, 111
    pd &= 0xF
    if pd == 5:
        type &= 0x3f
    #elif pd == 8:
    #    pass
    #
    try:
        Msg = NASMTDispatcher[pd][type]()
    except:
        # error 97, message type non-existent or not implemented
        return None, 97
    #
    try:
        Msg.from_bytes(buf)
    except:
        # error 96, invalid mandatory info
        return None, 96
    #
    return Msg, 0

