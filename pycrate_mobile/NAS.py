# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI. P1sec.
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
# * File Name : pycrate_mobile/NAS.py
# * Created : 2017-07-17
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.utils import *
if python_version < 3:
    from struct import unpack

from .TS24008_IE    import *
from .TS24008_MM    import *
from .TS24008_CC    import *
from .TS24080_SS    import *
from .TS44018_RR    import *
from .TS44018_GTTP  import *

from .TS24011_PPSMS import *
from .TS23040_SMS   import *
from .TS23041_CBS   import *
from .TS23038       import *

from .TS24008_GMM   import *
from .TS24008_SM    import *

from .TS24301_IE    import *
from .TS24301_EMM   import *
from .TS24301_ESM   import *
from .NASLTE        import *

NASMODispatcher = {
    2 : ESMTypeClasses,
    3 : CCTypeMOClasses,
    4 : GTTPTypeClasses,
    5 : MMTypeClasses,
    6 : RRTypeMOClasses,
    7 : EMMTypeMOClasses,
    8 : GMMTypeMOClasses,
    9 : PPSMSCPTypeClasses,
    10: SMTypeClasses,
    11: SSTypeMOClasses
    }

NASMTDispatcher = {
    2 : ESMTypeClasses,
    3 : CCTypeMTClasses,
    4 : GTTPTypeClasses,
    5 : MMTypeClasses,
    6 : RRTypeMTClasses,
    7 : EMMTypeMTClasses,
    8 : GMMTypeMTClasses,
    9 : PPSMSCPTypeClasses,
    10: SMTypeClasses,
    11: SSTypeMTClasses
    }


def parse_NAS_MO(buf):
    """Parses a Mobile Originated NAS message bytes' buffer
    
    Args:
        buf: uplink NAS message bytes' buffer
    
    Returns:
        element, err: 2-tuple
            element: Element instance, if err is null (no error)
            element: None, if err is not null (standard NAS error code)
    """
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
    if pd in (3, 5, 11):
        type &= 0x3f
    elif pd in (2, 7):
        return parse_NASLTE_MO(buf, inner=True)
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


def parse_NAS_MT(buf, wl2=False):
    """Parses a Mobile Terminated NAS message bytes' buffer
    
    Args:
        buf: downlink NAS message bytes' buffer
        wl2: bool, True if the signalling message is a GSM RR with a 
             L2PseudoLength prefix
    
    Returns:
        element, err: 2-tuple
            element: Element instance, if err is null (no error)
            element: None, if err is not null (standard NAS error code)
    """
    if python_version < 3:
        try:
            if wl2:
                pd, type = unpack('>BB', buf[1:3])
            else:
                pd, type = unpack('>BB', buf[:2])
        except:
            # error 111, unspecified protocol error
            return None, 111
    else:
        try:
            if wl2:
                pd, type = buf[1], buf[2]
            else:
                pd, type = buf[0], buf[1]
        except:
            # error 111, unspecified protocol error
            return None, 111
    pd &= 0xF
    if pd in (3, 5, 11):
        type &= 0x3f
    elif pd in (2, 7):
        return parse_NASLTE_MT(buf, inner=True)
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
