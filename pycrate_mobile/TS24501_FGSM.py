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
# * File Name : pycrate_mobile/TS24501_FGSM.py
# * Created : 2019-11-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#__all__ = [
#    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.501: NAS protocol for 5G
# release 16 (g20)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007    import *
#from .TS24008_IE import (
#    
#    )
#from .TS24301_IE import (
#    
#    )
from .TS24501_IE import *

#------------------------------------------------------------------------------#
# 5GS Session Management header
# TS 24.501, section 9
#------------------------------------------------------------------------------#

# section 9.7
_FGSM_dict = {
    #
    193 : "PDU session establishment request",
    194 : "PDU session establishment accept",
    195 : "PDU session establishment reject",
    #
    197 : "PDU session authentication command",
    198 : "PDU session authentication complete",
    199 : "PDU session authentication result",
    #
    201 : "PDU session modification request",
    202 : "PDU session modification reject",
    203 : "PDU session modification command",
    204 : "PDU session modification complete",
    205 : "PDU session modification command reject",
    #
    209 : "PDU session release request",
    210 : "PDU session release reject",
    211 : "PDU session release command",
    212 : "PDU session release complete",
    #
    214 : "5GSM status"
    }


class FGSMHeader(Envelope):
    _GEN = (
        Uint8('EPD', val=46, dic=ProtDisc_dict),
        Uint8('PDUSessionId'),
        Uint8('PTI'),
        Uint8('Type', val=214, dic=_FGSM_dict)
        )


