# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2018. Benoit Michau. P1sec.
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
# * File Name : pycrate_mobile/TS44018_GTTP.py
# * Created : 2018-11-21
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# 3GPP TS 44.018 GSM / EDGE RRC protocol
# release 15 (f30)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007    import *
from .TS44018_IE import *


GTTPType_dict = {
    0 : 'GPRS INFORMATION',
    }


class GTTPHeader(Envelope):
    _GEN = (
        Uint('SkipInd', bl=4),
        Uint('ProtDisc', val=4, bl=4, dic=ProtDisc_dict),
        Uint('Type', bl=8, dic=GTTPType_dict),
        )


#------------------------------------------------------------------------------#
# GPRS INFORMATION
# TS 44.018, section 9.6.1
#------------------------------------------------------------------------------#

class GTTPGPRSInformation(Layer3):
    _GEN = (
        GTTPHeader(val={'Type':0}),
        Type3V('TLLI', val={'V':4*b'\0'}, bl={'V':32}, IE=TLLI()),
        Type4LV('LLC_PDU', val={'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# GTTP dispatcher
#------------------------------------------------------------------------------#

GTTPTypeClasses = {
    0 : GTTPGPRSInformation,
    }

def get_gttp_msg_instances():
    return {0: GTTPGPRSInformation()}

