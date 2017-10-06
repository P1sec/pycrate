# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.2
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
# * File Name : pycrate_mobile/TS24301_IE.py
# * Created : 2017-06-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# 3GPP TS 24.301: NAS protocol for EPS
# release 13 (da0)
#------------------------------------------------------------------------------#

from binascii import unhexlify

from pycrate_core.utils  import *
from pycrate_core.elt    import Envelope, Array, REPR_RAW, REPR_HEX, REPR_BIN, REPR_HD, REPR_HUM
from pycrate_core.base   import *
from pycrate_core.repr   import *
from pycrate_core.charpy import Charpy

from pycrate_mobile.MCC_MNC import MNC_dict

#------------------------------------------------------------------------------#
# Additional update type
# TS 24.301, 9.9.3.0B
#------------------------------------------------------------------------------#

_PNBCIoT_dict = {
    0 : 'no additional information',
    1 : 'control plane CIoT EPS optimization',
    2 : 'user plane CIoT EPS optimization',
    3 : 'reserved'
    }
_SAF_dict = {
    0: 'NAS signalling not required after completion of TAU',
    1: 'NAS signalling required after completion of TAU'
    }
_AUTV_dict = {
    1 : 'SMS only'
    }

class AddUpdateType(Envelope):
    _GEN = (
        Uint('PNB_CIoT', val=0, bl=2, dic=_PNBCIoT_dict),
        Uint('SAF', val=0, bl=1, dic=_SAF_dict),
        Uint('AUTV', val=0, bl=1, dic=_AUTV_dict)
        )


#------------------------------------------------------------------------------#
# UE network capability
# TS 24.301, 9.9.3.34
#------------------------------------------------------------------------------#

class UENetCap(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('EEA0', bl=1),
        Uint('EEA1_128', bl=1),
        Uint('EEA2_128', bl=1),
        Uint('EEA3_128', bl=1),
        Uint('EEA4', bl=1),
        Uint('EEA5', bl=1),
        Uint('EEA6', bl=1),
        Uint('EEA7', bl=1),
        Uint('EIA0', bl=1),
        Uint('EIA1_128', bl=1),
        Uint('EIA2_128', bl=1),
        Uint('EIA3_128', bl=1),
        Uint('EIA4', bl=1),
        Uint('EIA5', bl=1),
        Uint('EIA6', bl=1),
        Uint('EIA7', bl=1), # end of octet 2 (mandatory part)
        Uint('UEA0', bl=1),
        Uint('UEA1', bl=1),
        Uint('UEA2', bl=1),
        Uint('UEA3', bl=1),
        Uint('UEA4', bl=1),
        Uint('UEA5', bl=1),
        Uint('UEA6', bl=1),
        Uint('UEA7', bl=1), # end of octet 3
        Uint('UCS2', bl=1),
        Uint('UIA1', bl=1),
        Uint('UIA2', bl=1),
        Uint('UIA3', bl=1),
        Uint('UIA4', bl=1),
        Uint('UIA5', bl=1),
        Uint('UIA6', bl=1),
        Uint('UIA7', bl=1), # end of octet 4
        Uint('ProSe_dd', bl=1),
        Uint('ProSe', bl=1),
        Uint('H245_ASH', bl=1),
        Uint('ACC_CSFB', bl=1),
        Uint('LPP', bl=1),
        Uint('LCS', bl=1),
        Uint('X1_SRVCC', bl=1),
        Uint('NF', bl=1), # end of octet 5
        Uint('ePCO', bl=1),
        Uint('HC_CP_CIoT', bl=1),
        Uint('ERw_oPDN', bl=1),
        Uint('S1U_data', bl=1),
        Uint('UP_CIoT', bl=1),
        Uint('CP_CIoT', bl=1),
        Uint('ProSe_relay', bl=1),
        Uint('ProSe_dc', bl=1), # end of octet 6
        Uint('spare', bl=1),
        Uint('spare', bl=1),
        Uint('spare', bl=1),
        Uint('spare', bl=1),
        Uint('spare', bl=1),
        Uint('spare', bl=1),
        Uint('spare', bl=1),
        Uint('MultiDRB', bl=1), # end of octet 7
        Buf('spare', val=b'', rep=REPR_HEX) # from 0 to 6 bytes
        )
    
    def _from_char(self, char):
        l = char.len_bit()
        if l <= 56:
            # disable all elements after bit l
            self.disable_from(l)
        elif l > 56:
            # enables some spare bits at the end
            self[-1]._bl = l-56
        Envelope._from_char(self, char)
    
    def disable_from(self, ind):
        """disables all elements from index `ind' excluded (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = self._by_name.index(ind)
        [e.set_trans(True) for e in self._content[ind:]]
    
    def enable_upto(self, ind):
        """enables all elements up to index `ind' included (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = 1 + self._by_name.index(ind)
        [e.set_trans(False) for e in self._content[:ind]]


