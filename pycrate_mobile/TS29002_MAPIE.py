# −*− coding: UTF−8 −*−
#/**
# * Software Name : pycrate
# * Version : 0.4.0
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
# * File Name : pycrate_mobile/TS29002_MAPIE.py
# * Created : 2019-12-05
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from pycrate_mobile.TS24008_IE import BufBCD


#------------------------------------------------------------------------------#
# AddressString
#------------------------------------------------------------------------------#

_AddressStrNumType_dict = {
    0 : 'unknown',
    1 : 'international number',
    2 : 'national significant number',
    3 : 'network specific number',
    4 : 'subscriber number',
    5 : 'reserved',
    6 : 'abbreviated number',
    7 : 'reserved for extension'
    }

_AddressStrNumPlan_dict = {
    0 : 'unknown',
    1 : 'ISDN/Telephony Numbering Plan (Rec ITU-T E.164)',
    2 : 'spare',
    3 : 'data numbering plan (ITU-T Rec X.121)',
    4 : 'telex numbering plan (ITU-T Rec F.69)',
    5 : 'spare',
    6 : 'land mobile numbering plan (ITU-T Rec E.212)',
    7 : 'spare',
    8 : 'national numbering plan',
    9 : 'private numbering plan',
    15 : 'reserved for extension'
    }


class AddressString(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('NumType', bl=3, dic=_AddressStrNumType_dict),
        Uint('NumPlan', bl=4, dic=_AddressStrNumPlan_dict),
        Alt('Num', GEN={
            1 : BufBCD('E164'),
            6 : BufBCD('E212'), 
            },
            DEFAULT=Buf('Hex', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[2].get_val())
        )

