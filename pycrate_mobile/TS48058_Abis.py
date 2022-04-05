# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2020. Benoit Michau. P1sec.
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
# * File Name : pycrate_osmo/TS48058_Abis.py
# * Created : 2020-01-15
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'ChannelNumber',
    'LinkIdentifier',
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 48.058: BSC - BTS Abis signaling protocol 
# release 15 (f00)
#------------------------------------------------------------------------------#
# this is only the implementation of few Information Elements
# to bu used within osmocom-bb wrapping

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *
from pycrate_core.repr  import *


#------------------------------------------------------------------------------#
# Channel Number
# TS 48.058, section 9.3.1
#------------------------------------------------------------------------------#

ChannelNumberCbits_dict = {
    1 : 'Bm + ACCH',
    2 : 'Lm + ACCH; subchannel 0',
    3 : 'Lm + ACCH; subchannel 1',
    4 : 'SDCCH/4 + ACCH; subchannel 0',
    5 : 'SDCCH/4 + ACCH; subchannel 1',
    6 : 'SDCCH/4 + ACCH; subchannel 2',
    7 : 'SDCCH/4 + ACCH; subchannel 3',
    8 : 'SDCCH/8 + ACCH; subchannel 0',
    9 : 'SDCCH/8 + ACCH; subchannel 1',
    10 : 'SDCCH/8 + ACCH; subchannel 2',
    11 : 'SDCCH/8 + ACCH; subchannel 3',
    12 : 'SDCCH/8 + ACCH; subchannel 4',
    13 : 'SDCCH/8 + ACCH; subchannel 5',
    14 : 'SDCCH/8 + ACCH; subchannel 6',
    15 : 'SDCCH/8 + ACCH; subchannel 7',
    16 : 'BCCH',
    17 : 'Uplink CCCH (RACH)',
    18 : 'Downlink CCCH (PCH + AGCH)',
    }

class ChannelNumber(Envelope):
    _GEN = (
        Uint('Cbits', val=1, bl=5, dic=ChannelNumberCbits_dict),
        Uint('TN', bl=3) 
        )


#------------------------------------------------------------------------------#
# Link Identifier
# TS 48.058, section 9.3.2
#------------------------------------------------------------------------------#

LinkIdentifierCbits_dict = {
    0 : 'main signalling channel (FACCH or SDCCH)',
    1 : 'SACCH'
    }

LinkIdentifierPriority_dict = {
    0 : 'normal',
    1 : 'high',
    2 : 'low',
    }

LinkIdentifierSAPI_dict = {
    0 : 'CC/MM/RR',
    3 : 'SMS',
    }

class LinkIdentifier(Envelope):
    _GEN = (
        Uint('Cbits', bl=2, dic=LinkIdentifierCbits_dict),
        Uint('NA', bl=1, dic={1: 'not applicable'}),
        Uint('Priority', bl=2, dic=LinkIdentifierPriority_dict),
        Uint('SAPI', bl=3, dic=LinkIdentifierSAPI_dict)
        )


