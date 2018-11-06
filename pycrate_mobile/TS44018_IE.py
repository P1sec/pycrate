# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.3
# *
# * Copyright 2018. Benoit Michau. ANSSI.
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
# * File Name : pycrate_mobile/TS44018_IE.py
# * Created : 2018-06-21
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# 3GPP TS 44.018 GSM / EDGE RRC protocol
# release 13 (d80)
#------------------------------------------------------------------------------#

from pycrate_core.utils  import *
from pycrate_core.elt    import Envelope, Array, Sequence, REPR_RAW, REPR_HEX, \
                                REPR_BIN, REPR_HD, REPR_HUM
from pycrate_core.base   import *
from pycrate_core.repr   import *



#------------------------------------------------------------------------------#
# Channel Description
# TS 44.018, 10.5.2.5
#------------------------------------------------------------------------------#

ChanDescType_dict = {
    1 : 'TCH/F + ACCHs; TSC Set 1 shall be used',
    17 : 'TCH/F + ACCHs; TSC Set 2 shall be used; subchannel 0',
    18 : 'TCH/F + ACCHs; TSC Set 2 shall be used; subchannel 1',
    4 : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); TSC Set 1 shall be used; subchannel 0',
    5 : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); TSC Set 1 shall be used; subchannel 1',
    6 : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); TSC Set 1 shall be used; subchannel 2',
    7 : 'SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4); TSC Set 1 shall be used; subchannel 3',
    8 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 0',
    9 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 1',
    10 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 2',
    11 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 3',
    12 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 4',
    13 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 5',
    14 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 6',
    15 : 'SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8); TSC Set 1 shall be used; subchannel 7',
}

ChanDescHop_dict = {
    0 : 'Single RF channel',
    1 : 'RF hopping channel',
}

class ChanDesc(Envelope):
    _GEN = (
        Uint('ChanType', bl=5, dic=ChanDescType_dict),
        Uint('TN', bl=3),
        Uint('TSC', bl=3),
        Uint('HopChan', bl=1, dic=ChanDescHop_dict),
        Uint('spare', bl=2, rep=REPR_HEX),
        Uint('ARFCN', bl=10),
        Uint('MAIO', bl=6),
        Uint('HSN', bl=6)
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        # manage single / hopping channel conditional fields
        self[4].set_transauto(lambda: True if self[3].get_val() == 1 else False)
        self[5].set_transauto(lambda: True if self[3].get_val() == 1 else False)
        self[6].set_transauto(lambda: True if self[3].get_val() == 0 else False)
        self[7].set_transauto(lambda: True if self[3].get_val() == 0 else False)


#------------------------------------------------------------------------------#
# Frequency List
# TS 44.018, 10.5.2.13
#------------------------------------------------------------------------------#
'''
class FreqList(Envelope):
    _GEN = (
        Uint('Fmt', bl=2),
        Alt(
            GEN={
                }
        )
    def __init__(self, *args, **kwargs):
        self[1].set_valauto()
'''
#------------------------------------------------------------------------------#
# Mobile Allocation
# TS 44.018, 10.5.2.21
#------------------------------------------------------------------------------#

class MobAlloc(Buf):
    _rep = REPR_BIN
    
    # dedicated method to get, set and unset cell alloc offsets
    def get(self, off):
        return 1 & (self.to_uint()>>(off-1))
    
    def set(self, off):
        u = self.to_uint()
        o = 1<<(off-1)
        if not u & o:
            self.from_uint(u+o)
    
    def unset(self, off):
        u = self.to_uint()
        o = 1<<(off-1)
        if u & o:
            self.from_uint(u-o)


#------------------------------------------------------------------------------#
# Starting Time
# TS 44.018, 10.5.2.38
#------------------------------------------------------------------------------#

class StartingTime(Envelope):
    _GEN = (
        Uint('T1prime', bl=5),
        Uint('T3', bl=6),
        Uint('spare', bl=5)
        )


#------------------------------------------------------------------------------#
# Extended TSC Set
# TS 44.018, 10.5.2.82
#------------------------------------------------------------------------------#

class ExtTSCSet(Envelope):
    _GEN = (
        Uint('PSSecondTSCVal', bl=3),
        Uint('PSSecondTSCSet', bl=1),
        Uint('PSPrimTSCSet', bl=1),
        Uint('PSSecondTSCAssign', bl=1),
        Uint('CSTSCSet', bl=2)
        )

