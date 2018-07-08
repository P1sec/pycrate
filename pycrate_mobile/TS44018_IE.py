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
# Mobile Allocation
# TS 44.018, 10.5.2.21
#------------------------------------------------------------------------------#

class MobileAlloc(Envelope):
    _GEN = (
        )

