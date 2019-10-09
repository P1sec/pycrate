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
# * File Name : pycrate_diameter/DiameterIETF.py
# * Created : 2019-08-01
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'FMT_LUT_RFC6733',
    'Grouped',
    'AVPIETF',
    'DiameterIETF'
    ]


#------------------------------------------------------------------------------#
# IETF RFC 6733
# https://tools.ietf.org/html/rfc6733
# IETF specific implementation (with AVP specific format)
#------------------------------------------------------------------------------#

from pycrate_core.elt           import Sequence
from pycrate_diameter.Diameter  import *


#------------------------------------------------------------------------------#
# 4.1.  AVP Header
#------------------------------------------------------------------------------#

class AVPIETF(AVPGeneric):
    pass


#------------------------------------------------------------------------------#
# 4.4.   Grouped AVP Values
#------------------------------------------------------------------------------#

class Grouped(Sequence):
    _GEN = AVPIETF()


#------------------------------------------------------------------------------#
# 4.5.  Diameter Base Protocol AVPs
#------------------------------------------------------------------------------#

# 1 -> 190 : RADIUS (code -> name, fmt [to be translated from RADIUS to Diameter])
# 256+     : Diameter (code -> name, fmt)

FMT_LUT_RFC6733 = {
    1   : UTF8String,
    25  : OctetString,
    27  : Unsigned32,
    33  : OctetString,
    44  : OctetString,
    50  : UTF8String,
    55  : Time,
    85  : Unsigned32,
    257 : Address,
    258 : Unsigned32,
    259 : Unsigned32,
    260 : Grouped,
    261 : Enumerated,
    262 : Unsigned32,
    263 : UTF8String,
    264 : DiameterIdentity,
    265 : Unsigned32,
    266 : Unsigned32,
    267 : Unsigned32,
    268 : Unsigned32,
    269 : UTF8String,
    270 : Unsigned32,
    271 : Enumerated,
    272 : Unsigned32,
    273 : Enumerated,
    274 : Enumerated,
    276 : Unsigned32,
    277 : Enumerated,
    278 : Unsigned32,
    279 : Grouped,
    280 : DiameterIdentity,
    281 : UTF8String,
    282 : DiameterIdentity,
    283 : DiameterIdentity,
    284 : Grouped,
    285 : Enumerated,
    287 : Unsigned64,
    291 : Unsigned32,
    292 : DiameterURI,
    293 : DiameterIdentity,
    294 : DiameterIdentity,
    295 : Enumerated,
    296 : DiameterIdentity,
    297 : Grouped,
    298 : Unsigned32,
    299 : Unsigned32,
    480 : Enumerated,
    483 : Enumerated,
    485 : Unsigned32,
    }


#------------------------------------------------------------------------------#
# 3.  Diameter Header
#------------------------------------------------------------------------------#

AVPIETF.FMT_LUT = FMT_LUT_RFC6733


class DiameterIETF(DiameterGeneric):
    _GEN = (
        DiameterHdr(),
        Sequence('AVPs', GEN=AVPIETF(), hier=1)
        )

