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
    'FMT_LUT_IETF',
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

FMT_LUT_IETF = {
    # RFC 4004
    320 : OctetString,
    321 : OctetString,
    322 : Grouped,
    333 : Address,
    334 : Address,
    336 : DiameterIdentity,
    337 : Unsigned32,
    338 : Unsigned32,
    339 : Unsigned32,
    340 : Unsigned32,
    341 : Unsigned32,
    342 : IPFilterRule,
    344 : OctetString,
    347 : Grouped,
    348 : Grouped,
    # RFC 4005
    2   : OctetString,
    4   : OctetString,
    5   : Unsigned32,
    6   : Enumerated,
    7   : Enumerated,
    8   : OctetString,
    9   : OctetString,
    10  : Enumerated,
    11  : UTF8String,
    12  : Unsigned32,
    13  : Enumerated,
    14  : OctetString,
    15  : Enumerated,
    16  : Unsigned32,
    18  : UTF8String,
    19  : UTF8String,
    20  : UTF8String,
    22  : UTF8String,
    23  : UTF8String,
    24  : OctetString,
    28  : Unsigned32,
    30  : UTF8String,
    31  : UTF8String,
    32  : UTF8String,
    34  : OctetString,
    35  : OctetString,
    36  : OctetString,
    37  : Unsigned32,
    38  : Unsigned32,
    39  : OctetString,
    41  : Unsigned32,
    45  : Enumerated,
    46  : Unsigned32,
    51  : Unsigned32,
    60  : OctetString,
    61  : Enumerated,
    62  : Unsigned32,
    63  : OctetString,
    64  : Enumerated,
    65  : Enumerated,
    66  : UTF8String,
    67  : UTF8String,
    68  : OctetString,
    69  : OctetString,
    70  : OctetString,
    71  : OctetString,
    72  : Enumerated,
    73  : Unsigned32,
    74  : OctetString,
    75  : Unsigned32,
    76  : Enumerated,
    77  : UTF8String,
    78  : OctetString,
    81  : OctetString,
    82  : OctetString,
    83  : Unsigned32,
    84  : OctetString,
    86  : Unsigned32,
    87  : UTF8String,
    88  : OctetString,
    90  : UTF8String,
    91  : UTF8String,
    94  : OctetString,
    95  : OctetString,
    96  : Unsigned64,
    97  : OctetString,
    98  : OctetString,
    99  : UTF8String,
    100 : OctetString,
    295 : Enumerated,
    363 : Unsigned64,
    364 : Unsigned64,
    365 : Unsigned64,
    366 : Unsigned64,
    400 : IPFilterRule,
    401 : Grouped,
    402 : Grouped,
    403 : Enumerated,
    404 : OctetString,
    405 : OctetString,
    406 : Enumerated,
    #407 : QoSFilterRule,
    408 : Enumerated,
    # RFC 4006
    412 : Unsigned64,
    413 : Grouped,
    414 : Unsigned64,
    415 : Unsigned32,
    416 : Enumerated,
    417 : Unsigned64,
    418 : Enumerated,
    419 : Unsigned64,
    420 : Unsigned32,
    421 : Unsigned64,
    422 : Enumerated,
    423 : Grouped,
    424 : UTF8String,
    425 : Unsigned32,
    426 : Enumerated,
    427 : Enumerated,
    428 : Enumerated,
    429 : Integer32,
    430 : Grouped,
    431 : Grouped,
    432 : Unsigned32,
    433 : Enumerated,
    434 : Grouped,
    435 : UTF8String,
    436 : Enumerated,
    437 : Grouped,
    439 : Unsigned32,
    440 : Grouped,
    441 : Unsigned32,
    443 : Grouped,
    444 : UTF8String,
    445 : Grouped,
    446 : Grouped,
    447 : Integer64,
    448 : Unsigned32,
    449 : Enumerated,
    450 : Enumerated,
    451 : Time,
    452 : Enumerated,
    453 : Unsigned32,
    454 : Enumerated,
    455 : Enumerated,
    456 : Grouped,
    457 : Grouped,
    458 : Grouped,
    459 : Enumerated,
    461 : UTF8String,
    # RFC 4072
    102 : OctetString,
    462 : OctetString,
    463 : OctetString,
    464 : OctetString,
    465 : Unsigned64,
    # RFC 5447
    124 : Unsigned64,
    125 : OctetString,
    #334 : Address,
    #348 : Grouped,
    486 : Grouped,
    # RFC 5777
    508 : Grouped,
    509 : Grouped,
    510 : Unsigned32,
    511 : Grouped,
    512 : OctetString,
    513 : Enumerated,
    514 : Enumerated,
    515 : Grouped,
    516 : Grouped,
    517 : Enumerated,
    518 : Address,
    519 : Grouped,
    520 : Address,
    521 : Address,
    522 : Grouped,
    523 : Unsigned32,
    524 : OctetString,
    525 : Grouped,
    526 : OctetString,
    527 : OctetString,
    528 : Grouped,
    529 : OctetString,
    530 : Integer32,
    531 : Grouped,
    532 : Integer32,
    533 : Integer32,
    534 : Enumerated,
    535 : Enumerated,
    536 : Enumerated,
    537 : Grouped,
    538 : Enumerated,
    539 : OctetString,
    540 : Grouped,
    541 : Enumerated,
    542 : OctetString,
    543 : Grouped,
    544 : Unsigned32,
    545 : Grouped,
    546 : Enumerated,
    547 : Enumerated,
    548 : Grouped,
    549 : Grouped,
    550 : OctetString,
    551 : OctetString,
    552 : Grouped,
    553 : Unsigned32,
    554 : Unsigned32,
    555 : Unsigned32,
    556 : Unsigned32,
    557 : Grouped,
    558 : Unsigned32,
    559 : Unsigned32,
    560 : Grouped,
    561 : Unsigned32,
    562 : Unsigned32,
    563 : Unsigned32,
    564 : Unsigned32,
    565 : Unsigned32,
    566 : Time,
    567 : Unsigned32,
    568 : Time,
    569 : Unsigned32,
    570 : Enumerated,
    571 : Integer32,
    572 : Grouped,
    573 : Unsigned32,
    574 : Grouped,
    575 : Enumerated,
    576 : Grouped,
    577 : Grouped,
    578 : Grouped,
    # RFC 5778
    89  : OctetString,
    343 : OctetString,
    345 : Enumerated,
    346 : Enumerated,
    487 : Address,
    488 : OctetString,
    489 : OctetString,
    490 : OctetString,
    491 : Unsigned32,
    492 : Grouped,
    493 : UTF8String,
    494 : Enumerated,
    # RFC 6733
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
    # RFC 7683
    621 : Grouped,
    622 : Unsigned64,
    623 : Grouped,
    624 : Unsigned64,
    625 : Unsigned32,
    626 : Enumerated,
    627 : Unsigned32,
    # RFC 7944
    301 : Enumerated,
    # RFC 8583
    649 : DiameterIdentity,
    650 : Grouped,
    651 : Enumerated,
    652 : Unsigned64,
    }


#------------------------------------------------------------------------------#
# 3.  Diameter Header
#------------------------------------------------------------------------------#

AVPIETF.FMT_LUT = FMT_LUT_IETF


class DiameterIETF(DiameterGeneric):
    _GEN = (
        DiameterHdr(),
        Sequence('AVPs', GEN=AVPIETF(), hier=1)
        )

