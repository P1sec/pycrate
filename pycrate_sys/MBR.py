# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
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
# * File Name : pycrate_sys/MBR.py
# * Created : 2018-06-01
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.elt  import *
from pycrate_core.base import *
from pycrate_core.repr import *

Buf.REPR_MAXLEN = 1024

class PTE(Envelope):
    """Partition Table Entry
    """
    _GEN = (
        Uint('Active', bl=1),
        Uint('Status', bl=7, repr=REPR_HEX),
        Uint24('CHSAddrFirst', repr=REPR_HEX),
        Uint8('Type'),
        Uint24('CHSAddrLast', repr=REPR_HEX),
        Uint32('LBA'),
        Uint32('NumOfSectors')
        )

class MBR(Envelope):
    """Master Boot Record
    """
    _GEN = (
        Buf('Code', bl=0xDF0, rep=REPR_HD),
        PTE('PTE_1'),
        PTE('PTE_2'),
        PTE('PTE_3'),
        PTE('PTE_4'),
        Uint16('55AA', rep=REPR_HEX)
        )
