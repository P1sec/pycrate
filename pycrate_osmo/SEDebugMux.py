# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2022. Vadim Yanitskiy
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
# * File Name : pycrate_osmo/SEDebugMux.py
# * Created : 2022-01-08
# * Authors : Vadim Yanitskiy
# *--------------------------------------------------------
#*/

import crcmod

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *
from pycrate_core.repr  import *


class DebugMuxFrame(Envelope):
    _GEN = (
        Buf('magic', desc='Start marker', val=b'\x42\x42', bl=16),
        Uint16LE('length', desc='Message length'), # val automated
        Uint8('tx_count', desc='Number of messages sent'),
        Uint8('rx_count', desc='Number of messages received'),
        Uint8('msg_type', desc='Message type', rep=REPR_HEX),
        Buf('msg_data', rep=REPR_HEX), # TODO: define inner data structures
        Uint16LE('fcs', desc='Frame Check Sequence', rep=REPR_HEX) # val automated
        )

    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        
        # The 'length' field indicates length of *all* fields following it
        self['length'].set_valauto(lambda: 3 + self['msg_data'].get_len() + 2)
        self['msg_data'].set_blauto(lambda: (self['length'].get_val() - 3 - 2) * 8)
        
        # Kudos to Stefan @Sec Zehl for finding the CRC function parameters
        self._fcs_func = crcmod.mkCrcFun(0x11021, rev=True, initCrc=0x0, xorOut=0xffff)
        self['fcs'].set_valauto(lambda: self._fcs_func(self[:-1].to_bytes()))
