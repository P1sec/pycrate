# −*− coding: UTF−8 −*−
#/**
# * Software Name : pycrate 
# * Version : 0.4
# *
# * Copyright 2016. Benoit Michau. ANSSI.
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
# * File Name : pycrate_ether/ARP.py
# * Created : 2016-04-27
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 


from pycrate_core.elt import Envelope, REPR_RAW, REPR_HEX, REPR_BIN
from pycrate_core.base import *
from pycrate_core.repr import *


class ARP(Envelope):
    _GEN = (
        Uint16('hw_type', val=1, rep=REPR_HEX),
        Uint16('prot', rep=REPR_HEX),
        Uint8('hw_size'), # val automated
        Uint8('prot_size'), # val automated
        Uint16('op', val=1, dic={1:'request', 2:'reply'}),
        Buf('src_mac', val=6*b'\0', rep=REPR_HEX), # bl automated
        Buf('src', val=4*b'\0', rep=REPR_HEX), # bl automated
        Buf('dst_mac', val=6*b'\0', rep=REPR_HEX), # bl automated
        Buf('dst', val=4*b'\0', rep=REPR_HEX) # bl automated
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(self._set_hwsz_val)
        self[3].set_valauto(self._set_protsz_val)
        self[5].set_blauto(self._set_addrmac_bl)
        self[7].set_blauto(self._set_addrmac_bl)
        self[6].set_blauto(self._set_addr_bl)
        self[8].set_blauto(self._set_addr_bl)
    
    def _set_hwsz_val(self):
        return (self[5].get_bl() + self[7].get_bl()) // 16
    
    def _set_protsz_val(self):
        return (self[6].get_bl() + self[8].get_bl()) // 16
    
    def _set_addrmac_bl(self):
        return 8 * self[2].get_val()
    
    def _set_addr_bl(self):
        return 8 * self[3].get_val()

