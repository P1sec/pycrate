# −*− coding: UTF−8 −*−
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
# * File Name : pycrate_ether/MPLS.py
# * Created : 2019-07-02
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.elt  import Envelope, Sequence, REPR_RAW, REPR_HEX, REPR_BIN
from pycrate_core.base import *
from pycrate_core.repr import *


class MPLSLabel(Envelope):
    _GEN = (
        Uint('Label', bl=20),
        Uint('Exp', bl=3),
        Uint('S', bl=1),
        Uint8('TTL')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: self._s_set())
    
    def _s_set(self):
        n = self.get_next()
        if n and isinstance(n, self.__class__):
            self[2].set_val(0)
        else:
            self[2].set_val(1)


class MPLSHeader(Envelope):
    _GEN = (
        MPLSLabel(),
        )
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self.__init__()
        self[0]._from_char(char)
        while char.len_bit() >= 32 and self[-1]['S']() == 0:
            self.append( MPLSLabel() )
            self[-1]._from_char(char)

