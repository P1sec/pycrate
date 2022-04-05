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
# * File Name : pycrate_media/MPEG4.py
# * Created : 2016-04-14
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

# made from ISO_IEC_14496-12_2008.pdf (free ISO spec)
# does not implement 64-bit size field for atom / box
# does not implement specific atoms with extended header

from pycrate_core.charpy import *
from pycrate_core.elt    import *
from pycrate_core.base   import *
from pycrate_core.repr   import *

Buf.REPR_MAXLEN = 512

class Atom(Envelope):
    _GEN = (
        Uint32('size'),
        Buf('type', bl=32),
        Buf('data', val=b'', rep=REPR_HD)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(self._set_size_val)
        self[2].set_blauto(self._set_data_bl)
    
    def _set_data_bl(self):
        return 8*(self[0].get_val()-8)
    
    def _set_size_val(self):
        return 8+self[2].get_len()
    
    def _from_char(self, char):
        Envelope._from_char(self, char)
        # Atom recursive parsing
        if self[0].get_val() >= 16:
            data = self[2].get_val()
            sub = AtomSub('data')
            sub._from_char(Charpy(data))
            if sub.get_len() == len(data):
                self.replace(self[2], sub)

class AtomSub(Sequence):
    _GEN = Atom()

class MPEG4(Sequence):
    _GEN = Atom()

