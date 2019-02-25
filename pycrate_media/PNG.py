# -*- coding: UTF-8 -*-
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
# * File Name : pycrate_media/PNG.py
# * Created : 2016-03-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from zlib import crc32

from pycrate_core.elt  import *
from pycrate_core.base import *
from pycrate_core.repr import *

Buf.REPR_MAXLEN = 256

_Colour_dict = {
    0 : 'Greyscale',
    2 : 'Truecolour',
    3 : 'Indexed-colour',
    4 : 'Greyscale with alpha',
    6 : 'Truecolour with alpha'
    }
_CompMeth_dict = {
    0 : 'inflate/deflate with sliding window'
    }
_FilterMeth_dict = {
    0 : 'adaptative filtering with 5 basic filter types',
    }
_InterMeth_dict = {
    0 : 'no interlace',
    1 : 'Adam7 interlace'
    }

class IHDR(Envelope):
    _GEN = (
      Uint32('width'),
      Uint32('height'),
      Uint8('depth', desc='bit depth'),
      Uint8('color', desc='color type', dic=_Colour_dict),
      Uint8('comp', desc='compression method', dic=_CompMeth_dict),
      Uint8('filter', desc='filter method', dic=_InterMeth_dict),
      Uint8('interlace', desc='interlace method', dic=_InterMeth_dict)
      )

class PaletteEntry(Envelope):
    _GEN = (
        Uint8('Red'),
        Uint8('Green'),
        Uint8('Blue')
        )

class PLTE(Array):
    _GEN = PaletteEntry()

class PNGChunk(Envelope):
    CHK_CRC = True
    
    _GEN = (
        Uint32('len'),
        Buf('type', bl=32),
        Buf('data', rep=REPR_HD),
        Uint32('crc', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(self[2].get_len)
        self[2].set_blauto(lambda: 8*self[0].get_val())
        self[3].set_valauto(lambda: crc32(self[1:3].to_bytes()) & 0xffffffff)
    
    def _from_char(self, char):
        Envelope._from_char(self, char)
        chunk_len, chunk_type = self[0].get_val(), self[1].get_val()
        if chunk_type == b'IHDR' and chunk_len == 13:
            ihdr = IHDR()
            ihdr.from_bytes(self[2].to_bytes())
            self.replace(self[2], ihdr)
        elif chunk_type == b'PLTE' and chunk_len % 3 == 0:
            plte = PLTE()
            plte.set_num(chunk_len//3)
            plte.from_bytes(self[2].to_bytes())
            self.replace(self[2], plte)
        #
        if self.CHK_CRC:
            crc = self[3].get_val()
            self[3].reautomate()
            if self[3].get_val() != crc:
                log('warning, bad CRC32 for chunk {0}'.format(self[1].get_val()))

class PNG(Envelope):
    _GEN = (
        Buf('sig', desc='PNG signature', val=b'\x89PNG\r\n\x1a\n', bl=64),
        Sequence('PNGBody', hier=1, GEN=PNGChunk())
        )
