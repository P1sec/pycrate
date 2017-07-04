# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright © 2016. Benoit Michau. ANSSI.
# *
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# * 
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# * 
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# * 02110-1301, USA.
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

class IHDR(Envelope):
    _GEN = (
      Uint32('width', bitlen=32),
      Uint32('height', bitlen=32),
      Uint8('depth', desc='bit depth'),
      Uint8('color', desc='color type'),
      Uint8('comp', desc='compression method'),
      Uint8('filter', desc='filter method'),
      Uint8('interlace', desc='interlace method')
      )

class PNGChunk(Envelope):
    CHK_CRC = True
    
    _GEN = (
        Uint32('len', desc='chunk length'),
        Buf('type', desc='chunk type', bl=32),
        Buf('data', desc='chunk data', rep=REPR_HD),
        Uint32('crc', desc='chunk CRC32', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(self[2].get_len)
        self[2].set_blauto(self._get_bl)
        self[3].set_valauto(self._set_crc)
    
    def _get_bl(self):
        return 8 * self[0].get_val()
    
    def _set_crc(self):
        return crc32(self[1:3].to_bytes()) & 0xffffffff
    
    def _from_char(self, char):
        Envelope._from_char(self, char)
        if self[1].get_val() == b'IHDR' and self[2].get_bl() == 104:
            ihdr = IHDR()
            ihdr.from_bytes(self[2].to_bytes())
            self.replace(self[2], ihdr)
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

