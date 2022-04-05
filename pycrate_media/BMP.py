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
# * File Name : pycrate_media/BMP.py
# * Created : 2016-03-04
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.elt  import *
from pycrate_core.base import *
from pycrate_core.repr import *

Buf.REPR_MAXLEN = 256


# BMP pixels array, with 2 variants
class PixelRow(Array):
    _GEN = UintLE('Pixel', bl=8, rep=REPR_HEX)
    
    #def _from_char(self, char):
    #    self._log('val before: {0}'.format(self._val))
    #    Array._from_char(self, char)
    #    self._log('val after: {0}'.format(self._val))

class PixelRowPad(Envelope):
    _GEN = (
        PixelRow(),
        Buf('padding', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_blauto(self._set_pad_len)
    
    def _set_pad_len(self):
        bl = self[0].get_bl()
        if bl % 32:
            return 32 - (bl%32)
        else:
            return 0

class PixelArray(Array):
    _GEN = PixelRowPad()

class PixelArrayBuf(Array):
    _GEN = Buf('PixelRowBuf', rep=REPR_HD)

# BMP headers
class ColorTable(Array):
    _GEN = Uint32LE('Color')

class DIBHeader(Envelope):
    _GEN = (
        Uint32LE('DIBHeaderSize'),
        Uint32LE('Width'),
        Uint32LE('Height'),
        Uint16LE('Planes'),
        Uint16LE('BitsPerPixel'),
        Uint32LE('Comp'),
        Uint32LE('ImageSize'),
        Uint32LE('XPixelsPerMeter'),
        Uint32LE('YPixelsPerMeter'),
        Uint32LE('ColorsInColorTable'),
        Uint32LE('ImportantColorCount'),
        Uint32LE('RedChannelBitmask', rep=REPR_HEX),
        Uint32LE('GreenChannelBitmask', rep=REPR_HEX),
        Uint32LE('BlueChannelBitmask', rep=REPR_HEX),
        Uint32LE('AlphaChannelBitmask', rep=REPR_HEX),
        Uint32LE('ColorSpaceType'),
        Uint32LE('ColorSpaceEndpoints'),
        Uint32LE('GammaRed'),
        Uint32LE('GammaGreen'),
        Uint32LE('GammaBlue'),
        Uint32LE('Intent'),
        Uint32LE('ICCProfileData'),
        Uint32LE('ICCProfileSize'),
        Uint32LE('Reserved', rep=REPR_HEX),
        )
    
    def _from_char(self, char):
        # DIB header may be shorter, depending of the BMP encoder used
        # non-encoded elements are set transparent
        size = char.to_uint_le(32)
        if size < 92:
            [self[-i].set_trans(True) for i in range(1, 1+((92-size)//4))]
        Envelope._from_char(self, char)

class FileHeader(Envelope):
    _GEN = (
        Buf('Signature', val=b'BM', bl=16),
        Uint32LE('Size'),
        Buf('Reserved', val=b'\0\0\0\0', bl=32, rep=REPR_HEX),
        Uint32LE('Offset')
        )

# TODO: check what is implied by multiple "Planes"
# does it mean multiple PixelArray ?

class BMP(Envelope):
    
    _GEN_LBUF = (
        FileHeader(),
        DIBHeader(hier=1),
        ColorTable(hier=2),
        Buf('padding', hier=2, rep=REPR_HD),
        PixelArrayBuf(hier=2)
        )
    
    _GEN_LPIX = (
        FileHeader(),
        DIBHeader(hier=1),
        ColorTable(hier=2),
        Buf('padding', hier=2, rep=REPR_HD),
        PixelArray(hier=2)
        )
    
    _GEN = _GEN_LBUF
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0][1].set_valauto(self._set_fileheader_size)
        self[0][3].set_valauto(self._set_fileheader_off)
        self[1][0].set_valauto(self._set_dibheader_size)
        self[1][9].set_valauto(self._set_dibheader_col)
        self[2].set_numauto(self._set_colortable_num)
        self[3].set_blauto(self._set_padding_len)
        self[4].set_numauto(self._set_pixelrow_num)
    
    def _set_fileheader_size(self):
        return 14 + self[1:].get_len()
    
    def _set_fileheader_off(self):
        return 14 + self[1:4].get_len()
    
    def _set_dibheader_size(self):
        return self[1].get_len()
    
    def _set_dibheader_col(self):
        return self[2].get_num()
    
    def _set_colortable_num(self):
        return self[1][9].get_val()
    
    def _set_padding_len(self):
        return 8 * (self[0][3].get_val() - self[0:3].get_len())
    
    def _set_pixelrow_num(self):
        return self[1][2].get_val()
    
    def _from_char(self, char):
        self[0:2]._from_char(char)
        w = self[1][1].get_val() # width
        h = self[1][2].get_val() # height
        pbl = self[1][4].get_val() # pixel bitlen
        #log('w, h, pbl:', w, h, pbl)
        if isinstance(self[4], PixelArrayBuf):
            # set PixelRowBuf length in bits (width * bits per pixel)
            row_len = w * pbl
            if row_len % 32:
                row_len += 32 - (row_len % 32)
            self[4].set_attrs(num=h, tmpl={'bl': row_len})
        else:
            # set PixelArray pixel bit length, width and height
            self[4].set_attrs(num=h, tmpl={'content':{'PixelRow': {'num':w, 'tmpl':{'bl':pbl}}}})
        #log(self[4].get_attrs())
        # continue parsing color table and pixel array
        self[2:]._from_char(char)

