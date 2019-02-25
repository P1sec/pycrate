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
# * File Name : pycrate_media/GIF.py
# * Created : 2016-04-15
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

# made from https://www.w3.org/Graphics/GIF/spec-gif89a.txt

from math import log as mathlog

from pycrate_core.charpy import *
from pycrate_core.elt    import *
from pycrate_core.base   import *
from pycrate_core.repr   import *

Buf.REPR_MAXLEN = 512

# GIF sub-blocks structure
class DataSubBlock(Envelope):
    _GEN = (
        Uint8('Size'),
        Buf('DataValues', rep=REPR_HD)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(self[1].get_len)
        self[1].set_blauto(self._set_data_len)
    
    def _set_data_len(self):
        return 8*self[0].get_val()

class DataSubBlocks(Array):
    _GEN = DataSubBlock()
    
    def _from_char(self, char):
        if self.get_trans():
            return
        # 1) determine the number of iteration of the template within the array
        if self._numauto is not None:
            num = self._numauto()
            if self._SAFE_DYN and not isinstance(num, integer_types):
                raise(EltErr('{0} [_from_char]: num type produced is {1}, expecting integer'\
                      .format(self._name, type(num).__name__)))
        elif self._num is not None:
            num = self._num
        else:
            # num is None, _from_char will consume the charpy instance until
            # it raises
            num = None
        # 2) init value
        self._val = []
        # 3) consume char and fill in self._val
        if num is not None:
            #'''
            try:
                [self._val.append(self._tmpl.get_val()) for i in range(num) \
                 if self._tmpl._from_char(char) is None]
            except CharpyErr as err:
                raise(CharpyErr('{0} [_from_char]: {1}'.format(self._name, err)))
            except Exception as err:
                raise(EltErr('{0} [_from_char]: {1}'.format(self._name, err)))
            self._tmpl.set_val(None)
            '''
            for i in range(num):
                try:
                    self._tmpl._from_char(char)
                except CharpyErr as err:
                    raise(CharpyErr('{0} [_from_char]: {1}'.format(self._name, err)))
                except Exception as err:
                    raise(EltErr('{0} [_from_char]: {1}'.format(self._name, err)))
                else:
                    self._val.append(self._tmpl.get_val())
            self._tmpl.set_val(None)
            '''
        else:
            # parse the char buffer until we encounter a 0-size DataSubBlock
            while True:
                # remember charpy cursor position, to restore it when it raises
                cur = char._cur
                try:
                    self._tmpl._from_char(char)
                except CharpyErr as err:
                    char._cur = cur
                    break
                except Exception as err:
                    raise(EltErr('{0} [_from_char]: {1}'.format(self._name, err)))
                else:
                    self._val.append(self._tmpl.get_val())
                    if self._val[-1][0] == 0:
                        break
            self._tmpl.set_val(None)

# GIF header and global metadata
class Header(Envelope):
    _GEN = (
        Buf('Signature', val=b'GIF', bl=24),
        Buf('Version', val=b'89a', bl=24)
        )

class LogicalScreenDescriptor(Envelope):
    _GEN = (
        Uint16LE('Width'),
        Uint16LE('Height'),
        Uint('GlobalColorTableFlag', bl=1),
        Uint('ColorResolution', bl=3),
        Uint('SortFlag', bl=1),
        Uint('SizeOfGlobalColorTable', bl=3),
        Uint8('BackgroundColorIndex'),
        Uint8('PixelAspectRatio')
        )

class GlobalColorTable(Array):
    _GEN = Envelope('ColorTriplet', GEN=(
            Uint8('Red'),
            Uint8('Green'),
            Uint8('Blue')
            ))
    # num: 2^(SizeOfGlobalColorTable+1)

class GIFHeader(Envelope):
    _GEN = (
        Header(),
        LogicalScreenDescriptor(),
        GlobalColorTable()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1][5].set_valauto(self._set_sizeOfGlobalColorTable)
        self[2].set_transauto(self._set_globalColorTable_trans)
        self[2].set_numauto(self._set_globalColorTable_num)
    
    def _set_sizeOfGlobalColorTable(self):
        num = self[2].get_num()
        if num > 0:
            return int(mathlog(num, 2)-1)
        else:
            return 0
    
    def _set_globalColorTable_trans(self):
        return (True, False)[self[1][2].get_val()]
    
    def _set_globalColorTable_num(self):
        return 2**(1+self[1][5].get_val())

# GIF image description
class ImageDescriptor(Envelope):
    _GEN = (
        Uint8('ImageSeparator', val=0x2c),
        Uint16LE('ImageLeftPosition'),
        Uint16LE('ImageTopPosition'),
        Uint16LE('ImageWidth'),
        Uint16LE('ImageHeight'),
        Uint('LocalColorTableFlag', bl=1),
        Uint('InterlaceFlag', bl=1),
        Uint('SortFlag', bl=1),
        Uint('Reserved', bl=2, rep=REPR_BIN),
        Uint('SizeOfLocalColorTable', bl=3)
        )

class LocalColorTable(Array):
    _GEN = Envelope('ColorTriplet', GEN=(
            Uint8('Red'),
            Uint8('Green'),
            Uint8('Blue')
            ))
    # num: 2^(SizeOfLocalColorTable+1)
    
class TableBasedImageData(Envelope):
    _GEN = (
        Uint8('LZWMinimumCodeSize'),
        DataSubBlocks('ImageData')
        )

class GIFImage(Envelope):
    _GEN = (
        ImageDescriptor(),
        LocalColorTable(),
        TableBasedImageData()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0][9].set_valauto(self._set_sizeOfLocalColorTable)
        self[1].set_transauto(self._set_localColorTable_trans)
        self[1].set_numauto(self._set_localColorTable_num)
    
    def _set_sizeOfLocalColorTable(self):
        num = self[1].get_num()
        if num > 0:
            return int(mathlog(num, 2)-1)
        else:
            return 0
    
    def _set_localColorTable_trans(self):
        return (True, False)[self[0][5].get_val()]
    
    def _set_localColorTable_num(self):
        return 2**(1+self[0][9].get_val())

# GIF extensions
class GraphicControlExtension(Envelope):
    _GEN = (
        Uint8('ExtensionIntroducer', val=0x21),
        Uint8('GraphicControlLabel', val=0xf9),
        Uint8('BlockSize', val=4),
        Uint('Reserved', bl=3),
        Uint('DisposalMethod', bl=3),
        Uint('UserInputFlag', bl=1),
        Uint('TransparentColorFlag', bl=1),
        Uint16LE('DelayTime'),
        Uint8('TransparentColorIndex'),
        Uint8('BlockTerminator')
        )

class CommentExtension(Envelope):
    _GEN = (
        Uint8('ExtensionIntroducer', val=0x21),
        Uint8('CommentLabel', val=0xfe),
        DataSubBlocks('CommentData'),
        )

class PlainTextExtension(Envelope):
    _GEN = (
        Uint8('ExtensionIntroducer', val=0x21),
        Uint8('PlainTextLabel', val=0x01),
        Uint8('BlockSize', val=12),
        Uint16LE('TextGridLeftPosition'),
        Uint16LE('TextGridTopPosition'),
        Uint16LE('TextGridWidth'),
        Uint16LE('TextGridHeight'),
        Uint8('CharacterCellWidth'),
        Uint8('CharacterCellHeight'),
        Uint8('TextForegroundColorIndex'),
        Uint8('TextBackgroundColorIndex'),
        DataSubBlocks('PlainTextData'),
        )

class ApplicationExtension(Envelope):
    _GEN = (
        Uint8('ExtensionIntroducer', val=0x21),
        Uint8('ExtensionLabel', val=0xff),
        Uint8('BlockSize', val=11),
        Buf('ApplicationIdentifier', bl=64),
        Buf('ApplicationAuthenticationCode', bl=24),
        DataSubBlocks('ApplicationData'),
        )

Extensions_dict = {
    0x01 : PlainTextExtension,
    0xf9 : GraphicControlExtension,
    0xfe : CommentExtension,
    0xff : ApplicationExtension
    }

# Complete GIF file format
class GIF(Envelope):
    _GEN = (
        GIFHeader(),
        Uint8('Trailer', val=0x3b)
        )
    
    def _from_char(self, char):
        self[0]._from_char(char)
        while True:
            mark = char.to_uint(8)
            if mark == 0x2c:
                # image data block
                im = GIFImage(hier=1)
                im._from_char(char)
                self.insert(-1, im)
            elif mark == 0x21:
                # extension block
                char._cur += 8
                submark = char.to_uint(8)
                char._cur -= 8
                if submark in Extensions_dict:
                    ext = Extensions_dict[submark](hier=1)
                    ext._from_char(char)
                    self.insert(-1, ext)
                else:
                    raise(Exception('GIF: invalid extension label: {0}'\
                                    .format(hex(submark))))
            elif mark == 0x3b:
                break
            else:
                raise(Exception('GIF: invalid block marker: {0}'.format(hex(mark))))
        self[-1]._from_char(char)
