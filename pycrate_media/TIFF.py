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
# * File Name : pycrate_media/TIFF.py
# * Created : 2016-03-31
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

# TIFF specification:
# http://partners.adobe.com/public/developer/en/tiff/TIFF6.pdf

from pycrate_core.elt  import *
from pycrate_core.base import *
from pycrate_core.repr import *

Buf.REPR_MAXLEN = 256

# image file header

class Header_BE(Envelope):
    _GEN = (
        Buf('BO', desc='byte order', val=b'MM', bl=16,
            dic={b'II':'little endian', b'MM':'big endian'}),
        Uint16('42', val=42),
        Uint32('IFDOffset'),
        )

class Header_LE(Envelope):
    _GEN = (
        Buf('BO', desc='byte order', val=b'II', bl=16,
            dic={b'II':'little endian', b'MM':'big endian'}),
        Uint16LE('FourtyTwo', val=42),
        Uint32LE('IFDOffset', desc='ImageFileDir offset'),
        )

# image file directories

Type_dict = {
    1 : 'BYTE',
    2 : 'ASCII',
    3 : 'SHORT',
    4 : 'LONG',
    5 : 'RATIONAL',
    6 : 'SBYTE',
    7 : 'UNDEFINED',
    8 : 'SSHORT',
    9 : 'SLONG',
    10 : 'SRATIONAL',
    11 : 'FLOAT',
    12 : 'DOUBLE'
    }

TypeLen_dict = {
    1 : 1,
    2 : 1,
    3 : 2,
    4 : 4,
    5 : 8,
    6 : 1,
    7 : 1,
    8 : 2,
    9 : 4,
    10 : 8,
    11 : 4,
    12 : 8
    }

TypeStructBE_dict = {
    1 : Buf('Val', desc='BYTE array', rep=REPR_HD),
    2 : Buf('Val', desc='ASCII buffer'),
    3 : Array('Val', GEN=Uint16('SHORT')),
    4 : Array('Val', GEN=Uint32('LONG')),
    5 : Array('Val', GEN=Envelope('RATIONAL', GEN=(Uint32('num'), Uint32('den')))),
    6 : Buf('Val', desc='SBYTE array', rep=REPR_HD),
    7 : Buf('Val', desc='UNDEFINED buffer', rep=REPR_HD),
    8 : Array('Val', GEN=Int16('SSHORT')),
    9 : Array('Val', GEN=Int32('SLONG')),
    10 : Array('Val', GEN=Envelope('SRATIONAL', GEN=(Uint32('num'), Uint32('den')))),
    11 : Array('Val', GEN=Buf('FLOAT', bl=32)),
    12 : Array('Val', GEN=Buf('DOUBLE', bl=64))
    }
TypeStructLE_dict = {
    1 : Buf('Val', desc='BYTE array', rep=REPR_HD),
    2 : Buf('Val', desc='ASCII buffer'),
    3 : Array('Val', GEN=Uint16LE('SHORT')),
    4 : Array('Val', GEN=Uint32LE('LONG')),
    5 : Array('Val', GEN=Envelope('RATIONAL', GEN=(Uint32LE('num'), Uint32LE('den')))),
    6 : Buf('Val', desc='SBYTE array', rep=REPR_HD),
    7 : Buf('Val', desc='UNDEFINED buffer', rep=REPR_HD),
    8 : Array('Val', GEN=Int16LE('SSHORT')),
    9 : Array('Val', GEN=Int32LE('SLONG')),
    10 : Array('Val', GEN=Envelope('SRATIONAL', GEN=(Uint32LE('num'), Uint32LE('den')))),
    11 : Array('Val', GEN=Buf('FLOAT', bl=32)),
    12 : Array('Val', GEN=Buf('DOUBLE', bl=64))
    }
TypeStruct_dict = {
    'l': TypeStructLE_dict,
    'b': TypeStructBE_dict
    }

Tag_dict = {
    142 : 'Software',
    
    154 : 'DateTime',
    
    254 : 'NewSubfileType',
    255 : 'SubfileType',
    256 : 'ImageWidth',
    257 : 'ImageLength',
    258 : 'BitsPerSample',
    259 : 'Compression',
    
    262 : 'PhotometricInterpretation',
    263 : 'Thresholding',
    264 : 'CellWidth',
    265 : 'CellLength',
    266 : 'FillOrder',
    
    270 : 'ImageDescription',
    271 : 'Make',
    272 : 'Model',
    273 : 'StripOffsets',
    274 : 'Orientation',
    
    277 : 'SamplesPerPixel',
    278 : 'RowsPerStrip',
    279 : 'StripByteCounts',
    280 : 'MinSampleValue',
    281 : 'MaxSampleValue',
    282 : 'XResolution',
    283 : 'YResolution',
    284 : 'PlanarConfiguration',
    
    288 : 'FreeOffsets',
    289 : 'FreeByteCounts',
    290 : 'GrayResponseUnit',
    291 : 'GrayResponseCurve',
    
    296 : 'ResolutionUnit',
    
    305 : 'Software',
    306 : 'DateTime',
    
    315 : 'Artist',
    316 : 'HostComputer',
    
    320 : 'ColorMap',
    
    338 : 'ExtraSamples',
    
    33432 : 'Copyright',
    }

class IFDEntry_BE(Envelope):
    #_VAL_OFF = None # in case val is an offset
    
    _GEN = (
        Uint16('Tag', dic=Tag_dict),
        Uint16('Type', dic=Type_dict),
        Uint32('Count'),
        Uint32('ValRef', bl=32)
        )

class IFD_BE(Envelope):
    _GEN = (
        Uint16('Num'),
        Sequence('IFDEntries', GEN=IFDEntry_BE()),
        Uint32('NextIFDOffset')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(self[1].get_num)
        self[1].set_numauto(self[0].get_val)

class IFDEntry_LE(Envelope):
    #_VAL_OFF = None # in case val is an offset
    
    _GEN = (
        Uint16LE('Tag', dic=Tag_dict),
        Uint16LE('Type', dic=Type_dict),
        Uint32LE('Count'),
        Uint32LE('ValRef', bl=32)
        )

class IFD_LE(Envelope):
    _GEN = (
        Uint16LE('Num'),
        Sequence('IFDEntries', GEN=IFDEntry_LE()),
        Uint32LE('NextIFDOffset')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(self[1].get_num)
        self[1].set_numauto(self[0].get_val)


# image file
# there is no predefined structure

class TIFF(Envelope):
    
    def _from_char(self, char):
        self._IFD = []
        sig = char.to_bytes(32)
        if sig == b'II*\x00':
            # little endian TIFF file
            self._E = 'l'
            self.append( Header_LE() )
            self[0]._from_char(char)
        elif sig == b'MM\x00*':
            # big-endian TIFF file
            self._E = 'b'
            self.append( Header_BE() )
            self[0]._from_char(char)
        else:
            log('TIFF: invalid file signature')
        self._from_char_cont(char)
    
    def _new_ifd(self, offset, ifd):
        self._IFD.append({
            'off': offset,
            'len': ifd.get_len(),
            'ifd': ifd,
            'val': [],
            'strip': []})
    
    def _from_char_cont(self, char):
        # parse all IFD, get 1st one
        offset = self[0][2].get_val() # IFDOffset
        char._cur = 8*offset
        while True:
            if self._E == 'l':
                ifd = IFD_LE()
            else:
                ifd = IFD_BE()
            ifd._from_char(char)
            self._new_ifd(offset, ifd)
            for entry in ifd[1]:
                # check all entries in the IFD
                self._get_ifd_entry(entry, char)
            # get the strips according to the IFD
            self._get_strips(char)
            # check for more IFD
            offset = ifd[2].get_val()
            if offset == 0:
                break
            else:
                char._cur = 8*offset
        # rebuild the sequential structure of data
        self._build_struct(char)
    
    def _get_ifd_entry(self, entry, char):
        # check type and count of the IFD entry
        typ, count = entry[1].get_val(), entry[2].get_val()
        # get length for the given type
        if typ in TypeLen_dict:
            tlen = TypeLen_dict[typ]
        else:
            tlen = 1
        # get the structure corresponding to the type
        if typ in TypeStruct_dict[self._E]:
            val = TypeStruct_dict[self._E][typ].clone()
            val.set_num(count)
        else:
            val = Buf('Val', desc='unknown type', bl=count*8, rep=REPR_HD)
        # get the values
        if count * tlen > 4:
            # reference to a file offset with the array of values
            offset = entry[3].get_val()
            char._cur = 8*offset
            val._from_char(char)
            # offset, length, tag, value
            self._IFD[-1]['val'].append((offset,
                                         count * tlen,
                                         entry[0].get_val(),
                                         val))
        else:
            # direct values
            val_buf = entry[3].to_bytes()
            val_len = val.get_len()
            val.from_bytes(val_buf)
            entry.replace(entry[3], val)
            if val_len < 4:
                # potential padding
                undef = Buf('Undef', bl=32-val.get_bl(), rep=REPR_HEX)
                undef.from_bytes(val_buf[val_len:])
                entry.append(undef)
    
    def _get_strips(self, char):
        # get the image strips for the last IFD
        ifd = self._IFD[-1]
        offsets, lengths = [], []
        # check 1st if strips offsets and lengths are stored outside of the IFD
        for infos in ifd['val']:
            # infos: (offset, len, tag, val)
            if infos[2] == 273:
                # strips offset
                offsets = [v.get_val() for v in infos[3]]
            elif infos[2] == 279:
                # strips length
                lengths = [v.get_val() for v in infos[3]]
        if not offsets and not lengths:
            # check for offsets and lengths directly stored within the IFD
            for entry in ifd['ifd'][1]:
                tag = entry[0].get_val()
                if tag == 273:
                    # strips offsets
                    offsets = [v.get_val() for v in entry[3]]
                elif tag == 279:
                    # strips lengths
                    lengths = [v.get_val() for v in entry[3]]
        if len(offsets) != len(lengths):
            raise(Exception('TIFF: invalid number of strip offsets and lengths'\
                            ' for IFD {0}'.format(len(self._IFD))))
        for i in range(len(offsets)):
            ifd['strip'].append( (offsets[i], lengths[i]) )
    
    def _build_struct(self, char):
        # get the list of offset, length and structure of all defined areas 
        # of data in the TIFF file
        areas = []
        i = 0
        for ifd in self._IFD:
            ifd_struct = ifd['ifd']
            ifd_struct._name = 'IFD{0}_{1}'.format(i, ifd_struct._name[4:])
            areas.append( (ifd['off'], ifd['len'], ifd_struct) )
            for val in ifd['val']:
                val_struct = val[3]
                val_struct._name = 'IFD{0}_Tag{1}_Val'.format(i, val[2])
                areas.append( (val[0], val[1], val_struct) )
            j = 0
            for infos in ifd['strip']:
                strip = Buf('IFD{0}_Strip{1}'.format(i, j), bl=infos[1]*8, rep=REPR_HD)
                char._cur = infos[0]*8
                strip._from_char(char)
                areas.append( (infos[0], infos[1], strip) )
                j += 1
            i += 1
        # sort areas by offset
        areas.sort(key=lambda x: x[0])
        #
        char._cur = 64
        for area in areas:
            if 8*area[0] != char._cur:
                # undefined data exists in the TIFF file
                log('TIFF: undefined data at offset {0}'.format(char._cur//8))
                undef = Buf('Undef', bl=(8*area[0])-char._cur, rep=REPR_HD)
                undef._from_char(char)
                self.append(undef)
            self.append(area[2])
            char._cur += 8*area[1]

