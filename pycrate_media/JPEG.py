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
# * File Name : pycrate_media/JPEG.py
# * Created : 2016-03-09
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.elt  import *
from pycrate_core.base import *
from pycrate_core.repr import *

Buf.REPR_MAXLEN = 256

# Detailed JPEG metadata segments
# Start Of Frame
class SOFComponent(Envelope):
    _GEN = (
        Uint8('C', desc='Component identifier'),
        Uint('H', desc='Horizontal sampling factor', bl=4),
        Uint('V', desc='Vertical sampling factor', bl=4),
        Uint8('Tq', desc='Quantization table destination selector')
        )

class SOF(Envelope):
    _GEN = (
        Uint8('P', desc='Sample Precision'),
        Uint16('Y', desc='Number of lines'),
        Uint16('X', desc='Number of sample per line'),
        Uint8('Nf', desc='Number of image components in frame'),
        Array('SOFComponents', GEN=SOFComponent())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[3].set_valauto(self[4].get_num)
        self[4].set_numauto(self[3].get_val)
    
# Start Of Scan
class SOSComponent(Envelope):
    _GEN = (
        Uint8('Cs', desc='Scan component selector'),
        Uint('Td', desc='DC entropy coding table destination selector', bl=4),
        Uint('Ta', desc='AC entropy coding table destination selector', bl=4)
        )

class SOS(Envelope):
    _GEN = (
        Uint8('Nf', desc='Number of image components in frame'),
        Array('SOSComponents', GEN=SOSComponent()),
        Uint8('Ss', desc='Start of spectral or predictor selection'),
        Uint8('Se', desc='End of spectral selection'),
        Uint('Ah', desc='Successive approximation bit position high', bl=4),
        Uint('Al', desc='Successive approximation bit position low', bl=4),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(self[1].get_num)
        self[1].set_numauto(self[0].get_val)
    
    def append_data(self, data=b''):
        self.append( Buf('Data', val=data, rep=REPR_HD) )

# Quantization Table
class DQT(Envelope):
    _GEN = (
        Uint('Pq', ReprName='Quantization table element precision', bl=4),
        Uint('Tq', ReprName='Quantization table destination identifier', bl=4),
        Array('QT', num=64, 
              GEN=Uint8('QTe', desc='Quantization table element', val=1))
        )
        
    def _from_char(self, char):
        self[0:2]._from_char(char)
        if self[0].get_val():
            self[2].set_bl(16)
        self[2]._from_char(char)

# Huffman Table
class DHT(Envelope):
    _GEN = (
        Uint('Tc', desc='Huffman table class', bl=4),
        Uint('Th', desc='Huffman table destination identifier', bl=4) ) + \
        tuple([Uint8('HCL{0}'.format(i),
                     desc='Number of huffman codes of length {0}'.format(i)) \
               for i in range(1, 17)]) + \
        (Buf('HCV'),
        )
    
    def _from_char(self, char):
        Envelope._from_char(self, char)
        # generate the detailed table of values for all the huffman codes 
        hcv_gen = []
        for hcl in self[2:18]:
            for j in range(1, 1+hcl.get_val()):
                hcv_gen.append( \
                    Uint8('{0}_HCV{1}'.format(hcl._name, j),
                          desc='Value {0} for {1}'.format(j, hcl._name)) )
        hcv_env = Envelope('HCV', GEN=tuple(hcv_gen))
        # parse it, and substitute if to the buffer one
        hcv = self[18].get_val()
        hcv_env.from_bytes(hcv)
        if hcv_env.get_len() == len(hcv):
            self.replace(self[18], hcv_env)

# Arithmetic Table
class DACComponent(Envelope):
    _GEN = (
        Uint('Tc', desc='Table class', bl=4),
        Uint('Tb',
             desc='Arithmetic coding conditioning table destination identifier',
             bl=4),
        Uint8('CS', desc='Conditioning table value')
        )
    
class DAC(Array):
    _GEN = DACComponent()


# generic JPEG metadata segment
# Segment containing JPEG meta-data
# Start Of Scan segment contains the image compressed data

Segment_dict = {
    
    # reserved markers
    0x01 : 'Temporary private use in arithmetic coding',
    
    # non-differential Huffman coding
    0xC0 : 'Start Of Frame (Baseline DCT)',
    0xC1 : 'Start Of Frame (Extended Sequential DCT)',
    0xC2 : 'Start Of Frame (Progressive DCT)',
    0xC3 : 'Start Of Frame (Lossless Sequential)',
    
    # differential Huffman coding
    0xC5 : 'Start Of Frame (Differential Sequential DCT)',
    0xC6 : 'Start Of Frame (Differential Progressive DCT)',
    0xC7 : 'Start Of Frame (Differential Lossless Sequential)',
    
    # non-differential arithmetic coding
    0xC8 : 'Start Of Frame (Reserved for JPEG extensions)',
    0xC9 : 'Start Of Frame (Extended Sequential DCT)',
    0xCA : 'Start Of Frame (Progressive DCT)',
    0xCB : 'Start Of Frame (Lossless Sequential)',
    
    # differential arithmetic coding
    0xCD : 'Start Of Frame (Differential Sequential DCT)',
    0xCE : 'Start Of Frame (Differential Progressive DCT)',
    0xCF : 'Start Of Frame (Differential Lossless Sequential)',
    
    # huffman table spec
    0xC4 : 'Define Huffman Table(s)',
    # arithmetic coding conditioning spec
    0xCC : 'Define Arithmetic Coding Conditioning(s)',
    
    # restart interval termination
    0xD0 : 'RST0',
    0xD1 : 'RST1',
    0xD2 : 'RST2',
    0xD3 : 'RST3',
    0xD4 : 'RST4',
    0xD5 : 'RST5',
    0xD6 : 'RST6',
    0xD7 : 'RST7',
    
    # other markers
    0xD8 : 'Start Of Image',
    0xD9 : 'End Of Image',
    0xDA : 'Start Of Scan',
    0xDB : 'Define Quantization Table(s)',
    0xDD : 'Define Restart Interval',
    0xDE : 'Define Hierarchichal Progression',
    0xDF : 'Expand Reference Component(s)',
    
    # reserved for application segments
    0xE0 : 'APP0',
    0xE1 : 'APP1',
    0xE2 : 'APP2',
    0xE3 : 'APP3',
    0xE4 : 'APP4',
    0xE5 : 'APP5',
    0xE6 : 'APP6',
    0xE7 : 'APP7',
    0xE8 : 'APP8',
    0xE9 : 'APP9',
    0xEA : 'APPA',
    0xEB : 'APPB',
    0xEC : 'APPC',
    0xED : 'APPD',
    0xEE : 'APPE',
    0xEF : 'APPF',
    
    # reserved for JPEG extensions
    0xF0 : 'JPG0',
    0xF1 : 'JPG1',
    0xF2 : 'JPG2',
    0xF3 : 'JPG3',
    0xF4 : 'JPG4',
    0xF5 : 'JPG5',
    0xF6 : 'JPG6',
    0xF7 : 'JPG7',
    0xF8 : 'JPG8',
    0xF9 : 'JPG9',
    0xFA : 'JPGA',
    0xFB : 'JPGB',
    0xFC : 'JPGC',
    0xFD : 'JPGD',
    
    # comment
    0xFE : 'Comment',
    }

class Segment(Envelope):
    _GEN = (
        Uint8('mark', val=0xFF, rep=REPR_HEX),
        Uint8('type', val=0xFE, dic=Segment_dict),
        Uint16('len'),
        Buf('pay'),
        )
    
    # these are segment types without length / payload
    _no_pay = (0xD8, 0xD9)
    
    # these are the segments for which there is a detailed structure
    _det_struct = {
        # Start Of Frame
        0xC0 : SOF, 
        0xC1 : SOF, 
        0xC2 : SOF, 
        0xC3 : SOF,
        0xC5 : SOF, 
        0xC6 : SOF, 
        0xC7 : SOF,
        0xC8 : SOF, 
        0xC9 : SOF, 
        0xCA : SOF, 
        0xCB : SOF, 
        0xCD : SOF, 
        0xCE : SOF, 
        0xCF : SOF,
        # Start Of Scan
        0xDA : SOS,
        # Tables
        0xDB : DQT,
        0xC4 : DHT,
        0xCC : DAC
        }
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_transauto(self._has_no_pay)
        self[2].set_valauto(self._set_len)
        self[3].set_transauto(self._has_no_pay)
        self[3].set_blauto(self._get_len)
    
    def _has_no_pay(self):
        if self[1].get_val() in self._no_pay:
            return True
        else:
            return False
    
    def _set_len(self):
        return 2 + self[3].get_len()
    
    def _get_len(self):
        return 8 * (self[2].get_val()-2)
    
    def _from_char(self, char):
        Envelope._from_char(self, char)
        t = self[1].get_val()
        p = self[3].get_val()
        if t in self._det_struct:
            # detailed structure available
            ds = self._det_struct[t]()
            ds.from_bytes(p)
            if ds.get_len() == len(p):
                self.replace(self[3], ds)
        if t == 0xDA:
            # start of scan: compressed data is following
            buf = char.to_bytes()
            mark = self._scan_marker(buf)
            if mark > 0:
                self.append( Buf('Data', val=buf[:mark], rep=REPR_HD) )
                buf = buf[mark:]
                char.forward(8*mark)
    
    def _scan_marker(self, buf):
        off = 0
        while True:
            mark = buf[off:].find(b'\xFF')
            if mark >= 0 and buf[off+mark+1:off+mark+2] != b'\x00':
                # found a real marker
                return off+mark
            elif mark == -1:
                # no marker found
                return -1
            else:
                # escaped marker found, continue scanning
                off += 2+mark

# JPEG structure
class JPEG(Sequence):
    _GEN = Segment()

