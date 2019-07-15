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
# * File Name : pycrate_media/MP3.py
# * Created : 2016-04-15
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/ 

from functools import reduce

from pycrate_core.elt    import *
from pycrate_core.base   import *
from pycrate_core.charpy import *
from pycrate_core.utils  import decompose_uint, TYPE_UINT
from pycrate_core.repr   import *

#Element.ENV_SEL_TRANS = False
Buf.REPR_MAXLEN = 512


# MPEG1/2/2.5, Layer I/II/II, frame format
# made from http://mpgedit.org/mpgedit/mpeg_format/mpeghdr.htm

MPEGVersion_dict = {
    0 : 'MPEG version 2.5',
    1 : 'reserved',
    2 : 'MPEG version 2',
    3 : 'MPEG version 1',
    }

MPEGLayer_dict = {
    0 : 'reserved',
    1 : 'Layer III',
    2 : 'Layer II',
    3 : 'Layer I',
    }

BitrateV1L1_dict = {
    0: 'free', 1: '32',   2: '64',   3: '96', 
    4: '128',  5: '160',  6: '192',  7: '224',
    8: '256',  9: '288',  10: '320', 11: '352',
    12: '384', 13: '416', 14: '448', 15: 'bad'
    }
BitrateV1L2_dict = {
    0: 'free', 1: '32',   2: '48',   3: '56', 
    4: '64',   5: '80',   6: '96',   7: '112',
    8: '128',  9: '160',  10: '192', 11: '224',
    12: '256', 13: '320', 14: '384', 15: 'bad'
    }
BitrateV1L3_dict = {
    0: 'free', 1: '32',   2: '40',   3: '48', 
    4: '56',   5: '64',   6: '80',   7: '96',
    8: '112',  9: '128',  10: '160', 11: '192',
    12: '224', 13: '256', 14: '320', 15: 'bad'
    }
BitrateV2L1_dict = {
    0: 'free', 1: '32',   2: '48',   3: '56', 
    4: '64',   5: '80',   6: '96',   7: '112',
    8: '128',  9: '144',  10: '160', 11: '176',
    12: '192', 13: '224', 14: '256', 15: 'bad'
    }
BitrateV2L2L3_dict = {
    0: 'free', 1: '8',   2: '16',   3: '24', 
    4: '32',   5: '40',  6: '48',   7: '56',
    8: '64',   9: '80',  10: '96', 11: '112',
    12: '128', 13: '144', 14: '160', 15: 'bad'
    }

SampRateV1_dict = {
    0: '44100', 1: '48000', 2: '32000', 3: 'reserved'}
SampRateV2_dict = {
    0: '22050', 1: '24000', 2: '16000', 3: 'reserved'}
SampRateV25_dict = {
    0: '11025', 1: '12000', 2: '8000', 3: 'reserved'}

ChanMode_dict = {
    0 : 'Stereo',
    1 : 'Joint stereo',
    2 : 'Dual channel',
    3 : 'Single channel'
    }

Emphasis_dict = {
    0 : 'None',
    1 : '50/15 ms',
    2 : 'reserved',
    3 : 'CCIT J.17' 
}

class Header(Envelope):
    _GEN = (
        Uint('FrameSync', val=2047, bl=11, rep=REPR_HEX),
        Uint('Version', bl=2, dic=MPEGVersion_dict),
        Uint('Layer', bl=2, dic=MPEGLayer_dict),
        Uint('CRCBit', bl=1),
        Uint('Bitrate', bl=4),
        Uint('SamplingRate', bl=2),
        Uint('PaddingBit', bl=1),
        Uint('PrivateBit', bl=1),
        Uint('ChannelMode', bl=2, dic=ChanMode_dict),
        Uint('ModeExtension', bl=2),
        Uint('Copyright', bl=1),
        Uint('Original', bl=1),
        Uint('Emphasis', bl=2, dic=Emphasis_dict)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[4].set_dicauto(self._set_Bitrate_dic)
        self[5].set_dicauto(self._set_SampRate_dic)
    
    def _set_Bitrate_dic(self):
        V, L = self[1].get_val(), self[2].get_val()
        if V == 3:
            # version 1
            if L == 3:
                return BitrateV1L1_dict
            elif L == 2:
                return BitrateV1L2_dict
            elif L == 1:
                return BitrateV1L3_dict
        elif V in (0, 2):
            # version 2
            if L == 3:
                return BitrateV2L1_dict
            elif L in (1, 2):
                return BitrateV2L2L3_dict
        return {}
    
    def _set_SampRate_dic(self):
        V = self[1].get_val()
        if V == 3:
            return SampRateV1_dict
        elif V == 2:
            return SampRateV2_dict
        elif V == 0:
            return SampRateV25_dict
        return {}


# Samples (compressed) per frame, depending of version and layer
FrameSamp_dict = {
    0 : {0: 0, 1: 576, 2: 1152, 3: 384}, # version 2.5, layer r,3,2,1
    1 : {0: 0, 0: 0, 0: 0, 0: 0}, # version r
    2 : {0: 0, 1: 576, 2: 1152, 3: 384}, # version 2, layer r,3,2,1
    3 : {0: 0, 1: 1152, 2: 1152, 3: 384} # version 1, layer r,3,2,1
    }

# Slot size
SlotSize_dict = {
    0: 0, 1: 1, 2: 1, 3: 4
    }


class MPEGFrame(Envelope):
    _GEN = (
        Header(),
        Buf('Data', hier=1, rep=REPR_HD)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_blauto(self._set_Data_bl)
    
    def _set_Data_bl(self):
        V, L = self[0][1].get_val(), self[0][2].get_val()
        br, br_dic = self[0][4].get_val(), self[0][4].get_dic()
        try:
            br = 1000 * int(br_dic[br])
        except:
            raise(Exception('MP3: invalid bitrate, {0}'.format(br)))
        sr, sr_dic = self[0][5].get_val(), self[0][5].get_dic()
        try:
            sr = int(sr_dic[sr])
        except:
            raise(Exception('MP3: invalid samplerate, {0}'.format(sr)))
        samples = FrameSamp_dict[V][L]
        slotsz = SlotSize_dict[L]
        bps = samples / 8.0
        #
        flen = ((bps * br) / sr)
        if self[0][6].get_val():
            flen += SlotSize_dict[L]
        #
        return (8*int(flen)) - 32


#class Stream(Array):
class MPEGStream(Sequence):
    _GEN = MPEGFrame()


# ID3V1 MP3 metadata
# made from http://mpgedit.org/mpgedit/mpeg_format/mpeghdr.htm

class ID3V1(Envelope):
    _GEN = (
        Buf('TAG', val=b'TAG', bl=24),
        Buf('Title', bl=240),
        Buf('Artist', bl=240),
        Buf('Album', bl=240),
        Buf('Year', bl=32),
        Buf('Comment', bl=240),
        Buf('Genre', bl=8)
        )


class ID3V1Ext(Envelope):
    _GEN = (
        Buf('TAG+', val=b'TAG+', bl=32),
        Buf('Title', bl=480),
        Buf('Artist', bl=480),
        Buf('Album', bl=480),
        Buf('Speed', bl=8),
        Buf('Genre', bl=240),
        Buf('StartTime', bl=48),
        Buf('EndTime', bl=48)
        )


# ID3V2 MP3 metadata
# made from http://id3.org/id3v2.4.0-structure

class Uint32SynchSafe(Uint32):
    
    #--------------------------------------------------------------------------#
    # format routines
    #--------------------------------------------------------------------------#
    
    def _val_chk(self, val):
        if not isinstance(val, self.TYPES):
            raise(EltErr('{0} [_val_chk]: val type is {1}, expecting {2}'\
                            .format(self._name,
                                    type(val).__name__,
                                    self.TYPENAMES)))
        elif val < 0:
            # only 28 bits of dynamic
            raise(EltErr('{0} [_val_chk]: val underflow'.format(self._name)))
        elif self._bl is not None and val > (2**28)-1:
            raise(EltErr('{0} [_val_chk]: val overflow'.format(self._name)))
    
    #--------------------------------------------------------------------------#
    # conversion routines
    #--------------------------------------------------------------------------#
    
    def _to_pack(self):
        '''Produces a tuple ready to be packed with pack_val() according to its
        internal value
        '''
        if not self.get_trans():
            # expand uint28 value to uint32 format
            dec = decompose_uint(1<<7, self.get_val())
            if len(dec) < 4:
                dec.extend( [0]*(4-len(dec)) )
            exp = reduce(lambda x,y: (x<<8)+y, reversed(dec))
            return [(TYPE_UINT, exp, self.get_bl())]
        else:
            return []
    
    def _from_char(self, char):
        '''Consume the charpy intance and set its internal value according to
        it
        '''
        if not self.get_trans():
            try:
                exp = char.get_uint(32)
            except CharpyErr as err:
                raise(CharpyErr('{0} [_from_char]: {1}'.format(self._name, err)))
            else:
                # get uint32 value, zero all 8'th bit of each byte
                # and pack it to an uint28 value
                dec = decompose_uint(1<<8, exp)
                if len(dec) < 4:
                    dec.extend( [0]*(4-len(dec)) )
                val = reduce(lambda x,y: ((x&0x7f)<<7)+(y&0x7f), reversed(dec))
                try:
                    self.set_val(val)
                except Exception as err:
                    raise(EltErr('{0} [_from_char]: {1}'\
                                 .format(self._name, err)))


class ID3V2Header(Envelope):
    _GEN = (
        Buf('ID3', val=b'ID3', bl=24),
        Buf('Version', val=b'\x04\0', bl=16, rep=REPR_HEX),
        Uint('Unsynchronisation', bl=1),
        Uint('ExtendedHeader', bl=1),
        Uint('ExperimentalIndicator', bl=1),
        Uint('Footer', bl=1),
        Uint('Undefined', bl=4),
        Uint32SynchSafe('Size')
        )


class ID3V2Footer(Envelope):
    _GEN = (
        Buf('Identifier', val=b'3DI', bl=24),
        Buf('Version', val=b'\x04\0', bl=16, rep=REPR_HEX),
        Uint('Unsynchronisation', bl=1),
        Uint('ExtendedHeader', bl=1),
        Uint('ExperimentalIndicator', bl=1),
        Uint('Footer', bl=1),
        Uint('Undefined', bl=4),
        Uint32SynchSafe('Size')
        )


class ID3V2HeaderExtension(Envelope):
    _GEN = (
        Uint32SynchSafe('Size', bl=32),
        Uint8('NumFlagBytes', bl=8),
        Buf('Flags', val=b'\0', rep=REPR_BIN)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(self._set_Size_val)
        self[1].set_valauto(self[2].get_len)
        self[2].set_blauto(self._set_Flags_bl)
    
    def _set_Size_val(self):
        return 5 + self[1].get_val()
    
    def _set_Flags_bl(self):
        return 8 * self[1].get_val()


class ID3V2Frame(Envelope):
    _GEN = (
        Buf('FrameID', bl=32),
        Uint32SynchSafe('Size'),
        Buf('Flags', bl=16, rep=REPR_BIN),
        Buf('Data', rep=REPR_HD)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(self[3].get_len)
        self[3].set_blauto(self._set_Data_bl)
    
    def _set_Data_bl(self):
        return 8*self[1].get_val()


class ID3V2Frames(Array):
    _GEN = ID3V2Frame()
    
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
        # 3) consume char and fill in self._val, stops when padding starts
        if num is not None:
            try:
                [self._val.append(self._tmpl.get_val()) for i in range(num) \
                 if self._tmpl._from_char(char) is None]
            except CharpyErr as err:
                raise(CharpyErr('{0} [_from_char]: {1}'.format(self._name, err)))
            except Exception as err:
                raise(EltErr('{0} [_from_char]: {1}'.format(self._name, err)))
            self._tmpl.set_val(None)
        else:
            # parse the char buffer until we encounter an ID3V2Frame 
            # with a null FrameID
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
                    if self._tmpl[0].get_val() == b'\0\0\0\0':
                        char._cur = cur
                        break 
                    self._val.append(self._tmpl.get_val())
            self._tmpl.set_val(None)


class ID3V2(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        ID3V2Header(),
        ID3V2HeaderExtension(hier=1),
        ID3V2Frames(hier=1),
        Buf('ID3V2Padding', hier=1, rep=REPR_HD),
        ID3V2Footer()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0][7].set_valauto(self._set_Size_val)
        self[1].set_transauto(self._set_HExt_trans)
        self[3].set_blauto(self._set_Pad_bl)
        self[4].set_transauto(self._set_Foot_trans)
        self[4][7].set_valauto(self._set_Size_val)
    
    def _set_Size_val(self):
        return self[1].get_len() + self[2].get_len() + self[3].get_len()
    
    def _set_HExt_trans(self):
        return (True, False)[self[0][3].get_val()]
    
    def _set_Pad_bl(self):
        return 8*(self[0][7].get_val() - self[1].get_len() - self[2].get_len())
    
    def _set_Foot_trans(self):
        return (True, False)[self[0][5].get_val()]
    
    def _from_char(self, char):
        self[0]._from_char(char)
        size = self[0][7].get_val()
        char_id3v2 = Charpy(char.get_bytes(8*size))
        self[1:4]._from_char(char_id3v2)
        self[4]._from_char(char)


# MP3 file format, including metadata
class MP3(Envelope):
    _GEN = ()
    
    def _from_char(self, char):
        while True:
            # consume charpy frame by frame
            try:
                sig = char.to_uint(32)
            except CharpyErr:
                break
            else:
                if sig >> 21 == 0x7ff:
                    # MPEG frame
                    f = MPEGFrame()
                elif sig == 0x54414743:
                    # ID3V1 extended frame
                    f = ID3V1Ext()
                elif sig >> 8 == 0x544147:
                    # ID3V1 frame
                    f = ID3V1()
                elif sig >> 8 == 0x494433:
                    # ID3V2 frame
                    f = ID3V2()
                else:
                    raise(Exception('MP3: unknown frame delimiter, {0:x}'\
                                    .format(sig)))
                f._from_char(char)
                self.append(f)
    
