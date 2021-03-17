# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
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
# * File Name : pycrate_mobile/TS24008_IE.py
# * Created : 2017-06-12
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# 3GPP TS 24.008: Mobile radio interface layer 3 specification
# release 13 (d90)
#------------------------------------------------------------------------------#

from binascii import hexlify, unhexlify
from time     import struct_time

from pycrate_core.utils  import *
from pycrate_core.elt    import (
    Envelope, Array, Sequence, Alt,
    REPR_RAW, REPR_HEX, REPR_BIN, REPR_HD, REPR_HUM
    )
from pycrate_core.base   import *
from pycrate_core.repr   import *
from pycrate_core.charpy import Charpy

from .MCC_MNC import MNC_dict
from .PPP     import LCP, LCPDataConf, NCP, NCPDataConf, PAP, CHAP
from .TS23038 import *
from .TS24007 import ProtDisc_dict

#------------------------------------------------------------------------------#
# TS 24.008 IE specified with CSN.1
#------------------------------------------------------------------------------#

from pycrate_csn1dir.classmark_3_value_part           import classmark_3_value_part
from pycrate_csn1dir.ms_network_capability_value_part import ms_network_capability_value_part
from pycrate_csn1dir.ms_ra_capability_value_part      import ms_ra_capability_value_part
from pycrate_csn1dir.receive_npdu_number_list_value   import receive_npdu_number_list_value

#------------------------------------------------------------------------------#
# str shortcuts
#------------------------------------------------------------------------------#

_str_reserved = 'reserved'

#------------------------------------------------------------------------------#
# std encoding / decoding routines
#------------------------------------------------------------------------------#

def encode_bcd(dig):
    if len(dig) % 2:
        dig += 'F'
    dig = list(dig)
    dig[1::2], dig[::2] = dig[::2], dig[1::2]
    return unhexlify(''.join(dig))


def decode_bcd(buf):
    if python_version < 3:
        buf = [ord(c) for c in buf]
    ret = []
    for o in buf:
        msb, lsb = o>>4, o&0xf
        if lsb > 9:
            break
        else:
            ret.append( str(lsb) )
        if msb > 9:
            break
        else:
            ret.append( str(msb) )
    return ''.join(ret)


#------------------------------------------------------------------------------#
# TS 24.008 IE common objects
#------------------------------------------------------------------------------#

# BCD string is a string of digits, each digit being coded on a nibble (4 bits)
# Here, BufBCD is a subclass of pycrate_core.base.Buf
# with additionnal methods: encode(), decode()

class BufBCD(Buf):
    """Subclass of pycrate_core.base.Buf object
    with additional encode() and decode() capabilities in order to handle
    BCD encoding
    """
    
    _rep = REPR_HUM
    _dic = None     # dict lookup not supported for repr()
    
    # characters accepted in a BCD number
    _chars  = ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '*', '#', 'a', 'b', 'c')
    # filler character for odd length number encoding
    _filler = 0xF
    
    def __init__(self, *args, **kw):
        # element name in kw, or first args
        if len(args):
            self._name = str(args[0])
        elif 'name' in kw:
            self._name = str(kw['name'])
        # if not provided, it's the class name
        else:
            self._name = self.__class__.__name__
        # element description customization
        if 'desc' in kw:
            self._desc = str(kw['desc'])
        # element representation customization
        if 'rep' in kw and kw['rep'] in self.REPR_TYPES:
            self._rep = kw['rep']
        # element hierarchy
        if 'hier' in kw:
            self._hier = kw['hier']
        # element bit length
        if 'bl' in kw:
            self._bl = kw['bl']
        # element value
        if 'val' in kw:
            self.set_val(kw['val'])
        # element transparency
        if 'trans' in kw:
            self._trans = kw['trans']
        if self._SAFE_STAT:
            self._chk_hier()
            self._chk_bl()
            self._chk_val()
            self._chk_trans()
    
    def set_val(self, val):
        if isinstance(val, Buf.TYPES + (NoneType, )):
            Buf.set_val(self, val)
        elif isinstance(val, str_types):
            self.encode(val)
    
    def decode(self):
        """returns the encoded string of digits
        """
        if python_version < 3:
            num = [ord(c) for c in self.get_val()]
        else:
            num = self.get_val()
        ret = []
        for o in num:
            msb, lsb = o>>4, o&0xf
            if lsb == 0xF:
                break
            else:
                ret.append( self._chars[lsb] )
            if msb == 0xF:
                break
            else:
                ret.append( self._chars[msb] )
        return ''.join(ret)
    
    def encode(self, bcd='12345678'):
        """encode the given BCD string and store the resulting buffer in 
        self._val
        """
        # encode the chars
        try:
            ret = [self._chars.index(c) for c in bcd]
        except Exception:
            raise(PycrateErr('{0}: invalid character in BCD string to encode, {1!r}'\
                  .format(self._name, bcd)))
        if len(ret) % 2:
            ret.append( self._filler )
        #
        if python_version < 3:
            self._val = ''.join([chr(c) for c in map(lambda x,y:x+(y<<4), ret[::2], ret[1::2])])
        else:
            self._val = bytes(map(lambda x,y:x+(y<<4), ret[::2], ret[1::2]))
    
    def repr(self):
        # special hexdump representation
        if self._rep == REPR_HD:
            return '\n'.join(self._repr_hd())
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        # type of representation to be used
        if self._rep == REPR_HUM:
            val_repr = self.decode()
        elif self._rep == REPR_RAW:
            val_repr = repr(self.get_val())
        elif self._rep == REPR_BIN:
            val_repr = '0b' + self.bin()
        elif self._rep == REPR_HEX:
            val_repr = '0x' + self.hex()
        if self.REPR_MAXLEN > 0 and len(val_repr) > self.REPR_MAXLEN:
            val_repr = val_repr[:self.REPR_MAXLEN] + '...'
        return '<%s%s%s : %s>' % (self._name, desc, trans, val_repr)
    
    __repr__ = repr


# PLMN is a string of digits, each digit being coded on a nibble (4 bits)
# Here, PLMN is a subclass of pycrate_core.base.Buf
# with additionnal methods: encode(), decode()

class PLMN(Buf):
    """Child of pycrate_core.base.Buf object
    with additional encode() and decode() capabilities in order to handle
    PLMN encoding
    """
    
    _bl  = 24 # 3 bytes
    _rep = REPR_HUM
    _dic = MNC_dict
    
    # default to PLMN 001.01
    DEFAULT_VAL = b'\x00\xf1\x10'
    
    def __init__(self, *args, **kw):
        # element name in kw, or first args
        if len(args):
            self._name = str(args[0])
        elif 'name' in kw:
            self._name = str(kw['name'])
        # if not provided, it's the class name
        else:
            self._name = self.__class__.__name__
        # element description customization
        if 'desc' in kw:
            self._desc = str(kw['desc'])
        # element representation customization
        if 'rep' in kw and kw['rep'] in self.REPR_TYPES:
            self._rep = kw['rep']
        # element hierarchy
        if 'hier' in kw:
            self._hier = kw['hier']
        # element bit length
        if 'bl' in kw:
            self._bl = kw['bl']
        # element value
        if 'val' in kw:
            self.set_val( kw['val'] )
        # element transparency
        if 'trans' in kw:
            self._trans = kw['trans']
        if self._SAFE_STAT:
            self._chk_hier()
            self._chk_bl()
            self._chk_val()
            self._chk_trans()
    
    def set_val(self, val):
        if isinstance(val, Buf.TYPES + (NoneType, )):
            Buf.set_val(self, val)
        elif isinstance(val, str_types):
            self.encode(val)
    
    def decode(self):
        """returns the encoded string of digits
        """
        plmn = []
        if python_version < 3:
            for c in self.get_val():
                b = ord(c)
                plmn.append(b>>4)
                plmn.append(b&0xf)
            try:
                if plmn[2] == 0xf:
                    return u'%i%i%i%i%i' % (plmn[1], plmn[0], plmn[3], plmn[5], plmn[4])
                else:
                    return u'%i%i%i%i%i%i' % (plmn[1], plmn[0], plmn[3], plmn[5], plmn[4], plmn[2])
            except IndexError:
                # an invalid value has been set, _SAFE_STAT / DYN is probably disabled
                # for e.g. fuzzing purpose, but there is still need to not break here
                return '0x%s' % hexlify(self.to_bytes()).decode('ascii')
        else:
            for b in self.get_val():
                plmn.append(b>>4)
                plmn.append(b&0xf)
            try:
                if plmn[2] == 0xf:
                    return '%i%i%i%i%i' % (plmn[1], plmn[0], plmn[3], plmn[5], plmn[4])
                else:
                    return '%i%i%i%i%i%i' % (plmn[1], plmn[0], plmn[3], plmn[5], plmn[4], plmn[2])
            except IndexError:
                # an invalid value has been set, _SAFE_STAT / DYN is probably disabled
                # for e.g. fuzzing purpose, but there is still need to not break here
                return '0x%s' % hexlify(self.to_bytes()).decode('ascii')
    
    def encode(self, plmn=u'00101'):
        """encode the given PLMN string and store the resulting buffer in 
        self._val
        """
        if not plmn.isdigit():
            raise(PycrateErr('{0}: invalid PLMN string to encode, {1!r}'\
                  .format(self._name, plmn)))
        if len(plmn) == 5:
            plmn += 'F'
        elif len(plmn) != 6:
            raise(PycrateErr('{0}: invalid PLMN string to encode, {1!r}'\
                  .format(self._name, plmn)))
        # no need to distinguish Python version as join() and unhexlify() seems to
        # do a good job here in both cases
        self._val = unhexlify(''.join((plmn[1], plmn[0], plmn[5], plmn[2], plmn[4], plmn[3])))
    
    def repr(self):
        # special hexdump representation
        if self._rep == REPR_HD:
            return '\n'.join(self._repr_hd())
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        # type of representation to be used
        if self._rep == REPR_HUM:
            val_repr = self.decode()
            if self._dic and val_repr in self._dic:
                mccmnc = self._dic[val_repr]
                val_repr += ' (%s.%s)' % (mccmnc[2], mccmnc[3])
        elif self._rep == REPR_RAW:
            val_repr = repr(self.get_val())
        elif self._rep == REPR_BIN:
            val_repr = '0b' + self.bin()
        elif self._rep == REPR_HEX:
            val_repr = '0x' + self.hex()
        if self.REPR_MAXLEN > 0 and len(val_repr) > self.REPR_MAXLEN:
            val_repr = val_repr[:self.REPR_MAXLEN] + '...'
        return '<%s%s%s : %s>' % (self._name, desc, trans, val_repr)
    
    __repr__ = repr


#------------------------------------------------------------------------------#
# Cell Identity
# TS 24.008, 10.5.1.1
#------------------------------------------------------------------------------#

class CellId(Uint16):
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# CKSN
# TS 24.008, 10.5.1.2
#------------------------------------------------------------------------------#

CKSN_dict = {
    7:'No key is available (from MS) / reserved (from network)'
    }


#------------------------------------------------------------------------------#
# Local Area Identifier
# TS 24.008, 10.5.1.3
#------------------------------------------------------------------------------#

class LAI(Envelope):
    _GEN = (
        PLMN(),
        Uint16('LAC', rep=REPR_HEX)
        )
    
    encode = Envelope.set_val
    
    def decode(self):
        return (self[0].decode(), self[1].get_val())


#------------------------------------------------------------------------------#
# Mobile Identity
# TS 24.008, 10.5.1.4
#------------------------------------------------------------------------------#

IDType_dict = {
    0 : 'No Identity',
    1 : 'IMSI',
    2 : 'IMEI',
    3 : 'IMEISV',
    4 : 'TMSI',
    5 : 'TMGI',
    6 : 'ffu'
    }
IDTYPE_NONE   = 0
IDTYPE_IMSI   = 1
IDTYPE_IMEI   = 2
IDTYPE_IMEISV = 3
IDTYPE_TMSI   = 4
IDTYPE_TMGI   = 5

class IDNone(Envelope):
    _GEN = (
        Uint('spare', bl=5, rep=REPR_HEX),
        Uint('Type', bl=3, dic=IDType_dict)
        )

class IDTemp(Envelope):
    _GEN = (
        Uint('Digit1', val=0xF, bl=4, rep=REPR_HEX),
        Uint('Odd', bl=1),
        Uint('Type', val=IDTYPE_TMSI, bl=3, dic=IDType_dict),
        Uint32('TMSI', rep=REPR_HEX)
        )

class IDDigit(Envelope):
    _GEN = (
        Uint('Digit1', val=0xF, bl=4, rep=REPR_HEX),
        Uint('Odd', bl=1),
        Uint('Type', val=IDTYPE_IMSI, bl=3, dic=IDType_dict),
        Buf('Digits', val=b'', rep=REPR_HEX)
        )

class IDGroup(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('spare', bl=2),
        Uint('MBMSSessInd', bl=1),
        Uint('MCCMNCInd', bl=1),
        Uint('Odd', bl=1),
        Uint('Type', val=IDTYPE_TMGI, dic=IDType_dict),
        Uint24('MBMSServID', rep=REPR_HEX),
        PLMN(),
        Uint8('MBMSSessID')
        )
    
    def __init__(self, *args, **kw):
        Envelope.__init__(self, *args, **kw)
        self[6].set_transauto(lambda: False if self[2].get_val() else True)
        self[7].set_transauto(lambda: False if self[1].get_val() else True)

class ID(Envelope):
    
    # during encode() / _from_char() processing
    # specific attributes are created:
    # self._IDNone  = IDNone()
    # self._IDTemp  = IDTemp()
    # self._IDDigit = IDDigit()
    # self._IDGroup = IDGroup()
    
    def set_val(self, vals):
        if isinstance(vals, dict) and 'type' in vals and 'ident' in vals:
            self.encode(vals['type'], vals['ident'])
        else:
            Envelope.set_val(self, vals)
    
    def decode(self):
        """returns the mobile identity type and value
        """
        type = self['Type'].get_val()
        if type == IDTYPE_NONE:
            return (type, None)
        #
        elif type == IDTYPE_TMSI:
            return (type, self[3].get_val())
        #
        elif type in (IDTYPE_IMSI, IDTYPE_IMEI, IDTYPE_IMEISV):
            return (type, str(self[0].get_val()) + decode_bcd(self[3].get_val()))
        #
        elif type == IDTYPE_TMGI:
            if self[1].get_val():
                # MBMSSessID
                mid = self[7].get_val()
            else:
                mid = None
            if self[2].get_val():
                # MCCMNC
                plmn = self[6].decode()
            else:
                plmn = None
            return (type, (self[5].get_val(), plmn, mid))
    
    def encode(self, type=IDTYPE_NONE, ident=None):
        """sets the mobile identity with given type
        
        if type is IDTYPE_TMSI: ident must be an uint32
        if type is IDTYPE_IMSI, IDTYPE_IMEI or IDTYPE_IMEISV: ident must be a 
            string of digits
        if type is IDTYPE_TMGI: ident must be a 3-tuple (MBMSServID -uint24-, 
            PLMN -string of digits- or None, MBMSSessID -uint8- or None)
        """
        if type == IDTYPE_NONE:
            if not hasattr(self, '_IDNone'):
                self._IDNone = IDNone()
            self._content = self._IDNone._content
            self._by_id   = self._IDNone._by_id
            self._by_name = self._IDNone._by_name
        #
        elif type == IDTYPE_TMSI:
            if not hasattr(self, '_IDTemp'):
                self._IDTemp = IDTemp()
            self._content = self._IDTemp._content
            self._by_id   = self._IDTemp._by_id
            self._by_name = self._IDTemp._by_name
            self[3].set_val(ident)
        #
        elif type in (IDTYPE_IMSI, IDTYPE_IMEI, IDTYPE_IMEISV):
            if not ident.isdigit():
                raise(PycrateErr('{0}: invalid identity to encode, {1!r}'\
                      .format(self._name, ident)))
            if not hasattr(self, '_IDDigit'):
                self._IDDigit = IDDigit()
            self._content = self._IDDigit._content
            self._by_id   = self._IDDigit._by_id
            self._by_name = self._IDDigit._by_name
            self[2]._val = type
            if len(ident) % 2:
                self[1]._val = 1
            # encode digits the BCD way
            self[0]._val = int(ident[0])
            self[3]._val = encode_bcd(ident[1:])
        #
        elif type == IDTYPE_TMGI:
            if not isinstance(ident, (tuple, list)) or len(ident) != 3:
                raise(PycrateErr('{0}: invalid identity to encode, {1!r}'\
                      .format(self._name, ident)))
            if not hasattr(self, '_IDGroup'):
                self._IDGroup = IDGroup()
            self._content = self._IDGroup._content
            self._by_id   = self._IDGroup._by_id
            self._by_name = self._IDGroup._by_name
            self[5].set_val( ident[0] )
            if ident[1] is not None:
                # MCCMNC
                self[2]._val = 1
                self[6].encode( ident[1] )
            if ident[2] is not None:
                # MBMSSessID
                self[1]._val = 1
                self[7].set_val( ident[2] )
    
    def _from_char(self, char):
        if not self.get_trans():
            try:
                spare = char.get_uint(5)
                type  = char.get_uint(3)
            except CharpyErr as err:
                raise(CharpyErr('{0} [_from_char]: {1}'.format(self._name, err)))
            except Exception as err:
                raise(EltErr('{0} [_from_char]: {1}'.format(self._name, err)))
            #
            if type == IDTYPE_TMSI:
                if not hasattr(self, '_IDTemp'):
                    self._IDTemp = IDTemp()
                self._content = self._IDTemp._content
                self._by_id   = self._IDTemp._by_id
                self._by_name = self._IDTemp._by_name
                self[0]._val = spare >> 1
                self[1]._val = spare & 1
                self[3]._from_char(char)
            #
            elif type in (IDTYPE_IMSI, IDTYPE_IMEI, IDTYPE_IMEISV):
                if not hasattr(self, '_IDDigit'):
                    self._IDDigit = IDDigit()
                self._content = self._IDDigit._content
                self._by_id   = self._IDDigit._by_id
                self._by_name = self._IDDigit._by_name
                self[0]._val = spare >> 1
                self[1]._val = spare & 1
                self[2]._val = type
                self[3]._from_char(char)   
            #
            elif type == IDTYPE_TMGI:
                if not hasattr(self, '_IDGroup'):
                    self._IDGroup = IDGroup()
                self._content = self._IDGroup._content
                self._by_id   = self._IDGroup._by_id
                self._by_name = self._IDGroup._by_name
                self[0]._val = spare >> 3
                self[1]._val = (spare >> 2) & 1
                self[2]._val = (spare >> 1) & 1
                self[3]._val = spare & 1
                self[5]._from_char(char)
                if self[2]._val:
                    self[6]._from_char(char)
                if self[1]._val:
                    self[7]._from_char(char)
            #
            elif type == IDTYPE_NONE:
                if not hasattr(self, '_IDNone'):
                    self._IDNone = IDNone()
                self._content = self._IDNone._content
                self._by_id   = self._IDNone._by_id
                self._by_name = self._IDNone._by_name
            #
            else:
                if not hasattr(self, '_IDNone'):
                    self._IDNone = IDNone()
                log('WNG: ID, type unhandled, %i' % type)
                self._content = self._IDNone._content
                self._by_id   = self._IDNone._by_id
                self._by_name = self._IDNone._by_name
    
    def repr(self):
        if not self._content:
            return Envelope.repr(self)
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        #
        type = self['Type'].get_val()
        #
        if type == IDTYPE_TMSI:
            if self[3]._rep in (REPR_RAW, REPR_HUM):
                t_repr = repr(self[3].get_val())
            elif self[3]._rep == REPR_HEX:
                t_repr = '0x' + self[3].hex()
            elif self[3].rep == REPR_BIN:
                t_repr = '0b' + self[3].bin()
            else:
                t_repr = ''
            return '<%s%s%s [TMSI] : %s>' % (self._name, desc, trans, t_repr)
        elif type in (IDTYPE_IMSI, IDTYPE_IMEI, IDTYPE_IMEISV):
            return '<%s%s%s [%s] : %s>' % (self._name, desc, trans, IDType_dict[type],
                                           str(self[0].get_val()) + decode_bcd(self[3].get_val()))  
        else:
            return Envelope.repr(self)
    
    __repr__ = repr


#------------------------------------------------------------------------------#
# Mobile Station Classmark 1
# TS 24.008, 10.5.1.5
#------------------------------------------------------------------------------#

_RevLevel_dict = {
    0:'Reserved for GSM phase 1',
    1:'GSM phase 2 MS',
    2:'MS supporting R99 or later',
    3:'FFU'
    }
_RFClass_dict = {
    0:'class 1',
    1:'class 2',
    2:'class 3',
    3:'class 4',
    4:'class 5'
    }

class MSCm1(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('RevLevel', val=2, bl=2, dic=_RevLevel_dict),
        Uint('EarlyCmCap', bl=1),
        Uint('NoA51', bl=1),
        Uint('RFClass', bl=3, dic=_RFClass_dict)
        )


#------------------------------------------------------------------------------#
# Mobile Station Classmark 2
# TS 24.008, 10.5.1.6
#------------------------------------------------------------------------------#

# SS screening indicator (TS 24.080, section 3.7.1)
_SSScreen_dict = {
    0:'default value of phase 1',
    1:'capability of handling of ellipsis notation and phase 2 error handling',
    2:'ffu',
    3:'ffu'
    }

class MSCm2(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('RevLevel', val=2, bl=2, dic=_RevLevel_dict),
        Uint('EarlyCmCap', bl=1),
        Uint('NoA51', bl=1),
        Uint('RFClass', bl=3, dic=_RFClass_dict),
        Uint('spare', bl=1),
        Uint('PSCap', bl=1),
        Uint('SSScreeningCap', bl=2, dic=_SSScreen_dict),
        Uint('MTSMSCap', bl=1),
        Uint('VBSNotifCap', bl=1),
        Uint('VGCSNotifCap', bl=1),
        Uint('FCFreqCap', bl=1),
        Uint('MSCm3Cap', bl=1),
        Uint('spare', bl=1),
        Uint('LCSVACap', bl=1),
        Uint('UCS2', bl=1),
        Uint('SoLSACap', bl=1),
        Uint('CMServPrompt', bl=1),
        Uint('A53', bl=1),
        Uint('A52', bl=1)
        )


#------------------------------------------------------------------------------#
# Descriptive group or broadcast call reference
# TS 24.008, 10.5.1.9
#------------------------------------------------------------------------------#

PriorityLevel_dict = {
    0 : 'no priority applied',
    1 : 'call priority level 4',
    2 : 'call priority level 3',
    3 : 'call priority level 2',
    4 : 'call priority level 1',
    5 : 'call priority level 0',
    6 : 'call priority level B',
    7 : 'call priority level A'
    }

class BroadcastCallRef(Envelope):
    _GEN = (
        Uint('Value', bl=27, rep=REPR_HEX),
        Uint('SF', bl=1, dic={0:'VBS, broadcast call', 1:'VGCS, group call'}),
        Uint('AF', bl=1, dic={0:'ACK not required', 1:'ACK required'}),
        Uint('CallPriority', bl=3, dic=PriorityLevel_dict),
        Uint('CipheringInfo', bl=4, dic={0:'no ciphering'}),
        Uint('spare', bl=4)
        )


#------------------------------------------------------------------------------#
# PD and SAPI $(CCBS)$
# TS 24.008, 10.5.1.10a
#------------------------------------------------------------------------------#

class PD_SAPI(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('SAPI', bl=2),
        Uint('PD', val=5, bl=4, dic=ProtDisc_dict)
        )


#------------------------------------------------------------------------------#
# Priority Level
# TS 24.008, 10.5.1.11
#------------------------------------------------------------------------------#

class PriorityLevel(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('CallPriority', bl=3, dic=PriorityLevel_dict)
        )


#------------------------------------------------------------------------------#
# PLMN list
# TS 24.008, 10.5.1.13
#------------------------------------------------------------------------------#

class PLMNList(Array):
    _GEN = PLMN()


#------------------------------------------------------------------------------#
# MS network feature support
# TS 24.008, 10.5.1.15
#------------------------------------------------------------------------------#

class MSNetFeatSupp(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('ExtPeriodTimers', bl=1)
        )


#------------------------------------------------------------------------------#
# Authentication Parameter AUTN (UMTS and EPS authentication challenge)
# TS 24.008, 10.5.3.1.1
#------------------------------------------------------------------------------#

class AUTN(Envelope):
    _GEN = (
        Buf('SQNxAK', bl=48, rep=REPR_HEX),
        Buf('AMF', bl=16, rep=REPR_HEX),
        Buf('MAC', bl=64, rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# CM Service type
# TS 24.008, 10.5.3.3
#------------------------------------------------------------------------------#

CMService_dict = {
    1:'Mobile originating call / packet mode connection',
    2:'Emergency call',
    4:'SMS',
    8:'Supplementary service',
    9:'Voice group call',
    10:'Voice broadcast call',
    11:'Location service'
    }


#------------------------------------------------------------------------------#
# Location Updating type
# TS 24.008, 10.5.3.5
#------------------------------------------------------------------------------#

_LocUpdType_dict = {
    0 : 'Normal location updating',
    1 : 'Periodic updating',
    2 : 'IMSI attach',
    3 : _str_reserved
    }

class LocUpdateType(Envelope):
    _GEN = (
        Uint('FollowOnReq', bl=1),
        Uint('spare', bl=1),
        Uint('Type', bl=2, dic=_LocUpdType_dict)
        )


#------------------------------------------------------------------------------#
# Network Name
# section 10.5.3.5a
#------------------------------------------------------------------------------#

_CodingScheme_dict = {
    0 : 'GSM 7 bit default alphabet',
    1 : 'UCS2 (16 bit)'
    }
CODTYPE_7B   = 0
CODTYPE_UCS2 = 1

class NetworkName(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Coding', val=CODTYPE_7B, bl=3, dic=_CodingScheme_dict),
        Uint('AddCountryInitials', bl=1),
        Uint('SpareBits', bl=3),
        Buf('Name', val=b'', rep=REPR_HEX)
        )
    
    def set_val(self, vals):
        Name = None
        if isinstance(vals, dict) and 'Name' in vals:
            Name = dict(vals['Name'])
            del vals['Name']
        elif isinstance(vals, (tuple, list)) and len(vals) == 5:
            vals = list(vals)
            Name = vals[-1]
            vals[-1] = None
        Envelope.set_val(self, vals)
        if Name is not None:
            if isinstance(Name, Buf.TYPES + (NoneType,)):
                self[4].set_val(Name)
            elif isinstance(Name, str_types):
                # encode it according to the Coding value
                Coding = self[1]()
                if Coding == CODTYPE_7B:
                    enc, c = encode_7b(Name)
                    self[4]._val = enc
                    self[3]._val = (8-((7*c)%8))%8
                elif Coding == CODTYPE_UCS2:
                    self[4]._val = Name.encode('utf-16-be')
                    self[3]._val = 0
    
    encode = set_val
    
    def decode(self):
        """returns the textual network name
        """
        Coding = self[1].get_val()
        if Coding == CODTYPE_7B:
            dec = decode_7b(self[4].get_val())
            if self[3]() == 7:
                dec = dec[:-1]
            return dec
        elif Coding == CODTYPE_UCS2:
            # WNG: this will certainly fail in Python2
            return self[4].get_val().decode('utf-16-be')
        else:
            return None


#------------------------------------------------------------------------------#
# Reject Cause
# TS 24.008, section 10.5.3.6
#------------------------------------------------------------------------------#

_RejectCause_dict = {
    2:'IMSI unknown in HLR',
    3:'Illegal MS',
    4:'IMSI unknown in VLR',
    5:'IMEI not accepted',
    6:'Illegal ME',
    11:'PLMN not allowed',
    12:'Location Area not allowed',
    13:'Roaming not allowed in this location area',
    15:'No Suitable Cells In Location Area',
    17:'Network failure',
    20:'MAC failure',
    21:'Synch failure',
    22:'Congestion',
    23:'GSM authentication unacceptable',
    25:'Not authorized for this CSG',
    32:'Service option not supported',
    33:'Requested service option not subscribed',
    34:'Service option temporarily out of order',
    38:'Call cannot be identified',
    48:'retry upon entry into a new cell',
    95:'Semantically incorrect message',
    96:'Invalid mandatory information',
    97:'Message type non-existent or not implemented',
    98:'Message type not compatible with the protocol state',
    99:'Information element non-existent or not implemented',
    100:'Conditional IE error',
    101:'Message not compatible with the protocol state',
    111:'Protocol error, unspecified'
    }

class RejectCause(Uint8):
    _dic = _RejectCause_dict


#------------------------------------------------------------------------------#
# Time Zone
# TS 24.008, section 10.5.3.8
#------------------------------------------------------------------------------#
# identical to TS23040_SMS._TP_SCTS_TZ structure

class TimeZone(Envelope):
    _Sign_dict = {0: '+', 1: '-'}
    _GEN = (
        Uint('TZ1', bl=4),
        Uint('TZS', bl=1, dic=_Sign_dict),
        Uint('TZ0', bl=3)
        )
    
    def set_val(self, vals):
        if isinstance(vals, float):
            self.encode(vals)
        else:
            Envelope.set_val(self, vals)
    
    def encode(self, val):
        if val < 0:
            self[1].set_val(1)
            val = -val
        else:
            self[1].set_val(0)
        if val != 0:
            quart = ceil((val*4) % 128)
            self[0].set_val( quart%16 )
            self[2].set_val( quart>>4 )
        else:
            self[0].set_val(0)
            self[2].set_val(0)
    
    def decode(self):
        if self[1]() == 1:
            return -0.25 * ((self[2]()<<4) + self[0]())
        else:
            return 0.25 * ((self[2]()<<4) + self[0]())
    
    def repr(self):
        return '<TimeZone: %s%.2f>' % (self._Sign_dict[self[1]()], 0.25 * (self[0]() + (self[2]()<<4)))
        
    __repr__ = repr


#------------------------------------------------------------------------------#
# Time Zone and Time
# TS 24.008, section 10.5.3.9
#------------------------------------------------------------------------------#
# identical to TS23040_SMS.TP_SCTS structure


class _TP_SCTS_Comp(Envelope):
    
    def set_val(self, vals):
        if isinstance(vals, integer_types):
            self.encode(vals)
        else:
            Envelope.set_val(self, vals)
    
    def encode(self, val):
        self.set_val( (val%10, val//10) )
    
    def decode(self):
        return self[0]()+10*self[1]()
    
    def repr(self):
        return '<%s : %i%i>' % (self._name, self[1](), self[0]())
    
    __repr__ = repr


class TimeZoneTime(Envelope):
    
    YEAR_BASE = 2000
    
    _GEN = (
        _TP_SCTS_Comp('Year', GEN=(Uint('Y1', bl=4), Uint('Y0', bl=4))),
        _TP_SCTS_Comp('Mon',  GEN=(Uint('M1', bl=4), Uint('M0', bl=4))),
        _TP_SCTS_Comp('Day',  GEN=(Uint('D1', bl=4), Uint('D0', bl=4))),
        _TP_SCTS_Comp('Hour', GEN=(Uint('H1', bl=4), Uint('H0', bl=4))),
        _TP_SCTS_Comp('Min',  GEN=(Uint('M1', bl=4), Uint('M0', bl=4))),
        _TP_SCTS_Comp('Sec', GEN=(Uint('S1', bl=4), Uint('S0', bl=4))),
        TimeZone('TimeZone')
        )
    
    def set_val(self, val):
        if isinstance(val, (tuple, list)) and len(val) == 2:
            self.encode(*val)
        else:
            Envelope.set_val(self, val)
    
    def encode(self, ts, tz=0.0):
        """encode a Python struct_time and potential timezone shift as the value of
        the TimeZoneTime
        """
        self['Year'].encode( ts.tm_year-self.YEAR_BASE )
        self['Mon'].encode( ts.tm_mon  )
        self['Day'].encode( ts.tm_mday )
        self['Hour'].encode( ts.tm_hour )
        self['Min'].encode( ts.tm_min  )
        self['Sec'].encode( ts.tm_sec )
        self['TZ'].encode( tz )
    
    def decode(self):
        """decode the value of the TimeZoneTime into a Python struct_time and 
        timezone shift
        """
        ts = struct_time((
            self.YEAR_BASE+self['Year'].decode(),
            self['Mon'].decode(),
            self['Day'].decode(),
            self['Hour'].decode(),
            self['Min'].decode(),
            self['Sec'].decode(),
            0, 0, 0))
        return ts, self['TimeZone'].decode()


#------------------------------------------------------------------------------#
# Daylight Saving Time
# TS 24.008, section 10.5.3.12
#------------------------------------------------------------------------------#

_DLSavingTime = {
    0 : 'No adjustment for Daylight Saving Time',
    1 : '+1 hour adjustment for Daylight Saving Time',
    2 : '+2 hours adjustment for Daylight Saving Time',
    3 : _str_reserved
    }

class DLSavingTime(Envelope):
    _GEN = (
        Uint('spare', bl=6),
        Uint('Value', bl=2, dic=_DLSavingTime)
        )


#------------------------------------------------------------------------------#
# Supported codec list
# TS 24.008, section 10.5.4.32
#------------------------------------------------------------------------------#

class SuppCodec(Envelope):
    _GEN = (
        Uint8('SysID'),
        Uint8('BMLen'),
        Buf('CodecBM', val=b'\0', rep=REPR_BIN),
        )
    def __init__(self, *args, **kw):
        Envelope.__init__(self, *args, **kw)
        self[1].set_valauto( self[2].get_len )
        self[2].set_blauto( lambda: 8*self[1]() )

class SuppCodecList(Array):
    _GEN = SuppCodec()


#------------------------------------------------------------------------------#
# Emergency Service Category
# TS 24.008, section 10.5.4.33
#------------------------------------------------------------------------------#

class EmergServiceCat(Envelope):
    _GEN = (
        Uint('Police', bl=1),
        Uint('Ambulance', bl=1),
        Uint('Fire', bl=1),
        Uint('Marine', bl=1),
        Uint('Mountain', bl=1),
        Uint('manual eCall', bl=1),
        Uint('auto eCall', bl=1),
        Uint('spare', bl=1)
        )


#------------------------------------------------------------------------------#
# Emergency Number List
# TS 24.008, section 10.5.3.13
#------------------------------------------------------------------------------#

class EmergNum(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint('spare', bl=3),
        EmergServiceCat('ServiceCat')[:5],
        BufBCD('Num')
        )
    
    def __init__(self, *args, **kw):
        Envelope.__init__(self, *args, **kw)
        self[2]._name = 'ServiceCat' # otherwise, it says 'slice'
        self._by_name[2] = 'ServiceCat' # otherwise, it says 'slice'
        self[0].set_valauto( lambda: 1 + self[3].get_len() )
        self[3].set_blauto( lambda: 8*(self[0]()-1) )


class EmergNumList(Array):
    _GEN = EmergNum()


#------------------------------------------------------------------------------#
# Additional Update Parameters
# TS 24.008, 10.5.3.14
#------------------------------------------------------------------------------#

_CSMO_dict = {
    1 : 'CS fallback MO call'
    }
_CSMT_dict = {
    1 : 'CS fallback MT call'
    }

class AddUpdateParams(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('CSMO', bl=1, dic=_CSMO_dict),
        Uint('CSMT', bl=1, dic=_CSMT_dict)
        )


#------------------------------------------------------------------------------#
# MM Timer
# TS 24.008, 10.5.3.16
#------------------------------------------------------------------------------#

_MMTimerUnit_dict = {
    0 : '2 sec',
    1 : '1 min',
    2 : '6 min',
    7 : 'timer deactivated'
    }

class MMTimer(Envelope):
    _GEN = (
        Uint('Unit', bl=3, dic=_MMTimerUnit_dict),
        Uint('Value', bl=5)
        )
    
    def get_time(self):
        """returns the timer set in seconds
        """
        unit, val = self.get_val()
        if unit == 0:
            return val*2
        elif unit == 1:
            return val*60
        elif unit == 2:
            return val*360
        else:
            return 0


#------------------------------------------------------------------------------#
# Auxiliary states
# TS 24.008, 10.5.4.4
#------------------------------------------------------------------------------#

_AuxHold_dict = {
    0 : 'idle',
    1 : 'hold request',
    2 : 'call held',
    3 : 'retrieve request'
    }
_AuxMPTY_dict = {
    0 : 'idle',
    1 : 'MPTY request',
    2 : 'call in MPTY',
    3 : 'split request'
    }

class AuxiliaryStates(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('spare', bl=3),
        Uint('Hold', bl=2, dic=_AuxHold_dict),
        Uint('MPTY', bl=2, dic=_AuxMPTY_dict)
        )


#------------------------------------------------------------------------------#
# Backup bearer capability
# TS 24.008, 10.5.4.4a
#------------------------------------------------------------------------------#

_RadioChanReq_dict = {
    0:'reserved',
    1:'full rate support only MS',
    2:'dual rate support MS/half rate preferred',
    3:'dual rate support MS/full rate preferred'
    }

_BCapCodingStd_dict = {
    0 : 'GSM standardized coding',
    1 : _str_reserved
    }

_TransferMode_dict = {
    0:'circuit',
    1:'packet'
    }

_TransferCap_dict = {
    0:'speech',
    1:'unrestricted digital information',
    2:'3.1 kHz audio, ex PLMN',
    3:'facsimile group 3',
    5:'Other ITC (See Octet 5a)',
    7:'reserved, to be used in the network'
    }

class _BearerCapOct4(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Compress', bl=1),
        Uint('Structure', bl=2),
        Uint('DuplexMode', bl=1),
        Uint('Config', bl=1),
        Uint('NIRR', bl=1),
        Uint('Estab', bl=1)
        )

class _BearerCapExt5a(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('OtherITC', bl=2),
        Uint('OtherRateAdapt', bl=2),
        Uint('spare', bl=3)
        )

class _BUBearerCapOct5(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('AccessId', bl=2),
        Uint('RateAdapt', bl=2),
        Uint('SignalAccessProt', bl=3),
        _BearerCapExt5a('Ext5a')
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[4].set_transauto(lambda: self[0]() == 1)

class _BearerCapExt6a(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('NumStopBits', bl=1),
        Uint('Negotation', bl=1),
        Uint('NumDataBits', bl=1),
        Uint('UserRate', bl=4)
        )

class _BearerCapExt6b(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('IntermedRate', bl=2),
        Uint('NICOnTx', bl=1),
        Uint('NICOnRx', bl=1),
        Uint('Parity', bl=3)
        )

class _BearerCapExt6c(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('ConnectElt', bl=2),
        Uint('ModemType', bl=5)
        )

class _BearerCapExt6d(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('OtherModemType', bl=2),
        Uint('FixedNetUserRate', bl=5)
        )

class _BearerCapExt6e(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('AcceptableChanCodings', bl=4),
        Uint('MaxNumOfTrafficChan', bl=3)
        )

class _BearerCapExt6f(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('UIMI', bl=3),
        Uint('WantedAirIFUserRate', bl=4)
        )

class _BearerCapExt6g(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('AcceptableChanCodingsExt', bl=3),
        Uint('AssymetryInd', bl=2),
        Uint('spare', bl=2)
        )

class _BearerCapOct6(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Layer1Id', val=1, bl=2),
        Uint('UserInfoLayer1Prot', bl=4),
        Uint('Sync', bl=1),
        _BearerCapExt6a('Ext6a'),
        _BearerCapExt6b('Ext6b'),
        _BearerCapExt6c('Ext6c'),
        _BearerCapExt6d('Ext6d'),
        _BearerCapExt6e('Ext6e'),
        _BearerCapExt6f('Ext6f'),
        _BearerCapExt6g('Ext6g')
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[4].set_transauto(lambda: self[0]() == 1)
        self[5].set_transauto(lambda: self[4].get_trans() or self[4][0]() == 1)
        self[6].set_transauto(lambda: self[5].get_trans() or self[5][0]() == 1)
        self[7].set_transauto(lambda: self[6].get_trans() or self[6][0]() == 1)
        self[8].set_transauto(lambda: self[7].get_trans() or self[7][0]() == 1)
        self[9].set_transauto(lambda: self[8].get_trans() or self[8][0]() == 1)
        self[10].set_transauto(lambda: self[9].get_trans() or self[9][0]() == 1)

class _BearerCapOct7(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Layer2Id', val=2, bl=2),
        Uint('UserInfoLayer2Prot', bl=5)
        )

class BackupBearerCap(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('RadioChanReq', val=1, bl=2, dic=_RadioChanReq_dict),
        Uint('CodingStd', bl=1, dic=_BCapCodingStd_dict),
        Uint('TransferMode', bl=1, dic=_TransferMode_dict),
        Uint('InfoTransferCap', bl=3, dic=_TransferCap_dict),
        _BearerCapOct4('Oct4', trans=True),
        _BUBearerCapOct5('Oct5', trans=True),
        _BearerCapOct6('Oct6', trans=True),
        _BearerCapOct7('Oct7', trans=True)
        )
    
    def _from_char(self, char):
        Envelope._from_char(self, char)
        if char.len_byte():
            # Oct4
            self[5].set_trans(False)
            self[5]._from_char(char)
            if char.len_byte():
                # Oct5
                self[6].set_trans(False)
                self[6]._from_char(char)
                if char.len_byte():
                    # Oct6
                    self[7].set_trans(False)
                    self[7]._from_char(char)
                    if char.len_byte():
                        # Oct7
                        self[8].set_trans(False)
                        self[8]._from_char(char)


#------------------------------------------------------------------------------#
# Bearer capability
# TS 24.008, 10.5.4.5
#------------------------------------------------------------------------------#

_CTMSupp_dict = {
    0 : 'CTM text telephony is not supported',
    1 : 'CTM text telephony is supported'
    }

_CodingExt3_dict = {
    0 : 'octet used for extension of information transfer capability',
    1 : 'octet used for other extension of octet 3'
    }

_SpeechVersInd_dict = {
    0 : 'GSM FR v1 (GSM FR)',
    2 : 'GSM FR v2 (GSM EFR)',
    4 : 'GSM FR v3 (FR AMR)',
    6 : 'GSM FR v4',
    8 : 'GSM FR v5',
    1 : 'GSM HR v1 (GSM HR)',
    5 : 'GSM HR v3 (HR AMR)',
    7 : 'GSM HR v4',
    11 : 'GSM HR v6',
    15 : 'no speech version supported for GERAN'
    }

class _BearerCapExt3a(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Coding', bl=1, dic=_CodingExt3_dict),
        Uint('CTM', bl=1, dic=_CTMSupp_dict),
        Uint('spare', bl=1),
        Uint('SpeechVersionInd', bl=4, dic=_SpeechVersInd_dict)
        )

class _BearerCapExt3bRec(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Coding', bl=1, dic=_CodingExt3_dict),
        Uint('spare', bl=2),
        Uint('SpeechVersionInd', bl=4, dic=_SpeechVersInd_dict)
        )

class _BearerCapExt3b(Sequence):
    _GEN = _BearerCapExt3bRec()
    
    def _from_char(self, char):
        # while Ext bit is 1, stack another sequenced element
        if self.get_trans():
            return
        # 1) determine the number of iteration of the template within the sequence
        num = None
        # 2) init content
        self._content = []
        # 3) consume char and fill in self._content
        # there is no predefined limit in the number of repeated content
        # consume the charpy instance until Ext == 1
        while True:
            # remember charpy cursor position, to restore it when it raises
            cur = char._cur
            clone = self._tmpl.clone()
            try:
                clone._from_char(char)
            except CharpyErr as err:
                char._cur = cur
                break
            else:
                self._content.append(clone)
                clone._env = self
            if clone[0]() == 1:
                break

class _BearerCapExt5b(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Hdr', bl=1),
        Uint('Multiframe', bl=1),
        Uint('Mode', bl=1),
        Uint('LLI', bl=1),
        Uint('Assignor', bl=1),
        Uint('InbNeg', bl=1),
        Uint('spare', bl=1)
        )

class _BearerCapOct5(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('AccessId', bl=2),
        Uint('RateAdapt', bl=2),
        Uint('SignalAccessProt', bl=3),
        _BearerCapExt5a('Ext5a'),
        _BearerCapExt5b('Ext5b')
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[4].set_transauto(lambda: self[0]() == 1)
        self[5].set_transauto(lambda: self[4].get_trans() or self[4][0]() == 1)

class BearerCap(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('RadioChanReq', val=1, bl=2, dic=_RadioChanReq_dict),
        Uint('CodingStd', bl=1, dic=_BCapCodingStd_dict),
        Uint('TransferMode', bl=1, dic=_TransferMode_dict),
        Uint('InfoTransferCap', bl=3, dic=_TransferCap_dict),
        _BearerCapExt3a('Ext3a'),
        _BearerCapExt3b('Ext3b'),
        _BearerCapOct4('Oct4', trans=True),
        _BearerCapOct5('Oct5', trans=True),
        _BearerCapOct6('Oct6', trans=True),
        _BearerCapOct7('Oct7', trans=True)
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[5].set_transauto(lambda: self[0]() == 1)
        self[6].set_transauto(lambda: self[5].get_trans() or self[5][0]() == 1)
    
    def _from_char(self, char):
        Envelope._from_char(self, char)
        if char.len_byte():
            # Oct4
            self[7].set_trans(False)
            self[7]._from_char(char)
            if char.len_byte():
                # Oct5
                self[8].set_trans(False)
                self[8]._from_char(char)
                if char.len_byte():
                    # Oct6
                    self[9].set_trans(False)
                    self[9]._from_char(char)
                    if char.len_byte():
                        # Oct7
                        self[10].set_trans(False)
                        self[10]._from_char(char)


#------------------------------------------------------------------------------#
# Call Control Capabilities
# TS 24.008, 10.5.4.5a
#------------------------------------------------------------------------------#

class CCCap(Envelope):
    _GEN = (
        Uint('MaxNumSupportedBearers', bl=4),
        Uint('MultimediaCAT', bl=1),
        Uint('ENICM', bl=1),
        Uint('PCP', bl=1),
        Uint('DTMF', val=1, bl=1),
        Uint('spare', bl=4),
        Uint('MaxNumSpeechBearers', bl=4)
        )


#------------------------------------------------------------------------------#
# Call state
# TS 24.008, 10.5.4.6
#------------------------------------------------------------------------------#

_CodingStd_dict = {
    0 : 'Standardized coding, as described in ITU-T Q.931',
    1 : 'Reserved for other international standards',
    2 : 'National standard',
    3 : 'Standard defined for the GSM PLMNs'
    }

_CallState_dict = {
    0 : 'null',
    2 : 'MM connection pending',
    34 : 'CC prompt present',
    35 : 'Wait for network information',
    36 : 'CC-Establishment present',
    37 : 'CC-Establishment confirmed',
    38 : 'Recall present',
    1 : 'call initiated',
    3 : 'mobile originating call proceeding',
    4 : 'call delivered',
    6 : 'call present',
    7 : 'call received',
    8 : 'connect request',
    9 : 'mobile terminating call confirmed',
    10 : 'active',
    11 : 'disconnect request',
    12 : 'disconnect indication',
    19 : 'release request',
    26 : 'mobile originating modify',
    27 : 'mobile terminating modify',
    28 : 'connect indication'
    }

class CallState(Envelope):
    _GEN = (
        Uint('CodingStd', bl=2, dic=_CodingStd_dict),
        Uint('Value', bl=6, dic=_CallState_dict)
        )


#------------------------------------------------------------------------------#
# Called party BCD number
# TS 24.008, 10.5.4.7
#------------------------------------------------------------------------------#

# generic BCD number
# BCDType and NumPlan are extended with values from TS 23.040, section 9.1.2.15

_BCDType_dict = {
    0 : 'unknown',
    1 : 'international number',
    2 : 'national number',
    3 : 'network specific number',
    4 : 'dedicated access, short code',
    5 : 'alphanumeric',         # only for SMS
    6 : 'abbreviated number',   # only for SMS
    7 : _str_reserved
    }

_NumPlan_dict = {
    0 : 'unknown',
    1 : 'ISDN / telephony numbering plan (E.164 / E.163)',
    2 : 'generic numbering plan',
    3 : 'data numbering plan (X.121)',
    4 : 'telex numbering plan (F.69)',
    5 : 'service center specific',  # only for SMS
    6 : 'service center specific',  # only for SMS
    8 : 'national numbering plan',
    9 : 'private numbering plan',
    10: 'ERMES numbering plan',     # only for SMS
    11: 'reserved for CTS',
    15: _str_reserved
    }

_PresInd_dict = {
    0 : 'presentation allowed',
    1 : 'presentation restricted',
    2 : 'number not available due to interworking',
    3 : _str_reserved
    }

_ScreenInd_dict = {
    0 : 'user-provided, not screened',
    1 : 'user-provided, verified and passed',
    2 : 'user-provided, verified and failed',
    3 : 'network provided'
    }

class _BCDNumberExt3a(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('PresentationInd', bl=2, dic=_PresInd_dict),
        Uint('spare', bl=3),
        Uint('ScreeningInd', bl=2, dic=_ScreenInd_dict)
        )

class BCDNumber(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Type', val=1, bl=3, dic=_BCDType_dict),
        Uint('NumberingPlan', val=1, bl=4, dic=_NumPlan_dict),
        _BCDNumberExt3a('Ext3a'),
        BufBCD('Num')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[3].set_transauto(lambda: self[0]() == 1)


class CalledPartyBCDNumber(BCDNumber):
    pass


#------------------------------------------------------------------------------#
# Called party subaddress
# TS 24.008, 10.5.4.8
#------------------------------------------------------------------------------#

# generic sub-address

_SubaddrType_dict = {
    0 : 'NSAP',
    2 : 'user defined'
    }

class Subaddress(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Type', bl=3, dic=_SubaddrType_dict),
        Uint('Odd', bl=1),
        Uint('spare', bl=3),
        Buf('Addr', val=b'', rep=REPR_HEX)
        )

class CalledPartySubaddress(Subaddress):
    pass

#------------------------------------------------------------------------------#
# Calling party BCD number
# TS 24.008, 10.5.4.9
#------------------------------------------------------------------------------#

class CallingPartyBCDNumber(BCDNumber):
    pass


#------------------------------------------------------------------------------#
# Calling party subaddress
# TS 24.008, 10.5.4.10
#------------------------------------------------------------------------------#

class CallingPartySubaddress(Subaddress):
    pass


#------------------------------------------------------------------------------#
# Cause
# TS 24.008, 10.5.4.11
#------------------------------------------------------------------------------#

_Location_dict = {
    0 : 'User',
    1 : 'Private network serving the local user',
    2 : 'Public network serving the local user',
    4 : 'Public network serving the remote user',
    5 : 'Private network serving the remote user',
    10 : 'Network beyond interworking point'
    }

_CauseClass_dict = {
    0 : 'normal event',
    1 : 'normal event',
    2 : 'resource unavailable',
    3 : 'service or option not available',
    4 : 'service or option not implemented',
    5 : 'invalid message (e.g. parameter out of range)',
    6 : 'protocol error (e.g. unknown message)',
    7 : 'interworking'
    }

_CauseValue_dict = {
    0 : {
        1 : 'Unassigned (unallocated) number',
        3 : 'No route to destination',
        6 : 'Channel unacceptable',
        8 : 'Operator determined barring'
        },
    1 : {
        0 : 'Normal call clearing',
        1 : 'User busy',
        2 : 'No user responding',
        3 : 'User alerting, no answer',
        5 : 'Call rejected',
        6 : 'Number changed',
        8 : 'Call rejected due to feature at the destination',
        9 : 'Pre-emption',
        10 : 'Non selected user clearing',
        11 : 'Destination out of order',
        12 : 'Invalid number format (incomplete number)',
        13 : 'Facility rejected',
        14 : 'Response to STATUS ENQUIRY',
        15 : 'Normal, unspecified'
        },
    2 : {
        2 : 'No circuit/channel available',
        6 : 'Network out of order',
        9 : 'Temporary failure',
        10 : 'Switching equipment congestion',
        11 : 'Access information discarded',
        12 : 'requested circuit/channel not available',
        15 : 'Resources unavailable, unspecified'
        },
    3 : {
        1 : 'Quality of service unavailable',
        2 : 'Requested facility not subscribed',
        7 : 'Incoming calls barred within the CUG',
        9 : 'Bearer capability not authorized',
        10 : 'Bearer capability not presently available',
        15 : 'Service or option not available, unspecified'
        },
    4 : {
        1 : 'Bearer service not implemented',
        4 : 'ACM equal to or greater than ACMmax',
        5 : 'Requested facility not implemented',
        6 : 'Only restricted digital information bearer capability is available',
        15 : 'Service or option not implemented, unspecified'
        },
    5 : {
        1 : 'Invalid transaction identifier value',
        7 : 'User not member of CUG',
        8 : 'Incompatible destination',
        11 : 'Invalid transit network selection',
        15 : 'Semantically incorrect message'
        },
    6 : {
        0 : 'Invalid mandatory information',
        1 : 'Message type non-existent or not implemented',
        2 : 'Message type not compatible with protocol state',
        3 : 'Information element non-existent or not implemented',
        4 : 'Conditional IE error',
        5 : 'Message not compatible with protocol state',
        6 : 'Recovery on timer expiry',
        15 : 'Protocol error, unspecified'
        },
    7 : {
        15 : 'Interworking, unspecified'
        }
    }

class _CauseExt3a(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Recommendation', bl=7)
        )

class Cause(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('CodingStd', bl=2, dic=_CodingStd_dict),
        Uint('spare', bl=1),
        Uint('Location', bl=4, dic=_Location_dict),
        _CauseExt3a('Ext3a'),
        Uint('Ext', val=1, bl=1),
        Uint('Class', bl=3, dic=_CauseClass_dict),
        Uint('Value', bl=4),
        Buf('Diagnostic', val=b'')
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[4].set_transauto(lambda: self[0]() == 1)
        self[7].set_dicauto(lambda: _CauseValue_dict[self[6]()])


#------------------------------------------------------------------------------#
# Congestion level
# TS 24.008, 10.5.4.12
#------------------------------------------------------------------------------#

CongestionLevel_dict = {
    0 : 'receiver ready',
    15 : 'receiver not ready'
    }


#------------------------------------------------------------------------------#
# Connected number
# TS 24.008, 10.5.4.13
#------------------------------------------------------------------------------#

class ConnectedNumber(BCDNumber):
    pass


#------------------------------------------------------------------------------#
# Connected subaddress
# TS 24.008, 10.5.4.14
#------------------------------------------------------------------------------#

class ConnectedSubaddress(Subaddress):
    pass


#------------------------------------------------------------------------------#
# High layer compatibility
# TS 24.008, 10.5.4.16
#------------------------------------------------------------------------------#

class _HighLayerCompOct3(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('CodingStd', bl=2, dic=_CodingStd_dict),
        Uint('Interpretation', bl=3),
        Uint('PresentationMethProtProfile', bl=2)
        )

class _HighLayerCompExt4a(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('HighLayerCharIdentExt', bl=7)
        )

class _HighLayerCompOct4(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('Ext', bl=1),
        Uint('HighLayerCharIdent', bl=7),
        _HighLayerCompExt4a('Ext4a')
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_transauto(lambda: self[0]() == 1)

class HighLayerComp(Envelope):
    _GEN = (
        _HighLayerCompOct3('Oct3', trans=True),
        _HighLayerCompOct4('Oct4', trans=True)
        )
    
    def _from_char(self, char):
        l = char.len_byte()
        if l > 1:
            self[0].set_trans(False)
            self[1].set_trans(False)
        elif l == 1:
            self[0].set_trans(False)
        Envelope._from_char(self, char)


#------------------------------------------------------------------------------#
# Notification indicator
# TS 24.008, 10.5.4.20
#------------------------------------------------------------------------------#

_Notification_dict = {
    0 : 'User suspended',
    1 : 'User resumed',
    2 : 'Bearer change'
    }

class NotificationInd(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Notification', bl=7, dic=_Notification_dict)
        )


#------------------------------------------------------------------------------#
# Progress indicator
# TS 24.008, 10.5.4.21
#------------------------------------------------------------------------------#

_Progress_dict = {
    1 : 'Call is not end-to-end PLMN/ISDN, further call progress information may be available in-band',
    2 : 'Destination address in non-PLMN/ISDN',
    3 : 'Origination address in non-PLMN/ISDN',
    4 : 'Call has returned to the PLMN/ISDN',
    8 : 'In-band information or appropriate pattern now available',
    9 : 'In-band multimedia CAT available',
    32: 'Call is end-to-end PLMN/ISDN',
    64: 'Queueing'
    }

class ProgressInd(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('CodingStd', bl=2, dic=_CodingStd_dict),
        Uint('spare', bl=1),
        Uint('Location', bl=4, dic=_Location_dict),
        Uint('Ext', val=1, bl=1),
        Uint('Progress', bl=7, dic=_Progress_dict)
        )


#------------------------------------------------------------------------------#
# Recall type $(CCBS)$
# TS 24.008, 10.5.4.21a
#------------------------------------------------------------------------------#

_RecallType_dict = {
    0 : 'CCBS',
    7 : _str_reserved
    }

class RecallType(Envelope):
    _GEN = (
        Uint('spare', bl=5),
        Uint('Value', bl=3, dic=_RecallType_dict)
        )


#------------------------------------------------------------------------------#
# Redirecting party BCD number
# TS 24.008, 10.5.4.21b
#------------------------------------------------------------------------------#

class RedirectingPartyBCDNumber(BCDNumber):
    pass


#------------------------------------------------------------------------------#
# Redirecting party subaddress
# TS 24.008, 10.5.4.21c
#------------------------------------------------------------------------------#

class RedirectingPartySubaddress(Subaddress):
    pass


#------------------------------------------------------------------------------#
# Repeat indicator
# TS 24.008, 10.5.4.22
#------------------------------------------------------------------------------#

RepeatInd_dict = {
    1 : 'Circular for successive selection, mode 1 alternate mode 2',
    2 : 'Support of fallback, mode 1 preferred, mode 2 selected if setup of mode 1 fails',
    3 : _str_reserved,
    4 : 'Service change and fallback, mode 1 alternate mode 2, mode 1 preferred'
    }


#------------------------------------------------------------------------------#
# Signal
# TS 24.008, 10.5.4.23
#------------------------------------------------------------------------------#

_Signal_dict = {
    0 : 'dial tone on',
    1 : 'ring back tone on',
    2 : 'intercept tone on',
    3 : 'network congestion tone on',
    4 : 'busy tone on',
    5 : 'confirm tone on',
    6 : 'answer tone on',
    7 : 'call waiting tone on',
    8 : 'off-hook warning tone on',
    63 : 'tones off',
    79 : 'alerting off'
    }

class Signal(Uint8):
    _dic = _Signal_dict


#------------------------------------------------------------------------------#
# User-user
# TS 24.008, 10.5.4.25
#------------------------------------------------------------------------------#

_UUType_dict = {
    0 : 'User specific protocol',
    1 : 'OSI high layer protocols',
    2 : 'X.244',
    3 : 'Reserved for system management convergence function',
    4 : 'IA5 characters',
    7 : 'rate adaption according to ITU-T V.120',
    8 : 'user-network call control messages according to ITU-T Q.931',
    79: '3GPP capability exchange protocol'
    }

class UserUser(Envelope):
    _GEN = (
        Uint8('Type', val=4, dic=_UUType_dict),
        Buf('Data', val=b'') # should be 32 or 128 bytes
        )


#------------------------------------------------------------------------------#
# Alerting Pattern $(NIA)$
# TS 24.008, 10.5.4.26
#------------------------------------------------------------------------------#

class AlertingPattern(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Value', bl=4)
        )


#------------------------------------------------------------------------------#
# Allowed actions $(CCBS)$
# TS 24.008, 10.5.4.27
#------------------------------------------------------------------------------#

_CCBSAct_dict = {
    0 : 'Activation of CCBS not possible',
    1 : 'Activation of CCBS possible'
    }

class CCBSAllowedActions(Envelope):
    _GEN = (
        Uint('CCBSAct', bl=1, dic=_CCBSAct_dict),
        Uint('spare', bl=7)
        )


#------------------------------------------------------------------------------#
# Stream Identifier
# TS 24.008, 10.5.4.28
#------------------------------------------------------------------------------#

class StreamIdent(Uint8):
    pass


#------------------------------------------------------------------------------#
# Network Call Control Capabilities
# TS 24.008, 10.5.4.29
#------------------------------------------------------------------------------#

class NetCCCap(Envelope):
    _GEN = (
        Uint('spare', bl=7),
        Uint('MultiCallSupport', bl=1)
        )


#------------------------------------------------------------------------------#
# Cause of No CLI
# TS 24.008, 10.5.4.30
#------------------------------------------------------------------------------#

_CauseNoCLI_dict = {
    0 : 'Unavailable',
    1 : 'Reject by user',
    2 : 'Interaction with other service',
    3 : 'Coin line/payphone'
    }

class CauseNoCLI(Uint8):
    _dic = _CauseNoCLI_dict


#------------------------------------------------------------------------------#
# Supported codec list
# TS 24.008, 10.5.4.32
#------------------------------------------------------------------------------#

_CodecSysID_dict = {
    0:'GSM',
    4:'UMTS'
    }

class _CodecBitmap(Envelope):
    _GEN = (
        Uint('TDMA_EFR', bl=1),
        Uint('UMTS_AMR2', bl=1),
        Uint('UMTS_AMR', bl=1),
        Uint('HR_AMR', bl=1),
        Uint('FR_AMR', bl=1),
        Uint('GSM_EFR', bl=1),
        Uint('GSM_HR', bl=1),
        Uint('GSM_FR', bl=1),
        Uint('reserved', bl=1),
        Uint('reserved', bl=1),
        Uint('OHR_AMR-WB', bl=1),
        Uint('OFR_AMR-WB', bl=1),
        Uint('OHR_AMR', bl=1),
        Uint('UMTS_AMR-WB', bl=1),
        Uint('FR_AMR-WB', bl=1),
        Uint('PDC_EFR', bl=1),
        Buf('spare', val=b'')
        )

class CodecSysID(Envelope):
    _GEN = (
        Uint8('SysID', dic=_CodecSysID_dict),
        Uint8('BMLen'),
        _CodecBitmap('CodecBM')
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
    
    def _from_char(self, char):
        self[0]._from_char(char)
        self[1]._from_char(char)
        l = self[1]()
        clen = char._len_bit
        char._len_bit = char._cur + 8*l
        if char._len_bit > clen:
            raise(EltErr('{0} [_from_char]: bit length overflow'.format(self._name)))
        if l == 1:
            for b in self[8:16]:
                b.set_trans(True)
        self[2]._from_char(char)
        char._len_bit = clen

class SupportedCodecs(Sequence):
    _GEN = CodecSysID()


#------------------------------------------------------------------------------#
# Attach result
# TS 24.008, 10.5.5.1
#------------------------------------------------------------------------------#

_AttachResult_dict = {
    1 : 'GPRS-only attached',
    3 : 'Combined GPRS/IMSI attached'
    }

class AttachResult(Envelope):
    _GEN = (
        Uint('FollowOnProc', bl=1),
        Uint('Result', bl=3, dic=_AttachResult_dict)
        )


#------------------------------------------------------------------------------#
# Attach type
# TS 24.008, 10.5.5.2
#------------------------------------------------------------------------------#

_AttachType_dict = {
    1 : 'GPRS attach',
    2 : 'Not used (earlier versions)',
    3 : 'Combined GPRS/IMSI attach',
    4 : 'Emergency attach'
    }

class AttachType(Envelope):
    _GEN = (
        Uint('FollowOnReq', bl=1),
        Uint('Type', bl=3, dic=_AttachType_dict)
        )


#------------------------------------------------------------------------------#
# Ciphering algorithm
# TS 24.008, 10.5.5.3
#------------------------------------------------------------------------------#

CiphAlgo_dict = {
    0 : 'ciphering not used',
    1 : 'GEA/1',
    2 : 'GEA/2',
    3 : 'GEA/3',
    4 : 'GEA/4',
    5 : 'GEA/5',
    6 : 'GEA/6',
    7 : 'GEA/7'
    }


#------------------------------------------------------------------------------#
# Integrity algorithm
# TS 24.008, 10.5.5.3a
#------------------------------------------------------------------------------#

IntegAlgo_dict = {
    0 : 'GIA/4',
    1 : 'GIA/5',
    2 : 'GIA/6',
    3 : 'GIA/7'
    }


#------------------------------------------------------------------------------#
# TMSI Status
# TS 24.008, 10.5.5.4
#------------------------------------------------------------------------------#

_TMSIStatus_dict = {
    0 : 'no valid TMSI available',
    1 : 'valid TMSI available'
    }

class TMSIStatus(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('Flag', bl=1, dic=_TMSIStatus_dict)
        )


#------------------------------------------------------------------------------#
# Detach type
# TS 24.008, 10.5.5.5
#------------------------------------------------------------------------------#

_DetachTypeMO_dict = {
    1 : 'GPRS detach',
    2 : 'IMSI detach',
    3 : 'Combined GPRS/IMSI detach'
    }
_DetachTypeMT_dict = {
    1 : 're-attach required',
    2 : 're-attach not required',
    3 : 'IMSI detach (after VLR failure)'
    }

class DetachTypeMO(Envelope):
    _GEN = (
        Uint('PowerOff', bl=1),
        Uint('Type', bl=3, dic=_DetachTypeMO_dict)
        )

class DetachTypeMT(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Type', bl=3, dic=_DetachTypeMT_dict)
        )


#------------------------------------------------------------------------------#
# DRX Parameter
# TS 24.008, 10.5.5.6
#------------------------------------------------------------------------------#

_SplitPGCycleC_dict = {
    0 : '704 (no DRX)',
    65 : '71',
    66 : '72',
    67 : '74',
    68 : '75',
    69 : '77',
    70 : '79',
    71 : '80',
    72 : '83',
    73 : '86',
    74 : '88',
    75 : '90',
    76 : '92',
    77 : '96',
    78 : '101',
    79 : '103',
    80 : '107',
    81 : '112',
    82 : '116',
    83 : '118',
    84 : '128',
    85 : '141',
    86 : '144',
    87 : '150',
    88 : '160',
    89 : '171',
    90 : '176',
    91 : '192',
    92 : '214',
    93 : '224',
    94 : '235',
    95 : '256',
    96 : '288',
    97 : '320',
    98 : '352'
    }
_DRXCycleLen_dict = {
    0 : 'DRX not specified by the MS',
    6 : 'Iu coeff 6 and S1 T = 32',
    7 : 'Iu coeff 7 and S1 T = 64',
    8 : 'Iu coeff 8 and S1 T = 128',
    9 : 'Iu coeff 9 and S1 T = 256'
    }
_NonDRXTimer_dict = {
    0 : 'no non-DRX mode after transfer state',
    1 : 'max 1 sec non-DRX mode after transfer state',
    2 : 'max 2 sec non-DRX mode after transfer state',
    3 : 'max 4 sec non-DRX mode after transfer state',
    4 : 'max 8 sec non-DRX mode after transfer state',
    5 : 'max 16 sec non-DRX mode after transfer state',
    6 : 'max 32 sec non-DRX mode after transfer state',
    7 : 'max 64 sec non-DRX mode after transfer state'
    }

class DRXParam(Envelope):
    _GEN = (
        Uint8('SPLIT_PG_CYCLE_CODE', dic=_SplitPGCycleC_dict),
        Uint('DRXCycleLen', bl=4, dic=_DRXCycleLen_dict),
        Uint('SPLITonCCCH', bl=1),
        Uint('NonDRXTimer', bl=3, dic=_NonDRXTimer_dict)
        )


#------------------------------------------------------------------------------#
# Force to standby
# TS 24.008, 10.5.5.7
#------------------------------------------------------------------------------#

ForceStdby_dict = {
    0 : 'Force to standby not indicated',
    1 : 'Force to standby indicated'
    }

class ForceStdby(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Value', bl=3, dic=ForceStdby_dict)
        )


#------------------------------------------------------------------------------#
# IMEISV request
# TS 24.008, 10.5.5.10
#------------------------------------------------------------------------------#

class IMEISVReq(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Value', bl=3, dic={0:'IMEISV not requested', 1:'IMEISV requested'})
        )


#------------------------------------------------------------------------------#
# GMM Cause
# TS 24.008, 10.5.5.14
#------------------------------------------------------------------------------#

GMMCause_dict = {
    0  : 'Protocol error, unspecified',
    2  : 'IMSI unknown in HLR',
    3  : 'Illegal MS',
    5  : 'IMEI not accepted',
    6  : 'Illegal ME',
    7  : 'GPRS services not allowed',
    8  : 'GPRS services and non-GPRS services not allowed',
    9  : 'MS identity cannot be derived by the network',
    10 : 'implicitly detached',
    11 : 'PLMN not allowed',
    12 : 'Location Area not allowed',
    13 : 'Roaming not allowed in this location area',
    14 : 'GPRS services not allowed in this PLMN',
    15 : 'No Suitable Cells In Location Area',
    16 : 'MSC temporarily not reachable',
    17 : 'Network failure',
    20 : 'MAC failure',
    21 : 'Synch failure',
    22 : 'Congestion',
    23 : 'GSM authentication unacceptable',
    25 : 'Not authorized for this CSG',
    40 : 'No PDP context activated',
    48 : 'retry upon entry into a new cell',
    95 : 'Semantically incorrect message',
    96 : 'Invalid mandatory information',
    97 : 'Message type non-existent or not implemented',
    98 : 'Message type not compatible with the protocol state',
    99 : 'Information element non-existent or not implemented',
    100: 'Conditional IE error',
    101: 'Message not compatible with the protocol state',
    111: 'Protocol error, unspecified'
    }

class GMMCause(Uint8):
    _dic = GMMCause_dict


#------------------------------------------------------------------------------#
# Routing Area Identifier
# TS 24.008, 10.5.5.15
#------------------------------------------------------------------------------#

class RAI(Envelope):
    _GEN = (
        PLMN(),
        Uint16('LAC', rep=REPR_HEX),
        Uint8('RAC', rep=REPR_HEX)
        )
    
    encode = Envelope.set_val
    
    def decode(self):
        return (self[0].decode(), self[1].get_val(), self[2].get_val())


#------------------------------------------------------------------------------#
# Update result
# TS 24.008, 10.5.5.17
#------------------------------------------------------------------------------#

_UpdateResult_dict = {
    0 : 'RA updated',
    1 : 'combined RA/LA updated',
    4 : 'RA updated and ISR activated',
    5 : 'combined RA/LA updated and ISR activated',
    }

class UpdateResult(Envelope):
    _GEN = (
        Uint('FollowOnProc', bl=1),
        Uint('Value', bl=3, dic=_UpdateResult_dict)
        )


#------------------------------------------------------------------------------#
# Update type
# TS 24.008, 10.5.5.18
#------------------------------------------------------------------------------#

_UpdType_dict = {
    0 : 'RA updating',
    1 : 'combined RA/LA updating',
    2 : 'combined RA/LA updating with IMSI attach',
    3 : 'Periodic updating'
    }

class UpdateType(Envelope):
    _GEN = (
        Uint('FollowOnReq', bl=1),
        Uint('Value', bl=3, dic=_UpdType_dict)
        )


#------------------------------------------------------------------------------#
# Service type
# TS 24.008, 10.5.5.20
#------------------------------------------------------------------------------#

ServiceType_dict = {
    0 : 'Signalling',
    1 : 'Data',
    2 : 'Paging Response',
    3 : 'MBMS Multicast Service Reception',
    4 : 'MBMS Broadcast Service Reception',
    }


#------------------------------------------------------------------------------#
# PS LCS Capability
# TS 24.008, 10.5.5.22
#------------------------------------------------------------------------------#

class PSLCSCap(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('APC', bl=1),
        Uint('OTD_A', bl=1),
        Uint('OTD_B', bl=1),
        Uint('GPS_A', bl=1),
        Uint('GPS_B', bl=1),
        Uint('GPS_C', bl=1)
        )


#------------------------------------------------------------------------------#
# Network feature support
# TS 24.008, 10.5.5.23
#------------------------------------------------------------------------------#

class NetFeatSupp(Envelope):
    _GEN = (
        Uint('LCS_MOLR', bl=1),
        Uint('MBMS', bl=1),
        Uint('IMS_VoPS', bl=1),
        Uint('EMC_BS', bl=1)
        )


#------------------------------------------------------------------------------#
# Additional network feature support
# TS 24.008, 10.5.5.23A
#------------------------------------------------------------------------------#

class AddNetFeatSupp(Envelope):
    _GEN = (
        Uint('spare', bl=7),
        Uint('GPRS_SMS', bl=1)
        )


#------------------------------------------------------------------------------#
# Voice Domain Preference
# TS 24.008, 10.5.5.24
#------------------------------------------------------------------------------#

_UEUsage_dict = {
    0 : 'Voice centric',
    1 : 'Data centric'
    }
_VoiceDomPref_dict = {
    0 : 'CS Voice only',
    1 : 'IMS PS Voice only',
    2 : 'CS voice preferred, IMS PS Voice as secondary',
    3 : 'IMS PS voice preferred, CS Voice as secondary'
    }

class VoiceDomPref(Envelope):
    _GEN = (
        Uint('spare', bl=5),
        Uint('UEUsage', bl=1, dic=_UEUsage_dict),
        Uint('VoiceDomPref', bl=2, dic=_VoiceDomPref_dict)
        )


#------------------------------------------------------------------------------#
# Requested MS information
# TS 24.008, 10.5.5.25
#------------------------------------------------------------------------------#


class ReqMSInfo(Envelope):
    _GEN = (
        Uint('I_RAT', bl=1),
        Uint('I_RAT2', bl=1),
        Uint('spare', bl=2)
        )

#------------------------------------------------------------------------------#
# P-TMSI Type
# TS 24.008, 10.5.5.29
#------------------------------------------------------------------------------#

_PTMSIType_dict = {
    0 : 'Native P-TMSI',
    1 : 'Mapped P-TMSI'
    }

class PTMSIType(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('Value', bl=1, dic=_PTMSIType_dict)
        )


#------------------------------------------------------------------------------#
# Network Resource Identifier
# TS 24.008, 10.5.5.31
#------------------------------------------------------------------------------#

class NRICont(Envelope):
    _GEN = (
        Uint('Value', bl=10, rep=REPR_HEX),
        Uint('spare', bl=6)
        )


#------------------------------------------------------------------------------#
# Extended DRX parameters
# TS 24.008, 10.5.5.32
#------------------------------------------------------------------------------#

class ExtDRXParam(Envelope):
    _GEN = (
        Uint('PTX', bl=4),
        Uint('eDRX', bl=4)
        )


#------------------------------------------------------------------------------#
# User-Plane integrity indicator
# TS 24.008, 10.5.5.34
#------------------------------------------------------------------------------#

class UPIntegrityInd(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('Value', bl=1)
        )


#------------------------------------------------------------------------------#
# DCN-ID
# TS 24.008, 10.5.5.35
#------------------------------------------------------------------------------#
# Dedicated Core Network ID

class DCNID(Uint16):
    pass


#------------------------------------------------------------------------------#
# Non-3GPP NW provided policies
# TS 24.008, 10.5.5.37
#------------------------------------------------------------------------------#

_Non3GPPNWProvPol_dict = {
    0 : 'use of non-3GPP emergency numbers not permitted', 
    1 : 'use of non-3GPP emergency numbers permitted'
    }

class Non3GPPNWProvPol(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('Value', bl=1, dic=_Non3GPPNWProvPol_dict)
        )


#------------------------------------------------------------------------------#
# Access point name
# TS 24.008, 10.5.6.1
#------------------------------------------------------------------------------#
# referring TS 23.003

class _APNItem(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('Value')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(self[1].get_len)
        self[1].set_blauto(lambda: 8*self[0].get_val())


class APN(Sequence):
    _GEN = _APNItem('APNItem')
    
    def set_val(self, val):
        if isinstance(val, str_types):
            self.encode(val)
        else:
            Sequence.set_val(self, val)
    
    def encode(self, val):
        apn_items = val.split('.')
        Sequence.set_val(self, [{'Value': apn_item} for apn_item in apn_items])
    
    def decode(self, val):
        return '.'.join([apn_item[1] for apn_item in self.get_val()])


#------------------------------------------------------------------------------#
# Network service access point identifier
# TS 24.008, 10.5.6.2
#------------------------------------------------------------------------------#

_NSAPI_dict = {
    0 : _str_reserved,
    1 : _str_reserved,
    2 : _str_reserved,
    3 : _str_reserved,
    4 : _str_reserved
    }

class NSAPI(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Value', val=5, bl=4, dic=_NSAPI_dict)
        )


#------------------------------------------------------------------------------#
# Protocol configuration options
# TS 24.008, 10.5.6.3
#------------------------------------------------------------------------------#

_ProtConfig_dict = {
    # 3GPP additional parameters
    0x0001 : 'P-CSCF IPv6 Address Request',
    0x0002 : 'IM CN Subsystem Signaling Flag',
    0x0003 : 'DNS Server IPv6 Address Request',
    0x0004 : 'Policy Control rejection code',
    0x0005 : 'Selected Bearer Control Mode',
    0x0006 : 'Reserved',
    0x0007 : 'DSMIPv6 Home Agent Address',
    0x0008 : 'DSMIPv6 Home Network Prefix',
    0x0009 : 'DSMIPv6 IPv4 Home Agent Address',
    0x000A : 'IP address allocation via NAS signalling',
    0x000B : 'Reserved',
    0x000C : 'P-CSCF IPv4 Address',
    0x000D : 'DNS server IPv4 address request',
    0x000E : 'MSISDN Request',
    0x000F : 'IFOM-Support-Request',
    0x0010 : 'IPv4 Link MTU Request',
    0x0011 : 'Support of Local address in TFT indicator',
    0x0012 : 'P-CSCF Re-selection support',
    0x0013 : 'NBIFOM request indicator',
    0x0014 : 'NBIFOM mode',
    0x0015 : 'Non-IP Link MTU Request',
    0x0016 : 'APN rate control support indicator',
    
    # ETSI / IETF protocol identifiers
    0x8021 : 'IPCP',
    0xC021 : 'LCP',
    0xC023 : 'PAP',
    0xC223 : 'CHAP'
    }

class ProtConfigElt(Envelope):
    # when set to True, will decode the content into NCP / LCP / PAP / CHAP
    DECODE_INNER = True
    _ContLUT = {
        0x8021 : NCP,
        0xC021 : LCP,
        0xC023 : PAP,
        0xC223 : CHAP
        }
    
    _GEN = (
        Uint16('ID', val=0x8021, dic=_ProtConfig_dict),
        Uint8('Len'),
        Buf('Cont', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: 8*self[1].get_val())
    
    def set_val(self, val):
        if isinstance(val, (list, tuple)) and not isinstance(val[2], bytes_types):
            # eventually replace Cont by a NCP / LCP / PAP / CHAP Envelope
            if val[0] in self._ContLUT:
                self.replace(self[2], self._ContLUT[val[0]]('Cont'))
        elif isinstance(val, dict) and 'ID' in val and 'Cont' in val \
        and not isinstance(val['Cont'], bytes_types):
            # eventually replace Cont by a NCP / LCP / PAP / CHAP Envelope
            if val['ID'] in self._ContLUT:
                self.replace(self[2], self._ContLUT[val['ID']]('Cont'))
        Envelope.set_val(self, val)
        
    def _from_char(self, char):
        self[0]._from_char(char)
        self[1]._from_char(char)
        ident, cont = self[0].get_val(), None
        if self.DECODE_INNER and ident in self._ContLUT:
            cont = self._ContLUT[ident]('Cont')
            ccur, clen = char._cur, char._len_bit
            char._len_bit = ccur + 8*self[1].get_val()
            if char._len_bit > clen:
                raise(EltErr('{0} [_from_char]: bit length overflow'.format(self._name)))
            try:
                cont._from_char(char)
            except Exception:
                char._cur, char._len_bit = ccur, clen
            else:
                if char._cur < char._len_bit:
                    char._cur, char._len_bit = ccur, clen
                else:
                    self.replace(self[2], cont)
                    char._len_bit = clen
        if cont is None:
            self[2]._from_char(char)


class ProtConfig(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('spare', bl=4),
        Uint('Prot', bl=3, dic={0:'PPP with IP PDP'}),
        Sequence('Config', GEN=ProtConfigElt())
        )

#------------------------------------------------------------------------------#
# Packet data protocol address
# TS 24.008, 10.5.6.4
#------------------------------------------------------------------------------#

_PDPTypeOrg_dict = {
    0 : 'ETSI allocated',
    1 : 'IETF allocated',
    15 : 'Empty PDP type',
    }
_PDPTypeNum0_dict = {
    0 : 'reserved',
    1 : 'PPP',
    }
_PDPTypeNum1_dict = {
    33 : 'IPv4',
    87 : 'IPv6',
    141 : 'IPv4v6',
    }

class PDPAddr(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('TypeOrg', val=1, bl=4, dic=_PDPTypeOrg_dict),
        Uint8('Type', val=33),
        Buf('Addr', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_dicauto(self._set_pdpt_dic)
        # Addr can be empty, when PDPAddr is used within a request
        #self[3].set_blauto(self._set_addr_len)
    
    def _set_pdpt_dic(self):
        to = self[1]()
        if to == 0:
            return _PDPTypeNum0_dict
        elif to == 1:
            return _PDPTypeNum1_dict
        else:
            return None
    
    #def _set_addr_len(self):
    #    to, t = self[1](), self[2]()
    #    if to == 1:
    #        if t == 33:
    #            return 32
    #        elif t == 87:
    #            return 128
    #        elif t == 141:
    #            return 160
    #    return None
    
#------------------------------------------------------------------------------#
# Quality of service
# TS 24.008, 10.5.6.5
#------------------------------------------------------------------------------#

_ReliabClass_dict = {
    0 : 'subscribed reliability class',
    1 : 'unused; interpreted as unack GTP, ack LLC and RLC, protected data',
    2 : 'unack GTP, ack LLC and RLC, protected data',
    3 : 'unack GTP and LLC, ack RLC, protected data',
    4 : 'unack GTP, LLC and RLC, protected data',
    5 : 'unack GTP, LLC and RLC, unprotected data',
    6 : 'unack GTP and RLC, ack LLC, protected data',
    7 : _str_reserved,
    }

_DelayClass_dict = {
    0 : 'subscribed delay class',
    1 : 'delay class 1',
    2 : 'delay class 2',
    3 : 'delay class 3',
    4 : 'delay class 4 (best effort)',
    7 : _str_reserved,
    }

_PrecedClass_dict = {
    0 : 'subscribed precedence',
    1 : 'high priority',
    2 : 'normal priority',
    3 : 'low priority',
    4 : 'normal priority',
    7 : _str_reserved,
    }

_PeakTP_dict = {
    0 : 'subscribed peak throughput',
    1 : 'Up to 1 000 octet/s',
    2 : 'Up to 2 000 octet/s',
    3 : 'Up to 4 000 octet/s',
    4 : 'Up to 8 000 octet/s',
    5 : 'Up to 16 000 octet/s',
    6 : 'Up to 32 000 octet/s',
    7 : 'Up to 64 000 octet/s',
    8 : 'Up to 128 000 octet/s',
    9 : 'Up to 256 000 octet/s',
    }

_MeanTP_dict = {
    0 : 'subscribed mean throughput',
    1 : '100 octet/h',
    2 : '200 octet/h',
    3 : '500 octet/h',
    4 : '1 000 octet/h',
    5 : '2 000 octet/h',
    6 : '5 000 octet/h',
    7 : '10 000 octet/h',
    8 : '20 000 octet/h',
    9 : '50 000 octet/h',
    10: '100 000 octet/h',
    11: '200 000 octet/h',
    12: '500 000 octet/h',
    13: '1 000 000 octet/h',
    14: '2 000 000 octet/h',
    15: '5 000 000 octet/h',
    16: '10 000 000 octet/h',
    17: '20 000 000 octet/h',
    18: '50 000 000 octet/h',
    30: _str_reserved,
    31: 'Best effort'
    }

_ErronSDU_dict = {
    0 : 'Subscribed delivery of erroneous SDUs',
    1 : 'No detect',
    2 : 'Erroneous SDUs are delivered',
    3 : 'Erroneous SDUs are not delivered',
    7 : _str_reserved
    }

_DeliverOrd_dict = {
    0 : 'Subscribed delivery order',
    1 : 'With delivery order',
    2 : 'Without delivery order',
    3 : _str_reserved
    }

_TraffClass_dict = {
    0 : 'Subscribed traffic class',
    1 : 'Conversational class',
    2 : 'Streaming class',
    3 : 'Interactive class',
    4 : 'Background class',
    7 : _str_reserved
    }

_SignalInd_dict = {
    0 : 'Not optimised for signalling',
    1 : 'Optimised for signalling'
    }

_SourceStats_dict = {
    0 : 'unknown',
    1 : 'speech'
    }

# TODO: build dicts for DL / UL max / guaranteed throughput

class QoS(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('spare', bl=2),
        Uint('DelayClass', bl=3, dic=_DelayClass_dict),
        Uint('ReliabilityClass', bl=3, dic=_ReliabClass_dict), # 1
        Uint('PeakThroughput', bl=4, dic=_PeakTP_dict),
        Uint('spare', bl=1),
        Uint('PrecedenceClass', bl=3, dic=_PrecedClass_dict), # 2
        Uint('spare', bl=3),
        Uint('MeanThroughput', bl=5, dic=_MeanTP_dict), # 3
        Uint('TrafficClass', bl=3, dic=_TraffClass_dict),
        Uint('DeliveryOrder', bl=2, dic=_DeliverOrd_dict),
        Uint('ErroneousSDU', bl=3, dic=_ErronSDU_dict), # 4
        Uint8('MaxSDUSize'),
        Uint8('MaxULBitrate'),
        Uint8('MaxDLBitrate'),
        Uint('ResidualBER', bl=4),
        Uint('SDUErrorRatio', bl=4), # 8
        Uint('TransferDelay', bl=6),
        Uint('TrafficHandlingPriority', bl=2), # 9
        Uint8('GuaranteedULBitrate'),
        Uint8('GuaranteedDLBitrate'),
        Uint('spare', bl=3),
        Uint('SignallingInd', bl=1, dic=_SignalInd_dict),
        Uint('SourceStatsDesc', bl=4, dic=_SourceStats_dict), # 12
        Uint8('MaxDLBitrateExt', trans=True),
        Uint8('GuaranteedDLBitrateExt', trans=True),
        Uint8('MaxULBitrateExt', trans=True),
        Uint8('GuaranteedULBitrateExt', trans=True),
        Uint8('MaxDLBitrateExt2', trans=True),
        Uint8('GuaranteedDLBitrateExt2', trans=True),
        Uint8('MaxULBitrateExt2', trans=True),
        Uint8('GuaranteedULBitrateExt2', trans=True),
        )
    
    def set_val(self, vals):
        # in case extended values are set, make them non-transparent
        if vals is None:
            self._set_trans_dlbrext(True)
            self._set_trans_ulbrext(True)
            self._set_trans_dlbrext2(True)
            self._set_trans_ulbrext2(True)
        elif isinstance(vals, (tuple, list)):
            if len(vals) > 29:
                self._set_trans_dlbrext(False)
                self._set_trans_ulbrext(False)
                self._set_trans_dlbrext2(False)
                self._set_trans_ulbrext2(False)
            elif len(vals) > 27:
                self._set_trans_dlbrext(False)
                self._set_trans_ulbrext(False)
                self._set_trans_dlbrext2(False)
            elif len(vals) > 25:
                self._set_trans_dlbrext(False)
                self._set_trans_ulbrext(False)
            elif len(vals) > 23:
                self._set_trans_dlbrext(False)
        elif isinstance(vals, dict):
            if 'MaxULBitrateExt2' in vals or 'GuaranteedULBitrateExt2' in vals:
                self._set_trans_dlbrext(False)
                self._set_trans_ulbrext(False)
                self._set_trans_dlbrext2(False)
                self._set_trans_ulbrext2(False)
            elif 'MaxDLBitrateExt2' in vals or 'GuaranteedDLBitrateExt2' in vals:
                self._set_trans_dlbrext(False)
                self._set_trans_ulbrext(False)
                self._set_trans_dlbrext2(False)
            elif 'MaxULBitrateExt' in vals or 'GuaranteedULBitrateExt' in vals:
                self._set_trans_dlbrext(False)
                self._set_trans_ulbrext(False)
            elif 'MaxDLBitrateExt' in vals or 'GuaranteedDLBitrateExt' in vals:
                self._set_trans_dlbrext(False)
        Envelope.set_val(self, vals)
    
    def _set_trans_dlbrext(self, trans):
        self[23].set_trans(trans)
        self[24].set_trans(trans)
    
    def _set_trans_ulbrext(self, trans):
        self[25].set_trans(trans)
        self[26].set_trans(trans)
    
    def _set_trans_dlbrext2(self, trans):
        self[27].set_trans(trans)
        self[28].set_trans(trans)
    
    def _set_trans_ulbrext2(self, trans):
        self[29].set_trans(trans)
        self[30].set_trans(trans)
    
    def _from_char(self, char):
        # in case long-enough buffer is available, make extended fields non-transparent
        l = char.len_byte()
        if l > 18:
            self._set_trans_dlbrext(False)
            self._set_trans_ulbrext(False)
            self._set_trans_dlbrext2(False)
            self._set_trans_ulbrext2(False)
        elif l > 16:
            self._set_trans_dlbrext(False)
            self._set_trans_ulbrext(False)
            self._set_trans_dlbrext2(False)
        elif l > 14:
            self._set_trans_dlbrext(False)
            self._set_trans_ulbrext(False)
        elif l > 12:
            self._set_trans_dlbrext(False)
        Envelope._from_char(self, char)


#------------------------------------------------------------------------------#
# Re-attempt indicator
# TS 24.008, 10.5.6.5a
#------------------------------------------------------------------------------#

_EPLMNC_dict = {
    0 : 'MS is allowed to re-attempt the procedure in an equivalent PLMN',
    1 : 'MS is not allowed to re-attempt the procedure in an equivalent PLMN'
    }

_RATC_dict = {
    0 : 'MS is allowed to re-attempt the procedure in S1 mode',
    1 : 'MS is not allowed to re-attempt the procedure in S1 mode'
    }

class ReattemptInd(Envelope):
    _GEN = (
        Uint('spare', bl=6),
        Uint('EPLMNC', bl=1, dic=_EPLMNC_dict),
        Uint('RATC', bl=1, dic=_RATC_dict)
        )


#------------------------------------------------------------------------------#
# SM Cause
# TS 24.008, 10.5.6.6
#------------------------------------------------------------------------------#

SMCause_dict = {
    8 : 'Operator Determined Barring',
    24 : 'MBMS bearer capabilities insufficient for the service',
    25 : 'LLC or SNDCP failure(A/Gb mode only)',
    26 : 'Insufficient resources',
    27 : 'Missing or unknown APN',
    28 : 'Unknown PDP address or PDP type',
    29 : 'User authentication failed',
    30 : 'Activation rejected by GGSN, Serving GW or PDN GW',
    31 : 'Activation rejected, unspecified',
    32 : 'Service option not supported',
    33 : 'Requested service option not subscribed',
    34 : 'Service option temporarily out of order',
    35 : 'NSAPI already used (not sent)',
    36 : 'Regular deactivation',
    37 : 'QoS not accepted',
    38 : 'Network failure',
    39 : 'Reactivation requested',
    40 : 'Feature not supported',
    41 : 'Semantic error in the TFT operation',
    42 : 'Syntactical error in the TFT operation',
    43 : 'Unknown PDP context',
    44 : 'Semantic errors in packet filter(s)',
    45 : 'Syntactical errors in packet filter(s)',
    46 : 'PDP context without TFT already activated',
    47 : 'Multicast group membership time-out',
    48 : 'Request rejected, BCM violation',
    50 : 'PDP type IPv4 only allowed',
    51 : 'PDP type IPv6 only allowed',
    52 : 'Single address bearers only allowed',
    56 : 'Collision with network initiated request',
    60 : 'Bearer handling not supported',
    65 : 'Maximum number of PDP contexts reached',
    66 : 'Requested APN not supported in current RAT and PLMN combination',
    81 : 'Invalid transaction identifier value',
    95 : 'Semantically incorrect message',
    96 : 'Invalid mandatory information',
    97 : 'Message type non-existent or not implemented',
    98 : 'Message type not compatible with the protocol state',
    99 : 'Information element non-existent or not implemented',
    100 : 'Conditional IE error',
    101 : 'Message not compatible with the protocol state',
    111 : 'Protocol error, unspecified',
    112 : 'APN restriction value incompatible with active PDP context',
    113 : 'Multiple accesses to a PDN connection not allowed'
    }

class SMCause(Uint8):
    _dic = SMCause_dict


#------------------------------------------------------------------------------#
# Linked TI
# TS 24.008, 10.5.6.7
#------------------------------------------------------------------------------#
# see transaction identifier in TS 24.007, section 11.2.3.1.3

class TransId(Envelope):
    _GEN = (
        Uint('Flag', bl=1, dic={0: 'initiator', 1: 'responder'}),
        Uint('TIO', bl=3),
        Uint('spare', bl=4),
        Uint('Ext', val=1, bl=1, trans=True),
        Uint('TIE', bl=7, trans=True),
        Uint8('TI', trans=True) # virtual field to get the TI value easily
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[5].set_valauto(self._set_ti)
    
    def _set_ti(self):
        tio = self[1]()
        if tio == 7 and not self[4].get_trans():
            return self[4]()
        else:
            return tio
    
    def set_val(self, vals):
        if isinstance(vals, dict) and 'TI' in vals:
            ti = vals['TI']
            del vals['TI']
            if 0 <= ti < 7:
                self[1].set_val(ti)
                self[3].set_trans(True)
                self[4].set_trans(True)
            elif ti < 128:
                # extended
                self[1].set_val(7)
                self[3].set_trans(False)
                self[4].set_trans(False)
                self[4].set_val(ti)
        Envelope.set_val(self, vals)
    
    def _from_char(self, char):
        if char.len_byte() > 1:
            self[3].set_trans(False)
            self[4].set_trans(False)
        Envelope._from_char(self, char)


#------------------------------------------------------------------------------#
# LLC service access point identifier
# TS 24.008, 10.5.6.9
#------------------------------------------------------------------------------#

_LLC_SAPI_dict = {
    0 : 'not assigned',
    1 : _str_reserved,
    2 : _str_reserved,
    4 : _str_reserved,
    6 : _str_reserved,
    7 : _str_reserved,
    8 : _str_reserved,
    10: _str_reserved,
    11: _str_reserved,
    12: _str_reserved,
    13: _str_reserved,
    14: _str_reserved,
    15: _str_reserved
    }

class LLC_SAPI(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Value', bl=4, dic=_LLC_SAPI_dict)
        )


#------------------------------------------------------------------------------#
# Tear Down Indicator
# TS 24.008, 10.5.6.10
#------------------------------------------------------------------------------#

class TearDownInd(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('Value', bl=1, dic={0:'teardown not requested', 1:'teardown requested'}),
        )


#------------------------------------------------------------------------------#
# Packet Flow Identifier
# TS 24.008, 10.5.6.11
#------------------------------------------------------------------------------#

_PktFlowId_dict = {
    0: 'Best Effort',
    1: 'Signaling',
    2: 'SMS',
    3: 'TOM8'
    }

class PacketFlowId(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Value', bl=7, dic=_PktFlowId_dict)
        )


#------------------------------------------------------------------------------#
# Traffic Flow Template
# TS 24.008, 10.5.6.12
#------------------------------------------------------------------------------#

_TFTOpcode_dict = {
    0 : 'Ignore this IE',
    1 : 'Create new TFT',
    2 : 'Delete existing TFT',
    3 : 'Add packet filters to existing TFT',
    4 : 'Replace packet filters in existing TFT',
    5 : 'Delete packet filters from existing TFT',
    6 : 'No TFT operation',
    7 : _str_reserved
    } 

_PktFilterDir_dict = {
    0 : 'pre Rel-7 TFT filter',
    1 : 'downlink only',
    2 : 'uplink only',
    3 : 'bidirectional'
    }

_PktFilterCompType_dict = {
    16 : 'IPv4 remote address type',
    17 : 'IPv4 local address type ',
    32 : 'IPv6 remote address type',
    33 : 'IPv6 remote address/prefix length type',
    35 : 'IPv6 local address/prefix length type',
    48 : 'Protocol identifier/Next header type',
    64 : 'Single local port type',
    65 : 'Local port range type',
    80 : 'Single remote port type',
    81 : 'Remote port range type',
    96 : 'Security parameter index type',
    112 : 'Type of service/Traffic class type',
    128 : 'Flow label type'
    }

# if TFT opcode == 0, E == 0 and no pkt filters must be there 
# if TFT opcode == 5, only pkt filters' id are provided in the pkt filters list
# TFTPktFilter content if made of a sequence of components

class TFTPktFilterId(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Id', bl=4)
        )


class _CompIPv4(Envelope):
    _GEN = (
        Buf('Address', bl=32, rep=REPR_HEX),
        Buf('Netmask', bl=32, rep=REPR_HEX)
        )


class _CompIPv6(Envelope):
    _GEN = (
        Buf('Address', bl=128, rep=REPR_HEX),
        Buf('Netmask', bl=128, rep=REPR_HEX)
        )


class _CompIPv6Pref(Envelope):
    _GEN = (
        Buf('Address', bl=128, rep=REPR_HEX),
        Uint8('PrefixLen')
        )


class _CompPortRange(Envelope):
    _GEN = (
        Uint16('PortLo'),
        Uint16('PortHi')
        )


class _CompTrafficClass(Envelope):
    _GEN = (
        Uint8('Class'),
        Uint8('Mask')
        )


class TFTPktFilterComp(Envelope):
    _GEN = (
        Uint8('Type', dic=_PktFilterCompType_dict),
        Alt('Value', GEN={
            16 : _CompIPv4('IPv4'),
            17 : _CompIPv4('IPv4'),
            32 : _CompIPv6('IPv6'),
            33 : _CompIPv6Pref('IPv6Pref'),
            35 : _CompIPv6Pref('IPv6Pref'),
            48 : Uint8('ProtId'),
            64 : Uint16('Port'),
            65 : _CompPortRange('PortRange'),
            80 : Uint16('Port'),
            81 : _CompPortRange('PortRange'),
            96 : Uint32('SPI'),
            112 : _CompTrafficClass('TrafficClass'),
            128 : Uint24('FlowLabel')
            },
            DEFAULT=Buf('unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()['Type'].get_val())
        )


class TFTPktFilter(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('Dir', bl=2, dic=_PktFilterDir_dict),
        Uint('Id', bl=4),
        Uint8('Precedence'),
        Uint8('Len'),
        Sequence('Cont', GEN=TFTPktFilterComp())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['Len'].set_valauto(lambda: self['Cont'].get_len())
        self['Cont'].set_blauto(lambda: self['Len'].get_val()<<3)


class TFTParameter(Envelope):
    _GEN = (
        Uint8('Id'),
        Uint8('Len'),
        Buf('Cont', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(self[2].get_len)
        self[2].set_blauto(lambda: 8*self[1]())


class TFT(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('Opcode', bl=3, dic=_TFTOpcode_dict),
        Uint('E', bl=1, dic={0: 'no parameters list', 1: 'parameters list included'}),
        Uint('NumPktFilters', bl=4),
        Sequence('PktFilterIds', GEN=TFTPktFilterId()),
        Sequence('PktFilters', GEN=TFTPktFilter()),
        Sequence('Parameters', GEN=TFTParameter())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: self[3].get_num() if \
            self[0]() == 5 else self[4].get_num())
        self[3].set_transauto(lambda: self[0]() != 5)
        self[3].set_numauto(lambda: self[2]())
        self[4].set_transauto(lambda: self[0]() == 5)
        self[4].set_numauto(lambda: self[2]())
        self[5].set_transauto(lambda: self[1]() == 0)
        # there is no num automation of the Parameters
        # hence, all remaining buffer will be consumed when calling _from_char()


#------------------------------------------------------------------------------#
# Temporary mobile group identity (TMGI)
# TS 24.008, 10.5.6.13
#------------------------------------------------------------------------------#

class TMGI(Envelope):
    _GEN = (
        Uint24('MBMSServID', rep=REPR_HEX),
        PLMN()
        )
    
    def set_val(self, vals):
        if isinstance(vals, (tuple, list)) and len(vals) == 1:
            self[1].set_trans(True)  
        elif isinstance(vals, dict) and 'PLMN' not in vals:
            self[1].set_trans(True)  
        Envelope.set_val(self, vals)
    
    def _from_char(self, char):
        if char.len_bit() < 48:
            self[1].set_trans(True)
        Envelope._from_char(self, char)


#------------------------------------------------------------------------------#
# MBMS bearer capabilities
# TS 24.008, 10.5.6.14
#------------------------------------------------------------------------------#

class MBMSBearerCap(Envelope):
    _GEN = (
        Uint8('MaxDLBitrate'),
        Uint8('MaxDLBitrateExt')
        )

#------------------------------------------------------------------------------#
# Enhanced network service access point identifier
# TS 24.008, 10.5.6.16
#------------------------------------------------------------------------------#

_ENSAPI_dict = {0xff: _str_reserved}
for i in range(0, 0x7f):
    _ENSAPI_dict[i] = _str_reserved
for i in range(0x80, 0xfe):
    _ENSAPI_dict[i] = 'NSAPI_%i_MBMS' % i

class ENSAPI(Uint8):
    _dic = _ENSAPI_dict


#------------------------------------------------------------------------------#
# Request type
# TS 24.008, 10.5.6.17
#------------------------------------------------------------------------------#

RequestType_dict = {
    1 : 'Initial request',
    2 : 'Handover',
    3 : 'Unused. Interpreted as initial request',
    4 : 'Emergency',
    }


#------------------------------------------------------------------------------#
# Notification indicator
# TS 24.008, 10.5.6.18
#------------------------------------------------------------------------------#

class NotificationInd(Uint8):
    _dic = {0:'SRVCC handover cancelled, IMS session re-establishment required'}


#------------------------------------------------------------------------------#
# Connectivity type
# TS 24.008, 10.5.6.19
#------------------------------------------------------------------------------#

ConnectivityType_dict = {
    0 : 'The PDN connection type is not indicated',
    1 : 'The PDN connection is considered a LIPA PDN connection'
    }


#------------------------------------------------------------------------------#
# WLAN offload acceptability
# TS 24.008, 10.5.6.20
#------------------------------------------------------------------------------#

_UTRANOffAcc_dict = {
    0 : 'Offloading the traffic of the PDN connection via a WLAN when in Iu mode is not acceptable',
    1 : 'Offloading the traffic of the PDN connection via a WLAN when in Iu mode is acceptable'
    }

_EUTRANOffAcc_dict = {
    0 : 'Offloading the traffic of the PDN connection via a WLAN when in S1 mode is not acceptable',
    1 : 'Offloading the traffic of the PDN connection via a WLAN when in S1 mode is acceptable'
    }

class WLANOffloadAccept(Envelope):
    _GEN = (
        Uint('spare', bl=2),
        Uint('UTRANOffloadAccept', bl=1, dic=_UTRANOffAcc_dict),
        Uint('EUTRANOffloadAccept', bl=1, dic=_EUTRANOffAcc_dict)
        )


#------------------------------------------------------------------------------#
# NBIFOM container
# TS 24.008, 10.5.6.21
#------------------------------------------------------------------------------#

_NBIFOMParamID_dict = {
    0 : 'Not assigned',
    1 : 'NBIFOM mode',
    2 : 'NBIFOM default access',
    3 : 'NBIFOM status',
    4 : 'NBIFOM routing rules',
    5 : 'NBIFOM IP flow mapping',
    6 : 'NBIFOM RAN rules handling',
    7 : 'NBIFOM Access stratum status',
    8 : 'NBIFOM access usability indication',
    }

class NBIFOMParameter(Envelope):
    _GEN = (
        Uint8('ParamID', dic=_NBIFOMParamID_dict),
        Uint8('ParamLen'),
        Buf('Param', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: self[1].get_val()<<3)


class NBIFOMContainer(Sequence):
    _GEN = NBIFOMParameter()


#------------------------------------------------------------------------------#
# PDP Context Status
# TS 24.008, 10.5.7.1
#------------------------------------------------------------------------------#

_PDPCtxtStat_dict = {
    0 : 'PDP-INACTIVE',
    1 : 'PDP-ACTIVE'
    }

class PDPCtxtStat(Envelope):
    _GEN = (
        Uint('NSAPI_7', bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_6', bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_5', bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_4', bl=1),
        Uint('NSAPI_3', bl=1),
        Uint('NSAPI_2', bl=1),
        Uint('NSAPI_1', bl=1),
        Uint('NSAPI_0', bl=1),
        Uint('NSAPI_15', bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_14', bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_13', bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_12', bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_11', bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_10', bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_9', bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_8', bl=1, dic=_PDPCtxtStat_dict)
        )


#------------------------------------------------------------------------------#
# Radio Priority
# TS 24.008, 10.5.7.2 and 10.5.7.5
#------------------------------------------------------------------------------#

RadioPrio_dict = {
    1 : 'priority level 1 (highest)',
    2 : 'priority level 2',
    3 : 'priority level 3',
    4 : 'priority level 4 (lowest)'
    }

class RadioPriority(Envelope):
    _GEN = (
        Uint('spare', bl=1),
        Uint('Value', bl=3, dic=RadioPrio_dict)
        )


#------------------------------------------------------------------------------#
# GPRS Timer
# TS 24.008, 10.5.7.3
#------------------------------------------------------------------------------#

_GPRSTimerUnit_dict = _MMTimerUnit_dict

class GPRSTimer(Envelope):
    _GEN = (
        Uint('Unit', bl=3, dic=_GPRSTimerUnit_dict),
        Uint('Value', bl=5)
        )
    
    def get_time(self):
        """returns the timer set in seconds
        """
        unit, val = self.get_val()
        if unit == 0:
            return val*2
        elif unit == 1:
            return val*60
        elif unit == 2:
            return val*360
        else:
            return 0


#------------------------------------------------------------------------------#
# GPRS Timer 3
# TS 24.008, 10.5.7.4a
#------------------------------------------------------------------------------#

_GPRSTimer3Unit_dict = {
    0 : '10 min',
    1 : '1 hour',
    2 : '10 hours',
    3 : '2 sec',
    4 : '30 sec',
    5 : '1 min',
    6 : '320 hours',
    7 : 'timer deactivated'
    }

_GPRSTimer3Unit_mult = {
    0 : 600,
    1 : 3600,
    2 : 36000,
    3 : 2,
    4 : 30,
    5 : 60,
    6 : 1152000,
    7 : 0
    }


class GPRSTimer3(Envelope):
    _GEN = (
        Uint('Unit', bl=3, dic=_GPRSTimer3Unit_dict),
        Uint('Value', bl=5)
        )
    
    def get_time(self):
        """returns the timer set in seconds
        """
        unit, val = self.get_val()
        return val * _GPRSTimer3Unit_mult[unit]


#------------------------------------------------------------------------------#
# MBMS context status
# TS 24.008, 10.5.7.6
#------------------------------------------------------------------------------#

class MBMSCtxtStat(Envelope):
    
    ENV_SEL_TRANS = False
    
    #_GEN = () # built at __init__()
    
    def __init__(self, *args, **kw):
        GEN = []
        for i in range(16):
            for j in range(7, -1, -1):
                GEN.append( Uint('NSAPI_%i' % (128+8*i+j), bl=1, dic=_PDPCtxtStat_dict) )
        kw['GEN'] = tuple(GEN)
        Envelope.__init__(self, *args, **kw)
    
    def _from_char(self, char):
        l = char.len_bit()
        self.enable_upto(l-1)
        self.disable_from(l-1)
        Envelope._from_char(self, char)
    
    def disable_from(self, ind):
        """disables all elements from index `ind' excluded (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = self._by_name.index(ind)
        [e.set_trans(True) for e in self._content[ind:]]
    
    def enable_upto(self, ind):
        """enables all elements up to index `ind' included (integer -bit offset- 
        or element name)
        """
        if isinstance(ind, str_types) and ind in self._by_name:
            ind = 1 + self._by_name.index(ind)
        [e.set_trans(False) for e in self._content[:ind]]


#------------------------------------------------------------------------------#
# Uplinlk data status
# TS 24.008, 10.5.7.7
#------------------------------------------------------------------------------#

_ULDataStat_dict = {
    1 : 'UL data pending'
    }

class ULDataStat(Envelope):
    _GEN = (
        Uint('NSAPI_7', bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_6', bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_5', bl=1, dic=_ULDataStat_dict),
        Uint('spare', bl=5),
        Uint('NSAPI_15', bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_14', bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_13', bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_12', bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_11', bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_10', bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_9', bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_8', bl=1, dic=_ULDataStat_dict)
        )

#------------------------------------------------------------------------------#
# Device Properties
# TS 24.008, 10.5.7.8
#------------------------------------------------------------------------------#

class DeviceProp(Envelope):
    _GEN = (
        Uint('spare', bl=3),
        Uint('LowPriority', bl=1)
        )
