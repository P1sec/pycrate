# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.1
# *
# * Copyright © 2017. Benoit Michau. ANSSI.
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
# * File Name : pycrate_mobile/TS24008_IE.py
# * Created : 2017-06-12
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# 3GPP TS 24.008: Mobile radio interface layer 3 specification
# release 13 (d90)
#------------------------------------------------------------------------------#

from binascii import unhexlify

from pycrate_core.utils  import *
from pycrate_core.elt    import Envelope, Array, REPR_RAW, REPR_HEX, REPR_BIN, REPR_HD, REPR_HUM
from pycrate_core.base   import *
from pycrate_core.repr   import *
from pycrate_core.charpy import Charpy

from pycrate_mobile.MCC_MNC import MNC_dict

#------------------------------------------------------------------------------#
# TS 24.008 IE specified with CSN.1
#------------------------------------------------------------------------------#

from pycrate_csn1dir.mscm3          import Classmark_3_Value_part
from pycrate_csn1dir.msnetcap       import MS_network_capability_value_part
from pycrate_csn1dir.msracap        import MS_RA_capability_value_part
from pycrate_csn1dir.rcvnpdunumlist import Receive_N_PDU_Number_list_value

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


def encode_7b(txt):
    # FlUxIuS encoding
    new, bit, len_t = [], 0, len(txt)
    for i in range(len_t):
        if bit > 7:
            bit=0
        mask = (0Xff >> (7-bit))
        if i < len_t-1:
            group = (ord(txt[i+1]) & mask)
        else:
            group = 0
        add = (group << 7-bit)
        if bit != 7:
            new.append( (ord(txt[i]) >> bit) | add )
        bit += 1
    if python_version < 3:
        return ''.join(map(chr, new))
    else:
        return bytes(new)


def decode_7b(buf):
    # TODO: implement a faster decoding, just like the encoding
    if python_version < 3:
        char = Charpy(''.join(reversed(buf)))
    else:
        char = Charpy(bytes(reversed(buf)))
    # jump over the padding bits from the end of buf
    chars_num = (8*len(buf)) // 7
    char._cur = (8*len(buf))-(7*chars_num)
    # get all chars
    chars = [char.get_uint(7) for i in range(chars_num)]
    # reverse and return the corresponding str
    if python_version < 3:
        return ''.join(map(chr, reversed(chars)))
    else:
        return bytes(reversed(chars)).decode('ascii')

#------------------------------------------------------------------------------#
# TS 24.008 IE common objects
#------------------------------------------------------------------------------#

# BCD string is a string of digits, each digit being coded on a nibble (4 bits)
# Here, BufBCD is a subclass of pycrate_core.base.Buf
# with additionnal methods: encode(), decode()

class BufBCD(Buf):
    """Child of pycrate_core.base.Buf object
    with additional encode() and decode() capabilities in order to handle
    BCD encoding
    """
    
    _rep = REPR_HUM
    _dic = None # dict lookup not supported for repr()
    
    # characters accepted in a BCD number
    _chars = '0123456789*#abc'
    
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
        if isinstance(val, str):
            self.encode(val)
        else:
            Buf.set_val(self, val)
    
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
            ret = [self._chars.find(c) for c in bcd]
        except:
            raise(PycrateErr('{0}: invalid BCD string to encode, {1!r}'\
                  .format(self._name, bcd)))
        if len(ret) % 2:
            ret.append( 0xF )
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
        if isinstance(val, str_types):
            self.encode(val)
        else:
            Buf.set_val(self, val)
    
    def decode(self):
        """returns the encoded string of digits
        """
        if python_version < 3:
            num = [ord(c) for c in self.get_val()]
        else:
            num = self.get_val()
        plmn = []
        [plmn.extend((o>>4, o&0xF)) for o in num]
        if plmn[2] == 15:
            # 3-digits MNC
            return ''.join((str(plmn[1]), str(plmn[0]), str(plmn[3]),
                            str(plmn[5]), str(plmn[4])))
        else:
            # 3-digits MNC
            return ''.join((str(plmn[1]), str(plmn[0]), str(plmn[3]),
                            str(plmn[5]), str(plmn[4]), str(plmn[2])))
    
    def encode(self, plmn='00101'):
        """encode the given PLMN string and store the resulting buffer in 
        self._val
        """
        if not plmn.isdigit():
            raise(PycrateErr('{0}: invalid PLMN string to encode, {1!r}'\
                  .format(self._name, bcd)))
        if len(plmn) == 5:
            plmn += 'F'
        elif len(plmn) != 6:
            raise(PycrateErr('{0}: invalid PLMN string to encode, {1!r}'\
                  .format(self._name, bcd)))
        #
        if python_version > 2:
            plmn = tuple(plmn)
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
        Uint16('LAC', val=0, rep=REPR_HEX)
        )
    
    def set_val(self, vals):
        if isinstance(vals, dict) and 'plmn' in vals and 'lac' in vals:
            self.encode(vals['plmn'], vals['lac'])
        else:
            Envelope.set_val(self, vals)
    
    def encode(self, *args):
        if args:
            self[0].encode(args[0])
            if len(args) > 1:
                self[1].set_val(args[1])
    
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
        Uint('spare', val=0, bl=5, rep=REPR_HEX),
        Uint('Type', val=0, bl=3, dic=IDType_dict)
        )

class IDTemp(Envelope):
    _GEN = (
        Uint('Digit1', val=0xF, bl=4, rep=REPR_HEX),
        Uint('Odd', val=0, bl=1),
        Uint('Type', val=IDTYPE_TMSI, bl=3, dic=IDType_dict),
        Uint32('TMSI', val=0, rep=REPR_HEX)
        )

class IDDigit(Envelope):
    _GEN = (
        Uint('Digit1', val=0xF, bl=4, rep=REPR_HEX),
        Uint('Odd', val=0, bl=1),
        Uint('Type', val=IDTYPE_IMSI, bl=3, dic=IDType_dict),
        Buf('Digits', val=b'', rep=REPR_HEX)
        )

class IDGroup(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=2),
        Uint('MBMSSessInd', val=0, bl=1),
        Uint('MCCMNCInd', val=0, bl=1),
        Uint('Odd', val=0, bl=1),
        Uint('Type', val=IDTYPE_TMGI, dic=IDType_dict),
        Uint24('MBMSServID', val=0, rep=REPR_HEX),
        PLMN(),
        Uint8('MBMSSessID', val=0)
        )
    
    def __init__(self, *args, **kw):
        Envelope.__init__(self, *args, **kw)
        self[6].set_transauto(lambda: False if self[2].get_val() else True)
        self[7].set_transauto(lambda: False if self[1].get_val() else True)

class ID(Envelope):
    
    _IDNone  = IDNone()
    _IDTemp  = IDTemp()
    _IDDigit = IDDigit()
    _IDGroup = IDGroup()
    
    def set_val(self, vals):
        if isinstance(vals, dict) and 'type' in vals and 'ident' in vals:
            self.encode(vals['type'], vals['ident'])
        else:
            Envelope.set_val(self, vals[0])
    
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
            self._content = self._IDNone._content
            self._by_id   = self._IDNone._by_id
            self._by_name = self._IDNone._by_name
        #
        elif type == IDTYPE_TMSI:
            self._content = self._IDTemp._content
            self._by_id   = self._IDTemp._by_id
            self._by_name = self._IDTemp._by_name
            self[3].set_val(ident)
        #
        elif type in (IDTYPE_IMSI, IDTYPE_IMEI, IDTYPE_IMEISV):
            if not ident.isdigit():
                raise(PycrateErr('{0}: invalid identity to encode, {1!r}'\
                      .format(self._name, ident)))
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
                self._content = self._IDTemp._content
                self._by_id   = self._IDTemp._by_id
                self._by_name = self._IDTemp._by_name
                self[0]._val = spare >> 1
                self[1]._val = spare & 1
                self[3]._from_char(char)
            #
            elif type in (IDTYPE_IMSI, IDTYPE_IMEI, IDTYPE_IMEISV):
                self._content = self._IDDigit._content
                self._by_id   = self._IDDigit._by_id
                self._by_name = self._IDDigit._by_name
                self[0]._val = spare >> 1
                self[1]._val = spare & 1
                self[2]._val = type
                self[3]._from_char(char)   
            #
            elif type == IDTYPE_TMGI:
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
            else:
                log('WNG: ID type unhandled, %i' % type)
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
        Uint('spare', val=0, bl=1),
        Uint('RevLevel', val=2, bl=2, dic=_RevLevel_dict),
        Uint('EarlyCmCap', val=0, bl=1),
        Uint('NoA51', val=0, bl=1),
        Uint('RFClass', val=0, bl=3, dic=_RFClass_dict)
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
        Uint('spare', val=0, bl=1),
        Uint('RevLevel', val=2, bl=2, dic=_RevLevel_dict),
        Uint('EarlyCmCap', val=0, bl=1),
        Uint('NoA51', val=0, bl=1),
        Uint('RFClass', val=0, bl=3, dic=_RFClass_dict),
        Uint('spare', val=0, bl=1),
        Uint('PSCap', val=0, bl=1),
        Uint('SSScreeningCap', val=0, bl=2, dic=_SSScreen_dict),
        Uint('MTSMSCap', val=0, bl=1),
        Uint('VBSNotifCap', val=0, bl=1),
        Uint('VGCSNotifCap', val=0, bl=1),
        Uint('FCFreqCap', val=0, bl=1),
        Uint('MSCm3Cap', val=0, bl=1),
        Uint('spare', val=0, bl=1),
        Uint('LCSVACap', val=0, bl=1),
        Uint('UCS2', val=0, bl=1),
        Uint('SoLSACap', val=0, bl=1),
        Uint('CMServPrompt', val=0, bl=1),
        Uint('A53', val=0, bl=1),
        Uint('A52', val=0, bl=1)
        )


#------------------------------------------------------------------------------#
# Priority Level
# TS 24.008, 10.5.1.11
#------------------------------------------------------------------------------#

_PriorityLevel_dict = {
    0 : 'no priority applied',
    1 : 'call priority level 4',
    2 : 'call priority level 3',
    3 : 'call priority level 2',
    4 : 'call priority level 1',
    5 : 'call priority level 0',
    6 : 'call priority level B',
    7 : 'call priority level A'
    }

class PriorityLevel(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=1),
        Uint('CallPriority', val=0, bl=3, dic=_PriorityLevel_dict)
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
        Uint('spare', val=0, bl=3),
        Uint('ExtPeriodTimers', val=0, bl=1)
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
    3 : 'Reserved'
    }

class LocUpdateType(Envelope):
    _GEN = (
        Uint('FollowOnReq', val=0, bl=1),
        Uint('spare', val=0, bl=1),
        Uint('Type', val=0, bl=2, dic=_LocUpdType_dict)
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
        Uint('AddCountryInitials', val=0, bl=1),
        Uint('SpareBits', val=0, bl=3),
        Buf('Name', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kw):
        val = None
        if 'val' in kw:
            val = kw['val']
            del kw['val']
        Envelope.__init__(self, *args, **kw)
        if val:
            if isinstance(val, (tuple, list)):
                self[0].set_val(val[0])
                self[2].set_val(val[2])
                if val[1] in (CODTYPE_7B, CODTYPE_UCS2):
                    self.encode(val[1], val[4])
                else:
                    self[1].set_val(val[1])
                    self[3].set_val(val[3])
                    self[4].set_val(val[4])
            elif isinstance(val, dict):
                if 'Coding' in val and 'Name' in val and \
                val['Coding'] in (CODTYPE_7B, CODTYPE_UCS2):
                    self.encode(val['Coding'], val['Name'])
                else:
                    self.set_val(val)
    
    def decode(self):
        """returns the textual network name
        """
        coding = self[1].get_val()
        if coding == CODTYPE_7B:
            return decode_7b(self[4].get_val())
        elif coding == CODTYPE_UCS2:
            # WNG: this will certainly fail in Python2
            return self[4].get_val().decode('utf16')
        else:
            return None
    
    def encode(self, coding=CODTYPE_7B, name=u''):
        """sets the network name with given coding type
        """
        if coding == CODTYPE_7B:
            self[1]._val = CODTYPE_7B
            self[3]._val = (8 - ((7*len(name))%8)) % 8
            self[4]._val = encode_7b(name)
        elif coding == CODTYPE_UCS2:
            self[1]._val = CODTYPE_UCS2
            self[3]._val = 0
            # WNG: this will certainly fail in Python2
            self[4]._val = name.encode('utf16')
        else:
            raise(PycrateErr('{0}: invalid coding / name'.format(self._name)))


#------------------------------------------------------------------------------#
# Reject Cause
# TS 24.008, section 10.5.3.6
#------------------------------------------------------------------------------#

RejectCause_dict = {
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


#------------------------------------------------------------------------------#
# Time Zone and Time
# TS 24.008, section 10.5.3.9
#------------------------------------------------------------------------------#

class TimeZoneTime(Envelope):
    _GEN = (
        Uint8('Year'),
        Uint8('Month'),
        Uint8('Day'),
        Uint8('Hour'),
        Uint8('Minute'),
        Uint8('Second'),
        Uint8('TimeZone')
        )


#------------------------------------------------------------------------------#
# Supported codec list
# TS 24.008, section 10.5.4.32
#------------------------------------------------------------------------------#

class SuppCodec(Envelope):
    _GEN = (
        Uint8('SysID', val=0),
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
        Uint('Police', val=0, bl=1),
        Uint('Ambulance', val=0, bl=1),
        Uint('Fire', val=0, bl=1),
        Uint('Marine', val=0, bl=1),
        Uint('Mountain', val=0, bl=1),
        Uint('manual eCall', val=0, bl=1),
        Uint('auto eCall', val=0, bl=1),
        Uint('spare', val=0, bl=1)
        )

#------------------------------------------------------------------------------#
# Emergency Number List
# TS 24.008, section 10.5.3.13
#------------------------------------------------------------------------------#

class EmergNum(Envelope):
    _GEN = (
        Uint8('Len'),
        Uint('spare', val=0, bl=3),
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
        Uint('spare', val=0, bl=2),
        Uint('CSMO', val=0, bl=1, dic=_CSMO_dict),
        Uint('CSMT', val=0, bl=1, dic=_CSMT_dict)
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
        Uint('Unit', val=0, bl=3, dic=_MMTimerUnit_dict),
        Uint('Value', val=0, bl=5)
        )


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
        Uint('spare', val=0, bl=3),
        Uint('Hold', val=0, bl=2, dic=_AuxHold_dict),
        Uint('MPTY', val=0, bl=2, dic=_AuxMPTY_dict)
        )


#------------------------------------------------------------------------------#
# Called party BCD number
# TS 24.008, 10.5.4.7
#------------------------------------------------------------------------------#
# TODO: for BCDNumber, check the stuff about the Ext bit and following fields...
# not clear if always present: see TS 24.007, 11.2.2.1
# TODO: align with CallingPartyBCDNumberStar

_BCDType_dict = {
    0 : 'unknown',
    1 : 'international number',
    2 : 'national number',
    3 : 'network specific number',
    4 : 'dedicated access, short code',
    }
_NumPlan_dict = {
    0 : 'unknown',
    1 : 'ISDN / telephony numbering plan (E.164 / E.163)',
    3 : 'data numbering plan (X.121)',
    4 : 'telex numbering plan (F.69)',
    8 : 'national numbering plan',
    9 : 'private numbering plan',
    11: 'reserved for CTS',
    }

class BCDNumber(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('Type', val=1, bl=3, dic=_BCDType_dict),
        Uint('NumberingPlan', val=1, bl=4, dic=_NumPlan_dict),
        BufBCD('Num')
        )

CalledPartyBCDNumber = BCDNumber


#------------------------------------------------------------------------------#
# Calling party BCD number
# TS 24.008, 10.5.4.9
#------------------------------------------------------------------------------#
# 2 alternatives for the calling party number format:
# CallingPartyBCDNumber, CallingPartyBCDNumberStar

CallingPartyBCDNumber = BCDNumber

_PresInd_dict = {
    0 : 'presentation allowed',
    1 : 'presentation restricted',
    2 : 'number not available due to interworking',
    3 : 'reserved'
    }
_ScreenInd_dict = {
    0 : 'user-provided, not screened',
    1 : 'user-provided, verified and passed',
    2 : 'user-provided, verified and failed',
    3 : 'network provided'
    }

class CallingPartyBCDNumberStar(Envelope):
    _GEN = (
        Uint('Ext', val=1, bl=1),
        Uint('PresentationInd', val=0, bl=2, dic=_PresInd_dict),
        Uint('spare', val=0, bl=3),
        Uint('ScreeningInd', val=1, bl=2, dic=_ScreenInd_dict),
        BufBCD('Num')
        )


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
        Uint('FollowOnProc', val=0, bl=1),
        Uint('Result', val=0, bl=3, dic=_AttachResult_dict)
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
        Uint('FollowOnReq', val=0, bl=1),
        Uint('Type', val=0, bl=3, dic=_AttachType_dict)
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
        Uint('spare', val=0, bl=3),
        Uint('Flag', val=0, bl=1, dic=_TMSIStatus_dict)
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
        Uint('PowerOff', val=0, bl=1),
        Uint('Type', val=0, bl=3, dic=_DetachTypeMO_dict)
        )

class DetachTypeMT(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=1),
        Uint('Type', val=0, bl=3, dic=_DetachTypeMT_dict)
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
        Uint8('SPLIT_PG_CYCLE_CODE', val=0, dic=_SplitPGCycleC_dict),
        Uint('DRXCycleLen', val=0, bl=3, dic=_DRXCycleLen_dict),
        Uint('SPLITonCCCH', val=0, bl=1),
        Uint('NonDRXTimer', val=0, bl=4, dic=_NonDRXTimer_dict)
        )


#------------------------------------------------------------------------------#
# Force to standby
# TS 24.008, 10.5.5.7
#------------------------------------------------------------------------------#

_ForceStdby_dict = {
    0 : 'Force to standby not indicated',
    1 : 'Force to standby indicated'
    }

class ForceStdby(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=1),
        Uint('Value', val=0, bl=3, dic=_ForceStdby_dict)
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


#------------------------------------------------------------------------------#
# Routing Area Identifier
# TS 24.008, 10.5.5.15
#------------------------------------------------------------------------------#

class RAI(Envelope):
    _GEN = (
        PLMN(),
        Uint16('LAC', val=0, rep=REPR_HEX),
        Uint8('RAC', val=0, rep=REPR_HEX)
        )
    
    def set_val(self, vals):
        if isinstance(vals, dict) and \
        'plmn' in vals and 'lac' in vals and 'rac' in vals:
            self.encode(vals['plmn'], vals['lac'], vals['rac'])
        else:
            Envelope.set_val(self, vals)
    
    def encode(self, *args):
        if args:
            self[0].encode(args[0])
            if len(args) > 1:
                self[1].set_val(args[1])
                if len(args) > 2:
                    self[2].set_val(args[2])
    
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
        Uint('FollowOnProc', val=0, bl=1),
        Uint('Result', val=0, bl=3, dic=_UpdateResult_dict)
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
        Uint('FollowOnReq', val=0, bl=1),
        Uint('Type', val=0, bl=3, dic=_UpdType_dict)
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
        Uint('spare', val=0, bl=2),
        Uint('APC',   val=0, bl=1),
        Uint('OTD_A', val=0, bl=1),
        Uint('OTD_B', val=0, bl=1),
        Uint('GPS_A', val=0, bl=1),
        Uint('GPS_B', val=0, bl=1),
        Uint('GPS_C', val=0, bl=1)
        )


#------------------------------------------------------------------------------#
# Network feature support
# TS 24.008, 10.5.5.23
#------------------------------------------------------------------------------#

class NetFeatSupp(Envelope):
    _GEN = (
        Uint('LCS_MOLR', val=0, bl=1),
        Uint('MBMS', val=0, bl=1),
        Uint('IMS_VoPS', val=0, bl=1),
        Uint('EMC_BS', val=0, bl=1)
        )


#------------------------------------------------------------------------------#
# Additional network feature support
# TS 24.008, 10.5.5.23A
#------------------------------------------------------------------------------#

class AddNetFeatSupp(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=7),
        Uint('GPRS_SMS', val=0, bl=1)
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
        Uint('spare', val=0, bl=5),
        Uint('UEUsage', val=0, bl=1, dic=_UEUsage_dict),
        Uint('VoiceDomPref', val=0, bl=2, dic=_VoiceDomPref_dict)
        )


#------------------------------------------------------------------------------#
# Requested MS information
# TS 24.008, 10.5.5.25
#------------------------------------------------------------------------------#


class ReqMSInfo(Envelope):
    _GEN = (
        Uint('I_RAT', val=0, bl=1),
        Uint('I_RAT2', val=0, bl=1),
        Uint('spare', val=0, bl=2)
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
        Uint('spare', val=0, bl=3),
        Uint('Value', val=0, bl=1, dic=_PTMSIType_dict)
        )


#------------------------------------------------------------------------------#
# Network Resource Identifier
# TS 24.008, 10.5.5.31
#------------------------------------------------------------------------------#

class NRICont(Envelope):
    _GEN = (
        Uint('Value', val=0, bl=10, rep=REPR_HEX),
        Uint('spare', val=0, bl=6)
        )


#------------------------------------------------------------------------------#
# Extended DRX parameters
# TS 24.008, 10.5.5.32
#------------------------------------------------------------------------------#

class ExtDRXParam(Envelope):
    _GEN = (
        Uint('PTX', val=0, bl=4),
        Uint('eDRX', val=0, bl=4)
        )


#------------------------------------------------------------------------------#
# User-Plane integrity indicator
# TS 24.008, 10.5.5.34
#------------------------------------------------------------------------------#

class UPIntegrityInd(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=3),
        Uint('Value', val=0, bl=1)
        )


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
        Uint('NSAPI_7', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_6', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_5', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_4', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_3', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_2', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_1', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_0', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_15', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_14', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_13', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_12', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_11', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_10', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_9', val=0, bl=1, dic=_PDPCtxtStat_dict),
        Uint('NSAPI_8', val=0, bl=1, dic=_PDPCtxtStat_dict)
        )

#------------------------------------------------------------------------------#
# GPRS Timer
# TS 24.008, 10.5.7.3
#------------------------------------------------------------------------------#

_GPRSTimerUnit_dict = _MMTimerUnit_dict

class GPRSTimer(Envelope):
    _GEN = (
        Uint('Unit', val=0, bl=3, dic=_GPRSTimerUnit_dict),
        Uint('Value', val=0, bl=5)
        )


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

class GPRSTimer3(Envelope):
    _GEN = (
        Uint('Unit', val=0, bl=3, dic=_GPRSTimer3Unit_dict),
        Uint('Value', val=0, bl=5)
        )


#------------------------------------------------------------------------------#
# Radio Priority
# TS 24.008, 10.5.7.5
#------------------------------------------------------------------------------#

_RadioPrio_dict = {
    1 : 'priority level 1 (highest)',
    2 : 'priority level 2',
    3 : 'priority level 3',
    4 : 'priority level 4 (lowest)'
    }

class RadioPriority(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=1),
        Uint('Value', val=0, bl=3, dic=_RadioPrio_dict)
        )


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
                GEN.append( Uint('NSAPI_%i' % (128+8*i+j), val=0, bl=1, dic=_PDPCtxtStat_dict) )
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
        Uint('NSAPI_7', val=0, bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_6', val=0, bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_5', val=0, bl=1, dic=_ULDataStat_dict),
        Uint('spare', val=0, bl=5),
        Uint('NSAPI_15', val=0, bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_14', val=0, bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_13', val=0, bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_12', val=0, bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_11', val=0, bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_10', val=0, bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_9', val=0, bl=1, dic=_ULDataStat_dict),
        Uint('NSAPI_8', val=0, bl=1, dic=_ULDataStat_dict)
        )

#------------------------------------------------------------------------------#
# Device Properties
# TS 24.008, 10.5.7.8
#------------------------------------------------------------------------------#

class DeviceProp(Envelope):
    _GEN = (
        Uint('spare', val=0, bl=3),
        Uint('LowPriority', val=0, bl=1)
        )

