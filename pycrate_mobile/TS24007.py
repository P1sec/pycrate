# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI. P1sec.
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
# * File Name : pycrate_mobile/TS24007.py
# * Created : 2017-06-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'Layer3',
    'Layer3E',
    'IE',
    'Type1V',
    'Type1TV',
    'Type2',
    'Type3V',
    'Type3TV',
    'Type4LV',
    'Type4TLV',
    'Type6LVE',
    'Type6TLVE',
    'RestOctets',
    'TI',
    'TIPD',
    'ProtDisc_dict'
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.007: Mobile radio interface signalling layer 3
# release 13 (d00)
#------------------------------------------------------------------------------#

from binascii import hexlify

from pycrate_core.utils  import *
from pycrate_core.elt    import Element, Envelope, EltErr, CharpyErr, REPR_RAW, REPR_HEX, REPR_BIN
from pycrate_core.base   import *
from pycrate_core.repr   import *
from pycrate_csn1.csnobj import CSN1Obj


#------------------------------------------------------------------------------#
# Components of a standard L3 message
# TS 24.007, section 11.2.1
#------------------------------------------------------------------------------#

class Layer3(Envelope):
    
    ENV_SEL_TRANS = False
    
    # this is to break the decoding routine when an unknown IE is encountered
    # this needs to be set to True for 2G RR signaling message (due to rest octets)
    DEC_BREAK_ON_UNK_IE = False
    
    def __init__(self, *args, **kw):
        if 'val' in kw:
            val = kw['val']
            del kw['val']
        else:
            val = None
        if 'sec' in kw:
            # used within the NAS LTE EMM stack of corenet
            sec = kw['sec']
            del kw['sec']
        else:
            sec = None
        Envelope.__init__(self, *args, **kw)
        self._sec = sec
        # build a list of (tag length, tag value) for the optional part
        # configure IE set by **kw as non-transparent and set their value
        self._opts, self._rest = [], None
        if val is None:
            # go faster by just looking for optional IE
            for ie in self._content:
                if isinstance(ie, (Type1TV, Type2, Type3TV, Type4TLV, Type6TLVE)):
                    # optional IE
                    T = ie[0]
                    self._opts.append( (T.get_bl(), T(), ie) )
                elif isinstance(ie, RestOctets):
                    # rest octets
                    self._rest = ie
        else:
            for ie in self._content:
                if isinstance(ie, (Type1V, Type3V, Type4LV, Type6LVE)) and ie._name in val:
                    # setting value for non-optional IE
                    ie.set_val({'V': val[ie._name]})
                elif isinstance(ie, (Type1TV, Type3TV, Type4TLV, Type6TLVE)):
                    # optional IE
                    T = ie[0]
                    self._opts.append( (T.get_bl(), T(), ie) )
                    if ie._name in val:
                        ie._trans = False
                        ie.set_val({'V': val[ie._name]})
                elif isinstance(ie, Type2):
                    # optional Tag-only IE
                    self._opts.append( (8, ie[0](), ie) )
                    if ie._name in val:
                        ie._trans = False
                elif isinstance(ie, RestOctets):
                    self._rest = ie
                elif ie._name in val:
                    ie.set_val(val[ie._name])
    
    def reset_opts(self):
        """reset the optional part of the message
        """
        [opt[2].set_trans(True) for opt in self._opts]
    
    def get_opts(self):
        """returns the list of optional IE of the message
        """
        return [opt[2] for opt in self._opts]
    
    def _from_char(self, char):
        # in case some optional IE are set (with transparency enabled)
        # they are decoded as much as the char buffer allows it
        # 1) decode mandatory part
        if self._rest is not None:
            self._rest.set_trans(True)
            dec_brk = self.DEC_BREAK_ON_UNK_IE
            self.DEC_BREAK_ON_UNK_IE = True
        Envelope._from_char(self, char)
        # 2) decode optional part
        opts, dec = self._opts[:], False
        while char.len_bit() >= 8:
            T4, T8, dec = char.to_uint(4), char.to_uint(8), False
            for i, opt in enumerate(opts):
                # check the list of optional IEs in order
                # opt[0] is the tag length: 4 or 8
                # opt[1] is the tag value: 0 <= T <= 255
                if (opt[0] == 4 and opt[1] == T4) or opt[1] == T8:
                    opt[2]._trans = False
                    opt[2]._from_char(char)
                    dec = True
                    del opts[i]
                    break
            if not dec:
                # unknown IEI
                if self.DEC_BREAK_ON_UNK_IE:
                    #log('%s, unknown IE remaining, not decoded' % self._name)
                    break
                else:
                    char._cur += 8
                    self._dec_unk_ie(T8, char)
        # 3) decode rest octets
        if not dec and self._rest is not None:
            self._rest.set_trans(False)
            self.DEC_BREAK_ON_UNK_IE = dec_brk
            self._rest._from_char(char)
    
    def _dec_unk_ie(self, T8, char):
        if T8 & 0x80:
            # Type1TV IE, could also be a Type2 IE
            log('%s, _dec_unk_ie: unknown Type1TV IE, 0x%.2x' % (self._name, T8))
            self.append( Type1TV('_T_%X' % (T8>>4), val={'T':T8>>4, 'V':T8&0xf}) )
        else:
            # Type4TLV IE
            L = char.get_uint(8)
            V = char.get_bytes(8*L)
            log('%s, _dec_unk_ie: unknown Type4TLV IE, T: 0x%.2x, V: 0x%s' \
                % (self._name, T8, hexlify(V).decode('ascii')))
            self.append( Type4TLV('_T_%X' % T8, val=[T8, L, V]) )
    
    def repr(self):
        # element transparency
        if self.get_trans():
            trans = ' [transparent]'
        else:
            trans = ''
        # additional description
        if self._desc:
            desc = ' [%s]' % self._desc
        else:
            desc = ''
        #
        return '<%s%s%s : %s>' % \
               (self._name, desc, trans, ''.join(map(repr, self._content)))
    
    __repr__ = repr


class Layer3E(Layer3):
    
    # list of clear-text IEs, used for 5GMM NAS message
    _ies_ct = set()
    
    def _dec_unk_ie(self, T8, char):
        if T8 & 0x80:
            # Type1TV IE, could also be a Type2 IE
            log('%s, _dec_unk_ie: unknown Type1TV IE, 0x%.2x' % (self._name, T8))
            self.append( Type1TV('_T_%X' % (T8>>4), val={'T':T8>>4, 'V':T8&0xf}) )
        elif T8 & 0x70 == 0x70:
            # Type6TLV IE
            L = char.get_uint(16)
            V = char.get_bytes(8*L)
            log('%s, _dec_unk_ie: unknown Type6TLVE IE, T: 0x%.2x, V: 0x%s' \
                % (self._name, T8, hexlify(V)))
            self.append( Type6TLVE('_T_%i' % T8, val=[T8, L, V]) )
        else:
            # Type4TLV IE
            L = char.get_uint(8)
            V = char.get_bytes(8*L)
            log('%s, _dec_unk_ie: unknown Type4TLV IE, T: 0x%.2x, V: 0x%s' \
                % (self._name, T8, hexlify(V).decode('ascii')))
            self.append( Type4TLV('_T_%X' % T8, val=[T8, L, V]) )


class IE(Envelope):
    
    # to decode inner IE, when defined
    DECODE_INNER = True
    
    # _V stores the Value instance, when existing
    _V = None
    # _IE_stat stores an instance of an IE class that must be kept as is
    # when required (during encoding / decoding) it is cloned into _IE
    _IE_stat = None
    _IE      = None
    
    def __init__(self, *args, **kw):
        if 'IE' in kw:
            if isinstance(kw['IE'], (Element, CSN1Obj)):
                self._IE_stat = kw['IE']
            elif self._SAFE_STAT:
                raise(PycrateErr('IE [__init__]: IE type is {0}, expecting Element'\
                      .format(type(kw['IE']).__name__)))
            del kw['IE']
        Envelope.__init__(self, *args, **kw)
        if self[-1]._name == 'V':
            self._V = self[-1]
    
    def set_val(self, vals):
        ie_val = None
        if vals is None:
            self.unset_IE()
            [elt.set_val(None) for elt in self.__iter__()]
        elif isinstance(vals, (tuple, list)):
            for ind, elt in enumerate(self.__iter__()):
                val = vals[ind]
                if elt._name == 'V' and not isinstance(val, elt.TYPES):
                    # keep value for setting the inner IE
                    ie_val = val
                else:
                    # set raw V value
                    elt.set_val(val)
        elif isinstance(vals, dict):
            for key, val in vals.items():
                if key == 'V' and not isinstance(val, self['V'].TYPES):
                    # keep value for setting the inner IE
                    ie_val = val
                else:
                    # set raw V value
                    self.__setitem__(key, val)
        elif self._SAFE_STAT:
            raise(EltErr('{0} [set_val]: vals type is {1}, expecting None, tuple, list or dict'\
                  .format(self._name, type(vals).__name__)))
        if ie_val is not None:
            # set the value to the inner IE
            self.set_IE(val=ie_val)
    
    def _from_char(self, char):
        if self[-1]._name != 'V':
            # restore the std buffer for handling the value
            self.unset_IE()
        Envelope._from_char(self, char)
        # in case self._IE is defined, use it to decode char instead of V
        if self.DECODE_INNER and self._IE_stat is not None:
            if self._IE is None:
                self._IE = self._IE_stat.clone()
            iebl = self[-1].get_bl()
            ccur, clen = char._cur, char._len_bit
            char._cur -= iebl
            char._len_bit = char._cur + iebl
            try:
                self._IE._from_char(char)
            except:
                log('%s, _from_char: unable to decode IE, %s'\
                    % (self._name, self._IE._name))
            else:
                if char.len_bit() > 0:
                    log('%s, _from_char: uncorrect decoding for IE, %s'\
                        % (self._name, self._IE._name))
                else:
                    # replace V with the IE structure
                    self.replace(self[-1], self._IE)
            char._cur, char._len_bit = ccur, clen
    
    def clone(self):
        kw = {}
        if self._desc != self.__class__._desc:
            kw['desc'] = self._desc
        if self._hier != self.__class__._hier:
            kw['hier'] = self._hier
        if self._trans != self.__class__._trans:
            kw['trans'] = self._trans
        if self._IE_stat is not None:
            # additional attribute, compared to Envelope.clone()
            kw['IE'] = self._IE_stat
        # substitute the Envelope generator with clones of the current 
        # envelope's content
        kw['GEN'] = tuple([elt.clone() for elt in self._content])
        return self.__class__(self._name, **kw)
    
    # new methods, specific to IE
    
    def set_IE(self, *args, **kw):
        if self._IE_stat is None:
            return
        elif self._IE is None:
            # potentially clone the IE
            self._IE = self._IE_stat.clone()
        self._IE.__init__(*args, **kw)
        if self[-1]._name != self._IE._name:
            self.replace(self[-1], self._IE)
    
    def unset_IE(self):
        if self[-1]._name != 'V' and self._V is not None:
            self.replace(self[-1], self._V)


class Type1V(IE):
    """The Type1_V IE is a mandatory IE,
    its content is a single 4 bit unsigned int value 
    """
    _GEN = (
        Uint('V', bl=4),
        )
    
    def __init__(self, *args, **kw):
        if 'dic' in kw:
            dic = kw['dic']
            del kw['dic']
        else:
            dic = None
        IE.__init__(self, *args, **kw)
        if dic is not None:
            self[0]._dic = dic
    
    def set_val(self, vals):
        ie_val = None
        if vals is None:
            [elt.set_val(None) for elt in self.__iter__()]
        elif isinstance(vals, (tuple, list)):
            ind = 0
            for elt in self.__iter__():
                val = vals[ind]
                if elt._name == 'V' and not isinstance(val, integer_types):
                    ie_val = val
                else:
                    elt.set_val(val)
                ind += 1
        elif isinstance(vals, dict):
            for key, val in vals.items():
                if key == 'V' and not isinstance(val, integer_types):
                    ie_val = val
                else:
                    self.__setitem__(key, val)
        elif self._SAFE_STAT:
            raise(EltErr('{0} [set_val]: vals type is {1}, expecting None, tuple, list or dict'\
                  .format(self._name, type(vals).__name__)))
        if ie_val is not None:
            # set IE it according to val
            self.set_IE(val=ie_val)


class Type1TV(IE):
    """The Type1_TV IE is an optional IE,
    its content is a 4 bit tag and a 4 bit unsigned int value
    """
    DEFAULT_TRANS = True
    _GEN = (
        Uint('T', bl=4),
        Uint('V', bl=4)
        )
    
    def __init__(self, *args, **kw):
        if 'dic' in kw:
            dic = kw['dic']
            del kw['dic']
        else:
            dic = None
        IE.__init__(self, *args, **kw)
        if dic is not None:
            self[1]._dic = dic
    
    def set_val(self, vals):
        ie_val = None
        if vals is None:
            [elt.set_val(None) for elt in self.__iter__()]
        elif isinstance(vals, (tuple, list)):
            ind = 0
            for elt in self.__iter__():
                val = vals[ind]
                if elt._name == 'V' and not isinstance(val, integer_types):
                    ie_val = val
                else:
                    elt.set_val(val)
                ind += 1
        elif isinstance(vals, dict):
            for key, val in vals.items():
                if key == 'V' and not isinstance(val, integer_types):
                    ie_val = val
                else:
                    self.__setitem__(key, val)
        elif self._SAFE_STAT:
            raise(EltErr('{0} [set_val]: vals type is {1}, expecting None, tuple, list or dict'\
                  .format(self._name, type(vals).__name__)))
        if ie_val is not None:
            # set IE it according to val
            self.set_IE(val=ie_val)


class Type2(IE):
    """The Type2 IE is an optional IE,
    its content is a single 8 bit tag (i.e. a flag)
    """
    DEFAULT_TRANS = True
    _GEN = (
        Uint8('T'),
        )


class Type3V(IE):
    """The Type3_V IE is a mandatory IE,
    its content is a simple buffer
    """
    _GEN = (
        Buf('V', rep=REPR_HEX),
        )
    

class Type3TV(IE):
    """The Type3_TV IE is an optional IE,
    its content is a 8 bit tag and a simple buffer
    """
    DEFAULT_TRANS = True
    _GEN = (
        Uint8('T'),
        Buf('V', rep=REPR_HEX)
        )


class Type4LV(IE):
    """The Type4_LV IE is a mandatory IE
    its content is a 8 bit length and a buffer of given length
    """
    _GEN = (
        Uint8('L'),
        Buf('V', rep=REPR_HEX)
        )
    def __init__(self, *args, **kwargs):
        IE.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: 8*self[0]())


class Type4TLV(IE):
    """The Type4_TLV IE is an optional IE
    its content is a 8 bit tag, a 8 bit length and a buffer of given length
    """
    DEFAULT_TRANS = True
    _GEN = (
        Uint8('T'),
        Uint8('L'),
        Buf('V', rep=REPR_HEX)
        )
    def __init__(self, *args, **kwargs):
        IE.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: 8*self[1].get_val())


class Type6LVE(IE):
    """The Type6_LVE IE is a mandatory IE only used in EPS
    its content is a 16 bit length and a buffer of given length
    """
    _GEN = (
        Uint16('L'),
        Buf('V', rep=REPR_HEX)
        )
    def __init__(self, *args, **kwargs):
        IE.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: 8*self[0].get_val())


class Type6TLVE(IE):
    """The Type6_TLVE IE is an optional IE only used in EPS
    its content is a 8 bit tag, a 16 bit length and a buffer of given length
    """
    DEFAULT_TRANS = True
    _GEN = (
        Uint8('T'),
        Uint16('L'),
        Buf('V', rep=REPR_HEX)
        )
    def __init__(self, *args, **kwargs):
        IE.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[2].get_len())
        self[2].set_blauto(lambda: 8*self[1].get_val())


class RestOctets(IE):
    """Rest octets (or Type5) IE is a specific IE only used in GSM / GPRS
    its content is a single buffer of variable length, which is tied to the
    L2PseudoLength at the beginning of the L3 GSM message containing it
    """
    _GEN = (
        BufAuto('V', rep=REPR_HEX),
        )
    
    def __init__(self, *args, **kwargs):
        IE.__init__(self, *args, **kwargs)
        self[0].PAD_VAL = b'+' # 0x2b, GSM padding
        if self[0]._bl is None:
            # in case the length is not fixed at init, it is handled in 
            # a dynamic way, tied to the L2PseudoLength element prefixing the
            # parent Layer3 envelope
            self[0].set_blauto(lambda: 176 - (self.get_env()[0][0].get_val()<<3))


#------------------------------------------------------------------------------#
# Imperative part of a standard L3 message
# TS 24.007, section 11.2.3
#------------------------------------------------------------------------------#

class TI(Envelope):
    """Transaction identifier (extendable)
    TS 24.007, section 11.2.3.1.3
    """
    #ENV_SEL_TRANS = False
    _GEN = (
        Uint('TIFlag', bl=1, dic={0: 'allocated by sender', 1: 'allocated by receiver'}),
        Uint('TIO', bl=3),
        Uint('spare', bl=4),
        Uint('Ext', val=1, bl=1, trans=True),
        Uint('TIE', bl=7, trans=True),
        Uint8('TI', trans=True) # virtual field to get and set the TI value easily
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[5].set_valauto(self._set_ti)
    
    def _set_ti(self):
        tio = self[1].get_val()
        if tio == 7 and not self[4].get_trans():
            return self[4].get_val()
        else:
            return tio
    
    def set_val(self, vals):
        ti, disp = None, True
        if isinstance(vals, integer_types):
            ti = vals
            disp = False
        elif isinstance(vals, dict) and 'TI' in vals:
            ti = vals['TI']
        if ti is not None:
            if 0 <= ti < 7:
                self[1].set_val(ti)
                self[3].set_trans(True)
                self[4].set_trans(True)
                self[4].set_val(None)
            elif ti < 128:
                # extended
                self[1].set_val(7)
                self[3].set_trans(False)
                self[4].set_trans(False)
                self[4].set_val(ti)
        if disp:
            Envelope.set_val(self, vals)
    
    def _from_char(self, char):
        self[0]._from_char(char)
        self[1]._from_char(char)
        self[2]._from_char(char)
        if self[1].get_val() == 7 and char.len_byte():
            self[3].set_trans(False)
            self[3]._from_char(char)
            self[4].set_trans(False)
            self[4]._from_char(char)
        else:
            self[3].set_trans(True)
            self[4].set_trans(True)
            self[4].set_val(None)


ProtDisc_dict = {
    0  : 'GCC',
    1  : 'BCC',
    2  : 'ESM',
    3  : 'CC',
    4  : 'GTTP',
    5  : 'MM',
    6  : 'RRM',
    7  : 'EMM',
    8  : 'GMM',
    9  : 'SMS',
    10 : 'SM',
    11 : 'SS',
    12 : 'LCS',
    14 : 'extended ProtDisc',
    15 : 'testing',
    46 : '5GSM',
    126: '5GMM'
    }

class TIPD(TI):
    """Transaction identifier (extendable) and protocol discriminator
    TS 24.007, section 11.2.3.1
    """
    _GEN = (
        Uint('TIFlag', bl=1, dic={0: 'allocated by sender', 1: 'allocated by receiver'}),
        Uint('TIO', bl=3),
        Uint('ProtDisc', bl=4, dic=ProtDisc_dict),
        Uint('Ext', val=1, bl=1, trans=True),
        Uint('TIE', bl=7, trans=True),
        Uint8('TI', trans=True) # virtual field to get and set the TI value easily
        )

