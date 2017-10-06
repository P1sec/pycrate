# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.2
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
# * File Name : pycrate_mobile/TS24007.py
# * Created : 2017-06-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# 3GPP TS 24.007: Mobile radio interface signalling layer 3
# release 13 (d00)
#------------------------------------------------------------------------------#

from binascii import hexlify

from pycrate_core.utils  import *
from pycrate_core.elt    import Element, Envelope, REPR_RAW, REPR_HEX, REPR_BIN
from pycrate_core.base   import *
from pycrate_core.repr   import *
from pycrate_csn1.csnobj import CSN1Obj

#------------------------------------------------------------------------------#
# Components of a standard L3 message
# TS 24.007, section 11.2.1
#------------------------------------------------------------------------------#

class Layer3(Envelope):
    
    ENV_SEL_TRANS = False
    
    def __init__(self, *args, **kw):
        if 'val' in kw:
            val = kw['val']
            del kw['val']
        else:
            val = None
        Envelope.__init__(self, *args, **kw)
        # build a list of (tag length, tag value) for the optional part
        # configure IE set by **kw as non-transparent and set their value
        self._opts = []
        if val is None:
            # go faster by just looking for optional IE
            for ie in self._content:
                if isinstance(ie, (Type1TV, Type2, Type3TV, Type4TLV, Type6TLVE)):
                    # optional IE
                    T = ie[0]
                    self._opts.append( (T.get_bl(), T(), ie) )
        else:
            for ie in self._content:
                if isinstance(ie, (Type1V, Type3V, Type4LV, Type6LVE)) and \
                val and ie._name in val:
                    # setting value for non-optional IE
                    if isinstance(val[ie._name], bytes_types):
                        # setting raw value
                        ie['V'].set_val(val[ie._name])
                    else:
                        # setting embedded IE structure
                        ie.set_IE(val=val[ie._name])
                elif isinstance(ie, (Type1TV, Type3TV, Type4TLV, Type6TLVE)):
                    # optional IE
                    T = ie[0]
                    self._opts.append( (T.get_bl(), T(), ie) )
                    if val and ie._name in val:
                        ie._trans = False
                        if isinstance(val[ie._name], bytes_types):
                            # setting raw value
                            ie['V'].set_val(val[ie._name])
                        else:
                            # setting embedded IE structure
                            ie.set_IE(val=val[ie._name])
                elif isinstance(ie, Type2):
                    # optional Tag-only IE
                    self._opts.append( (8, ie[0](), ie) )
                    if val and ie._name in val:
                        ie._trans = False
                elif val and ie._name in val:
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
        Envelope._from_char(self, char)
        # 2) decode optional part
        opts = self._opts[:]
        while char.len_bit() >= 8:
            T4, T8, dec = char.to_uint(4), char.to_uint(8), False
            for i, opt in enumerate(opts):
                # check the list of optional IEs in order
                if opt[1] in (T4, T8):
                    opt[2]._trans = False
                    opt[2]._from_char(char)
                    dec = True
                    del opts[i]
                    break
            if not dec:
                # unknown IEI
                char._cur += 8
                self._dec_unk_ie(T8, char)
    
    def _dec_unk_ie(self, T8, char):
        if T8 & 0x80:
            # 1 byte IE
            log('%s, _dec_unk_ie: unknown Type2 IE, 0x%x' % (self._name, T8))
            self.append( Type2('_T_%i' % T8, val=[T8]) )
        else:
            # Type4TLV IE
            L = char.get_uint(8)
            V = char.get_bytes(8*L)
            log('%s, _dec_unk_ie: unknown Type4TLV IE, T: 0x%x, V: 0x%s' \
                % (self._name, T8, hexlify(V)))
            self.append( Type4TLV('_T_%i' % T8, val=[T8, L, V]) )
    
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


class Layer3EPS(Layer3):
    
    def _dec_unk_ie(self, T8, char):
        if T8 & 0x80:
            # 1 byte IE
            log('%s, _dec_unk_ie: unknown Type2 IE, 0x%x' % (self._name, T8))
            self.append( Type2('_T_%i' % T8, val=[T8]) )
        elif T8 & 0x70 == 0x70:
            # Type6 TLV IE
            L = char.get_uint(16)
            V = char.get_bytes(8*L)
            log('%s, _dec_unk_ie: unknown Type6TLVE IE, T: 0x%x, V: 0x%s' \
                % (self._name, T8, hexlify(V)))
            self.append( Type6TLVE('_T_%i' % T8, val=[T8, L, V]) )
        else:
            # Type4TLV IE
            L = char.get_uint(8)
            V = char.get_bytes(8*L)
            log('%s, _dec_unk_ie: unknown Type4TLV IE, T: 0x%x, V: 0x%s' \
                % (self._name, T8, hexlify(V)))
            self.append( Type4TLV('_T_%i' % T8, val=[T8, L, V]) )


class IE(Envelope):
    
    # do not represent transparent IE
    REPR_TRANS = False
    
    _IE = None
    _V  = None
    
    def __init__(self, *args, **kw):
        if 'IE' in kw:
            if isinstance(kw['IE'], (Element, CSN1Obj)):
                self._IE = kw['IE'].clone()
            elif self._SAFE_STAT:
                raise(PycrateErr('IE [__init__]: IE type is {0}, expecting Element'\
                      .format(type(kw['IE']).__name__)))
        Envelope.__init__(self, *args, **kw)
    
    def _from_char(self, char):
        Envelope._from_char(self, char)
        # in case self._IE is defined, use it to decode char instead of V
        if self._IE is not None:
            iebl = self[-1].get_bl()
            char_cur = char._cur
            char_lb  = char._len_bit
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
                    # save the V buffer
                    self._V = self[-1]
                    # replace it with the IE structure
                    self.replace(self[-1], self._IE)
                    if self[-2]._name == 'L':
                        # Type4 and Type6
                        self[-2].set_valauto( self[-1].get_len )
            char._cur = char_cur
            char._len_bit = char_lb
    
    def clone(self):
        kw = {}
        if self._desc != self.__class__._desc:
            kw['desc'] = self._desc
        if self._hier != self.__class__._hier:
            kw['hier'] = self._hier
        if self._trans != self.__class__._trans:
            kw['trans'] = self._trans
        if self._IE is not None:
            # additional attribute, compared to Envelope.clone()
            kw['IE'] = self._IE
        # substitute the Envelope generator with clones of the current 
        # envelope's content
        kw['GEN'] = tuple([elt.clone() for elt in self._content])
        return self.__class__(self._name, **kw)
    
    # new methods, specific to IE
    
    def set_IE(self, *args, **kw):
        if self._IE is not None:
            self._IE.__init__(*args, **kw)
            assert( self[-1]._name == 'V' )
            self._V = self[-1]
            self.replace(self[-1], self._IE)
            if self[-2]._name == 'L':
                # Type4 and Type6
                self[-2].set_valauto( self[-1].get_len )
    
    def unset_IE(self, *args):
        if self._IE is not None:
            assert( self._V is not None )
            self[-1] = self._V
            if args:
                self[-1].__init__(val=args[0])
            if self[-2]._name == 'L':
                # Type4 and Type6
                self[-2].set_valauto( self[-1].get_len )
                self[-1].set_blauto( lambda: 8*self[-2].get_val() )


class Type1V(IE):
    """The Type1_V IE is a mandatory IE,
    its content is a single 4 bit indicator 
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


class Type1TV(IE):
    """The Type1_TV IE is an optional IE,
    its content is a 4 bit tag and a 4 bit value
    """
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
            self[0]._dic = dic


class Type2(IE):
    """The Type2 IE is an optional IE,
    its content is a single 8 bit tag (i.e. a flag)
    """
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
        self[0].set_valauto( self[1].get_len )
        self[1].set_blauto( lambda : 8*self[0]() )


class Type4TLV(IE):
    """The Type4_TLV IE is an optional IE
    its content is a 8 bit tag, a 8 bit length and a buffer of given length
    """
    _GEN = (
        Uint8('T'),
        Uint8('L'),
        Buf('V', rep=REPR_HEX)
        )
    def __init__(self, *args, **kwargs):
        IE.__init__(self, *args, **kwargs)
        self[1].set_valauto( self[2].get_len )
        self[2].set_blauto( lambda : 8*self[1].get_val() )


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
        self[1].set_valauto( self[2].get_len )
        self[2].set_blauto( lambda : 8*self[1].get_val() )


class Type6TLVE(IE):
    """The Type6_TLVE IE is an optional IE only used in EPS
    its content is a 8 bit tag, a 16 bit length and a buffer of given length
    """
    _GEN = (
        Uint8('T'),
        Uint16('L'),
        Buf('V', rep=REPR_HEX)
        )
    def __init__(self, *args, **kwargs):
        IE.__init__(self, *args, **kwargs)
        self[1].set_valauto( self[2].get_len )
        self[2].set_blauto( lambda : 8*self[1].get_val() )


#------------------------------------------------------------------------------#
# Imperative part of a standard L3 message
# TS 24.007, section 11.2.3
#------------------------------------------------------------------------------#

ProtDisc_dict = {
    0 : 'GCC',
    1 : 'BCC',
    2 : 'ESM',
    3 : 'CC',
    4 : 'GTTP',
    5 : 'MM',
    6 : 'RRM',
    7 : 'EMM',
    8 : 'GMM',
    9 : 'SMS',
    10: 'SM',
    11: 'SS',
    12: 'LCS',
    13: 'extended ProtDisc',
    14: 'testing',
    }


