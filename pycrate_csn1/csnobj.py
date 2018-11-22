# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.3
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
# * File Name : pycrate_csn1/csnobj.py
# * Created : 2017-06-12
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.utils  import *
from pycrate_core.charpy import *

from .utils import *

#------------------------------------------------------------------------------#
# CSN.1 runtime
#------------------------------------------------------------------------------#

global _root_obj # for referencing the root object name, in case of self reference
_root_obj = None


class CSN1Obj(Element):
    """Parent class to handle CSN.1 objects encoding and decoding and definition
    
    internal attributes:
        - name: str, named of the object,
            can be a null-string in case of anonymous object
        - num : 
            int, static number of repetition for the object
                default is 1, it can be >= 0
                or -1, for an undefined number of repetitions
            (x:int, (a:int, b:int)) is an alternate possible value in case
                the number of repetitions is dynamic and depends on another 
                object:
                x: backward reference to a field into the parent object which 
                   has to be a list
                a, b: transform in the form x: a*(x+b) to be applied to the 
                      value of the backward reference to get the length of self
        - lref: enforces a limitation to the length in bits during the decoding 
                and potentially the encoding, used for lists and alternatives
            None, no limitation
            int, static limitation of the number of bits
            (x:int, (a:int, b:int)) is an alternate possible value in case the
                limitation of number of bits is dynamic and depends on another 
                object, handling is similar to num
    
    This class must not be used directly, only CSN1Bit, CSN1List, CSN1Alt, 
    CSN1Val, CSN1Ref, CSN1SelfRef.
    """
    
    CLASS = 'CSN1Obj'
    
    # in order to disable any csnlog() during the runtime
    _SILENT = False
    
    #_REPR = 'B' # value always represented with bit-string
    _REPR = 'V' # value represented with their original type (uint -default- or bit-string)
    
    # for certain CSN.1 structure, there is a distinction between padding bit (L)
    # and non padding bit (H), where a padding octet is e.g. 0x2b in GSM
    # null padding :
    #Lv = [0, 0, 0, 0, 0, 0, 0, 0]
    #Lb = '00000000'
    # 0x2B padding :
    Lv = [0, 0, 1, 0, 1, 0, 1, 1]
    Lb = '00101011'
    
    _name = ''
    _num  = 1
    _lref = None
    _par  = None
    
    @classmethod
    def set_pad_null(cls):
        cls.Lv = [0, 0, 0, 0, 0, 0, 0, 0]
        cls.Lb = '00000000'
    
    @classmethod
    def set_pad_gsm(cls):
        cls.Lv = [0, 0, 1, 0, 1, 0, 1, 1]
        cls.Lb = '00101011'
    
    @classmethod
    def conv_b_pad_gsm(cls, val, off):
        ret = []
        for i, c in enumerate(val):
            if c == cls.Lb[(off+i)%8]:
                ret.append('L')
            else:
                ret.append('H')
        return ''.join(ret)
    
    def __init__(self, **kw):
        if 'name' in kw and kw['name']:
            self._name = kw['name']
        if 'num' in kw and kw['num'] != 1:
            self._num  = kw['num']
        if 'lref' in kw and kw['lref'] is not None:
            self._lref = kw['lref']
        if 'val' in kw:
            self.set_val(kw['val'])
        else:
            self._val = None
        # offset for dealing with L / H bits
        self._off = 0
    
    def repr(self):
        global _root_obj
        #
        if self._par is None:
            root_obj  = _root_obj
            _root_obj = self
        #
        if self._name:
            name = '%s (%s)' % (self._name, self.__class__.__name__)
        else:
            name = '(%s)' % self.__class__.__name__
        if self._val is not None:
            if isinstance(self._num, tuple):
                num = self._resolve_ref(self._num)
            else:
                num = self._num
            if num != 1:
                # multiple iteration of the object's value
                content   = []
                _num      = self._num
                _val      = self._val
                self._num = 1
                for val in _val:
                    self._val = val
                    content.append( self._repr_val() )
                self._num = _num
                self._val = _val
                ret = '<%s: [%s]>' % (name, ', '.join(content))
            else:
                ret = '<%s: %s>' % (name, self._repr_val())
        else:
            # only print the class name when no value is set
            ret = '<%s>' % name
        #
        if self._par is None:
            _root_obj = root_obj
        #
        return ret
    
    __repr__ = repr
    
    def show(self):
        # don't print the class name when values are set
        global _root_obj
        #
        if self._par is None:
            root_obj  = _root_obj
            _root_obj = self
        #
        if self._name:
            name = '%s (%s)' % (self._name, self.__class__.__name__)
        else:
            name = '(%s)' % self.__class__.__name__
        if self._val is not None:
            if isinstance(self._num, tuple):
                num = self._resolve_ref(self._num)
            else:
                num = self._num
            if num != 1:
                # multiple iteration of the object's value
                content   = []
                _num      = self._num
                _val      = self._val
                self._num = 1
                for val in _val:
                    self._val = val
                    content.append( self._show_val().replace('\n', '\n ') )
                self._num = _num
                self._val = _val
                ret = '<%s: [%s]>' % (name, ',\n'.join(content))
            else:
                ret = '<%s: %s>' % (name, self._show_val())
        else:
            ret = '<%s>' % name
        #
        if self._par is None:
            _root_obj = root_obj
        #
        return ret
    
    #--------------------------------------------------------------------------#
    # value management
    #--------------------------------------------------------------------------#
    
    def set_val(self, val):
        print('ok: %r' % val)
        self._val = val
    
    def get_val(self):
        return self._val
    
    def __call__(self):
        return self._val
    
    def _resolve_ref(self, ref):
        """resolves the reference for dynamic values
        """
        if ref[0][0] == '#':
            # reference not converted correclty, unable to process it
            if not self._SILENT:
                csnlog('%s: unable to resolve reference, %s' % (self._name, ref[0]))
            return 0
        #
        par = self._par
        assert( par is not None )
        for r in ref[0]:
            if r == -1:
                par = par._par
                assert( par is not None )
            else:
                # r is uint
                assert( isinstance(par, (CSN1List, CSN1Alt)) )
                assert( isinstance(par._val, list) and len(par._val) >= r )
                val = par._val[r]
                if isinstance(val, str_types):
                    # CSN1T_BSTR
                    return ref[1](int(val, 2))
                else:
                    # CSN1T_UINT or custom callback
                    return ref[1](val)
    
    #--------------------------------------------------------------------------#
    # object common API with pycrate_core.elt.Element 
    #--------------------------------------------------------------------------#
    
    #def _from_char_obj(self, char):
    #    raise(CSN1Err('not implemented'))
    # 
    #def _to_pack_obj(self):
    #    raise(CSN1Err('not implemented'))
    
    def _from_char(self, char):
        global _root_obj
        #
        if self._par is None:
            root_obj = _root_obj
            _root_obj = self
        #
        if self._lref is not None:
            if isinstance(self._lref, integer_types):
                # static shortage of the char buffer
                lref = self._lref
            else:
                # dynamic shortage of the char buffer
                lref = self._resolve_ref(self._lref)
            char_lb = char._len_bit
            char._len_bit = char._cur + lref
            assert( char._len_bit <= char_lb )
        #
        if isinstance(self._num, tuple):
            # dynamic number of repetitions
            num = self._resolve_ref(self._num)
        else:
            # static number of repetitions
            num = self._num
        if num == 1:
            self._from_char_obj(char)
        elif num > 1:
            val = []
            for i in range(num):
                self._from_char_obj(char)
                val.append( self._val )
            self._val = val
        elif num == -1:
            # infinite number of repetitions
            val = []
            while char.len_bit():
                char_cur = char._cur
                #csnlog('%s: char_cur, %i' % (self._name, char_cur))
                try:
                    self._from_char_obj(char)
                except (CSN1NoCharErr, CSN1InvalidValueErr) as err:
                    # we went to far, have to exit the loop
                    #csnlog('%s: err, %s' % (self._name, err))
                    char._cur = char_cur
                    break
                else:
                    val.append( self._val )
                    #csnlog('%s: val, %r' % (self._name, val))
            self._val = val
            #csnlog('%s: self._val, %r' % (self._name, self._val))
        else:
            assert()
        #
        if self._lref is not None:
            # restore the original char buffer length
            char._len_bit = char_lb
        #
        if self._par is None:
            _root_obj = root_obj
    
    def _to_pack(self):
        global _root_obj
        #
        if self._par is None:
            root_obj  = _root_obj
            _root_obj = self
        #
        # TODO: check if we want to encode automatically the referred field
        # in case self._lref is set
        #
        ret = []
        if isinstance(self._num, tuple):
            # dynamic number of repetitions
            num = self._resolve_ref(self._num)
        else:
            # static number of repetitions
            num = self._num
        if num == 1:
            ret.extend( self._to_pack_obj() )
        elif num == -1 or num > 1:
            # self._val is a list
            assert( isinstance(self._val, list) )
            if num > 1:
                assert( len(self._val) == num )
            _num = self._num
            _val = self._val
            self._num = 1
            for val in _val:
                self._val = val
                ret.extend( self._to_pack_obj() )
            self._num = _num
            self._val = _val
        else:
            assert()
        #
        if self._par is None:
            _root_obj = root_obj
        #
        return ret
    
    def get_bl(self):
        # this is required to support .bin() and .hex()
        # we use _to_pack() because counting bits for CSN1Alt depends on the
        # value set and needs value propagation and so on... and it's hard...
        if self._val is None:
            return 0
        else:
            return sum([p[2] for p in self._to_pack()])
    
    def from_bytes(self, buf):
        if isinstance(buf, bytes_types):
            char = Charpy(buf)
        else:
            char = buf
        self._from_char(char)
    
    def to_bytes(self):
        if self._val is None:
            return b''
        else:
            return pack_val( *self._to_pack() )[0]
    
    # TODO: implement _from_char / _to_pack methods building structures
    # with Envelope() and Atom() elements... hard work
    def from_bytes_ws(self, buf):
        raise(CSN1Err('not implemented'))
    
    def to_bytes_ws(self, buf):
        raise(CSN1Err('not implemented'))
    
    def _clone_get_kw(self):
        kw = {}
        if self._name:
            kw['name'] = self._name
        if self._num != self.__class__._num:
            kw['num'] = self._num
        if self._lref != self.__class__._lref:
            kw['lref'] = self._lref
        return kw
    
    def clone(self):
        """Returns a independant instance of self, all internal attributes
        are cloned except value
        """
        raise(CSN1Err('not implemented'))


class CSN1Bit(CSN1Obj):
    """Class to handle a CSN.1 bit field
    
    specific internal attributes:
        - bit : number of bits in the bit field (default 1)
        - type: CSN1T_UINT (default) or CSN1T_BSTR, how the value is handled
        - dic : dictionnary for value representation
        - val : uint (type CSN1T_UINT) or bit string (type CSN1T_BSTR)
    """
    
    _bit  = 1
    _type = CSN1T_UINT
    _dic  = None
    
    def __init__(self, **kw):
        CSN1Obj.__init__(self, **kw)
        if 'bit' in kw and kw['bit'] != 1:
            self._bit  = kw['bit']
        if 'type' in kw and kw['type'] != self.__class__._type:
            self._type = kw['type']
        if 'dict' in kw and kw['dict'] is not None:
            self._dic  = kw['dict']
    
    def _repr_val(self):
        if self._REPR == 'B' and self._type == CSN1T_UINT:
            if isinstance(self._bit, tuple):
                bit = self._resolve_ref(self._bit)
            elif self._bit == -1:
                if hasattr(self, '_valbl'):
                    bit = self._valbl
                else:
                    bit = 0
            else:
                bit = self._bit
            val = uint_to_bitstr(self._val, bit)
        else:
            val = self._val
        if self._dic and self._val in self._dic:
            return '%r (%s)' % (val, self._dic[self._val])
        else:
            # int or bit-string
            return val.__repr__()
    
    _show_val = _repr_val
    
    def _from_char_obj(self, char):
        if isinstance(self._bit, tuple):
            # dynamic number of bits
            bit = self._resolve_ref(self._bit)
        elif self._bit == -1:
            # consumes all the remaining bits
            bit = char.len_bit()
            self._valbl = bit
        else:
            # static number of bits
            bit = self._bit
        try:
            self._val = char.get_uint(bit)
        except CharpyErr:
            raise(CSN1NoCharErr())
        else:
            self._off += bit
            self._off %= 8
            if self._type == CSN1T_BSTR:
                self._val = uint_to_bitstr(self._val, bit)
    
    def _to_pack_obj(self):
        if isinstance(self._bit, tuple):
            # dynamic number of bits
            bit = self._resolve_ref(self._bit)
        elif self._bit == -1:
            # requires to know the length in bits
            if hasattr(self, '_valbl'):
                bit = self._valbl
            else:
                # do not encode
                return []
        else:
            # static number of bits
            bit = self._bit
        self._off += bit
        self._off %= 8
        if self._type == CSN1T_UINT:
            return [(CSN1T_UINT, self._val, bit)]
        else:
            return [(CSN1T_UINT, int(self._val, 2), bit)]
    
    def clone(self):
        kw = self._clone_get_kw()
        if self._bit != self.__class__._bit:
            kw['bit'] = self._bit
        if self._type != self.__class__._type:
            kw['type'] = self._type
        if self._dic != self.__class__._dic:
            kw['dic'] = self._dic
        return self.__class__(**kw)


class CSN1Val(CSN1Obj):
    """Class to handle a CSN.1 value
    
    specific internal attributes:
        - val: bit string or 'null'
    """
    
    _val = ''
    
    def __init__(self, **kw):
        CSN1Obj.__init__(self, **kw)
        if 'L' in self._val or 'H' in self._val:
            # TODO: support mixed padding L/H and non-padding 0/1 values
            assert( '0' not in self._val )
            assert( '1' not in self._val )
            self._pad_gsm = 1
        else:
            self._pad_gsm = 0
        if self._val[-2:] == '**':
            self._val = self._val[:-2]
            self._num = -1
    
    def _repr_val(self):
        return self._val.__repr__()
    
    _show_val = _repr_val
    
    def _from_char_obj(self, char):
        if self._val == 'null':
            return
        bit = len(self._val)
        if bit:
            try:
                val = char.get_uint(bit)
            except CharpyErr:
                raise(CSN1NoCharErr())
            else:
                if self._pad_gsm:
                    # convert val to a bit-string to be compared to self._val
                    val_p = CSN1Obj.conv_b_pad_gsm(uint_to_bitstr(val, bit), self._off)
                    if self._val != val_p:
                        raise(CSN1InvalidValueErr())
                    else:
                        self._off += bit
                        self._off %= 8
                else:
                    if int(self._val, 2) != val:
                        raise(CSN1InvalidValueErr())
                    else:
                        self._off += bit
                        self._off %= 8
    
    def _to_pack_obj(self):
        if self._val == 'null':
            return []
        bit = len(self._val)
        if not bit:
            return []
        else:
            if self._pad_gsm:
                bl = []
                for i, c in enumerate(self._val):
                    p = self.Lv[self._off+i]
                    if c == 'L':
                        # padding value
                        bl.append(p)
                    else:
                        # non-padding value
                        bl.append(p^1)
                self._off += bit
                self._off %= 8
                return [(CSN1T_UINT, bitlist_to_uint(bl), bit)]
            else:
                self._off += bit
                self._off %= 8
                return [(CSN1T_UINT, int(self._val, 2), bit)]
    
    def clone(self):
        kw = self._clone_get_kw()
        if self._val != self.__class__._val:
            kw['val'] = self._val
        return self.__class__(**kw)


class CSN1Ref(CSN1Obj):
    """Class to handle a reference to another CSN.1 object
    
    specific internal attributes:
        - obj: ASN1Obj instance
        - val: value according to obj
    """
    
    _obj = None
    
    def __init__(self, **kw):
        CSN1Obj.__init__(self, **kw)
        if 'obj' in kw and kw['obj']:
            self._obj = kw['obj']
    
    def _repr_val(self):
        obj_val        = self._obj._val
        self._obj._val = self._val
        obj_repr       = self._obj.repr()
        self._obj._val = obj_val
        return obj_repr
    
    def _show_val(self):
        obj_val        = self._obj._val
        self._obj._val = self._val
        obj_repr       = self._obj.show()
        self._obj._val = obj_val
        return obj_repr
    
    def _from_char_obj(self, char):
        obj_val = self._obj._val
        obj_off = self._obj._off
        self._obj._off = self._off
        try:
            self._obj._from_char(char)
        except (CSN1NoCharErr, CSN1InvalidValueErr) as err:
            self._val = None
            self._obj._val = obj_val
            self._obj._off = obj_off
            raise(err)
        else:
            self._val = self._obj._val
            self._off = self._obj._off
            self._obj._val = obj_val
            self._obj._off = obj_off
    
    def _to_pack_obj(self):
        obj_val = self._obj._val
        obj_off = self._obj._off
        self._obj._val = self._val
        self._obj._off = self._off
        ret = self._obj._to_pack()
        self._off = self._obj._off
        self._obj._val = obj_val
        self._obj._off = obj_off
        return ret
    
    def clone(self):
        kw = self._clone_get_kw()
        kw['obj'] = self._obj.clone()
        return self.__class__(**kw)


class CSN1List(CSN1Obj):
    """Class to handle a CSN.1 list of CSN1Obj instances
    
    specific internal attributes:
        - list : list of CSN1Obj instances
        - trunc: enables the list of values to be truncated
        - val  : list of CSN1Obj values
    """
    
    _list  = []
    _trunc = False
    
    def __init__(self, **kw):
        CSN1Obj.__init__(self, **kw)
        if 'list' in kw and kw['list']:
            self._list = kw['list']
            for Obj in self._list:
                Obj._par = self
        if 'trunc' in kw and kw['trunc']:
            self._trunc = True
    
    def _repr_val(self):
        content = []
        for i, val in enumerate(self._val):
            Obj = self._list[i]
            obj_val  = Obj._val
            Obj._val = val
            content.append( Obj.repr() )
            Obj._val = obj_val
        if not content:
            return '[]'
        else:
            return '[' + ''.join(content) + ']'
    
    def _show_val(self):
        content = []
        for i, val in enumerate(self._val):
            Obj = self._list[i]
            obj_val  = Obj._val
            Obj._val = val
            content.append( Obj.show().replace('\n', '\n ') )
            Obj._val = obj_val
        if not content:
            return '[]'
        else:
            return '[\n ' + '\n '.join(content) + ']'
    
    def _from_char_obj(self, char):
        self._val = []
        for Obj in self._list:
            obj_val = Obj._val
            obj_off = Obj._off
            Obj._off = self._off
            try:
                Obj._from_char(char)
            except (CSN1NoCharErr, CSN1InvalidValueErr) as err:
                # TODO: it will be required at some point to handle truncation
                # properly (e.g. "//" at the end of a CSN1 list)
                Obj._val = obj_val
                Obj._off = obj_off
                if self._trunc:
                    break
                else:
                    raise(err)
            else:
                self._val.append( Obj._val )
                self._off = Obj._off
                Obj._val = obj_val
                Obj._off = obj_off
    
    def _to_pack_obj(self):
        ret = []
        for i, val in enumerate(self._val):
            Obj = self._list[i]
            obj_off = Obj._off
            Obj._off = self._off
            if isinstance(Obj, CSN1Val):
                ret.extend( Obj._to_pack() )
            else:
                obj_val  = Obj._val
                Obj._val = val
                ret.extend( Obj._to_pack() )
                Obj._val = obj_val
            self._off = Obj._off
            Obj._off = obj_off
        return ret
    
    def clone(self):
        kw = self._clone_get_kw()
        if self._list:
            kw['list'] = [Obj.clone() for Obj in self._list]
        if self._trunc:
            kw['trunc'] = True
        return self.__class__(**kw)


class CSN1Alt(CSN1Obj):
    """Class to handle a CSN.1 alternative between multiple list of CSN1Obj 
    instances
    
    specific internal attributes:
        - alt : dict of { key bit-string : list of CSN1Obj instances }
        - kdic: dictionnary of {key bit-string : alternative name}
        - kord: dictionnary of {key length: {set of keys of given length}}
        - val : list of CSN1Obj values
    """
    # ENC_LREF enables to automatically encode length determinant
    ENC_LREF = True
    
    _alt   = {}
    _kdic  = None
    _trunc = False
    
    def __init__(self, **kw):
        CSN1Obj.__init__(self, **kw)
        if 'alt' in kw and kw['alt']:
            self._alt = kw['alt']
            for alt in self._alt.values():
                for Obj in alt[1]:
                    Obj._par = self
        if 'kdic' in kw and kw['kdic']:
            self._kdic = kw['kdic']
        #
        keys = [k for k in self._alt if k is not None and len(k) > 0]
        if any(['L' in k or 'H' in k for k in keys]):
            # TODO: support mixed padding L/H and non-padding 0/1 keys
            assert( all(['0' not in k and '1' not in k for k in keys]) )
            self._pad_gsm = 1
        else:
            self._pad_gsm = 0
        #
        klen = set([len(k) for k in keys])
        self._kord = {kl: set([k for k in keys if len(k) == kl]) for kl in klen}
    
    def _repr_val(self):
        if not self._val:
            return '{}'
        else:
            k = self._val[0]
            if self._kdic and k in self._kdic:
                alt_name = self._kdic[k]
            else:
                alt_name = self._alt[k][0]
            alt_list = self._alt[k][1]
            if alt_name:
                pref = '{%r (%s): [' % (k, alt_name)
            else:
                pref = '{%r, [' % k
            content = []
            for i, val in enumerate(self._val[1:]):
                Obj = alt_list[i]
                obj_val  = Obj._val
                Obj._val = val
                content.append( Obj.repr() )
                Obj._val = obj_val
            if not content:
                return pref + ']}'
            else:
                return pref + ''.join(content) + ']}'
    
    def _show_val(self):
        if not self._val:
            return '{}'
        else:
            k = self._val[0]
            if self._kdic and k in self._kdic:
                alt_name = self._kdic[k]
            else:
                alt_name = self._alt[k][0]
            alt_list = self._alt[k][1]
            if alt_name:
                pref = '{%r (%s): [\n ' % (k, alt_name)
            else:
                pref = '{%r, [\n ' % k
            content = []
            for i, val in enumerate(self._val[1:]):
                Obj = alt_list[i]
                obj_val  = Obj._val
                Obj._val = val
                content.append( Obj.show().replace('\n', '\n ') )
                Obj._val = obj_val
            if not content:
                return pref[:-2] + ']}'
            else:
                return pref + '\n '.join(content) + ']}'
    
    def _from_char_obj(self, char):
        self._val = []
        # 
        # 1) select alternative
        if '' in self._alt and char.len_bit() > 0:
            k = ''
        elif None in self._alt and char.len_bit() == 0:
            # not entering any alternative
            #self._val = None
            return
        else:
            # start with the shortest to the longest key
            found = False
            for kl, keys in self._kord.items():
                try:
                    k = uint_to_bitstr(char.to_uint(kl), kl)
                except CharpyErr:
                    raise(CSN1NoCharErr())
                if self._pad_gsm:
                    # convert k to a bit-string to be compared to keys
                    k = CSN1Obj.conv_b_pad_gsm(k, self._off)
                if k in keys:
                    found = True
                    char._cur += kl
                    self._off += kl
                    self._off %= 8
                    break
            if not found:
                raise(CSN1InvalidValueErr())
        #
        obj_list = self._alt[k][1]
        self._val.append(k)
        #
        # 2) decode alternative
        for Obj in obj_list:
            obj_val = Obj._val
            obj_off = Obj._off
            Obj._off = self._off
            try:
                Obj._from_char(char)
            except (CSN1NoCharErr, CSN1InvalidValueErr) as err:
                # TODO: it will be required at some point to handle truncation
                # properly (e.g. "//" at the end of a CSN1 list)
                Obj._val = obj_val
                Obj._off = obj_off
                if self._trunc:
                    break
                else:
                    raise(err)
            else:
                self._val.append( Obj._val )
                self._off = Obj._off
                Obj._val = obj_val
                Obj._off = obj_off
    
    def _to_pack_obj(self):
        ret = []
        if not self._val and None in self._alt:
            return ret
        # encode alternative selector
        k = self._val[0]
        assert( isinstance(k, str_types) )
        if k:
            # TODO: handle L/H keys
            if self._pad_gsm:
                bl = []
                for i, c in enumerate(k):
                    p = self.Lv[self._off+i]
                    if c == 'L':
                        # padding value
                        bl.append(p)
                    else:
                        # non-padding value
                        bl.append(p^1)
                ret.append( (CSN1T_UINT, bitlist_to_uint(bl), len(k)) )
            else:
                ret.append( (CSN1T_UINT, int(k, 2), len(k)) )
            self._off += len(k)
            self._off %= 8
        obj_list = self._alt[k][1]
        #
        # encode alternative list
        for i, val in enumerate(self._val[1:]):
            Obj = obj_list[i]
            obj_off = Obj._off
            Obj._off = self._off
            if isinstance(Obj, CSN1Val):
                ret.extend( Obj._to_pack() )
            else:
                obj_val  = Obj._val
                Obj._val = val
                ret.extend( Obj._to_pack() )
                Obj._val = obj_val
            self._off = Obj._off
            Obj._off = obj_off
        return ret
    
    def clone(self):
        kw = self._clone_get_kw()
        kw['kord'] = self._kord
        if self._alt:
            kw['alt'] = {k: (self._alt[k][0], [Obj.clone() for Obj in self._alt[k][1]]) for k in self._alt}
        if self._kdic != self.__class__._kdic:
            kw['kdic'] = self._kdic
        if self._trunc:
            kw['trunc'] = True
        return self.__class__(**kw)


class CSN1SelfRef(CSN1Obj):
    """Class to handle a reference to the root CSN1 object
    
    specific internal attributes:
        - val: value according to the root object
    """
    
    def _repr_val(self):
        global _root_obj
        root_obj_val   = _root_obj._val
        _root_obj._val = self._val
        root_obj_repr  = _root_obj.repr()
        _root_obj._val = root_obj_val
        return root_obj_repr
    
    def _show_val(self):
        global _root_obj
        root_obj_val   = _root_obj._val
        _root_obj._val = self._val
        root_obj_repr  = _root_obj.show()
        _root_obj._val = root_obj_val
        return root_obj_repr
    
    def _from_char_obj(self, char):
        global _root_obj
        if _root_obj is None:
            raise(CSN1Err('{0}: no root object referenced'.format(self._name)))
        # preserve already existing root object value
        root_obj_val = _root_obj._val
        _root_obj._from_char(char)
        self._val = _root_obj._val
        # restore initial value
        _root_obj._val = root_obj_val
    
    def _to_pack_obj(self):
        global _root_obj
        if _root_obj is None:
            raise(CSN1Err('{0}: no root object referenced'.format(self._name)))
        # preserve already existing root object value
        root_obj_val = _root_obj._val
        _root_obj._val = self._val
        ret = _root_obj._to_pack()
        # restore initial value
        _root_obj._val = root_obj_val
        return ret
    
    def clone(self):
        return self.__class__(**self._clone_get_kw())

