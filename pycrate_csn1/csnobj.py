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
# * File Name : pycrate_csn1/csnobj.py
# * Created : 2017-06-12
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from pycrate_core.utils  import *
from pycrate_core.charpy import *

from .utils import *

from pycrate_core.elt import _with_json
if _with_json:
    from pycrate_core.elt import JsonEnc, JsonDec, JSONDecodeError


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
                if isinstance(self, CSN1Val) and self._val:
                    # fixed value repeated N times
                    if num == -1:
                        ret = '<%s: %s**>' % (name, self._val[0])
                    else:
                        ret = '<%s: %s*%i>' % (name, self._val[0], num)
                else:
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
                # multiple iteration of the object's value
                if isinstance(self, CSN1Val) and self._val:
                    # fixed value repeated N times
                    if num == -1:
                        ret = '<%s: %s**>' % (name, self._val[0])
                    else:
                        ret = '<%s: %s*%i>' % (name, self._val[0], num)
                else:
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
        self._val = val
    
    def get_val(self):
        return self._val
    
    def __call__(self):
        return self.get_val()
    
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
        # TODO: ultimately, this offset reset could be removed...
        self._off = 0
        self._from_char_csn(char)
    
    def _from_char_csn(self, char):
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
        #csnlog('%-20s: offset %i' % (self._name, self._off))
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
        # TODO: ultimately, this offset reset could be removed...
        self._off = 0
        return self._to_pack_csn()
    
    def _to_pack_csn(self):
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
        #csnlog('%-20s: offset %i' % (self._name, self._off))
        if num == 1:
            ret.extend( self._to_pack_obj() )
        elif num == -1 or num > 1:
            # self._val is a list
            assert( isinstance(self._val, list) )
            if num > 1:
                assert( len(self._val) == num )
            sval = self._val
            for v in sval:
                self._val = v
                ret.extend( self._to_pack_obj() )
            self._val = sval
        else:
            assert()
        #
        if self._par is None:
            _root_obj = root_obj
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
    
    if _with_json:
        
        def _from_jval(self, val):
            raise(CSN1Err('not implemented'))
        
        def _from_jval_csn(self, val):
            if self._name:
                if not isinstance(val, dict) or len(val) != 1:
                    raise(CSN1Err('{0}: invalid json value, {1}'.format(self._name, val)))
                name, val = tuple(val.items())[0]
                if name != self._name:
                    raise(CSN1Err('{0}: invalid json value, {1}'.format(self._name, val)))
            #
            global _root_obj
            #
            if self._par is None:
                root_obj = _root_obj
                _root_obj = self
            #
            if isinstance(self._num, tuple):
                # dynamic number of repetitions
                num = self._resolve_ref(self._num)
            else:
                # static number of repetitions
                num = self._num
            #
            if num == 1:
                self._from_jval(val)
            elif num == -1 or num > 1:
                if not isinstance(val, list):
                    raise(CSN1Err('{0}: invalid json value, {1}'.format(self._name, val)))
                sval = []
                for i, v in enumerate(val):
                    self._from_jval(v)
                    sval.append( self._val )
                    if num > 1 and i >= num:
                        raise(CSN1Err('{0}: invalid json value, {1}'.format(self._name, val)))
                self._val = sval
            else:
                assert()
            #
            if self._par is None:
                _root_obj = root_obj
        
        def from_json(self, txt):
            try:
                val = JsonDec.decode(txt)
            except JSONDecodeError as err:
                raise(CSN1Err('{0}: invalid json, {1}'.format(self._name, err)))
            self._from_jval_csn(val)
        
        def _to_jval(self):
            raise(CSN1Err('not implemented'))
        
        def _to_jval_csn(self):
            global _root_obj
            #
            if self._par is None:
                root_obj  = _root_obj
                _root_obj = self
            #
            if isinstance(self._num, tuple):
                # dynamic number of repetitions
                num = self._resolve_ref(self._num)
            else:
                # static number of repetitions
                num = self._num
            #
            ret = None
            if num == 1:
                ret = self._to_jval()
            elif num == -1 or num > 1:
                # self._val is a list
                assert( isinstance(self._val, list) )
                if num > 1:
                    assert( len(self._val) == num )
                snum, sval, ret = self._num, self._val, []
                self._num = 1
                for v in sval:
                    self._val = v
                    ret.append( self._to_jval() )
                self._num, self._val = snum, sval
            else:
                assert()
            #
            if self._par is None:
                _root_obj = root_obj
            if self._name:
                return {self._name: ret}
            else:
                return ret
        
        def to_json(self):
            return JsonEnc.encode(self._to_jval_csn())


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
        if 'dic' in kw and kw['dic'] is not None:
            self._dic  = kw['dic']
    
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
            return '%s (%s)' % (val, self._dic[self._val])
        else:
            # int or bit-string
            return str(val)
    
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
            self._off = (self._off + bit) % 8
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
        self._off = (self._off + bit) % 8
        if self._type == CSN1T_UINT:
            return [(CSN1T_UINT, self._val, bit)]
        else:
            return [(CSN1T_BSTR, int(self._val, 2), bit)]
    
    def clone(self):
        kw = self._clone_get_kw()
        if self._bit != self.__class__._bit:
            kw['bit'] = self._bit
        if self._type != self.__class__._type:
            kw['type'] = self._type
        if self._dic != self.__class__._dic:
            kw['dic'] = self._dic
        return self.__class__(**kw)
    
    if _with_json:
        
        def _from_jval(self, val):
            if isinstance(self._bit, tuple):
                bit = self._resolve_ref(self._bit)
            elif self._bit == -1:
                # consumes all the remaining bits
                bit = len(val)
                self._valbl = bit
            else:
                # static number of bits
                bit = self._bit
            if len(val) != bit:
                raise(CSN1Err('{0}: invalid json value, {1!r}'.format(self._name, val)))
            if self._type == CSN1T_UINT:
                try:
                    self._val = bitstr_to_uint(val)
                except Exception:
                    raise(CSN1Err('{0}: invalid json value, {1!r}'.format(self._name, val)))
            else:
                self._val = val
        
        def _to_jval(self):
            if isinstance(self._bit, tuple):
                bit = self._resolve_ref(self._bit)
            elif self._bit == -1:
                if hasattr(self, '_valbl'):
                    bit = self._valbl
                else:
                    bit = 0
            else:
                bit = self._bit
            
            self._off = (self._off + bit) % 8
            if self._type == CSN1T_BSTR:
                return self._val
            else:
                return uint_to_bitstr(self._val, bit)


class CSN1Val(CSN1Obj):
    """Class to handle a CSN.1 value
    
    specific internal attributes:
        - stat: fixed bit string or 'null'
        - val: bit string or 'null'
    
    specific init args:
        - val: fixed bit string or 'null' to set _stat attribute
    """
    
    _val = None
    
    def __init__(self, **kw):
        if 'name' in kw and kw['name']:
            self._name = kw['name']
        if 'num' in kw and kw['num'] != 1:
            self._num  = kw['num']
        if 'lref' in kw and kw['lref'] is not None:
            self._lref = kw['lref']
        # self._val can be used temporarly during encoding / decoding
        # hence the need to keep the static value into another attribute _stat
        if 'val' in kw:
            self._stat = kw['val']
        else:
            assert()
        # offset for dealing with L / H bits
        self._off = 0
        # verification and constraint on the static value
        if 'L' in self._stat or 'H' in self._stat:
            # TODO: support mixed padding L/H and non-padding 0/1 values
            assert( '0' not in self._stat )
            assert( '1' not in self._stat )
            self._pad_gsm = 1
        else:
            self._pad_gsm = 0
        if self._stat[-2:] == '**':
            self._stat = self._stat[:-2]
            self._num = -1
    
    def set_val(self, val):
        self._val = val
    
    def get_val(self):
        return self._val
    
    def _repr_val(self):
        return str(self._val)
    
    _show_val = _repr_val
    
    def _from_char_obj(self, char):
        if self._stat == 'null':
            return
        bit = len(self._stat)
        if not bit:
            return
        try:
            val = char.get_uint(bit)
        except CharpyErr:
            raise(CSN1NoCharErr())
        else:
            if self._pad_gsm:
                # convert val to a bit-string to be compared to self._stat
                val_p = CSN1Obj.conv_b_pad_gsm(uint_to_bitstr(val, bit), self._off)
                if self._stat != val_p:
                    raise(CSN1InvalidValueErr())
                else:
                    self._val = self._stat
            else:
                if int(self._stat, 2) != val:
                    raise(CSN1InvalidValueErr())
                else:
                    self._val = self._stat
            self._off = (self._off + bit) % 8
    
    def _to_pack_obj(self):
        if self._stat == 'null':
            return []
        bit = len(self._stat)
        if not bit:
            return []
        if self._pad_gsm:
            bl = []
            for i, c in enumerate(self._stat):
                p = self.Lv[self._off+i]
                if c == 'L':
                    # padding value
                    bl.append(p)
                else:
                    # non-padding value
                    bl.append(p^1)
            self._off = (self._off + bit) % 8
            return [(CSN1T_UINT, bitlist_to_uint(bl), bit)]
        else:
            self._off = (self._off + bit) % 8
            return [(CSN1T_UINT, int(self._stat, 2), bit)]
    
    def clone(self):
        kw = self._clone_get_kw()
        kw['val'] = self._stat
        return self.__class__(**kw)
    
    if _with_json:
        
        def _from_jval(self, val):
            if val != self._stat:
                raise(CSN1Err('{0}: invalid json value, {1!r}'.format(self._name, val)))
            else:
                self._val = self._stat
        
        def _to_jval(self):
            return self._stat


class CSN1Ref(CSN1Obj):
    """Class to handle a reference to another CSN.1 object
    
    specific internal attributes:
        - obj: ASN1Obj instance
        - val: value according to obj
        
    specific init args:
        - obj
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
        # transfer offset to self._obj
        obj_off, obj_val = self._obj._off, self._obj._val
        self._obj._off = self._off
        try:
            self._obj._from_char_csn(char)
        except (CSN1NoCharErr, CSN1InvalidValueErr) as err:
            # restore offset and val
            self._obj._off, self._obj._val = obj_off, obj_val
            self._val = None
            raise(err)
        else:
            # restore offset and val
            self._off, self._val = self._obj._off, self._obj._val
            self._obj._off, self._obj._val = obj_off, obj_val
    
    def _to_pack_obj(self):
        # transfer offset and value to self._obj
        obj_off, obj_val = self._obj._off, self._obj._val
        self._obj._off, self._obj._val = self._off, self._val
        ret = self._obj._to_pack_csn()
        # restore offset and value
        self._off = self._obj._off
        self._obj._off, self._obj._val = obj_off, obj_val
        return ret
    
    def clone(self):
        kw = self._clone_get_kw()
        kw['obj'] = self._obj.clone()
        return self.__class__(**kw)
    
    if _with_json:
        
        def _from_jval(self, val):
            obj_val = self._obj._val
            self._obj._from_jval_csn(val)
            self._val = self._obj._val
            self._obj._val = obj_val
        
        def _to_jval(self):
            obj_val = self._obj._val
            self._obj._val = self._val
            ret = self._obj._to_jval_csn()
            self._obj._val = obj_val
            return ret


class CSN1List(CSN1Obj):
    """Class to handle a CSN.1 list of CSN1Obj instances
    
    specific internal attributes:
        - list : list of CSN1Obj instances
        - trunc: enables the list of values to be truncated
        - val  : list of CSN1Obj values
    
    specific init args:
        - list
        - trunc
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
            # transfer offset to Obj
            obj_off, obj_val = Obj._off, Obj._val
            Obj._off = self._off
            try:
                Obj._from_char_csn(char)
            except (CSN1NoCharErr, CSN1InvalidValueErr) as err:
                # restore offset and val
                Obj._off, Obj._val = obj_off, obj_val
                if self._trunc:
                    break
                else:
                    raise(err)
            else:
                self._val.append( Obj._val )
                # restore offset and val
                self._off = Obj._off
                Obj._off, Obj._val = obj_off, obj_val
    
    def _to_pack_obj(self):
        ret = []
        for i, val in enumerate(self._val):
            Obj = self._list[i]
            # transfer offset and value to Obj
            obj_off, obj_val = Obj._off, Obj._val
            Obj._off, Obj._val = self._off, val
            ret.extend( Obj._to_pack_csn() )
            # restore offset and value
            self._off = Obj._off
            Obj._off, Obj._val = obj_off, obj_val
        return ret
    
    def clone(self):
        kw = self._clone_get_kw()
        if self._list:
            kw['list'] = [Obj.clone() for Obj in self._list]
        if self._trunc:
            kw['trunc'] = True
        return self.__class__(**kw)
    
    if _with_json:
        
        def _from_jval(self, val):
            if not isinstance(val, list):
                raise(CSN1Err('{0}: invalid json value, {1!r}'.format(self._name, val)))
            self._val = []
            for i, Obj in enumerate(self._list):
                obj_val = Obj._val
                try:
                    Obj._from_jval_csn(val[i])
                except IndexError:
                    Obj._val = obj_val
                    if self._trunc:
                        break
                    else:
                        raise(CSN1Err('{0}: invalid json value, {1!r}'.format(self._name, val)))
                else:
                    self._val.append(Obj._val)
                Obj._val = obj_val
        
        def _to_jval(self):
            ret = []
            for i, val in enumerate(self._val):
                Obj = self._list[i]
                obj_val = Obj._val
                Obj._val = val
                ret.append( Obj._to_jval_csn() )
                Obj._val = obj_val
            return ret


class CSN1Alt(CSN1Obj):
    """Class to handle a CSN.1 alternative between multiple list of CSN1Obj 
    instances
    
    specific internal attributes:
        - alt  : dict of { key bit-string : 2-tuple(alternative_name, list of CSN1Obj instances) }
        - trunc: in case the list of objects within alternatives can be truncated
        - kord : dict of {key length: {set of keys of given length}}, built at init
        - val  : list of CSN1Obj values
    
    specific init args:
        - alt
        - trunc
        - kdic : dict of { key bit-string : alternative name } to update potential 
                 alternatives' name from self._alt
    """
    
    _alt   = {}
    _trunc = False
    
    def __init__(self, **kw):
        CSN1Obj.__init__(self, **kw)
        if 'alt' in kw and kw['alt']:
            self._alt = kw['alt']
            for alt in self._alt.values():
                for Obj in alt[1]:
                    Obj._par = self
        if 'kdic' in kw and kw['kdic']:
            # update alternatives' name
            kdic = kw['kdic']
            for k in self._alt:
                if k in kdic:
                    self._alt[k] = (kdic[k], self._alt[k][1])
        if 'trunc' in kw and kw['trunc']:
            self._trunc = True
        self._init_dic()
    
    def _init_dic(self):
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
            alt_name, alt_list = self._alt[k]
            if alt_name:
                pref = '{ %s (%s) : [' % (k, alt_name)
            else:
                pref = '{ %s : [' % k
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
            alt_name, alt_list = self._alt[k]
            if alt_name:
                pref = '{ %s (%s) : [\n ' % (k, alt_name)
            else:
                pref = '{ %s : [\n ' % k
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
                    self._off  = (self._off + kl) % 8
                    break
            if not found:
                raise(CSN1InvalidValueErr())
        #
        obj_list = self._alt[k][1]
        self._val.append(k)
        #
        # 2) decode alternative
        for Obj in obj_list:
            # transfer offset to Obj
            obj_off, obj_val = Obj._off, Obj._val
            Obj._off = self._off
            try:
                Obj._from_char_csn(char)
            except (CSN1NoCharErr, CSN1InvalidValueErr) as err:
                # restore offset and val
                Obj._off, Obj._val = obj_off, obj_val
                if self._trunc:
                    break
                else:
                    raise(err)
            else:
                self._val.append( Obj._val )
                # restore offset and val
                self._off = Obj._off
                Obj._off, Obj._val = obj_off, obj_val
    
    def _to_pack_obj(self):
        ret = []
        if not self._val and None in self._alt:
            return ret
        # encode alternative selector
        k = self._val[0]
        assert( isinstance(k, str_types) )
        if k:
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
            self._off = (self._off + len(k)) % 8
        obj_list = self._alt[k][1]
        #
        # encode alternative list
        for i, val in enumerate(self._val[1:]):
            Obj = obj_list[i]
            # transfer offset and value to Obj
            obj_off, obj_val = Obj._off, Obj._val
            Obj._off, Obj._val = self._off, val
            ret.extend( Obj._to_pack_csn() )
            # restore offset and value
            self._off = Obj._off
            Obj._off, Obj._val = obj_off, obj_val
        return ret
    
    def clone(self):
        kw = self._clone_get_kw()
        if self._trunc:
            kw['trunc'] = True
        clo = self.__class__(**kw)
        # handle _alt and _kdic out of the init process
        clo._alt = {}
        for (k, (altname, altlist)) in self._alt.items():
            clo_altlist = [Obj.clone() for Obj in altlist]
            [setattr(Obj, '_par', clo) for Obj in clo_altlist]
            clo._alt[k] = (altname, clo_altlist)
        clo._kord    = self._kord
        clo._pad_gsm = self._pad_gsm
        return clo
    
    if _with_json:
        
        def _from_jval(self, val):
            if not isinstance(val, list):
                raise(CSN1Err('{0}: invalid json value, {1!r}'.format(self._name, val)))
            self._val = []
            if not val:
                if None in self._alt:
                    return
                else:
                    raise(CSN1Err('{0}: invalid json value, {1!r}'.format(self._name, val)))
            else:
                k = val[0]
            self._val = [k]
            #
            try:
                alt_name, obj_list = self._alt[k]
            except KeyError:
                raise(CSN1Err('{0}: invalid json value, {1!r}'.format(self._name, val)))
            for i, Obj in enumerate(obj_list):
                obj_val = Obj._val
                try:
                    Obj._from_jval_csn(val[1+i])
                except IndexError:
                    Obj._val = obj_val
                    if self._trunc:
                        break
                    else:
                        raise(CSN1Err('{0}: invalid json value, {1!r}'.format(self._name, val)))
                else:
                    self._val.append(Obj._val)
                Obj._val = obj_val
        
        def _to_jval(self):
            if not self._val:
                return []
            else:
                k = self._val[0]
                alt_name, obj_list = self._alt[k]
                ret = [k]
                for i, val in enumerate(self._val[1:]):
                    Obj = obj_list[i]
                    obj_val = Obj._val
                    Obj._val = val
                    ret.append( Obj._to_jval_csn() )
                    Obj._val = obj_val
                return ret


class CSN1SelfRef(CSN1Obj):
    """Class to handle a reference to a root CSN1 object
    
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
        # preserve already existing root object value and offset
        # and transfer offset to it
        obj_off, obj_val = _root_obj._off, _root_obj._val
        _root_obj._off = self._off
        _root_obj._from_char_csn(char)
        self._off, self._val = _root_obj._off, _root_obj._val
        # restore initial value and offset
        _root_obj._off, _root_obj._val = obj_off, obj_val
    
    def _to_pack_obj(self):
        global _root_obj
        if _root_obj is None:
            raise(CSN1Err('{0}: no root object referenced'.format(self._name)))
        # preserve already existing root object value
        obj_off, obj_val = _root_obj._off, _root_obj._val
        _root_obj._off, _root_obj._val = self._off, self._val
        ret = _root_obj._to_pack_csn()
        # restore initial offset and value
        self._off = _root_obj._off
        _root_obj._off, _root_obj._val = obj_off, obj_val
        return ret
    
    def clone(self):
        return self.__class__(**self._clone_get_kw())
    
    if _with_json:
        
        def _from_jval(self, val):
            global _root_obj
            root_obj_val = _root_obj._val
            _root_obj._from_jval_csn(val)
            self._val = _root_obj._val
            _root_obj._val = root_obj_val
        
        def _to_jval(self):
            global _root_obj
            obj_val = _root_obj._val
            _root_obj._val = self._val
            ret = _root_obj._to_jval_csn()
            _root_obj._val = obj_val
            return ret

