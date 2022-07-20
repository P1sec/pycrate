# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
# * Copyright 2018. Benoit Michau. P1Sec.
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
# * File Name : pycrate_asn1rt/asnobj_basic.py
# * Created : 2017-01-31
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/


from .utils   import *
from .err     import *
from .dictobj import *
from .glob    import *
from .refobj  import *
from .setobj  import *
from .asnobj  import *
from .codecs  import *

from .asnobj  import _with_json

#------------------------------------------------------------------------------#
# NULL and BOOLEAN
#------------------------------------------------------------------------------#

class NULL(ASN1Obj):
    __doc__ = """
ASN.1 basic type NULL object

Single value: int 0
%s
""" % ASN1Obj_docstring
    
    TYPE  = TYPE_NULL
    TAG   = 5
    
    def _safechk_val(self, val):
        if val != 0:
            raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        if txt[:4] == 'NULL':
            self._val = 0
            return txt[4:].strip()
        else:
            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                  .format(self.fullname(), txt)))
    
    def _to_asn1(self):
        return 'NULL'
    
    ###
    # conversion between internal value and ASN.1 PER encoding
    ###
    
    def _from_per_ws(self, char):
        self._struct = Envelope(self._name)
        self._val = 0
    
    def _from_per(self, char):
        self._val = 0
    
    def _to_per_ws(self):
        self._struct = Envelope(self._name)
        return self._struct
    
    def _to_per(self):
        return []
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_ber_cont_ws(self, char, vbnd):
        if not isinstance(vbnd, tuple):
            raise(ASN1BERDecodeErr('{0}: invalid NULL constructed structure'\
                  .format(self.fullname())))
        if vbnd[1] != vbnd[0]:
            raise(ASN1BERDecodeErr('{0}: invalid NULL length, {1!r}'\
                  .format(self.fullname(), lval)))
        self._val = 0
        return Buf('V', val=b'', bl=0)
    
    def _decode_ber_cont(self, char, vbnd):
        if not isinstance(vbnd, tuple):
            raise(ASN1BERDecodeErr('{0}: invalid NULL constructed structure'\
                  .format(self.fullname())))
        if vbnd[1] != vbnd[0]:
            raise(ASN1BERDecodeErr('{0}: invalid NULL length, {1!r}'\
                  .format(self.fullname(), lval)))
        self._val = 0
    
    def _encode_ber_cont_ws(self):
        return 0, 0, Buf('V', val=b'', bl=0)
    
    def _encode_ber_cont(self):
        return 0, 0, []
    
    ###
    # conversion between internal value and ASN.1 JER encoding
    ###
    if _with_json:
        
        def _from_jval(self, val):
            if val is None:
                self._val = 0
            else:
                raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                      .format(self.fullname(), val)))
        
        def _to_jval(self):
            return None

    ###
    # conversion between internal value and ASN.1 OER/COER encoding
    ###

    def _from_oer(self, char):
        self._from_per(char)

    def _from_oer_ws(self, char):
        self._from_per_ws()

    def _to_oer(self):
        return self._to_per()

    def _to_oer_ws(self):
        return self._to_per_ws()


class BOOL(ASN1Obj):
    __doc__ = """
ASN.1 basic type BOOLEAN object

Single value: Python bool
%s
""" % ASN1Obj_docstring
    
    TYPE  = TYPE_BOOL
    TAG   = 1
    
    _ASN_RE   = re.compile('TRUE|FALSE')
    _ASN_LUT  = {'FALSE': False, 'TRUE': True, False: 'FALSE', True: 'TRUE'}
    _PER_LUT  = {0: False, 1: True}
    _PER_LUTR = {False: 0, True: 1}
    _OER_LUT = {ASN1CodecOER.TRUE: True, ASN1CodecOER.FALSE: False}
    _OER_LUTS = {ASN1CodecOER.FALSE: 'FALSE', ASN1CodecOER.TRUE: 'TRUE'}
    
    def _safechk_val(self, val):
        if not isinstance(val, bool):
            raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        m = self._ASN_RE.match(txt)
        if m:
            self._val = self._ASN_LUT[m.group()]
            return txt[m.end():].strip()
        else:
            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                  .format(self.fullname(), txt)))
    
    def _to_asn1(self):
        return self._ASN_LUT[self._val]
    
    ###
    # conversion between internal value and ASN.1 PER encoding
    ###
    
    def _from_per_ws(self, char):
        self._struct = Envelope(self._name, GEN=(
                        Uint('V', bl=1, dic={0:'FALSE', 1:'TRUE'}), ))
        self._struct._from_char(char)
        self._val = self._PER_LUT[self._struct[0]._val]
        if ASN1CodecPER.ALIGNED:
            ASN1CodecPER._off[-1] += 1
    
    def _from_per(self, char):
        self._val = self._PER_LUT[char.get_uint(1)]
        if ASN1CodecPER.ALIGNED:
            ASN1CodecPER._off[-1] += 1
    
    def _to_per_ws(self):
        self._struct = Envelope(self._name, GEN=(
                        Uint('V', bl=1, val=self._PER_LUTR[self._val], dic={0:'FALSE', 1:'TRUE'}), ))
        if ASN1CodecPER.ALIGNED:
            ASN1CodecPER._off[-1] += 1
        return self._struct
    
    def _to_per(self):
        if ASN1CodecPER.ALIGNED:
            ASN1CodecPER._off[-1] += 1
        return [(T_UINT, self._PER_LUTR[self._val], 1)]
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_ber_cont_ws(self, char, vbnd):
        if not isinstance(vbnd, tuple):
            raise(ASN1BERDecodeErr('{0}: invalid BOOLEAN constructed structure'\
                  .format(self.fullname())))
        if vbnd[1] - vbnd[0] != 8:
            raise(ASN1BERDecodeErr('{0}: invalid BOOLEAN length, {1!r}'\
                  .format(self.fullname(), lval)))
        char._cur, char._len_bit = vbnd[0], vbnd[1]
        V = Uint('V', bl=8)
        V._from_char(char)
        if V() == 0:
            self._val = False
        else:
            self._val = True
        return V
    
    def _decode_ber_cont(self, char, vbnd):
        if not isinstance(vbnd, tuple):
            raise(ASN1BERDecodeErr('{0}: invalid BOOLEAN constructed structure'\
                  .format(self.fullname())))
        if vbnd[1] - vbnd[0] != 8:
            raise(ASN1BERDecodeErr('{0}: invalid BOOLEAN length, {1!r}'\
                  .format(self.fullname(), lval)))
        char._cur, char._len_bit = vbnd[0], vbnd[1]
        val = char.get_uint(8)
        if val:
            self._val = True
        else:
            self._val = False
    
    def _encode_ber_cont_ws(self):
        if self._val:
            return 0, 1, Uint('V', val=ASN1CodecBER.ENC_BOOLTRUE, bl=8)
        else:
            return 0, 1, Uint('V', val=0, bl=8)
    
    def _encode_ber_cont(self):
        if self._val:
            return 0, 1, [(T_UINT, ASN1CodecBER.ENC_BOOLTRUE, 8)]
        else:
            return 0, 1, [(T_UINT, 0, 8)]
    
    ###
    # conversion between internal value and ASN.1 JER encoding
    ###
    
    if _with_json:
        
        def _from_jval(self, val):
            if isinstance(val, bool):
                self._val = val
            else:
                raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                      .format(self.fullname(), val)))
        
        def _to_jval(self):
            return self._val

    ###
    # conversion between internal value and ASN.1 OER/COER encoding
    ###

    def _from_oer(self, char):
        self._val = (char.get_uint(8) > ASN1CodecOER.FALSE)

    def _from_oer_ws(self, char):
        self._struct = Envelope(self._name, GEN=(
            Uint('V', bl=8, dic=self._OER_LUTS), ))
        self._struct._from_char(char)
        self._val = self._OER_LUT[self._struct[0]._val]

    def _to_oer(self):
        # actually, COER only
        val = ASN1CodecOER.TRUE if (self._val is True) else ASN1CodecOER.FALSE
        return [(T_UINT, val, 8)]

    def _to_oer_ws(self):
        # actually, COER only
        val = ASN1CodecOER.TRUE if (self._val is True) else ASN1CodecOER.FALSE
        self._struct = Envelope(self._name, GEN=(
            Uint('V', bl=8, val=val, dic=self._OER_LUTS), ))
        return self._struct

#------------------------------------------------------------------------------#
# INTEGER and REAL
#------------------------------------------------------------------------------#

class INT(ASN1Obj):
    __doc__ = """
ASN.1 basic type INTEGER object

Single value: Python int

Alternative setting value: Python str (from the object's NamedNumber)
    This is only to be used in set_val() method, and is converted to a Python
    int when set

Specific attribute:
    
    - cont: None or ASN1Dict {ident (str): single value},
        provides the content of the INTEGER object
%s
""" % ASN1Obj_docstring
    
    TYPE  = TYPE_INT
    TAG   = 2
    
    _ASN_RE = re.compile(r'\-{0,1}[0-9]{1,}')
    
    def _safechk_val(self, val):
        if isinstance(val, str_types):
            if not self._cont:
                raise(ASN1ObjErr('{0}: invalid named value, {1!r}'.format(self.fullname(), val)))
            elif val not in self._cont:
                raise(ASN1ObjErr('{0}: invalid named value, {1!r}'.format(self.fullname(), val)))
        else:
            self._safechk_val_int(val)
    
    def _safechk_bnd(self, val):
        # only check bound when an integer is set as value
        if isinstance(val, integer_types):
            ASN1Obj._safechk_bnd(self, val)
    
    def get_name(self):
        """Returns the NamedNumber corresponding to the internal value
        """
        try:
            return self._cont_rev[self._val]
        except Exception:
            return None
    
    def _name_to_val(self):
        try:
            self._val = self._cont[self._val]
        except:
            raise(ASN1ObjErr('{0}: invalid named value, {1!r}'.format(self.fullname(), val)))
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        m = self._ASN_RE.match(txt)
        if m:
            self._val = int(m.group())
            return txt[m.end():].strip()
        elif self._cont:
            if not hasattr(self, '_ASN_RE_CONT'):
                items = list(self._cont.keys())
                items.sort(key=len, reverse=True)
                self._ASN_RE_CONT = re.compile('|'.join(items))
            m = self._ASN_RE_CONT.match(txt)
            if m:
                self._val = self._cont[m.group()]
                return txt[m.end():].strip()
        raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'.format(self.fullname(), txt)))
    
    def _to_asn1(self):
        name = None
        if isinstance(self._val, str_types):
            name = self._val
            self._name_to_val()
        elif self._cont and self._val in self._cont_rev:
            name = self._cont_rev[self._val]
        if name:
            return '%i -- %s --' % (self._val, name)
        else:
            return '%i' % self._val
    
    ###
    # conversion between internal value and ASN.1 PER encoding
    ###
    
    def _from_per_ws(self, char):
        GEN = []
        if self._const_val:
            if self._const_val.ext is not None:
                E = Uint('E', bl=1)
                E._from_char(char)
                GEN.append(E)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                if E():
                    # 1) value in the extension part
                    # decoded as unconstraint integer
                    self._val, _gen = ASN1CodecPER.decode_intunconst_ws(char)
                    self._struct = Envelope(self._name, GEN=tuple(GEN + _gen))
                    return
            # value in the root part
            if self._const_val.rdyn:
                # 2) defined range of possible values
                self._val, _gen = ASN1CodecPER.decode_intconst_ws(char, self._const_val)
                self._struct = Envelope(self._name, GEN=tuple(GEN + _gen))
                return
            elif self._const_val.rdyn == 0:
                # 3) only a single value possible
                self._val = self._const_val.lb
                self._struct = Envelope(self._name, GEN=tuple(GEN))
                return
            elif self._const_val.lb is not None and self._const_val.ub is None:
                # 4) semi-constraint value
                self._val, _gen = ASN1CodecPER.decode_intunconst_ws(char, self._const_val.lb)
                self._struct = Envelope(self._name, GEN=tuple(GEN + _gen))
                return
        # 5) no constraint
        self._val, _gen = ASN1CodecPER.decode_intunconst_ws(char)
        self._struct = Envelope(self._name, GEN=tuple(GEN + _gen))
        return
    
    def _from_per(self, char):
        if self._const_val:
            if self._const_val.ext is not None:
                E = char.get_uint(1)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                if E:
                    # 1) value in the extension part
                    # decoded as unconstraint integer
                    self._val = ASN1CodecPER.decode_intunconst(char)
                    return
            # value in the root part
            if self._const_val.rdyn:
                # 2) defined range of possible values
                self._val = ASN1CodecPER.decode_intconst(char, self._const_val)
                return
            elif self._const_val.rdyn == 0:
                # 3) only a single value possible
                self._val = self._const_val.lb
                return
            elif self._const_val.lb is not None and self._const_val.ub is None:
                # 4) semi-constraint value
                self._val = ASN1CodecPER.decode_intunconst(char, self._const_val.lb)
                return
        # 5) no constraint
        self._val = ASN1CodecPER.decode_intunconst(char)
        return
    
    def _to_per_ws(self):
        if isinstance(self._val, str_types):
            self._name_to_val()
        GEN = []
        if self._const_val:
            if self._const_val.ext is not None:
                if not self._const_val.in_root(self._val):
                    GEN.append( Uint('E', val=1, bl=1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
                    GEN.extend( ASN1CodecPER.encode_intunconst_ws(self._val) )
                    self._struct = Envelope(self._name, GEN=tuple(GEN))
                    return self._struct
                else:
                    GEN.append( Uint('E', val=0, bl=1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
            # value in the root part
            if self._const_val.rdyn:
                # 2) defined range of possible values
                GEN.extend( ASN1CodecPER.encode_intconst_ws(self._val, self._const_val) )
                self._struct = Envelope(self._name, GEN=tuple(GEN))
                return self._struct
            elif self._const_val.rdyn == 0:
                # 3) only a single value possible
                self._struct = Envelope(self._name, GEN=tuple(GEN))
                return self._struct
            elif self._const_val.lb is not None and self._const_val.ub is None:
                # 4) semi-constraint value
                GEN.extend( ASN1CodecPER.encode_intunconst_ws(self._val, self._const_val.lb) )
                self._struct = Envelope(self._name, GEN=tuple(GEN))
                return self._struct
        # 5) no constraint
        GEN.extend( ASN1CodecPER.encode_intunconst_ws(self._val) )
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return self._struct
    
    def _to_per(self):
        if isinstance(self._val, str_types):
            self._name_to_val()
        GEN = []
        if self._const_val:
            if self._const_val.ext is not None:
                if not self._const_val.in_root(self._val):
                    GEN.append( (T_UINT, 1, 1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
                    GEN.extend( ASN1CodecPER.encode_intunconst(self._val) )
                    return GEN
                else:
                    GEN.append( (T_UINT, 0, 1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
            # value in the root part
            if self._const_val.rdyn:
                GEN.extend( ASN1CodecPER.encode_intconst(self._val, self._const_val) )
                return GEN
            elif self._const_val.rdyn == 0:
                # 3) only a single value possible
                return GEN
            elif self._const_val.lb is not None and self._const_val.ub is None:
                # 4) semi-constraint value
                GEN.extend( ASN1CodecPER.encode_intunconst(self._val, self._const_val.lb) )
                return GEN
        # 5) no constraint
        GEN.extend( ASN1CodecPER.encode_intunconst(self._val) )
        return GEN
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_ber_cont_ws(self, char, vbnd):
        if not isinstance(vbnd, tuple):
            raise(ASN1BERDecodeErr('{0}: invalid INTEGER constructed structure'\
                  .format(self.fullname())))
        if vbnd[1] - vbnd[0] <= 0:
            raise(ASN1BERDecodeErr('{0}: invalid INTEGER length, {1!r}'\
                  .format(self.fullname(), vbnd[1]-vbnd[0])))
        char._cur, char._len_bit = vbnd[0], vbnd[1]
        V = Int('V', bl=vbnd[1]-vbnd[0])
        V._from_char(char)
        self._val = V()
        return V
    
    def _decode_ber_cont(self, char, vbnd):
        if not isinstance(vbnd, tuple):
            raise(ASN1BERDecodeErr('{0}: invalid INTEGER constructed structure'\
                  .format(self.fullname())))
        if vbnd[1] - vbnd[0] <= 0:
            raise(ASN1BERDecodeErr('{0}: invalid INTEGER length, {1!r}'\
                  .format(self.fullname(), vbnd[1]-vbnd[0])))
        char._cur, char._len_bit = vbnd[0], vbnd[1]
        self._val = char.get_int(vbnd[1]-vbnd[0])
    
    def _encode_ber_cont_ws(self):
        if isinstance(self._val, str_types):
            self._name_to_val()
        lval = int_bytelen(self._val)
        return 0, lval, Int('V', val=self._val, bl=8*lval)
    
    def _encode_ber_cont(self):
        if isinstance(self._val, str_types):
            self._name_to_val()
        lval = int_bytelen(self._val)
        return 0, lval, [(T_INT, self._val, 8*lval)]

    ###
    # conversion between internal value and ASN.1 JER encoding
    ###
    
    if _with_json:
        
        def _from_jval(self, val):
            if isinstance(val, integer_types):
                self._val = val
            else:
                raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                      .format(self.fullname(), val)))
        
        def _to_jval(self):
            if isinstance(self._val, set):
                self._names_to_val()
            return self._val

    ###
    # conversion between internal value and ASN.1 OER/COER encoding
    ###

    def _to_oer(self):
        if self._const_val:
            # Constraints defined
            if self._const_val.ext is not None:
                # Extensible OER-visible constraints are encoded as integer
                # type with no bounds
                return ASN1CodecOER.encode_intunconst(self._val)

            # Constrained
            return ASN1CodecOER.encode_intconst(self._val, self._const_val)
        else:
            # Unconstrained
            return ASN1CodecOER.encode_intunconst(self._val)

    def _to_oer_ws(self):
        if self._const_val:
            # Constraints defined
            if self._const_val.ext is not None:
                # Extensible OER-visible constraints are encoded as integer
                # type with no bounds
                self._struct = Envelope(
                    self._name,
                    GEN=ASN1CodecOER.encode_intunconst_ws(self._val))
                return self._struct

            # Constrained
            self._struct = Envelope(
                self._name,
                GEN=ASN1CodecOER.encode_intconst_ws(self._val, self._const_val)
            )
            return self._struct
        else:
            # Unconstrained
            self._struct = Envelope(
                self._name,
                GEN=ASN1CodecOER.encode_intunconst_ws(self._val)
            )
            return self._struct

    def _from_oer(self, char):
        if self._const_val:
            if self._const_val.ext is not None:
                self._val = ASN1CodecOER.decode_intunconst(char)
                return

            # Constrained
            self._val = ASN1CodecOER.decode_intconst(char, self._const_val)
            return
        else:
            # Unconstrained
            self._val = ASN1CodecOER.decode_intunconst(char)
            return

    def _from_oer_ws(self, char):
        if self._const_val:
            if self._const_val.ext is not None:
                self._val, _gen = ASN1CodecOER.decode_intunconst_ws(char)
                self._struct = Envelope(self._name, GEN=_gen)
                return

            # Constrained
            self._val, _gen = ASN1CodecOER.decode_intconst_ws(char, self._const_val)
            self._struct = Envelope(self._name, GEN=_gen)
        else:
            # Unconstrained
            self._val, _gen = ASN1CodecOER.decode_intunconst_ws(char)
            self._struct = Envelope(self._name, GEN=_gen)


class REAL(ASN1Obj):
    __doc__ = """
ASN.1 basic type REAL object

Single value: Python tuple of 3 int
    1st int is the mantissa, 2nd is the base, 3rd is the exponent
    Special values are:
    (-1, None, None): MINUS-INFINITY
    (1,  None, None): PLUS-INFINITY
    (0,  None, None): NOT-A-NUMBER

Specific attribute:
    
    - cont: ASN1Dict {"mantissa": int, "base": 2|10, "exponent": int},
        provides the content of the REAL object

%s
""" % ASN1Obj_docstring
    
    # SEQUENCE-like definition of REAL:
    #
    # REAL ::= SEQUENCE {
    #    mantissa INTEGER,
    #    base INTEGER (2|10),
    #    exponent INTEGER }
    
    TYPE  = TYPE_REAL
    TAG   = 9
    
    _ASN_RE = re.compile(
    r'((\-{0,1}[0-9]{1,}){1}(?:\.([0-9]{0,})){0,1}(?:[eE](\-{0,1}[0-9]{1,})){0,1})|'\
    r'(\{\s{0,}mantissa\s{1,}(\-{0,1}[0-9]{1,})\s{0,},\s{0,}base\s{1,}(2|10)\s{0,},\s{0,}exponent\s{1,}(\-{0,1}[0-9]{1,})\s{0,}\})|'\
    r'((?:PLUS\-INFINITY)|(?:MINUS\-INFINITY)|(?:NOT-A-NUMBER))')
    _NR1_RE = re.compile(r'[ 0]{0,}[-+]{0,1}[0-9]{1,}')
    _NR2_RE = re.compile(r'[ 0]{0,}([-+]{0,1}[0-9]{0,})[\.,]{1}([0-9]{0,})')
    _NR3_RE = re.compile(r'[ 0]{0,}([-+]{0,1}[0-9]{0,})[\.,]{1}([0-9]{0,})[eE]([-+]{0,1}[0-9]{1,})')
    
    _ASN_LUT = {'MINUS-INFINITY': (-1, None, None),
                'PLUS-INFINITY' : ( 1, None, None),
                'NOT-A-NUMBER'  : ( 0, None, None),
                (-1, None, None): 'MINUS-INFINITY',
                ( 1, None, None): 'PLUS-INFINITY',
                ( 0, None, None): 'NOT-A-NUMBER'}
    
    _JER_RE = re.compile(r'[ 0]{0,}([-+]{0,1}[0-9]{0,})(?:[\.,]{1}([0-9]{0,})){0,1}[eE]([-+]{0,1}[0-9]{1,})')
    
    def _safechk_val(self, val):
        self._safechk_val_real(val)
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        m = self._ASN_RE.match(txt)
        if m:
            grp = m.groups()
            if grp[0] is not None:
                self._from_asn1_sci(*grp[1:4])
            elif grp[4] is not None:
                self._val = (int(grp[5]), int(grp[6]), int(grp[7]))
            else:
                self._val = self._ASN_LUT[grp[8]]
            return txt[m.end():].strip()
        else:
            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                  .format(self.fullname(), txt)))
    
    def _from_asn1_sci(self, i, d, e):
        # integral, decimal, base 10 exponent parts
        if not d:
            if not e:
                self._val = (int(i), 10, 0)
            else:
                self._val = (int(i), 10, int(e))
        else:
            # decimal part present
            # need to adjust the base 10 exponent
            if not e:
                e = 0
            else:
                e = int(e)
            e -= len(d)
            self._val = (int(i+d), 10, e)
    
    def _to_asn1(self):
        if self._val in self._ASN_LUT:
            return self._ASN_LUT[self._val]
        else:
            return '{mantissa %d, base %d, exponent %d}' % self._val
    
    ###
    # conversion between internal value and ASN.1 PER encoding
    # content is actually encoded like the BER one, prefixed with a bytes count
    ###
    
    def _from_per_ws(self, char):
        buf, GEN = ASN1CodecPER.decode_unconst_open_ws(char, wrapped=None)
        self._decode_cont(buf)
        self._struct = Envelope(self._name, GEN=tuple(GEN))
    
    def _from_per(self, char):
        self._decode_cont( ASN1CodecPER.decode_unconst_open(char, wrapped=None) )
    
    def _to_per_ws(self):
        GEN = ASN1CodecPER.encode_unconst_buf_ws( self._encode_cont() )
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return self._struct
    
    def _to_per(self):
        return ASN1CodecPER.encode_unconst_buf( self._encode_cont() )
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_cont(self, bytes):
        if not bytes:
            # 0 value, whatever base 2 or 10 and exponent
            self._val = ASN1CodecBER.DEC_REALNULL
        else:
            B0 = ord(bytes[0:1])
            b2 = B0 >> 6
            if b2 == 0:
                # base 10: character string encoding
                if B0 == 1:
                    # NR1 encoding, simple whole numbers
                    if python_version < 3:
                        m = self._NR1_RE.match( bytes[1:] )
                    else:
                        m = self._NR1_RE.match( str(bytes[1:], 'ascii') )
                    if not m:
                        raise(ASN1BERDecodeErr('{0}: invalid REAL base 10 NR1 encoding, {1!r}'\
                              .format(self.fullname(), bytes[1:])))
                    mant = int(bytes[1:])
                    self._val = (mant, 10, 0)
                elif B0 == 2:
                    # NR2 encoding, requires a decimal mark
                    if python_version < 3:
                        m = self._NR2_RE.match( bytes[1:] )
                    else:
                        m = self._NR2_RE.match( str(bytes[1:], 'ascii') )
                    if not m:
                        raise(ASN1BERDecodeErr('{0}: invalid REAL base 10 NR2 encoding, {1!r}'\
                              .format(self.fullname(), bytes[1:])))
                    i, d = m.groups()
                    # remove trailing zero of the decimal part and keep track of 
                    # the exponent
                    d = d.rstrip('0')
                    e = -len(d)
                    self._val = (int(i+d), 10, e)
                elif B0 == 3:
                    # NR3 encoding, requires the exponent notation
                    if python_version < 3:
                        m = self._NR3_RE.match( bytes[1:] )
                    else:
                        m = self._NR3_RE.match( str(bytes[1:], 'ascii') )
                    if not m:
                        raise(ASN1BERDecodeErr('{0}: invalid REAL base 10 NR3 encoding, {1!r}'\
                              .format(self.fullname(), bytes[1:])))
                    i, d, e = m.groups()
                    # remove trailing zero of the decimal part and adjust 
                    # the exponent
                    d = d.rstrip('0')
                    if not e:
                        e = -len(d)
                    else:
                        e = int(e) - len(d)
                    self._val = (int(i+d), 10, e)
                else:
                    raise(ASN1BERDecodeErr('{0}: invalid REAL base 10 encoding, {1}'\
                          .format(self.fullname(), B0&0x3F)))
            elif b2 == 1:
                # special values
                if B0 == 64:
                    # PLUS-INFINITY
                    self._val = (1, None, None)
                elif B0 == 65:
                    # MINUS-INFINITY
                    self._val = (-1, None, None)
                elif B0 == 66:
                    # NOT-A-NUMBER
                    self._val = (0, None, None)
                elif B0 == 67:
                    # minus zero
                    self._val = ASN1CodecBER.DEC_REALNULL
                else:
                    raise(ASN1BERDecodeErr('{0}: invalid REAL special value, {1!r}'\
                          .format(self.fullname(), B0&0x3F)))
            else:
                # base 2 encoding
                B0 &= 0x3F
                S, B, F, LE = b2&1, B0>>4, (B0>>2)&3, B0&3
                # decode the exponent
                if LE < 3:
                    E = bytes_to_int(bytes[1:2+LE], 8*(1+LE))
                    bytes = bytes[2+LE:]
                else:
                    # LE == 3
                    LE = ord(bytes[1:2])
                    if len(bytes)-2 < LE:
                        raise(ASN1BERDecodeErr('{0}: invalid REAL base 2 exponent length, {1!r}'\
                              .format(self.fullname(), LE)))
                    E = bytes_to_int(bytes[2:2+LE], 8*LE)
                    bytes = bytes[2+LE:]
                N = bytes_to_uint(bytes, 8*len(bytes))
                # REAL value = (-1)**S * N * 2**F * B**E
                # F is just increasing E, for the REAL standard base 2 notation
                self._val = (N * (-1)**S, 2, E<<F)
    
    def _encode_cont(self):
        if self._val[0] == 0:
            return b''
        elif self._val in self._ASN_LUT:
            # special values
            if self._val == (1, None, None):
                # PLUS-INFINITY
                return b'\x40'
            elif self._val == (-1, None, None):
                # MINUS-INFINITY
                return b'\x41'
            else:
                # NOT-A-NUMBER
                return b'\x42'
        elif self._val[1] == 10:
            # base 10: character string encoding
            if ASN1CodecBER.ENC_REALNR == 1:
                if self._val[2] < 0:
                    raise(ASN1BEREncodeErr('{0}: invalid REAL base 10 encoding NR1 for decimal value'\
                          .format(self.fullname())))
                i = self._val[0] * (10**self._val[2])
                if python_version < 3:
                    return '\x01' + \
                           ASN1CodecBER.ENC_REALNR1_SPA * ' ' + \
                           ASN1CodecBER.ENC_REALNR1_ZER * '0' + \
                           str(i)
                else:
                    return b'\x01' + \
                           ASN1CodecBER.ENC_REALNR1_SPA * b' ' + \
                           ASN1CodecBER.ENC_REALNR1_ZER * b'0' + \
                           bytes(str(i), 'ascii')
            elif ASN1CodecBER.ENC_REALNR == 2:
                if python_version < 3:
                    i = bytes(self._val[0])
                else:
                    i = bytes(str(self._val[0]), 'ascii')
                if self._val[2] >= 0:
                    # we need to add trailing zero
                    i += self._val[2] * b'0'
                    i += b'.'
                else:
                    #self._val[2] < 0:
                    # we need to place a coma correctly
                    d = -self._val[2]
                    if len(i) < d:
                        # we need to add heading zero
                        i = b'.' + (d-len(i)) * b'0' + i
                    else:
                        # we need to place the coma within i
                        i = i[:len(i)-d] + b'.' + i[len(i)-d:]
                return b'\x02' + \
                       ASN1CodecBER.ENC_REALNR2_SPA * b' ' + \
                       ASN1CodecBER.ENC_REALNR2_ZER * b'0' + \
                       i + \
                       ASN1CodecBER.ENC_REALNR2_ZERTRAIL * b'0'
            else:
                #ASN1CodecBER.ENC_REALNR == 3
                if python_version < 3:
                    i, e = bytes(self._val[0]), self._val[2]
                else:
                    i, e = bytes(str(self._val[0]), 'ascii'), self._val[2]
                # remove trailing zero
                while i[-1:] == b'0':
                    i = i[:-1]
                    e += 1
                if e == 0:
                    e = b'+0'
                elif python_version < 3:
                    e = bytes(e)
                else:
                    e = bytes(str(e), 'ascii')
                return b'\x03' + i + b'.E' + e
        else:
            # base 2, encoding the CER / DER way:
            # msb = 1
            # B = 0 (base 2), F = 0, mant = 0 or is odd, 
            # mant and exp encoded in the minimum number of bytes
            # ensure mant is 0 or odd
            if self._val[0] < 0:
                S, m, E = 1, -self._val[0], self._val[2]
            else:
                S, m, E = 0, self._val[0], self._val[2]
            while m > 0 and m % 2 == 0:
                m >>= 1
                E += 1
            LE = int_bytelen(E)
            E = int_to_bytes(E, 8*LE)
            N = uint_to_bytes(m, 8*uint_bytelen(m))
            if python_version < 3:
                if LE > 3:
                    return chr(0x80 + (S<<6) + 3) + uint_to_bytes(LE) + E + N
                else:
                    return chr(0x80 + (S<<6) + LE-1) + E + N
            else:
                if LE > 3:
                    return bytes((0x80 + (S<<6) + 3, )) + uint_to_bytes(LE) + E + N
                else:
                    return bytes((0x80 + (S<<6) + LE-1, )) + E + N
    
    def _decode_ber_cont_ws(self, char, vbnd):
        char._cur, char._len_bit = vbnd[0], vbnd[1]
        V = Buf('V', bl=vbnd[1]-vbnd[0])
        V._from_char(char)
        self._decode_cont(V.to_bytes())
        return V
    
    def _decode_ber_cont(self, char, vbnd):
        char._cur, char._len_bit = vbnd[0], vbnd[1]
        self._decode_cont(char.get_bytes(vbnd[1]-vbnd[0]))
    
    def _encode_ber_cont_ws(self):
        buf = self._encode_cont()
        lval = len(buf)
        return 0, lval, Buf('V', val=buf, bl=8*lval)
    
    def _encode_ber_cont(self):
        buf = self._encode_cont()
        lval = len(buf)
        return 0, lval, [(T_BYTES, buf, 8*lval)]
    
    ###
    # conversion between internal value and ASN.1 JER encoding
    ###
    
    if _with_json:
        
        def _from_jval(self, val):
            if isinstance(val, integer_types):
                self._val = (val, 2, 0)
            elif isinstance(val, float):
                if val == float('inf'):
                    self._val = (1, None, None)
                elif val == float('nan'):
                    self._val = (0, None, None)
                elif val == float('-inf'):
                    self._val = (-1, None, None)
                else:
                    num, den = val.as_integer_ratio()
                    # den is the fractionnal denominator, which must be a pow of 2
                    p = 0
                    while den > 1:
                        den >> 1
                        p += 1
                    self._val = (num, 2, p)
            elif isinstance(val, dict):
                try:
                    sci = val['base10Value']
                except KeyError:
                    raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                          .format(self.fullname(), val)))
                m = self._JER_RE.match(sci)
                if not m:
                    raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                          .format(self.fullname(), val)))
                i, d, e = m.groups()
                # remove trailing zero of the decimal part and adjust 
                # the exponent
                if d:
                    d = d.rstrip('0')
                    if not e:
                        e = -len(d)
                    else:
                        e = int(e) - len(d)
                    self._val = (int(i+d), 10, e)
                else:
                    self._val = (int(i), 10, int(e))
            else:
                raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                      .format(self.fullname(), val)))
        
        def _to_jval(self):
            if self._val[1] == 2:
                if self._val[2] >= 0:
                    return self._val[0] * (2<<self._val[2])
                else:
                    return {'base10Value': '%.16e' % (self._val[0]*(2**self._val[2]))}
            else:
                #self._val[1] == 10
                # TODO: some constraints on the mantissa / base / exponent should
                # lead to an integer encoding instead of this scientific notation
                return {'base10Value': '%ie%i' % (self._val[0], self._val[2])}

    ###
    # conversion between internal value and ASN.1 OER/COER encoding
    ###

    def _from_oer_ws(self, char):
        # Assuming pycrate takes care of constraints
        if ((self._const_val is not None) and
                (not self._const_val.in_root(None)) and
                (self._const_val.ext is None)):
            # Check for constraints
            lb = self._const_val.root[0].lb
            ub = self._const_val.root[0].ub
            if lb[1] == ub[1] == 2:  # Automatically excludes +/- Inf
                if (((min(lb[3], ub[3]) >=
                      ASN1CodecOER.REAL_IEEE754_32_EXP_MIN) and
                     (max(lb[3], ub[3]) <=
                      ASN1CodecOER.REAL_IEEE754_32_EXP_MAX)) and
                        ((min(lb[0], ub[0]) >=
                          ASN1CodecOER.REAL_IEEE754_32_MANTIS_MIN) and
                         (max(lb[3], ub[3]) <=
                          ASN1CodecOER.REAL_IEEE754_32_MANTIS_MAX))):
                    buf = Buf('V', bl=32)
                    buf._from_char(char)
                    self._struct = Envelope(self._name, GEN=(buf,))
                    self._val = decode_ieee754_32(Charpy(buf.to_bytes()))
                    return

                if (((min(lb[3], ub[3]) >=
                      ASN1CodecOER.REAL_IEEE754_64_EXP_MIN) and
                     (max(lb[3], ub[3]) <=
                      ASN1CodecOER.REAL_IEEE754_64_EXP_MAX)) and
                        ((min(lb[0], ub[0]) >=
                          ASN1CodecOER.REAL_IEEE754_64_MANTIS_MIN) and
                         (max(lb[3], ub[3]) <=
                          ASN1CodecOER.REAL_IEEE754_64_MANTIS_MAX))):
                    buf = Buf('V', bl=64)
                    buf._from_char(char)
                    self._struct = Envelope(self._name, GEN=(buf,))
                    self._val = decode_ieee754_64(Charpy(buf.to_bytes()))
                    return

        # else DER
        l_val, _gen = ASN1CodecOER.decode_length_determinant_ws(char)
        buf = Buf('V', bl=l_val*8)
        buf._from_char(char)
        _gen.append(buf)
        self._struct = Envelope(self._name, GEN=(_gen,))
        self.from_der(buf.to_bytes())

    def _from_oer(self, char):
        # Assuming pycrate takes care of constraints
        if ((self._const_val is not None) and
                (not self._const_val.in_root(None)) and
                (self._const_val.ext is None)):
            # Check for constraints
            lb = self._const_val.root[0].lb
            ub = self._const_val.root[0].ub
            if lb[1] == ub[1] == 2:  # Automatically excludes +/- Inf
                if (((min(lb[3], ub[3]) >=
                      ASN1CodecOER.REAL_IEEE754_32_EXP_MIN) and
                     (max(lb[3], ub[3]) <=
                      ASN1CodecOER.REAL_IEEE754_32_EXP_MAX)) and
                        ((min(lb[0], ub[0]) >=
                          ASN1CodecOER.REAL_IEEE754_32_MANTIS_MIN) and
                         (max(lb[3], ub[3]) <=
                          ASN1CodecOER.REAL_IEEE754_32_MANTIS_MAX))):
                    self._val = decode_ieee754_32(char)
                    return

                if (((min(lb[3], ub[3]) >=
                      ASN1CodecOER.REAL_IEEE754_64_EXP_MIN) and
                     (max(lb[3], ub[3]) <=
                      ASN1CodecOER.REAL_IEEE754_64_EXP_MAX)) and
                        ((min(lb[0], ub[0]) >=
                          ASN1CodecOER.REAL_IEEE754_64_MANTIS_MIN) and
                         (max(lb[3], ub[3]) <=
                          ASN1CodecOER.REAL_IEEE754_64_MANTIS_MAX))):
                    self._val = decode_ieee754_64(char)
                    return

        # else DER
        l_val = ASN1CodecOER.decode_length_determinant(char)
        val = char.get_bytes(l_val*8)
        self.from_der(val)

    def _to_oer_ws(self):
        # Assuming pycrate takes care of constraints
        if ((self._const_val is not None) and
                (not self._const_val.in_root(None)) and
                (self._const_val.ext is None)):
            # Check for constraints
            lb = self._const_val.root[0].lb
            ub = self._const_val.root[0].ub
            if lb[1] == ub[1] == 2:  # Automatically excludes +/- Inf
                if (((min(lb[3], ub[3]) >=
                      ASN1CodecOER.REAL_IEEE754_32_EXP_MIN) and
                     (max(lb[3], ub[3]) <=
                      ASN1CodecOER.REAL_IEEE754_32_EXP_MAX)) and
                        ((min(lb[0], ub[0]) >=
                          ASN1CodecOER.REAL_IEEE754_32_MANTIS_MIN) and
                         (max(lb[3], ub[3]) <=
                          ASN1CodecOER.REAL_IEEE754_32_MANTIS_MAX))):
                    _gen = (Buf('V', val=encode_ieee754_32(self._val), bl=32),)
                    self._struct = Envelope(self._name, GEN=_gen)
                    return self._struct

                if (((min(lb[3], ub[3]) >=
                      ASN1CodecOER.REAL_IEEE754_64_EXP_MIN) and
                     (max(lb[3], ub[3]) <=
                      ASN1CodecOER.REAL_IEEE754_64_EXP_MAX)) and
                        ((min(lb[0], ub[0]) >=
                          ASN1CodecOER.REAL_IEEE754_64_MANTIS_MIN) and
                         (max(lb[3], ub[3]) <=
                          ASN1CodecOER.REAL_IEEE754_64_MANTIS_MAX))):
                    _gen = (Buf('V', val=encode_ieee754_64(self._val), bl=64),)
                    self._struct = Envelope(self._name, GEN=_gen)
                    return self._struct

        # else DER
        val = self.to_der()  # not to_det_ws!!!, we are only interested in buf
        l_val = len(val)
        _gen = ASN1CodecOER.encode_length_determinant_ws(len(val))
        _gen.append(Buf('V', val=val, bl=l_val*8))
        self._struct = Envelope(self._name, GEN=(_gen,))
        return self._struct

    def _to_oer(self):
        # Assuming pycrate takes care of constraints
        if ((self._const_val is not None) and
                (not self._const_val.in_root(None)) and
                (self._const_val.ext is None)):
            # Check for constraints
            lb = self._const_val.root[0].lb
            ub = self._const_val.root[0].ub
            if lb[1] == ub[1] == 2:  # Automatically excludes +/- Inf
                if (((min(lb[3], ub[3]) >=
                      ASN1CodecOER.REAL_IEEE754_32_EXP_MIN) and
                     (max(lb[3], ub[3]) <=
                      ASN1CodecOER.REAL_IEEE754_32_EXP_MAX)) and
                    ((min(lb[0], ub[0]) >=
                      ASN1CodecOER.REAL_IEEE754_32_MANTIS_MIN) and
                     (max(lb[3], ub[3]) <=
                      ASN1CodecOER.REAL_IEEE754_32_MANTIS_MAX))):
                    return [(T_BYTES, encode_ieee754_32(self._val), 32)]

                if (((min(lb[3], ub[3]) >=
                      ASN1CodecOER.REAL_IEEE754_64_EXP_MIN) and
                     (max(lb[3], ub[3]) <=
                      ASN1CodecOER.REAL_IEEE754_64_EXP_MAX)) and
                    ((min(lb[0], ub[0]) >=
                      ASN1CodecOER.REAL_IEEE754_64_MANTIS_MIN) and
                     (max(lb[3], ub[3]) <=
                      ASN1CodecOER.REAL_IEEE754_64_MANTIS_MAX))):
                    return [(T_BYTES, encode_ieee754_64(self._val), 64)]

        # else DER
        val = self.to_der()
        l_val = len(val)
        GEN = ASN1CodecOER.encode_length_determinant(len(val))
        GEN.append((T_BYTES, val, l_val*8))
        return GEN

#------------------------------------------------------------------------------#
# ENUMERATED, OID and RELATIVE-OID
#------------------------------------------------------------------------------#

class ENUM(ASN1Obj):
    __doc__ = """
ASN.1 basic type ENUMERATED object

Single value: Python str, must be a key in _cont
    special case is the "_ext_$ind" value which encodes an unknown extension 
    index $ind
    

Specific attribute:
    
    - cont: ASN1Dict {enum (str): enum index (int)},
        provides the content of the ENUMERATED object
    
    - cont_rev: Python dict {enum index (int): enum (str)}
    
    - const_ind: ASN1Set, provides the set of ranges for root indexes and ext 
        indexes of the content
%s
""" % ASN1Obj_docstring
    
    _cont_rev  = {}
    _const_ind = None
    
    TYPE  = TYPE_ENUM
    TAG   = 10
    
    #_ASN_RE created at runtime, depends of self._cont
    
    def _safechk_val(self, val):
        if not isinstance(val, str_types) or val not in self._cont:
            if self._ext is None or not re.match('_ext_[0-9]{1,}', val):
                raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        if not hasattr(self, '_ASN_RE'):
            items = list(self._cont.keys())
            items.sort(key=len, reverse=True)
            self._ASN_RE = re.compile('|'.join(items))
        m = self._ASN_RE.match(txt)
        if m:
            self._val = m.group()
            return txt[m.end():].strip()
        else:
            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                  .format(self.fullname(), txt)))
    
    def _to_asn1(self):
        return self._val
    
    ###
    # conversion between internal value and ASN.1 PER encoding
    ###
    
    def _from_per_ws(self, char):
        GEN = []
        if self._ext is not None:
            E = Uint('E', bl=1)
            E._from_char(char)
            GEN.append(E)
            if E():
                # 1) index value is in the extended part (could be unknown)
                big = Uint('big', bl=1)
                big._from_char(char)
                GEN.append(big)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 2
                if big():
                    # 2) not-small index value (>= 64)
                    ind, _gen = ASN1CodecPER.decode_intunconst_ws(char, 0, name='I')
                    GEN.extend(_gen)
                else:
                    # 3) normally-small index value (< 64)
                    nsv = Uint('I', bl=6)
                    nsv._from_char(char)
                    ind = nsv()
                    GEN.append(nsv)
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 6
                if ind < len(self._ext):
                    # known extension
                    self._val = self._ext[ind]
                else:
                    # unknown extension
                    if not self._SILENT:
                        asnlog('ENUM._from_per_ws: %s, unknown extension index %r'\
                               % (self._name, ind))
                    self._val = '_ext_%r' % ind
                self._struct = Envelope(self._name, GEN=tuple(GEN))
                return
            elif ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += 1
        # 4) value is in the root part
        if len(self._root) == 1:
            # 5) only a single enum possible, nothing to decode
            self._val = self._root[0]
            self._struct = Envelope(self._name, GEN=tuple(GEN))
            return
        else:
            # 6) decode the enum index in the minimum number of bits
            ind, _gen = ASN1CodecPER.decode_intconst_ws(char, self._const_ind, name='I')
            try:
                self._val = self._root[ind]
            except IndexError:
                raise(ASN1PERDecodeErr('{0}: invalid ENUMERATED index, %r'.format(self.fullname(), ind)))
            self._struct = Envelope(self._name, GEN=tuple(GEN + _gen))
            return
    
    def _from_per(self, char):
        if self._ext is not None:
            E = char.get_uint(1)
            if E:
                # 1) index value is in the extended part (could be unknown)
                big = char.get_uint(1)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 2
                if big:
                    # 2) not-small index value (>= 64)
                    ind = ASN1CodecPER.decode_intunconst(char, 0)
                else:
                    # 3) normally-small index value (< 64)
                    ind = char.get_uint(6)
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 6
                if ind < len(self._ext):
                    # known extension
                    self._val = self._ext[ind]
                else:
                    # unknown extension
                    if not self._SILENT:
                        asnlog('ENUM._from_per: %s, unknown extension index %r'\
                               % (self._name, ind))
                    self._val = '_ext_%r' % ind
                return
            elif ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += 1
        # 4) value is in the root part
        if len(self._root) == 1:
            # 5) only a single enum possible, nothing to decode
            self._val = self._root[0]
            return
        else:
            # 6) decode the enum index in the minimum number of bits
            ind = ASN1CodecPER.decode_intconst(char, self._const_ind)
            try:
                self._val = self._root[ind]
            except IndexError:
                raise(ASN1PERDecodeErr('{0}: invalid ENUMERATED index, %r'.format(self.fullname(), ind)))
            return
    
    def _to_per_ws(self):
        GEN = []
        if self._ext is not None:
            # 1) extensible type
            if self._val in self._root:
                # 2) value index in the root part
                GEN.append( Uint('E', val=0, bl=1) )
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                ind = self._root.index(self._val)
            else:
                # 3) extended value index
                GEN.append( Uint('E', val=1, bl=1) )
                if self._val in self._ext:
                    ind = self._ext.index(self._val)
                else:
                    #self._val[:5] == '_ext_'
                    ind = int(self._val[5:])
                if ind < 64:
                    # 4) normally small index
                    GEN.extend( (Uint('big', val=0, bl=1), Uint('I', val=ind, bl=6)) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 8
                else:
                    # 5) big index
                    GEN.append( Uint('big', val=1, bl=1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 2
                    GEN.extend( ASN1CodecPER.encode_intunconst_ws(ind, 0, name='I') )
                self._struct = Envelope(self._name, GEN=tuple(GEN))
                return self._struct
        else:
            ind = self._root.index(self._val)
        # 6) value index in the root part
        if len(self._root) > 1:
            # 7) encode the enum index in the minimum number of bits
            GEN.extend( ASN1CodecPER.encode_intconst_ws(ind, self._const_ind, name='I') )
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return self._struct
    
    def _to_per(self):
        GEN = []
        if self._ext is not None:
            # 1) extensible type
            if self._val in self._root:
                # 2) value index in the root part
                GEN.append( (T_UINT, 0, 1) )
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                ind = self._root.index(self._val)
            else:
                # 3) extended value index
                if self._val in self._ext:
                    GEN.append( (T_UINT, 1, 1) )
                    ind = self._ext.index(self._val)
                else:
                    # self._val[:5] == '_ext_'
                    GEN.append( (T_UINT, 1, 1) )
                    ind = int(self._val[5:])
                if ind < 64:
                    # 4) normally small index, msb (the "big" bit) is 0
                    GEN.append( (T_UINT, ind, 7) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 8
                else:
                    # 5) big index
                    GEN.append( (T_UINT, 1, 1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 2
                    GEN.extend( ASN1CodecPER.encode_intunconst(ind, 0) )
                return GEN
        else:
            ind = self._root.index(self._val)
        # 6) value index in the root part
        if len(self._root) > 1:
            # 7) encode the enum index in the minimum number of bits
            GEN.extend( ASN1CodecPER.encode_intconst(ind, self._const_ind) )
        return GEN
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_ber_cont_ws(self, char, vbnd):
        if not isinstance(vbnd, tuple):
            raise(ASN1BERDecodeErr('{0}: invalid ENUMERATED constructed structure'\
                  .format(self.fullname())))
        char._cur, char._len_bit = vbnd[0], vbnd[1]
        V = Int('V', bl=vbnd[1]-vbnd[0])
        V._from_char(char)
        val = V()
        if val not in self._cont_rev:
            if self._ext is not None:
                # unknown extension
                if not self._SILENT:
                    asnlog('ENUM._from_ber_ws: %s, unknown extension value %r'\
                           % (self._name, val))
                self._val = '_ext_%r' % val
            else:
                raise(ASN1BERDecodeErr('{0}: invalid ENUMERATED value, %r'\
                      .format(self.fullname(), val)))
        else:
            self._val = self._cont_rev[val]
        return V
    
    def _decode_ber_cont(self, char, vbnd):
        if not isinstance(vbnd, tuple):
            raise(ASN1BERDecodeErr('{0}: invalid ENUMERATED constructed structure'\
                  .format(self.fullname())))
        char._cur, char._len_bit = vbnd[0], vbnd[1]
        val = char.get_int(vbnd[1]-vbnd[0])
        if val not in self._cont_rev:
            if self._ext is not None:
                # unknown extension
                if not self._SILENT:
                    asnlog('ENUM._from_ber_ws: %s, unknown extension value %r'\
                           % (self._name, val))
                self._val = '_ext_%r' % val
            else:
                raise(ASN1BERDecodeErr('{0}: invalid ENUMERATED value, %r'\
                      .format(self.fullname(), val)))
        else:
            self._val = self._cont_rev[val]
    
    def _encode_ber_cont_ws(self):
        if self._val in self._cont:
            val = self._cont[self._val]
        else:
            # self._val[:5] == '_ext_'
            val = int(self._val[5:])
        lval = int_bytelen(val)
        return 0, lval, Int('V', val=val, bl=8*lval)
    
    def _encode_ber_cont(self):
        if self._val in self._cont:
            val = self._cont[self._val]
        else:
            # self._val[:5] == '_ext_'
            val = int(self._val[5:])
        lval = int_bytelen(val)
        return 0, lval, [ (T_INT, val, 8*lval) ]
    
    ###
    # conversion between internal value and ASN.1 JER encoding
    ###
    
    if _with_json:
        
        def _from_jval(self, val):
            if val in self._cont:
                self._val = val
            else:
                raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                      .format(self.fullname(), val)))
        
        def _to_jval(self):
            return self._val

    ###
    # conversion between internal value and ASN.1 OER/COER encoding
    ###

    def _get_index(self):
        try:
            ind = self._cont[self._val]
        except KeyError:
            if self._ext is not None:
                # Just try to convert the value into an index
                try:
                    ind = int(self._val)
                except ValueError:
                    try:
                        # The pycrate "_ext_" format
                        ind = int(self._val[5:])
                    except ValueError:
                        raise ASN1OEREncodeErr(
                            "{0}: invalid ENUMERATED value, {1}".format(
                                self.fullname(),
                                self._val))
        return ind

    def _get_index_value(self, index):
        try:
            val = self._cont_rev[index]
        except (KeyError):
            if self._ext is not None:
                if not self._SILENT:
                    asnlog('ENUM._from_oer: %s, unknown extension value %r' \
                           % (self._name, index))
                # Just try to convert the value into an index
                val = '_ext_%r' % index
            else:
                raise (ASN1OERDecodeErr(
                    '{0}: invalid ENUMERATED value, {1}'.format(self.fullname(),
                                                               index)))

        return val

    def _from_oer_ws(self, char):
        index, _gen = ASN1CodecOER.decode_enumerated_ws(char)
        self._val = self._get_index_value(index)
        self._struct = Envelope(self._name, GEN=(_gen,))

    def _from_oer(self, char):
        self._val = self._get_index_value(ASN1CodecOER.decode_enumerated(char))

    def _to_oer_ws(self):
        self._struct = Envelope(self._name, GEN=(
            ASN1CodecOER.encode_enumerated_ws(self._get_index()),
        ))
        return self._struct

    def _to_oer(self):
        return ASN1CodecOER.encode_enumerated(self._get_index())


class _OID(ASN1Obj):
    
    # this class implements the methods that are common to OID and REL_OID    
    
    _ASN_RE = re.compile(r'\{([a-zA-Z0-9\-\(\)\s]{1,})\}')
    _ASN_RE_COMP = re.compile(
    r'([0-9]{1,})|(?:([a-zA-Z]{1}[a-zA-Z0-9\-]{0,})\s{0,}(?:\(([0-9]{1,})\)){0,1})')
    
    # _ASN_WASC potentially add the name of the OID in ascii in comment
    # when returned by _to_asn1() 
    _ASN_WASC = True
    
    def _safechk_val(self, val):
        if not isinstance(val, tuple) or \
        not all([isinstance(i, integer_types) for i in val]):
            raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        m = self._ASN_RE.match(txt)
        if m:
            txtval = txt[m.start()+1:m.end()-1].strip()
            _val = []
            txt = txt[m.end():].strip()
            m = self._ASN_RE_COMP.match(txtval)
            while m is not None:
                if m.group(1) or m.group(3):
                    _val.append( int(m.group(1) or m.group(3)) )
                else:
                    key = tuple(_val + [m.group(2)])
                    if key in ASN1_OID_ISO:
                        _val.append( ASN1_OID_ISO[key] )
                    else:
                        raise(ASN1NotSuppErr('{0}: unknown OID identifier, {1}'\
                              .format(self.fullname(), m.group(2))))
                txtval = txtval[m.end():].strip()
                m = self._ASN_RE_COMP.match(txtval)
            if txtval:
                raise(ASN1ASNDecodeErr('{0}: invalid remaining OID definition, {1}'\
                      .format(self.fullname(), txtval)))
            self._val = tuple(_val)
            return txt
        else:
            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                  .format(self.fullname(), txt)))
    
    def _to_asn1(self):
        if self.TYPE == TYPE_OID and self._ASN_WASC and self._val in GLOBAL.OID:
            return '{%s} -- %s --' % (' '.join(map(str, self._val)), GLOBAL.OID[self._val])
        else:
            return '{%s}' % ' '.join(map(str, self._val))
    
    ###
    # conversion between internal value and ASN.1 PER encoding
    # content is actually encoded like the BER one, prefixed with a bytes count
    ###
    
    def _from_per_ws(self, char):
        buf, GEN = ASN1CodecPER.decode_unconst_open_ws(char, wrapped=None)
        self._decode_cont(buf)
        self._struct = Envelope(self._name, GEN=tuple(GEN))
    
    def _from_per(self, char):
        self._decode_cont( ASN1CodecPER.decode_unconst_open(char, wrapped=None) )
    
    def _to_per_ws(self):
        GEN = ASN1CodecPER.encode_unconst_buf_ws( self._encode_cont() )
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return self._struct
    
    def _to_per(self):
        return ASN1CodecPER.encode_unconst_buf( self._encode_cont() )
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_ber_cont_ws(self, char, vbnd):
        if not isinstance(vbnd, tuple):
            raise(ASN1BERDecodeErr('{0}: invalid OID constructed structure'\
                  .format(self.fullname())))
        char._cur, char._len_bit = vbnd[0], vbnd[1]
        V = Buf('V', bl=vbnd[1]-vbnd[0])
        V._from_char(char)
        self._decode_cont(V.to_bytes())
        return V
    
    def _decode_ber_cont(self, char, vbnd):
        if not isinstance(vbnd, tuple):
            raise(ASN1BERDecodeErr('{0}: invalid OID constructed structure'\
                  .format(self.fullname())))
        char._cur, char._len_bit = vbnd[0], vbnd[1]
        self._decode_cont(char.get_bytes(vbnd[1]-vbnd[0]))
    
    def _encode_ber_cont_ws(self):
        buf = self._encode_cont()
        lval = len(buf)
        return 0, lval, Buf('V', val=buf, bl=8*lval)
    
    def _encode_ber_cont(self):
        buf = self._encode_cont()
        lval = len(buf)
        return 0, lval, [ (T_BYTES, buf, 8*lval) ]
    
    ###
    # conversion between internal value and ASN.1 JER encoding
    ###
    
    if _with_json:
        
        def _from_jval(self, val):
            try:
                self._val = tuple(map(int, val.split('.')))
            except Exception:
                raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                      .format(self.fullname(), val)))
        
        def _to_jval(self):
            return '.'.join(map(str, self._val))

    ###
    # conversion between internal value and ASN.1 OER/COER encoding
    ###
    def _to_oer(self):
        _, l_val, _gen = self._encode_ber_cont()
        det = ASN1CodecOER.encode_length_determinant(l_val)
        det.extend(_gen)
        return det

    def _to_oer_ws(self):
        _, l_val, _gen = self._encode_ber_cont_ws()
        det = ASN1CodecOER.encode_length_determinant_ws(l_val)
        det.append(_gen)
        self._struct = Envelope(self._name, GEN=tuple(det))
        return self._struct

    def _from_oer(self, char):
        l_val = ASN1CodecOER.decode_length_determinant(char)
        buf = char.get_bytes(l_val * 8)
        self._decode_cont(buf)

    def _from_oer_ws(self, char):
        l_val, det = ASN1CodecOER.decode_length_determinant_ws(char)
        buf = Buf('V', bl=l_val*8)
        buf._from_char(char)
        det.append(buf)
        self._decode_cont(buf.to_bytes())
        return Envelope(self._name, GEN=tuple(det))


class OID(_OID):
    __doc__ = """
ASN.1 basic type OBJECT IDENTIFIER object

Single value: Python tuple of int
%s
""" % ASN1Obj_docstring
    
    TYPE  = TYPE_OID
    TAG   = 6

    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_cont(self, buf):
        # 1) decode the list of integers, encoded like a BER tag
        arcs = []
        char = Charpy(buf)
        lb = 8 * len(buf)
        while char._cur < lb:
            e = char.get_uint(1)
            v = char.get_uint(7)
            while e:
                try:
                    e = char.get_uint(1)
                    v <<= 7
                    v += char.get_uint(7)
                except Exception:
                    raise(ASN1BERDecodeErr('{0}: invalid OID integer value'\
                          .format(self.fullname())))
            arcs.append(v)
        # 2) expand the 1st value as the value for the 2 1st arcs
        if arcs:
            if arcs[0] < 40:
                arcs.insert(0, 0)
            elif arcs[0] < 80:
                arcs.insert(0, 1)
                arcs[1] -= 40
            else:
                arcs.insert(0, 2)
                arcs[1] -= 80
        self._val = tuple(arcs)
    
    def _encode_cont(self):
        if len(self._val) < 2:
            raise(ASN1BEREncodeErr('{0}: missing OID 2 first integer values'\
                  .format(self.fullname())))
        # 1) encode the 1st 2 arcs
        if self._val[0] == 0:
            arcs = self._val[1:]
        elif self._val[0] == 1:
            arcs = (40 + self._val[1], ) + self._val[2:]
        else:
            arcs = (80 + self._val[1], ) + self._val[2:]
        # 2) encode each integer like a BER tag
        by = []
        for i in arcs:
            fact = decompose_uint_sl(7, i)
            if ASN1CodecBER.ENC_OID_LEXT and len(fact) < ASN1CodecBER.ENC_OID_LEXT:
                fact.extend([0]*(ASN1CodecBER.ENC_OID_LEXT-len(fact)))
            fact.reverse()
            for f in fact[:-1]:
                by.append( 0x80 + f )
            by.append( fact[-1] )
        if python_version > 2:
            return bytes(by)
        else:
            return ''.join(map(chr, by))    


class REL_OID(_OID):
    __doc__ = """
ASN.1 basic type RELATIVE-OID object

Single value: Python tuple of int
%s
""" % ASN1Obj_docstring
    
    TYPE  = TYPE_REL_OID
    TAG   = 13
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_cont(self, buf):
        # decode the list of integers, encoded like a BER tag
        arcs = []
        char = Charpy(buf)
        lb = 8 * len(buf)
        while char._cur < lb:
            e = char.get_uint(1)
            v = char.get_uint(7)
            while e:
                try:
                    e = char.get_uint(1)
                    v <<= 7
                    v += char.get_uint(7)
                except Exception:
                    raise(ASN1BERDecodeErr('{0}: invalid OID integer value'\
                          .format(self.fullname())))
            arcs.append(v)
        self._val = tuple(arcs)
    
    def _encode_cont(self):
        # encode each integer like a BER tag
        by = []
        for i in self._val:
            fact = decompose_uint_sl(7, i)
            if ASN1CodecBER.ENC_OID_LEXT and len(fact) < ASN1CodecBER.ENC_OID_LEXT:
                fact.extend([0]*(ASN1CodecBER.ENC_OID_LEXT-len(fact)))
            fact.reverse()
            for f in fact[:-1]:
                by.append( 0x80 + f )
            by.append( fact[-1] )
        if python_version > 2:
            return bytes(by)
        else:
            return ''.join(map(chr, by))    

