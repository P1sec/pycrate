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
# * File Name : pycrate_asn1rt/asnobj_str.py
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
from .codecs  import _with_json

try:
    from datetime import datetime, timedelta
    _with_datetime = True
    # required for UTC decay encoding in GeneralizedTime
except ImportError:
    _with_datetime = False

try:
    from time import strptime, asctime
    _with_time = True
except ImportError:
    _with_time = False


#------------------------------------------------------------------------------#
# BIT STRING and OCTET STRING
#------------------------------------------------------------------------------#

class BIT_STR(ASN1Obj):
    __doc__ = """
ASN.1 basic type BIT STRING object

Single value: Python 2-tuple of int
    1st int is the unsigned integral value, 2nd int is the length in bits

Alternative single value: Python set of str (from the object's NamedBitList)
    This is only to be used in set_val() method, and is converted to a Python
    2-tuple of int when set

Alternative single value: Python 2-tuple
    the 1st item corresponds to a reference to another ASN.1 object, it can be:
        - a str corresponding to an ASN.1 typeref taken from the CONTAINING constraint of self
        - a 2-tuple (module_name, object_name) corresponding to any user-defined ASN.1 object
    and the 2nd item corresponds to a single value compliant to the object 
    referenced in the 1st item

Specific attribute:
    
    - cont: None or ASN1Dict {ident (str): bit offset position (int)},
        provides the content of the BIT STRING object

Specific constraints attributes:
    
    - const_sz: None or ASN1Set (TYPE_INT), provides the set of sizes that 
        constraints the type
    
    - const_cont: None or ASN1Obj, provides the contained object
    
    - const_cont_enc: None or OID value, only set if const_cont is set,
        provides an OID for a specific codec
%s
""" % ASN1Obj_docstring
    
    _const_sz    = None
    _const_cont  = None
    
    TYPE  = TYPE_BIT_STR
    TAG   = 3

    _ASN_RE = re.compile(r'(?:\'([\s01]{0,})\'B)|(?:\'([\s0-9A-F]{0,})\'H)')

    # _ASN_WASC potentially add the ascii representation of the BIT STRING in comment
    # when returned by _to_asn1() 
    _ASN_WASC = True
    
    def _get_val_obj(self, ref):
        if isinstance(ref, str_types) and self._const_cont:
            if self._const_cont._typeref:
                ident = self._const_cont._typeref.called[1]
            else:
                ident = self._const_cont.TYPE 
            if ref == ident:
                return self._const_cont
            else:
                raise(ASN1ObjErr('{0}: invalid object reference, {1!r}'\
                      .format(self.fullname(), ref)))
        else:
            try:
                return GLOBAL.MOD[ref[0]][ref[1]]
            except Exception:
                raise(ASN1ObjErr('{0}: invalid object reference, {1!r}'\
                      .format(self.fullname(), ref)))
    
    def _safechk_val(self, val):
        if isinstance(val, tuple) and len(val) == 2:
            if isinstance(val[0], integer_types):
                # raw value
                if not isinstance(val[1], integer_types):
                    raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
            else:
                # CONTAINING value
                self._get_val_obj(val[0])._safechk_val(val[1])
        elif isinstance(val, set):
            # named bits
            if not self._cont:
                raise(ASN1ObjErr('{0}: invalid named bits, {1!r}'.format(self.fullname(), val)))
            elif any([nb not in self._cont for nb in val]):
                raise(ASN1ObjErr('{0}: invalid named bits, {1!r}'.format(self.fullname(), val)))
        else:
            raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
    
    def _safechk_bnd(self, val):
        if isinstance(val, tuple):
            if isinstance(val[0], integer_types):
                # check val against potential constraints
                ASN1Obj._safechk_bnd(self, val)
                if self._const_sz and \
                self._const_sz.ext is None and \
                val[1] not in self._const_sz:
                    raise(ASN1ObjErr('{0}: value out of size constraint, {1!r}'\
                          .format(self.fullname(), val)))
            elif self._const_cont:
                if self._const_cont._typeref:
                    ident = self._const_cont._typeref.called[1]
                else:
                    ident = self._const_cont.TYPE 
                if val[0] != ident:
                    raise(ASN1ObjErr('{0}: value out of containing constraint, {1!r}'\
                          .format(self.fullname(), val)))
    
    def get_names(self):
        """Returns the set of names from the NamedBitList corresponding to the 
        internal value currently set
        """
        if isinstance(self._val, set):
            return self._val
        names = set()
        if self._cont is None or not isinstance(self._val, tuple) \
        or len(self._val) != 2 or not isinstance(self._val[0], integer_types):
            # self._val has not the correct format
            return names
        for off, bit in enumerate(uint_to_bitstr(self._val[0], self._val[1])):
            if bit == '1' and off in self._cont_rev:
                names.add(self._cont_rev[off])
        return names
    
    def _names_to_val(self):
        off, val = [], self._val
        for name in val:
            try:
                off.append(self._cont[name])
            except Exception:
                raise(ASN1ObjErr('{0}: invalid named bits, {1!r}'.format(self.fullname(), val)))
        if off:
            moff = max(off)
            val  = (sum([1<<(moff-i) for i in off]), 1+moff)
        else:
            moff = 0
            val  = (0, 0)
        if self._const_sz and self._const_sz.ext is None \
        and self._const_sz.lb and val[1] < self._const_sz.lb:
            # need to extend the value to the lower bound of the size constraint
            diff = self._const_sz.lb - val[1]
            self._val = (val[0] << diff, val[1] + diff)
        else:
            self._val = val
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        m = self._ASN_RE.match(txt)
        if m:
            grp = m.groups()
            if grp[0] is not None:
                # BSTRING
                bs = re.subn(r'\s{1,}', '', grp[0])[0]
                if not bs:
                    # null length bit string
                    self._val = (0, 0)
                else:
                    self._val = (int(bs, 2), len(bs))
            else:
                # HSTRING
                hs = re.subn(r'\s{1,}', '', grp[1])[0]
                if not hs:
                    self._val = (0, 0)
                else:
                    self._val = (int(hs, 16), 4*len(hs))
            return txt[m.end():].strip()
        elif txt[:1] == '{' and self._cont:
            if not hasattr(self, '_ASN_RE_CONT'):
                kw = '|'.join(self._cont.keys())
                self._ASN_RE_CONT = re.compile(
                    r'\{((?:\s{0,}(?:' + kw + r')\s{0,},){0,}(?:\s{0,}(?:' + kw + r')\s{0,}){0,1})\}')
            m = self._ASN_RE_CONT.match(txt)
            if m:
                # named offsets
                off = set(map(str.strip, m.group(1).split(',')))
                if len(off) == 1 and '' in off:
                    # empty content
                    bval  = 0
                    bsize = 0
                else:
                    # converting to integral offsets (starting from 0)
                    off   = [self._cont[no] for no in off]
                    moff  = max(off)
                    bval  = sum([1<<(moff-i) for i in off])
                    bsize = 1+moff
                if self._const_sz is not None and self._const_sz.ext is None \
                and self._const_sz.lb is not None and bsize < self._const_sz.lb:
                    # non extensible size constraint that requires bsize to be extended
                    # and bval to be shifted accordingly
                    bval <<= (self._const_sz.lb - bsize)
                    bsize = self._const_sz.lb
                self._val = (bval, bsize)
                return txt[m.end():].lstrip()
        elif self._const_cont:
            # CHOICE-like value notation
            if self._const_cont._typeref:
                ident = self._const_cont._typeref.called[1]
            else:
                ident = self._const_cont.TYPE 
            m = re.match(r'%s\s{0,}:' % ident, txt)
            if m:
                txt = txt[m.end():].strip()
                txt = self._const_cont.from_asn1(txt)
                self._val = (ident, self._const_cont._val)
                return txt
        raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'.format(self.fullname(), txt)))
    
    def _to_asn1(self):
        if isinstance(self._val, set):
            self._names_to_val()
        if isinstance(self._val[0], integer_types):
            uint = Uint('bs', val=self._val[0], bl=self._val[1])
            if self._val[1] % 4 == 0:
                # HSTRING
                ret = '\'%s\'H' % uint_to_hex(self._val[0], self._val[1]).upper()
            else:
                # BSTRING
                ret = '\'%s\'B' % uint_to_bitstr(self._val[0], self._val[1])
            if self._cont:
                # add named bits in comment
                flags = []
                for i, v in enumerate(uint_to_bitstr(self._val[0], self._val[1])):
                    if i in self._cont_rev and v == '1':
                        flags.append(self._cont_rev[i])
                return ret + ' -- %s --' % ' | '.join(flags)
            elif self._ASN_WASC and self._val[1] % 8 == 0:
                # eventually add printable repr
                try:
                    if python_version < 3:
                        s = uint_to_bytes(self._val[0], self._val[1])
                    else:
                        s = uint_to_bytes(self._val[0], self._val[1]).decode('ascii')
                    if is_printable(s):
                        return ret + ' -- %s --' % repr(s)[1:-1]
                    else:
                        return ret
                except Exception:
                    return ret
            else:
                return ret
        elif self._const_cont:
            # CHOICE-like value notation
            if self._const_cont._typeref:
                ident = self._const_cont._typeref.called[1]
            else:
                ident = self._const_cont.TYPE 
            if self._val[0] == ident:
                self._const_cont._val = self._val[1]
                return '%s: %s' % (self._val[0], self._const_cont._to_asn1())
        raise(ASN1ASNEncodeErr('{0}: non-encodable value, {1!r}'\
              .format(self.fullname(), self._val)))
    
    ###
    # conversion between internal value and ASN.1 unaligned PER encoding
    ###
    
    def __val_from_buf(self, buf, bl):
        if bl:
            self._val = (bytes_to_uint(buf, bl), bl)
        else:
            # empty BIT STRING
            self._val = (0, 0)
    
    def __val_from_buf_struct(self, Buf):
        if Buf._bl:
            self._val = (Buf.to_uint(), Buf.get_bl())
        else:
            # empty BIT STRING
            self._val = (0, 0)
    
    def _from_per_ws(self, char):
        GEN, ldet = [], None
        if self._const_sz:
            if self._const_sz._ev is not None:
                E = Uint('E', bl=1)
                E._from_char(char)
                GEN.append(E)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                if E():
                    # 1) size in the extension part
                    # decoded as unconstraint integer
                    self.__from_per_ws_szunconst(char, GEN)
                    return
            # size in the root part
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    self.__from_per_ws_szunconst(char, GEN)
                    return
                else:
                    ldet, _gen = ASN1CodecPER.decode_intconst_ws(char, self._const_sz, name='C')
                    GEN.extend(_gen)
                    if ASN1CodecPER.ALIGNED:
                        # realignment
                        if ASN1CodecPER._off[-1] % 8:
                            GEN.extend( ASN1CodecPER.decode_pad_ws(char) )
                        ASN1CodecPER._off[-1] += ldet
                    V = Buf('V', bl=ldet, rep=REPR_BIN)
                    V._from_char(char)
                    GEN.append(V) 
                    self.__from_per_ws_buf(V)
                    self._struct = Envelope(self._name, GEN=tuple(GEN))
                    return
            elif self._const_sz.rdyn == 0:
                # 3) size has a single possible size (damned ASN.1 !!!)
                if self._const_sz.ub >= 65536:
                    self.__from_per_ws_szunconst(char, GEN)
                    return
                else:
                    ldet = self._const_sz.lb
                    if ASN1CodecPER.ALIGNED:
                        if ldet > 16 and ASN1CodecPER._off[-1] % 8:
                            # realignment
                            GEN.extend( ASN1CodecPER.decode_pad_ws(char) )
                        ASN1CodecPER._off[-1] += ldet
                    V = Buf('V', bl=ldet, rep=REPR_BIN)
                    V._from_char(char)
                    GEN.append(V)
                    self.__from_per_ws_buf(V)
                    self._struct = Envelope(self._name, GEN=tuple(GEN))
                    return
        if ldet is None:
            # 4) size is semi-constrained or has no constraint
            # decoded as unconstrained integer
            self.__from_per_ws_szunconst(char, GEN)
            return
        assert()
    
    def __from_per_ws_szunconst(self, char, GEN):
        # size is semi-constrained or unconstrained
        # anyway, it is decoded as unconstrained integer
        if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
            GEN.extend( ASN1CodecPER.decode_pad_ws(char) )
        ldet, _gen = ASN1CodecPER.decode_count_ws(char)
        GEN.extend(_gen)
        if ldet in (65536, 49152, 32768, 16384):
            # requires defragmentation
            (buf, ldet), _gen = ASN1CodecPER.decode_fragbytes_ws(char, ldet, bits=True)
            GEN.extend(_gen)
            V = Buf('V', val=buf, bl=ldet)
        else:
            # use Buf() structure for storing the content
            V = Buf('V', bl=ldet, rep=REPR_BIN)
            V._from_char(char)
            GEN.append(V)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += ldet
        self.__from_per_ws_buf(V)
        self._struct = Envelope(self._name, GEN=tuple(GEN))
    
    def __from_per_ws_buf(self, Buf):
        # set the BIT STRING value according to Buf instance
        if self._const_cont is not None:
            if self._const_cont_enc is not None:
                # TODO: different codec to be used
                if not self._SILENT:
                    asnlog('BIT_STR.__from_per_ws_buf: %s, specific CONTAINING encoder unhandled'\
                           % self._name)
                self.__val_from_buf_struct(Buf)
            else:
                char = Charpy(Buf())
                char._len_bit = Buf.get_bl()
                try:
                    if ASN1CodecPER.ALIGNED:
                        self._const_cont.from_aper_ws(char)
                    else:
                        self._const_cont.from_uper_ws(char)
                except Exception:
                    if not self._SILENT:
                        asnlog('BIT_STR.__from_per_ws_buf: %s, CONTAINING object decoding failed'\
                               % self._name)
                    #
                    self.__val_from_buf_struct(Buf)
                else:
                    if self._const_cont._typeref:
                        ident = self._const_cont._typeref.called[1]
                    else:
                        ident = self._const_cont.TYPE
                    self._val = (ident, self._const_cont._val)
        else:
            self.__val_from_buf_struct(Buf)
    
    def _from_per(self, char):
        ldet = None
        if self._const_sz:
            if self._const_sz._ev is not None:
                E = char.get_uint(1)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                if E:
                    # 1) size in the extension part
                    # decoded as unconstraint integer
                    self.__from_per_szunconst(char)
                    return
            # size in the root part
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    self.__from_per_szunconst(char)
                    return
                else:
                    ldet = ASN1CodecPER.decode_intconst(char, self._const_sz)
                    if ASN1CodecPER.ALIGNED:
                        # realignment
                        if ASN1CodecPER._off[-1] % 8:
                            ASN1CodecPER.decode_pad(char)
                        ASN1CodecPER._off[-1] += ldet
                    buf = char.get_bytes(ldet)
                    self.__from_per_buf(buf, ldet)
                    return
            elif self._const_sz.rdyn == 0:
                # 3) size has a single possible size
                if self._const_sz.ub >= 65536:
                    self.__from_per_szunconst(char)
                    return
                else:
                    ldet = self._const_sz.lb
                    if ASN1CodecPER.ALIGNED:
                        if ldet > 16 and ASN1CodecPER._off[-1] % 8:
                            # realignment
                            ASN1CodecPER.decode_pad(char)
                        ASN1CodecPER._off[-1] += ldet
                    buf = char.get_bytes(ldet)
                    self.__from_per_buf(buf, ldet)
                    return
        if ldet is None:
            # 4) size is semi-constrained or has no constraint
            # decoded as unconstrained integer
            self.__from_per_szunconst(char)
            return
        assert()
    
    def __from_per_szunconst(self, char):
        # size is semi-constrained or unconstrained
        # anyway, it is decoded as unconstrained integer
        if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
            ASN1CodecPER.decode_pad(char)
        ldet = ASN1CodecPER.decode_count(char)
        if ldet in (65536, 49152, 32768, 16384):
            # requires defragmentation
            buf, ldet = ASN1CodecPER.decode_fragbytes(char, ldet, bits=True)
        else:
            # use Buf() structure for storing the content
            buf = char.get_bytes(ldet)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += ldet
        self.__from_per_buf(buf, ldet)
    
    def __from_per_buf(self, buf, bl):
        # set the BIT STRING value according to buf and bit length
        if self._const_cont is not None:
            if self._const_cont_enc is not None:
                # TODO: different codec to be used
                if not self._SILENT:
                    asnlog('BIT_STR.__from_per_buf: %s, specific CONTAINING encoder unhandled'\
                           % self._name)
                self.__val_from_buf(buf, bl)
            else:
                char = Charpy(buf)
                char._len_bit = bl
                try:
                    if ASN1CodecPER.ALIGNED:
                        self._const_cont.from_aper(char)
                    else:
                        self._const_cont.from_uper(char)
                except Exception:
                    if not self._SILENT:
                        asnlog('BIT_STR.__from_per_buf: %s, CONTAINING object decoding failed'\
                               % self._name)
                    self.__val_from_buf(buf, bl)
                else:
                    if self._const_cont._typeref:
                        ident = self._const_cont._typeref.called[1]
                    else:
                        ident = self._const_cont.TYPE 
                    self._val = (ident, self._const_cont._val)
        else:
            self.__val_from_buf(buf, bl)
    
    # TODO: _to_per_ws() does not copy the structure of a potential wrapped
    # object into self._struct
    def _to_per_ws(self):
        if isinstance(self._val, set):
            self._names_to_val()
        buf, ldet = self.__to_per_ws_buf()
        GEN = []
        if self._const_sz:
            if self._const_sz._ev is not None:
                if not self._const_sz.in_root(ldet):
                    # 1) size in the extension part
                    # encoded as unconstraint integer
                    GEN.append( Uint('E', val=1, bl=1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
                    self.__to_per_ws_szunconst(buf, ldet, GEN)
                    return self._struct
                else:
                    GEN.append( Uint('E', val=0, bl=1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
            # size in the root part
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    self.__to_per_ws_szunconst(buf, ldet, GEN)
                    return self._struct
                else:
                    GEN.extend( ASN1CodecPER.encode_intconst_ws(ldet, self._const_sz, name='C') )
                    if ASN1CodecPER.ALIGNED:
                        # realignment
                        if ASN1CodecPER._off[-1] % 8:
                            GEN.extend( ASN1CodecPER.encode_pad_ws() )
                        ASN1CodecPER._off[-1] += ldet
                    GEN.append( Buf('V', val=buf, bl=ldet, rep=REPR_BIN) )
                    self._struct = Envelope(self._name, GEN=tuple(GEN))
                    return self._struct
            elif self._const_sz.rdyn == 0:
                # 3) size has a single possible size
                if self._const_sz.ub >= 65536:
                    self.__to_per_ws_szunconst(buf, ldet, GEN)
                    return self._struct
                else:
                    if ASN1CodecPER.ALIGNED:
                        if ldet > 16 and ASN1CodecPER._off[-1] % 8:
                            # realignment
                            GEN.extend( ASN1CodecPER.encode_pad_ws() )
                        ASN1CodecPER._off[-1] += ldet
                    GEN.append( Buf('V', val=buf, bl=ldet, rep=REPR_BIN) )
                    self._struct = Envelope(self._name, GEN=tuple(GEN))
                    return self._struct
        # 4) size is semi-constrained or has no constraint
        # encoded as unconstrained integer
        self.__to_per_ws_szunconst(buf, ldet, GEN)
        return self._struct
    
    def __to_per_ws_buf(self):
        # convert the value into a buffer and length in bits
        if not isinstance(self._val[0], integer_types):
            # 1) value is for a contained object to be encoded 
            Cont = self._get_val_obj(self._val[0])
            if Cont == self._const_cont and self._const_cont_enc is not None:
                # TODO: different codec to be used
                raise(ASN1NotSuppErr('{0}: specific CONTAINING encoder unhandled'\
                      .format(self.fullname())))
            Cont._val = self._val[1]
            if ASN1CodecPER.ALIGNED:
                buf = Cont.to_aper_ws()
            else:
                buf = Cont.to_uper_ws()
            #Cont._val = None
            return buf, 8*len(buf)
        else:
            # 2) value is the standard (uint, bit length)
            if self._val[1]:
                return uint_to_bytes(self._val[0], self._val[1]), self._val[1]
            else:
                # empty bit string
                return b'', 0
    
    def __to_per_ws_szunconst(self, buf, bl, GEN):
        # size is semi-constrained or unconstrained
        # anyway, it is encoded as unconstrained integer
        if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
            GEN.extend( ASN1CodecPER.encode_pad_ws() )
        if bl >= 16384:
            # requires fragmentation
            GEN.extend( ASN1CodecPER.encode_fragbytes_ws(buf, bits=bl) )
        else:
            GEN.extend( ASN1CodecPER.encode_count_ws(bl) )
            # use Buf() structure for storing the content
            GEN.append( Buf('V', val=buf, bl=bl, rep=REPR_BIN) )
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += bl
        self._struct = Envelope(self._name, GEN=tuple(GEN))
    
    def _to_per(self):
        if isinstance(self._val, set):
            self._names_to_val()
        buf, ldet = self.__to_per_buf()
        GEN = []
        if self._const_sz:
            if self._const_sz._ev is not None:
                if not self._const_sz.in_root(ldet):
                    # 1) size in the extension part
                    # encoded as unconstraint integer
                    GEN.append( (T_UINT, 1, 1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
                    self.__to_per_szunconst(buf, ldet, GEN)
                    return GEN
                else:
                    GEN.append( (T_UINT, 0, 1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
            # size in the root part
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    self.__to_per_szunconst(buf, ldet, GEN)
                    return GEN
                else:
                    GEN.extend( ASN1CodecPER.encode_intconst(ldet, self._const_sz) )
                    if ASN1CodecPER.ALIGNED:
                        if ASN1CodecPER._off[-1] % 8:
                            # realignment
                            GEN.extend( ASN1CodecPER.encode_pad() )
                        ASN1CodecPER._off[-1] += ldet
                    GEN.append( (T_BYTES, buf, ldet) )
                    return GEN
            elif self._const_sz.rdyn == 0:
                # 3) size has a single possible size
                if self._const_sz.ub >= 65536:
                    self.__to_per_szunconst(buf, ldet, GEN)
                    return GEN
                else:
                    if ASN1CodecPER.ALIGNED:
                        if ldet > 16 and ASN1CodecPER._off[-1] % 8:
                            # realignment
                            GEN.extend( ASN1CodecPER.encode_pad() )
                        ASN1CodecPER._off[-1] += ldet
                    GEN.append( (T_BYTES, buf, ldet) )
                    return GEN
        # 4) size is semi-constrained or has no constraint
        # encoded as unconstrained integer
        self.__to_per_szunconst(buf, ldet, GEN)
        return GEN
    
    def __to_per_buf(self):
        # convert the value into a buffer and length in bits
        if not isinstance(self._val[0], integer_types):
            # 1) value is for a contained object to be encoded 
            Cont = self._get_val_obj(self._val[0])
            if Cont == self._const_cont and self._const_cont_enc is not None:
                # TODO: different codec to be used
                raise(ASN1NotSuppErr('{0}: specific CONTAINING encoder unhandled'\
                      .format(self.fullname())))
            Cont._val = self._val[1]
            if ASN1CodecPER.ALIGNED:
                buf = Cont.to_aper()
            else:
                buf = Cont.to_uper()
            #Cont._val = None
            return buf, 8*len(buf)
        else:
            # 2) value is the standard (uint, bit length)
            if self._val[1]:
                return uint_to_bytes(self._val[0], self._val[1]), self._val[1]
            else:
                # empty bit string
                return b'', 0
    
    def __to_per_szunconst(self, buf, bl, GEN):
        # size is semi-constrained or unconstrained
        # anyway, it is encoded as unconstrained integer
        if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
            GEN.extend( ASN1CodecPER.encode_pad() )
        if bl >= 16384:
            # requires fragmentation
            GEN.extend( ASN1CodecPER.encode_fragbytes(buf, bits=bl) )
        else:
            GEN.extend( ASN1CodecPER.encode_count(bl) )
            # use Buf() structure for storing the content
            GEN.append( (T_BYTES, buf, bl) )
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += bl
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_ber_cont_ws(self, char, vs):
        if isinstance(vs, list):
            # constructed / fragmented form
            # vs: list of TLV
            Frag, bsfrag = [], []
            for tlv in vs:
                Tag, cl, pc, tval, Len, lval = tlv[0:6]
                if cl != 0:
                    raise(ASN1BERDecodeErr('{0}: invalid BIT STRING fragment tag class, {1!r}'\
                          .format(self.fullname(), cl)))
                elif tval != 3:
                    raise(ASN1BERDecodeErr('{0}: invalid BIT STRING fragment tag value, {1!r}'\
                          .format(self.fullname(), tval)))
                elif lval == 0:
                    raise(ASN1BERDecodeErr('{0}: invalid BIT STRING fragment length'\
                          .format(self.fullname())))
                elif pc != 0:
                    # fragmenting the fragment... damned BER recursivity !
                    raise(ASN1NotSuppErr('{0}: BIT STRING fragments within fragments'\
                          .format(self.fullname())))
                elif (tval, lval) == (0, 0):
                    # EOC marker
                    if tlv != vs[-1]:
                        raise(ASN1BERDecodeErr('{0}: invalid EOC within BIT STRING fragments'))
                    Frag.append( Envelope('EOC', GEN=(Tag, Len)) )
                else:
                    char._cur, char._len_bit = tlv[6][0], tlv[6][1]
                    Bu = Uint8('BU')
                    Bu._from_char(char)
                    bu = Bu()
                    if bu > 7:
                        raise(ASN1BERDecodeErr('{0}: invalid BIT STRING counter for unused bits'\
                              .format(self.fullname())))
                    Bs = Buf('BS', bl=tlv[6][1]-tlv[6][0]-8, rep=REPR_HEX)
                    Bs._from_char(char)
                    # concat the fragment of bit string
                    bsfrag.append( (T_BYTES, Bs.to_bytes(), tlv[6][1]-tlv[6][0]-8-bu) )
                    # generate the fragment envelope
                    Frag.append( Envelope('TLV', GEN=(Tag, Len, Envelope('V', GEN=(Bu, Bs)))) )
            # generate the complete V envelope
            V = Envelope('V', GEN=tuple(Frag))
            # process the defragmented bit string
            self.__from_ber_buf( *pack_val(*bsfrag) )
        else:
            # primitive form
            # vs: value boundary 2-tuple
            if vs[1]-vs[0] < 8:
                raise(ASN1BERDecodeErr('{0}: invalid BIT STRING length'\
                      .format(self.fullname())))
            char._cur, char._len_bit = vs[0], vs[1]
            Bu = Uint8('BU')
            Bu._from_char(char)
            bu = Bu()
            if bu > 7:
                raise(ASN1BERDecodeErr('{0}: invalid BIT STRING counter for unused bits'\
                      .format(self.fullname())))
            Bs = Buf('BS', bl=vs[1]-vs[0]-8, rep=REPR_HEX)
            Bs._from_char(char)
            # generate the V envelope
            V = Envelope('V', GEN=(Bu, Bs))
            # process the bit string
            self.__from_ber_buf( Bs.to_bytes(), vs[1]-vs[0]-8-bu )
        return V
    
    def _decode_ber_cont(self, char, vs):
        if isinstance(vs, list):
            # constructed / fragmented form
            # vs: list of TLV
            bsfrag = []
            for tlv in vs:
                cl, pc, tval, lval = tlv[0:4]
                if cl != 0:
                    raise(ASN1BERDecodeErr('{0}: invalid BIT STRING fragment tag class, {1!r}'\
                          .format(self.fullname(), cl)))
                elif tval != 3:
                    raise(ASN1BERDecodeErr('{0}: invalid BIT STRING fragment tag value, {1!r}'\
                          .format(self.fullname(), tval)))
                elif lval == 0:
                    raise(ASN1BERDecodeErr('{0}: invalid BIT STRING fragment length'\
                          .format(self.fullname())))
                elif pc != 0:
                    # fragmenting the fragment... damned BER recursivity !
                    raise(ASN1NotSuppErr('{0}: BIT STRING fragments within fragments'\
                          .format(self.fullname())))
                elif (tval, lval) == (0, 0):
                    # EOC marker
                    if tlv != vs[-1]:
                        raise(ASN1BERDecodeErr('{0}: invalid EOC within BIT STRING fragments'))
                else:
                    char._cur, char._len_bit = tlv[4][0], tlv[4][1]
                    bu = char.get_uint(8)
                    if bu > 7:
                        raise(ASN1BERDecodeErr('{0}: invalid BIT STRING counter for unused bits'\
                              .format(self.fullname())))
                    bs = char.get_bytes(8*(lval-1))
                    # concat the fragment of bit string
                    bsfrag.append( (T_BYTES, bs, tlv[4][1]-tlv[4][0]-8-bu) )
            # process the defragmented bit string
            self.__from_ber_buf( *pack_val(*bsfrag) )
        else:
            # primitive form
            # vs: value boundary 2-tuple
            if vs[1]-vs[0] < 8:
                raise(ASN1BERDecodeErr('{0}: invalid BIT STRING length'\
                      .format(self.fullname())))
            char._cur, char._len_bit = vs[0], vs[1]
            bu = char.get_uint(8)
            if bu > 7:
                raise(ASN1BERDecodeErr('{0}: invalid BIT STRING counter for unused bits'\
                      .format(self.fullname())))
            bs = char.get_bytes(vs[1]-vs[0]-8)
            # process the bit string
            self.__from_ber_buf( bs, vs[1]-vs[0]-8-bu )
    
    def __from_ber_buf(self, buf, bl):
        # set the BIT STRING value according to buf and bit length
        if self._const_cont is not None:
            if self._const_cont_enc is not None:
                # TODO: different codec to be used
                if not self._SILENT:
                    asnlog('BIT_STR.__from_ber_buf: %s, specific CONTAINING encoder unhandled'\
                           % self._name)
                self.__val_from_buf(buf, bl)
            else:
                Obj, char = self._const_cont, Charpy(buf)
                char._len_bit = bl
                _const_cont_par = Obj._parent
                Obj._parent = self._parent
                try:
                    Obj.from_ber(char, single=False)
                except Exception:
                    if not self._SILENT:
                        asnlog('BIT_STR.__from_ber_buf: %s, CONTAINING object decoding failed'\
                               % self._name)
                    Obj._parent = _const_cont_par
                    self.__val_from_buf(buf, bl)
                else:
                    Obj._parent = _const_cont_par
                    #
                    if Obj.TYPE == TYPE_OPEN and Obj._val[0].startswith('_unk'):
                        # content was decoded to an unknown BER TLV
                        # here we prefer to fallback to the standard BIT STRING value
                        self.__val_from_buf(buf, bl)
                    else:
                        if Obj._typeref is not None:
                            self._val = (Obj._typeref.called[1], Obj._val)
                        else:
                            self._val = (Obj.TYPE, Obj._val)
        else:
            self.__val_from_buf(buf, bl)
    
    def _encode_ber_cont_ws(self):
        if isinstance(self._val, set):
            self._names_to_val()
        buf, bl = self.__to_ber_buf()
        if bl % 8:
            bu = 8 - (bl%8)
        else:
            bu = 0
        if ASN1CodecBER.ENC_BSTR_FRAG and len(buf) >= ASN1CodecBER.ENC_BSTR_FRAG:
            # fragmentation required
            Frag, lval = [], 0
            for i in range(0, len(buf), ASN1CodecBER.ENC_BSTR_FRAG):
                frag = buf[i:i+ASN1CodecBER.ENC_BSTR_FRAG]
                TLV = Envelope('TLV', GEN=(
                        ASN1CodecBER.encode_tag_ws(0, 0, 3),
                        ASN1CodecBER.encode_len_ws(1+len(frag)),
                        Envelope('V', GEN=(Uint8('BU', val=0),
                                           Buf('BS', val=frag, rep=REPR_HEX)))))
                Frag.append(TLV)
                lval += 2 + (TLV[1].get_bl() >> 3) + len(frag)
            # set the bits unused BU in the last fragment
            Frag[-1][2][0]._val = bu
            return 1, lval, Envelope('V', GEN=tuple(Frag))
        else:
            lval = 1+len(buf)
            return 0, lval, Envelope('V', GEN=(Uint8('BU', val=bu),
                                               Buf('BS', val=buf, bl=8*len(buf), rep=REPR_HEX)))
    
    def _encode_ber_cont(self):
        if isinstance(self._val, set):
            self._names_to_val()
        buf, bl = self.__to_ber_buf()
        if bl % 8:
            bu = 8 - (bl%8)
        else:
            bu = 0
        if ASN1CodecBER.ENC_BSTR_FRAG and len(buf) >= ASN1CodecBER.ENC_BSTR_FRAG:
            # fragmentation required
            TLV, lval = [], 0
            for i in range(0, len(buf), ASN1CodecBER.ENC_BSTR_FRAG):
                frag = buf[i:i+ASN1CodecBER.ENC_BSTR_FRAG]
                TLV.extend( ASN1CodecBER.encode_tag(0, 0, 3) )
                L = ASN1CodecBER.encode_len(1+len(frag))
                TLV.extend( L )
                TLV.append( (T_UINT, 0, 8) )
                TLV.append( (T_BYTES, frag, 8*len(frag)) )
                lval += 2 + (sum([f[2] for f in L]) >> 3) + len(frag)
            # set the bits unused BU in the last fragment
            TLV[-2] = (T_UINT, bu, 8)
            return 1, lval, TLV
        else:
            return 0, 1 + len(buf), [ (T_UINT, bu, 8), (T_BYTES, buf, 8*len(buf)) ]
    
    def __to_ber_buf(self):
        # convert the value into a buffer and length in bits
        if not isinstance(self._val[0], integer_types):
            # 1) value is for a contained object to be encoded 
            Cont = self._get_val_obj(self._val[0])
            if Cont == self._const_cont and self._const_cont_enc is not None:
                # TODO: different codec to be used
                raise(ASN1NotSuppErr('{0}: specific CONTAINING encoder unhandled'\
                      .format(self.fullname())))
            Cont._val = self._val[1]
            buf = Cont.to_ber()
            return buf, 8*len(buf)
        else:
            # 2) value is the standard (uint, bit length)
            if self._val[1]:
                return uint_to_bytes(self._val[0], self._val[1]), self._val[1]
            else:
                # empty bit string
                return b'', 0
    
    ###
    # conversion between internal value and ASN.1 JER encoding
    ###
    
    if _with_json:
        
        def _from_jval(self, val):
            if isinstance(val, str_types):
                # ensure the sz constraint is fixed
                if not self._const_sz or self._const_sz.ra != 1 or len(self._const_sz._rv) != 1:
                    raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                          .format(self.fullname(), val)))
                else:
                    try:
                        val = int(val, 16)
                    except ValueError:
                        raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                              .format(self.fullname(), val)))
                    bl = self._const_sz._rv[0]
            elif isinstance(val, dict):
                if 'value' in val and 'length' in val:
                    bl  = val['length']
                    val = int(val['value'], 16)
                elif self._const_cont is not None:
                    if self._const_cont_enc is not None:
                        # TODO: different codec to be used
                        if not self._SILENT:
                            raise(ASN1NotSuppErr('{0}: specific CONTAINING decoder unhandled'\
                                  .format(self.fullname())))
                    Cont = self._const_cont
                    if Cont._typeref:
                        ident = Cont._typeref.called[1]
                    else:
                        ident = Cont.TYPE
                    _par = Cont._parent
                    Cont._parent = self
                    try:
                        Cont._from_jval(val[ident])
                    except KeyError:
                        Cont._parent = par
                        raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                              .format(self.fullname(), val)))
                    Cont._parent = _par
                    self._val = (ident, Cont._val)
                    return
            else:
                raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                      .format(self.fullname(), val)))
            if bl%8:
                self._val = (val>>(-bl%8), bl)
            else:
                self._val = (val, bl)
        
        def _to_jval(self):
            if isinstance(self._val, set):
                self._names_to_val()
            if not isinstance(self._val[0], integer_types):
                # value is for a contained object to be encoded
                # using a CHOICE-like encoding
                Cont = self._get_val_obj(self._val[0])
                if Cont == self._const_cont and self._const_cont_enc is not None:
                    # TODO: different codec to be used
                    raise(ASN1NotSuppErr('{0}: specific CONTAINING encoder unhandled'\
                          .format(self.fullname())))
                Cont._val = self._val[1]
                _par = Cont._parent
                Cont._parent = self
                val = Cont._to_jval()
                Cont._parent = _par
                if Cont._typeref:
                    return {Cont._typeref.called[1]: val}
                else:
                    return {Cont.TYPE: val}
            else:
                val, bl = self._val
                bl_rnd = -bl%8
                if self._const_sz and self._const_sz.ra == 1 and len(self._const_sz._rv) == 1:
                    if bl_rnd:
                        return uint_to_hex(val<<bl_rnd, bl+bl_rnd)
                    else:
                        return uint_to_hex(val, bl)
                else:
                    if bl_rnd:
                        return {'value': uint_to_hex(val<<bl_rnd, bl+bl_rnd), 'length': bl}
                    else:
                        return {'value': uint_to_hex(val, bl), 'length': bl}
    
    ###
    # conversion between internal value and ASN.1 OER/COER encoding
    ###
    
    def _to_oer(self):
        if isinstance(self._val, set):
            self._names_to_val()
        
        # Now check if the value is contained object or just number
        if not isinstance(self._val[0], integer_types):
            # 1) value is for a contained object to be encoded
            Cont = self._get_val_obj(self._val[0])
            if Cont == self._const_cont and self._const_cont_enc is not None:
                # TODO: different codec to be used
                raise(ASN1NotSuppErr('{0}: specific CONTAINING encoder unhandled' \
                                     .format(self.fullname())))
            Cont._val = self._val[1]
            buf = Cont.to_oer()
            l_val = len(buf) * 8
            pad_bits = 0
            _gen = [(T_BYTES, buf, l_val)]
            if Cont == self._const_cont:
                return _gen
        else:
            # 2) value is the standard (uint, bit length)
            if self._val[1]:
                l_val = self._val[1]
                _gen = [(T_UINT, self._val[0], l_val)]
                # padding bits
                pad_bits = (l_val % 8)
                pad_bits = (8 - pad_bits) if pad_bits else 0
                _gen.append((T_UINT, 0, pad_bits))
            else:
                # empty bit string
                pad_bits = 0
                l_val = 0
                _gen = [(T_BYTES, b'', l_val)]
        
        if self._const_sz:
            if (self._const_sz._ev is None) and (self._const_sz.ra == 1):
                # Fixed size constrains
                return _gen
        
        # Variable size constrains
        GEN = ASN1CodecOER.encode_length_determinant(((l_val + pad_bits) // 8) + 1)
        GEN.append((T_UINT, pad_bits, 8))  # Initial octet
        GEN.extend(_gen)
        return GEN
    
    def _to_oer_ws(self):
        if isinstance(self._val, set):
            self._names_to_val()
        
        ## Now check if the value is contained object or just number
        if not isinstance(self._val[0], integer_types):
            # 1) value is for a contained object to be encoded
            Cont = self._get_val_obj(self._val[0])
            if Cont == self._const_cont and self._const_cont_enc is not None:
                # TODO: different codec to be used
                raise (
                    ASN1NotSuppErr('{0}: specific CONTAINING encoder unhandled' \
                                   .format(self.fullname())))
            Cont._val = self._val[1]
            buf = Cont.to_oer()
            l_val = len(buf) * 8
            pad_bits = 0
            _gen = [Buf('V', val=buf, bl=l_val)]
            if Cont == self._const_cont:
                self._struct = Envelope(self._name, GEN=tuple(_gen))
                return self._struct
        else:
            # 2) value is the standard (uint, bit length)
            if self._val[1]:
                l_val = self._val[1]
                _gen = [Uint('V', val=self._val[0], bl=l_val)]
                # padding bits
                pad_bits = (l_val % 8)
                pad_bits = (8 - pad_bits) if pad_bits else 0
                _gen.append(Uint('Zero-pad', val=0, bl=pad_bits))
            else:
                # empty bit string
                pad_bits = 0
                l_val = 0
                _gen = [Buf('V', b'', l_val)]
        
        if self._const_sz:
            if (self._const_sz._ev is None) and (self._const_sz.ra == 1):
                # Fixed size constrains
                self._struct = Envelope(self._name, GEN=tuple(_gen))
                return self._struct
        
        # Variable size constrains
        GEN = [ASN1CodecOER.encode_length_determinant_ws(((l_val + pad_bits) // 8) + 1)]
        GEN.append(Uint('Initial octet', val=pad_bits, bl=8))
        GEN.extend(_gen)
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return self._struct
    
    def _from_oer(self, char):
        if self._const_sz:
            if (self._const_sz._ev is None) and (self._const_sz.ra == 1):
                # Fixed
                l_val = self._const_sz.lb
                pad_bits = (l_val % 8)
                pad_bits = (8 - pad_bits) if pad_bits else 0
                buf = char.get_uint(l_val+pad_bits)
                self._val = (buf >> pad_bits, l_val)
                return
        elif self._const_cont:
            # Contained by constraint
            Cont = self._get_val_obj(self._const_cont._typeref.called)
            Cont.from_oer(char)
            self._val = (self._const_cont._typeref.called, Cont._val)
            return
        
        # Variable size constraints
        l_det = ASN1CodecOER.decode_length_determinant(char)
        pad_bits = char.get_uint(8)
        l_val = 8*(l_det - 1) - pad_bits
        self._val = (char.get_uint(l_val+pad_bits) >> pad_bits, l_val)
    
    def _from_oer_ws(self, char):
        if self._const_sz:
            if (self._const_sz._ev is None) and (self._const_sz.ra == 1):
                # Fixed
                l_val = self._const_sz.lb
                pad_bits = (l_val % 8)
                pad_bits = (8 - pad_bits) if pad_bits else 0
                val = Uint('V', bl=l_val)
                val._from_char(char)
                zero_pad = Uint('Zero-pad', bl=pad_bits)
                zero_pad._from_char(char)
                self._val = (val.get_val(), val.get_bl())
                self._struct = Envelope(self._name, GEN=(val, zero_pad))
                return
        elif self._const_cont:
            # Contained by constraint
            Cont = self._get_val_obj(self._const_cont._typeref.called)
            Cont.from_oer_ws(char)
            _gen = Cont._struct
            self._val = (self._const_cont._typeref.called, Cont._val)
            self._struct = Envelope(self._name, GEN=(_gen,))
            return
        
        # Variable size constraints
        l_det, _gen = ASN1CodecOER.decode_length_determinant_ws(char)
        _gen = [_gen]
        i_oct = Uint('Initial octet', bl=8)
        i_oct._from_char(char)
        pad_bits = i_oct.get_val()
        l_val = 8*(l_det - 1) - pad_bits
        val = Uint('V', bl=l_val)
        val._from_char(char)
        zero_pad = Uint('Zero-pad', bl=pad_bits)
        zero_pad._from_char(char)
        _gen.extend((i_oct, val, zero_pad))
        self._val = (val.get_val(), val.get_bl())
        self._struct = Envelope(self._name, GEN=tuple(_gen))


class OCT_STR(ASN1Obj):
    __doc__ = """
ASN.1 basic type OCTET STRING object

Single value: Python bytes

Alternative single value: Python 2-tuple
    the 1st item corresponds to a reference to another ASN.1 object, it can be:
        - a str corresponding to an ASN.1 typeref taken from the CONTAINING constraint of self
        - a 2-tuple (module_name, object_name) corresponding to any user-defined ASN.1 object
    and the 2nd item corresponds to a single value compliant to the object 
    referenced in the 1st item

Specific constraints attributes:
    
    - const_sz: None or ASN1Set (TYPE_INT), provides the set of sizes that 
        constraints the type
    
    - const_cont: None or ASN1Obj, provides the contained object
    
    - const_cont_enc: None or OID value, only set if const_cont is set,
        provides an OID for a specific codec
%s
""" % ASN1Obj_docstring
    
    _const_sz    = None
    _const_cont  = None
    
    TYPE  = TYPE_OCT_STR
    TAG   = 4
    
    _ASN_RE = re.compile(r'(?:\'([\s01]{0,})\'B)|(?:\'([\s0-9A-F]{0,})\'H)')
    
    # _ASN_WASC potentially add the ascii representation of the BIT STRING in comment
    # when returned by _to_asn1() 
    _ASN_WASC = True
    
    def _get_val_obj(self, ref):
        if isinstance(ref, str_types) and self._const_cont:
            if self._const_cont._typeref:
                ident = self._const_cont._typeref.called[1]
            else:
                ident = self._const_cont.TYPE 
            if ref == ident:
                return self._const_cont
            else:
                raise(ASN1ObjErr('{0}: invalid object reference, {1!r}'\
                      .format(self.fullname(), ref)))
        else:
            try:
                return GLOBAL.MOD[ref[0]][ref[1]]
            except Exception:
                raise(ASN1ObjErr('{0}: invalid object reference, {1!r}'\
                      .format(self.fullname(), ref)))
    
    def _safechk_val(self, val):
        if not isinstance(val, bytes_types):
            self._get_val_obj(val[0])._safechk_val(val[1])
    
    def _safechk_bnd(self, val):
        if isinstance(val, bytes_types):
            # check val against potential constraints
            ASN1Obj._safechk_bnd(self, val)
            if self._const_sz and \
            self._const_sz.ext is None and \
            len(val) not in self._const_sz:
                raise(ASN1ObjErr('{0}: value out of size constraint, {1!r}'\
                      .format(self.fullname(), val)))
        else:
            if self._const_cont._typeref:
                ident = self._const_cont._typeref.called[1]
            else:
                ident = self._const_cont.TYPE
            if val[0] != ident:
                raise(ASN1ObjErr('{0}: value out of containing constraint, {1!r}'\
                      .format(self.fullname(), val)))
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        m = self._ASN_RE.match(txt)
        if m:
            grp = m.groups()
            if grp[0] is not None:
                # BSTRING
                bs = re.subn(r'\s{1,}', '', grp[0])[0]
                if not bs:
                    # null length octet string
                    self._val = b''
                else:
                    self._val = uint_to_bytes(int(bs, 2), len(bs))
            else:
                # HSTRING
                hs = re.subn(r'\s{1,}', '', grp[1])[0]
                if len(hs)%2:
                    self._val = unhexlify(hs + '0')
                else:
                    self._val = unhexlify(hs)
            return txt[m.end():].strip()
        elif self._const_cont:
            # CHOICE-like value notation
            if self._const_cont._typeref:
                ident = self._const_cont._typeref.called[1]
            else:
                ident = self._const_cont.TYPE 
            m = re.match(r'%s\s{0,}:' % ident, txt)
            if m:
                txt = txt[m.end():].strip()
                txt = self._const_cont.from_asn1(txt)
                self._val = (ident, self._const_cont._val)
                return txt
        raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'.format(self.fullname(), txt)))
    
    def _to_asn1(self):
        if isinstance(self._val, bytes_types):
            # HSTRING
            if python_version >= 3:
                ret = '\'%s\'H' % hexlify(self._val).decode('ascii').upper()
            else:
                ret = '\'%s\'H' % hexlify(self._val).upper()
            if self._ASN_WASC:
                # eventually add printable repr
                try:
                    s = self._val.decode('ascii')
                    if is_printable(s):
                        return ret + ' -- %s --' % repr(s)[1:-1]
                    else:
                        return ret
                except Exception:
                    return ret
            else:
                return ret
        elif self._const_cont:
            # CHOICE-like value notation
            if self._const_cont._typeref:
                ident = self._const_cont._typeref.called[1]
            else:
                ident = self._const_cont.TYPE 
            if self._val[0] == ident:
                self._const_cont._val = self._val[1]
                return '%s: %s' % (self._val[0], self._const_cont._to_asn1())
        raise(ASN1ASNEncodeErr('{0}: non-encodable value, {1!r}'\
              .format(self.fullname(), self._val)))
    
    ###
    # conversion between internal value and ASN.1 PER encoding
    ###
    
    def _from_per_ws(self, char):
        if self._const_sz:
            if self._const_sz._ev is not None:
                E = Uint('E', bl=1)
                E._from_char(char)
                GEN = [E]
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                if E():
                    # 1) size in the extension part
                    # decoded as unconstraint
                    self.__from_per_ws(char, GEN, unconst=True)
                    return
            else:
                GEN = []
            # size in the root part
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    self.__from_per_ws(char, GEN, unconst=True)
                    return
                else:
                    self.__from_per_ws(char, GEN)
                    return 
            elif self._const_sz.rdyn == 0:
                if self._const_sz.ub >= 65536:
                    self.__from_per_ws(char, GEN, unconst=True)
                    return
                else:
                    # 3) size has a single possible size
                    self.__from_per_ws(char, GEN)
                    return
        else:
            GEN = []
        # 4) size is semi-constrained or has no constraint
        # decoded as unconstrained
        self.__from_per_ws(char, GEN, unconst=True)
        return
    
    def __from_per_ws(self, char, GEN=[], unconst=False):
        if self._const_cont is not None:
            if self._const_cont_enc is not None:
                # TODO: different codec to be used
                if not self._SILENT:
                    asnlog('OCT_STR.__from_per_ws: %s, specific CONTAINING encoder unhandled'\
                           % self._name)
                if unconst:
                    self._val, _gen = ASN1CodecPER.decode_unconst_open_ws(char)
                else:
                    self._val, _gen = ASN1CodecPER.decode_const_open_ws(char, self._const_sz)
            else:
                Obj = self._const_cont
                _const_cont_par = Obj._parent
                Obj._parent = self._parent
                if unconst:
                    val, _gen = ASN1CodecPER.decode_unconst_open_ws(char, Obj)
                else:
                    val, _gen = ASN1CodecPER.decode_const_open_ws(char, self._const_sz, Obj)
                Obj._parent = _const_cont_par
                if Obj._typeref is not None:
                    self._val = (Obj._typeref.called[1], val)
                else:
                    self._val = (Obj.TYPE, val)
        else:
            if unconst:
                self._val, _gen = ASN1CodecPER.decode_unconst_open_ws(char)
            else:
                self._val, _gen = ASN1CodecPER.decode_const_open_ws(char, self._const_sz)
        self._struct = Envelope(self._name, GEN=tuple(GEN + _gen))
    
    def _from_per(self, char):
        if self._const_sz:
            if self._const_sz._ev is not None:
                E = char.get_uint(1)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                if E:
                    # 1) size in the extension part
                    # decoded as unconstraint
                    self.__from_per(char, unconst=True)
                    return
            # size in the root part
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    self.__from_per(char, unconst=True)
                    return
                else:
                    self.__from_per(char)
                    return 
            elif self._const_sz.rdyn == 0:
                if self._const_sz.ub >= 65536:
                    self.__from_per(char, unconst=True)
                    return
                else:
                    # 3) size has a single possible size
                    self.__from_per(char)
                    return
        else:
            GEN = []
        # 4) size is semi-constrained or has no constraint
        # decoded as unconstrained
        self.__from_per(char, unconst=True)
        return
    
    def __from_per(self, char, unconst=False):
        if self._const_cont is not None:
            if self._const_cont_enc is not None:
                # TODO: different codec to be used
                if not self._SILENT:
                    asnlog('OCT_STR.__from_per: %s, specific CONTAINING encoder unhandled'\
                           % self._name)
                if unconst:
                    self._val = ASN1CodecPER.decode_unconst_open(char)
                else:
                    self._val = ASN1CodecPER.decode_const_open(char, self._const_sz)
            else:
                Obj = self._const_cont
                _const_cont_par = Obj._parent
                Obj._parent = self._parent
                if unconst:
                    val = ASN1CodecPER.decode_unconst_open(char, Obj)
                else:
                    val = ASN1CodecPER.decode_const_open(char, self._const_sz, Obj)
                Obj._parent = _const_cont_par
                if Obj._typeref is not None:
                    self._val = (Obj._typeref.called[1], val)
                else:
                    self._val = (Obj.TYPE, val)
        else:
            if unconst:
                self._val = ASN1CodecPER.decode_unconst_open(char)
            else:
                self._val = ASN1CodecPER.decode_const_open(char, self._const_sz)
    
    # TODO: _to_per_ws() does not copy the structure of a potential wrapped
    # object into self._struct
    def _to_per_ws(self):
        if not isinstance(self._val, bytes_types):
            buf, wrapped = self.__to_per_ws_buf()
        else:
            buf, wrapped = self._val, None
        GEN = []
        if self._const_sz:
            if self._const_sz._ev is not None:
                if not self._const_sz.in_root(len(buf)):
                    # 1) size in the extension part
                    # encoded as unconstraint
                    GEN.append( Uint('E', val=1, bl=1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
                    GEN.extend( ASN1CodecPER.encode_unconst_buf_ws(buf) )
                    self._struct = Envelope(self._name, GEN=tuple(GEN))
                    return self._struct
                else:
                    GEN.append( Uint('E', val=0, bl=1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
            # size in the root part
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    GEN.extend( ASN1CodecPER.encode_unconst_buf_ws(buf) )
                    self._struct = Envelope(self._name, GEN=tuple(GEN))
                    return self._struct
                else:
                    GEN.extend( ASN1CodecPER.encode_const_buf_ws(buf, self._const_sz) )
                    self._struct = Envelope(self._name, GEN=tuple(GEN))
                    return self._struct
            elif self._const_sz.rdyn == 0:
                # 3) size has a single possible size
                if self._const_sz.ub >= 65536:
                    GEN.extend( ASN1CodecPER.encode_unconst_buf_ws(buf) )
                    self._struct = Envelope(self._name, GEN=tuple(GEN))
                    return self._struct
                else:
                    GEN.extend( ASN1CodecPER.encode_const_buf_ws(buf, self._const_sz) )
                    self._struct = Envelope(self._name, GEN=tuple(GEN))
                    return self._struct
        # 4) size is semi-constrained or has no constraint
        # encoded as unconstrained integer
        GEN.extend( ASN1CodecPER.encode_unconst_buf_ws(buf) )
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return self._struct
    
    def __to_per_ws_buf(self):
        # convert the contained object value into a buffer
        Cont = self._get_val_obj(self._val[0])
        if Cont == self._const_cont and self._const_cont_enc is not None:
            # TODO: different codec to be used
            raise(ASN1NotSuppErr('{0}: specific CONTAINING encoder unhandled'\
                  .format(self.fullname())))
        Cont._val = self._val[1]
        if ASN1CodecPER.ALIGNED:
            buf = Cont.to_aper_ws()
        else:
            buf = Cont.to_uper_ws()
        #Cont._val = None
        return buf, Cont
    
    def _to_per(self):
        if not isinstance(self._val, bytes_types):
            buf, wrapped = self.__to_per_buf()
        else:
            buf, wrapped = self._val, None
        GEN = []
        if self._const_sz:
            if self._const_sz._ev is not None:
                if not self._const_sz.in_root(len(buf)):
                    # 1) size in the extension part
                    # encoded as unconstraint
                    GEN.append( (T_UINT, 1, 1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
                    GEN.extend( ASN1CodecPER.encode_unconst_buf(buf) )
                    return GEN
                else:
                    GEN.append( (T_UINT, 0, 1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
            # size in the root part
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    GEN.extend( ASN1CodecPER.encode_unconst_buf(buf) )
                    return GEN
                else:
                    GEN.extend( ASN1CodecPER.encode_const_buf(buf, self._const_sz) )
                    return GEN
            elif self._const_sz.rdyn == 0:
                # 3) size has a single possible size
                if self._const_sz.ub >= 65536:
                    GEN.extend( ASN1CodecPER.encode_unconst_buf(buf) )
                    return GEN
                else:
                    GEN.extend( ASN1CodecPER.encode_const_buf(buf, self._const_sz) )
                    return GEN
        # 4) size is semi-constrained or has no constraint
        # encoded as unconstrained integer
        GEN.extend( ASN1CodecPER.encode_unconst_buf(buf) )
        return GEN
    
    def __to_per_buf(self):
        # convert the contained object value into a buffer
        Cont = self._get_val_obj(self._val[0])
        if Cont == self._const_cont and self._const_cont_enc is not None:
            # TODO: different codec to be used
            raise(ASN1NotSuppErr('{0}: specific CONTAINING encoder unhandled'\
                  .format(self.fullname())))
        Cont._val = self._val[1]
        if ASN1CodecPER.ALIGNED:
            buf = Cont.to_aper()
        else:
            buf = Cont.to_uper()
        #Cont._val = None
        return buf, Cont
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_ber_cont_ws(self, char, vs):
        if isinstance(vs, list):
            # constructed / fragmented form
            # vs: list of TLV
            Frag, osfrag = [], []
            for tlv in vs:
                Tag, cl, pc, tval, Len, lval = tlv[0:6]
                if cl != 0:
                    raise(ASN1BERDecodeErr('{0}: invalid OCTET STRING fragment tag class, {1!r}'\
                          .format(self.fullname(), cl)))
                elif tval != 4:
                    raise(ASN1BERDecodeErr('{0}: invalid OCTET STRING fragment tag value, {1!r}'\
                          .format(self.fullname(), tval)))
                elif pc != 0:
                    # fragmenting the fragment... damned BER recursivity !
                    raise(ASN1NotSuppErr('{0}: OCTET STRING fragments within fragments'\
                          .format(self.fullname())))
                elif (tval, lval) == (0, 0):
                    # EOC marker
                    if tlv != vs[-1]:
                        raise(ASN1BERDecodeErr('{0}: invalid EOC within OCTET STRING fragments'))
                    Frag.append( Envelope('EOC', GEN=(Tag, Len)) )
                else:
                    char._cur, char._len_bit = tlv[6][0], tlv[6][1]
                    Val = Buf('V', bl=tlv[6][1]-tlv[6][0], rep=REPR_HEX)
                    Val._from_char(char)
                    osfrag.append( Val.to_bytes() )
                    Frag.append( Envelope('TLV', GEN=(Tag, Len, Val)) )
            # generate the complete V envelope
            V = Envelope('V', GEN=tuple(Frag))
            # process the defragmented octet string
            self.__from_ber_buf( b''.join(osfrag) )
        else:
            # primitive form
            # vs: value boundary 2-tuple
            char._cur, char._len_bit = vs[0], vs[1]
            V = Buf('V', bl=vs[1]-vs[0], rep=REPR_HEX)
            V._from_char(char)
            # process the octet string
            self.__from_ber_buf( V.to_bytes() )
        return V
    
    def _decode_ber_cont(self, char, vs):
        if isinstance(vs, list):
            # constructed / fragmented form
            # vs: list of TLV
            osfrag = []
            for tlv in vs:
                cl, pc, tval, lval = tlv[0:4]
                if cl != 0:
                    raise(ASN1BERDecodeErr('{0}: invalid OCTET STRING fragment tag class, {1!r}'\
                          .format(self.fullname(), cl)))
                elif tval != 4:
                    raise(ASN1BERDecodeErr('{0}: invalid OCTET STRING fragment tag value, {1!r}'\
                          .format(self.fullname(), tval)))
                elif pc != 0:
                    # fragmenting the fragment... damned BER recursivity !
                    raise(ASN1NotSuppErr('{0}: OCTET STRING fragments within fragments'\
                          .format(self.fullname())))
                elif (tval, lval) == (0, 0):
                    # EOC marker
                    if tlv != vs[-1]:
                        raise(ASN1BERDecodeErr('{0}: invalid EOC within OCTET STRING fragments'))
                else:
                    char._cur, char._len_bit = tlv[4][0], tlv[4][1]
                    osfrag.append( char.get_bytes() )
            # process the defragmented octet string
            self.__from_ber_buf( b''.join(osfrag) )
        else:
            # primitive form
            # vs: value boundary 2-tuple
            char._cur, char._len_bit = vs[0], vs[1]
            self.__from_ber_buf( char.get_bytes(vs[1]-vs[0]) )
    
    def __from_ber_buf(self, buf):
        # set the OCTET STRING value according to buf
        if self._const_cont is not None:
            if self._const_cont_enc is not None:
                # TODO: different codec to be used
                if not self._SILENT:
                    asnlog('OCT_STR.__from_ber_buf: %s, specific CONTAINING encoder unhandled'\
                           % self._name)
                self._val = buf
            else:
                Obj, char = self._const_cont, Charpy(buf)
                _const_cont_par = Obj._parent
                Obj._parent = self._parent
                try:
                    Obj.from_ber(char, single=False)
                except Exception:
                    if not self._SILENT:
                        asnlog('OCT_STR.__from_ber_buf: %s, CONTAINING object decoding failed'\
                               % self._name)
                    Obj._parent = _const_cont_par
                    self._val = buf
                else:
                    Obj._parent = _const_cont_par
                    #
                    if Obj.TYPE == TYPE_OPEN and Obj._val[0].startswith('_unk'):
                        # content was decoded to an unknown BER TLV
                        # here we prefer to fallback to the standard OCTET STRING value
                        self._val = buf
                    else:
                        if Obj._typeref is not None:
                            self._val = (Obj._typeref.called[1], Obj._val)
                        else:
                            self._val = (Obj.TYPE, Obj._val)
        else:
            self._val = buf
    
    def _encode_ber_cont_ws(self):
        buf = self.__to_ber_buf()
        if ASN1CodecBER.ENC_OSTR_FRAG and len(buf) > ASN1CodecBER.ENC_OSTR_FRAG:
            # fragmentation required
            Frag, lval = [], 0
            for i in range(0, len(buf), ASN1CodecBER.ENC_OSTR_FRAG):
                frag = buf[i:i+ASN1CodecBER.ENC_OSTR_FRAG]
                TLV = Envelope('TLV', GEN=(
                        ASN1CodecBER.encode_tag_ws(0, 0, 4),
                        ASN1CodecBER.encode_len_ws(len(frag)),
                        Buf('V', val=frag, bl=8*len(frag), rep=REPR_HEX)))
                Frag.append(TLV)
                lval += 1 + (TLV[1].get_bl() >> 3) + len(frag)
            return 1, lval, Envelope('V', GEN=tuple(Frag))
        else:
            lval = len(buf)
            return 0, lval, Buf('V', val=buf, bl=8*lval, rep=REPR_HEX)
    
    def _encode_ber_cont(self):
        buf = self.__to_ber_buf()
        if ASN1CodecBER.ENC_OSTR_FRAG and len(buf) > ASN1CodecBER.ENC_OSTR_FRAG:
            # fragmentation required
            TLV, lval = [], 0
            for i in range(0, len(buf), ASN1CodecBER.ENC_OSTR_FRAG):
                frag = buf[i:i+ASN1CodecBER.ENC_OSTR_FRAG]
                TLV.extend( ASN1CodecBER.encode_tag(0, 0, 4) )
                L = ASN1CodecBER.encode_len(len(frag))
                TLV.extend( L )
                TLV.append( (T_BYTES, frag, 8*len(frag)) )
                lval += 1 + (sum([f[2] for f in L]) >> 3) + len(frag)
            return 1, lval, TLV
        else:
            return 0, len(buf), [ (T_BYTES, buf, 8*len(buf)) ]
    
    def __to_ber_buf(self):
        # convert the value into a buffer and length in bits
        if not isinstance(self._val, bytes_types):
            # 1) value is for a contained object to be encoded 
            Cont = self._get_val_obj(self._val[0])
            if Cont == self._const_cont and self._const_cont_enc is not None:
                # TODO: different codec to be used
                raise(ASN1NotSuppErr('{0}: specific CONTAINING encoder unhandled'\
                      .format(self.fullname())))
            Cont._val = self._val[1]
            buf = Cont.to_ber()
            return buf
        else:
            # 2) value is the standard (uint, bit length)
            return self._val
    
    ###
    # conversion between internal value and ASN.1 JER encoding
    ###
    # TODO: should support the alternative value based on the CONTAINING 
    # constraint (i.e. CHOICE-like)
    
    if _with_json:
        
        def _from_jval(self, val):
            if isinstance(val, str_types):
                try:
                    self._val = unhexlify(val)
                except TypeError:
                    raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                          .format(self.fullname(), val)))
            elif self._const_cont is not None:
                if self._const_cont_enc is not None:
                    # TODO: different codec to be used
                    if not self._SILENT:
                        raise(ASN1NotSuppErr('{0}: specific CONTAINING decoder unhandled'\
                              .format(self.fullname())))
                Cont = self._const_cont
                if Cont._typeref:
                    ident = Cont._typeref.called[1]
                else:
                    ident = Cont.TYPE
                _par = Cont._parent
                Cont._parent = self
                try:
                    Cont._from_jval(val[ident])
                except KeyError:
                    Cont._parent = _par
                    raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                          .format(self.fullname(), val)))
                Cont._parent = _par
                self._val = (ident, Cont._val)
        
        def _to_jval(self):
            if isinstance(self._val, bytes_types):
                return hexlify(self._val).decode()
            else:
                # value is for a contained object to be encoded
                # using a CHOICE-like encoding
                Cont = self._get_val_obj(self._val[0])
                if Cont == self._const_cont and self._const_cont_enc is not None:
                    # TODO: different codec to be used
                    raise(ASN1NotSuppErr('{0}: specific CONTAINING encoder unhandled'\
                          .format(self.fullname())))
                Cont._val = self._val[1]
                _par = Cont._parent
                Cont._parent = self
                val = Cont._to_jval()
                Cont._parent = _par
                if Cont._typeref:
                    return {Cont._typeref.called[1]: val}
                else:
                    return {Cont.TYPE: val}
    
    ###
    # conversion between internal value and ASN.1 OER/COER encoding
    ###
    
    def _from_oer(self, char):
        if self._const_sz:
            if (self._const_sz._ev is None) and (self._const_sz.ra == 1):
                # Fixed
                self._val = char.get_bytes(self._const_sz.lb * 8)
                return
        
        # Variable size constraint
        l_val = ASN1CodecOER.decode_length_determinant(char)
        val = char.get_bytes(l_val * 8)

        if self._const_cont:
            # Contained by constraint
            Cont = self._get_val_obj(self._const_cont._typeref.called)
            _const_cont_par = Cont._parent
            Cont._parent = self._parent
            Cont.from_oer(val)
            Cont._parent = _const_cont_par
            self._val = (self._const_cont._typeref.called[1], Cont._val)
        else:
            self._val = val
    
    def _from_oer_ws(self, char):
        if self._const_sz:
            if (self._const_sz._ev is None) and (self._const_sz.ra == 1):
                # Fixed
                val = Buf('V', bl=self._const_sz.lb * 8)
                val._from_char(char)
                self._val = val.get_val()
                self._struct = Envelope(self._name, GEN=(val,))
                return
        
        # Variable size constraints
        l_val, _gen = ASN1CodecOER.decode_length_determinant_ws(char)
        val = Buf('V', bl=8 * l_val)
        val._from_char(char)
        
        if self._const_cont:
            # Contained by constraint
            Cont = self._get_val_obj(self._const_cont._typeref.called)
            _const_cont_par = Cont._parent
            Cont._parent = self._parent
            Cont.from_oer_ws(val.get_val())
            Cont._parent = _const_cont_par
            _gen.append(Cont._struct)
            self._val = (self._const_cont._typeref.called[1], Cont._val)
        else:
            _gen.append(val)
            self._val = val.get_val()
        
        self._struct = Envelope(self._name, GEN=(_gen,))
    
    def __to_coer_buf(self):
        Cont = self._get_val_obj(self._val[0])
        if Cont == self._const_cont and self._const_cont_enc is not None:
            # TODO: different codec to be used
            raise(ASN1NotSuppErr('{0}: specific CONTAINING encoder unhandled'\
                                 .format(self.fullname())))
        Cont._val = self._val[1]
        buf = Cont.to_coer()
        return buf, Cont
    
    def __to_coer_ws_buf(self):
        Cont = self._get_val_obj(self._val[0])
        if Cont == self._const_cont and self._const_cont_enc is not None:
            # TODO: different codec to be used
            raise(ASN1NotSuppErr('{0}: specific CONTAINING encoder unhandled'\
                                 .format(self.fullname())))
        Cont._val = self._val[1]
        buf = Cont.to_coer_ws()
        return buf, Cont
    
    def _to_oer(self):
        if not isinstance(self._val, bytes_types):
            buf, wrapped = self.__to_coer_buf()
        else:
            buf, wrapped = self._val, None
        
        try:
            if ((self._const_sz._ev is None) and (self._const_sz.lb == self._const_sz.ub)):
                return [(T_BYTES, buf, len(buf)*8)]
        except AttributeError:
            pass
        
        # Means that it has variable constraint or no constraint
        GEN = ASN1CodecOER.encode_length_determinant(len(buf))
        GEN.append((T_BYTES, buf, len(buf) * 8))
        return GEN
    
    def _to_oer_ws(self):
        if not isinstance(self._val, bytes_types):
            buf, wrapped = self.__to_coer_ws_buf()
        else:
            buf, wrapped = self._val, None

        _gen = Buf('V', val=buf, bl=len(buf)*8)
        
        try:
            if ((self._const_sz._ev is None) and (self._const_sz.lb == self._const_sz.ub)):
                self._struct = Envelope(self._name, GEN=(_gen,))
                return self._struct
        except AttributeError:
            pass
        
        # Means that it has variable constraint or no constraint
        GEN = ASN1CodecOER.encode_length_determinant_ws(len(buf))
        GEN.append(_gen)
        self._struct = Envelope(self._name, GEN=(GEN,))
        return self._struct

#------------------------------------------------------------------------------#
# All *String
#------------------------------------------------------------------------------#

_String_docstring = """
Single value: Python str
    it can be encoded with 'ascii', 'utf8', 'utf16' or 'utf32' depending of the
    ASN.1 object

Specific attribute:
    
    - codec: indicates the Python codec used for encoding / decoding
    
    - clen: None or int, indicates the number of bits for a character in case it
        is fixed

Specific constraints attributes:
    
    - const_sz: None or ASN1Set (TYPE_INT), provides the set of sizes that 
        constraints the type
    
    - const_alpha: None or ASN1Set (*String), provides the set of alphabet 
        character that constraints the type
%s
""" % ASN1Obj_docstring

class _String(ASN1Obj):
    __doc__ = """
Virtual parent for any ASN.1 *String object
%s
""" % _String_docstring
    
    _const_sz    = None
    _const_alpha = None
    
    _codec       = 'utf8'
    _clen        = None
    _ALPHA_RE    = None
    
    def _get_char_dyn(self):
        # returns the number of bits required to encode a character
        if self._const_alpha:
            if self._const_alpha._ev is not None:
                # extensible alphabet constraint
                cdyn = self._clen
            else:
                cdyn = self._const_alpha.rdyn
        else:
            cdyn = self._clen
        if ASN1CodecPER.ALIGNED and cdyn is not None:
            return round_p2(cdyn)
        else:
            return cdyn
    
    def _safechk_val(self, val):
        if not isinstance(val, str_types):
            raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
        if self._ALPHA_RE and not all([c in self._ALPHA_RE for c in val]):
            raise(ASN1ObjErr('{0}: invalid character in value, {1!r}'.format(self.fullname(), val)))
    
    def _safechk_bnd(self, val):
        # check val against potential constraints
        ASN1Obj._safechk_bnd(self, val)
        if self._const_sz and \
        self._const_sz.ext is None and \
        len(val) not in self._const_sz:
            raise(ASN1ObjErr('{0}: value out of size constraint, {1!r}'\
                  .format(self.fullname(), val)))
        if self._const_alpha and \
        self._const_alpha.ext is None:
            for c in val:
                if c not in self._const_alpha:
                    raise(ASN1ObjErr('{0}: value out of alphabet constraint, {1!r}'\
                          .format(self.fullname(), val)))
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        rest, val = extract_charstr(txt)
        if val is not None:
            self._val = val
            return rest
        else:
            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'.format(self.fullname(), txt)))
    
    def _to_asn1(self):
        # character string
        return '"' + self._val.replace('"', '""') + '"'
    
    ###
    # conversion between internal value and ASN.1 PER encoding
    ###
    # check if there is an alphabet constraint, which can reduce some more the clen parameter,
    # this enables to determine the number of bits required to encode each character of the string
    # the size constraint is to be applied on the number of character
    
    def _from_per_ws(self, char):
        GEN = []
        if self._const_sz:
            if self._const_sz._ev is not None:
                E = Uint('E', bl=1)
                E._from_char(char)
                GEN.append(E)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                if E():
                    # 1) size in the extension part
                    # decoded as unconstraint integer
                    self.__from_per_ws_szunconst(char, GEN)
                    return
            # size in the root part
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    self.__from_per_ws_szunconst(char, GEN)
                    return
                else:
                    ldet, _gen = ASN1CodecPER.decode_intconst_ws(char, self._const_sz)
                    GEN.extend(_gen)
                    if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
                        # realignment
                        GEN.extend( ASN1CodecPER.decode_pad_ws(char) )
                    self.__from_per_ws_charstr(char, ldet, GEN)
                    return
            elif self._const_sz.rdyn == 0:
                if self._const_sz.ub >= 65536:
                    self.__from_per_ws_szunconst(char, GEN)
                    return
                else:
                    # 3) size has a single possible size
                    ldet = self._const_sz.lb
                    if ASN1CodecPER.ALIGNED and ldet > 2 and ASN1CodecPER._off[-1] % 8:
                        # realignment
                        GEN.extend( ASN1CodecPER.decode_pad_ws(char) )
                    self.__from_per_ws_charstr(char, ldet, GEN)
                    return
        # 4) size is semi-constrained or has no constraint
        # decoded as unconstrained integer
        self.__from_per_ws_szunconst(char, GEN)
    
    def __from_per_ws_szunconst(self, char, GEN):
        # size is semi-constrained or unconstrained
        # anyway, it is decoded as unconstrained integer
        if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
            GEN.extend( ASN1CodecPER.decode_pad_ws(char) )
        ldet, _gen = ASN1CodecPER.decode_count_ws(char)
        GEN.extend(_gen)
        if ldet in (65536, 49152, 32768, 16384):
            cdyn = self._get_char_dyn()
            # requires defragmentation
            if cdyn is None:
                # ldet is the number of bytes, val is bytes
                val, _gen = ASN1CodecPER.decode_fragbytes_ws(char, ldet)
                # e.g. utf-8 encoding
                if self._codec is None:
                    raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                          .format(self.fullname())))
                try:
                    self._val = val.decode(self._codec)
                except Exception as err:
                    raise(ASN1PERDecodeErr('{0}: invalid character, Python codec error, {1}'\
                          .format(self.fullname(), err)))
            elif cdyn < self._clen:
                # ldet is the number of characters, val is a list of uint
                val, _gen = ASN1CodecPER.decode_fragcharstr_ws(char, ldet, cdyn, arr=True)
                # character remapping required
                try:
                    self._val = ''.join([self._const_alpha.root[i] for i in val])
                except Exception:
                    raise(ASN1PERDecodeErr('{0}: character out of alphabet constraint'\
                          .format(self.fullname())))
            elif cdyn == 4:
                # ldet is the number of characters, val is a list of uint
                val, _gen = ASN1CodecPER.decode_fragcharstr_ws(char, ldet, cdyn, arr=True)
                # numeric string
                try:
                    self._val = ''.join([self._ALPHA_RE[i] for i in val])
                except Exception:
                    raise(ASN1PERDecodeErr('{0}: character out of alphabet'\
                          .format(self.fullname())))
            elif cdyn == 7:
                # ldet is the number of characters, val is a list of uint
                val, _gen = ASN1CodecPER.decode_fragcharstr_ws(char, ldet, cdyn, arr=True)
                # ascii encoding
                try:
                    self._val = ''.join(map(chr, val))
                except Exception:
                    raise(ASN1PERDecodeErr('{0}: character out of alphabet'\
                          .format(self.fullname())))
            else:
                # ldet is the number of characters, val is bytes
                assert( cdyn % 8 == 0 )
                val, _gen = ASN1CodecPER.decode_fragcharstr_ws(char, ldet, cdyn, arr=False)
                if self._codec is None:
                    raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                          .format(self.fullname())))
                try:
                    self._val = val.decode(self._codec)
                except Exception as err:
                    raise(ASN1PERDecodeErr('{0}: invalid character, Python codec error, {1}'\
                          .format(self.fullname(), err)))
            GEN.extend(_gen)
            self._struct = Envelope(self._name, GEN=tuple(GEN))
        else:
            self.__from_per_ws_charstr(char, ldet, GEN)
    
    def __from_per_ws_charstr(self, char, ldet, GEN):
        cdyn = self._get_char_dyn()
        if cdyn is None:
            # ldet is the number of bytes (e.g. utf-8 encoding)
            V = Buf('V', bl=8*ldet)
            V._from_char(char)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += 8*ldet
            if self._codec is None:
                raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                      .format(self.fullname())))
            try:
                self._val = V().decode(self._codec)
            except Exception as err:
                raise(ASN1PERDecodeErr('{0}: invalid character, Python codec error, {1}'\
                      .format(self.fullname(), err)))
        elif cdyn < self._clen:
            # ldet is the number of characters
            V = Array('V', num=ldet, GEN=Uint('char', bl=cdyn))
            V._from_char(char)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += cdyn*ldet
            # character remapping required
            try:
                self._val = ''.join([self._const_alpha.root[i] for i in V()])
            except Exception:
                raise(ASN1PERDecodeErr('{0}: character out of alphabet constraint, {1!r}'\
                      .format(self.fullname(), V())))
        elif cdyn == 4:
            # ldet is the number of characters
            V = Array('V', num=ldet, GEN=Uint('char', bl=cdyn))
            V._from_char(char)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += cdyn*ldet
            # numeric string
            try:
                self._val = ''.join([self._ALPHA_RE[i] for i in V()])
            except Exception:
                raise(ASN1PERDecodeErr('{0}: character out of alphabet, {1!r}'\
                      .format(self.fullname(), V())))
        elif cdyn == 7:
            # ldet is the number of characters
            V = Array('V', num=ldet, GEN=Uint('char', bl=cdyn))
            V._from_char(char)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += cdyn*ldet
            # ascii encoding
            try:    
                self._val = ''.join(map(chr, V()))
            except Exception:
                raise(ASN1PERDecodeErr('{0}: character out of alphabet, {1!r}'\
                      .format(self.fullname(), V())))
        else:
            # ldet is the number of characters, val is bytes
            assert( cdyn % 8 == 0 )
            V = Buf('V', bl=ldet*cdyn)
            V._from_char(char)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += cdyn*ldet
            if self._codec is None:
                raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                      .format(self.fullname())))
            try:
                self._val = V().decode(self._codec)
            except Exception as err:
                raise(ASN1PERDecodeErr('{0}: invalid character, Python codec error, {1}'\
                      .format(self.fullname(), err)))
        GEN.append(V)
        self._struct = Envelope(self._name, GEN=tuple(GEN))
    
    def _from_per(self, char):
        if self._const_sz:
            if self._const_sz._ev is not None:
                E = char.get_uint(1)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                if E:
                    # 1) size in the extension part
                    # decoded as unconstraint integer
                    self.__from_per_szunconst(char)
                    return
            # size in the root part
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    self.__from_per_szunconst(char)
                    return
                else:
                    ldet = ASN1CodecPER.decode_intconst(char, self._const_sz)
                    if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
                        # realignment
                        ASN1CodecPER.decode_pad(char)
                    self.__from_per_charstr(char, ldet)
                    return
            elif self._const_sz.rdyn == 0:
                if self._const_sz.ub >= 65536:
                    self.__from_per_szunconst(char)
                    return
                else:
                    # 3) size has a single possible size
                    ldet = self._const_sz.lb
                    if ASN1CodecPER.ALIGNED and ldet > 2 and ASN1CodecPER._off[-1] % 8:
                        # realignment
                        ASN1CodecPER.decode_pad(char)
                    self.__from_per_charstr(char, ldet)
                    return
        # 4) size is semi-constrained or has no constraint
        # decoded as unconstrained integer
        self.__from_per_szunconst(char)
    
    def __from_per_szunconst(self, char):
        # size is semi-constrained or unconstrained
        # anyway, it is decoded as unconstrained integer
        if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
            ASN1CodecPER.decode_pad(char)
        ldet = ASN1CodecPER.decode_count(char)
        if ldet in (65536, 49152, 32768, 16384):
            cdyn = self._get_char_dyn()
            # requires defragmentation
            if cdyn is None:
                # ldet is the number of bytes, val is bytes (e.g. utf-8 encoding)
                val = ASN1CodecPER.decode_fragbytes(char, ldet)
                if self._codec is None:
                    raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                          .format(self.fullname())))
                try:
                    self._val = val.decode(self._codec)
                except Exception as err:
                    raise(ASN1PERDecodeErr('{0}: invalid character, Python codec error, {1}'\
                          .format(self.fullname(), err)))
            elif cdyn < self._clen:
                # ldet is the number of characters, val is a list of uint
                val = ASN1CodecPER.decode_fragcharstr(char, ldet, cdyn, arr=True)
                # character remapping required
                try:
                    self._val = ''.join([self._const_alpha.root[i] for i in val])
                except Exception:
                    raise(ASN1PERDecodeErr('{0}: character out of alphabet constraint'\
                          .format(self.fullname())))
            elif cdyn == 4:
                # ldet is the number of characters, val is a list of uint
                val = ASN1CodecPER.decode_fragcharstr(char, ldet, cdyn, arr=True)
                # numeric string
                try:
                    self._val = ''.join([self._ALPHA_RE[i] for i in val])
                except Exception:
                    raise(ASN1PERDecodeErr('{0}: character out of alphabet'\
                          .format(self.fullname())))
            elif cdyn == 7:
                # ldet is the number of characters, val is a list of uint
                val = ASN1CodecPER.decode_fragcharstr(char, ldet, cdyn, arr=True)
                # ascii encoding
                try:
                    self._val = ''.join(map(chr, val))
                except Exception:
                    raise(ASN1PERDecodeErr('{0}: character out of alphabet'\
                          .format(self.fullname())))
            else:
                # ldet is the number of characters, val is bytes
                assert( cdyn % 8 == 0 )
                val = ASN1CodecPER.decode_fragcharstr(char, ldet, cdyn, arr=False)
                if self._codec is None:
                    raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                          .format(self.fullname())))
                try:
                    self._val = val.decode(self._codec)
                except Exception as err:
                    raise(ASN1PERDecodeErr('{0}: invalid character, Python codec error, {1}'\
                          .format(self.fullname(), err)))
        else:
            self.__from_per_charstr(char, ldet)
    
    def __from_per_charstr(self, char, ldet):
        cdyn = self._get_char_dyn()
        if cdyn is None:
            # ldet is the number of bytes (e.g. utf-8 encoding)
            val = char.get_bytes(8*ldet)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += 8*ldet
            if self._codec is None:
                raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                      .format(self.fullname())))
            try:
                self._val = val.decode(self._codec)
            except Exception as err:
                raise(ASN1PERDecodeErr('{0}: invalid character, Python codec error, {1}'\
                      .format(self.fullname(), err)))
        elif cdyn < self._clen:
            # ldet is the number of characters
            val = [char.get_uint(cdyn) for i in range(ldet)]
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += cdyn*ldet
            # character remapping required
            try:
                self._val = ''.join([self._const_alpha.root[i] for i in val])
            except Exception:
                raise(ASN1PERDecodeErr('{0}: character out of alphabet constraint, {1!r}'\
                      .format(self.fullname(), V())))
        elif cdyn == 4:
            # ldet is the number of characters
            val = [char.get_uint(cdyn) for i in range(ldet)]
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += cdyn*ldet
            # numeric string
            try:
                self._val = ''.join([self._ALPHA_RE[i] for i in val])
            except Exception:
                raise(ASN1PERDecodeErr('{0}: character out of alphabet, {1!r}'\
                      .format(self.fullname(), V())))
        elif cdyn == 7:
            # ldet is the number of characters
            val = [char.get_uint(cdyn) for i in range(ldet)]
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += cdyn*ldet
            # ascii encoding
            try:    
                self._val = ''.join(map(chr, val))
            except Exception:
                raise(ASN1PERDecodeErr('{0}: character out of alphabet, {1!r}'\
                      .format(self.fullname(), V())))
        else:
            # ldet is the number of characters, val is bytes
            assert( cdyn % 8 == 0 )
            val = char.get_bytes(ldet*cdyn)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += cdyn*ldet
            if self._codec is None:
                raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                      .format(self.fullname())))
            try:
                self._val = val.decode(self._codec)
            except Exception as err:
                raise(ASN1PERDecodeErr('{0}: invalid character, Python codec error, {1}'\
                      .format(self.fullname(), err)))
    
    def _to_per_ws(self):
        GEN = []
        val, cdyn, ldet = self.__to_per_val()
        if self._const_sz:
            if self._const_sz._ev is not None:
                if not self._const_sz.in_root(ldet):
                    # 1) size in the extension part
                    # encoded as unconstraint integer
                    GEN.append( Uint('E', val=1, bl=1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
                    self.__to_per_ws_szunconst(val, cdyn, ldet, GEN)
                    return self._struct
                else:
                    GEN.append( Uint('E', val=0, bl=1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
            # size in the root part
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    self.__to_per_ws_szunconst(val, cdyn, ldet, GEN)
                    return self._struct
                else:
                    GEN.extend( ASN1CodecPER.encode_intconst_ws(ldet, self._const_sz, name='C') )
                    if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
                        # realignment
                        GEN.extend( ASN1CodecPER.encode_pad_ws() )
                    self.__to_per_ws_charstr(val, cdyn, ldet, GEN)
                    return self._struct
            elif self._const_sz.rdyn == 0:
                # 3) size has a single possible size
                if self._const_sz.ub >= 65536:
                    self.__to_per_ws_szunconst(val, cdyn, ldet, GEN)
                    return self._struct
                else:
                    if ASN1CodecPER.ALIGNED and ldet > 2 and ASN1CodecPER._off[-1] % 8:
                        # realignment
                        GEN.extend( ASN1CodecPER.encode_pad_ws() )
                    self.__to_per_ws_charstr(val, cdyn, ldet, GEN)
                    return self._struct
        # 4) size is semi-constrained or has no constraint
        # encoded as unconstrained integer
        self.__to_per_ws_szunconst(val, cdyn, ldet, GEN)
        return self._struct
    
    def __to_per_val(self):
        cdyn = self._get_char_dyn()
        if cdyn is None:
            # ldet is the length in bytes
            if self._codec is None:
                raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                      .format(self.fullname())))
            try:
                buf = self._val.encode(self._codec)
            except Exception as err:
                raise(ASN1PEREncodeErr('{0}: invalid character, Python codec error, {1}'\
                      .format(self.fullname(), err)))
            return buf, cdyn, len(buf)
        else:
            # ldet is the length in number of chars, each encoded in $cdyn bits
            ldet = len(self._val)
            if cdyn < self._clen:
                # character remapping required
                try:
                    val = [self._const_alpha.root.index(c) for c in self._val]
                except Exception:
                    raise(ASN1PEREncodeErr('{0}: character out of alphabet constraint, {1!r}'\
                          .format(self.fullname(), self._val)))
            elif cdyn == 4:
                # numeric string
                try:
                    val = [self._ALPHA_RE.find(c) for c in self._val]
                except Exception:
                    raise(ASN1PEREncodeErr('{0}: character out of alphabet, {1!r}'\
                          .format(self.fullname(), self._val)))
            elif cdyn == 7:
                # ascii encoding
                try:
                    val = list(map(ord, self._val))
                except Exception:
                    raise(ASN1PEREncodeErr('{0}: character out of alphabet, {1!r}'\
                          .format(self.fullname(), self._val)))
            else:
                # builtin Python encoding, utf-16 or utf-32
                assert(cdyn % 8 == 0)
                if self._codec is None:
                    raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                          .format(self.fullname())))
                try:
                    val = self._val.encode(self._codec)
                except Exception as err:
                    raise(ASN1PEREncodeErr('{0}: invalid character, Python codec error, {1}'\
                          .format(self.fullname(), err)))
            return val, cdyn, ldet
    
    def __to_per_ws_szunconst(self, val, cdyn, ldet, GEN):
        # size is semi-constrained or unconstrained
        # anyway, it is encoded as unconstrained integer
        if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
            GEN.extend( ASN1CodecPER.encode_pad_ws() )
        if ldet >= 16384:
            # requires fragmentation
            if cdyn is None:
                # bytes fragmentation
                GEN.extend( ASN1CodecPER.encode_fragbytes_ws(val) )
            else:
                # int list or utf-16/32 bytes fragmentation
                GEN.extend( ASN1CodecPER.encode_fragcharstr_ws(val, cdyn, ldet) )
            self._struct = Envelope(self._name, GEN=tuple(GEN))
        else:
            GEN.extend( ASN1CodecPER.encode_count_ws(ldet) )
            self.__to_per_ws_charstr(val, cdyn, ldet, GEN)
    
    def __to_per_ws_charstr(self, val, cdyn, ldet, GEN):
        if cdyn is None:
            # use a Buf() structure for storing the content
            GEN.append( Buf('V', val=val, bl=8*ldet) )
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += 8*ldet
        elif isinstance(val, bytes_types):
            # utf-16/32 bytes buffer, use a Buf() structure
            GEN.append( Buf('V', val=val, bl=cdyn*ldet) )
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += cdyn*ldet
        else:
            # use an Array() structure
            GEN.append( Array('V', val=val, num=ldet, GEN=Uint('char', bl=cdyn)) )
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += cdyn*ldet
        self._struct = Envelope(self._name, GEN=tuple(GEN))
    
    def _to_per(self):
        GEN = []
        val, cdyn, ldet = self.__to_per_val()
        if self._const_sz:
            if self._const_sz._ev is not None:
                if not self._const_sz.in_root(ldet):
                    # 1) size in the extension part
                    # encoded as unconstraint integer
                    GEN.append( (T_UINT, 1, 1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
                    self.__to_per_szunconst(val, cdyn, ldet, GEN)
                    return GEN
                else:
                    GEN.append( (T_UINT, 0, 1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
            # size in the root part
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    self.__to_per_szunconst(val, cdyn, ldet, GEN)
                    return GEN
                else:
                    GEN.extend( ASN1CodecPER.encode_intconst(ldet, self._const_sz) )
                    if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
                        # realignment
                        GEN.extend( ASN1CodecPER.encode_pad() )
                    self.__to_per_charstr(val, cdyn, ldet, GEN)
                    return GEN
            elif self._const_sz.rdyn == 0:
                # 3) size has a single possible size
                if self._const_sz.ub >= 65536:
                    self.__to_per_szunconst(val, cdyn, ldet, GEN)
                    return GEN
                else:
                    if ASN1CodecPER.ALIGNED and ldet > 2 and ASN1CodecPER._off[-1] % 8:
                        # realignment
                        GEN.extend( ASN1CodecPER.encode_pad() )
                    self.__to_per_charstr(val, cdyn, ldet, GEN)
                    return GEN
        # 4) size is semi-constrained or has no constraint
        # encoded as unconstrained integer
        self.__to_per_szunconst(val, cdyn, ldet, GEN)
        return GEN
    
    def __to_per_szunconst(self, val, cdyn, ldet, GEN):
        # size is semi-constrained or unconstrained
        # anyway, it is encoded as unconstrained integer
        if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
            GEN.extend( ASN1CodecPER.encode_pad() )
        if ldet >= 16384:
            # requires fragmentation
            if cdyn is None:
                # bytes fragmentation
                GEN.extend( ASN1CodecPER.encode_fragbytes(val) )
            else:
                # int list or utf-16/32 bytes fragmentation
                GEN.extend( ASN1CodecPER.encode_fragcharstr(val, cdyn, ldet) )
        else:
            GEN.extend( ASN1CodecPER.encode_count(ldet) )
            self.__to_per_charstr(val, cdyn, ldet, GEN)
    
    def __to_per_charstr(self, val, cdyn, ldet, GEN):
        if cdyn is None:
            # use bytes for storing the content
            GEN.append( (T_BYTES, val, 8*ldet) )
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += 8*ldet
        elif isinstance(val, bytes_types):
            # utf-16/32 bytes buffer, use bytes again
            GEN.append( (T_BYTES, val, cdyn*ldet) )
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += cdyn*ldet
        else:
            # use an Array() structure
            GEN.extend( [(T_UINT, v, cdyn) for v in val] )
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += cdyn*ldet
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_ber_cont_ws(self, char, vs):
        if isinstance(vs, list):
            # constructed / fragmented form
            # vs: list of TLV
            Frag, sfrag = [], []
            for tlv in vs:
                Tag, cl, pc, tval, Len, lval = tlv[0:6]
                if cl != 0:
                    raise(ASN1BERDecodeErr('{0}: invalid String fragment tag class, {1!r}'\
                          .format(self.fullname(), cl)))
                elif tval != self.TAG:
                    raise(ASN1BERDecodeErr('{0}: invalid String fragment tag value, {1!r}'\
                          .format(self.fullname(), tval)))
                elif pc != 0:
                    # fragmenting the fragment... damned BER recursivity !
                    raise(ASN1NotSuppErr('{0}: String fragments within fragments'\
                          .format(self.fullname())))
                elif (tval, lval) == (0, 0):
                    # EOC marker
                    if tlv != vs[-1]:
                        raise(ASN1BERDecodeErr('{0}: invalid EOC within String fragments'))
                    Frag.append( Envelope('EOC', GEN=(Tag, Len)) )
                else:
                    char._cur, char._len_bit = tlv[6][0], tlv[6][1]
                    Val = Buf('V', bl=tlv[6][1]-tlv[6][0])
                    Val._from_char(char)
                    sfrag.append( Val.to_bytes() )
                    Frag.append( Envelope('TLV', GEN=(Tag, Len, Val)) )
            # generate the V envelope
            V = Envelope('V', GEN=tuple(Frag))
            # process the defragmented string
            if self._codec is None:
                raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                      .format(self.fullname())))
            try:
                self._val = b''.join(sfrag).decode(self._codec)
            except Exception as err:
                raise(ASN1PEREncodeErr('{0}: invalid character, Python codec error, {1}'\
                      .format(self.fullname(), err)))
        else:
            # primitive form
            # vs: value boundary 2-tuple
            char._cur, char._len_bit = vs[0], vs[1]
            V = Buf('V', bl=vs[1]-vs[0])
            V._from_char(char)
            # process the string
            if self._codec is None:
                raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                      .format(self.fullname())))
            try:
                self._val = V.to_bytes().decode(self._codec)
            except Exception as err:
                raise(ASN1PEREncodeErr('{0}: invalid character, Python codec error, {1}'\
                      .format(self.fullname(), err)))
        return V
    
    def _decode_ber_cont(self, char, vs):
        if isinstance(vs, list):
            # constructed / fragmented form
            # vs: list of TLV
            sfrag = []
            for tlv in vs:
                cl, pc, tval, lval = tlv[0:4]
                if cl != 0:
                    raise(ASN1BERDecodeErr('{0}: invalid String fragment tag class, {1!r}'\
                          .format(self.fullname(), cl)))
                elif tval != self.TAG:
                    raise(ASN1BERDecodeErr('{0}: invalid String fragment tag value, {1!r}'\
                          .format(self.fullname(), tval)))
                elif pc != 0:
                    # fragmenting the fragment... damned BER recursivity !
                    raise(ASN1NotSuppErr('{0}: String fragments of fragments'\
                          .format(self.fullname())))
                elif (tval, lval) == (0, 0):
                    # EOC marker
                    if tlv != vs[-1]:
                        raise(ASN1BERDecodeErr('{0}: invalid EOC within String fragments'))
                else:
                    char._cur, char._len_bit = tlv[4][0], tlv[4][1]
                    sfrag.append( char.get_bytes() )
            # process the defragmented string
            if self._codec is None:
                raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                      .format(self.fullname())))
            try:
                self._val = b''.join(sfrag).decode(self._codec)
            except Exception as err:
                raise(ASN1PEREncodeErr('{0}: invalid character, Python codec error, {1}'\
                      .format(self.fullname(), err)))
        else:
            # primitive form
            if self._codec is None:
                raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                      .format(self.fullname())))
            char._cur, char._len_bit = vs[0], vs[1]
            buf = char.get_bytes(vs[1]-vs[0])
            try:
                self._val = buf.decode(self._codec)
            except Exception as err:
                raise(ASN1PEREncodeErr('{0}: invalid character, Python codec error, {1}'\
                      .format(self.fullname(), err)))
    
    def _encode_ber_cont_ws(self):
        if self._codec is None:
            raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                  .format(self.fullname())))
        try:
            buf = self._val.encode(self._codec)
        except Exception as err:
            raise(ASN1PEREncodeErr('{0}: invalid character, Python codec error, {1}'\
                  .format(self.fullname(), err)))
        if ASN1CodecBER.ENC_OSTR_FRAG and len(buf) > ASN1CodecBER.ENC_OSTR_FRAG:
            # fragmentation required
            Frag, lval = [], 0
            for i in range(0, len(buf), ASN1CodecBER.ENC_OSTR_FRAG):
                frag = buf[i:i+ASN1CodecBER.ENC_OSTR_FRAG]
                TLV = Envelope('TLV', GEN=(
                        ASN1CodecBER.encode_tag_ws(0, 0, self.TAG),
                        ASN1CodecBER.encode_len_ws(len(frag)),
                        Buf('V', val=frag, bl=8*len(frag))))
                Frag.append(TLV)
                lval += 1 + (TLV[1].get_bl() >> 3) + len(frag)
            return 1, lval, Envelope('V', GEN=tuple(Frag))
        else:
            lval = len(buf)
            return 0, lval, Buf('V', val=buf, bl=8*lval)
    
    def _encode_ber_cont(self):
        if self._codec is None:
            raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                  .format(self.fullname())))
        try:
            buf = self._val.encode(self._codec)
        except Exception as err:
            raise(ASN1PEREncodeErr('{0}: invalid character, Python codec error, {1}'\
                  .format(self.fullname(), err)))
        if ASN1CodecBER.ENC_OSTR_FRAG and len(buf) > ASN1CodecBER.ENC_OSTR_FRAG:
            # fragmentation required
            TLV, lval = [], 0
            for i in range(0, len(buf), ASN1CodecBER.ENC_OSTR_FRAG):
                frag = buf[i:i+ASN1CodecBER.ENC_OSTR_FRAG]
                TLV.extend( ASN1CodecBER.encode_tag(0, 0, self.TAG) )
                L = ASN1CodecBER.encode_len(len(frag))
                TLV.extend( L )
                TLV.append( (T_BYTES, frag, 8*len(frag)) )
                lval += 1 + (sum([f[2] for f in L]) >> 3) + len(frag)
            return 1, lval, TLV
        else:
            return 0, len(buf), [ (T_BYTES, buf, 8*len(buf)) ]
    
    ###
    # conversion between internal value and ASN.1 JER encoding
    ###
    
    if _with_json:
        
        def _from_jval(self, val):
            if isinstance(val, str_types):
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
        try:
            if ((self._const_sz.rdyn == 0) and (self._const_sz._ev is None) \
            and (self._clen is not None)):
                # Fixed size
                b_len = round_p2(self._clen) * self._const_sz.lb
                self._val = self._decode_oer_cont(char.get_bytes(b_len))
                return
        except AttributeError:
            pass
        
        # All other variants
        l_det = ASN1CodecOER.decode_length_determinant(char)
        self._val = self._decode_oer_cont(char.get_bytes(l_det * 8))
    
    def _from_oer_ws(self, char):
        try:
            if ((self._const_sz.rdyn == 0) and (self._const_sz._ev is None) \
            and (self._clen is not None)):
                # Fixed size
                b_len = round_p2(self._clen) * self._const_sz.lb
                buf = Buf('V', bl=b_len)
                buf._from_char(char)
                self._struct = Envelope(self._name, GEN=(buf,))
                self._val = self._decode_oer_cont(buf.to_bytes())
                return
        except AttributeError:
            pass
        
        # All other variants
        l_det, _gen = ASN1CodecOER.decode_length_determinant_ws(char)
        _gen = [_gen]
        buf = Buf('V', bl=l_det*8)
        buf._from_char(char)
        _gen.append(buf)
        self._struct = Envelope(self._name, GEN=tuple(_gen))
        self._val = self._decode_oer_cont(buf.to_bytes())
    
    def _decode_oer_cont(self, content_bytes):
        if self._codec is None:
            raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                                 .format(self.fullname())))
        try:
            return content_bytes.decode(self._codec)
        except Exception as err:
            raise(ASN1OERDecodeErr('{0}: invalid character, Python codec error, {1}'\
                                   .format(self.fullname(), err)))
    
    def _encode_oer_cont(self):
        if self._codec is None:
            raise(ASN1NotSuppErr('{0}: ISO 2022 codec not supported'\
                                 .format(self.fullname())))
        try:
            return self._val.encode(self._codec)
        except Exception as err:
            raise(ASN1OEREncodeErr('{0}: invalid character, Python codec error, {1}'\
                                   .format(self.fullname(), err)))
    
    def _to_oer(self):
        buf = self._encode_oer_cont()
        l_buf = len(buf)
        buf = [(T_BYTES, buf, l_buf * 8)]
        
        try:
            if ((self._const_sz.rdyn == 0) and (self._const_sz._ev is None) \
            and (self._clen is not None)):
                # Fixed size
                return buf
        except AttributeError:
            pass
        
        # All other variants
        GEN = ASN1CodecOER.encode_length_determinant(l_buf)
        GEN.extend(buf)
        return GEN
    
    def _to_oer_ws(self):
        buf = self._encode_oer_cont()
        l_buf = len(buf)
        buf = Buf('V', val=buf, bl=l_buf * 8)

        try:
            if ((self._const_sz.rdyn == 0) and (self._const_sz._ev is None) \
            and (self._clen is not None)):
                # Fixed size
                self._struct = Envelope(self._name, GEN=(buf,))
                return self._struct
        except AttributeError:
            pass
        
        # All other variants
        GEN = [ASN1CodecOER.encode_length_determinant_ws(l_buf)]
        GEN.append(buf)
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return self._struct


# Python does not provide a complete support for ISO2022 encoding
# so here, we use iso2022_jp_2004
_ISO2022_CODEC = 'iso2022_jp_2004'
# If you want to disable support for ISO2022 entirely, just set this to None
#_ISO2022_CODEC = None


class OBJ_DESC(_String):
    __doc__ = """
ASN.1 basic type OBJECT DESCRIPTOR object
%s
""" % _String_docstring
    
    # OBJECT DESCRIPTOR is a subtype of GraphicString
    _codec    = _ISO2022_CODEC
    
    TYPE  = TYPE_OBJ_DESC
    TAG   = 7


class STR_UTF8(_String):
    __doc__ = """
ASN.1 basic type UTF8String object
%s
""" % _String_docstring
    
    TYPE  = TYPE_STR_UTF8
    TAG   = 12


class STR_NUM(_String):
    __doc__ = """
ASN.1 basic type NumericString object
%s
""" % _String_docstring
    
    _codec    = 'ascii'
    _clen     = 4
    _ALPHA_RE = ' 0123456789'
    
    TYPE  = TYPE_STR_NUM
    TAG   = 18


class STR_PRINT(_String):
    __doc__ = """
ASN.1 basic type PrintableString object
%s
""" % _String_docstring
    
    _codec    = 'ascii'
    _clen     = 7
    _ALPHA_RE = '0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\'()+,-./:=?'
    
    TYPE  = TYPE_STR_PRINT
    TAG   = 19


class STR_TELE(_String):
    __doc__ = """
ASN.1 basic type TeletexString object
%s
""" % _String_docstring
    
    _codec    = _ISO2022_CODEC
    
    TYPE  = TYPE_STR_TELE
    TAG   = 20
    
    if _with_json:
        _from_jval = OCT_STR._from_jval
        _to_jval   = OCT_STR._to_jval


class STR_T61(_String):
    __doc__ = """
ASN.1 basic type T61String object
%s
""" % _String_docstring
    
    _codec    = _ISO2022_CODEC
    
    TYPE  = TYPE_STR_T61
    TAG   = 20
    
    if _with_json:
        _from_jval = OCT_STR._from_jval
        _to_jval   = OCT_STR._to_jval


class STR_VID(_String):
    __doc__ = """
ASN.1 basic type VideotextString object
%s
""" % _String_docstring
    
    _codec    = _ISO2022_CODEC
    
    TYPE  = TYPE_STR_VID
    TAG   = 21
    
    if _with_json:
        _from_jval = OCT_STR._from_jval
        _to_jval   = OCT_STR._to_jval


class STR_IA5(_String):
    __doc__ = """
ASN.1 basic type IA5String object
%s
""" % _String_docstring
    
    _codec    = 'ascii'
    _clen     = 7
    _ALPHA_RE = \
    '\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16'\
    '\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOP'\
    'QRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
    
    TYPE  = TYPE_STR_IA5
    TAG   = 22


class STR_GRAPH(_String):
    __doc__ = """
ASN.1 basic type GraphicString object
%s
""" % _String_docstring
    
    _codec    = _ISO2022_CODEC
    
    TYPE  = TYPE_STR_GRAPH
    TAG   = 25
    
    if _with_json:
        _from_jval = OCT_STR._from_jval
        _to_jval   = OCT_STR._to_jval


class STR_VIS(_String):
    __doc__ = """
ASN.1 basic type VisibleString object
%s
""" % _String_docstring
    
    _codec    = 'ascii'
    _clen     = 7
    _ALPHA_RE = \
    '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}'
    
    TYPE  = TYPE_STR_VIS
    TAG   = 26


class STR_ISO646(_String):
    __doc__ = """
ASN.1 basic type ISO646String object
%s
""" % _String_docstring
    
    _codec    = 'ascii'
    _clen     = STR_VIS._clen
    _ALPHA_RE = STR_VIS._ALPHA_RE
    
    TYPE  = TYPE_STR_ISO646
    TAG   = 26


class STR_GENE(_String):
    __doc__ = """
ASN.1 basic type GenericString object
%s
""" % _String_docstring
    
    _codec    = _ISO2022_CODEC
    
    TYPE  = TYPE_STR_GENE
    TAG   = 27
    
    if _with_json:
        _from_jval = OCT_STR._from_jval
        _to_jval   = OCT_STR._to_jval


class STR_UNIV(_String):
    __doc__ = """
ASN.1 basic type UniversalString object
%s
""" % _String_docstring
    
    _codec = 'utf-32-be'
    _clen  = 32
    
    TYPE  = TYPE_STR_UNIV
    TAG   = 28


class STR_BMP(_String):
    __doc__ = """
ASN.1 basic type BMPString object
%s
""" % _String_docstring
    
    _codec = 'utf-16-be'
    _clen  = 16
    
    TYPE  = TYPE_STR_BMP
    TAG   = 30


#------------------------------------------------------------------------------#
# UTCTime and GeneralizedTime
#------------------------------------------------------------------------------#

class _Time(STR_VIS):
    __doc__ = """
Virtual parent for UTCTime and GeneralizedTime, both being actually subtype of
VisibleString
"""
    
    ###
    # convert the internal tuple value to a string, which then gets 
    # encoded / decoded like a VisibleString
    ###
    
    def _from_per_ws(self, char):
        _String._from_per_ws(self, char)
        self._decode_cont(self._val)
    
    def _from_per(self, char):
        _String._from_per(self, char)
        self._decode_cont(self._val)
    
    def _to_per_ws(self):
        val = self._val
        self._val = self._encode_cont(canon=True)
        ret = _String._to_per_ws(self)
        self._val = val
        return ret
    
    def _to_per(self):
        val = self._val
        self._val = self._encode_cont(canon=True)
        ret = _String._to_per(self)
        self._val = val
        return ret
    
    def _decode_ber_cont_ws(self, char, vs):
        ret = _String._decode_ber_cont_ws(self, char, vs)
        self._decode_cont(self._val)
        return ret
    
    def _decode_ber_cont(self, char, vs):
        _String._decode_ber_cont(self, char, vs)
        self._decode_cont(self._val)
    
    def _encode_ber_cont_ws(self):
        val = self._val
        if ASN1CodecBER.ENC_TIME_CANON:
            self._val = self._encode_cont(canon=True)
        else:
            self._val = self._encode_cont(canon=False)
        ret = _String._encode_ber_cont_ws(self)
        self._val = val
        return ret
    
    def _encode_ber_cont(self):
        val = self._val
        if ASN1CodecBER.ENC_TIME_CANON:
            self._val = self._encode_cont(canon=True)
        else:
            self._val = self._encode_cont(canon=False)
        ret = _String._encode_ber_cont(self)
        self._val = val
        return ret
    
    ###
    # conversion between internal value and ASN.1 JER encoding
    ###
    
    if _with_json:
        
        def _from_jval(self, val):
            _String._from_jval(self, val)
            self._decode_cont(self._val)
        
        def _to_jval(self):
            val = self._val
            self._val = self._encode_cont(canon=True)
            ret = _String._to_jval(self)
            self._val = val
            return ret
        
    

class TIME_UTC(_Time):
    __doc__ = """
ASN.1 basic type UTCTime object

Single value: Python 7-tuple of str or None 
    (YY, MM, DD, HH, MM, [SS,] Z)
    SS is optional, hence 6th element can be None
    Z corresponds to the UTC decay and can be Z or {+-}HHMM
%s
""" % ASN1Obj_docstring
    
    TYPE  = TYPE_TIME_UTC
    TAG   = 23
    
    _ASN_RE = re.compile(
    '"([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2}){0,1}((?:Z)|(?:[+-]{1}[0-9]{4}))"')
    
    def _safechk_val(self, val):
        if not isinstance(val, tuple) or len(val) != 7 \
        or not all([isinstance(v, str_types + (NoneType,)) for v in val]):
            # TODO: more conditions are required to test for the exact format
            raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        m = self._ASN_RE.match(txt.upper())
        if m is not None:
            self._val = m.groups()
            return txt[m.end():].strip()
        else:
            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'.format(self.fullname(), txt)))
    
    def _to_asn1(self):
        if self._val[5] is None:
            s = '"' + ''.join(self._val[:5] + self._val[-1:]) + '"'
            if _with_time:
                try:
                    if s[-2] == 'Z':
                        i = ' -- %s --' % asctime(strptime(s[1:-2], '%y%m%d%H%M'))
                    else:
                        i = ' -- %s --' % asctime(strptime(s[1:-1], '%y%m%d%H%M%Z'))
                except Exception:
                    i = ''
                return s + i
            else:
                return s
        else:
            s = '"' + ''.join(self._val) + '"'
            if _with_time:
                try:
                    if s[-2] == 'Z':
                        i = ' -- %s --' % asctime(strptime(s[1:-2], '%y%m%d%H%M%S'))
                    else:
                        i = ' -- %s --' % asctime(strptime(s[1:-1], '%y%m%d%H%M%S%Z'))
                except Exception:
                    i = ''
                return s + i
            else:
                return s
    
    ###
    # ascii encoding of the time string for BER and PER, in the canonical way
    ###
    
    def _decode_cont(self, asc):
        try:
            self._from_asn1('"' + asc + '"')
        except Exception:
            raise(ASN1BERDecodeErr('{0}: invalid UTCTime ascii encoding'\
                  .format(self.fullname())))
    
    def _encode_cont(self, canon=True):
        if self._val[5] is None:
            if canon:
                asc = ''.join(self._val[:5]) + '00' + self._val[-1]
            else:
                asc = ''.join(self._val[:5]) + self._val[-1]
        else:
            asc = ''.join(self._val)
        return asc


class TIME_GEN(_Time):
    __doc__ = """
ASN.1 basic type GeneralizedTime object

Single value: Python 8-tuple of str or None 
    (YYYY, MM, DD, HH, [MM, [SS,]] [{.,}F*,] [Z]),
    MM and SS are optional
    F* is optional and provides a fraction of seconds, minutes or hours
    Hence 5th, 6th and 7th element can be None
    Z corresponds to the UTC decay, can be Z, {+-}HH or {+-}HHMM and is optional, 
    hence 8th element can be None too
%s
""" % ASN1Obj_docstring
    
    TYPE  = TYPE_TIME_GEN
    TAG   = 24
    
    _ASN_RE = re.compile(
    r'"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})'
    r'(?:([0-9]{2})([0-9]{2}){0,1}){0,1}'
    r'(?:(?:\.|,)([0-9]{1,})){0,1}'
    r'((?:Z)|(?:[+-](?:[0-9]{2}){0,2})){0,1}"')
    
    def _safechk_val(self, val):
        if not isinstance(val, tuple) or len(val) != 8 \
        or not all([isinstance(v, str_types + (NoneType,)) for v in val]):
            # TODO: more conditions are required to test for the exact format
            raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        m = self._ASN_RE.match(txt)
        if m is not None:
            self._val = m.groups()
            return txt[m.end():].strip()
        else:
            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'.format(self.fullname(), txt)))
    
    def _to_asn1(self):
        if self._val[4] is None:
            num = list(self._val[:4])
        elif self._val[5] is None:
            num = list(self._val[:5])
        else:
            num = list(self._val[:6])
        if self._val[7] is not None:
            # fractionnal part
            if self._val[-1] is not None:
                # UTC decay
                num.extend( ['.'] + list(self._val[7:]) )
            else:
                num.extend( ['.', self._val[7]] )
        elif self._val[-1] is not None:
            # UTC decay
            num.append( self._val[-1] )
        return '"' + ''.join(num) + '"'
    
    ###
    # ascii encoding of the time string for BER and PER, in the canonical way
    ###
    
    def _decode_cont(self, asc):
        try:
            self._from_asn1('"' + asc + '"')
        except Exception:
            raise(ASN1BERDecodeErr('{0}: invalid GeneralizedTime ascii encoding'\
                  .format(self.fullname())))
    
    def _encode_cont(self, canon=True):
        if canon:
            if self._val[4] is None:
                asc = list(self._val[:4]) + ['00', '00']
            elif self._val[5] is None:
                asc = list(self._val[:5]) + ['00']
            else:
                asc = list(self._val[:6])
            if self._val[6] is not None and int(self._val[6]) != 0:
                # fractionnal part, removing trailing 0
                asc.append( '.' + self._val[6].rstrip('0') )
            if self._val[-1] in (None, 'Z'):
                # UTC time (or considered so...)
                asc.append( 'Z' )
            else:
                # apply the UTC decay compensation
                if not _with_datetime:
                    raise(ASN1NotSuppErr('{0}: UTC decay compensation requires module datetime'\
                          .format(self.fullname())))
                else:
                    # keep precision up to minutes
                    dt = datetime(*map(int, asc[:5]))
                    if len(self._val[-1]) == 3:
                        delta = timedelta(hours=int(self._val[-1][1:3]), minutes=0)
                    else:
                        delta = timedelta(hours=int(self._val[-1][1:3]), minutes=int(self._val[-1][3:5]))
                    if self._val[-1][0:1] == '-':
                        dt += delta
                    else:
                        dt -= delta
                    asc = [dt.strftime('%Y%m%d%H%M'), asc[5], asc[6], 'Z']
        else:
            if self._val[4] is None:
                asc = list(self._val[:4])
            elif self._val[5] is None:
                asc = list(self._val[:5])
            else:
                asc = list(self._val[:6])
            if self._val[6] is not None:
                # fractionnal part
                asc.append( '.' + self._val[6] )
            if self._val[-1] is not None:
                # UTC decay
                asc.append( self._val[-1] )
        return ''.join(asc)

