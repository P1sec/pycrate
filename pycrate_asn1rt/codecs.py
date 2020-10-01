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
# * File Name : pycrate_asn1rt/codec.py
# * Created : 2017-01-31
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from .utils import *
from .err   import *

from pycrate_core.elt import _with_json
if _with_json:
    from pycrate_core.elt import JsonEnc, JsonDec, JSONDecodeError
    from binascii         import hexlify, unhexlify


class ASN1Codec(object):
    pass


class ASN1CodecASN(ASN1Codec):
    pass


class ASN1CodecPER(ASN1Codec):
    
    ALIGNED = False # True: aligned PER (APER), False: unaligned PER (UPER)
    
    # canonicity is used to decide wether to encode default values or not in 
    # constructed object
    CANONICAL = True
    
    # this is used to return default values, even when absent from the transfer syntax
    GET_DEFVAL = True
    
    # maximum length (or number of objects) allowed when decoding a fragmented stream
    DEC_MAXL = 1 * 1024 * 1024 # 1M
    
    _off = [] # stack of offsets in bits, only used with APER
    
    _CntUndef_LUT = {1:16384, 2:32768, 3:49152, 4:65536,
                     16384:1, 32768:2, 49152:3, 65536:4}
    
    @classmethod
    def decode_pad_ws(cla, char):
        pl = 8 - (cla._off[-1] % 8)
        P = Uint('P', bl=pl, rep=REPR_BIN)
        P._from_char(char)
        cla._off[-1] += pl
        return [P]
    
    @classmethod
    def decode_pad(cla, char):
        pl = 8 - (cla._off[-1] % 8)
        pad = char.get_uint(pl)
        cla._off[-1] += pl
    
    @classmethod
    def encode_pad_ws(cla):
        pl = 8 - (cla._off[-1] % 8)
        cla._off[-1] += pl
        return [Uint('P', val=0, bl=pl, rep=REPR_BIN)]
    
    @classmethod
    def encode_pad(cla):
        pl = 8 - (cla._off[-1] % 8)
        cla._off[-1] += pl
        return [(T_UINT, 0, pl)]
    
    @classmethod
    def decode_count_ws(cla, char):
        GEN = [Uint('C_form', bl=1, dic={0:'short', 1:'long'})]
        GEN[-1]._from_char(char)
        if GEN[-1]():
            GEN.append( Uint('C_undef', bl=1) )
            GEN[-1]._from_char(char)
            if GEN[-1]():
                GEN.append( Uint('C', bl=6, dic=cla._CntUndef_LUT) )
                GEN[-1]._from_char(char)
                if cla.ALIGNED:
                    cla._off[-1] += 8
                try:
                    return cla._CntUndef_LUT[GEN[-1]()], GEN
                except KeyError:
                    raise(ASN1PERDecodeErr('invalid undef count value, {0}'.format(GEN[-1]())))
            else:
                GEN.append( Uint('C', bl=14) )
                GEN[-1]._from_char(char)
                if cla.ALIGNED:
                    cla._off[-1] += 16
                return GEN[-1](), GEN
        else:
            GEN.append( Uint('C', bl=7) )
            GEN[-1]._from_char(char)
            if cla.ALIGNED:
                cla._off[-1] += 8
            return GEN[-1](), GEN
    
    @classmethod
    def decode_count(cla, char):
        form = char.get_uint(1)
        if form:
            undef = char.get_uint(1)
            if undef:
                cnt = char.get_uint(6)
                if cla.ALIGNED:
                    cla._off[-1] += 8
                try:
                    return cla._CntUndef_LUT[cnt]
                except KeyError:
                    raise(ASN1PERDecodeErr('invalid undef count value, {0}'.format(cnt)))
            else:
                cnt = char.get_uint(14)
                if cla.ALIGNED:
                    cla._off[-1] += 16
                return cnt
        else:
            cnt = char.get_uint(7)
            if cla.ALIGNED:
                cla._off[-1] += 8
            return cnt
    
    @classmethod
    def encode_count_ws(cla, cnt):
        if 0 <= cnt <= 127:
            if cla.ALIGNED:
                cla._off[-1] += 8
            return [Uint('C_form', val=0, bl=1, dic={0:'short', 1:'long'}),
                    Uint('C', val=cnt, bl=7)]
        elif 128 <= cnt <= 16383:
            if cla.ALIGNED:
                cla._off[-1] += 16
            return [Uint('C_form', val=1, bl=1, dic={0:'short', 1:'long'}),
                    Uint('C_undef', val=0, bl=1),
                    Uint('C', val=cnt, bl=14)]
        elif cnt in (16384, 32768, 49152, 65536):
            if cla.ALIGNED:
                cla._off[-1] += 8
            return [Uint('C_form', val=1, bl=1, dic={0:'short', 1:'long'}),
                    Uint('C_undef', val=1, bl=1),
                    Uint('C', val=cla._CntUndef_LUT[cnt], bl=6, dic=cla._CntUndef_LUT)]
        else:
            raise(ASN1PEREncodeErr('count value overflow, {0}'.format(cnt)))
    
    @classmethod
    def encode_count(cla, cnt):
        if 0 <= cnt <= 127:
            if cla.ALIGNED:
                cla._off[-1] += 8
            return [(T_UINT, 0, 1), (T_UINT, cnt, 7)]
        elif 128 <= cnt <= 16383:
            if cla.ALIGNED:
                cla._off[-1] += 16
            return [(T_UINT, 1, 1), (T_UINT, 0, 1), (T_UINT, cnt, 14)]
        elif cnt in (16384, 32768, 49152, 65536):
            if cla.ALIGNED:
                cla._off[-1] += 8
            return [(T_UINT, 1, 1), (T_UINT, 1, 1), (T_UINT, cla._CntUndef_LUT[cnt], 6)]
        else:
            raise(ASN1PEREncodeErr('count value overflow, {0}'.format(cnt)))
    
    @classmethod
    def decode_intunconst_ws(cla, char, offset=None, name='V'):
        if cla.ALIGNED and cla._off[-1] % 8:
            GEN = cla.decode_pad_ws(char)
        else:
            GEN = []
        # 1) get byte-length determinant
        ldet, _gen = cla.decode_count_ws(char)
        GEN.extend(_gen)
        # 2) get value, byte-aligned
        if ldet == 0:
            if offset is None:
                return 0, GEN
            else:
                return offset, GEN
        elif ldet in (65536, 49152, 32768, 16384):
            # requires defragmentation
            (buf, buflen), _gen = cla.decode_fragbytes_ws(char, ldet)
            GEN.extend(_gen)
            if offset is None:
                return bytes_to_int(buf, 8*buflen), GEN
            else:
                return offset + bytes_to_uint(buf, 8*buflen), GEN
        else:
            if offset is None:
                V = Int(name, bl=8*ldet)
                V._from_char(char)
                GEN.append(V)
                if cla.ALIGNED:
                    cla._off[-1] += 8*ldet
                return V(), GEN
            else:
                V = Uint(name, bl=8*ldet)
                V._from_char(char)
                GEN.append(V)
                if cla.ALIGNED:
                    cla._off[-1] += 8*ldet
                return offset + V(), GEN
    
    @classmethod
    def decode_intunconst(cla, char, offset=None):
        if cla.ALIGNED and cla._off[-1] % 8:
            cla.decode_pad(char)
        # 1) get byte-length determinant
        ldet = cla.decode_count(char)
        # 2) get value, byte-aligned
        if ldet == 0:
            if offset is None:
                return 0
            else:
                return offset
        elif ldet in (65536, 49152, 32768, 16384):
            # requires defragmentation
            buf, buflen = cla.decode_fragbytes(char, ldet)
            if offset is None:
                return bytes_to_int(buf, 8*buflen)
            else:
                return offset + bytes_to_uint(buf, 8*buflen)
        else:
            if offset is None:
                if cla.ALIGNED:
                    cla._off[-1] += 8*ldet
                return char.get_int(8*ldet)
            else:
                if cla.ALIGNED:
                    cla._off[-1] += 8*ldet
                return offset + char.get_uint(8*ldet)
    
    @classmethod
    def encode_intunconst_ws(cla, val, offset=None, name='V'):
        if cla.ALIGNED and cla._off[-1] % 8:
            GEN = cla.encode_pad_ws()
        else:
            GEN = []
        if offset is None:
            # 1) set byte-length determinant
            ldet = int_bytelen(val)
            if ldet >= 16384:
                # val is a large integer, requires fragmentation
                buf = Int(name, val=val, bl=8*ldet).to_bytes()
                GEN.extend( cla.encode_fragbytes_ws(buf) )
            else:
                GEN.extend( cla.encode_count_ws(ldet) )
                # 2) set value, byte-aligned
                GEN.append( Int(name, val=val, bl=8*ldet) )
                if cla.ALIGNED:
                    cla._off[-1] += 8*ldet
        else:
            # 1) set byte-length determinant
            val = val - offset
            ldet = uint_bytelen(val)
            if ldet >= 16384:
                # val is a large integer, requires fragmentation
                buf = Uint(name, val=val, bl=8*ldet).to_bytes()
                GEN.extend( cla.encode_fragbytes_ws(buf) )
            else:
                GEN.extend( cla.encode_count_ws(ldet) )
                # 2) set value, byte-aligned
                GEN.append( Uint(name, val=val, bl=8*ldet) )
                if cla.ALIGNED:
                    cla._off[-1] += 8*ldet
        return GEN
    
    @classmethod
    def encode_intunconst(cla, val, offset=None):
        if cla.ALIGNED and cla._off[-1] % 8:
            GEN = cla.encode_pad()
        else:
            GEN = []
        if offset is None:
            # 1) set byte-length determinant
            ldet = int_bytelen(val)
            if ldet >= 16384:
                # val is a large integer, requires fragmentation
                buf = Int('V', val=val, bl=8*ldet).to_bytes()
                GEN.extend( cla.encode_fragbytes(buf) )
            else:
                GEN.extend( cla.encode_count(ldet) )
                # 2) set value, byte-aligned
                GEN.append( (T_INT, val, 8*ldet) )
                if cla.ALIGNED:
                    cla._off[-1] += 8*ldet
        else:
            # 1) set byte-length determinant
            val = val - offset
            ldet = uint_bytelen(val)
            if ldet >= 16384:
                # val is a large integer, requires fragmentation
                buf = Uint('V', val=val, bl=8*ldet).to_bytes()
                GEN.extend( cla.encode_fragbytes(buf) )
            else:
                GEN.extend( cla.encode_count(ldet) )
                # 2) set value, byte-aligned
                GEN.append( (T_UINT, val, 8*ldet) )
                if cla.ALIGNED:
                    cla._off[-1] += 8*ldet
        return GEN
    
    @classmethod
    def decode_intconst_ws(cla, char, const_val, name='V'):
        GEN = []
        if cla.ALIGNED:
            # 2) fully constrained value, aligned variant
            if const_val.ra <= 255:
                # no realignment
                bl = const_val.rdyn
            elif const_val.ra <= 65536:
                # realignment required, and 1 or 2 bytes encoding
                if cla._off[-1] % 8:
                    GEN.extend( cla.decode_pad_ws(char) )
                if const_val.ra == 256:
                    bl = 8
                else:
                    bl = 16
            else:
                # custom length determinant and realignment
                odyn = int(ceil(const_val.rdyn/8.0))-1
                ldet_bl = odyn.bit_length()
                ldet = Uint('C', bl=ldet_bl)
                ldet._from_char(char)
                GEN.append(ldet)
                cla._off[-1] += ldet_bl
                bl = 8*(1+ldet())
                if cla._off[-1] % 8:
                    GEN.extend( cla.decode_pad_ws(char) )
            cla._off[-1] += bl
        else:
            # 3) fully constrained value, unaligned variant
            # decoding the value offset in the minimum number of bits
            bl = const_val.rdyn
        Vo = Uint(name, bl=bl)
        Vo._from_char(char)
        GEN.append(Vo)
        return Vo() + const_val.lb, GEN
    
    @classmethod
    def decode_intconst(cla, char, const_val):
        if cla.ALIGNED:
            # 2) fully constrained value, aligned variant
            if const_val.ra <= 255:
                # no realignment
                bl = const_val.rdyn
            elif const_val.ra <= 65536:
                # realignment required, and 1 or 2 bytes encoding
                if cla._off[-1] % 8:
                    cla.decode_pad(char)
                if const_val.ra == 256:
                    bl = 8
                else:
                    bl = 16
            else:
                # custom length determinant and realignment
                odyn = int(ceil(const_val.rdyn/8.0))-1
                ldet_bl = odyn.bit_length()
                ldet = char.get_uint(ldet_bl)
                cla._off[-1] += ldet_bl
                bl = 8*(1+ldet)
                if cla._off[-1] % 8:
                    cla.decode_pad(char)
            cla._off[-1] += bl
        else:
            # 3) fully constrained value, unaligned variant
            # decoding the value offset in the minimum number of bits
            bl = const_val.rdyn
        return char.get_uint(bl) + const_val.lb
    
    @classmethod
    def encode_intconst_ws(cla, val, const_val, name='V'):
        GEN = []
        val = val - const_val.lb
        if cla.ALIGNED:
            # 2) fully constrained value, aligned variant
            if const_val.ra <= 255:
                # no realignment
                bl = const_val.rdyn
            elif const_val.ra <= 65536:
                # realignment required, and 1 or 2 bytes encoding
                if cla._off[-1] % 8:
                    GEN.extend( cla.encode_pad_ws() )
                if const_val.ra == 256:
                    bl = 8
                else:
                    bl = 16
            else:
                # custom length determinant
                odyn = int(ceil(const_val.rdyn/8.0))-1
                ldet_bl = odyn.bit_length()
                if val:
                    val_dyn = int(ceil(val.bit_length()/8.0))
                else:
                    val_dyn = 1
                GEN.append( Uint('C', val=val_dyn-1, bl=ldet_bl) )
                cla._off[-1] += ldet_bl
                bl = 8*val_dyn
                if cla._off[-1] % 8:
                    GEN.extend( cla.encode_pad_ws() )
            cla._off[-1] += bl
        else:
            # 3) fully constrained value, unaligned variant
            # decoding the value offset in the minimum number of bits
            bl = const_val.rdyn
        GEN.append( Uint(name, val=val, bl=bl) )
        return GEN
    
    @classmethod
    def encode_intconst(cla, val, const_val):
        GEN = []
        val = val - const_val.lb
        if cla.ALIGNED:
            # 2) fully constrained value, aligned variant
            if const_val.ra <= 255:
                # no realignment
                bl = const_val.rdyn
            elif const_val.ra <= 65536:
                # realignment required, and 1 or 2 bytes encoding
                if cla._off[-1] % 8:
                    GEN.extend( cla.encode_pad() )
                if const_val.ra == 256:
                    bl = 8
                else:
                    bl = 16
            else:
                # custom length determinant
                odyn = int(ceil(const_val.rdyn/8.0))-1
                ldet_bl = odyn.bit_length()
                if val:
                    val_dyn = int(ceil(val.bit_length()/8.0))
                else:
                    val_dyn = 1
                GEN.append( (T_UINT, val_dyn-1, ldet_bl) )
                cla._off[-1] += ldet_bl
                bl = 8*val_dyn
                if cla._off[-1] % 8:
                    GEN.extend( cla.encode_pad() )
            cla._off[-1] += bl
        else:
            # 3) fully constrained value, unaligned variant
            # decoding the value offset in the minimum number of bits
            bl = const_val.rdyn
        GEN.append( (T_UINT, val, bl) )
        return GEN
    
    @classmethod
    def decode_fragbytes_ws(cla, char, ldet, bits=False):
        GEN, B, L = [], [], 0
        while ldet in (65536, 49152, 32768, 16384):
            if bits:
                F = Buf('F_%r' % ldet, bl=ldet, rep=REPR_BIN)
                if cla.ALIGNED:
                    cla._off[-1] += ldet
            else:
                F = Buf('F_%r' % ldet, bl=8*ldet, rep=REPR_HEX)
                if cla.ALIGNED:
                    cla._off[-1] += 8*ldet
            F._from_char(char)
            B.append( F.to_bytes() )
            GEN.append(F)
            ldet, _gen = cla.decode_count_ws(char)
            GEN.extend( _gen )
            L += ldet
            if L > cla.DEC_MAXL:
                raise(ASN1PERDecodeErr('too much fragments, {0!r}'.format(L)))
        if bits:
            F = Buf('F_rem', bl=ldet, rep=REPR_BIN)
            if cla.ALIGNED:
                cla._off[-1] += ldet
        else:
            F = Buf('F_rem', bl=8*ldet, rep=REPR_HEX)
            if cla.ALIGNED:
                cla._off[-1] += 8*ldet
        F._from_char(char)
        B.append( F.to_bytes() )
        GEN.append(F)
        L += ldet
        return (b''.join(B), L), GEN
    
    @classmethod
    def decode_fragbytes(cla, char, ldet, bits=False):
        B, L = [], 0
        while ldet in (65536, 49152, 32768, 16384):
            if bits:
                B.append( char.get_bytes(ldet) )
                if cla.ALIGNED:
                    cla._off[-1] += ldet
            else:
                B.append( char.get_bytes(8*ldet) )
                if cla.ALIGNED:
                    cla._off[-1] += 8*ldet
            ldet = cla.decode_count(char)
            L += ldet
            if L > cla.DEC_MAXL:
                raise(ASN1PERDecodeErr('too much fragments, {0!r}'.format(L)))
        if bits:
            B.append( char.get_bytes(ldet) )
            if cla.ALIGNED:
                cla._off[-1] += ldet
        else:
            B.append( char.get_bytes(8*ldet) )
            if cla.ALIGNED:
                cla._off[-1] += ldet
        L += ldet
        return b''.join(B), L
    
    @classmethod
    def encode_fragbytes_ws(cla, buf, bits=None):
        # check how much fragments are required
        if bits:
            frags, rem = factor_perfrag(bits)
        else:
            frags, rem = factor_perfrag(len(buf))
        GEN, off = [], 0
        if cla.ALIGNED and cla._off[-1] % 8:
            GEN.extend( cla.encode_pad_ws() )
        # encode all fragments
        for (fs, fn) in frags:
            for i in range(fn):
                GEN.extend( cla.encode_count_ws(fs) )
                if bits:
                    GEN.append( Buf('F_%r' % fs, val=buf[off:off+fs>>3], bl=fs, rep=REPR_BIN) )
                    off += fs>>3
                    if cla.ALIGNED:
                        cla._off[-1] += fs
                else:
                    GEN.append( Buf('F_%r' % fs, val=buf[off:off+fs], bl=8*fs, rep=REPR_HEX) )
                    off += fs
                    if cla.ALIGNED:
                        cla._off[-1] += 8*fs
        # encode the remainder
        GEN.extend( cla.encode_count_ws(rem) )
        if bits:
            GEN.append( Buf('F_rem', val=buf[off:], bl=rem, rep=REPR_BIN) )
            if cla.ALIGNED:
                cla._off[-1] += rem
        else:
            GEN.append( Buf('F_rem', val=buf[off:], bl=8*rem, rep=REPR_HEX) )
            if cla.ALIGNED:
                cla._off[-1] += 8*rem
        return GEN
    
    @classmethod
    def encode_fragbytes(cla, buf, bits=None):
        # check how much fragments are required
        if bits:
            frags, rem = factor_perfrag(bits)
        else:
            frags, rem = factor_perfrag(len(buf))
        GEN, off = [], 0
        if cla.ALIGNED and cla._off[-1] % 8:
            GEN.extend( cla.encode_pad() )
        # encode all fragments
        for (fs, fn) in frags:
            for i in range(fn):
                GEN.extend( cla.encode_count(fs) )
                if bits:
                    GEN.append( (T_BYTES, buf[off:off+fs>>3], fs) )
                    off += fs>>3
                    if cla.ALIGNED:
                        cla._off[-1] += fs
                else:
                    GEN.append( (T_BYTES, buf[off:off+fs], 8*fs) )
                    off += fs
                    if cla.ALIGNED:
                        cla._off[-1] += 8*fs
        # encode the remainder
        GEN.extend( cla.encode_count(rem) )
        if bits:
            GEN.append( (T_BYTES, buf[off:], rem) )
            if cla.ALIGNED:
                cla._off[-1] += rem
        else:
            GEN.append( (T_BYTES, buf[off:], 8*rem) )
            if cla.ALIGNED:
                cla._off[-1] += 8*rem
        return GEN
    
    @classmethod
    def decode_fragcharstr_ws(cla, char, ldet, cdyn, arr=False):
        # check how much fragments are required
        frags, rem = factor_perfrag(ldet)
        GEN, V, L = [], [], 0
        while ldet in (65536, 49152, 32768, 16384):
            if arr:
                F = Array('F_%r' % ldet, num=ldet, GEN=Uint('char', bl=cdyn))
            else:
                F = Buf('F_%r' % ldet, bl=ldet*cdyn)
            F._from_char(char)
            GEN.append(F)
            if cla.ALIGNED:
                cla._off[-1] += ldet*cdyn
            if arr:
                V.extend( F() )
            else:
                V.append( F() )
            ldet, _gen = cla.decode_count_ws(char)
            GEN.extend(_gen)
            L += ldet
            if L > cla.DEC_MAXL:
                raise(ASN1PERDecodeErr('too much fragments, {0!r}'.format(L)))
        if arr:
            F = Array('F_%r' % ldet, num=ldet, GEN=Uint('char', bl=cdyn))
        else:
            F = Buf('F_%r' % ldet, bl=ldet*cdyn)
        F._from_char(char)
        GEN.append(F)
        if cla.ALIGNED:
            cla._off[-1] += ldet*cdyn
        if arr:
            V.extend( F() )
        else:
            V.append( F() )
            V = ''.join(V)
        return V, GEN
    
    @classmethod
    def decode_fragcharstr(cla, char, ldet, cdyn, arr=False):
        # check how much fragments are required
        frags, rem = factor_perfrag(ldet)
        V = []
        while ldet in (65536, 49152, 32768, 16384):
            if arr:
                V.extend( [char.get_uint(cdyn) for i in range(ldet)] )
            else:
                V.append( char.get_bytes(cdyn*ldet) )
            if cla.ALIGNED:
                cla._off[-1] += ldet*cdyn
            ldet = cla.decode_count(char)
            L += ldet
            if L > cla.DEC_MAXL:
                raise(ASN1PERDecodeErr('too much fragments, {0!r}'.format(L)))
        if arr:
            V.extend( [char.get_uint(cdyn) for i in range(ldet)] )
        else:
            V.append( char.get_bytes(cdyn*ldet) )
        if cla.ALIGNED:
            cla._off[-1] += ldet*cdyn
        if not arr:
            V = ''.join(V)
        return V
    
    @classmethod
    def encode_fragcharstr_ws(cla, val, cdyn, ldet):
        # check how much fragments are required
        frags, rem = factor_perfrag(ldet)
        GEN, off = [], 0
        if isinstance(val, bytes_types):
            # utf-16 or utf-32 characters
            isbytes, codyn = True, cdyn>>8
        else:
            isbytes = False
        if cla.ALIGNED and cla._off[-1] % 8:
            GEN.extend( cla.encode_pad() )
        # encode all fragments
        for (fs, fn) in frags:
            for i in range(fn):
                GEN.extend( cla.encode_count_ws(fs) )
                if isbytes:
                    l = fs*codyn
                    GEN.append( Buf('F_%r' % fs, val=val[off:off+l], bl=l) )
                    off += l
                    if cla.ALIGNED:
                        cla._off[-1] += 8*l
                else:
                    GEN.append( Array('F_%r' % fs, val=val[off:off+fs], GEN=Uint('char', bl=cdyn)) )
                    off += fs
                    if cla.ALIGNED:
                        cla._off[-1] += fs*cdyn
        # encode the remainder
        GEN.extend( cla.encode_count(rem) )
        if isbytes:
            l = rem*codyn
            GEN.append( Buf('F_%r' % fs, val=val[off:off+l], bl=l) )
            off += l
            if cla.ALIGNED:
                cla._off[-1] += 8*l
        else:
            GEN.append( Array('F_%r' % fs, val=val[off:off+rem], GEN=Uint('char', bl=cdyn)) )
            off += rem
            if cla.ALIGNED:
                cla._off[-1] += rem*cdyn
        return GEN
    
    @classmethod
    def encode_fragcharstr(cla, val, cdyn, ldet):
        # check how much fragments are required
        frags, rem = factor_perfrag(len(val))
        GEN, off = [], 0
        if isinstance(val, bytes_types):
            # utf-16 or utf-32 characters
            isbytes, codyn = True, cdyn>>8
        else:
            isbytes = False
        if cla.ALIGNED and cla._off[-1] % 8:
            GEN.extend( cla.encode_pad() )
        # encode all fragments
        for (fs, fn) in frags:
            for i in range(fn):
                GEN.extend( cla.encode_count(fs) )
                if isbytes:
                    l = fs*codyn
                    GEN.append( (T_BYTES, val[off:off+l], 8*l) )
                    off += l
                    if cla.ALIGNED:
                        cla._off[-1] += 8*l
                else:
                    GEN.extend( [(T_UINT, v, cdyn) for v in val[off:off+fs]] )
                    off += fs
                    if cla.ALIGNED:
                        cla._off[-1] += fs*cdyn
        # encode the remainder
        GEN.extend( cla.encode_count(rem) )
        if isbytes:
            l = rem*codyn
            GEN.append( (T_BYTES, val[off:off+l], 8*l) )
            off += l
            if cla.ALIGNED:
                cla._off[-1] += 8*l
        else:
            GEN.extend( [(T_UINT, v, cdyn) for v in val[off:off+rem]] )
            off += rem
            if cla.ALIGNED:
                cla._off[-1] += rem*cdyn
        return GEN
    
    @classmethod
    def decode_unconst_open_ws(cla, char, wrapped=None):
        if cla.ALIGNED and cla._off[-1] % 8:
            GEN = cla.decode_pad_ws(char)
        else:
            GEN = []
        # decode the unconstrained length determinant
        ldet, _gen = cla.decode_count_ws(char)
        GEN.extend(_gen)
        if ldet in (65536, 49152, 32768, 16384):
            # requires defragmentation
            (buf, ldet), _gen = cla.decode_fragbytes_ws(char, ldet)
            GEN.extend(_gen)
            if wrapped is None:
                return buf, GEN
            else:
                if cla.ALIGNED:
                    wrapped.from_aper_ws(buf)
                else:
                    wrapped.from_uper_ws(buf)
                val = wrapped._val
                #wrapped._val = None
                return val, GEN
        elif wrapped is None:
            V = Buf('V', bl=8*ldet, rep=REPR_HEX)
            V._from_char(char)
            GEN.append(V)
            if cla.ALIGNED:
                cla._off[-1] += 8*ldet
            return V(), GEN
        else:
            # shorten char according to ldet
            lb = char._len_bit
            char._len_bit = char._cur + 8*ldet
            if char._len_bit > lb:
                raise(ASN1PERDecodeErr('length determinant too long'))
            if cla.ALIGNED:
                # keep track of the char's cursor to increment the APER offset
                _cur = char._cur
                wrapped.from_aper_ws(char)
                cla._off[-1] += char._cur - _cur
            else:
                wrapped.from_uper_ws(char)
            # restore char length
            char._len_bit = lb
            GEN.append(wrapped._struct)
            val = wrapped._val
            #wrapped._val = None
            return val, GEN
    
    @classmethod
    def decode_const_open_ws(cla, char, const_sz, wrapped=None):
        if const_sz.rdyn != 0:
            # decode the constrained length determinant
            ldet, GEN = cla.decode_intconst_ws(char, const_sz)
            if cla.ALIGNED and cla._off[-1] % 8:
                GEN.extend( cla.decode_pad_ws(char) )
        else:
            # implicit length determinant
            ldet, GEN = const_sz.ub, []
            if cla.ALIGNED and ldet > 2 and cla._off[-1] % 8:
                GEN.extend( cla.decode_pad_ws(char) )
        if wrapped is None:
            # no wrapped object, decoding a byte buffer 
            V = Buf('V', bl=8*ldet, rep=REPR_HEX)
            V._from_char(char)
            GEN.append(V)
            if cla.ALIGNED:
                cla._off[-1] += 8*ldet
            return V(), GEN
        else:
            # shorten char according to ldet
            lb = char._len_bit
            char._len_bit = char._cur + 8*ldet
            if char._len_bit > lb:
                raise(ASN1PERDecodeErr('length determinant too long'))
            # decoding a wrapped object
            if cla.ALIGNED:
                # keep track of the char's cursor to increment the APER offset
                _cur = char._cur
                wrapped.from_aper_ws(char)
                cla._off[-1] += char._cur - _cur
            else:
                wrapped.from_uper_ws(char)
            # restore char length
            char._len_bit = lb
            GEN.append(wrapped._struct)
            val = wrapped._val
            #wrapped._val = None
            return val, GEN
    
    @classmethod
    def decode_unconst_open(cla, char, wrapped=None):
        # decode the unconstrained length determinant
        if cla.ALIGNED and cla._off[-1] % 8:
            cla.decode_pad(char)
        ldet = cla.decode_count(char)
        if ldet in (65536, 49152, 32768, 16384):
            # requires defragmentation
            buf, ldet = cla.decode_fragbytes(char, ldet)
            if wrapped is None:
                return buf
            else:
                if cla.ALIGNED:
                    wrapped.from_aper(buf)
                else:
                    wrapped.from_uper(buf)
                val = wrapped._val
                #wrapped._val = None
                return val
        elif wrapped is None:
            if cla.ALIGNED:
                cla._off[-1] += 8*ldet
            return char.get_bytes(8*ldet)
        else:
            # shorten char according to ldet
            lb = char._len_bit
            char._len_bit = char._cur + 8*ldet
            if char._len_bit > lb:
                raise(ASN1PERDecodeErr('length determinant too long'))
            if cla.ALIGNED:
                # keep track of the char's cursor to increment the APER offset
                _cur = char._cur
                wrapped.from_aper(char)
                cla._off[-1] += char._cur - _cur
            else:
                wrapped.from_uper(char)
            # restore char length
            char._len_bit = lb
            val = wrapped._val
            #wrapped._val = None
            return val
    
    @classmethod
    def decode_const_open(cla, char, const_sz, wrapped=None):
        if const_sz.rdyn != 0:
            # decode the constrained length determinant
            ldet = cla.decode_intconst(char, const_sz)
            if cla.ALIGNED and cla._off[-1] % 8:
                cla.decode_pad(char)
        else:
            # implicit length determinant
            ldet = const_sz.ub
            if cla.ALIGNED and ldet > 2 and cla._off[-1] % 8:
                cla.decode_pad(char)
        if wrapped is None:
            # no wrapped object, decoding a byte buffer 
            if cla.ALIGNED:
                cla._off[-1] += 8*ldet
            return char.get_bytes(8*ldet)
        else:
            # shorten char according to ldet
            lb = char._len_bit
            char._len_bit = char._cur + 8*ldet
            if char._len_bit > lb:
                raise(ASN1PERDecodeErr('length determinant too long'))
            # decoding a wrapped object
            if cla.ALIGNED:
                # keep track of the char's cursor to increment the APER offset
                _cur = char._cur
                wrapped.from_aper(char)
                cla._off[-1] += char._cur - _cur
            else:
                wrapped.from_uper(char)
            # restore char length
            char._len_bit = lb
            val = wrapped._val
            #wrapped._val = None
            return val
    
    @classmethod
    def encode_unconst_open_ws(cla, wrapped):
        if cla.ALIGNED and cla._off[-1] % 8:
            GEN = cla.encode_pad_ws()
        else:
            GEN = []
        # encode wrapped
        if cla.ALIGNED:
            buf = wrapped.to_aper_ws()
        else:
            buf = wrapped.to_uper_ws()
        # need to check the length in bytes
        ldet = len(buf)
        if len(buf) >= 16384:
            # requires fragmentation
            GEN.extend( cla.encode_fragbytes_ws(buf) )
        else:
            GEN.extend( cla.encode_count_ws(ldet) )
            if cla.ALIGNED:
                cla._off[-1] += 8*ldet
            if wrapped._typeref is not None:
                wrapped._struct._name = wrapped._tr._name
            GEN.append( wrapped._struct )
        return GEN
    
    @classmethod
    def encode_unconst_open(cla, wrapped):
        if cla.ALIGNED and cla._off[-1] % 8:
            GEN = cla.encode_pad()
        else:
            GEN = []
        # encode wrapped
        if cla.ALIGNED:
            buf = wrapped.to_aper()
        else:
            buf = wrapped.to_uper()
        # need to check the length in bytes
        ldet = len(buf)
        if len(buf) >= 16384:
            # requires fragmentation
            GEN.extend( cla.encode_fragbytes(buf) )
        else:
            GEN.extend( cla.encode_count(ldet) )
            GEN.append( (T_BYTES, buf, 8*ldet) )
            if cla.ALIGNED:
                cla._off[-1] += 8*ldet
        return GEN
    
    @classmethod
    def encode_unconst_buf_ws(cla, buf):
        if cla.ALIGNED and cla._off[-1] % 8:
            GEN = cla.encode_pad_ws()
        else:
            GEN = []
        ldet = len(buf)
        if ldet >= 16384:
            # requires fragmentation
            GEN.extend( cla.encode_fragbytes_ws(buf) )
        else:
            GEN.extend( cla.encode_count_ws(ldet) )
            GEN.append( Buf('V', val=buf, bl=8*ldet, rep=REPR_HEX) )
            if cla.ALIGNED:
                cla._off[-1] += 8*ldet
        return GEN
    
    @classmethod
    def encode_const_buf_ws(cla, buf, const_sz):
        ldet = len(buf)
        if const_sz.rdyn != 0:
            # encode the constrained length determinant
            GEN = cla.encode_intconst_ws(ldet, const_sz, name='C')
            if cla.ALIGNED:
                if cla._off[-1] % 8:
                    GEN.extend( cla.encode_pad_ws() )
                cla._off[-1] += 8*ldet
        else:
            # implicit length determinant
            if ldet != const_sz.ub:
                raise(ASN1PEREncodeErr('invalid buf length'))
            GEN = []
            if cla.ALIGNED:
                if const_sz.ub > 2 and cla._off[-1] % 8:
                    GEN.extend( cla.encode_pad_ws() )
                cla._off[-1] += 8*ldet
        GEN.append( Buf('V', val=buf, bl=8*ldet, rep=REPR_HEX) )
        return GEN
    
    @classmethod
    def encode_unconst_buf(cla, buf):
        if cla.ALIGNED and cla._off[-1] % 8:
            GEN = cla.encode_pad()
        else:
            GEN = []
        ldet = len(buf)
        if ldet >= 16384:
            # requires fragmentation
            GEN.extend( cla.encode_fragbytes(buf) )
        else:
            GEN.extend( cla.encode_count(ldet) )
            GEN.append( (T_BYTES, buf, 8*ldet) )
            if cla.ALIGNED:
                cla._off[-1] += 8*ldet
        return GEN
    
    @classmethod
    def encode_const_buf(cla, buf, const_sz):
        ldet = len(buf)
        if const_sz.rdyn != 0:
            # encode the constrained length determinant
            GEN = cla.encode_intconst(ldet, const_sz)
            if cla.ALIGNED:
                if cla._off[-1] % 8:
                    GEN.extend( cla.encode_pad() )
                cla._off[-1] += 8*ldet
        else:
            GEN = []
            # implicit length determinant
            if ldet != const_sz.ub:
                raise(ASN1PEREncodeErr('invalid buf length'))
            if cla.ALIGNED:
                if const_sz.ub > 2 and cla._off[-1] % 8:
                    GEN.extend( cla.encode_pad() )
                cla._off[-1] += 8*ldet
        GEN.append( (T_BYTES, buf, 8*ldet) )
        return GEN


class ASN1CodecBER(ASN1Codec):
    
    # maximum number of bytes the decoder accepts for a tag integral value
    DEC_MAXT = 32
    # maximum number of bytes the decoder accepts for a length integral value
    # the ASN.1 standard has a max of 126 here, anyway...
    DEC_MAXL = 32
    
    # force the encoder to use the long format of the length if ENC_LLONG > 0
    # then provides the maximum value between ENC_LLONG and the minimum of bytes 
    # required for encoding the length
    # CER and DER require ENC_LLONG = 0
    ENC_LLONG  = 0
    # force the encoder to use the undefinite format of the length of constructed
    # objects
    # CER requires ENC_LUNDEF = True
    # DER requires ENC_LUNDEF = False
    ENC_LUNDEF = False
    
    # force the encoder to use a given value for BOOLEAN TRUE (0 < X < 0xff)
    # CER and DER require ENC_BOOLTRUE = 0xff
    ENC_BOOLTRUE = 0xff
    
    # set the default null value for decoding REAL
    #DEC_REALNULL = (0, 10, 1)
    DEC_REALNULL = (0, 2, 0)
    
    # force the encoder to a given Number Representation for REAL base 10 encoding
    # NR 1, 2 or 3 are possible
    # CER and DER require NR 3
    ENC_REALNR = 3
    ENC_REALNR1_SPA = 0 # heading spaces for NR1 encoding
    ENC_REALNR1_ZER = 0 # heading zero for NR1 encoding
    ENC_REALNR2_SPA = 0 # heading spaces for NR2 encoding
    ENC_REALNR2_ZER = 0 # heading zero for NR2 encoding
    ENC_REALNR2_ZERTRAIL = 0 # trailing zero for NR2 encoding
    # even if ASN.1 enables to play with NR3,
    # here NR3 cannot be tricked like NR1 and 2, 
    # so that it's the way to go for CER / DER
    
    # force the encoder to extend to a given length the encoding of unsigned 
    # integers within OBJECT IDENTIFIER and RELATIVE-OID
    ENC_OID_LEXT = 0
    # force the encoder to extend to a given length the encoding of unsigned 
    # integers for tag prefixes
    ENC_TAG_LEXT = 0
    
    # force the encoder to use the constructed form enabling the fragmentation
    # of the bit string / octet (or character) string 
    # every ENC_BSTR_FRAG / ENC_OSTR_FRAG bytes
    # ENC_[BO]STR_FRAG = 0 disables the fragmentation
    # DER requires ENC_[BO]STR_FRAG = 0
    # CER rquires ENC_[B0]STR_FRAG = 1000
    ENC_BSTR_FRAG = 0
    ENC_OSTR_FRAG = 0
    
    # force the encoder to produce canonical time representation
    ENC_TIME_CANON = False
    
    # force the encoder not to encode DEFAULT values within SEQUENCE / SET
    ENC_DEF_CANON = False
    
    # tag classes
    TagClassLUT = {0: TAG_UNIVERSAL,
                   1: TAG_APPLICATION,
                   2: TAG_CONTEXT_SPEC,
                   3: TAG_PRIVATE,
                   TAG_UNIVERSAL: 0,
                   TAG_APPLICATION: 1,
                   TAG_CONTEXT_SPEC: 2,
                   TAG_PRIVATE: 3}
    # tag prim / construct
    TagPCLUT    = {0: 'primitive', 1: 'constructed'}
    # universal tags
    TagUnivLUT = {
        0 : 'reserved for BER',
        1 : 'BOOLEAN',
        2 : 'INTEGER',
        3 : 'BIT STRING',
        4 : 'OCTET STRING',
        5 : 'NULL',
        6 : 'OBJECT IDENTIFIER',
        7 : 'ObjectDescriptor',
        8 : 'INSTANCE OF, EXTERNAL',
        9 : 'REAL',
        10: 'ENUMERATED',
        11:	'EMBEDDED PDV',
        12:	'UTF8String',
        13:	'RELATIVE-OID',
        16:	'SEQUENCE, SEQUENCE OF',
        17:	'SET, SET OF',
        18: 'NumericString',
        19: 'PrintableString',
        20:	'TeletexString, T61String',
        21:	'VideotexString',
        22:	'IA5String',
        23:	'UTCTime',
        24:	'GeneralizedTime',
        25:	'GraphicString',
        26:	'VisibleString, ISO646String',
        27:	'GeneralString',
        28:	'UniversalString',
        29:	'CHARACTER STRING',
        30:	'BMPString'}
    # length fmt
    LenFormLUT  = {0: 'short', 1: 'long'}
    
    
    @classmethod
    def decode_tlv_ws(cla, char):
        '''Generic BER decoder, works on whatever BER/CER/DER-encoded `char' input,
        without knowing the corresponding ASN.1 specification
        '''
        V = []
        Tag, tag_cl, tag_pc, tag_val = cla.decode_tag_ws(char)
        if tag_cl == 0 and tag_val in cla.TagUnivLUT:
            V = [ (0, tag_val, cla.TagUnivLUT[tag_val]) ]
        else:
            V = [ (tag_cl, tag_val) ]
        Len, l = cla.decode_len_ws(char)
        GEN = [Tag, Len]
        if tag_pc == 1:
            # constructed object encoding
            InGEN, InV = [], []
            if l == -1:
                # undefinite length
                while char._len_bit - char._cur >= 16:
                    _GEN, _V = cla.decode_tlv_ws(char)
                    InGEN.append(_GEN)
                    InV.append(_V)
                    if len(_V) == 1:
                        # only a (null) tag is provided
                        break
            else:
                # adjust the length of the char instance before re-entering
                char_lb = char._len_bit
                char._len_bit = char._cur + 8*l
                while char._len_bit - char._cur >= 16:
                    _GEN, _V = cla.decode_tlv_ws(char)
                    InGEN.append(_GEN)
                    InV.append(_V)
                # restore the original length of the char instance
                char._len_bit = char_lb
            GEN.append( Envelope('Val', GEN=tuple(InGEN)) )
            V.append(InV)
        else:
            # primitive object encoding
            if tag_cl == 0 and tag_val == 0 and l == 0:
                # special case to exit the decoding of undefinite length structure
                pass
            elif l == -1:
                raise(ASN1BERDecodeErr('unvalid length prefix'))
            else:
                # put a bytes buffer as a value
                buf = char.get_bytes(8*l)
                GEN.append( Buf('Val', val=buf, bl=8*l, rep=REPR_HEX) )
                V.append( buf )
        return Envelope('TLV', GEN=tuple(GEN)), V 
    
    @classmethod
    def decode_tlv(cla, char):
        '''Generic BER decoder, works on whatever BER/CER/DER-encoded `char' input,
        without knowing the corresponding ASN.1 specification
        '''
        V = []
        tag_cl, tag_pc, tag_val = cla.decode_tag(char)
        if tag_cl == 0 and tag_val in cla.TagUnivLUT:
            V.append( (0, tag_val, cla.TagUnivLUT[tag_val]) )
        else:
            V.append( (tag_cl, tag_val) )
        l = cla.decode_len(char)
        if tag_pc == 1:
            # constructed object encoding
            In = []
            if l == -1:
                # undefinite length
                while char._len_bit - char._cur >= 16:
                    In.append( cla.decode_tlv(char) )
                    if len(In[-1]) == 1:
                        # only a (null) tag and (null) length are provided
                        break
            else:
                # adjust the length of the char instance before re-entering
                char_lb = char._len_bit
                char._len_bit = char._cur + 8*l
                while char._len_bit - char._cur >= 16:
                    In.append( cla.decode_tlv(char) )
                # restore the original length of the char instance
                char._len_bit = char_lb
            V.append( In )
        else:
            # primitive object encoding
            if tag_cl == 0 and tag_val == 0 and l == 0:
                # special case to exit the decoding of undefinite length structure
                pass
            elif l == -1:
                raise(ASN1BERDecodeErr('unvalid length prefix'))
            else:
                # put a bytes buffer has a value
                V.append( char.get_bytes(8*l) )
        return V
    
    @classmethod
    def encode_tlv_ws(cla, tag_cl, tag_val, val, pc=None):
        '''Generic BER encoder, works on whatever BER/CER/DER-encoded tag / value input,
        without knowing the corresponding ASN.1 specification
        '''
        if isinstance(val, bytes_types):
            # primitive object encoding, unless pc is set
            tag_pc = 0 if pc is None else pc
            GEN = [cla.encode_tag_ws(tag_cl, tag_pc, tag_val)]
            if tag_pc == 1 and cla.ENC_LUNDEF:
                l = -1
                GEN.append( cla.encode_len_ws(l) )
                GEN.append( Buf('V', val=val, rep=REPR_HEX) )
                GEN.append( cla.encode_tag_ws(0, 0, 0) )
                GEN.append( cla.encode_len_ws(l) )
            else:
                l = len(val)
                GEN.append( cla.encode_len_ws(l) )
                #if l:
                #    GEN.append( Buf('V', val=val, bl=8*l, rep=REPR_HEX) )
                GEN.append( Buf('V', val=val, bl=8*l, rep=REPR_HEX) )
            return Envelope('TLV', GEN=tuple(GEN))
        elif isinstance(val, (tuple, list)):
            # constructed object encoding
            tag_pc = 1
            GEN = [cla.encode_tag_ws(tag_cl, tag_pc, tag_val)]
            # encode the value 1st to get its length in bytes
            In, undef, le = [], False, 0
            for v in val:
                if len(v) == 1:
                    # null tag, no value, end of undefinite length format
                    In.append( cla.encode_tlv_ws(v[0][0], v[0][1], b'') )
                    undef = True
                else:
                    if undef == True:
                        # that was not really an end of stream marker...
                        undef = False
                    In.append( cla.encode_tlv_ws(v[0][0], v[0][1], v[1]) )
                le += In[-1].get_len()
            if undef or cla.ENC_LUNDEF:
                # undefinite length
                GEN.append( cla.encode_len_ws(-1) )
            else:
                # defined length
                GEN.append( cla.encode_len_ws(le) )
            GEN.append( Envelope('V', GEN=tuple(In)) )
            return Envelope('TLV', GEN=tuple(GEN))
        else:
            raise(ASN1BEREncodeErr('invalid val type, {0!r}'.format(type(val))))
    
    @classmethod
    def encode_tlv(cla, tag_cl, tag_val, val, pc=None):
        '''Generic BER encoder, works on whatever BER/CER/DER-encoded tag / value input,
        without knowing the corresponding ASN.1 specification
        '''
        if isinstance(val, bytes_types):
            # primitive object encoding, unless pc is set
            tag_pc = 0 if pc is None else pc
            GEN = cla.encode_tag(tag_cl, tag_pc, tag_val)
            if tag_pc == 1 and cla.ENC_LUNDEF:
                l = -1
                GEN.extend( cla.encode_len(l) )
                GEN.append( (T_BYTES, val, 8*len(val)) )
                GEN.append( (T_BYTES, b'\0\0', 16) )
            else:
                l = len(val)
                GEN.extend( cla.encode_len(l) )
                if l:
                    GEN.append( (T_BYTES, val, 8*l) )
            return GEN
        elif isinstance(val, (tuple, list)):
            # constructed object encoding
            tag_pc = 1
            GEN = cla.encode_tag(tag_cl, tag_pc, tag_val)
            # encode the value 1st to get its length in bytes
            In, undef = [], False
            for v in val:
                if len(v) == 1:
                    # null tag, no value, end of undefinite length format
                    In.extend( cla.encode_tag(v[0][0], 0, v[0][1]) )
                    In.append( (T_UINT, 0, 8) )
                    undef = True
                else:
                    if undef == True:
                        # that was not really an end of stream marker...
                        undef = False
                    In.extend( cla.encode_tlv(v[0][0], v[0][1], v[1]) )
            if undef or cla.ENC_LUNDEF:
                # undefinite length
                GEN.extend( cla.encode_len(-1) )
            else:
                # `In' is a list of 3-tuples where the 3rd item is the length in bits
                GEN.extend( cla.encode_len(sum(map(lambda x:x[2], In)) >> 3) )
            GEN.extend(In)
            return GEN
        else:
            raise(ASN1BEREncodeErr('invalid val type, {0!r}'.format(type(val))))
    
    @classmethod
    def decode_tag_ws(cla, char):
        Tag = Envelope('T', GEN=(Uint('Class', bl=2, dic=cla.TagClassLUT),
                                 Uint('PC', bl=1, dic=cla.TagPCLUT),
                                 Uint('Val', bl=5)))
        Tag._from_char(char)
        v = Tag[2].get_val()
        if Tag[0]() == 0:
            Tag[2]._dic = cla.TagUnivLUT
        if v == 31:
            # extended tag value
            Tag[2]._name = 'Ext'
            Tag.append(Uint('E', val=char.get_uint(1), bl=1))
            Tag.append(Uint('Val7', val=char.get_uint(7), bl=7))
            d, v = 0, Tag[-1].get_val()
            while Tag[-2].get_val() == 1:
                Tag.append(Uint('E', val=char.get_uint(1), bl=1))
                Tag.append(Uint('Val7', val=char.get_uint(7), bl=7))
                d += 1
                v <<= 7
                v += Tag[-1].get_val()
                if d == cla.DEC_MAXT:
                    raise(ASN1BERDecodeErr('tag too long, more than {0!r} bytes'.format(d)))
        return Tag, Tag[0].get_val(), Tag[1].get_val(), v
    
    @classmethod
    def decode_tag(cla, char):
        # get tag class, Primitive/Constructed bit, value
        B = char.get_uint(8)
        cl, pc, val = B >> 6, (B >> 5) & 0x1, B & 0x1f
        if val == 31:
            # extended value for the tag: 
            # each byte, MSB is 1 if another byte is required, 
            # MSB is 0 for the last byte;
            # hence, the value is encoded with 7-bits chunks
            B = char.get_uint(8)
            cnt, more, val = 0, B >> 7, B & 0x7f
            while more:
                B = char.get_uint(8)
                more = B >> 7
                val <<= 7
                val += B & 0x7f
                cnt += 1
                if cnt == cla.DEC_MAXT:
                    raise(ASN1BERDecodeErr('tag too long, more than {0!r} bytes'.format(d)))
        return cl, pc, val    
    
    @classmethod
    def encode_tag_ws(cla, cl, pc, val):
        GEN = [Uint('Class', val=cl, bl=2, dic=cla.TagClassLUT),
               Uint('PC', val=pc, bl=1, dic=cla.TagPCLUT)]
        if val >= 31:
            # extended value for the tag
            GEN.append( Uint('Ext', val=31, bl=5) )
            fact = decompose_uint_sl(7, val)
            if cla.ENC_TAG_LEXT and len(fact) < cla.ENC_TAG_LEXT:
                fact.extend([0]*(cla.ENC_TAG_LEXT-len(fact)))
            fact.reverse()
            E = Uint('E', val=1, bl=1)
            [GEN.extend( (E, Uint('Val7', val=f, bl=7)) ) for f in fact[:-1]]
            GEN.extend( (Uint('E', val=0, bl=1), Uint('Val7', val=fact[-1], bl=7)) )
        else:
            GEN.append( Uint('Val', val=val, bl=5) )
            if cl == 0:
                GEN[-1]._dic = cla.TagUnivLUT
        return Envelope('T', GEN=tuple(GEN))
    
    @classmethod
    def encode_tag(cla, cl, pc, val):
        GEN = [(T_UINT, cl, 2), (T_UINT, pc, 1)]
        if val >= 31:
            # extended value for the tag
            GEN.append( (T_UINT, 31, 5) )
            fact = decompose_uint_sl(7, val)
            if cla.ENC_TAG_LEXT and len(fact) < cla.ENC_TAG_LEXT:
                fact.extend([0]*(cla.ENC_TAG_LEXT-len(fact)))
            fact.reverse()
            E = (T_UINT, 1, 1)
            [GEN.extend( (E, (T_UINT, f, 7)) ) for f in fact[:-1]]
            GEN.extend( ((T_UINT, 0, 1), (T_UINT, fact[-1], 7)) )
        else:
            GEN.append( (T_UINT, val, 5) )
        return GEN
    
    @classmethod
    def decode_len_ws(cla, char):
        Len = Envelope('L', GEN=(Uint('Form', bl=1, dic=cla.LenFormLUT),
                                 Uint('Val', bl=7)))
        Len._from_char(char)
        if Len[0].get_val() == 1:
            ll = Len[1].get_val()
            if ll == 0:
                # undefinite length format
                # shall only happen for constructed types
                return Len, -1
            elif ll > cla.DEC_MAXL:
                # unacceptably long format
                raise(ASN1BERDecodeErr('length prefix too long, {0!r} bytes'.format(ll)))
            else:
                # long format
                Len[1]._name = 'Len'
                V = Uint('Val', bl=8*Len[1].get_val())
                V._from_char(char)
                Len.append(V)
                return Len, V.get_val()
        else:
            # short format
            return Len, Len[1].get_val()
    
    @classmethod
    def decode_len(cla, char):
        B = char.get_uint(8)
        form = B >> 7
        if form:
            ll = B & 0x7f
            if not ll:
                # undefinite length format
                return -1
            elif ll > cla.DEC_MAXL:
                # unacceptably long format
                raise(ASN1BERDecodeErr('length prefix too long, {0!r} bytes'.format(ll)))
            else:
                # long format
                return char.get_uint(8*ll)
        else:
            return B & 0x7f
    
    @classmethod
    def encode_len_ws(cla, l):
        if l == -1:
            # undefinite length format
            return Envelope('L', GEN=(Uint('Form', val=1, bl=1, dic=cla.LenFormLUT),
                                        Uint('Val', val=0, bl=7)))
        elif cla.ENC_LLONG:
            # forcing long format
            # check the number of bytes required for l, and take the max
            ll = max(cla.ENC_LLONG, int(ceil(l.bit_length()/8.0)))
            return Envelope('L', GEN=(Uint('Form', val=1, bl=1, dic=cla.LenFormLUT),
                                        Uint('Len', val=ll, bl=7),
                                        Uint('Val', val=l, bl=8*ll)))
        elif l > 127:
            # minimum number of bytes long format
            ll = int(ceil(l.bit_length()/8.0))
            return Envelope('L', GEN=(Uint('Form', val=1, bl=1, dic=cla.LenFormLUT),
                                        Uint('Len', val=ll, bl=7),
                                        Uint('Val', val=l, bl=8*ll)))
        else:
            # short format
            return Envelope('L', GEN=(Uint('Form', val=0, bl=1, dic=cla.LenFormLUT),
                                        Uint('Val', val=l, bl=7)))
    
    @classmethod
    def encode_len(cla, l):
        if l == -1:
            # undefinite length format
            return [(T_UINT, 1, 1), (T_UINT, 0, 7)]
        elif cla.ENC_LLONG:
            # forcing long format
            # check the number of bytes required for l, and take the max
            ll = max(cla.ENC_LLONG, int(ceil(l.bit_length()/8.0)))
            return [(T_UINT, 1, 1), (T_UINT, ll, 7), (T_UINT, l, 8*ll)]
        elif l > 127:
            # minimum number of bytes long format
            ll = int(ceil(l.bit_length()/8.0))
            return [(T_UINT, 1, 1), (T_UINT, ll, 7), (T_UINT, l, 8*ll)]
        else:
            # short format
            return [(T_UINT, 0, 1), (T_UINT, l, 7)]
    
    @classmethod
    def decode_single_ws(cla, char, lundef=False):
        EOS = False
        # tag
        Tag, cl, pc, tval = cla.decode_tag_ws(char)
        # length
        Len, lval = cla.decode_len_ws(char)
        # keep track of the char cursor
        ccur = char._cur
        # value
        if pc == 1:
            # constructed (can have an undefinite length)
            if lval == -1:
                V = cla.decode_all_ws(char, lundef=True)
            else:
                char_lb = char._len_bit
                char._len_bit = char._cur + 8*lval
                V = cla.decode_all_ws(char, lundef=False)
                char._len_bit = char_lb
            TLV = [Tag, cl, pc, tval, Len, lval, V, ccur]
        else:
            # primitive
            if (cl, pc, tval, lval) == (0, 0, 0, 0):
                # EOC marker
                TLV = [Tag, cl, pc, tval, Len, lval, 0, ccur]
                if lundef:
                    EOS = True
            else:
                if lval < 0:
                    raise(ASN1BERDecodeErr('invalid undefinite length'))
                # keep track of the decoded tag and length, and the value boundary
                TLV = [Tag, cl, pc, tval, Len, lval, (char._cur, char._cur + 8*lval), ccur]
                char._cur += 8*lval
        return TLV, EOS
    
    @classmethod
    def decode_all_ws(cla, char, lundef=False):
        TLVs = []
        while char._len_bit - char._cur >= 16:
            TLV, EOS = cla.decode_single_ws(char, lundef)
            TLVs.append( TLV )
            if EOS:
                break
        return TLVs
    
    @classmethod
    def decode_single(cla, char, lundef=False):
        EOS = False
        # tag
        cl, pc, tval = cla.decode_tag(char)
        # length
        lval = cla.decode_len(char)
        # keep track of the char cursor
        ccur = char._cur
        # value
        if pc == 1:
            # constructed (can have an undefinite length)
            if lval == -1:
                V = cla.decode_all(char, lundef=True)
            else:
                char_lb = char._len_bit
                char._len_bit = char._cur + 8*lval
                V = cla.decode_all(char, lundef=False)
                char._len_bit = char_lb
            TLV = [cl, pc, tval, lval, V, ccur]
        else:
            # primitive
            if (cl, pc, tval, lval) == (0, 0, 0, 0):
                # EOC marker
                TLV = [cl, pc, tval, lval, 0, ccur]
                if lundef:
                    EOS = True
            else:
                if lval < 0:
                    raise(ASN1BERDecodeErr('invalid undefinite length'))
                # keep track of the decoded tag and length, and the value boundary
                TLV = [cl, pc, tval, lval, (char._cur, char._cur + 8*lval), ccur]
                # and jump over the value
                char._cur += 8*lval
        return TLV, EOS
    
    @classmethod
    def decode_all(cla, char, lundef=False):
        TLVs = []
        while char._len_bit - char._cur >= 16:
            TLV, EOS = cla.decode_single(char, lundef)
            TLVs.append(TLV)
            if EOS:
                break
        return TLVs
    
    @classmethod
    def scan_tlv_ws(cla, char, tlv):
        # we scan the 1st level TLV and returns a Python bytes buffer 
        # corresponding to it
        lval, char._cur = tlv[5], tlv[-1]
        if lval >= 0:
            # lval >= 0, just get the char cursor and extract the given buffer
            return char.get_bytes(8*lval)
        else:
            # lval == -1, need to scan up to an EOC marker
            # requires pc == 1
            if tlv[2] != 1:
                raise(ASN1BERDecodeErr('invalid primitive tag'))
            # tlv[6] is a list of tlv
            V = tlv[6]
            if not isinstance(V, list):
                raise(ASN1BERDecodeErr('invalid value type'))
            # the last component being an EOC, (cl, pc, tval) == (0, 0, 0)
            if V[-1][1:4] != [0, 0, 0]:
                raise(ASN1BERDecodeErr('missing EOC marker'))
            # get the buffer up to the end of this EOC - 16
            ecur = V[-1][-1] - 16
            return char.get_bytes(ecur - char._cur)
            
    @classmethod
    def scan_tlv(cla, char, tlv):
        # we scan the 1st level TLV and returns a Python bytes buffer 
        # corresponding to it
        lval, char._cur = tlv[3], tlv[-1]
        if lval >= 0:
            # lval >= 0, just get the char cursor and extract the given buffer
            return char.get_bytes(8*lval)
        else:
            # lval == -1, need to scan up to an EOC marker
            # requires pc == 1
            if tlv[2] != 1:
                raise(ASN1BERDecodeErr('invalid primitive tag'))
            # tlv[6] is a list of tlv
            V = tlv[4]
            if not isinstance(V, list):
                raise(ASN1BERDecodeErr('invalid value type'))
            # the last component being an EOC, (cl, pc, tval, lval) == (0, 0, 0, 0)
            if V[-1][0:4] != [0, 0, 0, 0]:
                raise(ASN1BERDecodeErr('missing EOC marker'))
            # get the buffer up to the end of this EOC - 16
            ecur = V[-1][-1] - 16
            return char.get_bytes(ecur - char._cur)


class ASN1CodecCER(ASN1CodecBER):
    pass


class ASN1CodecDER(ASN1CodecBER):
    pass


class ASN1CodecGSER(ASN1Codec):
    # TODO: implement this
    pass


class ASN1CodecOER(ASN1Codec):

    # canonicity is used to decide whether to encode default values or not in
    # constructed object
    CANONICAL = True

    TRUE = 0xFF
    FALSE = 0x00

    LenFormLUT = {0: 'short', 1: 'long'}
    REAL_IEEE754_32_MANTIS_MIN = -2 ** 24 + 1
    REAL_IEEE754_32_MANTIS_MAX = 2 ** 24 - 1
    REAL_IEEE754_64_MANTIS_MIN = -2 ** 53 - 1
    REAL_IEEE754_64_MANTIS_MAX = 2 ** 53 - 1
    REAL_IEEE754_32_EXP_MIN = -126
    REAL_IEEE754_32_EXP_MAX = 127
    REAL_IEEE754_64_EXP_MIN = -1022
    REAL_IEEE754_64_EXP_MAX = 1023

    # tag classes
    TagClassLUT = {0b00: TAG_UNIVERSAL,
                   0b01: TAG_APPLICATION,
                   0b10: TAG_CONTEXT_SPEC,
                   0b11: TAG_PRIVATE,
                   TAG_UNIVERSAL: 0b00,
                   TAG_APPLICATION: 0b01,
                   TAG_CONTEXT_SPEC: 0b10,
                   TAG_PRIVATE: 0b11}

    GET_DEFVAL = True

    @classmethod
    def encode_tag(cls, tag, tag_class=TAG_CONTEXT_SPEC):
        try:
            tag_enc = [(T_UINT, cls.TagClassLUT[tag_class], 2)]
        except KeyError:
            ASN1OEREncodeErr("Unknown tag class: {0}".format(tag_class))

        if tag < 63:
            # Tag encoded in 6b:
            tag_enc.append((T_UINT, tag, 6))
        else:
            # Multi-octet tag encoding
            tag_enc.append((T_UINT, 0b111111, 6))  # Initial octet
            tag_temp = []
            # Last byte (going in reverse)
            tag_temp.append((T_UINT, tag & 0b1111111, 7))
            tag_temp.append((T_UINT, 0, 1))
            tag = tag >> 7

            # All the other bytes
            while tag.bit_length() > 0:
                tag_temp.append((T_UINT, tag & 0b1111111, 7))
                tag_temp.append((T_UINT, 1, 1))
                tag = tag >> 7

            tag_enc.extend(tag_temp[::-1])

        return tag_enc

    @classmethod
    def encode_tag_ws(cls, tag, tag_class=TAG_CONTEXT_SPEC):
        try:
            tag_enc = [Uint('Class', val=cls.TagClassLUT[tag_class], bl=2)]
        except KeyError:
            ASN1OEREncodeErr("Unknown tag class: {0}".format(tag_class))

        if tag < 63:
            # Tag encoded in 6b:
            tag_enc.append(Uint('Val', val=tag, bl=6))
        else:
            # Multi-octet tag encoding
            tag_enc.append(Uint('Multi-octet', val=0b111111, bl=6))  # Initial octet
            tag_temp = []
            # Last byte (going in reverse)
            tag_temp.append(Uint('Val', val=tag & 0b1111111, bl=7))
            tag_temp.append(Uint('Cont',val=0, bl=1))
            tag = tag >> 7

            # All the other bytes
            while tag.bit_length() > 0:
                tag_temp.append(Uint('Val', val=tag & 0b1111111, bl=7))
                tag_temp.append(Uint('Cont', val=1, bl=1))
                tag = tag >> 7

            tag_enc.extend(tag_temp[::-1])

        return Envelope('T', GEN=tuple(tag_enc))

    @classmethod
    def decode_tag(cls, char):
        tag_class = char.get_uint(2)
        try:
            tag_class = cls.TagClassLUT[tag_class]
        except KeyError:
            ASN1OEREncodeErr("Unknown tag class: {0}".format(tag_class))

        first_octet = char.get_uint(6)
        if first_octet < 63:
            # Tag encoded in 6b:
            tag_val = first_octet
        else:
            # Multi-octet tag encoding
            tag_val = []
            while True:
                val_cont = char.get_uint(1)
                tag_val.extend(char.get_bitlist(7))
                if not val_cont:
                    break

            tag_val = bitlist_to_uint(tag_val)

        return tag_class, tag_val

    @classmethod
    def decode_tag_ws(cls, char):
        tag_class = Uint('Class', bl=2)
        tag_class._from_char(char)
        try:
            tag_class_val = cls.TagClassLUT[tag_class.get_val()]
        except KeyError:
            ASN1OEREncodeErr("Unknown tag class: {0}".format(tag_class.get_val()))

        tag_struct = [tag_class]

        first_val = Uint('Val', bl=6)
        first_val._from_char(char)
        tag_struct.append(first_val)

        if first_val.get_val() < 63:
            # Tag encoded in 6b:
            tag_val = first_val.get_val()
        else:
            first_val._name = 'Multi-octet'
            tag_val = 0
            while True:
                tmp_cont = Uint('Cont', bl=1)
                tmp_cont._from_char(char)
                tmp_val = Uint('Val', bl=7)
                tmp_val._from_char(char)

                tag_val = tag_val << 7
                tag_val = tag_val | tmp_val.get_val()
                tag_struct.append(tmp_cont)
                tag_struct.append(tmp_val)

                if not tmp_cont.get_val():
                    break

        return tag_class_val, tag_val, Envelope('T', GEN=tuple(tag_struct))

    @classmethod
    def encode_length_determinant(cls, length):
        # Always canonical (implementing non-canonical doesn't make sense)
        determinant = []
        if length > 127:
            # long determinant
            dl = uint_bytelen(length)
            determinant.extend([(T_UINT, 1, 1),
                                (T_UINT, dl, 7),
                                (T_UINT, length, dl*8)
                                ])
        else:
            # short determinant
            determinant.append((T_UINT, length, 8))

        return determinant

    @classmethod
    def encode_length_determinant_ws(cls, length):
        # Always canonical (implementing non-canonical doesn't make sense)
        if length > 127:
            # long determinant
            dl = uint_bytelen(length)
            determinant = (
                Uint('Form', val=1, bl=1, dic=cls.LenFormLUT),
                Uint('Len', val=dl, bl=7),
                Uint('Val', val=length, bl=dl*8)
            )
        else:
            # short determinant
            determinant = (
                Uint('Form', val=0, bl=1, dic=cls.LenFormLUT),
                Uint('Val', val=length, bl=7)
            )

        return Envelope('L', GEN=determinant)

    @classmethod
    def decode_length_determinant(cls, char):
        long_form = char.get_uint(1)
        length = char.get_uint(7)
        if long_form:
            length = char.get_uint(length*8)
        return length

    @classmethod
    def decode_length_determinant_ws(cls, char):
        length = Envelope('L', GEN=(
            Uint('Form', bl=1, dic=cls.LenFormLUT),
            Uint('Val', bl=7)
        ))
        length._from_char(char)
        long_form = length[0].get_val()
        ll = length[1].get_val()
        if long_form:
            length[1]._name = "Len"
            val = Uint('Val', bl=8*ll)
            val._from_char(char)
            ll = val.get_val()
            length.append(val)
        return ll, length

    @classmethod
    def encode_intunconst(cls, val, signed=True):
        if val < 0:
            signed = True
        vl = int_bytelen(val) if signed else uint_bytelen(val)
        GEN = cls.encode_length_determinant(vl)
        vt = T_INT if signed else T_UINT
        GEN.append((vt, val, vl * 8))
        return GEN

    @classmethod
    def encode_intunconst_ws(cls, val, signed=True):
        if val < 0:
            signed = True
        vl = int_bytelen(val) if signed else uint_bytelen(val)
        GEN = cls.encode_length_determinant_ws(vl)
        vt = Int if signed else Uint
        GEN.append(vt('V', val=val, bl=vl*8))
        return (GEN,)

    @classmethod
    def decode_intunconst(cls, char, signed=True):
        vl = cls.decode_length_determinant(char)
        if signed:
            return char.get_int(vl*8)
        else:
            return char.get_uint(vl*8)

    @classmethod
    def decode_intunconst_ws(cls, char, signed=True):
        vl, det_st = cls.decode_length_determinant_ws(char)
        vt = Int if signed else Uint
        val = vt('V', bl=vl * 8)
        val._from_char(char)
        return val.get_val(), (det_st, val)

    @classmethod
    def encode_intconst(cls, val, const_val):
        if const_val.lb is not None:
            if const_val.lb >= 0:
                # 10.3 a ~ d Check on the upper bound
                if const_val.ub is not None:
                    ubl = round_p2(uint_bytelen(const_val.ub))
                    if ubl <= 8:
                        return [(T_UINT, val, ubl*8)]
                # No other conditions are fulfilled
                return cls.encode_intunconst(val, signed=False)
            else:
                # 10.4 a ~ d
                if const_val.ub is not None:
                    dbl = round_p2(max(int_bytelen(const_val.lb),
                                       int_bytelen(const_val.ub)))
                    if dbl <= 8:
                        return [(T_INT, val, dbl*8)]
                # No upper bound etc.
                return cls.encode_intunconst(val)
        else:
            # No lower bound -> encode with length determinant
            return cls.encode_intunconst(val)

    @classmethod
    def encode_intconst_ws(cls, val, const_val):
        if const_val.lb is not None:
            if const_val.lb >= 0:
                # 10.3 a ~ d Check on the upper bound
                if const_val.ub is not None:
                    ubl = round_p2(uint_bytelen(const_val.ub))
                    if ubl <= 8:
                        return (Uint('V', val=val, bl=ubl*8),)
                # No other conditions are fulfilled
                return cls.encode_intunconst_ws(val, signed=False)
            else:
                # 10.4 a ~ d
                if const_val.ub is not None:
                    dbl = round_p2(max(int_bytelen(const_val.lb),
                                       int_bytelen(const_val.ub)))
                    if dbl <= 8:
                        return (Int('V', val=val, bl=dbl*8),)
                # No upper bound etc.
                return cls.encode_intunconst_ws(val)
        else:
            # No lower bound -> encode with length determinant
            return cls.encode_intunconst_ws(val)

    @classmethod
    def decode_intconst(cls, char, const_val):
        if const_val.lb is not None:
            if const_val.lb >= 0:
                # 10.3 a ~ d Check on the upper bound
                if const_val.ub is not None:
                    ubl = round_p2(uint_bytelen(const_val.ub))
                    if ubl <= 8:
                        return char.get_uint(ubl*8)
                # No other conditions are fulfilled
                return cls.decode_intunconst(char, signed=False)
            else:
                # 10.4 a ~ d
                if const_val.ub is not None:
                    dbl = round_p2(max(int_bytelen(const_val.lb),
                                       int_bytelen(const_val.ub)))
                    if dbl <= 8:
                        return char.get_int(dbl*8)
                # No upper bound etc.
                return cls.decode_intunconst(char)
        else:
            # No lower bound -> encode with length determinant
            return cls.decode_intunconst(char)

    @classmethod
    def decode_intconst_ws(cls, char, const_val):
        if const_val.lb is not None:
            if const_val.lb >= 0:
                # 10.3 a ~ d Check on the upper bound
                if const_val.ub is not None:
                    ubl = round_p2(uint_bytelen(const_val.ub))
                    if ubl <= 8:
                        val = Uint('V', bl=ubl*8)
                        val._from_char(char)
                        return val.get_val(), (val,)
                # No other conditions are fulfilled
                return cls.decode_intunconst_ws(char, signed=False)
            else:
                # 10.4 a ~ d
                if const_val.ub is not None:
                    dbl = round_p2(max(int_bytelen(const_val.lb),
                                       int_bytelen(const_val.ub)))
                    if dbl <= 8:
                        val = Int('V', bl=dbl*8)
                        val._from_char(char)
                        return val.get_val(), (val,)
                # No upper bound etc.
                return cls.decode_intunconst_ws(char)
        else:
            # No lower bound -> encode with length determinant
            return cls.decode_intunconst_ws(char)

    @classmethod
    def encode_enumerated(cls, val):
        # Always canonical (implementing non-canonical doesn't make sense)
        _gen = []
        if 0 <= val <= 127:
            # short form
            _gen.append((T_UINT, val, 8))
        else:
            # long form
            dl = int_bytelen(val)
            _gen.extend([(T_UINT, 1, 1),
                         (T_UINT, dl, 7),
                         (T_INT, val, dl * 8)
                         ])

        return _gen

    @classmethod
    def encode_enumerated_ws(cls, val):
        if 0 <= val <= 127:
            # short form
            _gen = (
                Uint('Form', val=0, bl=1, dic=cls.LenFormLUT),
                Uint('Val', val=val, bl=7)
            )
        else:
            # long form
            dl = int_bytelen(val)
            _gen = (
                Uint('Form', val=1, bl=1, dic=cls.LenFormLUT),
                Uint('Len', val=dl, bl=7),
                Int('Val', val=val, bl=dl*8)
            )

        return Envelope('L', GEN=_gen)

    @classmethod
    def decode_enumerated(cls, char):
        long_form = char.get_uint(1)
        val = char.get_uint(7)
        if long_form:
            val = char.get_int(val*8)
        return val

    @classmethod
    def decode_enumerated_ws(cls, char):
        t_enum = Envelope('L', GEN=(
            Uint('Form', bl=1, dic=cls.LenFormLUT),
            Uint('Val', bl=7)
        ))
        t_enum._from_char(char)
        long_form = t_enum[0].get_val()
        enum_val = t_enum[1].get_val()
        if long_form:
            t_enum[1]._name = "Len"
            val = Int('Val', bl=8*enum_val)
            val._from_char(char)
            enum_val = val.get_val()
            t_enum.append(val)
        return enum_val, t_enum

    @classmethod
    def encode_open_type(cls, value_bytes):
        # The standard is quite unclear to me about this. But tested on CHOICE
        # with extension type using ASN1 Playground, it seems it is the correct
        # implementation.
        l_val = len(value_bytes)
        tmp = (cls.encode_length_determinant(l_val))
        tmp.append((T_BYTES, value_bytes, l_val*8))
        return tmp

    @classmethod
    def encode_open_type_ws(cls, value_bytes):
        l_val = len(value_bytes)
        _gen = [cls.encode_length_determinant_ws(l_val)]
        _gen.append(Buf('V', val=value_bytes, bl=l_val*8))
        return Envelope("Open-Type", GEN=tuple(_gen))

    @classmethod
    def decode_open_type(cls, char):
        l_val = cls.decode_length_determinant(char)
        val_bytes = char.get_bytes(l_val * 8)
        return val_bytes

    @classmethod
    def decode_open_type_ws(cls, char):
        l_val, l_struct = cls.decode_length_determinant_ws(char)
        _gen = [l_struct]
        val_struct = Buf('V', bl=l_val*8)
        val_struct._from_char(char)
        _gen.append(val_struct)
        val_bytes = val_struct.get_val()
        return val_bytes, Envelope("Open-Type", GEN=tuple(_gen))

