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
# * File Name : pycrate_asn1rt/asnobj_ext.py
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
from .codecs  import *
from .codecs  import _with_json
from .asnobj_basic     import *
from .asnobj_str       import *
from .asnobj_construct import *
from .asnobj_construct import _CONSTRUCT


_ASN1ObjBasicLUT = {
    TYPE_NULL       : NULL,
    TYPE_BOOL       : BOOL,
    TYPE_INT        : INT,
    TYPE_REAL       : REAL,
    TYPE_ENUM       : ENUM,
    TYPE_BIT_STR    : BIT_STR,
    TYPE_OCT_STR    : OCT_STR,
    TYPE_OID        : OID,
    TYPE_REL_OID    : REL_OID,
    TYPE_STR_IA5    : STR_IA5,
    TYPE_STR_PRINT  : STR_PRINT,
    TYPE_STR_NUM    : STR_NUM,
    TYPE_STR_VIS    : STR_VIS,
    TYPE_STR_BMP    : STR_BMP,
    TYPE_STR_UTF8   : STR_UTF8,
    TYPE_STR_ISO646 : STR_ISO646,
    TYPE_STR_TELE   : STR_TELE,
    TYPE_STR_VID    : STR_VID,
    TYPE_STR_GRAPH  : STR_GRAPH,
    TYPE_STR_T61    : STR_T61,
    TYPE_STR_GENE   : STR_GENE,
    TYPE_STR_UNIV   : STR_UNIV,
    TYPE_OBJ_DESC   : OBJ_DESC,
    TYPE_TIME_GEN   : TIME_GEN,
    TYPE_TIME_UTC   : TIME_UTC
    }


class OPEN(ASN1Obj):
    __doc__ = """
ASN.1 open type object,
corresponds to reference to a CLASS field which has no defined type

This is in general associated with a table constraint which can be looked-up
to provide a defined type according to the encoding / decoding context

Single value: Python 2-tuple
    the 1st item corresponds to a reference to another ASN.1 object, it can be:
        - a str starting with '_unk_$ind' for unknown content, the 2nd item will then be some bytes
          $ind is a list of digits, used as a dummy index
        - a str corresponding to an ASN.1 native basic type (TYPE_*, but not constructed one) or 
          a typeref taken from the constraint of self
        - a 2-tuple (module_name, object_name) corresponding to any user-defined ASN.1 object
        - an ASN1Obj instance
    and the 2nd item corresponds to a single value compliant to the object 
    referenced in the 1st item

%s
""" % ASN1Obj_docstring

    TYPE  = TYPE_OPEN
    TAG   = None
    
    # this enables object's table constraint lookup for OPEN types when decoding it
    _TAB_LUT = True
    
    _ASN_RE = re.compile('(?:\'([\s01]{0,})\'B)|(?:\'([\s0-9A-F]{0,})\'H)')
    
    def _get_val_obj(self, ref):
        const_tr = self._get_const_tr()
        if isinstance(ref, str_types):
            if ref in const_tr:
                return const_tr[ref]
            elif ref in _ASN1ObjBasicLUT:
                return _ASN1ObjBasicLUT[ref]()
            else:
                raise(ASN1ObjErr('{0}: invalid object reference, {1!r}'\
                      .format(self.fullname(), ref)))
        elif isinstance(ref, (tuple, list)):
            if ref in const_tr:
                return const_tr[ref]
            else:
                try:
                    return GLOBAL.MOD[ref[0]][ref[1]]
                except Exception:
                    raise(ASN1ObjErr('{0}: invalid object reference, {1!r}'\
                          .format(self.fullname(), ref)))
        else:
            raise(ASN1ObjErr('{0}: invalid object reference, {1!r}'\
                  .format(self.fullname(), ref)))
    
    def _get_const_tr(self):
        if hasattr(self, '__const_tr__'):
            return self.__const_tr__
        else:
            const_tr = {}
            if self._const_val:
                # collect all types in the constraint value
                for C in self._const_val.root:
                    if C._typeref is not None:
                        # put both complete module ref, and obj-only ref
                        const_tr[C._typeref.called] = C
                        const_tr[C._typeref.called[1]] = C
                    else:
                        const_tr[C.TYPE] = C
                if self._const_val.ext:
                    for C in self._const_val.ext:
                        if C._typeref is not None:
                            const_tr[C._typeref.calld] = C
                            const_tr[C._typeref.called[1]] = C
                        else:
                            const_tr[C.TYPE] = C
            if self._TAB_LUT and self._const_tab and self._const_tab_at:
                # collect all types from the table constraint
                assert( hasattr(self, '_const_tab_id') )
                for O in self._const_tab(self._const_tab_id)[::-1]:
                    if O._typeref is not None:
                        # put both complete module ref, and obj-only ref
                        const_tr[O._typeref.called] = O
                        const_tr[O._typeref.called[1]] = O
                    else:
                        const_tr[O.TYPE] = O
            self.__const_tr__ = const_tr
            return const_tr
    
    def _safechk_val(self, val):
        if isinstance(val, tuple) and len(val) == 2:
            if isinstance(val[0], ASN1Obj):
                val[0]._safechk_val(val[1])
            elif isinstance(val[0], str_types):
                if re.match('_unk_[0-9]{1,}', val[0]):
                    if not isinstance(val[1], bytes_types):
                        raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
                else:
                    self._get_val_obj(val[0])._safechk_val(val[1])
            elif isinstance(val[0], tuple) and len(val[0]) == 2:
                self._get_val_obj(val[0])._safechk_val(val[1])
            else:
                raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
        else:
            raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
    
    def _safechk_bnd(self, val):
        if isinstance(val[0], ASN1Obj):
            val[0]._safechk_bnd(val[1])
        elif val[0][:5] != '_unk_':
            self._get_val_obj(val[0])._safechk_bnd(val[1])
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        m = self._ASN_RE.match(txt)
        if m:
            grp = m.groups()
            if hasattr(self, '_val_tag'):
                ident = '_unk_%i%i%i' % self._val_tag
            else:
                ident = '_unk_004'
            if grp[0] is not None:
                # BSTRING
                bs = re.subn('\s{1,}', '', grp[0])[0]
                self._val = (ident, uint_to_bytes(int(bs, 2), len(bs)))
            else:
                # HSTRING
                hs = re.subn('\s{1,}', '', grp[1])[0]
                if len(hs)%2:
                    self._val = (ident, unhexlify(hs + '0'))
                else:
                    self._val = (ident, unhexlify(hs))
            return txt[m.end():].strip()
        else:
            # we must pick-up a type from a defined constraint
            # TODO: must implement the Module.value notation to compare to tuples
            # into const_tr, in addition to simple object name
            const_tr_keys = [name for name in self._get_const_tr() if isinstance(name, str_types)]
            m = re.match('\s{0,}:|'.join(const_tr_keys) + '\s{0,}:', txt)
            if m is not None:
                ident = m.group().split(':')[0].strip()
                txt = txt[m.end():].strip()
                Obj = self._get_const_tr()[ident]
                txt = Obj._from_asn1(txt)
                if Obj._typeref is not None:
                    self._val = (Obj._typeref.called[1], Obj._val)
                else:
                    self._val = (Obj.TYPE, Obj._val)
                return txt
            else:
                ASN1NotSuppErr('{0}: reference parsing unsupported'.format(self.fullname()))
    
    def _to_asn1(self):
        if isinstance(self._val[0], str_types):
            if self._val[0][:5] == '_unk_':
                # HSTRING
                if python_version >= 3:
                    return '\'%s\'H' % hexlify(self._val[1]).decode('ascii').upper()
                else:
                    return '\'%s\'H' % hexlify(self._val[1]).upper()
            else:
                ident = self._val[0]
                Obj   = self._get_val_obj(self._val[0])
        elif isinstance(self._val[0], tuple):
            ident = '.'.join(self._val[0])
            Obj   = self._get_val_obj(self._val[0])
        else:
            # self._val[0] is an ASN1Obj instance
            ident = '%s.%s' % (self._val[0]._mod, self._val[0]._name)
            Obj   = self._val[0]
        Obj._val = self._val[1]
        return '%s: %s' % (ident, Obj.to_asn1())
    
    ###
    # conversion between internal value and ASN.1 PER encoding
    ###
    
    def _from_per_ws(self, char):
        # try to get a defined object from a table constraint
        if self._TAB_LUT and self._const_tab and self._const_tab_at:
            const_obj_type, const_obj = self._get_tab_obj()
            if const_obj_type == CLASET_NONE:
                if not self._SILENT:
                    asnlog('OPEN._from_per_ws: %s, unable to retrieve a table-looked up object'\
                           % (self.fullname()))
                Obj = None
            elif const_obj_type == CLASET_UNIQ:
                Obj = const_obj
            else:
                # const_obj_type == CLASET_MULT
                # with PER, no tag to select a given object
                Obj = const_obj[0]
        else:
            # TODO: another way to provide a (set of) potential defined object(s)
            # is to look into value constraint self._const_val
            # if we have multiple, then we would have to bruteforce the decoding 
            # until a correct one is found !!!
            Obj = None
        #
        if Obj is None:
            if self._const_val:
                asnlog('OPEN._from_per_ws: %s, potential type constraint(s) available but unused'\
                       % self.fullname())
            val, GEN = ASN1CodecPER.decode_unconst_open_ws(char, wrapped=None)
            assert( isinstance(val, bytes_types) )
            self._val = ('_unk_004', val)
        else:
            if Obj._typeref is not None:
                val, GEN = ASN1CodecPER.decode_unconst_open_ws(char, wrapped=Obj._tr)
                self._val = (Obj._typeref.called[1], val)
            else:
                val, GEN = ASN1CodecPER.decode_unconst_open_ws(char, wrapped=Obj)
                self._val = (Obj.TYPE, val)
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return
    
    def _from_per(self, char):
        # try to get a defined object from a table constraint
        if self._TAB_LUT and self._const_tab and self._const_tab_at:
            const_obj_type, const_obj = self._get_tab_obj()
            if const_obj_type == CLASET_NONE:
                if not self._SILENT:
                    asnlog('OPEN._from_per: %s, unable to retrieve a table-looked up object'\
                           % (self.fullname()))
                Obj = None
            elif const_obj_type == CLASET_UNIQ:
                Obj = const_obj
            else:
                # const_obj_type == CLASET_MULT
                # with PER, no tag to select a given object
                Obj = const_obj[0]
        else:
            # TODO: another way to provide a (set of) potential defined object(s)
            # is to look into value constraint self._const_val
            # if we have multiple, then we would have to bruteforce the decoding
            # until a correct one is found !!!
            Obj = None
        #
        val = ASN1CodecPER.decode_unconst_open(char, wrapped=Obj)
        if Obj is None:
            if self._const_val:
                asnlog('OPEN._from_per: %s, potential type constraint(s) available but unused'\
                       % self.fullname())
            assert( isinstance(val, bytes_types) )
            self._val = ('_unk_004', val)
        else:
            if Obj._typeref is not None:
                self._val = (Obj._typeref.called[1], val)
            else:
                self._val = (Obj.TYPE, val)
        return
    
    def _to_per_ws(self):
        if isinstance(self._val[0], ASN1Obj):
            Obj = self._val[0]
        else:
            # isinstance(self._val[0], str_types)
            if self._val[0][:5] == '_unk_':
                GEN = ASN1CodecPER.encode_unconst_buf_ws(self._val[1])
                self._struct = Envelope(self._name, GEN=tuple(GEN))
                return self._struct
            Obj = self._get_val_obj(self._val[0])
        Obj._val = self._val[1]
        GEN = ASN1CodecPER.encode_unconst_open_ws(Obj)
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return self._struct
    
    def _to_per(self):
        if isinstance(self._val[0], ASN1Obj):
            Obj = self._val[0]
        else:
            # isinstance(self._val[0], str_types)
            if self._val[0][:5] == '_unk_':
                return ASN1CodecPER.encode_unconst_buf(self._val[1])
            Obj = self._get_val_obj(self._val[0])
        Obj._val = self._val[1]
        ret = ASN1CodecPER.encode_unconst_open(Obj)
        return ret
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_ber_cont_ws(self, char, tlv):
        # tlv: list of list of tag, length and value corresponding to the CHOICE
        if not isinstance(tlv, list):
            raise(ASN1BERDecodeErr('{0}: invalid OPEN / ANY primitive structure'\
                  .format(self.fullname())))
        # select the inner encoding
        tlv = tlv[0]
        Tag, cl, pc, tval, Len, lval = tlv[0:6]
        tag, Objs, obj_mult = (cl, tval), [], False
        # try to get a defined object from a table constraint
        if self._TAB_LUT and self._const_tab and self._const_tab_at:
            const_obj_type, const_obj = self._get_tab_obj()
            if const_obj_type == CLASET_NONE:
                if not self._SILENT:
                    asnlog('OPEN._decode_ber_cont_ws: %s, unable to retrieve a table-looked up object'\
                           % self.fullname())
            elif const_obj_type == CLASET_UNIQ:
                Objs = [const_obj]
            else:
                # const_obj_type == CLASET_MULT
                obj_mult = True
                Objs = get_obj_by_tag(self, tag, const_obj)
        #
        elif self._const_val is not None:
            # another way to provide a (set of) potential defined object(s)
            # is to look into value constraint self._const_val
            # we must select the right one according to the decoded tag
            Objs = get_obj_by_tag(self, tag)
        #
        elif hasattr(self, '_defby') and self._defby is not None:
            # TODO: 3rd way to specify the potential defined object
            # is to use a DEFINED BY specification (this is old-school)
            if not self._SILENT:
                asnlog('OPEN._decode_ber_cont_ws: %s, DEFINED BY lookup not supported' % self.fullname())
        #
        decoded = False
        if Objs:
            # we found at least one (or more) defined object
            char_cur, char_lb = char._cur, char._len_bit
            for Obj in Objs:
                try:
                    Obj._from_ber_ws(char, [tlv])
                except Exception:
                    # decoding failed
                    char._cur, char._len_bit = char_cur, char_lb
                else:
                    # set value
                    if Obj._typeref is not None:
                        if obj_mult:
                            self._val = (Obj._typeref.called, Obj._val)
                        else:
                            self._val = (Obj._typeref.called[1], Obj._val)
                    else:
                        self._val = (Obj.TYPE, Obj._val)
                    V = Obj._struct
                    decoded = True
                    break
            if not decoded and not self._SILENT:
                asnlog('OPEN._decode_ber_cont_ws: %s, decoding failed for all possible objects'\
                       % self.fullname())
        #
        if not decoded:
            # we did not find a defined object, or failed to decode it
            # hence we decode this as a simple buffer
            # with BER, we need to absolutely keep track of the decoded tag if
            # we want to be able to re-encode it
            if pc == 1:
                # constructed object
                #
                # char._cur will be updated in scan_tlv()
                # but we also need to extend char._len_bit according to tlv in some way...
                # however, the content is constructed and we don't have straight boundaries
                # as for the primitive case below, hence we extend the char buffer to its 
                # maximum
                char._len_bit = 8*len(char._buf)
                val = ASN1CodecBER.scan_tlv_ws(char, tlv)
                self._val_tag = (cl, pc, tval)
                ident = '_unk_%i%i%i' % self._val_tag
                self._val = (ident, val)
                V = Envelope('V', GEN=(Tag, Len, Buf(ident, val=val, bl=8*len(val), rep=REPR_HEX)))
            elif lval >= 0:
                # primitive object
                char._cur, char._len_bit = tlv[6][0], tlv[6][1]
                Val = Buf('_buf_', bl=8*lval, rep=REPR_HEX)
                Val._from_char(char)
                self._val_tag = (cl, pc, tval)
                self._val = ('_unk_%i%i%i' % self._val_tag, Val.to_bytes())
                V = Envelope('V', GEN=(Tag, Len, Val))
            else:
                raise(ASN1BERDecodeErr('{0}: invalid OPEN / ANY tag and length, {1!r}, {2!r}'\
                      .format(self.fullname(), (cl, pc, tval), lval)))
        #
        return V
    
    def _decode_ber_cont(self, char, tlv):
        # tlv: list of list of tag, length and value corresponding to the CHOICE
        if not isinstance(tlv, list):
            raise(ASN1BERDecodeErr('{0}: invalid OPEN / ANY primitive structure'\
                  .format(self.fullname())))
        # select the inner encoding
        tlv = tlv[0]
        cl, pc, tval, lval = tlv[0:4]
        tag, Objs, obj_mult = (cl, tval), [], False
        # try to get a defined object from a table constraint
        if self._TAB_LUT and self._const_tab and self._const_tab_at:
            const_obj_type, const_obj = self._get_tab_obj()
            if const_obj_type == CLASET_NONE:
                if not self._SILENT:
                    asnlog('OPEN._decode_ber_cont: %s, unable to retrieve a table-looked up object'\
                           % self.fullname())
            elif const_obj_type == CLASET_UNIQ:
                Objs = [const_obj]
            else:
                # const_obj_type == CLASET_MULT
                obj_mult = True
                Objs = get_obj_by_tag(self, tag, const_obj)
        #
        elif self._const_val is not None:
            # another way to provide a (set of) potential defined object(s)
            # is to look into value constraint self._const_val
            # we must select the right one according to the decoded tag
            Objs = get_obj_by_tag(self, tag)
        #
        elif hasattr(self, '_defby') and self._defby is not None:
            # TODO: 3rd way to specify the potential defined object
            # is to use a DEFINED BY specification (this is old-school)
            if not self._SILENT:
                asnlog('OPEN._decode_ber_cont: %s, DEFINED BY lookup not supported' % self.fullname())
        #
        decoded = False
        if Objs:
            # we found at least one (or more) defined object
            char_cur, char_lb = char._cur, char._len_bit
            for Obj in Objs:
                try:
                    Obj._from_ber(char, [tlv])
                except Exception:
                    char._cur, char._len_bit = char_cur, char_lb
                else:
                    # set value
                    if Obj._typeref is not None:
                        if obj_mult:
                            self._val = (Obj._typeref.called, Obj._val)
                        else:
                            self._val = (Obj._typeref.called[1], Obj._val)
                    else:
                        self._val = (Obj.TYPE, Obj._val)
                    decoded = True
                    break
            if not decoded and not self._SILENT:
                asnlog('OPEN._decode_ber_cont: %s, decoding failed for all possible objects'\
                       % self.fullname())
        #
        if not decoded:
            # we did not find a defined object, or failed to decode it
            # hence we decode this as a simple buffer
            # with BER, we need to absolutely keep track of the decoded tag if
            # we want to be able to re-encode it
            if pc == 1:
                # constructed object
                #
                # char._cur will be updated in scan_tlv()
                # but we also need to extend char._len_bit according to tlv in some way...
                # however, the content is constructed and we don't have straight boundaries
                # as for the primitive case below, hence we extend the char buffer to its 
                # maximum
                char._len_bit = 8*len(char._buf)
                #
                self._val_tag = (cl, pc, tval)
                self._val = ('_unk_%i%i%i' % self._val_tag, ASN1CodecBER.scan_tlv(char, tlv))
            elif lval >= 0:
                # primitive object
                char._cur, char._len_bit = tlv[4][0], tlv[4][1]
                self._val_tag = (cl, pc, tval)
                self._val = ('_unk_%i%i%i' % self._val_tag, char.get_bytes(8*lval))
            else:
                raise(ASN1BERDecodeErr('{0}: invalid OPEN / ANY tag and length, {1!r}, {2!r}'\
                      .format(self.fullname(), (cl, pc, tval), lval)))
    
    def _encode_ber_cont_ws(self):
        if isinstance(self._val[0], ASN1Obj):
            Obj = self._val[0]
            Obj._val = self._val[1]
            TLV = Obj._to_ber_ws()
        else:
            # isinstance(self._val[0], str_bytes)
            if self._val[0][:5] == '_unk_':
                try:
                    cl, pc, tval = int(self._val[0][5:6]), \
                                   int(self._val[0][6:7]), \
                                   int(self._val[0][7:])
                except Exception:
                    cl, pc, tval = 0, 0, 4
                TLV = ASN1CodecBER.encode_tlv_ws(cl, tval, self._val[1], pc=pc)
            else:
                Obj = self._get_val_obj(self._val[0])
                Obj._val = self._val[1]
                TLV = Obj._to_ber_ws()
        if ASN1CodecBER.ENC_LUNDEF:
            return 1, -1, TLV
        else:
            lval = TLV.get_bl() >> 3
            return 1, lval, TLV
    
    def _encode_ber_cont(self):
        if isinstance(self._val[0], ASN1Obj):
            Obj = self._val[0]
            Obj._val = self._val[1]
            TLV = Obj._to_ber()
        else:
            # isinstance(self._val[0], str_bytes)
            if self._val[0][:5] == '_unk_':
                try:
                    cl, pc, tval = int(self._val[0][5:6]), \
                                   int(self._val[0][6:7]), \
                                   int(self._val[0][7:])
                except Exception:
                    cl, pc, tval = 0, 0, 4
                TLV = ASN1CodecBER.encode_tlv(cl, tval, self._val[1], pc=pc)
            else:
                Obj = self._get_val_obj(self._val[0])
                Obj._val = self._val[1]
                TLV = Obj._to_ber()
        if ASN1CodecBER.ENC_LUNDEF:
            return 1, -1, TLV
        else:
            lval = sum([f[2] for f in TLV]) >> 3
            return 1, lval, TLV
    
    ###
    # conversion between internal value and ASN.1 JER encoding
    ###
    
    if _with_json:
        
        def _from_jval(self, val):
            # same as PER decodeing
            # try to get a defined object from a table constraint
            if self._TAB_LUT and self._const_tab and self._const_tab_at:
                const_obj_type, const_obj = self._get_tab_obj()
                if const_obj_type == CLASET_NONE:
                    if not self._SILENT:
                        asnlog('OPEN._from_jval: %s, unable to retrieve a table-looked up object, %s'\
                               % (self.fullname(), err))
                    Obj = None
                elif const_obj_type == CLASET_UNIQ:
                    Obj = const_obj
                else:
                    # const_obj_type == CLASET_MULT
                    Obj = const_obj[0]
            else:
                Obj = None
            #
            if Obj is None:
                if isinstance(val, str_types):
                    try:
                        self._val = ('_unk_004', unhexlify(val))
                    except TypeError:
                        raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                              .format(self.fullname(), val)))
                else:
                    #raise(ASN1JERDecodeErr('{0}: unknown wrapped object, {1!r}'\
                    #      .format(self.fullname(), val)))
                    if not self._SILENT:
                        asnlog('OPEN._from_jval: %s, unknown value type, %r' % (self.fullname(), val))
                    self._val = ('_unk_004', val)
            else:
                Obj._from_jval(val)
                if Obj._typeref is not None:
                    self._val = (Obj._typeref.called[1], Obj._val)
                else:
                    self._val = (Obj.TYPE, Obj._val)
        
        def _to_jval(self):
            if isinstance(self._val[0], ASN1Obj):
                Obj = self._val[0]
            else:
                if isinstance(self._val[0], str_types) and self._val[0][:5] == '_unk_':
                    if isinstance(self._val[1], bytes_types):
                        return hexlify(self._val[1]).decode()
                    else:
                        return self._val[1]
                Obj = self._get_val_obj(self._val[0])
            Obj._val = self._val[1]
            return Obj._to_jval()

    ###
    # conversion between internal value and ASN.1 OER/COER encoding
    ###

    def _from_oer(self, char):
        # try to get a defined object from a table constraint
        if self._TAB_LUT and self._const_tab and self._const_tab_at:
            const_obj_type, const_obj = self._get_tab_obj()
            if const_obj_type == CLASET_NONE:
                if not self._SILENT:
                    asnlog('OPEN._from_oer: %s, unable to retrieve a table-looked up object' \
                           % (self.fullname()))
                Obj = None
            elif const_obj_type == CLASET_UNIQ:
                Obj = const_obj
            else:
                # const_obj_type == CLASET_MULT
                # with PER, no tag to select a given object
                Obj = const_obj[0]
        else:
            # TODO: another way to provide a (set of) potential defined object(s)
            # is to look into value constraint self._const_val
            # if we have multiple, then we would have to bruteforce the decoding
            # until a correct one is found !!!
            Obj = None
        #
        val_bytes = ASN1CodecOER.decode_open_type(char)
        val = Obj.from_oer(val_bytes) if (Obj is not None) else val_bytes

        if Obj is None:
            if self._const_val:
                asnlog('OPEN._from_per: %s, potential type constraint(s) available but unused' \
                       % self.fullname())
            assert( isinstance(val, bytes_types) )
            self._val = ('_unk_004', val)
        else:
            if Obj._typeref is not None:
                self._val = (Obj._typeref.called[1], val)
            else:
                self._val = (Obj.TYPE, val)
        return

    def _from_oer_ws(self, char):
        # try to get a defined object from a table constraint
        if self._TAB_LUT and self._const_tab and self._const_tab_at:
            const_obj_type, const_obj = self._get_tab_obj()
            if const_obj_type == CLASET_NONE:
                if not self._SILENT:
                    asnlog('OPEN._from_per_ws: %s, unable to retrieve a table-looked up object' \
                           % (self.fullname()))
                Obj = None
            elif const_obj_type == CLASET_UNIQ:
                Obj = const_obj
            else:
                # const_obj_type == CLASET_MULT
                # with PER, no tag to select a given object
                Obj = const_obj[0]
        else:
            # TODO: another way to provide a (set of) potential defined object(s)
            # is to look into value constraint self._const_val
            # if we have multiple, then we would have to bruteforce the decoding
            # until a correct one is found !!!
            Obj = None
        #
        val_bytes, GEN = ASN1CodecOER.decode_open_type_ws(char)
        if Obj is None:
            if self._const_val:
                asnlog('OPEN._from_per_ws: %s, potential type constraint(s) available but unused' \
                       % self.fullname())
            self._val = ('_unk_004', val_bytes)
        else:
            val = Obj.from_oer(val_bytes)
            if Obj._typeref is not None:
                self._val = (Obj._typeref.called[1], val)
            else:
                self._val = (Obj.TYPE, val)
        self._struct = Envelope(self._name, GEN=tuple(GEN))

    def _to_oer(self):
        if isinstance(self._val[0], ASN1Obj):
            Obj = self._val[0]
        else:
            if self._val[0][:5] == '_unk_':
                return ASN1CodecOER.encode_open_type(self._val[1])
            Obj = self._get_val_obj(self._val[0])
        Obj._val = self._val[1]
        return ASN1CodecOER.encode_open_type(Obj.to_oer())

    def _to_oer_ws(self):
        if isinstance(self._val[0], ASN1Obj):
            Obj = self._val[0]
        else:
            if self._val[0][:5] == '_unk_':
                _gen = ASN1CodecOER.encode_open_type_ws(self._val[1])
                return Envelope(self._name, GEN=(_gen,))
            Obj = self._get_val_obj(self._val[0])
        Obj._val = self._val[1]
        _gen = ASN1CodecOER.encode_open_type_ws(Obj.to_oer())
        self._struct = Envelope(self._name, GEN=(_gen,))
        return self._struct


class ANY(OPEN):
    
    TYPE  = TYPE_ANY
    TAG   = None
    
    # ANY is just like OPEN type, 
    # with the additional DEFINED BY construction


# TYPE-IDENTIFIER and ABSTRACT-SYNTAX are bothes subtypes of CLASS:
#
# TYPE-IDENTIFIER ::= CLASS {
#   &id OBJECT IDENTIFIER UNIQUE,
#   &Type }
# WITH SYNTAX {&Type IDENTIFIED BY &id}
#
# ABSTRACT-SYNTAX ::= CLASS {
#  &id OBJECT IDENTIFIER,
#  &Type,
#  &property BIT STRING {handles-invalid-encodings(0)} DEFAULT {} }
# WITH SYNTAX { &Type IDENTIFIED BY &id [HAS PROPERTY &property] }
#
# they are both generated as is into the _IMPL_ module,
# when a specification requires it


class EXT(SEQ):
    """
    ASN.1 context switching type EXTERNAL object
    
    associated type:
        [UNIVERSAL 8] IMPLICIT SEQUENCE {
            identification [0] EXPLICIT CHOICE {
                syntaxes [0] SEQUENCE {
                    abstract [0] OBJECT IDENTIFIER,
                    transfer [1] OBJECT IDENTIFIER
                    },
                syntax [1] OBJECT IDENTIFIER,
                presentation-context-id [2] INTEGER,
                context-negotiation [3] SEQUENCE {
                    presentation-context-id [0] INTEGER,
                    transfer-syntax [1] OBJECT IDENTIFIER
                    },
                transfer-syntax [4] OBJECT IDENTIFIER,
                fixed [5] NULL
                },
            data-value-descriptor [1] ObjectDescriptor OPTIONAL,
            data-value [2] OCTET STRING
            } (WITH COMPONENTS {
                ...,
                identification (WITH COMPONENTS {
                    ...,
                    syntaxes ABSENT,
                    transfer-syntax ABSENT,
                    fixed ABSENT })
                })
    """
    
    TYPE  = TYPE_EXT
    TAG   = 8


class EMB_PDV(SEQ):
    """
    ASN.1 context switching type EMBEDDED PDV object
    
    associated type:
        [UNIVERSAL 11] IMPLICIT SEQUENCE {
            identification [0] EXPLICIT CHOICE {
                syntaxes [0] SEQUENCE {
                    abstract [0] OBJECT IDENTIFIER,
                    transfer [1] OBJECT IDENTIFIER
                    },
                syntax [1] OBJECT IDENTIFIER,
                presentation-context-id [2] INTEGER,
                context-negotiation [3] SEQUENCE {
                    presentation-context-id [0] INTEGER,
                    transfer-syntax [1] OBJECT IDENTIFIER
                    },
                transfer-syntax [4] OBJECT IDENTIFIER,
                fixed [5] NULL
                },
            data-value-descriptor [1] ObjectDescriptor OPTIONAL,
            data-value [2] OCTET STRING
            } (WITH COMPONENTS {
                ...,
                data-value-descriptor ABSENT
                })
    """
    
    TYPE  = TYPE_EMB_PDV
    TAG   = 11


class CHAR_STR(SEQ):
    """
    ASN.1 context switching type CHARACTER STRING object
    
    associated type:
        [UNIVERSAL 29] IMPLICIT SEQUENCE {
            identification [0] EXPLICIT CHOICE {
                syntaxes [0] SEQUENCE {
                    abstract [0] OBJECT IDENTIFIER,
                    transfer [1] OBJECT IDENTIFIER
                    },
                syntax [1] OBJECT IDENTIFIER,
                presentation-context-id [2] INTEGER,
                context-negotiation [3] SEQUENCE {
                    presentation-context-id [0] INTEGER,
                    transfer-syntax [1] OBJECT IDENTIFIER
                    },
                transfer-syntax [4] OBJECT IDENTIFIER,
                fixed [5] NULL
                },
            string-value [1] OCTET STRING 
            }
    """
    
    TYPE  = TYPE_CHAR_STR
    TAG   = 29

