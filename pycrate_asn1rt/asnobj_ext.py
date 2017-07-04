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

Single value: Python bytes

Alternative single value: Python 2-tuple
    the 1st item corresponds to a reference to another ASN.1 object, it can be:
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
        if isinstance(ref, str_types):
            if ref in _ASN1ObjBasicLUT:
                return _ASN1ObjBasicLUT[ref]()
            else:
                const_tr = self._build_const_tr()
                try:
                    return const_tr[ref]
                except:
                    raise(ASN1ObjErr('{0}: invalid object reference, {1!r}'\
                          .format(self.fullname(), ref)))
        else:
            try:
                return GLOBAL.MOD[ref[0]][ref[1]]
            except:
                raise(ASN1ObjErr('{0}: invalid object reference, {1!r}'\
                      .format(self.fullname(), ref)))
    
    def _build_const_tr(self):
        const_tr = {}
        if self._const_val:
            try:
                const_tr.update( {C._typeref.called[1]:C for C in self._const_val.root} )
            except:
                raise(ASN1NotSuppErr('{0}: OPEN constraint with ASN.1 native object'
                      .format(self.fullname())))
            if self._const_val.ext:
                try:
                    const_tr.update( {C._typeref.called[1]:C for C in self._const_val.ext} )
                except:
                    raise(ASN1NotSuppErr('{0}: OPEN extended constraint with ASN.1 native object'
                          .format(self.fullname())))
        if self._TAB_LUT and self._const_tab and self._const_tab_at:
            tab_obj = self._get_tab_obj()
            try:
                const_tr[tab_obj._typeref.called[1]] = tab_obj
            except:
                raise(ASN1NotSuppErr('{0}: OPEN table constraint with ASN.1 native object'
                      .format(self.fullname())))
        return const_tr
    
    def _safechk_val(self, val):
        if not isinstance(val, bytes_types):
            if isinstance(val[0], ASN1Obj):
                val[0]._safechk_val(val[1])
            else:
                self._get_val_obj(val[0])._safechk_val(val[1])
    
    def _safechk_bnd(self, val):
        # this does not make sense for OPEN objects
        pass
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        m = self._ASN_RE.match(txt)
        if m:
            grp = m.groups()
            if grp[0] is not None:
                # BSTRING
                bs = re.subn('\s{1,}', '', grp[0])[0]
                self.s_val = uint_to_bytes(int(bs, 2), len(bs))
            else:
                # HSTRING
                hs = re.subn('\s{1,}', '', grp[1])[0]
                if len(hs)%2:
                    self._val = unhexlify(hs + '0')
                else:
                    self._val = unhexlify(hs)
            return txt[m.end():].strip()
        else:
            # we must pick-up a type from a defined constraint
            const_tr = self._build_const_tr()
            m = re.match('\s{0,}:|'.join(const_tr.keys()) + '\s{0,}:', txt)
            if m is not None:
                ident = m.group().split(':')[0].strip()
                txt = txt[m.end():].strip()
                Obj = const_tr[ident]
                txt = Obj._from_asn1(txt)
                if Obj._typeref is not None:
                    self._val = (Obj._typeref.called, Obj._val)
                else:
                    self._val = (Obj.TYPE, Obj._val)
                #Obj._val = None
                return txt
        raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
              .format(self.fullname(), txt)))
    
    def _to_asn1(self):
        if isinstance(self._val, bytes_types):
            # HSTRING
            if python_version >= 3:
                return '\'%s\'H' % hexlify(self._val).decode('ascii').upper()
            else:
                return '\'%s\'H' % hexlify(self._val).upper()
        else:
            if isinstance(self._val[0], tuple):
                ident = self._val[0][1]
            else:
                ident = self._val[0]
            const_tr = self._build_const_tr()
            if ident in const_tr:
                Obj = const_tr[ident]
                Obj._val = self._val[1]
                return '%s: %s' % (ident, Obj.to_asn1())
                #Obj._val = None
        raise(ASN1ASNEncodeErr('{0}: non-encodable value, {1!r}'\
              .format(self.fullname(), self._val)))
    
    ###
    # conversion between internal value and ASN.1 PER encoding
    ###
    
    def _from_per_ws(self, char):
        # try to get a defined object from a table constraint
        if self._TAB_LUT and self._const_tab and self._const_tab_at:
            try:
                Obj = self._get_tab_obj()
            except Exception as err:
                if not self._SILENT:
                    asnlog('OPEN._from_per_ws: %s, unable to retrieve a table-looked up object, %s'\
                           % (self._name, err))
                Obj = None
        else:
            # TODO: another way to provide a (set of) potential defined object(s)
            # is to look into value constraint self._const_val
            # if we have multiple, then we would have to bruteforce the decoding 
            # until a correct one is found !!!
            Obj = None
        #
        if Obj is None:
            if self._const_val:
                asnlog('OPEN._from_per_ws: %s, potential type constraint(s) available'\
                       % self._name)
            #assert( isinstance(val, bytes_types) )
            val, GEN = ASN1CodecPER.decode_unconst_open_ws(char, wrapped=None)
            self._val = val
        else:
            if Obj._typeref is not None:
                val, GEN = ASN1CodecPER.decode_unconst_open_ws(char, wrapped=Obj._tr)
                self._val = (Obj._typeref.called, val)
            else:
                val, GEN = ASN1CodecPER.decode_unconst_open_ws(char, wrapped=Obj)
                self._val = (Obj.TYPE, val)
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return
    
    def _from_per(self, char):
        # try to get a defined object from a table constraint
        if self._TAB_LUT and self._const_tab and self._const_tab_at:
            try:
                Obj = self._get_tab_obj()
            except Exception as err:
                if not self._SILENT:
                    asnlog('OPEN._from_per: %s, unable to retrieve a defined object, %s'\
                           % (self._name, err))
                Obj = None
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
                asnlog('OPEN._from_per: %s, potential type constraint(s) available'\
                       % self._name)
            assert( isinstance(val, bytes_types) )
            self._val = val
        else:
            if Obj._typeref is not None:
                self._val = (Obj._typeref.called, val)
            else:
                self._val = (Obj.TYPE, val)
        return
    
    def _to_per_ws(self):
        if isinstance(self._val, bytes_types):
            GEN = ASN1CodecPER.encode_unconst_buf_ws(self._val)
            self._struct = Envelope(self._name, GEN=tuple(GEN))
            return self._struct
        elif isinstance(self._val[0], ASN1Obj):
            Obj = self._val[0]
        else:
            Obj = self._get_val_obj(self._val[0])
        Obj._val = self._val[1]
        GEN = ASN1CodecPER.encode_unconst_open_ws(Obj)
        #Obj._val = None
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return self._struct
    
    def _to_per(self):
        if isinstance(self._val, bytes_types):
            return ASN1CodecPER.encode_unconst_buf(self._val)
        elif isinstance(self._val[0], ASN1Obj):
            Obj = self._val[0]
        else:
            Obj = self._get_val_obj(self._val[0])
        Obj._val = self._val[1]
        ret = ASN1CodecPER.encode_unconst_open(Obj)
        #Obj._val = None
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
        # try to get a defined object from a table constraint
        if self._TAB_LUT and self._const_tab and self._const_tab_at:
            try:
                Obj = self._get_tab_obj()
            except Exception as err:
                if not self._SILENT:
                    asnlog('OPEN._decode_ber_cont_ws: %s, unable to retrieve a table-looked up object, %s'\
                           % (self._name, err))
                Obj = None
        else:
            # TODO: another way to provide a (set of) potential defined object(s)
            # is to look into value constraint self._const_val
            # if we have multiple, then we would have to bruteforce the decoding 
            # until a correct one is found !!!
            Obj = None
        #
        if Obj is None or (cl, tval) != Obj._tagc[0]:
            if self._const_val:
                asnlog('OPEN._decode_ber_cont_ws: %s, potential type constraint(s) available'\
                       % self._name)
            elif hasattr(self, '_defby') and self._defby is not None:
                asnlog('ANY._decode_ber_cont_ws: %s, DEFINED BY construction unhandled'\
                       % self._name)
            # with BER, we need to absolutely keep track of the decoded tag if
            # we want to be able to re-encode it
            # hence we use the 10 first bytes to store the tag class, pc and value
            if pc == 1:
                # constructed object
                val = ASN1CodecBER.scan_tlv_ws(char, tlv)
                V = Envelope('V', GEN=(Tag, Len, Buf(ident, val=val, bl=8*len(val), rep=REPR_HEX)))
            elif lval >= 0:
                # primitive object
                char._cur = tlv[6][0]
                Val = Buf(ident, bl=8*lval, rep=REPR_HEX)
                Val._from_char(char)
                val = Val.to_bytes()
                V = Envelope('V', GEN=(Tag, Len, Val))
            else:
                raise(ASN1BERDecodeErr('{0}: invalid OPEN / ANY tag and length, {1!r}, {2!r}'\
                      .format(self.fullname(), (cl, pc, tval), lval)))
            # grilling t-bones on it
            self._val = pack('>BBQ', cl, pc, tval) + val
        else:
            # defined object
            Obj._from_ber_ws(char, [tlv])
            # set value
            if Obj._typeref is not None:
                self._val = (Obj._typeref.called, Obj._val)
            else:
                self._val = (Obj.TYPE, Obj._val)
            V = Obj._struct
        return V
    
    def _decode_ber_cont(self, char, tlv):
        # tlv: list of list of tag, length and value corresponding to the CHOICE
        if not isinstance(tlv, list):
            raise(ASN1BERDecodeErr('{0}: invalid OPEN / ANY primitive structure'\
                  .format(self.fullname())))
        # select the inner encoding
        tlv = tlv[0]
        cl, pc, tval, lval = tlv[0:4]
        # try to get a defined object from a table constraint
        if self._TAB_LUT and self._const_tab and self._const_tab_at:
            try:
                Obj = self._get_tab_obj()
            except Exception as err:
                if not self._SILENT:
                    asnlog('OPEN._decode_ber_cont_ws: %s, unable to retrieve a table-looked up object, %s'\
                           % (self._name, err))
                Obj = None
        else:
            # TODO: another way to provide a (set of) potential defined object(s)
            # is to look into value constraint self._const_val
            # if we have multiple, then we would have to bruteforce the decoding 
            # until a correct one is found !!!
            Obj = None
        #
        if Obj is None or (cl, tval) != Obj._tagc[0]:
            if self._const_val:
                asnlog('OPEN._decode_ber_cont: %s, potential type constraint(s) available'\
                       % self._name)
            elif hasattr(self, '_defby') and self._defby is not None:
                asnlog('ANY._decode_ber_cont: %s, DEFINED BY construction unhandled'\
                       % self._name)
            # with BER, we need to absolutely keep track of the decoded tag if
            # we want to be able to re-encode it
            # hence we use the 10 first bytes to store the tag class, pc and value
            if pc == 1:
                # constructed object
                val = ASN1CodecBER.scan_tlv_ws(char, tlv)
            elif lval >= 0:
                # primitive object
                char._cur = tlv[6][0]
                val = char.get_bytes(8*lval)
            else:
                raise(ASN1BERDecodeErr('{0}: invalid OPEN / ANY tag and length, {1!r}, {2!r}'\
                      .format(self.fullname(), (cl, pc, tval), lval)))
            # grilling t-bones on it
            self._val = pack('>BBQ', cl, pc, tval) + val
        else:
            # defined object
            Obj._from_ber(char, [tlv])
            # set value
            if Obj._typeref is not None:
                self._val = (Obj._typeref.called, Obj._val)
            else:
                self._val = (Obj.TYPE, Obj._val)
    
    def _encode_ber_cont_ws(self):
        if isinstance(self._val, bytes_types):
            # unknown object re-encoding
            assert( len(self._val) >= 10 )
            cl, pc, tval = unpack('>BBQ', self._val[:10])
            TLV = ASN1CodecBER.encode_tlv_ws(cl, tval, self._val[10:], pc=pc)
        else:
            if isinstance(self._val[0], ASN1Obj):
                Obj = self._val[0]
            else:
                Obj = self._get_val_obj(self._val[0])
            Obj._val = self._val[1]
            TLV = Obj._to_ber_ws()
        if ASN1CodecBER.ENC_LUNDEF:
            return 1, -1, TLV
        else:
            # TODO: check which one is the more efficient
            #lval += (TLV[0].get_bl() >> 3) + (TLV[1].get_bl() >> 3) + TLV[1]()
            #lval = (TLV[0:2].get_bl() >> 3) + TLV[1]()
            lval = TLV.get_bl() >> 3
            return 1, lval, TLV
    
    def _encode_ber_cont(self):
        if isinstance(self._val, bytes_types):
            # unknown object re-encoding
            assert( len(self._val) >= 10 )
            cl, pc, tval = unpack('>BBQ', self._val[:10])
            TLV = ASN1CodecBER.encode_tlv_ws(cl, tval, self._val[10:], pc=pc)
        else:
            if isinstance(self._val[0], ASN1Obj):
                Obj = self._val[0]
            else:
                Obj = self._get_val_obj(self._val[0])
            Obj._val = self._val[1]
            TLV = Obj._to_ber()
        if ASN1CodecBER.ENC_LUNDEF:
            return 1, -1, TLV
        else:
            lval = sum([f[2] for f in TLV]) >> 3
            return 1, lval, TLV


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


class EXT(_CONSTRUCT):
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


class EMB_PDV(_CONSTRUCT):
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


class CHAR_STR(_CONSTRUCT):
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

