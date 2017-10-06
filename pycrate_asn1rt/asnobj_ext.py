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
            const_tr = self._get_const_tr()
            if ref in const_tr:
                return const_tr[ref]
            elif ref in _ASN1ObjBasicLUT:
                return _ASN1ObjBasicLUT[ref]()
            else:
                raise(ASN1ObjErr('{0}: invalid object reference, {1!r}'\
                      .format(self.fullname(), ref)))
        else:
            try:
                return GLOBAL.MOD[ref[0]][ref[1]]
            except:
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
                        const_tr[C._typeref.called[1]] = C
                    else:
                        const_tr[C.TYPE] = C
                if self._const_val.ext:
                    for C in self._const_val.ext:
                        if C._typeref is not None:
                            const_tr[C._typeref.called[1]] = C
                        else:
                            const_tr[C.TYPE] = C
            if self._TAB_LUT and self._const_tab and self._const_tab_at:
                # collect all type from the table constraint
                assert( hasattr(self, '_const_tab_id') )
                ObjsTab = self._const_tab(self._const_tab_id)
                for ObjTab in ObjsTab:
                    if ObjTab._typeref is not None and ObjTab._typeref.called[1] not in const_tr:
                        const_tr[ObjTab._typeref.called[1]] = ObjTab
                    elif ObjTab.TYPE not in const_tr:
                        const_tr[ObjTab.TYPE] = ObjTab
            self.__const_tr__ = const_tr
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
            const_tr = self._get_const_tr()
            m = re.match('\s{0,}:|'.join(const_tr.keys()) + '\s{0,}:', txt)
            if m is not None:
                ident = m.group().split(':')[0].strip()
                txt = txt[m.end():].strip()
                Obj = const_tr[ident]
                txt = Obj._from_asn1(txt)
                if Obj._typeref is not None:
                    self._val = (Obj._typeref.called[1], Obj._val)
                else:
                    self._val = (Obj.TYPE, Obj._val)
                return txt
            else:
                # TODO: module.object reference
                ASN1NotSuppErr('{0}: reference parsing unsupported'.format(self.fullname()))
    
    def _to_asn1(self):
        if isinstance(self._val, bytes_types):
            # HSTRING
            if python_version >= 3:
                return '\'%s\'H' % hexlify(self._val).decode('ascii').upper()
            else:
                return '\'%s\'H' % hexlify(self._val).upper()
        else:
            if isinstance(self._val[0], str_types):
                ident = self._val[0]
            else:
                ident = '.'.join(self._val[0])
            Obj = self._get_val_obj(self._val[0])
            Obj._val = self._val[1]
            return '%s: %s' % (ident, Obj.to_asn1())
    
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
                           % (self.fullname(), err))
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
                       % self.fullname())
            #assert( isinstance(val, bytes_types) )
            val, GEN = ASN1CodecPER.decode_unconst_open_ws(char, wrapped=None)
            self._val = val
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
            try:
                Obj = self._get_tab_obj()
            except Exception as err:
                if not self._SILENT:
                    asnlog('OPEN._from_per: %s, unable to retrieve a defined object, %s'\
                           % (self.fullname(), err))
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
                       % self.fullname())
            assert( isinstance(val, bytes_types) )
            self._val = val
        else:
            if Obj._typeref is not None:
                self._val = (Obj._typeref.called[1], val)
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
        tag, Obj = (cl, tval), None
        # try to get a defined object from a table constraint
        if self._TAB_LUT and self._const_tab and self._const_tab_at:
            try:
                Obj = self._get_tab_obj()
            except Exception as err:
                if not self._SILENT:
                    asnlog('OPEN._decode_ber_cont_ws: %s, unable to retrieve an object in the table '\
                           'constraint, err %s' % (self.fullname(), err))
        #
        elif self._const_val is not None:
            # another way to provide a (set of) potential defined object(s)
            # is to look into value constraint self._const_val
            # we must select the right one according to the decoded tag
            Obj = get_obj_by_tag(self, tag)
        #
        elif hasattr(self, '_defby') and self._defby is not None:
            # TODO: 3rd way to specify the potential defined object
            # is to use a DEFINED BY specification (this is old-school)
            if not self._SILENT:
                asnlog('OPEN._decode_ber_cont_ws: %s, DEFINED BY lookup not supported' % self.fullname())
        #
        decoded = False
        if Obj is not None:
            # we found a defined object
            try:
                Obj._from_ber_ws(char, [tlv])
            except Exception as err:
                # decoding failed, we fall back to the simple buffer decoding
                asnlog('OPEN._decode_ber_cont_ws: %s, decoding failed for the selected object %s'\
                       % (self.fullname(), Obj._name))
            else:
                # set value
                if Obj._typeref is not None:
                    self._val = (Obj._typeref.called[1], Obj._val)
                else:
                    self._val = (Obj.TYPE, Obj._val)
                V = Obj._struct
                decoded = True
        #
        if not decoded:
            # we did not find a defined object, or failed to decode it
            # hence we decode this as a simple buffer
            # with BER, we need to absolutely keep track of the decoded tag if
            # we want to be able to re-encode it
            self._val_tag = (cl, pc, tval)
            if pc == 1:
                # constructed object
                self._val = ASN1CodecBER.scan_tlv_ws(char, tlv)
                V = Envelope('V', GEN=(Tag, Len, Buf(ident, val=val, bl=8*len(val), rep=REPR_HEX)))
            elif lval >= 0:
                # primitive object
                char._cur, char._len_bit = tlv[6][0], tlv[6][1]
                Val = Buf('_buf_', bl=8*lval, rep=REPR_HEX)
                Val._from_char(char)
                self._val = Val.to_bytes()
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
        tag, Obj = (cl, tval), None
        # try to get a defined object from a table constraint
        if self._TAB_LUT and self._const_tab and self._const_tab_at:
            try:
                Obj = self._get_tab_obj()
            except Exception as err:
                if not self._SILENT:
                    asnlog('OPEN._decode_ber_cont: %s, unable to retrieve an object in the table '\
                           'constraint (%s)' % (self.fullname(), err))
        #
        elif self._const_val is not None:
            # another way to provide a (set of) potential defined object(s)
            # is to look into value constraint self._const_val
            # we must select the right one according to the decoded tag
            Obj = get_obj_by_tag(self, tag)
        #
        elif hasattr(self, '_defby') and self._defby is not None:
            # TODO: 3rd way to specify the potential defined object
            # is to use a DEFINED BY specification (this is old-school)
            if not self._SILENT:
                asnlog('OPEN._decode_ber_cont: %s, DEFINED BY lookup not supported' % self.fullname())
        #
        decoded = False
        if Obj is not None:
            # we found a defined object
            try:
                Obj._from_ber(char, [tlv])
            except Exception as err:
                # decoding failed, we fall back to the simple buffer decoding
                if not self._SILENT:
                    asnlog('OPEN._decode_ber_cont: %s, decoding failed for the selected object %s'\
                           % (self.fullname(), Obj._name))
            else:
                # set value
                if Obj._typeref is not None:
                    self._val = (Obj._typeref.called[1], Obj._val)
                else:
                    self._val = (Obj.TYPE, Obj._val)
                decoded = True
        #
        if not decoded:
            # we did not find a defined object, or failed to decode it
            # hence we decode this as a simple buffer
            # with BER, we need to absolutely keep track of the decoded tag if
            # we want to be able to re-encode it
            self._val_tag = (cl, pc, tval)
            if pc == 1:
                # constructed object
                self._val = ASN1CodecBER.scan_tlv_ws(char, tlv)
            elif lval >= 0:
                # primitive object
                char._cur, char._len_bit = tlv[4][0], tlv[4][1]
                self._val = char.get_bytes(8*lval)
            else:
                raise(ASN1BERDecodeErr('{0}: invalid OPEN / ANY tag and length, {1!r}, {2!r}'\
                      .format(self.fullname(), (cl, pc, tval), lval)))
    
    def _encode_ber_cont_ws(self):
        if isinstance(self._val, bytes_types):
            # unknown object re-encoding
            assert( hasattr(self, '_val_tag') )
            cl, pc, tval = self._val_tag
            TLV = ASN1CodecBER.encode_tlv_ws(cl, tval, self._val, pc=pc)
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
            assert( hasattr(self, '_val_tag') )
            cl, pc, tval = self._val_tag
            TLV = ASN1CodecBER.encode_tlv(cl, tval, self._val, pc=pc)
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

