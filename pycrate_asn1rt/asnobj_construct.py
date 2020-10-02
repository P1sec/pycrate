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
# * File Name : pycrate_asn1rt/asnobj_construct.py
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


#------------------------------------------------------------------------------#
# CHOICE
#------------------------------------------------------------------------------#

class CHOICE(ASN1Obj):
    __doc__ = """
ASN.1 constructed type CHOICE object

Single value: Python 2-tuple
    1st item is a Python str, choice identifier, must be a key in _cont
    2nd item is the ASN1Obj single value specific to the chosen object
    
    special case is the "_ext_$ind" 1st item which encodes an unknown 
    extension with index $ind, then the 2nd item must be a Python bytes

Specific attributes:
    
    - cont: ASN1Dict {ident (str): ASN1Obj instance},
        provides the content of the CHOICE object
    
    - cont_tags: dict with {tag (int): identifier (str)},
        provides a lookup table for tag value to components
    
    - ext_ident: dict with {identifier (str) : extended group index (int)},
        for grouped extended components
    
    - ext_group: dict with {extended group index (int) : list of identifiers (str)},
        for grouped extended components
    
    - const_ind: ASN1Set, provides the set of ranges for root indexes and ext 
        indexes of the content
%s
""" % ASN1Obj_docstring
    
    _const_ind = None
    
    TYPE  = TYPE_CHOICE
    TAG   = None
    
    def _safechk_val(self, val):
        if isinstance(val, tuple) and len(val) == 2:
            if val[0] in self._cont:
                self._cont[val[0]]._safechk_val(val[1])
            elif not re.match('_ext_[0-9]{1,}', val[0]) or not isinstance(val[1], bytes_types):
                raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
        else:
            raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
    
    def _safechk_bnd(self, val):
        if val[0] in self._cont:
            self._cont[val[0]]._safechk_bnd(val[1])
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        if not hasattr(self, '_ASN_RE'):
            items = list(self._cont.keys())
            items.sort(key=len, reverse=True)
            self._ASN_RE = re.compile('\s{0,}:|'.join(items) + '\s{0,}:')
        m = self._ASN_RE.match(txt)
        if m:
            ident = m.group().split(':')[0].strip()
            txt = txt[m.end():].strip()
            _par = self._cont[ident]._parent
            self._cont[ident]._parent = self
            txt = self._cont[ident]._from_asn1(txt)
            self._val = (ident, self._cont[ident]._val)
            self._cont[ident]._parent = _par
            return txt
        else:
            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                  .format(self.fullname(), txt)))
    
    def _to_asn1(self):
        ident = self._val[0]
        if ident in self._cont:
            self._cont[ident]._val = self._val[1]
            _par = self._cont[ident]._parent
            self._cont[ident]._parent = self
            ret = '%s : %s' % (ident, self._cont[ident]._to_asn1())
            self._cont[ident]._parent = _par
        else:
            ret = '%s : \'%s\'H' % (ident, hexlify(self._val[1]))
        return ret
    
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
                # chosen object in the extension part
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
                    ident = self._ext[ind]
                    Cho = self._cont[ident]
                    _par = Cho._parent
                    Cho._parent = self
                else:
                    # unknown extension
                    if not self._SILENT:
                        asnlog('CHOICE._from_per_ws: %s, unknown extension index %r'\
                               % (self.fullname(), ind))
                    ident = '_ext_%r' % ind
                    Cho = None
                val, _gen = ASN1CodecPER.decode_unconst_open_ws(char, wrapped=Cho)
                self._val = (ident, val)
                if Cho is not None:
                    Cho._parent = _par
                self._struct = Envelope(self._name, GEN=tuple(GEN + _gen))
                return
            elif ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += 1
        # chosen object is in the root part
        if len(self._cont) == 1:
            # implicit index
            ind = 0
        else:
            # index decoded as a constrained integer
            ind, _gen = ASN1CodecPER.decode_intconst_ws(char, self._const_ind, name='I')
            GEN.extend(_gen)
        try:
            ident = self._root[ind]
        except IndexError:
            raise(ASN1PERDecodeErr('{0}: invalid CHOICE index, %r'.format(self.fullname(), ind)))
        Cho = self._cont[ident]
        # decode the chosen object
        _par = Cho._parent
        Cho._parent = self
        Cho._from_per_ws(char)
        GEN.append(Cho._struct)
        self._val = (ident, Cho._val)
        Cho._parent = _par
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return
    
    def _from_per(self, char):
        GEN = []
        if self._ext is not None:
            E = char.get_uint(1)
            if E:
                # chosen object in the extension part
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
                    ident = self._ext[ind]
                    Cho = self._cont[ident]
                    _par = Cho._parent
                    Cho._parent = self
                else:
                    # unknown extension
                    if not self._SILENT:
                        asnlog('CHOICE._from_per: %s, unknown extension index %r'\
                               % (self.fullname(), ind))
                    ident = '_ext_%r' % ind
                    Cho = None
                self._val = (ident, ASN1CodecPER.decode_unconst_open(char, wrapped=Cho))
                if Cho is not None:
                    Cho._parent = _par
                return
            elif ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += 1
        # chosen object is in the root part
        if len(self._root) == 1:
            # implicit index
            ind = 0
        else:
            # index decoded as a constrained integer
            ind = ASN1CodecPER.decode_intconst(char, self._const_ind)
        try:
            ident = self._root[ind]
        except IndexError:
            raise(ASN1PERDecodeErr('{0}: invalid CHOICE index, %r'.format(self.fullname(), ind)))
        Cho = self._cont[ident]
        # decode the chosen object
        _par = Cho._parent
        Cho._parent = self
        Cho._from_per(char)
        self._val = (ident, Cho._val)
        Cho._parent = _par
        return
    
    def _to_per_ws(self):
        GEN = []
        if self._ext is not None:
            # extensible type
            if self._val[0] in self._root:
                # choice index in the root part
                GEN.append( Uint('E', val=0, bl=1) )
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                ind = self._root.index(self._val[0])
            else:
                # extended choice index
                GEN.append( Uint('E', val=1, bl=1) )
                if self._val[0] in self._ext:
                    # set the chosen index and object
                    ind = self._ext.index(self._val[0])
                    Cho = self._cont[self._val[0]]
                else:
                    # self._val[0][:5] == '_ext_'
                    ind = int(self._val[0][5:])
                    Cho = None
                # encode the index
                if ind < 64:
                    GEN.extend( (Uint('big', val=0, bl=1), Uint('I', val=ind, bl=6))  )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 8
                else:
                    GEN.append( Uint('big', val=1, bl=1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 2
                    GEN.extend( ASN1CodecPER.encode_intunconst_ws(ind, 0, name='I') )
                # encode the choice object
                if Cho is not None:
                    Cho._val = self._val[1]
                    _par = Cho._parent
                    Cho._parent = self
                    if ASN1CodecPER.ALIGNED:
                        buf = Cho.to_aper_ws()
                    else:
                        buf = Cho.to_uper_ws()
                    Cho._parent = _par
                else:
                    buf = self._val[1]
                GEN.extend( ASN1CodecPER.encode_unconst_buf_ws(buf) )
                self._struct = Envelope(self._name, GEN=tuple(GEN))
                return self._struct
        else:
            ind = self._root.index(self._val[0])
        # choice index in the root part
        if len(self._root) > 1:
            # choice index encoded as a constrained integer
            GEN.extend( ASN1CodecPER.encode_intconst_ws(ind, self._const_ind, name='I') )
        # encode the chosen object
        Cho = self._cont[self._val[0]]
        Cho._val = self._val[1]
        _par = Cho._parent
        Cho._parent = self
        GEN.append( Cho._to_per_ws() )
        Cho._parent = self
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return self._struct
    
    def _to_per(self):
        GEN = []
        if self._ext is not None:
            # extensible type
            if self._val[0] in self._root:
                # choice index in the root part
                GEN.append( (T_UINT, 0, 1) )
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                ind = self._root.index(self._val[0])
            else:
                # extended choice index
                GEN.append( (T_UINT, 1, 1) )
                if self._val[0] in self._ext:
                    # set the chosen index and object
                    ind = self._ext.index(self._val[0])
                    Cho = self._cont[self._val[0]]
                else:
                    # self._val[0][:5] == '_ext_'
                    ind = int(self._val[0][5:])
                    Cho = None
                # encode the index
                if ind < 64:
                    GEN.append( (T_UINT, ind, 7) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 8
                else:
                    GEN.append( (T_UINT, 1, 1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 2
                    GEN.extend( ASN1CodecPER.encode_intunconst(ind, 0) )
                # encode the choice object
                if Cho is not None:
                    Cho._val = self._val[1]
                    if ASN1CodecPER.ALIGNED:
                        buf = Cho.to_aper()
                    else:
                        buf = Cho.to_uper()
                else:
                    buf = self._val[1]
                GEN.extend( ASN1CodecPER.encode_unconst_buf(buf) )
                return GEN
        else:
            ind = self._root.index(self._val[0])
        # choice index in the root part
        if len(self._root) > 1:
            # choice index encoded as a constrained integer
            GEN.extend( ASN1CodecPER.encode_intconst(ind, self._const_ind) )
        # encode the chosen object
        Cho = self._cont[self._val[0]]
        Cho._val = self._val[1]
        _par = Cho._parent
        Cho._parent = self
        GEN.extend( Cho._to_per() )
        Cho._parent = _par
        return GEN
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    # the chosen item is encoded like if it where outside the CHOICE
    
    def _decode_ber_cont_ws(self, char, tlv):
        # tlv: list of list of tag, length and value corresponding to the CHOICE
        if not isinstance(tlv, list):
            raise(ASN1BERDecodeErr('{0}: invalid CHOICE primitive structure'\
                  .format(self.fullname())))
        # select the inner encoding
        tlv = tlv[0]
        Tag, cl, pc, tval, Len, lval = tlv[0:6]
        if (cl, tval) not in self._cont_tags:
            # decode unknown extension, if possible
            if self._ext is not None:
                # unknown extension
                if not self._SILENT:
                    asnlog('CHOICE._decode_ber_cont_ws: %s, unknown extension tag %r'\
                           % (self.fullname(), (cl, tval)))
                ident = '_ext_%i%i%i' % (cl, pc, tval)
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
                    raise(ASN1BERDecodeErr('{0}: invalid CHOICE tag and length, {1!r}, {2!r}'\
                          .format(self.fullname(), (cl, pc, tval), lval)))
                self._val = (ident, val)
                
            else:
                raise(ASN1BERDecodeErr('{0}: invalid CHOICE tag according to the content, {1!r}'\
                      .format(self.fullname(), (cl, tval))))
        else:
            # select the known choice
            path = self._cont_tags[(cl, tval)]
            if isinstance(path, list):
                # select untagged choice
                Cho = [self._cont[path[0]]]
                _par = [Cho[0]._parent]
                Cho[0]._parent = self
                for ident in path[1:]:
                    Cho.append( Cho[-1]._cont[ident] )
                    _par.append( Cho[-1]._parent )
                    Cho[-1]._parent = Cho[-2]
                # decode it
                Cho[-1]._from_ber_ws(char, [tlv])
                val = Cho[-1]._val
                # restore parents and set value
                for i in range(len(_par)):
                    Cho[i]._parent = _par[i]
                for ident in reversed(path[1:]):
                    val = (ident, val)
                self._val = (path[0], val)
                V = Cho[-1]._struct
            else:
                # select tagged component
                Cho = self._cont[path]
                _par = Cho._parent
                Cho._parent = self
                # decode it
                Cho._from_ber_ws(char, [tlv])
                # restore parent and set value
                Cho._parent = _par
                self._val = (path, Cho._val)
                V = Cho._struct
        return V
    
    def _decode_ber_cont(self, char, tlv):
        # tlv: list of list of tag, length and value corresponding to the CHOICE
        if not isinstance(tlv, list):
            raise(ASN1BERDecodeErr('{0}: invalid CHOICE primitive structure'\
                  .format(self.fullname())))
        # select the inner encoding
        tlv = tlv[0]
        cl, pc, tval, lval = tlv[0:4]
        if (cl, tval) not in self._cont_tags:
            # decode unknown extension, if possible
            if self._ext is not None:
                # unknown extension
                ident = '_ext_%i%i%i' % (cl, pc, tval)
                if not self._SILENT:
                    asnlog('CHOICE._decode_ber_cont: %s, unknown extension tag %r'\
                           % (self.fullname(), (cl, tval))) 
                if pc == 1:
                    # constructed object
                    val = ASN1CodecBER.scan_tlv(char, tlv)
                elif lval >= 0:
                    # primitive object
                    char._cur = tlv[4][0]
                    val = char.get_bytes(8*lval)
                self._val = (ident, val)
            else:
                raise(ASN1BERDecodeErr('{0}: invalid CHOICE tag according to the content, {1!r}'\
                      .format(self.fullname(), (cl, tval))))
        else:
            # select the known choice
            path = self._cont_tags[(cl, tval)]
            if isinstance(path, list):
                # select untagged choice
                Cho = [self._cont[path[0]]]
                _par = [Cho[0]._parent]
                Cho[0]._parent = self
                for ident in path[1:]:
                    Cho.append( Cho[-1]._cont[ident] )
                    _par.append( Cho[-1]._parent )
                    Cho[-1]._parent = Cho[-2]
                # decode it
                Cho[-1]._from_ber(char, [tlv])
                val = Cho[-1]._val
                # restore parents and set value
                for i in range(len(_par)):
                    Cho[i] = _par[i]
                for ident in reversed(path[1:]):
                    val = (ident, val)
                self._val = (path[0], val)
            else:
                # select tagged component
                Cho = self._cont[path]
                _par = Cho._parent
                Cho._parent = self
                # decode it
                Cho._from_ber(char, [tlv])
                # restore parent and set value
                Cho._parent = _par
                self._val = (path, Cho._val)
    
    def _encode_ber_cont_ws(self):
        if self._val[0][:5] == '_ext_':
            # unknown extension re-encoding
            cl, pc, tval = int(self._val[0][5:6]), int(self._val[0][6:7]), int(self._val[0][7:])
            TLV = ASN1CodecBER.encode_tlv_ws(cl, tval, self._val[1], pc=pc)
        else:
            Cho = self._cont[self._val[0]]
            Cho._val = self._val[1]
            _par = Cho._parent
            Cho._parent = self
            TLV = Cho._to_ber_ws()
            Cho._parent = _par
        if ASN1CodecBER.ENC_LUNDEF:
            return 1, -1, TLV
        else:
            lval = TLV.get_bl() >> 3
            return 1, lval, TLV
    
    def _encode_ber_cont(self):
        if self._val[0][:5] == '_ext_':
            # unknown extension re-encoding
            cl, pc, tval = int(self._val[0][5:6]), int(self._val[0][6:7]), int(self._val[0][7:])
            TLV = ASN1CodecBER.encode_tlv(cl, tval, self._val[1], pc=pc)
        else:
            Cho = self._cont[self._val[0]]
            Cho._val = self._val[1]
            _par = Cho._parent
            Cho._parent = self
            TLV = Cho._to_ber()
            Cho._parent = _par
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
            try:
                ident, value = tuple(val.items())[0]
            except Exception:
                raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                      .format(self.fullname(), val)))
            if ident in self._cont:
                _par = self._cont[ident]._parent
                self._cont[ident]._parent = self
                self._cont[ident]._from_jval(value)
                self._val = (ident, self._cont[ident]._val)
                self._cont[ident]._parent = _par
            else:
                # unknown extended value, keeping value as-is
                self._val = ('_ext_%s' % ident, value)
        
        def _to_jval(self):
            ident = self._val[0]
            if ident in self._cont:
                self._cont[ident]._val = self._val[1]
                _par = self._cont[ident]._parent
                self._cont[ident]._parent = self
                ret = {ident : self._cont[ident]._to_jval()}
                self._cont[ident]._parent = _par
            else:
                # reencoding unknown value
                assert( ident[:5] == '_ext_' )
                ret = {ident[5:] : self._val[1]}
            return ret

    ###
    # conversion between internal value and ASN.1 OER/COER encoding
    ###

    def _oer_tag_class(self):
        try:
            tag_class, tag = next(t for t, ident in self._cont_tags.items()
                                  if ident == self._val[0])
        except StopIteration:
            if self._val[0][:5] == '_ext_':
                # unknown extension re-encoding
                tag_class, _, tag = int(self._val[0][5:6]), int(
                    self._val[0][6:7]), int(self._val[0][7:])
            else:
                raise ASN1OEREncodeErr("Unknown tag for item {0}".format(
                    self._val[0]))
        try:
            tag_class = ASN1CodecOER.TagClassLUT[tag_class]
        except KeyError:
            ASN1OEREncodeErr("Unknown tag class: {0}".format(tag_class))

        return tag_class, tag

    def _to_oer(self):
        tag_class, tag = self._oer_tag_class()

        # Tag
        temp = ASN1CodecOER.encode_tag(tag, tag_class)

        if self._val[0] in self._root:
            # Normal encoding
            # Value
            Cho = self._cont[self._val[0]]
            Cho._val = self._val[1]
            temp.extend(Cho._to_oer())

        elif self._ext is not None:
            # Extensible type
            if self._val[0] in self._ext:
                Cho = self._cont[self._val[0]]
                Cho._val = self._val[1]
                temp.extend(ASN1CodecOER.encode_open_type(Cho.to_oer()))
            else:
                temp.extend(ASN1CodecOER.encode_open_type(self._val[1]))

        return temp

    def _to_oer_ws(self):
        tag_class, tag = self._oer_tag_class()

        # Tag
        temp = [ASN1CodecOER.encode_tag_ws(tag, tag_class)]

        if self._val[0] in self._root:
            # Normal encoding
            # Value
            Cho = self._cont[self._val[0]]
            Cho._val = self._val[1]
            temp.append(Cho._to_oer_ws())
        elif self._ext is not None:
            # Extensible type
            if self._val[0] in self._ext:
                Cho = self._cont[self._val[0]]
                Cho._val = self._val[1]
                temp.append(ASN1CodecOER.encode_open_type_ws(Cho.to_oer()))
            else:
                temp.append(ASN1CodecOER.encode_open_type_ws(self._val[1]))

        self._struct = Envelope(self._name, GEN=tuple(temp))
        return self._struct

    def _from_oer(self, char):
        tag_class, tag = ASN1CodecOER.decode_tag(char)
        try:
            tag_class = ASN1CodecOER.TagClassLUT[tag_class]
        except KeyError:
            ASN1OEREncodeErr("Unknown tag class: {0}".format(tag_class))

        try:
            ident = self._cont_tags[(tag_class, tag)]
            Cho = self._cont[ident]
            _par = Cho._parent
            Cho._parent = self
            if self._ext and (ident in self._ext):
                val_bytes = ASN1CodecOER.decode_open_type(char)
                Cho.from_oer(val_bytes)
            if ident in self._root:
                Cho.from_oer(char)
            Cho._parent = _par
            self._val = (ident, Cho._val)
        except KeyError:
            if self._ext is not None:
                # It's extension type
                if not self._SILENT:
                    asnlog('CHOICE._from_oer: %s, unknown extension tag %r' \
                           % (self.fullname(), (tag_class, tag)))
                # NOTE: There is no way how to resolve the primitive/constructed
                #       flag in OER, as far as I understand it.
                ident = "_ext_{0}{1}{2}".format(tag_class, 0, tag)
                val_bytes = ASN1CodecOER.decode_open_type(char)
                self._val = (ident, val_bytes)
            else:
                raise ASN1OERDecodeErr(
                    'CHOICE._from_oer: %s, unknown extension tag %r' \
                           % (self.fullname(), (tag_class, tag)))

    def _from_oer_ws(self, char):
        tag_class, tag, tag_struct = ASN1CodecOER.decode_tag_ws(char)
        try:
            tag_class = ASN1CodecOER.TagClassLUT[tag_class]
        except KeyError:
            ASN1OEREncodeErr("Unknown tag class: {0}".format(tag_class))

        _gen = [tag_struct]
        try:
            ident = self._cont_tags[(tag_class, tag)]
            Cho = self._cont[ident]
            _par = Cho._parent
            Cho._parent = self
            if self._ext and (ident in self._ext):
                val_bytes, val_struct = ASN1CodecOER.decode_open_type_ws(char)
                _gen.append(val_struct)
                Cho.from_oer_ws(val_bytes)
            if ident in self._root:
                Cho.from_oer_ws(char)
                _gen.extend(Cho._struct)
            Cho._parent = _par
            self._struct = Envelope(self._name, GEN=tuple(_gen) )
            self._val = (ident, Cho._val)
            return
        except KeyError:
            if self._ext is not None:
                # It's extension type
                if not self._SILENT:
                    asnlog('CHOICE._from_oer_ws: %s, unknown extension tag %r' \
                           % (self.fullname(), (tag_class, tag)))
                # NOTE: There is no way how to resolve the primitive/constructed
                #       flag in OER, as far as I understand it.
                ident = "_ext_{0}{1}{2}".format(tag_class, 0, tag)
                val_bytes, val_struct = ASN1CodecOER.decode_open_type_ws(char)
                _gen.append(val_struct)
                val = val_struct.get_val()
                self._struct = Envelope(self._name, GEN=tuple(_gen))
                self._val = (ident, val)
            else:
                raise ASN1OERDecodeErr(
                    'CHOICE._from_oer_ws: %s, unknown extension tag %r' \
                    % (self.fullname(), (tag_class, tag)))

#------------------------------------------------------------------------------#
# SEQUENCE and SET
#------------------------------------------------------------------------------#

class _CONSTRUCT(ASN1Obj):
    
    # this class implements the methods that are common to SEQ and SET
    
    def _safechk_val(self, val, rec=True):
        if not isinstance(val, dict):
            raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
        for k in val:
            if k in self._cont:
                if rec:
                    self._cont[k]._safechk_val(val[k])
            elif not re.match('_ext_[0-9]{1,}', k) or not isinstance(val[k], bytes_types):
                raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
        self._safechk_valcompl(val)
    
    def _safechk_valcompl(self, val):
        # check for OPTIONAL / DEFAULT root values
        if not all([k in val for k in self._root_mand]):
            raise(ASN1ObjErr('{0}: missing mandatory value, {1!r}'.format(self.fullname(), val)))
        # check for grouped extended values
        if self._ext and self._ext_group:
            # filter extended values in val
            ext = [k for k in val if k in self._ext]
            for e in ext:
                if e in self._ext_ident:
                    grp_id = self._ext_ident[e]
                    for ident, grp_comp in self._ext_group_obj[grp_id]._cont.items():
                        if not grp_comp._opt:
                            if ident not in ext:
                                raise(ASN1ObjErr('{0}: missing extended value for group {1}, {2!r}'\
                                      .format(self.fullname(), grp_id, val)))
                            else:
                                ext.remove(ident)
    
    def _safechk_bnd(self, val):
        for (name, Obj) in self._cont.items():
            if name in val:
                Obj._val = val[name]
                Obj._safechk_bnd(Obj._val)
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _to_asn1(self):
        if not self._val:
            # empty dict
            return '{ }'
        else:
            val = []
            # root and ext part in 1 shot
            # WNG: we are not ordering SET root components in canonical order
            for ident in self._cont:
                if ident in self._val:
                    _par = self._cont[ident]._parent
                    self._cont[ident]._parent = self
                    self._cont[ident]._val = self._val[ident]
                    val.append('  %s %s,\n' % (ident, self._cont[ident]._to_asn1().replace('\n', '\n  ')))
                    self._cont[ident]._parent = _par
            if val:
                val[-1] = val[-1][:-2]
            return '{\n' + ''.join(val) + '\n}'
    
    ###
    # conversion between internal value and ASN.1 PER encoding
    ###
    
    def _from_per_ws(self, char):
        GEN, self._val = [], {}
        if not self._cont and self._ext is None:
            # empty sequence
            self._struct = Envelope(self._name, GEN=tuple())
            return
        #
        extended = False
        if self._ext is not None:
            E = Uint('E', bl=1)
            E._from_char(char)
            GEN.append(E)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += 1
            if E():
                extended = True
        #
        # get the bitmap preambule for optional / default components of the root part
        if self._root_opt:
            opt_len = len(self._root_opt)
            B = Uint('B', bl=opt_len, rep=REPR_BIN)
            B._from_char(char)
            GEN.append(B)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += opt_len
            Bv = B()
            opt_idents = [self._root_opt[i] for i in range(opt_len) if Bv & (1<<(opt_len-1-i))]
        else:
            opt_idents = []
        #
        # decode components in the root part
        # or SET, use self._root_canon which is the canonical order of root components
        if self.TYPE == TYPE_SET:
            root_canon = self._root_canon
        else:
            root_canon = self._root
        for ident in root_canon:
            Comp = self._cont[ident]
            if ident in self._root_mand or ident in opt_idents:
                # component present in the encoding
                _par = Comp._parent
                Comp._parent = self
                Comp._from_per_ws(char)
                GEN.append(Comp._struct)
                self._val[ident] = Comp._val
                Comp._parent = _par
            elif Comp._def is not None and ASN1CodecPER.GET_DEFVAL:
                # component absent of the encoding, but with default value
                self._val[ident] = Comp._def
        #
        # decode components in the extension part
        if extended:
            # get the bitmap preambule for extended (group of) components
            # bitmap length is encoded with a normally small value
            big = Uint('big', bl=1)
            big._from_char(char)
            GEN.append(big)
            if big():
                # not so small value (>= 64)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                ldet, _gen = ASN1CodecPER.decode_intunconst_ws(char, 0, name='C')
                GEN.extend(_gen)
            else:
                nsv = Uint('C', bl=6)
                nsv._from_char(char)
                ldet = nsv()
                GEN.append(nsv)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 7
            ldet += 1
            # bitmap preambule
            B = Uint('B', bl=ldet, rep=REPR_BIN)
            B._from_char(char)
            GEN.append(B)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += ldet
                # realignment
                if ASN1CodecPER._off[-1] % 8:
                    GEN.extend( ASN1CodecPER.decode_pad_ws(char) )
            Bv = B()
            #
            for i in range(ldet):
                if Bv & (1<<(ldet-1-i)):
                    # extension present
                    if i < len(self._ext_nest):
                        # known extension
                        ext = self._ext_nest[i]
                        if isinstance(ext, list):
                            # grouped extension
                            Comp = self._ext_group_obj[self._ext_ident[ext[0]]]
                            val, _gen = ASN1CodecPER.decode_unconst_open_ws(char, wrapped=Comp)
                            self._val.update(val)
                        else:
                            # single extension, ident == ext
                            Comp = self._cont[ext]
                            _par = Comp._parent
                            Comp._parent = self
                            val, _gen = ASN1CodecPER.decode_unconst_open_ws(char, wrapped=Comp)
                            Comp._parent = _par
                            self._val[ext] = val
                    else:
                        # unknown extension
                        buf, _gen = ASN1CodecPER.decode_unconst_open_ws(char)
                        self._val['_ext_%r' % i] = buf
                    GEN.extend(_gen)
        #
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return
    
    def _from_per(self, char):
        GEN, self._val = [], {}
        if not self._cont and self._ext is None:
            # empty sequence
            return
        #
        extended = False
        if self._ext is not None:
            E = char.get_uint(1)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += 1
            if E:
                extended = True
        #
        # get the bitmap preambule for optional / default components of the root part
        if self._root_opt:
            opt_len = len(self._root_opt)
            Bv = char.get_uint(opt_len)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += opt_len
            opt_idents = [self._root_opt[i] for i in range(opt_len) if Bv & (1<<(opt_len-1-i))]
        else:
            opt_idents = []
        #
        # decode components in the root part
        # for SET, use self._root_canon which is the canonical order of root components
        if self.TYPE == TYPE_SET:
            root_canon = self._root_canon
        else:
            root_canon = self._root
        for ident in root_canon:
            Comp = self._cont[ident]
            if ident in self._root_mand or ident in opt_idents:
                # component present in the encoding
                _par = Comp._parent
                Comp._parent = self
                Comp._from_per(char)
                self._val[ident] = Comp._val
                Comp._parent = _par
            elif Comp._def is not None and ASN1CodecPER.GET_DEFVAL:
                # component absent of the encoding, but with default value
                self._val[ident] = Comp._def
        #
        # decode components in the extension part
        if extended:
            # get the bitmap preambule for extended (group of) components
            # bitmap length is encoded with a normally small value
            big = char.get_uint(1)
            if big:
                # not so small value (>= 64)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                ldet = 1 + ASN1CodecPER.decode_intunconst(char, 0)
            else:
                ldet = 1 + char.get_uint(6)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 7
            # bitmap preambule
            Bv = char.get_uint(ldet)
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += ldet
                # realignment
                if ASN1CodecPER._off[-1] % 8:
                    ASN1CodecPER.decode_pad(char)
            #
            for i in range(ldet):
                if Bv & (1<<(ldet-1-i)):
                    # extension present
                    if i < len(self._ext_nest):
                        # known extension
                        ext = self._ext_nest[i]
                        if isinstance(ext, list):
                            # grouped extension
                            Comp = self._ext_group_obj[self._ext_ident[ext[0]]]
                            self._val.update(ASN1CodecPER.decode_unconst_open(char, wrapped=Comp))
                        else:
                            # single extension, ident == ext
                            Comp = self._cont[ext]
                            _par = Comp._parent
                            Comp._parent = self
                            self._val[ext] = ASN1CodecPER.decode_unconst_open(char, wrapped=Comp)
                            Comp._parent = _par
                    else:
                        # unknown extension
                        self._val['_ext_%r' % i] = ASN1CodecPER.decode_unconst_open(char)
        #
        return
    
    def _to_per_ws(self):
        GEN = []
        if not self._cont and self._ext is None:
            # empty sequence
            self._struct = Envelope(self._name, GEN=tuple())
            return self._struct
        #
        extended = False
        if self._ext is not None:
            # check if some extended components are provided
            for k in self._val:
                if k in self._ext or k[:5] == '_ext_':
                    extended = True
                    break
            if extended:
                GEN.append( Uint('E', val=1, bl=1) )
            else:
                GEN.append( Uint('E', val=0, bl=1) )
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += 1
        #    
        # generate the bitmap preambule for optional / default components of the root part
        if self._root_opt:
            opt_len, opt_idents, Bv = len(self._root_opt), [], 0
            for i in range(opt_len):
                ident = self._root_opt[i]
                if ident in self._val:
                    if ASN1CodecPER.CANONICAL and self._val[ident] == self._cont[ident]._def:
                        # the value provided equals the default one
                        # hence will not be encoded
                        if not self._SILENT:
                            asnlog('_CONSTRUCT._to_per_ws: %s.%s, removing value equal '\
                                   'to the default one' % (self.fullname(), ident))
                        del self._val[ident]
                    else:
                        # component present in the encoding
                        Bv += 1<<(opt_len-1-i)
                        opt_idents.append(ident)
            # encoding the bitmap value
            GEN.append( Uint('B', val=Bv, bl=opt_len, rep=REPR_BIN) )
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += opt_len
        else:
            opt_idents = []
        #
        # encode components in the root part
        if self.TYPE == TYPE_SET:
            root_canon = self._root_canon
        else:
            root_canon = self._root
        for ident in root_canon:
            if ident in self._val:
                # component present in the encoding
                Comp = self._cont[ident]
                _par = Comp._parent
                Comp._parent = self
                Comp._val = self._val[ident]
                GEN.append( Comp._to_per_ws() )
                Comp._parent = _par
        #
        # encode components in the extension part
        if extended:
            # generate the structure for all known present extension
            _gen_ext, Bm, cnt = [], [], 1
            for ident in self._ext_nest:
                if isinstance(ident, list):
                    # group of extension
                    grp_val, gid = {}, None
                    for ident_inner in ident:
                        if ident_inner in self._val:
                            grp_val[ident_inner] = self._val[ident_inner]
                            if gid is None:
                                gid = self._ext_ident[ident_inner]
                    if grp_val:
                        # group present in the encoding
                        Comp = self._ext_group_obj[gid]
                        Comp._val = grp_val
                        _gen_ext.extend( ASN1CodecPER.encode_unconst_open_ws(Comp) )
                        Bm.append(cnt)
                else:
                    if ident in self._val:
                        # single extension present in the encoding
                        Comp = self._cont[ident]
                        _par = Comp._parent
                        Comp._parent = self
                        Comp._val = self._val[ident]
                        _gen_ext.extend( ASN1CodecPER.encode_unconst_open_ws(Comp) )
                        Comp._parent = _par
                        Bm.append(cnt)
                cnt += 1
            #
            # generate the structure for all unknown present extension
            unk_idents = [i for i in self._val if i[:5] == '_ext_']
            if unk_idents:
                # sort by index set to the ident
                unk_idents.sort(key=lambda x:int(x[5:]))
                for ident in unk_idents:
                    ind = int(ident[5:])
                    if ind >= cnt and ind not in Bm:
                        _gen_ext.extend( ASN1CodecPER.encode_unconst_buf_ws(self._val[ident]) )
                        Bm.append(ind)
                    elif not self._SILENT:
                        asnlog('_CONSTRUCT._to_per_ws: %s.%s, invalid unknown extension index'\
                               % (self.fullname(), ident))
            #
            if not Bm:
                self._struct = Envelope(self._name, GEN=tuple(GEN))
                return self._struct
            # generate the bitmap preambule for extended (group of) components
            # bitmap length is encoded with a normally small value
            ldet = max(Bm)
            if len(self._ext_nest) > ldet:
                ldet = len(self._ext_nest)
            if ldet > 64:
                # not so small value
                GEN.append( Uint('big', val=1, bl=1) )
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                GEN.extend( ASN1CodecPER.encode_intunconst_ws(ldet-1, 0, name='C') )
            else:
                GEN.extend( (Uint('big', val=0, bl=1), Uint('C', val=ldet-1, bl=6)) )
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 7
            # bitmap preambule
            GEN.append( Uint('B', val=sum([1<<(ldet-i) for i in Bm]), bl=ldet, rep=REPR_BIN) )
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += ldet
                if ASN1CodecPER._off[-1] % 8:
                    # realignment
                    GEN.extend( ASN1CodecPER.encode_pad_ws() )
            # finally concat with all encoded extensions
            GEN.extend(_gen_ext)
        #
        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return self._struct
    
    def _to_per(self):
        GEN = []
        if not self._cont and self._ext is None:
            # empty sequence
            return GEN
        #
        extended = False
        if self._ext is not None:
            # check if some extended components are provided
            for k in self._val:
                if k in self._ext or k[:5] == '_ext_':
                    extended = True
                    break
            if extended:
                GEN.append( (T_UINT, 1, 1) )
            else:
                GEN.append( (T_UINT, 0, 1) )
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += 1
        #    
        # generate the bitmap preambule for optional / default components of the root part
        if self._root_opt:
            opt_len, opt_idents, Bv = len(self._root_opt), [], 0
            for i in range(opt_len):
                ident = self._root_opt[i]
                if ident in self._val:
                    if ASN1CodecPER.CANONICAL and self._val[ident] == self._cont[ident]._def:
                        # the value provided equals the default one
                        # hence will not be encoded
                        if not self._SILENT:
                            asnlog('_CONSTRUCT._to_per: %s.%s, removing value equal '\
                                   'to the default one' % (self.fullname(), ident))
                        del self._val[ident]
                    else:
                        # component present in the encoding
                        Bv += 1<<(opt_len-1-i)
                        opt_idents.append(ident)
            # encoding the bitmap value
            GEN.append( (T_UINT, Bv, opt_len) )
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += opt_len
        else:
            opt_idents = []
        #
        # encode components in the root part
        if self.TYPE == TYPE_SET:
            root_canon = self._root_canon
        else:
            root_canon = self._root
        for ident in root_canon:
            if ident in self._val:
                # component present in the encoding
                Comp = self._cont[ident]
                _par = Comp._parent
                Comp._parent = self
                Comp._val = self._val[ident]
                GEN.extend( Comp._to_per() )
                Comp._parent = _par
        #
        # encode components in the extension part
        if extended:
            # generate the structure for all known present extension
            _gen_ext, Bm, cnt = [], [], 1
            for ident in self._ext_nest:
                if isinstance(ident, list):
                    # group of extension
                    grp_val, gid = {}, None
                    for ident_inner in ident:
                        if ident_inner in self._val:
                            grp_val[ident_inner] = self._val[ident_inner]
                            if gid is None:
                                gid = self._ext_ident[ident_inner]
                    if grp_val:
                        # group present in the encoding
                        Comp = self._ext_group_obj[gid]
                        Comp._val = grp_val
                        _gen_ext.extend( ASN1CodecPER.encode_unconst_open(Comp) )
                        Bm.append(cnt)
                else:
                    if ident in self._val:
                        # single extension
                        Comp = self._cont[ident]
                        _par = Comp._parent
                        Comp._parent = self
                        Comp._val = self._val[ident]
                        _gen_ext.extend( ASN1CodecPER.encode_unconst_open(Comp) )
                        Comp._parent = _par
                        Bm.append(cnt)
                cnt += 1
            #
            # generate the structure for all unknown present extension
            unk_idents = [i for i in self._val if i[:5] == '_ext_']
            if unk_idents:
                # sort by index set to the ident
                unk_idents.sort(key=lambda x:int(x[5:]))
                for ident in unk_idents:
                    ind = int(ident[5:])
                    if ind >= cnt and ind not in Bm:
                        _gen_ext.extend( ASN1CodecPER.encode_unconst_buf(self._val[ident]) )
                        Bm.append(ind)
                    elif not self._SILENT:
                        asnlog('_CONSTRUCT._to_per: %s.%s, invalid unknown extension index'\
                               % (self.fullname(), ident))
            #
            if not Bm:
                return GEN
            # generate the bitmap preambule for extended (group of) components
            # bitmap length is encoded with a normally small value
            ldet = max(Bm)
            if len(self._ext_nest) > ldet:
                ldet = len(self._ext_nest)
            if ldet > 64:
                # not so small value
                GEN.append( (T_UINT, 1, 1) )
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                GEN.extend( ASN1CodecPER.encode_intunconst(ldet-1, 0) )
            else:
                GEN.append( (T_UINT, ldet-1, 7) )
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 7
            # bitmap preambule
            GEN.append( (T_UINT, sum([1<<(ldet-i) for i in Bm]), ldet) )
            if ASN1CodecPER.ALIGNED:
                ASN1CodecPER._off[-1] += ldet
                if ASN1CodecPER._off[-1] % 8:
                    # realignment
                    GEN.extend( ASN1CodecPER.encode_pad() )
            # finally concat with all encoded extensions
            GEN.extend(_gen_ext)
        #
        return GEN
    
    ###
    # conversion between internal value and ASN.1 JER encoding
    ###
    
    if _with_json:
        
        def _from_jval(self, val):
            if not isinstance(val, dict):
                raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                      .format(self.fullname(), val)))
            self._val, val_cp = {}, dict(val)
            for ident, Comp in self._cont.items():
                if ident in val:
                    _par = Comp._parent
                    Comp._parent = self
                    Comp._from_jval( val[ident] )
                    Comp._parent = _par
                    self._val[ident] = Comp._val
                    del val_cp[ident]
            if val_cp:
                for ident, comp_val in val_cp.items():
                    self._val['_ext_%s' % ident] = comp_val
            try:
                self._safechk_val(self._val, rec=False)
            except Exception as err:
                raise(ASN1JERDecodeErr('{0}: invalid json value, {1}'\
                      .format(self.fullname(), err)))
        
        def _to_jval(self):
            if not self._val:
                return {}
            else:
                ret, val = {}, dict(self._val)
                for ident in self._cont:
                    if ident in val:
                        _par = self._cont[ident]._parent
                        self._cont[ident]._parent = self
                        self._cont[ident]._val = val[ident]
                        ret[ident] = self._cont[ident]._to_jval()
                        self._cont[ident]._parent = _par
                        del val[ident]
                if val:
                    # unknown extended components are there too
                    for ident, comp_val in val.items():
                        ret['_ext_%s' % ident] = comp_val
                return ret

    ###
    # conversion between internal value and ASN.1 OER/COER encoding
    ###

    def _to_oer(self):
        GEN = []
        if not self._cont and self._ext is None:
            # empty sequence
            return GEN

        extended = False
        ext_bit = 0
        if self._ext is not None:
            # check if some extended components are provided
            for k in self._val:
                if k in self._ext or k[:5] == '_ext_':
                    extended = True
                    break

            GEN.append((T_UINT, (1 if extended else 0), 1))
            ext_bit = 1

        # generate the bitmap preambule for optional / default components of the root part
        opt_len = 0
        Bv = 0
        if self._root_opt:
            opt_len, opt_idents = len(self._root_opt), []
            for i in range(opt_len):
                ident = self._root_opt[i]
                if ident in self._val:
                    if self._val[ident] == self._cont[ident]._def:
                        # the value provided equals the default one
                        # hence will not be encoded
                        if not self._SILENT:
                            asnlog('_CONSTRUCT._to_oer: %s.%s, removing value equal ' \
                                   'to the default one' % (self.fullname(), ident))
                        del self._val[ident]
                    else:
                        # component present in the encoding
                        Bv += 1<<(opt_len-1-i)
                        opt_idents.append(ident)
        else:
            opt_idents = []

        # Padding bits
        pad_bits = 8 - ((opt_len + ext_bit) % 8)
        pad_bits = 0 if (pad_bits == 8) else pad_bits
        Bv = Bv << pad_bits
        GEN.append( (T_UINT, Bv, opt_len + pad_bits) )

        # encode components in the root part
        if self.TYPE == TYPE_SET:
            root_canon = self._root_canon
        else:
            root_canon = self._root
        for ident in root_canon:
            if ident in self._val:
                # component present in the encoding
                Comp = self._cont[ident]
                _par = Comp._parent
                Comp._parent = self
                Comp._val = self._val[ident]
                GEN.extend( Comp._to_oer() )
                Comp._parent = _par

        # encode components in the extension part
        if extended:
            # generate the structure for all known present extension
            _gen_ext, Bm, cnt = [], [], 1
            for ident in self._ext_nest:
                if isinstance(ident, list):
                    # group of extension
                    grp_val, gid = {}, None
                    for ident_inner in ident:
                        if ident_inner in self._val:
                            grp_val[ident_inner] = self._val[ident_inner]
                            if gid is None:
                                gid = self._ext_ident[ident_inner]
                    if grp_val:
                        # group present in the encoding
                        Comp = self._ext_group_obj[gid]
                        Comp._val = grp_val
                        _gen_ext.extend( ASN1CodecOER.encode_open_type(
                            Comp.to_oer() ))
                        Bm.append(cnt)
                else:
                    if ident in self._val:
                        # single extension
                        Comp = self._cont[ident]
                        _par = Comp._parent
                        Comp._parent = self
                        Comp._val = self._val[ident]
                        _gen_ext.extend( ASN1CodecOER.encode_open_type(
                            Comp.to_oer()))
                        Comp._parent = _par
                        Bm.append(cnt)
                cnt += 1

            # generate the structure for all unknown present extension
            unk_idents = [i for i in self._val if i[:5] == '_ext_']
            if unk_idents:
                # sort by index set to the ident
                unk_idents.sort(key=lambda x:int(x[5:]))
                for ident in unk_idents:
                    ind = int(ident[5:])
                    if ind >= cnt and ind not in Bm:
                        _gen_ext.extend( ASN1CodecOER.encode_open_type(
                            self._val[ident]) )
                        Bm.append(ind)
                    elif not self._SILENT:
                        asnlog('_CONSTRUCT._to_oer: %s.%s, '
                               'invalid unknown extension index' \
                               % (self.fullname(), ident))

            if not Bm:
                return GEN

            # generate the bitmap preambule for extended (group of) components
            # bitmap length is encoded with a normally small value
            ldet = max(max(Bm), len(self._ext_nest))
            ext_bitmap = 0
            for i in Bm:
                ext_bitmap = ext_bitmap | (1<<(ldet-i))
            pad_bits = uint_bytelen(ext_bitmap)*8 - ldet
            ext_bitmap = ext_bitmap << pad_bits
            ext_bmp_len = pad_bits + ldet
            GEN.extend(ASN1CodecOER.encode_length_determinant(1 +
                                                              ext_bmp_len//8))
            GEN.append( (T_UINT, pad_bits, 8) )
            GEN.append( (T_UINT, ext_bitmap, ext_bmp_len) )
            GEN.extend(_gen_ext)

        return GEN

    def _to_oer_ws(self):
        GEN = []
        if not self._cont and self._ext is None:
            # empty sequence
            return GEN

        extended = False
        ext_bit = 0
        if self._ext is not None:
            # check if some extended components are provided
            for k in self._val:
                if k in self._ext or k[:5] == '_ext_':
                    extended = True
                    break

            GEN.append(Uint('Extension', val=(1 if extended else 0), bl=1))
            ext_bit = 1

        # generate the bitmap preambule for optional / default components of the root part
        opt_len = 0
        Bv = 0
        if self._root_opt:
            opt_len, opt_idents = len(self._root_opt), []
            for i in range(opt_len):
                ident = self._root_opt[i]
                if ident in self._val:
                    if self._val[ident] == self._cont[ident]._def:
                        # the value provided equals the default one
                        # hence will not be encoded
                        if not self._SILENT:
                            asnlog('_CONSTRUCT._to_oer: %s.%s, removing value equal ' \
                                   'to the default one' % (self.fullname(), ident))
                        del self._val[ident]
                    else:
                        # component present in the encoding
                        Bv += 1<<(opt_len-1-i)
                        opt_idents.append(ident)
        else:
            opt_idents = []

        # Padding bits
        pad_bits = 8 - ((opt_len + ext_bit) % 8)
        pad_bits = 0 if (pad_bits == 8) else pad_bits
        Bv = Bv << pad_bits
        GEN.append( Uint('Root-Bmp', val=Bv, bl=opt_len + pad_bits) )

        GEN = [Envelope('Preamble', GEN=tuple(GEN))]

        # encode components in the root part
        if self.TYPE == TYPE_SET:
            root_canon = self._root_canon
        else:
            root_canon = self._root
        for ident in root_canon:
            if ident in self._val:
                # component present in the encoding
                Comp = self._cont[ident]
                _par = Comp._parent
                Comp._parent = self
                Comp._val = self._val[ident]
                GEN.append( Comp._to_oer_ws() )
                Comp._parent = _par

        # encode components in the extension part
        if extended:
            # generate the structure for all known present extension
            _gen_ext, Bm, cnt = [], [], 1
            for ident in self._ext_nest:
                if isinstance(ident, list):
                    # group of extension
                    grp_val, gid = {}, None
                    for ident_inner in ident:
                        if ident_inner in self._val:
                            grp_val[ident_inner] = self._val[ident_inner]
                            if gid is None:
                                gid = self._ext_ident[ident_inner]
                    if grp_val:
                        # group present in the encoding
                        Comp = self._ext_group_obj[gid]
                        Comp._val = grp_val
                        _gen_ext.append( ASN1CodecOER.encode_open_type_ws(
                            Comp.to_oer() ))
                        Bm.append(cnt)
                else:
                    if ident in self._val:
                        # single extension
                        Comp = self._cont[ident]
                        _par = Comp._parent
                        Comp._parent = self
                        Comp._val = self._val[ident]
                        _gen_ext.append( ASN1CodecOER.encode_open_type_ws(
                            Comp.to_oer()))
                        Comp._parent = _par
                        Bm.append(cnt)
                cnt += 1

            # generate the structure for all unknown present extension
            unk_idents = [i for i in self._val if i[:5] == '_ext_']
            if unk_idents:
                # sort by index set to the ident
                unk_idents.sort(key=lambda x:int(x[5:]))
                for ident in unk_idents:
                    ind = int(ident[5:])
                    if ind >= cnt and ind not in Bm:
                        _gen_ext.append( ASN1CodecOER.encode_open_type_ws(
                            self._val[ident]) )
                        Bm.append(ind)
                    elif not self._SILENT:
                        asnlog('_CONSTRUCT._to_oer: %s.%s, '
                               'invalid unknown extension index' \
                               % (self.fullname(), ident))

            if not Bm:
                self._struct = Envelope(self._name, GEN=tuple(GEN))
                return self._struct

            # generate the bitmap preambule for extended (group of) components
            # bitmap length is encoded with a normally small value
            ldet = max(max(Bm), len(self._ext_nest))
            ext_bitmap = 0
            for i in Bm:
                ext_bitmap = ext_bitmap | (1<<(ldet-i))
            pad_bits = uint_bytelen(ext_bitmap)*8 - ldet
            ext_bitmap = ext_bitmap << pad_bits
            ext_bmp_len = pad_bits + ldet
            ext_bmp_struct = []
            ext_bmp_struct.append(ASN1CodecOER.encode_length_determinant_ws(1 +
                                                              ext_bmp_len//8))
            ext_bmp_struct.append( Uint('Initial-octet', val=pad_bits, bl=8) )
            ext_bmp_struct.append( Uint('Bitmap', val=ext_bitmap,
                                        bl=ext_bmp_len) )
            ext_bmp_struct = Envelope('Extension-bmp',
                                      GEN=tuple(ext_bmp_struct))
            GEN.append(ext_bmp_struct)
            GEN.extend(_gen_ext)

        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return self._struct

    def _from_oer(self, char):
        GEN, self._val = [], {}
        if not self._cont and self._ext is None:
            # empty sequence
            return

        extended = False
        ext_bit = 0
        if self._ext is not None:
            extended = (1 == char.get_uint(1))
            ext_bit = 1

        # get the bitmap preambule for optional / default components of the root part
        if self._root_opt:
            opt_len = len(self._root_opt)
            Bv = char.get_uint(opt_len)
            opt_idents = [self._root_opt[i] for i in range(opt_len) if Bv & (1<<(opt_len-1-i))]
        else:
            opt_len = 0
            opt_idents = []

        # Get the padding bits
        pad_bits = 8 - ((opt_len + ext_bit) % 8)
        pad_bits = 0 if (pad_bits == 8) else pad_bits
        char.get_uint(pad_bits)

        # decode components in the root part
        # for SET, use self._root_canon which is the canonical order of root components
        if self.TYPE == TYPE_SET:
            root_canon = self._root_canon
        else:
            root_canon = self._root
        for ident in root_canon:
            Comp = self._cont[ident]
            if ident in self._root_mand or ident in opt_idents:
                # component present in the encoding
                _par = Comp._parent
                Comp._parent = self
                Comp._from_oer(char)
                self._val[ident] = Comp._val
                Comp._parent = _par
            elif Comp._def is not None and ASN1CodecOER.GET_DEFVAL:
                # component absent of the encoding, but with default value
                self._val[ident] = Comp._def

        # decode components in the extension part
        if extended:
            # get the bitmap preambule for extended (group of) components
            ldet = ASN1CodecOER.decode_length_determinant(char)
            pad_bits = char.get_uint(8)
            ldet = (ldet - 1) * 8
            Bv = char.get_uint(ldet)
            Bv = Bv >> pad_bits
            ldet = ldet - pad_bits

            for i in range(ldet):
                if Bv & (1<<(ldet-1-i)):
                    # extension present
                    if i < len(self._ext_nest):
                        # known extension
                        ext = self._ext_nest[i]
                        if isinstance(ext, list):
                            # grouped extension
                            Comp = self._ext_group_obj[self._ext_ident[ext[0]]]
                            val_bytes = ASN1CodecOER.decode_open_type(char)
                            if Comp:
                                Comp.from_oer(val_bytes)
                                self._val.update(Comp._val)
                            else:
                                self._val.update(val_bytes)
                        else:
                            # single extension, ident == ext
                            Comp = self._cont[ext]
                            _par = Comp._parent
                            Comp._parent = self
                            Comp.from_oer(ASN1CodecOER.decode_open_type(char))
                            self._val[ext] = Comp._val
                            Comp._parent = _par
                    else:
                        # unknown extension
                        self._val['_ext_%r' % i] = \
                            ASN1CodecOER.decode_open_type(char)
        return

    def _from_oer_ws(self, char):
        GEN, self._val = [], {}
        if not self._cont and self._ext is None:
            # empty sequence
            return

        extended = False
        ext_bit = 0
        if self._ext is not None:
            extension = Uint('Extension', bl=1)
            extension._from_char(char)
            GEN.append(extension)
            extended = (1 == extension.get_val())
            ext_bit = 1

        # get the bitmap preambule for optional / default components of the root part
        opt_len = len(self._root_opt) if self._root_opt else 0
        pad_bits = 8 - ((opt_len + ext_bit) % 8)
        pad_bits = 0 if (pad_bits == 8) else pad_bits

        root_bmp = Uint('Root-bmp', bl=opt_len+pad_bits)
        root_bmp._from_char(char)
        GEN.append(root_bmp)

        if self._root_opt:
            Bv = root_bmp.get_val() >> pad_bits
            opt_idents = [self._root_opt[i] for i in range(opt_len) if Bv & (1<<(opt_len-1-i))]
        else:
            opt_len = 0
            opt_idents = []

        GEN = [Envelope('Preamble', GEN=tuple(GEN))]

        # decode components in the root part
        # for SET, use self._root_canon which is the canonical order of root components
        if self.TYPE == TYPE_SET:
            root_canon = self._root_canon
        else:
            root_canon = self._root
        for ident in root_canon:
            Comp = self._cont[ident]
            if ident in self._root_mand or ident in opt_idents:
                # component present in the encoding
                _par = Comp._parent
                Comp._parent = self
                Comp._from_oer_ws(char)
                self._val[ident] = Comp._val
                GEN.append(Comp._struct)
                Comp._parent = _par
            elif Comp._def is not None and ASN1CodecOER.GET_DEFVAL:
                # component absent of the encoding, but with default value
                self._val[ident] = Comp._def

        # decode components in the extension part
        if extended:
            # get the bitmap preambule for extended (group of) components
            ldet, ldet_struct = ASN1CodecOER.decode_length_determinant_ws(char)
            i_oct = Uint('Initial-octet', bl=8)
            i_oct._from_char(char)
            pad_bits = i_oct.get_val()
            ldet = (ldet - 1) * 8
            ext_bmp = Uint('Bitmap', bl=ldet)
            ext_bmp._from_char(char)
            Bv = ext_bmp.get_val()
            Bv = Bv >> pad_bits
            ldet = ldet - pad_bits

            GEN.append(Envelope('Extension-bmp',
                                GEN=(ldet_struct, i_oct, ext_bmp)))

            for i in range(ldet):
                if Bv & (1<<(ldet-1-i)):
                    # extension present
                    if i < len(self._ext_nest):
                        # known extension
                        ext = self._ext_nest[i]
                        if isinstance(ext, list):
                            # grouped extension
                            Comp = self._ext_group_obj[self._ext_ident[ext[0]]]
                            val_bytes, _struct = \
                                ASN1CodecOER.decode_open_type_ws(char)
                            if Comp:
                                Comp.from_oer(val_bytes)
                                self._val.update(Comp._val)
                            else:
                                self._val.update(val_bytes)
                            GEN.append(_struct)
                        else:
                            # single extension, ident == ext
                            Comp = self._cont[ext]
                            _par = Comp._parent
                            Comp._parent = self
                            val_bytes, _struct = \
                                ASN1CodecOER.decode_open_type_ws(char)
                            Comp.from_oer(val_bytes)
                            self._val[ext] = Comp._val
                            Comp._parent = _par
                            GEN.append(_struct)
                    else:
                        # unknown extension
                        val_bytes, _struct = \
                            ASN1CodecOER.decode_open_type_ws(char)
                        self._val['_ext_%r' % i] = val_bytes
                        GEN.append(_struct)

        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return


class SEQ(_CONSTRUCT):
    __doc__ = """
ASN.1 constructed type SEQUENCE object

Single value: Python dict
    keys are Python str, components' identifier, must be key in _cont
    values are ASN1Obj single value specific to components object
    
    special case is the "_ext_$ind" key which encodes an unknown 
    extension with index $ind, then the corresponding value must be a Python bytes

Specific attributes:
    
    - cont: ASN1Dict {ident (str): ASN1Obj instance},
        provides the content of the CHOICE object
    
    - cont_tags: dict with {tag (int): identifier (str)},
        provides a lookup table for tag value to components
    
    - root_mand: list of identifiers (str),
        provides the list of mandatory components in the root part
    
    - root_opt: list of identifiers (str),
        provides the list of optional components in the root part
    
    - ext_ident: dict with {identifier (str) : ext group index (int)},
        for grouped extended components
    
    - ext_group: dict with {ext group index (int) : list of identifiers (str)},
        for grouped extended components
    
    - ext_group_obj: dict with {ext group index (int): SEQ ASN1Obj instance},
        provides virtual SEQUENCE instance for each group of extended components
    
    - ext_nest: list, each item being a str (extension ident) or list of str 
        (group of extension idents)
%s
""" % ASN1Obj_docstring
    
    TYPE  = TYPE_SEQ
    TAG   = 16
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        if hasattr(self, '_gext'):
            self._val = {}
        else:
            if txt[0:1] != '{':
                raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                      .format(self.fullname(), txt)))
            txt, self._val = txt[1:].strip(), {}
        done = False if self._root_mand else True
        # empty sequence
        if done and txt[0:1] == '}':
            return txt[1:].strip()
        try:
            t_ident, t_rest = txt.split(' ', 1)
        except Exception:
            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                  .format(self.fullname(), txt)))
        val = self._val
        # root part
        for ident in self._root:
            if not done and ident == self._root_mand[-1]:
                done = True
            if t_ident == ident:
                _par = self._cont[ident]._parent
                self._cont[ident]._parent = self
                txt = self._cont[ident]._from_asn1(t_rest)
                val[ident] = self._cont[ident]._val
                self._cont[ident]._parent = _par
                if txt[0:1] == ',':
                    txt = txt[1:].strip()
                    try:
                        t_ident, t_rest = txt.split(' ', 1)
                    except Exception:
                        raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                              .format(self.fullname(), txt)))
                elif txt[0:1] == '}':
                    if done:
                        self._val = val
                        if hasattr(self, '_gext'):
                            return txt
                        else:
                            return txt[1:].strip()
                    else:
                        raise(ASN1ASNDecodeErr(
                              '{0}: missing mandatory value text, {1!r}'\
                              .format(self.fullname(), txt)))
                else:
                    raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                          .format(self.fullname(), txt)))
            elif ident in self._root_mand:
                raise(ASN1ASNDecodeErr('{0}: missing mandatory value text, {1!r}'\
                      .format(self.fullname(), txt)))
        # special case for grouped extension
        if hasattr(self, '_gext'):
            self._val = val
            return ', ' + txt
        # ext part
        if self._ext:
            i = 0
            while i < len(self._ext):
                ident = self._ext[i]
                if t_ident == ident:
                    if ident in self._ext_ident:
                        # 1st component of a grouped extension
                        GSeq = self._ext_group_obj[self._ext_ident[ident]]
                        txt = GSeq._from_asn1(txt)
                        val.update(GSeq._val)
                        i += len(GSeq._cont)
                    else:
                        # independent extension
                        _par = self._cont[ident]._parent
                        self._cont[ident]._parent = self
                        txt = self._cont[ident]._from_asn1(t_rest)
                        val[ident] = self._cont[ident]._val
                        self._cont[ident]._parent = _par
                        i += 1
                    if txt[0:1] == ',':
                        txt = txt[1:].strip()
                        try:
                            t_ident, t_rest = txt.split(' ', 1)
                        except Exception:
                            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                                  .format(self.fullname(), txt)))
                    elif txt[0:1] == '}':
                        self._val = val
                        return txt[1:].strip()
                    else:
                        raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                              .format(self.fullname(), txt)))
                else:
                    # jump over the single or group of extension
                    if ident in self._ext_ident:
                        i += len(self._ext_group[self._ext_ident[ident]])
                    else:
                        i += 1      
        # end of content
        if txt[0:1] == '}':
            return txt[1:].strip()
        elif self._ext is not None:
            raise(ASN1ASNDecodeErr('{0}: unknown extension, {1!r}'\
                  .format(self.fullname(), txt)))
        else:
            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                  .format(self.fullname(), txt))) 
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_ber_cont_ws(self, char, tlv):
        # tlv: list of list of tag, length and value corresponding to the SEQUENCE
        if not isinstance(tlv, list):
            raise(ASN1BERDecodeErr('{0}: invalid SEQUENCE primitive structure'\
                  .format(self.fullname())))
        #
        # 1) init the local value and structure
        self._val, TLV, ind, eoc = {}, [], 0, False
        if not tlv:
            # empty tlv, ensure there is no mandatory components
            if self._root_mand:
                raise(ASN1BERDecodeErr('{0}: missing mandatory component, {1!r}'\
                      .format(self.fullname(), self._root_mand)))
            else:
                return Envelope('V', GEN=tuple(TLV))
        #
        Tag, cl, pc, tval, Len, lval = tlv[ind][0:6]
        tag = (cl, tval)
        # list of decoded components
        dec = []
        #
        # 2) get over all components within the SEQUENCE content 1 by 1
        #    check if it corresponds to the current tlv
        #    decode the component
        for Comp in self._cont.values():
            #
            next = False
            if (cl, pc, tval, lval) == (0, 0, 0, 0):
                # EOC marker
                eoc = True
                break
            #
            else:
                m = match_tag(Comp, tag)
                if m == 1:
                    next = True
                elif m > 1:
                    # hack: in case content is not extensible and Comp is the last
                    # component of the content, we can consider it present
                    if Comp._name == self._cont._index[-1] and self._ext is None:
                        next = True
                    else:
                        if not self._SILENT:
                            asnlog('SEQUENCE._decode_ber_cont_ws: %s, unable to determine '\
                                   'if component %s is present (err %i)' % (self.fullname(), Comp._name, m))
                        if Comp._name in self._root_mand:
                            # component is mandatory, so we will still try to decode it
                            next = True
            #
            if next:
                # 3) decode the current component
                _par = Comp._parent
                Comp._parent = self
                Comp._from_ber_ws(char, [tlv[ind]])
                Comp._parent = _par
                self._val[Comp._name] = Comp._val
                TLV.append(Comp._struct)
                dec.append(Comp._name)
                # get next tlv
                ind += 1
                if ind < len(tlv):
                    Tag, cl, pc, tval, Len, lval = tlv[ind][0:6]
                    tag = (cl, tval)
                else:
                    # no more tlv to consume
                    break
        #
        # checks for error in the decoded structure
        for mandcomp in self._root_mand:
            if mandcomp not in dec:
                raise(ASN1BERDecodeErr('{0}: missing mandatory component, {1}'\
                      .format(self.fullname(), mandcomp)))
        if eoc and ind < len(tlv)-1:
            raise(ASN1BERDecodeErr('{0}: invalid EOC marker in between TLV components'\
                  .format(self.fullname())))
        #
        # 4) decode unknown provided extensions
        elif ind < len(tlv)-1 and self._ext is None:
            raise(ASN1BERDecodeErr('{0}: invalid extension to be decoded, {1!r}'\
                  .format(self.fullname(), tlv[ind])))
        while ind < len(tlv)-1:
            Tag, cl, pc, tval, Len, lval = tlv[ind][0:6]
            if (cl, pc, tval, lval) == (0, 0, 0, 0) and ind < len(tlv)-1:
                raise(ASN1BERDecodeErr('{0}: invalid EOC marker in between TLV components'\
                      .format(self.fullname())))
            else:
                if not self._SILENT:
                    asnlog('SEQUENCE._decode_ber_cont_ws: %s, unknown extension tag %r'\
                           % (self.fullname(), (cl, tval)))
                ident = '_ext_%i%i%i' % (cl, pc, tval)
                if pc == 1:
                    # constructed object
                    val = ASN1CodecBER.scan_tlv_ws(char, tlv[ind])
                    TLV.append( Envelope(ident, GEN=(Tag, Len, 
                                         Buf('V', val=val, bl=8*len(val), rep=REPR_HEX))) )
                elif lval >= 0:
                    # primitive object
                    char._cur = tlv[ind][6][0]
                    Val = Buf('V', bl=8*lval, rep=REPR_HEX)
                    Val._from_char(char)
                    val = Val.to_bytes()
                    TLV.append( Envelope(ident, GEN=(Tag, Len, Val)) )
                else:
                    raise(ASN1BERDecodeErr('{0}: invalid SEQUENCE extended tag and length, {1!r}, {2!r}'\
                          .format(self.fullname(), (cl, pc, tval), lval)))
                self._val[ident] = val
            ind += 1
        #
        return Envelope('V', GEN=tuple(TLV))
    
    def _decode_ber_cont(self, char, tlv):
        # tlv: list of list of tag, length and value corresponding to the SEQUENCE
        if not isinstance(tlv, list):
            raise(ASN1BERDecodeErr('{0}: invalid SEQUENCE primitive structure'\
                  .format(self.fullname())))
        #
        # 1) init the local value and structure
        self._val, ind, eoc = {}, 0, False
        if not tlv:
            # empty tlv, ensure there is no mandatory components
            if self._root_mand:
                raise(ASN1BERDecodeErr('{0}: missing mandatory component, {1!r}'\
                      .format(self.fullname(), self._root_mand)))
            else:
                return
        #
        cl, pc, tval, lval = tlv[ind][0:4]
        tag = (cl, tval)
        # list of decoded components
        dec = []
        #
        # 2) get over all components within the SEQUENCE content 1 by 1
        #    check if it corresponds to the current tlv
        #    decode the component
        for Comp in self._cont.values():
            next = False
            if (cl, pc, tval, lval) == (0, 0, 0, 0):
                # EOC marker
                eoc = True
                break
            #
            else:
                m = match_tag(Comp, tag)
                if m == 1:
                    next = True
                elif m > 1:
                    # hack: in case content is not extensible and Comp is the last
                    # component of the content, we can consider it present
                    if Comp._name == self._cont._index[-1] and self._ext is None:
                        next = True
                    else:
                        if not self._SILENT:
                            asnlog('SEQUENCE._decode_ber_cont: %s, unable to determine '\
                                   'if component %s is present (err %i)' % (self.fullname(), Comp._name, m))
                        if Comp._name in self._root_mand:
                            # component is mandatory, so we will still try to decode it
                            next = True
            #
            if next:
                # 3) decode the current component
                _par = Comp._parent
                Comp._parent = self
                Comp._from_ber(char, [tlv[ind]])
                Comp._parent = _par
                self._val[Comp._name] = Comp._val
                dec.append(Comp._name)
                # and get next tlv
                ind += 1
                if ind < len(tlv):
                    cl, pc, tval, lval = tlv[ind][0:4]
                    tag = (cl, tval)
                else:
                    # no more tlv to consume
                    break
        #
        # checks for error in the decoded structure
        for mandcomp in self._root_mand:
            if mandcomp not in dec:
                raise(ASN1BERDecodeErr('{0}: missing mandatory component, {1}'\
                      .format(self.fullname(), mandcomp)))
        if eoc and ind < len(tlv)-1:
            raise(ASN1BERDecodeErr('{0}: invalid EOC marker in between TLV components'\
                  .format(self.fullname())))
        #
        # 4) decode unknown provided extensions
        if ind < len(tlv)-1 and self._ext is None:
            raise(ASN1BERDecodeErr('{0}: invalid extension to be decoded, {1!r}'\
                  .format(self.fullname(), tlv[ind])))
        while ind < len(tlv)-1:
            cl, pc, tval, lval = tlv[ind][0:4]
            if (cl, pc, tval, lval) == (0, 0, 0, 0) and ind < len(tlv)-1:
                raise(ASN1BERDecodeErr('{0}: invalid EOC marker in between TLV components'\
                      .format(self.fullname())))
            else:
                if not self._SILENT:
                    asnlog('SEQUENCE._decode_ber_cont: %s, unknown extension tag %r'\
                           % (self.fullname(), (cl, tval)))
                ident = '_ext_%i%i%i' % (cl, pc, tval)
                if pc == 1:
                    # constructed object
                    val = ASN1CodecBER.scan_tlv(char, tlv[ind])
                elif lval >= 0:
                    # primitive object
                    char._cur = tlv[ind][4][0]
                    val = char.to_bytes(8*lval)
                else:
                    raise(ASN1BERDecodeErr('{0}: invalid SEQUENCE extended tag and length, {1!r}, {2!r}'\
                          .format(self.fullname(), (cl, pc, tval), lval)))
                self._val[ident] = val
            ind += 1
    
    def _encode_ber_cont_ws(self):
        TLV, val_ids = [], list(self._val.keys())
        if ASN1CodecBER.ENC_LUNDEF:
            lval = -1
        else:
            lval = 0
        # encode component 1 by 1
        for (ident, Comp) in self._cont.items():
            #
            if ident in self._val:
                if ASN1CodecBER.ENC_DEF_CANON and self._val[ident] == self._cont[ident]._def:
                    # the value provided equals the default one
                    # hence will not be encoded
                    if not self._SILENT:
                        asnlog('SEQ._encode_ber_cont_ws: %s.%s, removing value equal '\
                               'to the default one' % (self.fullname(), ident))
                    del self._val[ident]
                else:
                    # component to be encoded
                    _par = Comp._parent
                    Comp._parent = self
                    Comp._val = self._val[ident]
                    comp_tlv = Comp._to_ber_ws()
                    TLV.append( comp_tlv )
                    Comp._parent = _par
                    if lval >= 0:
                        lval += comp_tlv.get_bl() >> 3
                val_ids.remove(ident)
        #
        if val_ids:
            # encode unknown extended components
            for ident in val_ids:
                assert( ident[0:5] == '_ext_' )
                cl, pc, tval = int(ident[5:6]), int(ident[6:7]), int(ident[7:])
                comp_tlv = ASN1CodecBER.encode_tlv_ws(cl, tval, self._val[ident], pc=pc)
                TLV.append( comp_tlv )
                if lval >= 0:
                    lval += comp_tlv.get_bl() >> 3
        #
        return 1, lval, Envelope('V', GEN=tuple(TLV))
    
    def _encode_ber_cont(self):
        TLV, val_ids = [], list(self._val.keys())
        if ASN1CodecBER.ENC_LUNDEF:
            lval = -1
        else:
            lval = 0
        # encode component 1 by 1
        for (ident, Comp) in self._cont.items():
            #
            if ident in self._val:
                if ASN1CodecBER.ENC_DEF_CANON and self._val[ident] == self._cont[ident]._def:
                    # the value provided equals the default one
                    # hence will not be encoded
                    if not self._SILENT:
                        asnlog('SEQ._encode_ber_cont: %s.%s, removing value equal '\
                               'to the default one' % (self.fullname(), ident))
                    del self._val[ident]
                else:
                    # component to be encoded
                    _par = Comp._parent
                    Comp._parent = self
                    Comp._val = self._val[ident]
                    comp_tlv = Comp._to_ber()
                    TLV.extend( comp_tlv )
                    Comp._parent = _par
                    if lval >= 0:
                        lval += sum([f[2] for f in comp_tlv]) >> 3
                val_ids.remove(ident)
        #
        if val_ids:
            # encode unknown extended components
            for ident in val_ids:
                assert( ident[0:5] == '_ext_' )
                cl, pc, tval = int(ident[5:6]), int(ident[6:7]), int(ident[7:])
                comp_tlv = ASN1CodecBER.encode_tlv(cl, tval, self._val[ident], pc=pc)
                TLV.extend( comp_tlv )
                if lval >= 0:
                    lval += sum([f[2] for f in comp_tlv]) >> 3
        #
        return 1, lval, TLV


class SET(_CONSTRUCT):
    __doc__ = """
ASN.1 constructed type SET object

Single value: Python dict
    keys are components' identifier (str),
    values are ASN1Obj single value specific to components object
    
    special case is the "_ext_$ind" key which encodes an unknown 
    extension with index $ind, then the corresponding value must be a Python bytes

Specific attributes:
    
    - cont: ASN1Dict {ident (str): ASN1Obj instance},
        provides the content of the CHOICE object
    
    - cont_tags: dict with {tag (int): identifier (str)},
        provides a lookup table for tag value to components
    
    - root_mand: list of identifiers (str),
        provides the list of mandatory components in the root part
    
    - root_opt: list of identifiers (str),
        provides the list of optional components in the root part
    
    - root_canon: list of identifiers (str),
        provides the canonican order of root components
    
    - ext_ident: dict with {identifier (str) : ext group index (int)},
        for grouped extended components
    
    - ext_group: dict with {ext group index (int) : list of identifiers (str)},
        for grouped extended components
    
    - ext_group_obj: dict with {ext group index (int): SEQ ASN1Obj instance},
        provides virtual SEQUENCE instance for each group of extended components
    
    - ext_nest: list, each item being a str (extension ident) or list of str 
        (group of extension idents)
%s
""" % ASN1Obj_docstring
    
    TYPE  = TYPE_SET
    TAG   = 17
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        if txt[0:1] != '{':
            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                  .format(self.fullname(), txt)))
        #
        # 1) init local value
        txt, self._val = txt[1:].strip(), {}
        # empty set
        if txt[0:1] == '}':
            return txt[1:].strip()
        try:
            t_ident, t_rest = txt.split(' ', 1)
        except Exception:
            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                  .format(self.fullname(), txt)))
        #
        # 2) go over all identifier-value parts of the text
        #    check if it corresponds to the a component of the SET
        #    decode the component
        while True:
            if t_ident not in self._cont:
                raise(ASN1ASNDecodeErr('{0}: invalid component identifier, {1}'\
                      .format(self.fullname(), t_ident)))
            Comp = self._cont[t_ident]
            _par = Comp._parent
            Comp._parent = self
            txt = Comp._from_asn1(t_rest)
            Comp._parent = _par
            self._val[t_ident] = Comp._val
            if txt[0:1] == ',':
                txt = txt[1:].strip()
                try:
                    t_ident, t_rest = txt.split(' ', 1)
                except Exception:
                    raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                          .format(self.fullname(), txt)))
            elif txt[0:1] == '}':
                break
        #
        # 3) ensure all expected values have been provided
        try:
            self._safechk_valcompl(self._val)
        except Exception as err:
            raise(ASN1BERDecodeErr(err))
        return txt[1:].strip()
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_ber_cont_ws(self, char, tlv):
        # tlv: list of list of tag, length and value corresponding to the SET
        if not isinstance(tlv, list):
            raise(ASN1BERDecodeErr('{0}: invalid SET primitive structure'\
                  .format(self.fullname())))
        #
        # 1) init the local value and structure
        self._val, TLV = {}, []
        #
        # 2) get over all tlv within TLV 1 by 1
        #    check if it corresponds to the a component of the SET
        #    decode the component
        for comp_tlv in tlv:
            Tag, cl, pc, tval, Len, lval = comp_tlv[0:6]
            if (cl, tval) in self._cont_tags:
                # select the component
                path = self._cont_tags[(cl, tval)]
                if isinstance(path, list):
                    # select untagged component(s)
                    Comp = [self._cont[path[0]]]
                    _par = [Comp[0]._parent]
                    Comp[0]._parent = self
                    for ident in path[1:]:
                        Comp.append( Comp[-1]._cont[ident] )
                        _par.append( Comp[-1]._parent )
                        Comp[-1]._parent = Comp[-2]
                    # decode it
                    Comp[-1]._from_ber_ws(char, [comp_tlv])
                    val = Comp[-1]._val
                    # restore parents and set value
                    for i in range(len(_par)):
                        Comp[i] = _par[i]
                    for ident in reversed(path[1:]):
                        val = (ident, val)
                    self._val[path[0]] = val
                    TLV.append( Comp[-1]._struct )
                else:
                    # select tagged component
                    Comp = self._cont[path]
                    _par = Comp._parent
                    Comp._parent = self
                    # decode it
                    Comp._from_ber_ws(char, [comp_tlv])
                    # restore parent and set value
                    Comp._parent = _par
                    self._val[path] = Comp._val
                    TLV.append( Comp._struct )
            elif (cl, pc, tval, lval) == (0, 0, 0, 0):
                # EOC marker
                if comp_tlv != tlv[-1]:
                    raise(ASN1BERDecodeErr('{0}: invalid EOC marker in between TLV components'\
                          .format(self.fullname())))
                break
            elif self._ext is not None:
                if not self._SILENT:
                    asnlog('SET._decode_ber_cont_ws: %s, unknown extension tag %r'\
                           % (self.fullname(), (cl, tval)))
                ident = '_ext_%i%i%i' % (cl, pc, tval)
                if pc == 1:
                    # constructed object
                    val = ASN1CodecBER.scan_tlv_ws(char, comp_tlv)
                    TLV.append( Envelope(ident, GEN=(Tag, Len, 
                                         Buf('V', val=val, bl=8*len(val), rep=REPR_HEX))) )
                elif lval >= 0:
                    # primitive object
                    char._cur = comp_tlv[6][0]
                    Val = Buf('V', bl=8*lval, rep=REPR_HEX)
                    Val._from_char(char)
                    val = Val.to_bytes()
                    TLV.append( Envelope(ident, GEN=(Tag, Len, Val)) )
                else:
                    raise(ASN1BERDecodeErr('{0}: invalid SEQUENCE extended tag and length, {1!r}, {2!r}'\
                          .format(self.fullname(), (cl, pc, tval), lval)))
                self._val[ident] = val
            else:
                raise(ASN1BERDecodeErr('{0}: invalid SET tag according to the content, {1!r}'\
                      .format(self.fullname(), (cl, tval))))
        #
        # 3) ensure all expected values have been provided
        try:
            self._safechk_valcompl(self._val)
        except Exception as err:
            raise(ASN1BERDecodeErr(err))
        #
        return Envelope('V', GEN=tuple(TLV))
    
    def _decode_ber_cont(self, char, tlv):
        # tlv: list of list of tag, length and value corresponding to the SET
        if not isinstance(tlv, list):
            raise(ASN1BERDecodeErr('{0}: invalid SET primitive structure'\
                  .format(self.fullname())))
        #
        # 1) init the local value and structure
        self._val= {}
        #
        # 2) get over all tlv within TLV 1 by 1
        #    check if it corresponds to the a component of the SET
        #    decode the component
        for comp_tlv in tlv:
            cl, pc, tval, lval = comp_tlv[0:4]
            if (cl, tval) in self._cont_tags:
                path = self._cont_tags[(cl, tval)]
                if isinstance(path, list):
                    # select untagged component(s)
                    Comp = [self._cont[path[0]]]
                    _par = [Comp[0]._parent]
                    Comp[0]._parent = self
                    for ident in path[1:]:
                        Comp.append( Comp[-1]._cont[ident] )
                        _par.append( Comp[-1]._parent )
                        Comp[-1]._parent = Comp[-2]
                    # decode it
                    Comp[-1]._from_ber(char, [comp_tlv])
                    val = Comp[-1]._val
                    # restore parents and set value
                    for i in range(len(_par)):
                        Comp[i] = _par[i]
                    for ident in reversed(path[1:]):
                        val = (ident, val)
                    self._val[path[0]] = val
                else:
                    # select tagged component
                    Comp = self._cont[path]
                    _par = Comp._parent
                    Comp._parent = self
                    # decode it
                    Comp._from_ber(char, [comp_tlv])
                    # restore parent and set value
                    Comp._parent = _par
                    self._val[path] = Comp._val
            elif (cl, pc, tval, lval) == (0, 0, 0, 0):
                # EOC marker
                if comp_tlv != tlv[-1]:
                    raise(ASN1BERDecodeErr('{0}: invalid EOC marker within TLV components'\
                          .format(self.fullname())))
                break
            elif self._ext is not None:
                if not self._SILENT:
                    asnlog('SET._decode_ber_cont: %s, unknown extension tag %r'\
                           % (self.fullname(), (cl, tval)))
                ident = '_ext_%i%i%i' % (cl, pc, tval)
                if pc == 1:
                    # constructed object
                    val = ASN1CodecBER.scan_tlv(char, comp_tlv)
                elif lval >= 0:
                    # primitive object
                    char._cur = comp_tlv[6][0]
                    val = char.get_bytes(8*lval)
                else:
                    raise(ASN1BERDecodeErr('{0}: invalid SEQUENCE extended tag and length, {1!r}, {2!r}'\
                          .format(self.fullname(), (cl, pc, tval), lval)))
                self._val[ident] = val
            else:
                raise(ASN1BERDecodeErr('{0}: invalid SET tag according to the content, {1!r}'\
                      .format(self.fullname(), (cl, tval))))
        #
        # 3) ensure all expected values have been provided
        try:
            self._safechk_valcompl(self._val)
        except Exception as err:
            raise(ASN1BERDecodeErr(err))

    def _encode_ber_cont_ws(self):
        TLV, val_ids = [], list(self._val.keys())
        if ASN1CodecBER.ENC_LUNDEF:
            lval = -1
        else:
            lval = 0
        # encode root component 1 by 1 in canonical order
        for ident in self._root_canon:
            if ident in self._val:
                if ASN1CodecBER.ENC_DEF_CANON and self._val[ident] == self._cont[ident]._def:
                    # the value provided equals the default one
                    # hence will not be encoded
                    if not self._SILENT:
                        asnlog('SET._encode_ber_cont_ws: %s.%s, removing value equal '\
                               'to the default one' % (self.fullname(), ident))
                    del self._val[ident]
                else:
                    # component to be encoded
                    Comp = self._cont[ident]
                    _par = Comp._parent
                    Comp._parent = self
                    Comp._val = self._val[ident]
                    comp_tlv = Comp._to_ber_ws()
                    TLV.append( comp_tlv )
                    Comp._parent = _par
                    if lval >= 0:
                        lval += comp_tlv.get_bl() >> 3
                val_ids.remove(ident)
        # encode extended component 1 by 1 in their definition order
        for ident in self._ext:
            if ident in self._val:
                if ASN1CodecBER.ENC_DEF_CANON and self._val[ident] == self._cont[ident]._def:
                    # the value provided equals the default one
                    # hence will not be encoded
                    if not self._SILENT:
                        asnlog('SET._encode_ber_cont_ws: %s.%s, removing value equal '\
                               'to the default one' % (self.fullname(), ident))
                    del self._val[ident]
                else:
                    # component to be encoded
                    Comp = self._cont[ident]
                    _par = Comp._parent
                    Comp._parent = self
                    Comp._val = self._val[ident]
                    comp_tlv = Comp._to_ber_ws()
                    TLV.append( comp_tlv )
                    Comp._parent = _par
                    if lval >= 0:
                        lval += comp_tlv.get_bl() >> 3
                val_ids.remove(ident)
        #
        if val_ids:
            # encode unknown extended components
            for ident in val_ids:
                assert( ident[0:5] == '_ext_' )
                cl, pc, tval = int(ident[5:6]), int(ident[6:7]), int(ident[7:])
                comp_tlv = ASN1CodecBER.encode_tlv_ws(cl, tval, self._val[ident], pc=pc)
                TLV.append( comp_tlv )
                if lval >= 0:
                    lval += comp_tlv.get_bl() >> 3
        #
        return 1, lval, Envelope('V', GEN=tuple(TLV))
    
    def _encode_ber_cont(self):
        TLV, val_ids = [], list(self._val.keys())
        if ASN1CodecBER.ENC_LUNDEF:
            lval = -1
        else:
            lval = 0
        # encode root component 1 by 1 in canonical order
        for ident in self._root_canon:
            if ident in self._val:
                if ASN1CodecBER.ENC_DEF_CANON and self._val[ident] == self._cont[ident]._def:
                    # the value provided equals the default one
                    # hence will not be encoded
                    if not self._SILENT:
                        asnlog('SET._encode_ber_cont: %s.%s, removing value equal '\
                               'to the default one' % (self.fullname(), ident))
                    del self._val[ident]
                else:
                    # component to be encoded
                    Comp = self._cont[ident]
                    _par = Comp._parent
                    Comp._parent = self
                    Comp._val = self._val[ident]
                    comp_tlv = Comp._to_ber()
                    TLV.extend( comp_tlv )
                    Comp._parent = _par
                    if lval >= 0:
                        lval += sum([f[2] for f in comp_tlv]) >> 3
                val_ids.remove(ident)
        # encode extended component 1 by 1 in their definition order
        for ident in self._ext:
            if ident in self._val:
                if ASN1CodecBER.ENC_DEF_CANON and self._val[ident] == self._cont[ident]._def:
                    # the value provided equals the default one
                    # hence will not be encoded
                    if not self._SILENT:
                        asnlog('SET._encode_ber_cont: %s.%s, removing value equal '\
                               'to the default one' % (self.fullname(), ident))
                    del self._val[ident]
                else:
                    # component to be encoded
                    Comp = self._cont[ident]
                    _par = Comp._parent
                    Comp._parent = self
                    Comp._val = self._val[ident]
                    comp_tlv = Comp._to_ber()
                    TLV.extend( comp_tlv )
                    Comp._parent = _par
                    if lval >= 0:
                        lval += sum([f[2] for f in comp_tlv]) >> 3
                val_ids.remove(ident)
        #
        if val_ids:
            # encode unknown extended components
            for ident in val_ids:
                assert( ident[0:5] == '_ext_' )
                cl, pc, tval = int(ident[5:6]), int(ident[6:7]), int(ident[7:])
                comp_tlv = ASN1CodecBER.encode_tlv(cl, tval, self._val[ident], pc=pc)
                TLV.extend( comp_tlv )
                if lval >= 0:
                    lval += sum([f[2] for f in comp_tlv]) >> 3
        #
        return 1, lval, TLV


#------------------------------------------------------------------------------#
# SEQUENCE OF and SET OF
#------------------------------------------------------------------------------#

class _CONSTRUCT_OF(ASN1Obj):
    
    # this class implements the methods that are common to SEQ and SET
    
    # this is to potentially limit the length of the encoded content
    _ENC_MAXLEN = None
    
    def _safechk_val(self, val):
        if not isinstance(val, list):
            raise(ASN1ObjErr('{0}: invalid value, {1!r}'.format(self.fullname(), val)))
        for v in val:
            self._cont._safechk_val(v)
    
    def _safechk_bnd(self, val):
        ASN1Obj._safechk_bnd(self, val)
        if self._const_sz and \
        self._const_sz.ext is None and \
        len(val) not in self._const_sz:
            raise(ASN1ObjErr('{0}: value out of size constraint, {1!r}'\
                  .format(self.fullname(), val)))
        for v in val:
            self._cont._safechk_bnd(v)
    
    ###
    # conversion between internal value and ASN.1 syntax
    ###
    
    def _from_asn1(self, txt):
        if txt[0:1] != '{':
            raise(ASN1ASNDecodeErr('{0}: invalid text, {1!r}'\
                  .format(self.fullname(), txt)))
        txt, self._val = txt[1:].strip(), []
        if txt[0:1] == '}':
            # empty value
            return txt[1:].strip()
        _par = self._cont._parent
        self._cont._parent = self
        while True:
            txt = self._cont._from_asn1(txt)
            self._val.append(self._cont._val)
            if txt[0:1] == ',':
                txt = txt[1:].strip()
            elif txt[0:1] == '}':
                self._cont._parent = _par
                #self._val = self._val
                return txt[1:].strip()
            else:
                raise(ASN1ASNDecoderErr('{0}: invalid text, {1!r}'\
                      .format(self.fullname(), txt)))
    
    def _to_asn1(self):
        if not self._val:
            # empty list
            return '{ }'
        else:
            val = []
            _par = self._cont._parent
            self._cont._parent = self
            for v in self._val:
                self._cont._val = v
                val.append('  %s,\n' % self._cont._to_asn1().replace('\n', '\n  '))
            self._cont._parent = _par
            if val:
                val[-1] = val[-1][:-2]
            return '{\n' + ''.join(val) + '\n}'
    
    ###
    # conversion between internal value and ASN.1 PER encoding
    ###
    
    def _from_per_ws(self, char):
        GEN = []
        if self._const_sz:
            if self._const_sz.ext is not None:
                E = Uint('E', bl=1)
                E._from_char(char)
                GEN.append(E)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                if E():
                    # 1) size in the extension part
                    # decoded as unconstraint
                    self.__from_per_ws_szunconst(char, GEN)
                    return
            # size in the root part
            ldet = None
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    self.__from_per_ws_szunconst(char, GEN)
                    return
                else:
                    # decode the constrained length determinant
                    ldet, _gen = ASN1CodecPER.decode_intconst_ws(char, self._const_sz, name='C')
                    GEN.extend(_gen)
            elif self._const_sz.rdyn == 0:
                if self._const_sz.ub >= 65536:
                    self.__from_per_ws_szunconst(char, GEN)
                    return
                else:
                    # 3) size has a single possible size
                    ldet = self._const_sz.ub
            if ldet is not None:
                self._val = []
                _par = self._cont._parent
                self._cont._parent = self
                for i in range(ldet):
                    self._cont._from_per_ws(char)
                    GEN.append(self._cont._struct)
                    self._val.append(self._cont._val)
                self._cont._parent = _par
                self._struct = Envelope(self._name, GEN=tuple(GEN))
                return
        # 4) size is semi-constrained or has no constraint
        # decoded as unconstrained
        self.__from_per_ws_szunconst(char, GEN)
        return
    
    def __from_per_ws_szunconst(self, char, GEN):
        # size is semi-constrained or unconstrained
        # anyway, it is decoded as unconstrained integer
        if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
            GEN.extend( ASN1CodecPER.decode_pad_ws(char) )
        ldet, _gen = ASN1CodecPER.decode_count_ws(char)
        GEN.extend(_gen)
        self._val, L = [], ldet
        _par = self._cont._parent
        self._cont._parent = self
        while ldet in (65536, 49152, 32768, 16384):
            # requires defragmentation
            for i in range(ldet):
                self._cont._from_per_ws(char)
                GEN.append(self._cont._struct)
                self._val.append(self._cont._val)
            if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
                GEN.extend( ASN1CodecPER.decode_pad_ws(char) )
            ldet, _gen = ASN1CodecPER.decode_count_ws(char)
            GEN.extend(_gen)
            L += ldet
            if L > ASN1CodecPER.DEC_MAXL:
                raise(ASN1PERDecodeErr('too much fragments, {0!r}'.format(L)))
        for i in range(ldet):
            self._cont._from_per_ws(char)
            GEN.append(self._cont._struct)
            self._val.append(self._cont._val)
        self._cont._parent = _par
        self._struct = Envelope(self._name, GEN=tuple(GEN))
    
    def _from_per(self, char):
        GEN = []
        if self._const_sz:
            if self._const_sz.ext is not None:
                E = char.get_uint(1)
                if ASN1CodecPER.ALIGNED:
                    ASN1CodecPER._off[-1] += 1
                if E:
                    # 1) size in the extension part
                    # decoded as unconstraint
                    self.__from_per_szunconst(char)
                    return
            # size in the root part
            ldet = None
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    self.__from_per_szunconst(char)
                    return
                else:
                    # decode the constrained length determinant
                    ldet = ASN1CodecPER.decode_intconst(char, self._const_sz)
            elif self._const_sz.rdyn == 0:
                if self._const_sz.ub >= 65536:
                    self.__from_per_szunconst(char)
                    return
                else:
                    # 3) size has a single possible size
                    ldet = self._const_sz.ub
            if ldet is not None:
                self._val = []
                _par = self._cont._parent
                self._cont._parent = self
                for i in range(ldet):
                    self._cont._from_per(char)
                    self._val.append(self._cont._val)
                self._cont._parent = _par
                return
        # 4) size is semi-constrained or has no constraint
        # decoded as unconstrained
        self.__from_per_szunconst(char)
        return
    
    def __from_per_szunconst(self, char):
        # size is semi-constrained or unconstrained
        # anyway, it is decoded as unconstrained integer
        if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
            ASN1CodecPER.decode_pad(char)
        ldet = ASN1CodecPER.decode_count(char)
        self._val, L = [], ldet
        _par = self._cont._parent
        self._cont._parent = self
        while ldet in (65536, 49152, 32768, 16384):
            # requires defragmentation
            for i in range(ldet):
                self._cont._from_per(char)
                self._val.append(self._cont._val)
            if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
                ASN1CodecPER.decode_pad(char)
            ldet = ASN1CodecPER.decode_count(char)
            L += ldet
            if L > ASN1CodecPER.DEC_MAXL:
                raise(ASN1PERDecodeErr('too much fragments, {0!r}'.format(L)))
        for i in range(ldet):
            self._cont._from_per(char)
            self._val.append(self._cont._val)
        self._cont._parent = _par
    
    def _to_per_ws(self):
        GEN, ldet = [], len(self._val)
        if self._const_sz:
            if self._const_sz.ext is not None:
                if not self._const_sz.in_root(ldet):
                    # 1) size in the extension part
                    # encoded as unconstrained integer
                    GEN.append( Uint('E', val=1, bl=1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
                    self.__to_per_ws_szunconst(GEN)
                    return self._struct
                else:
                    GEN.append( Uint('E', val=0, bl=1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
            # size in the root part
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    self.__to_per_ws_szunconst(GEN)
                    return self._struct
                else:
                    GEN.extend( ASN1CodecPER.encode_intconst_ws(ldet, self._const_sz, name='C') )
                    _par = self._cont._parent
                    self._cont._parent = self
                    self.__to_per_ws_cont(GEN, ldet)
                    self._cont._parent = _par
                    self._struct = Envelope(self._name, GEN=tuple(GEN))
                    return self._struct
            elif self._const_sz.rdyn == 0:
                # 3) size has a single possible size
                if self._const_sz.ub >= 65536:
                    self.__to_per_ws_szunconst(GEN)
                    return self._struct
                else:
                    _par = self._cont._parent
                    self._cont._parent = self
                    self.__to_per_ws_cont(GEN, ldet)
                    self._cont._parent = _par
                    self._struct = Envelope(self._name, GEN=tuple(GEN))
                    return self._struct
        # 4) size is semi-constrained or has no constraint
        # encoded as unconstrained integer
        self.__to_per_ws_szunconst(buf, ldet, GEN)
        return self._struct
    
    def __to_per_ws_szunconst(self, GEN):
        ldet, off = len(self._val), 0
        _par = self._cont._parent
        self._cont._parent = self
        if ldet >= 16384:
            # requires fragmentation
            frags, rem = factor_perfrag(ldet)
            off, bl = 0, [0]
            # complete fragments
            for (fs, fn) in frags:
                for i in range(fn):
                    if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
                        GEN.extend( ASN1CodecPER.encode_pad_ws() )
                    GEN.extend( ASN1CodecPER.encode_count_ws(fs) )
                    self.__to_per_ws_cont(GEN, fs, off, bl)
                    off += fs
            if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
                GEN.extend( ASN1CodecPER.encode_pad_ws() )
            # last fragments (potentially incomplete)
            GEN.extend( ASN1CodecPER.encode_count_ws(rem) )
            self.__to_per_ws_cont(GEN, rem, off, bl)
        else:
            if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
                GEN.extend( ASN1CodecPER.encode_pad_ws() )
            GEN.extend( ASN1CodecPER.encode_count_ws(ldet) )
            self.__to_per_ws_cont(GEN, ldet)
        self._cont._parent = _par
        self._struct = Envelope(self._name, GEN=tuple(GEN))
    
    def __to_per_ws_cont(self, GEN, num, off=0, bl=None):
        if self._ENC_MAXLEN:
            if bl is None:
                bl_cur = 0
                bl_upd = False
            else:
                bl_cur = bl[0]
                bl_upd = True
            for i in range(num):
                self._cont._val = self._val[off+i]
                cont_per = self._cont._to_per_ws()
                bl_cur += cont_per.get_bl()
                if bl_cur > self._ENC_MAXLEN:
                    raise(ASN1NotSuppErr('{0}: encoding too long, {1} bytes'.format(self.fullname(), bl_cur>>3)))
                GEN.append( cont_per )
            if bl_upd:
                bl[0] = bl_cur
        else:
            for i in range(num):
                self._cont._val = self._val[off+i]
                GEN.append( self._cont._to_per_ws() )
    
    def _to_per(self):
        GEN, ldet = [], len(self._val)
        if self._const_sz:
            if self._const_sz.ext is not None:
                if not self._const_sz.in_root(ldet):
                    # 1) size in the extension part
                    # encoded as unconstrained integer
                    GEN.append( (T_UINT, 1, 1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
                    self.__to_per_szunconst(GEN)
                    return GEN
                else:
                    GEN.append( (T_UINT, 0, 1) )
                    if ASN1CodecPER.ALIGNED:
                        ASN1CodecPER._off[-1] += 1
            # size in the root part
            if self._const_sz.rdyn:
                # 2) defined range of possible sizes
                if self._const_sz.ub >= 65536:
                    self.__to_per_szunconst(GEN)
                    return GEN
                else:
                    GEN.extend( ASN1CodecPER.encode_intconst(ldet, self._const_sz) )
                    _par = self._cont._parent
                    self._cont._parent = self
                    self.__to_per_cont(GEN, ldet)
                    self._cont._parent = _par
                    return GEN
            elif self._const_sz.rdyn == 0:
                # 3) size has a single possible size
                if self._const_sz.ub >= 65536:
                    self.__to_per_szunconst(GEN)
                    return GEN
                else:
                    _par = self._cont._parent
                    self._cont._parent = self
                    self.__to_per_cont(GEN, ldet)
                    self._cont._parent = _par
                    return GEN
        # 4) size is semi-constrained or has no constraint
        # encoded as unconstrained integer
        self.__to_per_szunconst(GEN)
        return GEN
    
    def __to_per_szunconst(self, GEN):
        ldet, off = len(self._val), 0
        _par = self._cont._parent
        self._cont._parent = self
        if ldet >= 16384:
            # requires fragmentation
            frags, rem = factor_perfrag(ldet)
            off, bl = 0, [0]
            # complete fragments
            for (fs, fn) in frags:
                for i in range(fn):
                    if ASN1CodecPER.ALIGNED:
                        GEN.extend( ASN1CodecPER.encode_pas() )
                    GEN.extend( ASN1CodecPER.encode_count(fs) )
                    self.__to_per_cont(GEN, fs, off, bl)
                    off += fs
            if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
                GEN.extend( ASN1CodecPER.encode_pad() )
            # last fragment (potentially uncomplete)
            GEN.extend( ASN1CodecPER.encode_count(rem) )
            self.__to_per_cont(GEN, rem, off, bl)
        else:
            if ASN1CodecPER.ALIGNED and ASN1CodecPER._off[-1] % 8:
                GEN.extend( ASN1CodecPER.encode_pad() )
            GEN.extend( ASN1CodecPER.encode_count(ldet) )
            self.__to_per_cont(GEN, ldet)
        self._cont._parent = _par
    
    def __to_per_cont(self, GEN, num, off=0, bl=None):
        if self._ENC_MAXLEN:
            if bl is None:
                bl_cur = 0
                bl_upd = False
            else:
                bl_cur = bl[0]
                bl_upd = True
            for i in range(num):
                self._cont._val = self._val[off+i]
                cont_per = self._cont._to_per()
                bl_cur += sum([v[2] for v in cont_per])
                if bl_cur > self._ENC_MAXLEN:
                    raise(ASN1NotSuppErr('{0}: encoding too long, {1} bytes'.format(self.fullname(), bl_cur>>3)))
                GEN.extend( cont_per )
            if bl_upd:
                bl[0] = bl_cur
        else:
            for i in range(num):
                self._cont._val = self._val[off+i]
                GEN.extend( self._cont._to_per() )
    
    ###
    # conversion between internal value and ASN.1 BER encoding
    ###
    
    def _decode_ber_cont_ws(self, char, tlv):
        # tlv: list of list of tag, length and value corresponding to the SEQUENCE OF / SET OF
        if not isinstance(tlv, list):
            raise(ASN1BERDecodeErr('{0}: invalid SEQUENCE OF / SET OF primitive structure'\
                  .format(self.fullname())))
        #
        # 1) init the local value
        Comp, self._val, TLV = self._cont, [], []
        _par = Comp._parent
        Comp._parent = self
        #
        # 2) get over all tlv within TLV 1 by 1
        #    decode the component
        for comp_tlv in tlv:
            Tag, cl, pc, tval, Len, lval = comp_tlv[0:6]
            if (cl, pc, tval, lval) == (0, 0, 0, 0):
                # EOC marker
                if comp_tlv != tlv[-1]:
                    raise(ASN1BERDecodeErr('{0}: invalid EOC marker within TLV components'\
                          .format(self.fullname())))
                break
            else:
                Comp._from_ber_ws(char, [comp_tlv])
                self._val.append( Comp._val )
                TLV.append( Comp._struct )
        #
        Comp._parent = _par
        return Envelope('V', GEN=tuple(TLV))
    
    def _decode_ber_cont(self, char, tlv):
        # tlv: list of list of tag, length and value corresponding to the SEQUENCE OF / SET OF
        if not isinstance(tlv, list):
            raise(ASN1BERDecodeErr('{0}: invalid SEQUENCE OF / SET OF primitive structure'\
                  .format(self.fullname())))
        #
        # 1) init the local value
        Comp, self._val = self._cont, []
        _par = Comp._parent
        Comp._parent = self
        #
        # 2) get over all tlv within TLV 1 by 1
        #    decode the component
        for comp_tlv in tlv:
            if comp_tlv[0:4] == [0, 0, 0, 0]:
                # EOC marker
                if comp_tlv != tlv[-1]:
                    raise(ASN1BERDecodeErr('{0}: invalid EOC marker within TLV components'\
                          .format(self.fullname())))
                break
            else:
                Comp._from_ber(char, [comp_tlv])
                self._val.append( Comp._val )
        #
        Comp._parent = _par
    
    def _encode_ber_cont_ws(self):
        Comp, TLV = self._cont, []
        _par = Comp._parent
        Comp._parent = self
        #
        if ASN1CodecBER.ENC_LUNDEF and not self._ENC_MAXLEN:
            # do not track the length of the content
            for val in self._val:
                Comp._val = val
                tlv = Comp._to_ber_ws()
                TLV.append( tlv )
        elif self._ENC_MAXLEN:
            # track the length of the content and verify it at each iteration
            bl = 0
            for val in self._val:
                Comp._val = val
                tlv = Comp._to_ber_ws()
                bl += tlv.get_bl()
                if bl > self._ENC_MAXLEN:
                    raise(ASN1NotSuppErr('{0}: encoding too long, {1} bytes'.format(self.fullname(), bl>>3)))
                TLV.append( tlv )
        else:
            # track the length of the content
            bl = 0
            for val in self._val:
                Comp._val = val
                tlv = Comp._to_ber_ws()
                bl += tlv.get_bl()
                TLV.append( tlv )
        #
        Comp._parent = _par
        if ASN1CodecBER.ENC_LUNDEF:
            return 1, -1, Envelope('V', GEN=tuple(TLV))
        else:
            return 1, bl>>3, Envelope('V', GEN=tuple(TLV))
    
    def _encode_ber_cont(self):
        Comp, TLV = self._cont, []
        _par = Comp._parent
        Comp._parent = self
        #
        if ASN1CodecBER.ENC_LUNDEF and not self._ENC_MAXLEN:
            # do not track the length of the content
            for val in self._val:
                Comp._val = val
                tlv = Comp._to_ber()
                TLV.extend( tlv )
        elif self._ENC_MAXLEN:
            # track the length of the content and verify it at each iteration
            bl = 0
            for val in self._val:
                Comp._val = val
                tlv = Comp._to_ber()
                bl += sum([f[2] for f in tlv])
                if bl > self._ENC_MAXLEN:
                    raise(ASN1NotSuppErr('{0}: encoding too long, {1} bytes'.format(self.fullname(), bl>>3)))
                TLV.extend( tlv )
        else:
            # track the length of the content
            bl = 0
            for val in self._val:
                Comp._val = val
                tlv = Comp._to_ber()
                bl += sum([f[2] for f in tlv])
                TLV.extend( tlv )
        #
        Comp._parent = _par
        if ASN1CodecBER.ENC_LUNDEF:
            return 1, -1, TLV
        else:
            return 1, bl>>3, TLV
    
    ###
    # conversion between internal value and ASN.1 JER encoding
    ###
    
    if _with_json:
        
        def _from_jval(self, val):
            if not isinstance(val, list):
                raise(ASN1JERDecodeErr('{0}: invalid json value, {1!r}'\
                      .format(self.fullname(), val)))
            _par = self._cont._parent
            self._cont._parent = self
            self._val = []
            for v in val:
                self._cont._from_jval(v)
                self._val.append(self._cont._val)
            self._cont._parent = _par
        
        def _to_jval(self):
            if not self._val:
                return []
            else:
                _par, ret = self._cont._parent, []
                self._cont._parent = self
                for v in self._val:
                    self._cont._val = v
                    ret.append( self._cont._to_jval() )
                self._cont._parent = _par
                return ret

    ###
    # conversion between internal value and ASN.1 OER/COER encoding
    ###

    def _to_oer(self):
        GEN, ldet = [], len(self._val)
        l_size = uint_bytelen(ldet)
        GEN.extend(ASN1CodecOER.encode_length_determinant(l_size))
        GEN.append( (T_UINT, ldet, l_size*8) )

        # Iterate over items
        Comp = self._cont
        _par = Comp._parent
        Comp._parent = self

        for val in self._val:
            Comp._val = val
            GEN.extend(Comp._to_oer())

        Comp._parent = _par

        return GEN

    def _to_oer_ws(self):
        GEN, ldet = [], len(self._val)
        l_size = uint_bytelen(ldet)
        GEN.append(ASN1CodecOER.encode_length_determinant_ws(l_size))
        GEN.append(Uint('Quantity', val=ldet, bl=l_size * 8))

        GEN = [Envelope('Quantity-field', GEN=tuple(GEN))]

        # Iterate over items
        Comp = self._cont
        _par = Comp._parent
        Comp._parent = self

        for val in self._val:
            Comp._val = val
            GEN.append(Comp._to_oer_ws())

        Comp._parent = _par

        self._struct = Envelope(self._name, GEN=tuple(GEN))
        return self._struct

    def _from_oer(self, char):
        l_size = ASN1CodecOER.decode_length_determinant(char)
        ldet = char.get_uint(l_size*8)

        Comp = self._cont
        _par = Comp._parent
        Comp._parent = self
        val = []
        if ldet:
            for i in range(ldet):
                Comp._from_oer(char)
                val.append(Comp._val)

        Comp._parent = _par

        self._val = val

    def _from_oer_ws(self, char):
        GEN = []
        l_size, l_size_struct = ASN1CodecOER.decode_length_determinant_ws(char)
        GEN.append(l_size_struct)
        ldet_struct = Uint('Quantity', bl=l_size*8)
        ldet_struct._from_char(char)
        ldet = ldet_struct.get_val()
        GEN.append(ldet_struct)

        GEN = [Envelope('Quantity-field', GEN=tuple(GEN))]

        Comp = self._cont
        _par = Comp._parent
        Comp._parent = self
        val = []
        if ldet:
            for i in range(ldet):
                Comp._from_oer_ws(char)
                GEN.append(Comp._struct)
                val.append(Comp._val)

        Comp._parent = _par

        self._struct = Envelope(self._name, GEN=tuple(GEN))
        self._val = val


class SEQ_OF(_CONSTRUCT_OF):
    __doc__ = """
ASN.1 constructed type SEQUENCE OF object

Single value: Python list
    items are ASN1Obj single value specific to the component object

Specific attributes:
    
    - cont: ASN1Obj instance, provides the content of the SEQUENCE OF object
    
Specific constraints attributes:
    
    - const_sz: None or ASN1Set (TYPE_INT), provides the set of sizes that 
        constraints the type
%s
""" % ASN1Obj_docstring
    
    _const_sz     = None
    
    TYPE  = TYPE_SEQ_OF
    TAG   = 16


class SET_OF(_CONSTRUCT_OF):
    __doc__ = """
ASN.1 constructed type SET OF object

Single value: Python list
    items are ASN1Obj single value specific to the component object

Specific attributes:
    
    - cont: ASN1Obj instance, provides the content of the SEQUENCE OF object
    
Specific constraints attributes:qq
    
    - const_sz: None or ASN1Set (TYPE_INT), provides the set of sizes that 
        constraints the type
%s
""" % ASN1Obj_docstring
    
    _const_sz     = None
    
    TYPE  = TYPE_SET_OF
    TAG   = 17

