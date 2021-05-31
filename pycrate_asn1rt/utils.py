# -*- coding: UTF-8 -*-
# /**
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
# * File Name : pycrate_asn1rt/utils.py
# * Created : 2017-01-31
# * Authors : Benoit Michau 
# *--------------------------------------------------------
# */

import re
from keyword   import iskeyword
from binascii  import hexlify, unhexlify
from math      import log, ceil
from functools import reduce
from struct    import pack, unpack


from .err                import *
from pycrate_asn1c.utils import clean_text

# pycrate_core is used for basic library-wide functions / variables
# (i.e. log(), python_version, integer_types, bytes_types, str_types)
# and for encoding / decoding routines
from pycrate_core.utils  import *
from pycrate_core.utils  import TYPE_BYTES   as T_BYTES
from pycrate_core.utils  import TYPE_INT     as T_INT
from pycrate_core.utils  import TYPE_UINT    as T_UINT
from pycrate_core.utils  import TYPE_INT_LE  as T_INT_LE
from pycrate_core.utils  import TYPE_UINT_LE as T_UINT_LE
from pycrate_core.elt    import *
from pycrate_core.base   import *
from pycrate_core.charpy import *
Atom.REPR_MAXLEN = 512


# -----------------------------------------------------------------------------#
# asn1-wide Python routines
# -----------------------------------------------------------------------------#

def asnlog(msg):
    '''
    customizable logging function for the whole asn1 part
    '''
    log(msg)


# -----------------------------------------------------------------------------#
# asn1-wide Python variables and identifiers
# -----------------------------------------------------------------------------#

# list of ASN.1 OIDs required to be "known" by the compiler
ASN1_OID_ISO = {
    ('itu-t',): 0,
    ('ccitt',): 0,
    (0, 'recommendation'): 0,
    (0, 0, 'a'): 1,
    (0, 0, 'b'): 2,
    (0, 0, 'c'): 3,
    (0, 0, 'd'): 4,
    (0, 0, 'e'): 5,
    (0, 0, 'f'): 6,
    (0, 0, 'g'): 7,
    (0, 0, 'h'): 8,
    (0, 0, 'i'): 9,
    (0, 0, 'j'): 10,
    (0, 0, 'k'): 11,
    (0, 0, 'l'): 12,
    (0, 0, 'm'): 13,
    (0, 0, 'n'): 14,
    (0, 0, 'o'): 15,
    (0, 0, 'p'): 16,
    (0, 0, 'q'): 17,
    (0, 0, 'r'): 18,
    (0, 0, 's'): 19,
    (0, 0, 't'): 20,
    (0, 0, 'u'): 21,
    (0, 0, 'v'): 22,
    (0, 0, 'w'): 23,
    (0, 0, 'x'): 24,
    (0, 0, 'y'): 25,
    (0, 0, 'z'): 26,
    (0, 'question'): 1,
    (0, 'administration'): 2,
    (0, 'network-operator'): 3,
    (0, 'identified-organization'): 4,
    ('iso',): 1,
    (1, 'standard'): 0,
    (1, 'registration-authority'): 1,
    (1, 'member-body'): 2,
    (1, 2, 'f'): 250,
    (1, 'identified-organization'): 3,
    ('joint-iso-itu-t',): 2,
    ('joint-iso-ccitt',): 2,
    (2, 'asn1'): 1,
    (2, 1, 'basic-encoding'): 1,
    (2, 1, 'ber-derived'): 2,
    (2, 1, 'packed-encoding'): 3,
    (2, 'mhs-motif'): 6,
    (2, 'ms'): 9,
    (2, 'registration-procedures'): 17,
}

###
# DO NOT CHANGE the following identifiers
# as many of them correspond directly to the ASN.1 syntax
###

# ASN.1 object mode
MODE_VALUE = 'VALUE'
MODE_SET = 'SET'
MODE_TYPE = 'TYPE'

# ASN.1 type identifiers
# basic types
TYPE_NULL       = 'NULL'
TYPE_BOOL       = 'BOOLEAN'
TYPE_INT        = 'INTEGER'
TYPE_REAL       = 'REAL'
TYPE_ENUM       = 'ENUMERATED'
TYPE_BIT_STR    = 'BIT STRING'
TYPE_OCT_STR    = 'OCTET STRING'
TYPE_OID        = 'OBJECT IDENTIFIER'
TYPE_REL_OID    = 'RELATIVE-OID'
# string types
TYPE_STR_IA5    = 'IA5String'
TYPE_STR_PRINT  = 'PrintableString'
TYPE_STR_NUM    = 'NumericString'
TYPE_STR_VIS    = 'VisibleString'
TYPE_STR_BMP    = 'BMPString'
TYPE_STR_UTF8   = 'UTF8String'
TYPE_STR_ISO646 = 'ISO646String'
TYPE_STR_TELE   = 'TeletexString'
TYPE_STR_VID    = 'VideotexString'
TYPE_STR_GRAPH  = 'GraphicString'
TYPE_STR_T61    = 'T61String'
TYPE_STR_GENE   = 'GeneralString'
TYPE_STR_UNIV   = 'UniversalString'
TYPE_OBJ_DESC   = 'ObjectDescriptor'
# time types
TYPE_TIME_GEN   = 'GeneralizedTime'
TYPE_TIME_UTC   = 'UTCTime'
# constructed types
TYPE_CHOICE     = 'CHOICE'
TYPE_SEQ        = 'SEQUENCE'
TYPE_SEQ_OF     = 'SEQUENCE OF'
TYPE_SET        = 'SET'
TYPE_SET_OF     = 'SET OF'
# wrapper types
TYPE_OPEN       = 'OPEN_TYPE'
TYPE_ANY        = 'ANY'
TYPE_EXT        = 'EXTERNAL'
TYPE_EMB_PDV    = 'EMBEDDED PDV'
TYPE_CHAR_STR   = 'CHARACTER STRING'
# info object
TYPE_CLASS      = 'CLASS'
TYPE_INSTOF     = 'INSTANCE OF'

# types families
TYPES_BASIC = (
    TYPE_NULL,
    TYPE_BOOL,
    TYPE_INT,
    TYPE_REAL,
    TYPE_ENUM,
    TYPE_BIT_STR,
    TYPE_OCT_STR,
    TYPE_OID,
    TYPE_REL_OID,
    TYPE_STR_IA5,
    TYPE_STR_PRINT,
    TYPE_STR_NUM,
    TYPE_STR_VIS,
    TYPE_STR_BMP,
    TYPE_STR_UTF8,
    TYPE_STR_ISO646,
    TYPE_STR_TELE,
    TYPE_STR_VID,
    TYPE_STR_GRAPH,
    TYPE_STR_T61,
    TYPE_STR_GENE,
    TYPE_STR_UNIV,
    TYPE_OBJ_DESC,
    TYPE_TIME_GEN,
    TYPE_TIME_UTC
    )
TYPES_STRING = (
    TYPE_STR_IA5,
    TYPE_STR_PRINT,
    TYPE_STR_NUM,
    TYPE_STR_VIS,
    TYPE_STR_BMP,
    TYPE_STR_UTF8,
    TYPE_STR_ISO646,
    TYPE_STR_TELE,
    TYPE_STR_VID,
    TYPE_STR_GRAPH,
    TYPE_STR_T61,
    TYPE_STR_GENE,
    TYPE_STR_UNIV,
    TYPE_OBJ_DESC
    )
TYPES_CONSTRUCT = (
    TYPE_CHOICE,
    TYPE_SEQ,
    TYPE_SET,
    TYPE_SEQ_OF,
    TYPE_SET_OF
    )
TYPES_EXT = (
    TYPE_OPEN,
    TYPE_ANY,
    TYPE_EXT,
    TYPE_EMB_PDV,
    TYPE_CHAR_STR
    )
TYPES_CONST_SZ = (
    TYPE_BIT_STR,
    TYPE_OCT_STR,
    TYPE_SEQ_OF,
    TYPE_SET_OF
    ) + TYPES_STRING

# ASN.1 tag identifers
TAG_IMPLICIT     = 'IMPLICIT'
TAG_EXPLICIT     = 'EXPLICIT'
TAG_AUTO         = 'AUTOMATIC'
TAG_CONTEXT_SPEC = 'CONTEXT-SPECIFIC'
TAG_PRIVATE      = 'PRIVATE'
TAG_APPLICATION  = 'APPLICATION'
TAG_UNIVERSAL    = 'UNIVERSAL'

# constraints supported for types
CONST_VAL = 'VAL'
# keys: 'root': list,
#       'ext' : None or list
CONST_SIZE = 'SIZE'
# keys: 'root': list (of integer),
#       'ext' : None or list
CONST_CONTAINING = 'CONTAINING'
# keys: 'obj' : ASN1Obj,
#       'enc' : None or OID value
CONST_ALPHABET = 'ALPHABET'
# keys: 'root': list (of chars),
#       'ext' : None or list
CONST_COMPS = 'WITH COMPONENTS'
# keys: 'root': list
#       'ext': None or list
# each component of the root / ext list is a
# dict {'_abs' : list of absent ident,
#       '_pre' : list of present idents,
#       '$ident': {'const': [list of additional constraints for $ident]}
# constraints supported for CLASS
CONST_TABLE = 'TABLE'
# keys: 'tab': CLASS set object gathering all root / ext values
#       'at': str or None,
#       'exc': str or None
# constraints extacted but not supported at runtime
CONST_COMP = 'WITH COMPONENT'
# keys: none
CONST_ENCODE_BY = 'ENCODE BY'
# keys: None
CONST_REGEXP = 'PATTERN'
# keys: None
CONST_CONSTRAIN_BY = 'CONSTRAINED BY'
# keys: None
CONST_PROPERTY = 'SETTINGS'
# keys: none

# specific flags for constructed types components and CLASS type fields
FLAG_OPT   = 'OPTIONAL'
FLAG_UNIQ  = 'UNIQUE'
FLAG_DEF   = 'DEFAULT'
FLAG_DEFBY = 'DEFINED BY'

# specific flags for CLASS set of values, for specific use as table constraint
CLASET_UNIQ = 'U'
CLASET_MULT = 'M'
CLASET_NONE = 'N'

#------------------------------------------------------------------------------#
# asn1rt naming routine
#------------------------------------------------------------------------------#

def name_to_defin(n):
    if iskeyword(n):
        # n is a Python keyword
        n += '_'
    return n.replace('-', '_').replace(' ', '_')


#------------------------------------------------------------------------------#
# _String character parsing routine
#------------------------------------------------------------------------------#

def extract_charstr(text=''):
    """
    extracts the part of text between double-quote ", escaping doubled 
    double-quotes, and removing newline groups
    returns the remaining text, and the extracted content or None 
    """
    text = text.strip()
    if text[0:1] != '"':
        return text, None
    elif len(text) == 1:
        return text, None
    #
    esc = 0
    for cur in range(1, len(text)): 
        # 1) end of text
        if cur == len(text) - 1:
            if text[cur:1+cur] != '"':
                # no end-of-charstr found
                return text, None
            else:
                return '', re.subn('\s{0,}\n\s{0,}', '', text[1:-1])[0]
        
        # 2) finding a double-quote
        if text[cur:1+cur] == '"':
            if esc > 0:
                # 2.1) escape cursor already set
                if cur == esc:
                    # current double-quote escaped, unsetting escape cursor
                    esc = 0
                else:
                    # current double-quote not escaped
                    if text[1+cur:2+cur] == '"':
                        # escaping next char
                        esc = 1+cur
                    else:
                        # end of charstr
                        return text[1+cur:].strip(), \
                               re.subn('\s{0,}\n\s{0,}', '', text[1:cur])[0]
            else:
                # 2.2) escape cursor not set
                if text[1+cur:2+cur] == '"':
                    # escaping next char
                    esc = 1+cur
                else:
                    # end of charstr
                    return text[1+cur:].strip(), \
                           re.subn('\s{0,}\n\s{0,}', '', text[1:cur])[0]


_printable_str = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'\
                 '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c'

def is_printable(w):
    return all(c in _printable_str for c in w)

#------------------------------------------------------------------------------#
# integer factorization and rounding routine
#------------------------------------------------------------------------------#

# for PER fragmentation
# other ways on how to fragment are possible
def factor_perfrag(val):
    facs  = (65536, 49152, 32768, 16384)
    frags = []
    for f in facs:
        frags.append((f, val//f))
        val -= f * frags[-1][1]
    return frags, val


# for PER integer encoding
def int_bitlen(val):
    # get the length in bits required for the absolute value of val
    bl = val.bit_length()
    if val == -1<<(bl-1):
        # take care of the 2's complement dynamic
        # bl bits required
        return bl
    else:
        # 1+bl bits required
        return 1+bl


# for PER and BER integer encoding
def uint_bytelen(val):
    if val == 0:
        return 1
    bl = val.bit_length()
    if bl % 8:
        return 1 + (bl>>3)
    else:
        return bl>>3


def int_bytelen(val):
    # get the length in bits required for the absolute value of val
    if val == 0:
        bl = 1
    else:
        bl = val.bit_length()
    if val == -1<<(bl-1):
        # take care of the 2's complement dynamic
        # bl bits required
        if bl % 8:
            return 1 + (bl>>3)
        else:
            return bl>>3
    else:
        # bl+1 bits required
        bl += 1
        if bl % 8:
            return 1 + (bl>>3)
        else:
            return bl>>3


# for APER character rounding
def round_p2(val):
    e = 1
    while val > e:
        e <<= 1
    return e

#------------------------------------------------------------------------------#
# tag matching routine
#------------------------------------------------------------------------------#

def match_tag(Obj, tag):
    """Check in case tag (tag_class, tag_value) matches Obj,
    or some of its content in case Obj is untagged (CHOICE or OPEN / ANY)
    
    Returns:
        0 : no match
        1 : match
        2 and more: undetermined cases
    """
    if Obj._tagc:
        # Obj is tagged, check is easy
        if tag == Obj._tagc[0]:
            return 1
    elif Obj.TYPE == TYPE_CHOICE:
        # Obj is an untagged CHOICE, check is a bit more difficult
        if tag in Obj._cont_tags:
            return 1
        elif Obj._ext is not None:
            # extensible CHOICE object: that is tricky
            # in principle, the current tag could be part of it but we cannot
            # be sure...
            return 2
    elif Obj.TYPE in (TYPE_OPEN, TYPE_ANY):
        # Obj is an untagged OPEN / ANY object: this is a bit more tricky again
        if Obj._TAB_LUT and Obj._const_tab and Obj._const_tab_at:
            # a usable table constraint is defined
            const_obj_type, const_obj = Obj._get_tab_obj()
            if const_obj_type == CLASET_NONE:
                return 3
            elif const_obj_type == CLASET_UNIQ:
                ret = match_tag(const_obj, tag)
                if ret:
                    return ret
            else:
                #const_obj_type == CLASET_MULT
                for obj in const_obj:
                    ret = match_tag(obj, tag)
                    if ret:
                        return ret
        elif Obj._const_val:
            # some objects are defined as value constraint
            for ConstObj in Obj._const_val.root:
                ret = match_tag(ConstObj, tag)
                if ret:
                    return ret
            if Obj._const_val.ext is not None:
                # the value constraint is extensible
                for ConstObj in Obj._const_val.ext:
                    ret = match_tag(ConstObj, tag)
                    if ret:
                        return ret
                # the current tag could be part of this value constraint extension
                # but we cannot be sure, again...
                return 4
        elif hasattr(Obj, '_defby') and Obj._defby is not None:
            # DEFINED BY construction, not supported yet
            return 5
        else:
            # OPEN / ANY internal content cannot be determined
            # so we suppose we have a match
            return 1
    else:
        # we should never come here
        assert()
    return 0


def get_obj_by_tag(ObjOpen, tag, ConstList=None):
    """Check within the value constraint of an OPEN / ANY object ObjOpen 
    for a given tag (tag_class, tag_value) and return the matching object, 
    in case the tag matches
    """
    if not ConstList:
        # build ConstList from ObjOpen._const_val.root and ObjOpen._const_val.ext
        ConstList = ObjOpen._const_val.root
        if ObjOpen._const_val.ext:
            ConstList = ConstList + ObjOpen._const_val.ext
    #
    ret = []
    for ConstObj in ConstList:
        if ConstObj._tagc and tag == ConstObj._tagc[0]:
            ret.append(ConstObj)
        elif ConstObj.TYPE == TYPE_CHOICE and tag in ConstObj._cont_tags:
            ret.append(ConstObj)
    #
    return ret

#------------------------------------------------------------------------------#
# selection by path
#------------------------------------------------------------------------------#

def get_obj_at(Obj, path):
    """return the object within `Obj' according to the given path
    
    Args:
        Obj: ASN1Obj instance
        path: list of str
    
    Returns:
        ASN1Obj instance
    
    Raises:
        ASN1Err, if `path' is invalid
    """
    for p in path:
        try:
            if Obj.TYPE in (TYPE_CHOICE, TYPE_SEQ, TYPE_SET, TYPE_REAL, 
                            TYPE_EXT, TYPE_EMB_PDV, TYPE_CHAR_STR):
                Obj = Obj._cont[p]
            elif Obj.TYPE in (TYPE_SEQ_OF, TYPE_SET_OF):
                # p is not used
                Obj = Obj._cont
            elif Obj.TYPE in (TYPE_OPEN, TYPE_ANY):
                Obj = Obj._get_const_tr()[p]
            elif Obj.TYPE in (TYPE_BIT_STR, TYPE_OCT_STR):
                # p is not used
                Obj = Obj._const_cont
            else:
                raise()
        except:
            raise(ASN1Err('invalid object selection with path {0!r}, from {1}'\
                  .format(path, p)))
    return Obj  


def get_val_at(Obj, path):
    """return the value within `Obj' value according to the given path
    
    Args:
        Obj: ASN1Obj instance
        path: list of str or int
    
    Returns:
        value of an ASN1Obj instance
    
    Raises:
        ASN1Err, if `Obj' has no defined value or `path' is invalid
    """
    if Obj._val is None:
        raise(ASN1Err('{0} has no defined value'.format(Obj.fullname())))
    val = Obj._val
    for p in path:
        try:
            if Obj.TYPE in (TYPE_SEQ, TYPE_SET, TYPE_EXT, TYPE_EMB_PDV, TYPE_CHAR_STR):
                Obj = Obj._cont[p]
                val = val[p]
            elif Obj.TYPE == TYPE_REAL:
                Obj = None
                if instance(p, integer_types):
                    val = val[p]
                elif p == 'mantissa':
                    val = val[0]
                elif p == 'base':
                    val = val[1]
                elif p == 'exponent':
                    val = val[2]
                else:
                    raise()
            elif Obj.TYPE in (TYPE_CHOICE, TYPE_ANY, TYPE_OPEN, TYPE_BIT_STR, TYPE_OCT_STR):
                Obj = get_obj_at(Obj, [p])
                if p == val[0]:
                    val = val[1]
                else:
                    raise()
            elif Obj.TYPE in (TYPE_SEQ_OF, TYPE_SET_OF):
                Obj = Obj._cont
                val = val[p]
            else:
                raise()
        except:
            raise(ASN1Err('invalid value selection with path {0!r}, from {1}'\
                  .format(path, p)))
    return val


#------------------------------------------------------------------------------#
# working on the json dependency files generated by pycrate_asn1c
# to list top-level objects
#------------------------------------------------------------------------------#

def _get_json_dict(filepath):
    try:
        fd = open(filepath)
    except:
        asnlog('unable to open file: %r' % filepath)
        return None
    #
    import json
    jd = json.load(fd)
    fd.close()
    return jd


def get_top_level(filepath):
    """return the list of top-level ASN.1 object's names from the json file given 
    
    Args:
        filepath: path to the json file produces by the pycrate_asn1c compiler
    
    Returns:
        list of object's names
    """
    jd = _get_json_dict(filepath)
    if jd is None:
        return []
    #
    # modify the json dict to get something more workable
    objects = [node['id'] for node in jd['nodes']]
    sources, targets = set(), set()
    for link in jd['links']:
        sources.add( link['source'] )
        targets.add( link['target'] )
    #
    # check for each object if it references other objects,
    # but does not get referenced itself
    #
    ret = []
    for obj in objects:
        if obj in sources and obj not in targets:
            ret.append(obj)
    return ret


def get_referrers(filepath, objname):
    """return the list of ASN.1 object's names referring to the ASN.1 object
    objname
    
    Args:
        filepath: path to the json file produces by the pycrate_asn1c compiler
        objname: name of the ASN.1 object
    
    Returns:
        list of object's names
    """
    jd = _get_json_dict(filepath)
    if jd is None:
        return []
    objects = [node['id'] for node in jd['nodes']]
    if objname not in objects:
        asnlog('object %s not found' % objname)
        return []
    #
    ret = []
    for link in jd['links']:
        if link['target'] == objname:
            ret.append(link['source'])
    return ret


def get_referees(filepath, objname):
    """return the list of ASN.1 object's names referred by the ASN.1 object
    objname
    
    Args:
        filepath: path to the json file produces by the pycrate_asn1c compiler
        objname: name of the ASN.1 object
    
    Returns:
        list of object's names
    """
    jd = _get_json_dict(filepath)
    if jd is None:
        return []
    objects = [node['id'] for node in jd['nodes']]
    if objname not in objects:
        asnlog('object %s not found' % objname)
        return []
    #
    ret = []
    for link in jd['links']:
        if link['source'] == objname:
            ret.append(link['target'])
    return ret


#------------------------------------------------------------------------------#
# IEEE 754 float routines, used for REAL with OER codec
#------------------------------------------------------------------------------#

def decode_ieee754_32(char):
    """ Converts IEE754 single precision float to a pycrate REAL tuple:
    """
    sign = (-1) ** char.get_uint(1)
    exponent = char.get_uint(8) - 127
    fraction = char.get_uint(23)
    lsb = 0
    ifrac = 1
    for i in range(23):
        lb = fraction & 1
        if lb and (lsb == 0):
            lsb = 23 - i
        ifrac += 2 ** (-(23 - i)) * lb
        fraction = fraction >> 1

    # Convert the normalized mantissa (1.xxx) to a integer mantissa by multiplying 2
    ifrac = int((sign * ifrac) * (2 ** lsb))
    return (ifrac, 2, exponent - lsb)


def encode_ieee754_32(val):
    """ Converts pycrate REAL tuple into IEEE754 single precision value.
    """
    # There is of course a more efficient method going straight from mantissa,
    # but sorry, no time. This at least works for arbitrary base.
    return pack('>f', val[0] * (val[1] ** val[2]))


def decode_ieee754_64(char):
    """ Converts IEE754 single precision float to a pycrate REAL tuple:
    """
    sign = (-1) ** char.get_uint(1)
    exponent = char.get_uint(11) - 1023
    fraction = char.get_uint(52)
    lsb = 0
    ifrac = 1
    for i in range(52):
        lb = fraction & 1
        if lb and (lsb == 0):
            lsb = 53 - i
        ifrac += 2 ** (-(52 - i)) * lb
        fraction = fraction >> 1

    # Convert the normalized mantissa (1.xxx) to a integer mantissa by multiplying 2
    ifrac = int((sign * ifrac) * (2 ** lsb))
    return (ifrac, 2, exponent - lsb)


def encode_ieee754_64(val):
    """ Converts pycrate REAL tuple into IEEE754 single precision value.
    """
    # There is of course a more efficient method going straight from mantissa,
    # but sorry, no time. This at least works for arbitrary base.
    return pack('>d', val[0] * (val[1] ** val[2]))

