# -*- coding: UTF-8 -*-
# /**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2016. Benoit Michau. ANSSI.
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
# * File Name : pycrate_asn1c/utils.py
# * Created : 2016-03-02
# * Authors : Benoit Michau 
# *--------------------------------------------------------
# */

import re
import pprint
from keyword import iskeyword

# pycrate_core is used only for basic library-wide functions / variables:
# log(), python_version, integer_types, str_types
from pycrate_core.utils import *
from .err               import ASN1Err

# ------------------------------------------------------------------------------#
# asn1-wide Python routines
# ------------------------------------------------------------------------------#

def asnlog(msg):
    """
    customizable logging function for the whole asn1 part
    """
    log(msg)


_PP = pprint.PrettyPrinter(indent=1, width=80, depth=None, stream=None)

def pprint(obj):
    return _PP.pprint(obj)

def pformat(obj):
    return _PP.pformat(obj)

# ------------------------------------------------------------------------------#
# asn1-wide Python variables and identifiers
# ------------------------------------------------------------------------------#

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
TYPE_TYPEIDENT  = 'TYPE-IDENTIFIER'
TYPE_ABSSYNT    = 'ABSTRACT-SYNTAX'
TYPE_INSTOF     = 'INSTANCE OF'


# string types
TYPE_STRINGS    = (TYPE_STR_IA5, TYPE_STR_PRINT, TYPE_STR_NUM, TYPE_STR_VIS, 
                   TYPE_STR_BMP, TYPE_STR_UTF8, TYPE_STR_ISO646, TYPE_STR_TELE,
                   TYPE_STR_VID, TYPE_STR_GRAPH, TYPE_STR_T61, TYPE_STR_GENE,
                   TYPE_STR_UNIV, TYPE_OBJ_DESC)

# types with constructed content
TYPE_CONSTRUCT  = (TYPE_SEQ_OF, TYPE_SET_OF,
                   TYPE_CHOICE, TYPE_SEQ, TYPE_SET,
                   TYPE_CLASS,
                   TYPE_REAL, TYPE_EXT, TYPE_EMB_PDV)

# types with potential SIZE constraint
TYPE_CONST_SIZE = (TYPE_BIT_STR, TYPE_OCT_STR,
                   TYPE_STR_IA5, TYPE_STR_PRINT, TYPE_STR_NUM, TYPE_STR_VIS,
                   TYPE_STR_BMP, TYPE_STR_UTF8, TYPE_STR_ISO646, TYPE_STR_TELE,
                   TYPE_STR_VID, TYPE_STR_GRAPH, TYPE_STR_T61, TYPE_STR_GENE,
                   TYPE_STR_UNIV, TYPE_OBJ_DESC,
                   TYPE_SEQ_OF, TYPE_SET_OF,
                   TYPE_CHAR_STR)
                    

# ASN.1 tag identifers
TAG_IMPLICIT     = 'IMPLICIT'
TAG_EXPLICIT     = 'EXPLICIT'
TAG_AUTO         = 'AUTOMATIC'
TAG_CONTEXT_SPEC = 'CONTEXT-SPECIFIC'
TAG_PRIVATE      = 'PRIVATE'
TAG_APPLICATION  = 'APPLICATION'
TAG_UNIVERSAL    = 'UNIVERSAL'

# ASN.1 tag class canonical orderding
TAG_CANON_ORDER = {
    TAG_UNIVERSAL: 0,
    TAG_APPLICATION: 1,
    TAG_CONTEXT_SPEC: 2,
    TAG_PRIVATE: 3
    }

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

# ------------------------------------------------------------------------------#
# regexp for processing ASN.1 text
# ------------------------------------------------------------------------------#

# list of all ASN.1 keywords
SYNT_KEYWORDS = (
    'ABSENT', 'ABSTRACT-SYNTAX', 'ALL', 'APPLICATION', 'AUTOMATIC', 'BEGIN',
    'BIT', 'BMPString', 'BOOLEAN', 'BY', 'CHARACTER', 'CHOICE', 'CLASS', 'COMPONENT',
    'COMPONENTS', 'CONSTRAINED', 'CONTAINING', 'DEFAULT', 'DEFINITIONS', 'EMBEDDED',
    'ENCODED', 'END', 'ENUMERATED', 'EXCEPT', 'EXPLICIT', 'EXPORTS', 'EXTENSIBILITY',
    'EXTERNAL', 'FALSE', 'FROM', 'GeneralizedTime', 'GeneralString', 'GraphicString',
    'IA5String', 'IDENTIFIER', 'IMPLICIT', 'IMPLIED', 'IMPORTS', 'INCLUDES', 'INSTANCE',
    'INTEGER', 'INTERSECTION', 'ISO646String', 'MAX', 'MIN', 'MINUS-INFINITY',
    'NULL', 'NumericString', 'OBJECT', 'ObjectDescriptor', 'OCTET', 'OF', 'OPTIONAL',
    'PATTERN', 'PDV', 'PLUS-INFINITY', 'PRESENT', 'PrintableString', 'PRIVATE',
    'REAL', 'RELATIVE-OID', 'SEQUENCE', 'SET', 'SIZE', 'STRING', 'SYNTAX', 'T61String',
    'TAGS', 'TeletexString', 'TRUE', 'TYPE-IDENTIFIER', 'UNION', 'UNIQUE', 'UNIVERSAL',
    'UniversalString', 'UTCTime', 'UTF8String', 'VideotexString', 'VisibleString',
    'WITH')
_RE_KEYWORDS = '|'.join(SYNT_KEYWORDS)

# list of all ASN.1 basic types, constructed types and class
# WNG: OPEN_TYPE is a custom internal identifier
# WNG: INSTANCE OF is handled as a native type since it has a specific syntax
SYNT_NATIVE_TYPES = (
    'BOOLEAN', 'NULL', 'INTEGER', 'ENUMERATED', 'REAL', 'BIT STRING',
    'OCTET STRING', 'OBJECT IDENTIFIER', 'RELATIVE-OID',
    'NumericString', 'PrintableString', 'VisibleString', 'ISO646String',
    'IA5String', 'TeletexString', 'T61String', 'VideotexString', 'GraphicString',
    'GeneralString', 'UniversalString', 'BMPString', 'UTF8String',
    'ObjectDescriptor', 'GeneralizedTime', 'UTCTime',
    'SEQUENCE', 'SEQUENCE OF', 'SET', 'SET OF', 'CHOICE',
    'EXTERNAL', 'EMBEDDED PDV', 'CHARACTER STRING',
    'ANY', 'OPEN_TYPE',
    'CLASS', 'TYPE-IDENTIFIER', 'ABSTRACT-SYNTAX', 'INSTANCE OF')
_RE_NATIVE_TYPES = '|'.join(SYNT_NATIVE_TYPES)

# list of all ASN.1 keywords that cannot be used in a WITH SYNTAX statement
SYNT_SYNTAX_BL = (
    'BIT', 'BOOLEAN', 'CHARACTER', 'CHOICE', 'EMBEDDED', 'END', 'ENUMERATED',
    'EXTERNAL', 'FALSE', 'INSTANCE', 'INTEGER', 'INTERSECTION', 'MINUS-INFINITY',
    'NULL', 'OBJECT', 'OCTET', 'PLUS-INFINITY', 'REAL', 'RELATIVE-OID', 'SEQUENCE',
    'SET', 'TRUE', 'UNION')

# basic ASN.1 tokens
_RE_INTEGER = '(?:\-{0,1}0{1})|(?:\-{0,1}[1-9]{1}[0-9]{0,})'
_RE_INTEGER_POS = '(?:\-{0,1}0{1})|(?:[1-9]{1}[0-9]{0,})'
_RE_IDENT = '[a-z]{1,}[a-zA-Z0-9\-]{0,}'
_RE_TYPEREF = '[A-Z]{1,}[a-zA-Z0-9\-]{0,}'
_RE_CLASSREF = '[A-Z]{1,}[A-Z0-9\-]{0,}'
_RE_WORD = '[a-zA-Z]{1,}[a-zA-Z0-9\-]{0,}'

# ASN.1 names
SYNT_RE_WORD = re.compile(
    '(?:^|\s{1})(%s)' % _RE_WORD)
SYNT_RE_IDENT = re.compile(
    '(?:^|\s{1})(%s)' % _RE_IDENT)
SYNT_RE_TYPE = re.compile(
    '(?:^|\s{1})(%s)(?:$|[^0-9^a-z^A-Z^\-]{1,})' % _RE_NATIVE_TYPES)
SYNT_RE_TYPEREF = re.compile(
    '(?:^|\s{1})(%s)' % _RE_TYPEREF)
SYNT_RE_CLASSREF = re.compile(
    '(?:^|\s{1})(%s)' % _RE_CLASSREF)
SYNT_RE_CLASSFIELDIDENT = re.compile(
    '(?:^|\s{1})\&([a-zA-Z0-9\-]{1,})')
SYNT_RE_CLASSFIELDREF = re.compile(
    '(?:^|\s{1})((%s)\s{0,1}\.\&([a-zA-Z0-9\-]{1,}))' % _RE_CLASSREF)
SYNT_RE_CLASSFIELDREFINT = re.compile(
    '(?:^|\s{1})\&(%s)' % _RE_TYPEREF)
SYNT_RE_CLASSVALREF = re.compile(
    '(?:^|\s{1})((%s)\s{0,1}\.\&([a-zA-Z0-9\-]{1,}))' % _RE_IDENT)
SYNT_RE_CLASSINSTFIELDREF = re.compile(
    '(?:^|\s{1})(%s)(?:\s{0,1}\.\&(%s)){0,}' % (_RE_WORD, _RE_WORD))
SYNT_RE_IDENTEXT = re.compile(
    '(?:^|\s{1})((%s)\.(%s))' % (_RE_TYPEREF, _RE_IDENT))
# WNG: SYNT_RE_TYPEREF matches also SYNT_RE_CLASSREF

# ASN.1 expressions
SYNT_RE_MODULEDEF = re.compile(
    '\s{1,}(DEFINITIONS)\s{1,}')
SYNT_RE_MODULEREF = re.compile(
    '(?:^|\s{1})(%s){1}\s{0,}(\{[\s\-a-zA-Z0-9\(\)]{1,}\}){0,1}' % _RE_TYPEREF)

SYNT_RE_MODULEFROM = re.compile(
    '(?:FROM\s{1,})(%s)\s*' % _RE_TYPEREF)
SYNT_RE_MODULEFROM_SYM = re.compile(
    '(%s)(?:\s*\{\s*\}){0,1}(?:\s*,|\s{1,}FROM)' % _RE_WORD)
SYNT_RE_MODULEFROM_OID = re.compile(
    '(%s)\s*|(\{[a-zA-Z0-9\(\)\-\s]{4,}\})\s*' % _RE_IDENT)
SYNT_RE_MODULEFROM_WIT = re.compile(
    'WITH\s{1,}(SUCCESSORS|DESCENDANTS)\s*')

SYNT_RE_MODULEEXP = re.compile(
    '(?:^|\s{1})EXPORTS((.|\n)*?);')
SYNT_RE_MODULEIMP = re.compile(
    '(?:^|\s{1})IMPORTS((.|\n)*?);')
SYNT_RE_MODULEOPT = re.compile(
    '(?:^|\s{1})(EXPLICIT\s{1,}TAGS|IMPLICIT\s{1,}TAGS|AUTOMATIC\s{1,}TAGS)')
SYNT_RE_MODULEEXT = re.compile(
    '(?:^|\s{1})(EXTENSIBILITY\s{1,}IMPLIED)')
SYNT_RE_TAG = re.compile(
    '\[\s{0,}(UNIVERSAL|APPLICATION|PRIVATE){0,1}\s{0,}(?:(%s)|(%s))\s{0,}\]' \
    % (_RE_INTEGER_POS, _RE_IDENT))
SYNT_RE_PARAM = re.compile(
    '(%s)(?:\s{0,}\:\s{0,}(%s|%s)){0,1}' \
    % (_RE_TYPEREF, _RE_IDENT, _RE_TYPEREF))
SYNT_RE_SIZEOF = re.compile(
    '(\({0,1}\s{0,}SIZE)|(OF)')
SYNT_RE_INT_ID = re.compile(
    '(%s)\s{0,}\(\s{0,}((%s)|(%s))\s{0,}\)' \
    % (_RE_IDENT, _RE_INTEGER, _RE_IDENT))
SYNT_RE_ENUM = re.compile(
    '(%s|\.{3})\s{0,}(?:\(\s{0,}((%s)|(%s))\s{0,}\)){0,1}' \
    % (_RE_IDENT, _RE_INTEGER, _RE_IDENT))
SYNT_RE_OID_COMP = re.compile(
    '(%s)|((%s)\s{0,}(?:\((%s)\)){0,1})' \
    % (_RE_INTEGER_POS, _RE_IDENT, _RE_INTEGER_POS))
SYNT_RE_CLASSSYNTAX = re.compile(
    '(?:^|\s{1})((\[)|(\])|([A-Z\-]{1,})|(\&([a-zA-Z0-9\-]{1,})))')
SYNT_RE_CHOICEALT = re.compile(
    '(?:^|\s{1})(?:(%s)(?:\s{0,}<\s{0,})){1,}(%s)' % (_RE_IDENT, _RE_TYPEREF))
SYNT_RE_INTVAL = re.compile(
    '(?:^|\s{1})(\-{0,1}[0-9]{1,})')
SYNT_RE_BSTRING = re.compile(
    '(?:^|\s{1})\'([\s01]{0,})\'B')
SYNT_RE_HSTRING = re.compile(
    '(?:^|\s{1})\'([\s0-9A-F]{0,})\'H')
SYNT_RE_REALNUM = re.compile(
    '(?:^|\s{1})' \
    '(\-{0,1}[0-9]{1,}){1}' \
    '(?:\.([0-9]{0,})){0,1}' \
    '(?:[eE](\-{0,1}[0-9]{1,})){0,1}')
SYNT_RE_REALSEQ = re.compile(
    '(?:^|\s{1})' \
    '(?:\{\s{0,}mantissa\s{1,}(\-{0,1}[0-9]{1,})\s{0,},' \
    '\s{0,}base\s{1,}(2|10)\s{0,},' \
    '\s{0,}exponent\s{1,}(\-{0,1}[0-9]{1,})\s{0,}\})')
SYNT_RE_REALSPEC = re.compile(
    '(?:^|\s{1})((?:PLUS\-INFINITY)|(?:MINUS\-INFINITY)|(?:NOT-A-NUMBER))')
SYNT_RE_UNIVSTR = re.compile(
    '(?:^|\s{1})(?:\{\s{0,}'\
    '([0-9]{1,3})\s{0,},\s{0,}([0-9]{1,3})\s{0,},\s{0,}'\
    '([0-9]{1,3})\s{0,},\s{0,}([0-9]{1,3})\s{0,}\})')
SYNT_RE_TIMEUTC = re.compile(
    '(?:^|\s{1})' \
    '"([0-9]{2})([0-9]{2})([0-9]{2})' \
    '([0-9]{2})([0-9]{2})([0-9]{2}){0,1}' \
    '((?:Z)|(?:[+-]{1}[0-9]{4}))"')
SYNT_RE_TIMEGENE = re.compile(
    '(?:^|\s{1})' \
    '"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})' \
    '(?:([0-9]{2})([0-9]{2}){0,1}){0,1}' \
    '(?:(?:\.|,)([0-9]{1,})){0,1}' \
    '((?:Z)|(?:[+-](?:[0-9]{2}){0,2})){0,1}"')
SYNT_RE_CONST_DISPATCH = re.compile(
    '(?:^|\s{1})(INCLUDES)|(SIZE)|(FROM)|(WITH COMPONENTS)|(WITH COMPONENT)|' \
    '(PATTERN)|(SETTINGS)|(CONTAINING)|(ENCODED BY)|(CONSTRAINED BY)')
SYNT_RE_CONST_EXT = re.compile(
    ',\s{0,}\.\.\.')
SYNT_RE_GROUPVERS = re.compile(
    '(?:^|\s{1})[0-9]{1,}\s{0,1}\:')

def match_typeref(text):
    m = SYNT_RE_TYPEREF.match(text)
    if not m:
        return None
    else:
        # ensure the match does not correspond to an ASN.1 keyword
        if m.group() in SYNT_KEYWORDS:
            return None
        else:
            return m

# ------------------------------------------------------------------------------#
# text processing routines
# ------------------------------------------------------------------------------#


def strip(text=''):
    return text.strip()


def name_to_defin(n):
    if iskeyword(n):
        # n is a Python keyword
        n += '_'
    return n.replace('-', '_').replace(' ', '_')


def scan_for_comments(text=''):
    """
    returns a list of 2-tuple (start offset, end offset) for each ASN.1 comment
    found in text
    """
    ret = []
    cur = 0
    next = text.find('--')
    while next >= 0:
        cur += next
        # start of comment
        start = cur
        # move cursor forward to reach the end of comment
        cur += 2
        # exception for line full of ------------------ sh*t
        while text[cur:1+cur] == '-':
            cur += 1
        while True:
            # move 1 by 1
            if text[cur:1+cur] == '\n' or cur >= len(text):
                # end-of-line or end-of-file
                ret.append((start, cur))
                cur += 1
                break
            elif text[cur:2+cur] == '--':
                # end-of-comment
                cur += 2
                ret.append((start, cur))
                break
            else:
                cur += 1
        # find the next comment
        next = text[cur:].find('--')
    return ret


def scan_for_comments_cstyle(text=''):
    """
    returns a list of 2-tuple (start offset, end offset) for each ASN.1 comment
    in C-style found in text
    """
    ret = []
    cur = 0
    next = text.find('/*')
    while next >= 0:
        cur += next
        # start of comment
        start = cur
        # move cursor forward to reach the end of comment
        cur += 2
        while True:
            # move 1 by 1 and find an end-of-comment or end-of-file
            if cur >= len(text):
                # end-of-file
                ret.append((start, cur))
                break
            elif text[cur:2+cur] == '*/':
                # end-of-comment
                cur += 2
                ret.append((start, cur))
                break
            else:
                cur += 1
        # find the next comment
        next = text[cur:].find('/*')
    return ret


def clean_text(text=''):
    """
    processes text to: 
        remove ASN.1 comments
        replace tab with space
        remove duplicated spaces
    """
    # WARNING: this routine for text cleanup, as it is applied early in the text
    # processing, may mess up ASN.1 string values
    #
    # remove comments
    comments = scan_for_comments(text)
    if comments:
        # get the complementary text to comments, to get the text containing
        # the actual definitions
        start, defins = 0, []
        for (so, eo) in comments:
            defins.append( text[start:so] )
            start = eo
        defins.append( text[start:len(text)] )
        text = ''.join(defins)
    #
    # remove C-style comments
    comments = scan_for_comments_cstyle(text)
    if comments:
        start, defins = 0, []
        for (so, eo) in comments:
            defins.append( text[start:so] )
            start = eo
        defins.append( text[start:len(text)] )
        text = ''.join(defins)
    #
    # replace tab with space
    text = text.replace('\t', ' ')
    # remove duplicated CR
    text = re.sub('\n{2,}', '\n', text)
    # remove duplicated spaces
    text = re.sub(' {2,}', ' ', text)
    #
    return text


def search_top_lvl_sep(text='', sep=','):
    """
    returns a list of offsets for each top-level separator `sep' found in the text
    """
    ret = []
    #
    count = {'(': 0, ')': 0, '{': 0, '}': 0, '[': 0, ']': 0}
    _is_top_level = lambda c: c['('] == c[')'] and c['{'] == c['}'] and c['['] == c[']']
    #
    for cur in range(len(text)):
        if text[cur] in count:
            count[text[cur]] += 1
        if text[cur] == sep and _is_top_level(count):
            ret.append(cur)
    return ret


def search_top_lvl_off(text=''):
    """
    returns the offsets in the text corresponding to the top level
    (outside of any parenthesis / bracket / curlybracket groups)
    """
    # {1, 2, {3, True}} DEFAULT (1, 2) UNIQUE
    off = [[0]]
    #
    count = {'(': 0, ')': 0, '{': 0, '}': 0, '[': 0, ']': 0}
    _is_top_level = lambda c: c['('] == c[')'] and c['{'] == c['}'] and c['['] == c[']']
    #
    top_level = True
    for cur in range(len(text)):
        char = text[cur]
        if char in count:
            count[char] += 1
        if top_level and not _is_top_level(count):
            # transition to inner group: closing the top-level boundary
            off[-1].append(cur)
            top_level = False
        elif not top_level and _is_top_level(count):
            # transition to top level: opening a top-level boundary
            off.append([cur + 1])
            top_level = True
    # end of text
    if top_level:
        off[-1].append(len(text) + 1)
    else:
        # error ?
        del off[-1]
    # some clean-up
    if off[0] == [0, 0]:
        del off[0]
    return off


def search_between(text='', ins='{', outs='}'):
    """
    returns a list of 2-tuple for each top level part of the text in-between 
    `ins' and `outs' expression
    """
    # TODO: look for character string, defined between double-quotes ",
    # and do not evaluate matching character inside them
    #
    if len(ins) != len(outs):
        raise(ASN1Err('requires identical length for ins and outs'))
    lens = len(ins)
    #
    ret = []
    #
    count = {ins: 0, outs: 0}
    entered = False
    #
    for cur in range(len(text)):
        if not entered and text[cur:cur + lens] == ins:
            # passing initial ins char
            entered = True
            start = cur
        if text[cur:cur + lens] in count:
            # counting ins / outs chars
            count[text[cur:cur + lens]] += 1
        if entered and count[ins] == count[outs]:
            # passing last outs char
            stop = cur + lens
            ret.append((start, stop))
            entered = False
    return ret


def extract_curlybrack(text=''):
    """
    extracts the part of text between "{" and "}" if the "{" is at the start
    of the string
    returns the remaining text, and the extracted content or None
    """
    text = text.strip()
    offsets = search_between(text, '{', '}')
    if not offsets:
        return text, None
    offsets = offsets[0]
    if offsets[0] != 0:
        return text, None
    return text[offsets[1]:].strip(), text[1:offsets[1] - 1].strip()


def extract_parenth(text=''):
    """
    extracts the part of text between "(" and ")" if the "(" is at the start
    of the string
    returns the remaining text, and the extracted content or None
    """
    text = text.strip()
    offsets = search_between(text, '(', ')')
    if not offsets:
        return text, None
    offsets = offsets[0]
    if offsets[0] != 0:
        return text, None
    return text[offsets[1]:].strip(), text[1:offsets[1] - 1].strip()


def extract_brack(text=''):
    """
    extracts the part of text between "[" and "]" if the "[" is at the start
    of the string
    returns the remaining text, and the extracted content or None
    """
    text = text.strip()
    offsets = search_between(text, '[', ']')
    if not offsets:
        return text, None
    offsets = offsets[0]
    if offsets[0] != 0:
        return text, None
    return text[offsets[1]:].strip(), text[1:offsets[1] - 1].strip()


def extract_doublebrack(text=''):
    """
    extracts the part of text between "[[" and "]]" if the "[[" is at the start
    of the string
    returns the remaining text, and the extracted content or None
    """
    text = text.strip()
    offsets = search_between(text, '[[', ']]')
    if not offsets:
        return text, None
    offsets = offsets[0]
    if offsets[0] != 0:
        return text, None
    return text[offsets[1]:].strip(), text[2:offsets[1] - 2].strip()


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


def extract_multi(text=''):
    """
    extracts the list of textual components between curly-brackets
    returns the remaining text, and the list of extracted textual components
    """
    # e.g. { comp1, comp2, comp3 }
    rest, text = extract_curlybrack(text)
    if not text:
        return rest, text
    else:
        # split each coma-separated field
        coma_offsets = [-1] + search_top_lvl_sep(text, ',') + [len(text)]
        return rest, list(map(strip,
                              [text[coma_offsets[i] + 1:coma_offsets[i + 1]] \
                               for i in range(len(coma_offsets) - 1)]))


def extract_set(text=''):
    """
    extracts the list of root and extended textual components,
    each component being separated with "|",
    and root and extension being separated with commas and "..."
    taking care of character strings definition between double-quotes "
    
    returns a dict with root and ext keys and corresponding strings
    """
    # 1) we go char by char with a state machine, looking for:
    # 1) unescaped double-quote "
    # 2) or separator |
    # 3) coma ,
    #
    text = text.strip()
    #
    # list the set of group of values
    # the current group of values
    # the current list of chars
    valset = []
    valgrp = []
    value  = []
    #
    # state that says if we are in a charstr, between " or not
    # we do not evaluate escaped double-quotes especially, 
    # as it is like we are leaving and reentering the charstr state
    charstr = False
    #
    # state that says if we are inside any inner set inside the given set, 
    # between { and } or not
    innerset = 0
    #
    # go char by char
    for char in text:
        value.append(char)
        if char == '"':
            if charstr:
                charstr = False
            else:
                charstr = True
        else:
            if not charstr:
                if char == '{':
                    innerset += 1
                elif char == '}':
                    innerset -= 1
                    if innerset < 0:
                        raise(ASN1Err('extract_set, invalid number of closing curlybrackets'\
                              .format(text)))
                if innerset == 0:
                    if char == '|':
                        valgrp.append( ''.join(value[:-1]).strip() )
                        value = []
                    elif char == ',':
                        valgrp.append( ''.join(value[:-1]).strip() )
                        value = []
                        valset.append( valgrp )
                        valgrp = []
    if value:
        valgrp.append( ''.join(value).strip() )
    if valgrp:
        valset.append( valgrp )
    #
    # 2) we evaluate the list of groups found and the potential extensibility 
    # marker in between, and build the resulting root / ext dict
    #
    if len(valset) == 0:
        return {'root': [], 'ext': None}
    elif len(valset) == 1:
        if valset[0] == ['...']:
            return {'root': [], 'ext': []}
        else:
            return {'root': valset[0], 'ext': None}
    elif len(valset) == 2:
        if valset[0] == ['...']:
            return {'root': [], 'ext': valset[1]}
        else:
            if valset[1] != ['...']:
                raise(ASN1Err('extract_set, invalid coma-separated groups, {0!r}'\
                      .format(valset)))
            return {'root': valset[0], 'ext': []}
    elif len(valset) == 3:
        if valset[1] != ['...']:
            raise(ASN1Err('extract_set, invalid coma-separated groups, {0!r}'\
                  .format(valset)))
        return {'root': valset[0], 'ext': valset[2]}
    else:
        raise(ASN1Err('extract_set, invalid coma-separated groups, {0!r}'\
              .format(valset)))


def extract_from_import(text=''):
    """
    extracts the module name, reference and / or OID set after a FROM import
    statement, test `text` argument must start with the FROM keyword
    
    returns a 2-tuple with
        integer: length of the text containing the whole FROM statement
        dict: with "name", "oid", "oidref" and "with" keys
    """
    m = SYNT_RE_MODULEFROM.match(text)
    assert(m)
    cur = m.end()
    ret = {'name': m.group(1), 'oid': None, 'oidref': None, 'with': None}
    # check if we stop or continue with an OID value or OID reference
    if SYNT_RE_MODULEFROM_SYM.match(text[cur:]) or not text[cur:]:
        return cur, ret
    m = SYNT_RE_MODULEFROM_OID.match(text[cur:])
    assert(m)
    cur += m.end()
    assert(None in m.groups())
    if m.group(1):
        ret['oidref'] = m.group(1)
    else:
        ret['oid'] = m.group(2)
    # check if there is a final WITH stmt
    m = SYNT_RE_MODULEFROM_WIT.match(text[cur:])
    if m:
        ret['with'] = m.group(1)
        cur += m.end()
    # final control
    assert(SYNT_RE_MODULEFROM_SYM.match(text[cur:]) or not text[cur:])
    return cur, ret

