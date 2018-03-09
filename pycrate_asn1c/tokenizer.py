# -*- coding: UTF-8 -*-
# /**
# * Software Name : pycrate
# * Version : 0.3
# *
# * Copyright 2018. Benoit Michau. ANSSI.
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
# * File Name : pycrate_asn1c/tokenizer.py
# * Created : 2018-03-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
# */

import re
from .err import *

# white space and new line
_NL  = '\x0a\x0b\x0c\x0d'
_SNL = '\x09\x0a\x0b\x0c\x0d\x20' + '\xa0' # a0 is not a valid UTF-8 char
REScannerSNL = '[%s]{1,}' % _SNL

# exclude more characters
_EXC = '(?![a-zA-Z0-9\-]{1,})'

# native types
REScannerNTypes = '|'.join((
    'NULL',
    'BOOLEAN',
    'INTEGER',
    'REAL',
    'ENUMERATED',
    'OBJECT IDENTIFIER',
    'RELATIVE-OID',
    'OID-IRI',
    'RELATIVE-OID-IRI',
    'BIT STRING',
    'OCTET STRING',
    'NumericString',
    'PrintableString',
    'VisibleString',
    'ISO646String',
    'IA5String',
    'TeletexString',
    'T61String',
    'VideotexString',
    'GraphicString',
    'GeneralString',
    'UniversalString',
    'BMPString',
    'UTF8String',
    'ObjectDescriptor',
    'GeneralizedTime',
    'UTCTime',
    'TIME',
    'SEQUENCE',
    'SET',
    'CHOICE',
    'EXTERNAL',
    'EMBEDDED PDV',
    'CHARACTER STRING',
    'ANY',
    'CLASS',
    'TYPE-IDENTIFIER',
    'ABSTRACT-SYNTAX',
    'INSTANCE OF',
    'MACRO'
    ))

# integer
REScannerInt = '([+\-](?:[%s]{0,})){0,1}[0-9]{1,}' % _SNL

# real           int     dec                   exp
REScannerReal = '(%s){1}(?:\.([0-9]{0,})){0,1}(?:(?:[%s]{0,})[eE](%s)){0,1}'\
                % (REScannerInt, _SNL, REScannerInt)

# bstring
REScannerBStr = '\'[%s01]{0,}\'B' % _SNL

# hstring
REScannerHStr = '\'[%s0-9A-F]{0,}\'H' % _SNL


# tokens' identifiers

# comments and character string
TOK_CMT     = 'CMT'   # comment
TOK_CSTR    = 'CSTR'  # chars string

# definition and tag related
TOK_DEFI    = 'DEFI'  # DEFINITIONS
TOK_EXTI    = 'EXTI'  # EXTENSIBILITY IMPLIED
TOK_BEG     = 'BEG'   # BEGIN
TOK_END     = 'END'   # END
TOK_TAGS    = 'TAGS'  # TAGS
TOK_TUNI    = 'TUNI'  # UNIVERSAL
TOK_TAPP    = 'TAPP'  # APPLICATION
TOK_TPRI    = 'TPRI'  # PRIVATE
TOK_TEXP    = 'TEXP'  # EXPLICIT
TOK_TIMP    = 'TIMP'  # IMPLICIT

# set and value related
TOK_MINF    = 'MINF'  # MINUS-INFINITY
TOK_PINF    = 'PINF'  # PLUS-INFINITY
TOK_NAN     = 'NAN'   # NOT-A-NUMBER
TOK_ALL     = 'ALL'   # ALL
TOK_MIN     = 'MIN'   # MIN
TOK_MAX     = 'MAX'   # MAX
TOK_EXCE    = 'EXCE'  # EXCEPT
TOK_NULL    = 'NULL'  # NULL
TOK_TRUE    = 'TRUE'  # TRUE
TOK_FALS    = 'FALS'  # FALSE
TOK_REAL    = 'REAL'  # real number
TOK_INT     = 'INT'   # integer
TOK_BSTR    = 'BSTR'  # binary string
TOK_HSTR    = 'HSTR'  # hexa string

# other various keywords
TOK_ABS     = 'ABS'   # ABSENT
TOK_AUTO    = 'AUTO'  # AUTOMATIC
TOK_BY      = 'BY'    # BY
TOK_COMP    = 'COMP'  # COMPONENT
TOK_COMPS   = 'COMPS' # COMPONENTS
TOK_CONST   = 'CONST' # CONSTRAINED
TOK_CONT    = 'CONT'  # CONTAINING
TOK_DEF     = 'DEF'   # DEFAULT
TOK_ENC     = 'ENC'   # ENCODED
TOK_EXP     = 'EXP'   # EXPORTS
TOK_FROM    = 'FROM'  # FROM
TOK_IMP     = 'IMP'   # IMPORTS
TOK_INCL    = 'INCL'  # INCLUDES
TOK_OF      = 'OF'    # OF
TOK_OPT     = 'OPT'   # OPTIONAL
TOK_PAT     = 'PAT'   # PATTERN
TOK_PRES    = 'PRES'  # PRESENT
TOK_SIZE    = 'SIZE'  # SIZE
TOK_WSYN    = 'WSYN'  # WITH SYNTAX
TOK_UNIQ    = 'UNIQ'  # UNIQUE

# identifier related
TOK_NTYPE   = 'NTYPE' # native type
TOK_CLAID   = 'CLAID' # &[iI]dentifier
TOK_HID     = 'HID'   # IDENTIFIER
TOK_ID      = 'ID'    # Identifier
TOK_LID     = 'LID'   # identifier

# special (series of) characters
TOK_ASSI    = 'ASSI'  # ::=
TOK_COL     = 'COL'   # :
TOK_SCOL    = 'SCOL'  # ;
TOK_EQU     = 'EQU'   # =
TOK_COM     = 'COM'   # ,
TOK_PARO    = 'PARO'  # (
TOK_PARC    = 'PARC'  # )
TOK_DBRAO   = 'DBRAO' # [[
TOK_DBRAC   = 'DBRAC' # ]]
TOK_BRAO    = 'BRAO'  # [
TOK_BRAC    = 'BRAC'  # ]
TOK_CBRAO   = 'CBRAO' # {
TOK_CBRAC   = 'CBRAC' # }
TOK_TDOT    = 'TDOT'  # ...
TOK_DDOT    = 'DDOT'  # ..
TOK_DOT     = 'DOT'   # .
TOK_DOTA    = 'DOTA'  # .&
TOK_UNIO    = 'UNIO'  # |
TOK_INTER   = 'INTER' # ^
TOK_LTHAN   = 'LTHAN' # <
TOK_GTHAN   = 'GTHAN' # >
TOK_ARRO    = 'ARRO'  # @
TOK_EXCL    = 'EXCL'  # !


REScannerASN1 = re.Scanner([
    #
    (r'(--).*?([%s]|(--)|$)' % _NL,     lambda s, t: (TOK_CMT,   t)),
    (r'(/\*).*?(\*/)',                  lambda s, t: (TOK_CMT,   t)),
    (r'".*?(?<!")"(?!")',               lambda s, t: (TOK_CSTR,  t)),
    #
    (r'::=',                            lambda s, t: TOK_ASSI),
    (r':',                              lambda s, t: TOK_COL),
    (r';',                              lambda s, t: TOK_SCOL),
    (r'=',                              lambda s, t: TOK_EQU),
    (r',',                              lambda s, t: TOK_COM),
    (r'\(',                             lambda s, t: TOK_PARO),
    (r'\)',                             lambda s, t: TOK_PARC),
    (r'\[{2}',                          lambda s, t: TOK_DBRAO),
    (r'\]{2}',                          lambda s, t: TOK_DBRAC),
    (r'\[',                             lambda s, t: TOK_BRAO),
    (r'\]',                             lambda s, t: TOK_BRAC),
    (r'\{',                             lambda s, t: TOK_CBRAO),
    (r'\}',                             lambda s, t: TOK_CBRAC),
    (r'\.\.\.',                         lambda s, t: TOK_TDOT),
    (r'\.\.',                           lambda s, t: TOK_DDOT),
    (r'\.',                             lambda s, t: TOK_DOT),
    (r'\||(?:UNION%s)' % _EXC,          lambda s, t: TOK_UNIO),
    (r'\^|(?:INTERSECTION%s)' % _EXC,   lambda s, t: TOK_INTER),
    (r'<',                              lambda s, t: TOK_LTHAN),
    (r'>',                              lambda s, t: TOK_GTHAN),
    (r'@',                              lambda s, t: TOK_ARRO),
    (r'\!',                             lambda s, t: TOK_EXCL),
    #
    (r'ABSENT%s' % _EXC,                lambda s, t: TOK_ABS),
    (r'ALL%s' % _EXC,                   lambda s, t: TOK_ALL),
    (r'APPLICATION%s' % _EXC,           lambda s, t: TOK_TAPP),
    (r'AUTOMATIC%s' % _EXC,             lambda s, t: TOK_AUTO),
    (r'BEGIN%s' % _EXC,                 lambda s, t: TOK_BEG),
    (r'BY%s' % _EXC,                    lambda s, t: TOK_BY),
    (r'COMPONENT%s' % _EXC,             lambda s, t: TOK_COMP),
    (r'COMPONENTS%s' % _EXC,            lambda s, t: TOK_COMPS),
    (r'CONSTRAINED%s' % _EXC,           lambda s, t: TOK_CONST),
    (r'CONTAINING%s' % _EXC,            lambda s, t: TOK_CONT),
    (r'DEFAULT%s' % _EXC,               lambda s, t: TOK_DEF),
    (r'DEFINITIONS%s' % _EXC,           lambda s, t: TOK_DEFI),
    (r'ENCODED%s' % _EXC,               lambda s, t: TOK_ENC),
    (r'END%s' % _EXC,                   lambda s, t: TOK_END),
    (r'EXCEPT%s' % _EXC,                lambda s, t: TOK_EXCE),
    (r'EXPLICIT%s' % _EXC,              lambda s, t: TOK_TEXP),
    (r'EXPORTS%s' % _EXC,               lambda s, t: TOK_EXP),
    (r'EXTENSIBILITY%sIMPLIED%s' % (REScannerSNL, _EXC),    lambda s, t: TOK_EXTI),
    (r'FALSE%s' % _EXC,                 lambda s, t: TOK_FALS),
    (r'FROM%s' % _EXC,                  lambda s, t: TOK_FROM),
    (r'IMPLICIT%s' % _EXC,              lambda s, t: TOK_TIMP),
    (r'IMPORTS%s' % _EXC,               lambda s, t: TOK_IMP),
    (r'INCLUDES%s' % _EXC,              lambda s, t: TOK_INCL),
    (r'MAX%s' % _EXC,                   lambda s, t: TOK_MAX),
    (r'MIN%s' % _EXC,                   lambda s, t: TOK_MIN),
    (r'MINUS-INFINITY%s' % _EXC,        lambda s, t: TOK_MINF),
    (r'NOT-A-NUMBER%s' % _EXC,          lambda s, t: TOK_NAN),
    (r'NULL%s' % _EXC,                  lambda s, t: TOK_NULL),
    (r'OF%s' % _EXC,                    lambda s, t: TOK_OF),
    (r'OPTIONAL%s' % _EXC,              lambda s, t: TOK_OPT),
    (r'PATTERN%s' % _EXC,               lambda s, t: TOK_PAT),
    (r'PLUS-INFINITY%s' % _EXC,         lambda s, t: TOK_PINF),
    (r'PRESENT%s' % _EXC,               lambda s, t: TOK_PRES),
    (r'PRIVATE%s' % _EXC,               lambda s, t: TOK_TPRI),
    (r'SIZE%s' % _EXC,                  lambda s, t: TOK_SIZE),
    (r'TAGS%s' % _EXC,                  lambda s, t: TOK_TAGS),
    (r'TRUE%s' % _EXC,                  lambda s, t: TOK_TRUE),
    (r'UNIQUE%s' % _EXC,                lambda s, t: TOK_UNIQ),
    (r'UNIVERSAL%s' % _EXC,             lambda s, t: TOK_TUNI),
    (r'WITH%sSYNTAX%s' % (REScannerSNL, _EXC),              lambda s, t: TOK_WSYN),
    #
    (r'%s' % REScannerReal,             lambda s, t: (TOK_INT,   t)),
    (r'%s' % REScannerInt,              lambda s, t: (TOK_REAL,  t)),
    (r'%s' % REScannerBStr,             lambda s, t: (TOK_BSTR,  t)),
    (r'%s' % REScannerHStr,             lambda s, t: (TOK_HSTR,  t)),
    #
    (r'(%s)%s' % (REScannerNTypes, _EXC),                   lambda s, t: (TOK_NTYPE, t)),
    (r'&[a-zA-Z](?:\-{0,1}[a-zA-Z0-9]{1,}){0,}%s' % _EXC,   lambda s, t: (TOK_CLAID, t)),
    (r'[A-Z](?:\-{0,1}[a-zA-Z0-9]{1,}){0,}%s' % _EXC,       lambda s, t: (TOK_HID,   t)),
    (r'[A-Z](?:\-{0,1}[a-zA-Z0-9]{1,}){0,}%s' % _EXC,       lambda s, t: (TOK_ID,    t)),
    (r'[a-z](?:\-{0,1}[a-zA-Z0-9]{1,}){0,}%s' % _EXC,       lambda s, t: (TOK_LID,   t)),
    #
    (r'%s' % REScannerSNL,              None)
    ],
    flags=re.DOTALL
    )


# ASN.1 module global structure:
# ModName ModOID DEFINITIONS ModOpts ::= BEGIN ModExports ModImports ModObjects END
#
# ASN.1 object structure:
# ObjName ObjParam ObjType ::= ObjVal
# ObjName ObjParam ObjType ::= ObjSet
# ObjName ObjParam ::= ObjType
# ObjName MACRO ::= BEGIN .. END
#
# ASN.1 object type structure:
# ObjTags ObjType ObjParamAct ObjConsts ObjCont
# CLASS ObjParamAct ObjCont WITH SYNTAX ObjSynt
