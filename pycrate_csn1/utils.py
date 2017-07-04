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
# * File Name : pycrate_csn1/utils.py
# * Created : 2017-06-12
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import re

from pycrate_core.elt      import Element
from pycrate_core.utils    import *
from pycrate_core.utils    import TYPE_UINT as _TYPE_UINT
from pycrate_asn1c.utils   import scan_for_comments
from pycrate_asn1c.dictobj import ASN1Dict as CSN1Dict


#------------------------------------------------------------------------------#
# text processing
#------------------------------------------------------------------------------#

def clean_text(text=''):
    """
    processes text to: 
        remove ASN.1 comments
        replace tab with space
        remove duplicated spaces
    """
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
    # replace tab and \xa0 with space
    text = text.replace('\t', ' ').replace('\xa0', ' ')
    # remove duplicated CR
    text = re.sub('\n{2,}', '\n', text)
    # remove duplicated spaces
    text = re.sub(' {2,}', ' ', text)
    #
    return text

def pythonize_name(name=''):
    """
    pythonize CSN.1 object name
    """
    # remove any trailing special chars
    name = re.sub('[-/\.\s]{1,}$', '', name)
    # change space(s) and special character(s) to a single underscore
    name = re.sub('[-/\.\s]{1,}', '_', name)
    # do not let name starts with a numeric char
    if name and name[0] in '0123456789':
        name = '_' + name
    return name
    
#------------------------------------------------------------------------------#
# CSN.1 errors
#------------------------------------------------------------------------------#

# generic CSN.1 error
class CSN1Err(Exception):
    pass

class CSN1InvalidValueErr(CSN1Err):
    pass

#------------------------------------------------------------------------------#
# CSN.1 tokens
#------------------------------------------------------------------------------#

_RE_NAME  = '[a-zA-Z0-9_\-/ \.]{1,}'

SYNT_RE_NAME = re.compile(
    '<\s{0,}(%s)\s{0,}>\s{0,}' % _RE_NAME)
SYNT_RE_REPET = re.compile(
    '(?:\(\s{0,}(?:([0-9]{1,})|(\*))\s{0,}\))|(?:\*\s{0,}(?:([0-9]{1,})|(\*)))')
SYNT_RE_VALUE = re.compile(
    '([01\s]{1,})|([LH\s]{1,})|(null)')
SYNT_RE_LENREF = re.compile(
    '\(\s{0,}val\s{0,}\(\s{0,}(%s)\)\s{0,}\)\s{0,}\&' % _RE_NAME)

#------------------------------------------------------------------------------#
# value conversion
#------------------------------------------------------------------------------#

CSN1T_UINT = _TYPE_UINT
CSN1T_BSTR = 20

def bitstr_to_uint(bitstr):
    return int(bitstr, 2)

def uint_to_bitstr(uint, bl):
    bs = bin(uint)[2:]
    if len(bs) < bl:
        return (bl-len(bs)) * '0' + bs
    else:
        return bs

