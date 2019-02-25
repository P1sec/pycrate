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
# * File Name : pycrate_csn1/utils.py
# * Created : 2017-06-12
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

import re

from pycrate_core.elt      import Element
from pycrate_core.utils    import *
from pycrate_core.utils    import TYPE_UINT as _TYPE_UINT


#------------------------------------------------------------------------------#
# CSN.1 errors
#------------------------------------------------------------------------------#

def csnlog(msg):
    '''
    customizable logging function for the whole csn1 part
    '''
    log(msg)


# generic CSN.1 error
class CSN1Err(PycrateErr):
    pass

class CSN1InvalidValueErr(CSN1Err):
    pass

class CSN1NoCharErr(CSN1Err):
    pass


#------------------------------------------------------------------------------#
# text processing
#------------------------------------------------------------------------------#

def scan_for_comments(text=''):
    """
    returns a list of 2-tuple (start offset, end offset) for each CSN.1 comment
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
        #while text[cur:1+cur] == '-':
        #    cur += 1
        while True:
            # move 1 by 1 and find an end-of-comment or end-of-file
            if text[cur:1+cur] == '\n' or cur >= len(text):
                comment = False
                ret.append((start, cur))
                cur += 1
                break
            #elif text[cur:2+cur] == '--':
            #    comment = False
            #    cur += 2
            #    ret.append((start, cur))
            #    break
            else:
                cur += 1
        # find the next comment
        next = text[cur:].find('--')
    return ret


def clean_text(text=''):
    """
    processes text to: 
        remove CSN.1 comments
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
    return name.lower()

#------------------------------------------------------------------------------#
# CSN.1 tokens
#------------------------------------------------------------------------------#

_RE_NAME  = '[0-9a-zA-Z_ \-/\.]{1,}'
_RE_VAL   = 'val\s{0,}\(\s{0,}(%s)\s{0,}\)' % _RE_NAME

SYNT_RE_NAME  = re.compile('<\s{0,}(%s)\s{0,}>' % _RE_NAME)
SYNT_RE_VALUE = re.compile('([01\s]{1,})|([LH\s]{1,})|(null)')
SYNT_RE_NOSTR = re.compile('=\s{0,}<\s{0,}no\s{1,}string\s{0,}>')

# {iteration / length} arithmetic expression
TOK_UINT = 1
TOK_REF  = 2
TOK_ADD  = 3
TOK_SUB  = 4
TOK_MUL  = 5
TOK_OPEN = 6
TOK_CLOS = 7

def arithm_get_expr(m):
    return m.group()

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

