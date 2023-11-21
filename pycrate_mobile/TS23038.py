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
# * File Name : pycrate_mobile/TS23038.py
# * Created : 2017-10-23
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/
'''
__all__ = [
    'DCS_7B',
    'DCS_8B',
    'DCS_UCS',
    'SMS_DCS',
    'CBS_DCS',
    'encode_7b',
    'decode_7b',
    'encode_7b_cbs',
    'decode_7b_cbs'
    ]
'''
from binascii import hexlify

#------------------------------------------------------------------------------#
# 3GPP TS 23.038: Alphabets and language-specific information
# release 13 (d00)
#------------------------------------------------------------------------------#

from pycrate_core.utils  import pack_val, TYPE_UINT, PycrateErr, bytes_lshift
from pycrate_core.charpy import Charpy
from pycrate_core.elt    import Envelope
from pycrate_core.base   import Uint

_str_reserved = 'reserved'
DCS_7B  = 0
DCS_8B  = 1
DCS_UCS = 2

#------------------------------------------------------------------------------#
# SMS Data Coding Scheme
# TS 23.038, section 4
#------------------------------------------------------------------------------#

_SMSDCSGroup_dict = {
    0 : 'general data coding, uncompressed', # no class meaning
    1 : 'general data coding, uncompressed',
    2 : 'general data coding, compressed', # no class meaning
    3 : 'general data coding, compressed',
    4 : 'message for automatic deletion group, uncompressed', # no class meaning
    5 : 'message for automatic deletion group, uncompressed',
    6 : 'message for automatic deletion group, compressed', # no class meaning
    7 : 'message for automatic deletion group, compressed',
    8 : _str_reserved,
    9 : _str_reserved,
    10: _str_reserved,
    11: _str_reserved,
    12: 'message waiting indication group: discard message',
    13: 'message waiting indication group: store message',
    14: 'message waiting indication group: store message',
    15: 'data coding / message class'
    }

_SMSDCSCharset_dict = {
    0 : 'GSM 7 bit default alphabet',
    1 : '8 bit data',
    2 : 'UCS2 (16 bit)',
    3 : _str_reserved
    }

_SMSDCSClass_dict = {
    0 : 'Class 0',
    1 : 'Class 1 - default meaning: ME-specific',
    2 : 'Class 2 - (U)SIM specific message',
    3 : 'Class 3 - default meaning: TE specific',
    }

_SMSDCSIndSense_dict = {
    0 : 'GSM 7 bit default alphabet, set indication inactive',
    2 : 'GSM 7 bit default alphabet, set indication active'
    }

_SMSDCSIndSenseUCS_dict = {
    0 : 'UCS2 (16 bit), set indication inactive',
    2 : 'UCS2 (16 bit), set indication active'
    }

_SMSDCSIndType_dict = {
    0 : 'Voicemail Message Waiting',
    1 : 'Fax Message Waiting',
    2 : 'Electronic Mail Message Waiting',
    3 : 'Other Message Waiting',
    }

class SMS_DCS(Envelope):
    _GEN = (
        Uint('Group', bl=4, dic=_SMSDCSGroup_dict),
        Uint('Charset', bl=2),
        Uint('Class', bl=2)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_dicauto(self._set_cs_dic)
        self[2].set_dicauto(self._set_cla_dic)
    
    def _set_cs_dic(self):
        grp = self[0]()
        if grp < 8 or grp == 15:
            return _SMSDCSCharset_dict
        elif grp in (12, 13):
            return _SMSDCSIndSense_dict
        elif grp == 14:
            _SMSDCSIndSenseUCS_dict
        else:
            return {}
    
    def _set_cla_dic(self):
        grp = self[0]()
        if grp in (1, 3, 5, 7, 15):
            return _SMSDCSClass_dict
        elif grp in (12, 13, 14):
            return _SMSDCSIndType_dict 
        else:
            return {}


#------------------------------------------------------------------------------#
# CBS Data Coding Scheme
# TS 23.038, section 5
#------------------------------------------------------------------------------#

_CBSDCSGroup_dict = {
    0 : 'Language using the GSM 7 bit default alphabet',
    3 : 'Reserved for other languages using the GSM 7 bit default alphabet, '\
        'with unspecified handling at the MS',
    4 : 'general data coding, uncompressed', # no class meaning
    5 : 'general data coding, uncompressed',
    6 : 'general data coding, compressed', # no class meaning
    7 : 'general data coding, compressed',
    8 : _str_reserved,
    9 : 'Message with User Data Header (UDH) structure',
    13: 'I1 protocol message defined in 3GPP TS 24.294',
    14: 'Defined by the WAP Forum',
    15: 'data coding / message class'
    }

_CBSDCSCs0_dict = {
    0 : 'German',
    1 : 'English',
    2 : 'Italian',
    3 : 'French',
    4 : 'Spanish',
    5 : 'Dutch',
    6 : 'Swedish',
    7 : 'Danish',
    8 : 'Portuguese',
    9 : 'Finnish',
    10: 'Norwegian',
    11: 'Greek',
    12: 'Turkish',
    13: 'Hungarian',
    14: 'Polish',
    15: 'Language unspecified'
    }

_CBSDCSCs1_dict = {
    0 : 'GSM 7 bit default alphabet; message preceded by language indication',
    1 : 'UCS2; message preceded by language indication'
    }

_CBSDCSCs2_dict = {
    0 : 'Czech',
    1 : 'Hebrew',
    2 : 'Arabic',
    3 : 'Russian',
    4 : 'Icelandic'
    }

class CBS_DCS(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('Group', bl=4, dic=_CBSDCSGroup_dict),
        Uint('Charset', bl=4),
        Uint('Charset', bl=2),
        Uint('Class', bl=2)
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_transauto(self._set_cs4_trans)
        self[1].set_dicauto(self._set_cs4_dic)
        self[2].set_transauto(self._set_cs2_trans)
        self[2].set_dicauto(self._set_cs2_dic)
        self[3].set_transauto(self._set_cs2_trans)
        self[3].set_dicauto(self._set_cla_dic)
    
    def _set_cs4_trans(self):
        if self[0]() in (0, 1, 2, 3, 8, 10, 11, 12, 13, 14):
            return False
        else:
            return True
    
    def _set_cs4_dic(self):
        grp = self[0]()
        if grp == 0:
            return _CBSDCSCs0_dict
        elif grp == 1:
            return _CBSDCSCs1_dict
        elif grp == 2:
            return _CBSDCSCs2_dict
        else:
            return {}
        
    def _set_cs2_trans(self):
        if self[0]() in (4, 5, 6, 7, 9, 15):
            return False
        else:
            return True
    
    def _set_cs2_dic(self):
        grp = self[0]()
        if grp in (4, 5, 6, 7, 9, 15):
            return _SMSDCSCharset_dict
        else:
            return {}
    
    def _set_cla_dic(self):
        grp = self[0]()
        if grp in (5, 7, 9, 15):
            return _SMSDCSClass_dict
        else:
            return {}


#------------------------------------------------------------------------------#
# GSM 7 bit Default Alphabet
# TS 23.038, section 6.2.1
#------------------------------------------------------------------------------#

_GSM7bLUT = {
    0 : '@',
    1 : '£',
    2 : '$',
    3 : '¥',
    4 : 'è',
    5 : 'é',
    6 : 'ù',
    7 : 'ì',
    8 : 'ò',
    9 : 'Ç',
    10 : '\n',
    11 : 'Ø',
    12 : 'ø',
    13 : '\r',
    14 : 'Å',
    15 : 'å',
    16 : 'Δ',
    17 : '_',
    18 : 'Φ',
    19 : 'Γ',
    20 : 'Λ',
    21 : 'Ω',
    22 : 'Π',
    23 : 'Ψ',
    24 : 'Σ',
    25 : 'Θ',
    26 : 'Ξ',
    27 : '\x1b',
    28 : 'Æ',
    29 : 'æ',
    30 : 'ß',
    31 : 'É',
    32 : ' ',
    33 : '!',
    34 : '"',
    35 : '#',
    36 : '¤',
    37 : '%',
    38 : '&',
    39 : u"'",
    40 : '(',
    41 : ')',
    42 : '*',
    43 : '+',
    44 : ',',
    45 : '-',
    46 : '.',
    47 : '/',
    48 : '0',
    49 : '1',
    50 : '2',
    51 : '3',
    52 : '4',
    53 : '5',
    54 : '6',
    55 : '7',
    56 : '8',
    57 : '9',
    58 : ':',
    59 : ';',
    60 : '<',
    61 : '=',
    62 : '>',
    63 : '?',
    64 : '¡',
    65 : 'A',
    66 : 'B',
    67 : 'C',
    68 : 'D',
    69 : 'E',
    70 : 'F',
    71 : 'G',
    72 : 'H',
    73 : 'I',
    74 : 'J',
    75 : 'K',
    76 : 'L',
    77 : 'M',
    78 : 'N',
    79 : 'O',
    80 : 'P',
    81 : 'Q',
    82 : 'R',
    83 : 'S',
    84 : 'T',
    85 : 'U',
    86 : 'V',
    87 : 'W',
    88 : 'X',
    89 : 'Y',
    90 : 'Z',
    91 : 'Ä',
    92 : 'Ö',
    93 : 'Ñ',
    94 : 'Ü',
    95 : '§',
    96 : '¿',
    97 : 'a',
    98 : 'b',
    99 : 'c',
    100 : 'd',
    101 : 'e',
    102 : 'f',
    103 : 'g',
    104 : 'h',
    105 : 'i',
    106 : 'j',
    107 : 'k',
    108 : 'l',
    109 : 'm',
    110 : 'n',
    111 : 'o',
    112 : 'p',
    113 : 'q',
    114 : 'r',
    115 : 's',
    116 : 't',
    117 : 'u',
    118 : 'v',
    119 : 'w',
    120 : 'x',
    121 : 'y',
    122 : 'z',
    123 : 'ä',
    124 : 'ö',
    125 : 'ñ',
    126 : 'ü',
    127 : 'à'
    }

_GSM7bLUTInv = {
    '@' : 0,
    '£' : 1,
    '$' : 2,
    '¥' : 3,
    'è' : 4,
    'é' : 5,
    'ù' : 6,
    'ì' : 7,
    'ò' : 8,
    'Ç' : 9,
    '\n' : 10,
    'Ø' : 11,
    'ø' : 12,
    '\r' : 13,
    'Å' : 14,
    'å' : 15,
    'Δ' : 16,
    '_' : 17,
    'Φ' : 18,
    'Γ' : 19,
    'Λ' : 20,
    'Ω' : 21,
    'Π' : 22,
    'Ψ' : 23,
    'Σ' : 24,
    'Θ' : 25,
    'Ξ' : 26,
    '\x1b' : 27,
    'Æ' : 28,
    'æ' : 29,
    'ß' : 30,
    'É' : 31,
    ' ' : 32,
    '!' : 33,
    '"' : 34,
    '#' : 35,
    '¤' : 36,
    '%' : 37,
    '&' : 38,
    u"'" : 39,
    '(' : 40,
    ')' : 41,
    '*' : 42,
    '+' : 43,
    ',' : 44,
    '-' : 45,
    '.' : 46,
    '/' : 47,
    '0' : 48,
    '1' : 49,
    '2' : 50,
    '3' : 51,
    '4' : 52,
    '5' : 53,
    '6' : 54,
    '7' : 55,
    '8' : 56,
    '9' : 57,
    ':' : 58,
    ';' : 59,
    '<' : 60,
    '=' : 61,
    '>' : 62,
    '?' : 63,
    '¡' : 64,
    'A' : 65,
    'B' : 66,
    'C' : 67,
    'D' : 68,
    'E' : 69,
    'F' : 70,
    'G' : 71,
    'H' : 72,
    'I' : 73,
    'J' : 74,
    'K' : 75,
    'L' : 76,
    'M' : 77,
    'N' : 78,
    'O' : 79,
    'P' : 80,
    'Q' : 81,
    'R' : 82,
    'S' : 83,
    'T' : 84,
    'U' : 85,
    'V' : 86,
    'W' : 87,
    'X' : 88,
    'Y' : 89,
    'Z' : 90,
    'Ä' : 91,
    'Ö' : 92,
    'Ñ' : 93,
    'Ü' : 94,
    '§' : 95,
    '¿' : 96,
    'a' : 97,
    'b' : 98,
    'c' : 99,
    'd' : 100,
    'e' : 101,
    'f' : 102,
    'g' : 103,
    'h' : 104,
    'i' : 105,
    'j' : 106,
    'k' : 107,
    'l' : 108,
    'm' : 109,
    'n' : 110,
    'o' : 111,
    'p' : 112,
    'q' : 113,
    'r' : 114,
    's' : 115,
    't' : 116,
    'u' : 117,
    'v' : 118,
    'w' : 119,
    'x' : 120,
    'y' : 121,
    'z' : 122,
    'ä' : 123,
    'ö' : 124,
    'ñ' : 125,
    'ü' : 126,
    'à' : 127
    }

_GSM7bTab = '@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !"#¤%&\'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà'

_GSM7bExtLUT = {
    10 : '\x0c',
    13 : '\x11', # no real equivalent to CR2 in the ascii table
    20 : '^',
    27 : '\x0e', # no real equivalent to SS2 in the ascii table
    40 : '{',
    41 : '}',
    47 : '\\',
    60 : '[',
    61 : '~',
    62 : ']',
    64 : '|',
    101 : '€'
    }

_GSM7bExtLUTInv = {
    '\x0c' : 10,
    '\x11' : 13,
    '^' : 20,
    '\x0e' : 27,
    '{' : 40,
    '}' : 41,
    '\\' : 47,
    '[' : 60,
    '~' : 61,
    ']' : 62,
    '|' : 64,
    '€' : 101
    }

_GSM7bExtTab = '\x0c\x11^\x0e{}\\[~]|€'


def encode_7b(txt, off=0):
    """translates the unicode string `txt' to a GSM 7 bit characters buffer
    Enables the encoded buffer to start at a non-null bit offset `off' as it is the case
    with fill bits after certain SMS User-Data-Headers
    
    Args:
        txt (utf8 str): text string to encode
        off (uint): bit offset
     
    Returns:
        encoded buffer and septet count (bytes, uint)
    """
    arr, cnt = [], 0
    for c in reversed(txt):
        try:
            arr.append( (TYPE_UINT, _GSM7bLUTInv[c], 7) )
        except KeyError:
            try:
                arr.append( (TYPE_UINT, _GSM7bExtLUTInv[c], 7) )
            except KeyError:
                raise(PycrateErr('invalid GSM 7 bit char: %r' % c))
            else:
                # add the extension escape char
                arr.append( (TYPE_UINT, 27, 7) )
                cnt += 2
        else:
            cnt += 1
    # add fill bits at the front (for the UDH to align on septets)
    arr.append((TYPE_UINT, 0, off))
    # add fill bits at the end (to align on a byte boundary)
    padbl = (-off-cnt*7) % 8
    if padbl == 7:
        # pad with a \r, to avoid including a padding septet that would decode as @
        arr.insert(0, (TYPE_UINT, 13, 7))
    else:
        arr.insert(0, (TYPE_UINT, 0, padbl))
    return bytes(reversed(pack_val(*arr)[0])), cnt


def decode_7b(buf, off=0):
    """translates the GSM 7 bit characters buffer `buf' to an unicode string
    Enables the string to be decoded to start at a non-null offset `off' as it is
    the case with fill bits after certain SMS User-Data-Headers
    
    Args:
        buf (bytes): buffer to decode
        off (uint): bit offset
     
    Returns:
        decoded text string (utf8 str)
    """
    char = Charpy(bytes(reversed(buf)))
    #
    # get the size and number of characters
    buf_bl    = len(buf) << 3
    chars_bl  = buf_bl - off
    chars_num = chars_bl // 7
    # jump over the fill bits (from the UDH)
    char._cur = chars_bl - (7 * chars_num)
    #
    # get all chars
    arr = [char.get_uint(7) for i in range(chars_num)]
    chars = []
    for i, v in enumerate(arr):
        if v == 27:
            # escape char, replace last char with extended content
            try:
                chars[-1] = _GSM7bExtLUT[arr[i-1]]
            except KeyError:
                chars.append(' ')
        else:
            chars.append(_GSM7bLUT[v])
    #
    if chars and chars[0] in ('@', '\r'):
        # strip the last character corresponding to the last 7-bit padding (being 0x00 or 0x13)
        return ''.join(reversed(chars[1:]))
    else:
        return ''.join(reversed(chars))


def decode_7b_gmr(buf):
    pass


def encode_7b_cbs(txt):
    """translates the unicode string `txt' into a tuple of page(s) 
    containing GSM 7 bit characters, ready for broadcast
    
    a page is a 2-tuple: 82-bytes buffer, message length (<= 82)
    """
    pages, page, cnt = [], [], 0
    # check the number of 7 bit characters required for txt
    for c in txt:
        if c in _GSM7bLUTInv:
            c_cnt = 1
        elif c in _GSM7bExtLUTInv:
            c_cnt = 2
        else:
            raise(PycrateErr('invalid GSM 7 bit char: %r' % c))
        if cnt + c_cnt < 94:
            page.append(c)
            cnt += c_cnt
        else:
            # encode the current page to pages
            enc = encode_7b(''.join(page))[0]
            enc_len = len(enc)
            if enc_len < 82:
                # padding with CR
                enc += (82-enc_len) * b'\x0d'
            pages.append( (enc, enc_len) )
            # restart filling current page
            page, cnt = [c], c_cnt
    # pad and append last page
    if page:
        last = encode_7b(''.join(page))[0]
        last_len = len(last)
        last += (82-last_len) * b'\x0d'
        pages.append( (last, last_len) )
    # return the tuple of pages
    return tuple(pages)


def decode_7b_cbs(pages):
    """translates a tuple of `pages' containing GSM 7 bit characters to an 
    unicode string
    
    a page is a 2-tuple: 82-bytes buffer, message length (<= 82)
    """
    txt = []
    for page, page_len in pages:
        txt.append( decode_7b(page[:page_len]) )
    return ''.join(txt)

