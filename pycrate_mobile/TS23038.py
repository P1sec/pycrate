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

#------------------------------------------------------------------------------#
# 3GPP TS 23.038: Alphabets and language-specific information
# release 13 (d00)
#------------------------------------------------------------------------------#

from pycrate_core.utils  import python_version, pack_val, TYPE_UINT, PycrateErr
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
    0 : u'@',
    1 : u'£',
    2 : u'$',
    3 : u'¥',
    4 : u'è',
    5 : u'é',
    6 : u'ù',
    7 : u'ì',
    8 : u'ò',
    9 : u'Ç',
    10 : u'\n',
    11 : u'Ø',
    12 : u'ø',
    13 : u'\r',
    14 : u'Å',
    15 : u'å',
    16 : u'Δ',
    17 : u'_',
    18 : u'Φ',
    19 : u'Γ',
    20 : u'Λ',
    21 : u'Ω',
    22 : u'Π',
    23 : u'Ψ',
    24 : u'Σ',
    25 : u'Θ',
    26 : u'Ξ',
    27 : u'\x1b',
    28 : u'Æ',
    29 : u'æ',
    30 : u'ß',
    31 : u'É',
    32 : u' ',
    33 : u'!',
    34 : u'"',
    35 : u'#',
    36 : u'¤',
    37 : u'%',
    38 : u'&',
    39 : u"'",
    40 : u'(',
    41 : u')',
    42 : u'*',
    43 : u'+',
    44 : u',',
    45 : u'-',
    46 : u'.',
    47 : u'/',
    48 : u'0',
    49 : u'1',
    50 : u'2',
    51 : u'3',
    52 : u'4',
    53 : u'5',
    54 : u'6',
    55 : u'7',
    56 : u'8',
    57 : u'9',
    58 : u':',
    59 : u';',
    60 : u'<',
    61 : u'=',
    62 : u'>',
    63 : u'?',
    64 : u'¡',
    65 : u'A',
    66 : u'B',
    67 : u'C',
    68 : u'D',
    69 : u'E',
    70 : u'F',
    71 : u'G',
    72 : u'H',
    73 : u'I',
    74 : u'J',
    75 : u'K',
    76 : u'L',
    77 : u'M',
    78 : u'N',
    79 : u'O',
    80 : u'P',
    81 : u'Q',
    82 : u'R',
    83 : u'S',
    84 : u'T',
    85 : u'U',
    86 : u'V',
    87 : u'W',
    88 : u'X',
    89 : u'Y',
    90 : u'Z',
    91 : u'Ä',
    92 : u'Ö',
    93 : u'Ñ',
    94 : u'Ü',
    95 : u'§',
    96 : u'¿',
    97 : u'a',
    98 : u'b',
    99 : u'c',
    100 : u'd',
    101 : u'e',
    102 : u'f',
    103 : u'g',
    104 : u'h',
    105 : u'i',
    106 : u'j',
    107 : u'k',
    108 : u'l',
    109 : u'm',
    110 : u'n',
    111 : u'o',
    112 : u'p',
    113 : u'q',
    114 : u'r',
    115 : u's',
    116 : u't',
    117 : u'u',
    118 : u'v',
    119 : u'w',
    120 : u'x',
    121 : u'y',
    122 : u'z',
    123 : u'ä',
    124 : u'ö',
    125 : u'ñ',
    126 : u'ü',
    127 : u'à'
    }

_GSM7bLUTInv = {
    u'@' : 0,
    u'£' : 1,
    u'$' : 2,
    u'¥' : 3,
    u'è' : 4,
    u'é' : 5,
    u'ù' : 6,
    u'ì' : 7,
    u'ò' : 8,
    u'Ç' : 9,
    u'\n' : 10,
    u'Ø' : 11,
    u'ø' : 12,
    u'\r' : 13,
    u'Å' : 14,
    u'å' : 15,
    u'Δ' : 16,
    u'_' : 17,
    u'Φ' : 18,
    u'Γ' : 19,
    u'Λ' : 20,
    u'Ω' : 21,
    u'Π' : 22,
    u'Ψ' : 23,
    u'Σ' : 24,
    u'Θ' : 25,
    u'Ξ' : 26,
    u'\x1b' : 27,
    u'Æ' : 28,
    u'æ' : 29,
    u'ß' : 30,
    u'É' : 31,
    u' ' : 32,
    u'!' : 33,
    u'"' : 34,
    u'#' : 35,
    u'¤' : 36,
    u'%' : 37,
    u'&' : 38,
    u"'" : 39,
    u'(' : 40,
    u')' : 41,
    u'*' : 42,
    u'+' : 43,
    u',' : 44,
    u'-' : 45,
    u'.' : 46,
    u'/' : 47,
    u'0' : 48,
    u'1' : 49,
    u'2' : 50,
    u'3' : 51,
    u'4' : 52,
    u'5' : 53,
    u'6' : 54,
    u'7' : 55,
    u'8' : 56,
    u'9' : 57,
    u':' : 58,
    u';' : 59,
    u'<' : 60,
    u'=' : 61,
    u'>' : 62,
    u'?' : 63,
    u'¡' : 64,
    u'A' : 65,
    u'B' : 66,
    u'C' : 67,
    u'D' : 68,
    u'E' : 69,
    u'F' : 70,
    u'G' : 71,
    u'H' : 72,
    u'I' : 73,
    u'J' : 74,
    u'K' : 75,
    u'L' : 76,
    u'M' : 77,
    u'N' : 78,
    u'O' : 79,
    u'P' : 80,
    u'Q' : 81,
    u'R' : 82,
    u'S' : 83,
    u'T' : 84,
    u'U' : 85,
    u'V' : 86,
    u'W' : 87,
    u'X' : 88,
    u'Y' : 89,
    u'Z' : 90,
    u'Ä' : 91,
    u'Ö' : 92,
    u'Ñ' : 93,
    u'Ü' : 94,
    u'§' : 95,
    u'¿' : 96,
    u'a' : 97,
    u'b' : 98,
    u'c' : 99,
    u'd' : 100,
    u'e' : 101,
    u'f' : 102,
    u'g' : 103,
    u'h' : 104,
    u'i' : 105,
    u'j' : 106,
    u'k' : 107,
    u'l' : 108,
    u'm' : 109,
    u'n' : 110,
    u'o' : 111,
    u'p' : 112,
    u'q' : 113,
    u'r' : 114,
    u's' : 115,
    u't' : 116,
    u'u' : 117,
    u'v' : 118,
    u'w' : 119,
    u'x' : 120,
    u'y' : 121,
    u'z' : 122,
    u'ä' : 123,
    u'ö' : 124,
    u'ñ' : 125,
    u'ü' : 126,
    u'à' : 127
    }

_GSM7bExtLUT = {
    10 : u'\x0c',
    13 : u'\x11', # no real equivalent to CR2 in the ascii table
    20 : u'^',
    27 : u'\x0e', # no real equivalent to SS2 in the ascii table
    40 : u'{',
    41 : u'}',
    47 : u'\\',
    60 : u'[',
    61 : u'~',
    62 : u']',
    64 : u'|',
    101 : u'€'
    }

_GSM7bExtLUTInv = {
    u'\x0c' : 10,
    u'\x11' : 13,
    u'^' : 20,
    u'\x0e' : 27,
    u'{' : 40,
    u'}' : 41,
    u'\\' : 47,
    u'[' : 60,
    u'~' : 61,
    u']' : 62,
    u'|' : 64,
    u'€' : 101
    }


def encode_7b(txt, off=0):
    """translates the unicode string `txt' to a GSM 7 bit characters buffer
    
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
                # add an escape char
                arr.append( (TYPE_UINT, 27, 7) )
                cnt += 2
        else:
            cnt += 1
    # check the length in bits and add padding bits
    pad = ((8-(7*len(arr)+off)%8)%8)
    arr.insert(0, (TYPE_UINT, 0, pad))
    if python_version < 3:
        return ''.join(reversed(pack_val(*arr)[0])), cnt
    else:
        return bytes(reversed(pack_val(*arr)[0])), cnt


def decode_7b(buf, off=0):
    """translates the GSM 7 bit characters buffer `buf' to an unicode string
    
    Args:
        buf (bytes): buffer to decode
        off (uint): bit offset
     
    Returns:
        decoded text string (utf8 str)
    """
    if python_version < 3:
        char = Charpy(''.join(reversed(buf)))
    else:
        char = Charpy(bytes(reversed(buf)))
    # jump over the padding bits
    # WNG: in case of 7 bits padding, we will have an @ at the end 
    chars_num = (8*len(buf)-off) // 7
    char._cur = (8*len(buf)-off)-(7*chars_num)
    # get all chars
    arr = [char.get_uint(7) for i in range(chars_num)]
    chars = []
    #
    for i, v in enumerate(arr):
        if v == 27:
            # escape char, replace last char with extended content
            try:
                chars[-1] = _GSM7bExtLUT[arr[i-1]]
            except:
                chars.append(u' ')
        else:
            chars.append(_GSM7bLUT[v])
    return u''.join(reversed(chars))


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
    return u''.join(txt)

