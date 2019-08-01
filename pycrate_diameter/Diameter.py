# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2019. Benoit Michau. P1Sec.
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
# * File Name : pycrate_diameter/Diameter.py
# * Created : 2019-07-30
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#__all__ = [
#    ]

#------------------------------------------------------------------------------#
# IETF RFC 6733
# https://tools.ietf.org/html/rfc6733
#------------------------------------------------------------------------------#

import datetime

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *
from pycrate_core.repr  import *

try:
    from .parse_iana_diameter_xml import *
    AppID_dict, Cmd_dict, AVPCodes_dict, AVPSpecVal_dict = build_dict_from_xml(FILENAME_aaa_parameters)
    AddrFamNums_dict = build_dict_from_xml(FILENAME_address_family_numbers)
except Exception as err:
    log('warning: unable to extract Diameter dict from xml files, %s' % err)
    AppID_dict, Cmd_dict, AVPCodes_dict, AVPSpecVal_dict = {}, {}, {}, {}
    AddrFamNums_dict = {}


#------------------------------------------------------------------------------#
# 4.2.  Basic AVP Data Formats
#------------------------------------------------------------------------------#

# Basic AVP Data formats with direct pycrate correspondence:
#
# OctetString: Buf()
# Integer32: Int32()
# Integer64: Int64()
# Unsigned32: Uint32()
# Unsigned64: Uint64()

class OctetString(Buf):
    pass

class Integer32(Int32):
    pass

class Integer64(Int64):
    pass

class Unsigned32(Uint32):
    pass

class Unsigned64(Uint64):
    pass


# Float32 and Float64 require IEEE-754-1985 format definition

class _IEEE_754_1985(Envelope):
    # TODO: define set_val() and get_val() to handle floating / scientific numbers
    pass


class Float32(_IEEE_754_1985):
    _GEN = (
        Uint('S', bl=1, dic={0: '+', 1: '-'}),
        Uint('E', bl=8),
        Uint('F', bl=23)
        )


class Float64(_IEEE_754_1985):
    _GEN = (
        Uint('S', bl=1, dic={0: '+', 1: '-'}),
        Uint('E', bl=11),
        Uint('F', bl=52)
        )


#------------------------------------------------------------------------------#
# 4.3.  Derived AVP Data Formats
#------------------------------------------------------------------------------#

# Derived AVP Data formats with direct pycrate correspondence:
#
# UTF8String: UTF8String()
# DiameterIdentity: Buf(), ascii-encoded FQDN / Realm
# DiameterURI: UTF8String(), ascii or UTF8-encoded URI
# Enumerated: Int32(), with a dict provided
# IPFilterRule: Buf(), ascii-encoded filter rule

class DiameterIdentity(Buf):
    pass

class DiameterURI(UTF8String):
    pass

class Enumerated(Int32):
    pass

class IPFiterRule(Buf):
    pass


class Address(Envelope):
    # TODO: provides a better Value representation, at least for IPv4 and IPv6
    _GEN = (
        Uint16('AddressType', dic=AddrFamNums_dict),
        Buf('Value', rep=REPR_HEX)
        )


class Time(Buf):
    # TODO: provides a way to set time and represent it correctly
    # see Python ntplib source, e.g. https://github.com/remh/ntplib
    _bl  = 32
    _rep = REPR_HEX


#------------------------------------------------------------------------------#
# 4.1.  AVP Header
#------------------------------------------------------------------------------#

class AVPHdr(Envelope):
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint32('Code', dic=AVPCodes_dict),
        Uint('V', bl=1),
        Uint('M', bl=1),
        Uint('P', bl=1),
        Uint('reserved', bl=5),
        Uint24('Len'),
        Uint32('VendorID')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[6].set_transauto(lambda: False if self[1].get_val() else True)


class AVP(Envelope):
    _GEN = (
        AVPHdr(),
        Buf('AVPData', rep=REPR_HEX, hier=1),
        Buf('AVPPad', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0][5].set_valauto(lambda: 12 + self[1].get_len() if self[0][1].get_val() else \
                                        8 + self[1].get_len())
        self[1].set_blauto(lambda: (self[0][5].get_val() - 12) << 3 if self[0][1].get_val() else \
                                   (self[0][5].get_val() -  8) << 3)
        self[2].set_blauto(lambda: (-self[1].get_len()%4) << 3)


def GenerateAVP(Code, DataType, M=0, P=0, VendorID=None):
    """generate a specific Diameter AVP with the appropriate Code and Data type
    """
    val_hdr = {'Code': Code, 'M': M, 'P': P}
    if VendorID is not None:
        val_hdr['V'] = 1
        val_hdr['VendorID'] = VendorID
    #
    if isinstance(DataType._bl, integer_types) and DataType._bl % 32 == 0:
        # fixed length AVP, no padding required
        class AVP(Envelope):
            _GEN = (
                AVPHdr(val=val_hdr),
                DataType('AVPData', hier=1)
                )
            def __init__(self, *args, **kwargs):
                Envelope.__init__(self, *args, **kwargs)
                self[0][5].set_valauto(lambda: 12 + (self[1]._bl >> 3) if self[0][1].get_val() else \
                                                8 + (self[1]._bl >> 3))
    else:
        # variable length AVP, padding may be required
        class AVP(Envelope):
            _GEN = (
                AVPHdr(val=val_hdr),
                DataType('AVPData', hier=1),
                Buf('AVPPad', rep=REPR_HEX)
                )
            def __init__(self, *args, **kwargs):
                Envelope.__init__(self, *args, **kwargs)
                self[0][5].set_valauto(lambda: 12 + self[1].get_len() if self[0][1].get_val() else \
                                                8 + self[1].get_len())
                self[1].set_blauto(lambda: (self[0][5].get_val() - 12) << 3 if self[0][1].get_val() else \
                                           (self[0][5].get_val() -  8) << 3)
                self[2].set_blauto(lambda: (-self[1].get_len()%4) << 3)
    #
    return AVP


#------------------------------------------------------------------------------#
# 3.  Diameter Header
#------------------------------------------------------------------------------#

class DiameterHdr(Envelope):
    _GEN = (
        Uint8('Vers', val=1),
        Uint24('Len'),
        Uint('R', bl=1),
        Uint('P', bl=1),
        Uint('E', bl=1),
        Uint('T', bl=1),
        Uint('reserved', bl=4),
        Uint24('Cmd', dic=Cmd_dict),
        Uint32('AppID', dic=AppID_dict),
        Uint32('HHID', rep=REPR_HEX),
        Uint32('EEID', rep=REPR_HEX)
        )


class DiameterGeneric(Envelope):
    _GEN = (
        DiameterHdr(),
        Sequence('AVPs', GEN=AVP(), hier=1)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0][1].set_valauto(lambda: 20 + self[1].get_len())
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        #
        avps_len = self[0][1].get_val() - 20
        char_len = char.len_byte()
        if char_len > avps_len:
            char._len_bit -= 8*(char_len - avps_len)
            restore_char_len = True
            char_bl = char._len_bit
        else:
            restore_char_len = False
        #
        self[1]._from_char(char)
        #
        if restore_char_len:
            char._len_bit = char_bl

