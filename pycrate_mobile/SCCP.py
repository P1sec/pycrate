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
# * File Name : pycrate_mobile/SCCP.py
# * Created : 2017-11-27
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

from binascii import unhexlify

from pycrate_core.utils  import *
from pycrate_core.repr   import *
from pycrate_core.elt    import *
from pycrate_core.base   import *
from pycrate_core.charpy import *

from .TS24008_IE import BufBCD


#------------------------------------------------------------------------------#
# ITU-T Q.713: Signalling connection control part formats and codes
# SCCP
#------------------------------------------------------------------------------#

#------------------------------------------------------------------------------#
# SCCP general part
# ITU-T Q.713, section 2
#------------------------------------------------------------------------------#

_SCCPType_dict = {
    1 : 'CR',
    2 : 'CC',
    3 : 'CREF',
    4 : 'RLSD',
    5 : 'RLC',
    6 : 'DT1',
    7 : 'DT2',
    8 : 'AK',
    9 : 'UDT',
    10 : 'UDTS',
    11 : 'ED',
    12 : 'EA',
    13 : 'RSR',
    14 : 'RSC',
    15 : 'ERR',
    16 : 'IT',
    17 : 'XUDT',
    18 : 'XUDTS',
    19 : 'LUDT',
    20 : 'LUDTS'
    }


#------------------------------------------------------------------------------#
# SCCP parameters
# ITU-T Q.713, section 3
#------------------------------------------------------------------------------#

_SCCPParam_dict = {
    0 : 'End of optional parameters',
    1 : 'Destination local reference',
    2 : 'Source local reference',
    3 : 'Called Party address',
    4 : 'Calling party address',
    5 : 'Protocol class',
    6 : 'Segmenting/reassembling',
    7 : 'Receive sequence number',
    8 : 'Sequencint/segmenting',
    9 : 'Credit',
    10: 'Release cause',
    11: 'Return cause',
    12: 'Reset cause',
    13: 'Error cause',
    14: 'Refusal cause',
    15: 'Data',
    16: 'Segmentation',
    17: 'Hop counter',
    18: 'Importance',
    19: 'Long data'
    }

#------------------------------------------------------------------------------#
# End of optional parameters
# ITU-T Q.713, section 3.1
#------------------------------------------------------------------------------#

class EOO(Uint8):
    _val = 0
    _dic = _SCCPParam_dict


#------------------------------------------------------------------------------#
# Destination local reference
# ITU-T Q.713, section 3.2
#------------------------------------------------------------------------------#

class DstLocalRef(Uint24):
    pass


#------------------------------------------------------------------------------#
# Source local reference
# ITU-T Q.713, section 3.3
#------------------------------------------------------------------------------#

class SrcLocalRef(Uint24):
    pass


#------------------------------------------------------------------------------#
# Called Party Address / Calling Party Address
# ITU-T Q.713, section 3.4 / 3.5
#------------------------------------------------------------------------------#

class SCCPBufBCD(BufBCD):
    _chars  = ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '_', '11', '12', '_', 'ST')
    _filler = 0x0


# GTInd 0001
# section 3.4.2.3.1

_GTNAI_dict = {
0 : 'unknown',
1 : 'subscriber number',
2 : 'reserved for national use',
3 : 'national significant number',
4 : 'international number'
}
_str_reserved_natuse = 'reserved for national use'
for i in range(0b1110000, 0b1111110):
    _GTNAI_dict[i] = _str_reserved_natuse


class _GlobalTitle0001(Envelope):
    _GEN = (
        Uint('OE', bl=1, dic={0:'even number of address signals', 1:'odd number of address signals'}),
        Uint('NAI', val=1, bl=7, dic=_GTNAI_dict),
        SCCPBufBCD('Addr', val=b'')
        )
    
    def get_addr(self):
        """return BCD-encoded Addr, properly decoded according to OE
        """
        if self[0].get_val():
            return self[2].decode()[:-1]
        else:
            return self[2].decode()
    
    def set_addr(self, addr):
        """set the BCD-encoded Addr and OE
        """
        if len(addr) % 2:
            self[0].set_val(1)
        self[2].encode(addr)
    
    set_attr_bcd = set_addr


# GTInd 0010
# section 3.4.2.3.2

class _GlobalTitle0010(Envelope):
    _GEN = (
        Uint8('TranslationType'),
        Buf('Addr', val=b'', rep=REPR_HEX)
        )
    
    def get_addr(self):
        """return the hex-encoded Addr
        """
        return self[1].hex()
    
    def set_addr(self, addr):
        """set the hex-encoded Addr
        """
        self[1].set_val(unhexlify(addr))


# GTInd 0011
# section 3.4.2.3.3

_NumPlan_dict = {
    0 : 'unknown',
    1 : 'ISDN/telephony numbering plan (ITU-T E.163 and E.164)',
    2 : 'generic numbering plan',
    3 : 'data numbering plan (ITU-T X.121)',
    4 : 'telex numbering plan (ITU-T F.69)',
    5 : 'maritime mobile numbering plan (ITU-T E.210, E.211)',
    6 : 'land mobile numbering plan (ITU-T E.212)',
    7 : 'ISDN/mobile numbering plan (ITU-T E.214)',
    14 : 'private network or network-specific numbering plan'
    }

_EncScheme_dict = {
    0 : 'unknown',
    1 : 'BCD, odd number of digits',
    2 : 'BCD, even number of digits',
    3 : 'national specific'
    }

class _GlobalTitle0011(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint8('TranslationType'),
        Uint('NumberingPlan', val=1, bl=4, dic=_NumPlan_dict),
        Uint('EncodingScheme', val=1, bl=4, dic=_EncScheme_dict),
        Alt('Addr', GEN={
            1 : SCCPBufBCD('BCD', val=b''),
            2 : SCCPBufBCD('BCD', val=b'')},
            DEFAULT=Buf('Raw', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[2].get_val())
        )

    def get_addr(self):
        """return the BCD- or hex-encoded Addr, properly decoded according to EncodingScheme
        """
        enc = self[2].get_val()
        if enc == 1:
            return self[3].get_alt().decode()[:-1]
        elif enc == 2:
            return self[3].get_alt().decode()
        else:
            return self[3].get_alt().hex()
    
    def set_addr_bcd(self, addr):
        """set the BCD-encoded Addr and EncodingScheme
        """
        if len(addr) % 2:
            self[2].set_val(1)
        else:
            self[2].set_val(2)
        self[3].get_alt().encode(addr)


# GTInd 0100
# section 3.4.2.3.4

_GTIntTransType_dict = {
    255: 'reserved for expansion'
    }
_str_int_serv = 'international services'
_str_nat_serv = 'national network specific'
for i in range(0b1, 0b111111):
    _GTIntTransType_dict[i] = _str_int_serv
for i in range(0b10000000, 0b11111110):
    _GTIntTransType_dict[i] = _str_nat_serv


class _GlobalTitle0100(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint8('TranslationType', val=1, dic=_GTIntTransType_dict),
        Uint('NumberingPlan', val=1, bl=4, dic=_NumPlan_dict),
        Uint('EncodingScheme', val=1, bl=4, dic=_EncScheme_dict),
        Uint('spare', bl=1),
        Uint('NAI', val=1, bl=7, dic=_GTNAI_dict),
        Alt('Addr', GEN={
            1 : SCCPBufBCD('BCD', val=b''),
            2 : SCCPBufBCD('BCD', val=b'')},
            DEFAULT=Buf('Raw', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[2].get_val())
        )

    def get_addr(self):
        """return the BCD- or hex-encoded Addr, properly decoded according to EncodingScheme
        """
        enc = self[2].get_val()
        if enc == 1:
            return self[5].get_alt().decode()[:-1]
        elif enc == 2:
            return self[5].get_alt().decode()
        else:
            return self[5].get_alt().hex()
    
    def set_addr_bcd(self, addr):
        """set the BCD-encoded Addr and EncodingScheme
        """
        if len(addr) % 2:
            self[2].set_val(1)
        else:
            self[2].set_val(2)
        self[5].get_alt().encode(addr)


# SCCP called / calling party address

_RouteInd_dict = {
    0 : 'route on GT',
    1 : 'route on SSN'
    }

_GTInd_dict = {
    0 : 'no global title included',
    1 : 'global title includes nature of address indicator only',
    2 : 'global title includes translation type only',
    3 : 'global title includes translation type, numbering plan and encoding scheme',
    4 : 'global title includes translation type, numbering plan, '\
        'encoding scheme and nature of address indicator',
    }

_SSN_dict = {
    0 : 'SSN not known/not used',
    1 : 'SCCP management',
    2 : 'reserved for ITU-T allocation',
    3 : 'ISDN user part',
    4 : 'operation, maintenance and administration part (OMAP)',
    5 : 'mobile application part (MAP)',
    6 : 'home location register (HLR)',
    7 : 'visitor location register (VLR)',
    8 : 'mobile switching centre (MSC)',
    9 : 'equipment identifier register (EIR)',
    10 : 'authentication centre (AUC)',
    11 : 'ISDN supplementary services',
    12 : 'reserved for international use',
    13 : 'broadband ISDN edge-to-edge applications',
    14 : 'TC test responder',
    # from 3GPP TS 29.002 and 23.003
    142 : '3GPP RANAP',
    143 : '3GPP RNSAP',
    145 : '3GPP GMLC (MAP)',
    146 : '3GPP CAP',
    147 : '3GPP gsmSCF (MAP) or IM-SSF (MAP) or Presence Network Agent',
    148 : '3GPP SIWF (MAP)',
    149 : '3GPP SGSN (MAP)',
    150 : '3GPP GGSN (MAP)',
    248 : '3GPP CSS (MAP)',
    249 : '3GPP PCAP',
    250 : '3GPP BSC (BSSAP-LE)',
    251 : '3GPP MSC (BSSAP-LE)',
    252 : '3GPP SMLC (BSSAP-LE)',
    253 : '3GPP BSS O&M (A interface)',
    254 : '3GPP BSSAP (A interface)'
    }


class _SCCPAddr(Envelope):
    
    # this is to bypass the GT decoding process, and get a simple Buf() instead
    GT_DONT_DECODE = False
    
    ENV_SEL_TRANS = False
    _GEN = (
        Envelope('AddrInd', GEN=(
            Uint('res', bl=1),
            Uint('RoutingInd', val=0, bl=1, dic=_RouteInd_dict),
            Uint('GTInd', val=3, bl=4, dic=_GTInd_dict),
            Uint('SSNInd', val=0, bl=1),
            Uint('PCInd', val=0, bl=1)
            )),
        Uint16LE('PC'), # presence depends on PCInd
        Uint8('SSN', val=0, dic=_SSN_dict), # presence depends on SSNInd
        Alt('GT', GEN={
            1 : _GlobalTitle0001('GT_1'),
            2 : _GlobalTitle0010('GT_2'),
            3 : _GlobalTitle0011('GT_3'),
            4 : _GlobalTitle0100('GT_4')},
            DEFAULT=Buf('GT_unk', val=b'', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0][2].get_val())
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_transauto(lambda: False if self[0][4].get_val() != 0 else True)
        self[2].set_transauto(lambda: False if self[0][3].get_val() != 0 else True)
        self[3].set_transauto(lambda: False if self[0][2].get_val() != 0 else True)
    
    def _from_char(self, char):
        if not self.GT_DONT_DECODE:
            Envelope._from_char(self, char)
        else:
            self[0]._from_char(char)
            self[1]._from_char(char)
            self[2]._from_char(char)
            del self[3]
            gt = Buf('GT', rep=REPR_HEX)
            gt._from_char(char)
            self.append( gt )


class SCCPPartyAddr(Envelope):
    _GEN = (
        Uint8('Len'),
        _SCCPAddr('Value')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)
    
    def get_gt(self):
        return self[1][3].get_alt()


class CallingPartyAddr(SCCPPartyAddr):
    pass


class CalledPartyAddr(SCCPPartyAddr):
    pass


#------------------------------------------------------------------------------#
# Protocol Class
# ITU-T Q.713, section 3.6
#------------------------------------------------------------------------------#

_ProtClass_dict = {
    0 : 'Class 0 (connection-less)',
    1 : 'Class 1 (connection-less)',
    2 : 'Class 2 (connection-oriented)',
    3 : 'Class 3 (connection-oriented)'
    }

_ProtCon_dict = {i: 'spare' for i in range(16)}
_ProtConLess_dict = {i: 'spare' for i in range(16)}
_ProtConLess_dict[0] = 'no special options'
_ProtConLess_dict[8] = 'return message on error'


class ProtocolClass(Envelope):
    _GEN = (
        Uint('Handling', bl=4),
        Uint('Class', bl=4, dic=_ProtClass_dict)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_dicauto(lambda: _ProtConLess_dict if self[1].get_val() < 2 else _ProtCon_dict)


#------------------------------------------------------------------------------#
# Segmenting/reassembling
# ITU-T Q.713, section 3.7
#------------------------------------------------------------------------------#

class SegmentReassemb(Envelope):
    _GEN = (
        Uint('spare', bl=7),
        Uint('M', val=0, bl=1, dic={0:'no more data', 1:'more data'})
        )


#------------------------------------------------------------------------------#
# Receive sequence number
# ITU-T Q.713, section 3.8
#------------------------------------------------------------------------------#

class RecvSeqn(Envelope):
    _GEN = (
        Uint('PR', val=0, bl=7),
        Uint('spare', bl=1)
        )


#------------------------------------------------------------------------------#
# Sequencing/segmenting
# ITU-T Q.713, section 3.9
#------------------------------------------------------------------------------#

class SeqSegment(Envelope):
    _GEN = (
        Uint('PS', val=0, bl=7),
        Uint('spare', bl=1),
        Uint('PR', val=0, bl=7),
        Uint('M', val=0, bl=1, dic={0:'no more data', 1:'more data'})
        )


#------------------------------------------------------------------------------#
# Credit
# ITU-T Q.713, section 3.10
#------------------------------------------------------------------------------#

class Credit(Uint8):
    pass


#------------------------------------------------------------------------------#
# Release Cause
# ITU-T Q.713, section 3.11
#------------------------------------------------------------------------------#

_RelCause_dict = {
    0 : 'end user originated',
    1 : 'end user congestion',
    2 : 'end user failure',
    3 : 'SCCP user originated',
    4 : 'remote procedure error',
    5 : 'inconsistent connection data',
    6 : 'access failure',
    7 : 'access congestion',
    8 : 'subsystem failure',
    9 : 'subsystem congestion',
    10 : 'MTP failure',
    11 : 'network congestion',
    12 : 'expiration of reset timer',
    13 : 'expiration of receive inactivity timer',
    14 : 'reserved',
    15 : 'unqualified',
    16 : 'SCCP failure'
    }

class RelCause(Uint8):
    _dic = _RelCause_dict


#------------------------------------------------------------------------------#
# Return Cause
# ITU-T Q.713, section 3.12
#------------------------------------------------------------------------------#

_RetCause_dict = {
    0 : 'no translation for an address of such nature',
    1 : 'no translation for this specific address',
    2 : 'subsystem congestion',
    3 : 'subsystem failure',
    4 : 'unequipped user',
    5 : 'MTP failure',
    6 : 'network congestion',
    7 : 'unqualified',
    8 : 'error in message transport (Note)',
    9 : 'error in local processing (Note)',
    10 : 'destination cannot perform reassembly (Note)',
    11 : 'SCCP failure',
    12 : 'hop counter violation',
    13 : 'segmentation not supported',
    14 : 'segmentation failure'
    }

class RetCause(Uint8):
    _dic = _RetCause_dict


#------------------------------------------------------------------------------#
# Reset Cause
# ITU-T Q.713, section 3.13
#------------------------------------------------------------------------------#

_ResCause_dict = {
    0 : 'end user originated',
    1 : 'SCCP user originated',
    2 : 'message out of order – incorrect P(S)',
    3 : 'message out of order – incorrect P(R)',
    4 : 'remote procedure error – message out of window',
    5 : 'remote procedure error – incorrect P(S) after (re)initialization',
    6 : 'remote procedure error – general',
    7 : 'remote end user operational',
    8 : 'network operational',
    9 : 'access operational',
    10 : 'network congestion',
    11 : 'reserved',
    12 : 'unqualified'
    }

class ResCause(Uint8):
    _dic = _ResCause_dict


#------------------------------------------------------------------------------#
# Error Cause
# ITU-T Q.713, section 3.14
#------------------------------------------------------------------------------#

_ErrCause_dict = {
    0 : 'local reference number (LRN) mismatch – unassigned destination LRN',
    1 : 'local reference number (LRN) mismatch – inconsistent source LRN',
    2 : 'point code mismatch',
    3 : 'service class mismatch',
    4 : 'unqualified'
    }

class ErrCause(Uint8):
    _dic = _ErrCause_dict


#------------------------------------------------------------------------------#
# Refusal Cause
# ITU-T Q.713, section 3.15
#------------------------------------------------------------------------------#

_RefCause_dict = {
    0 : 'end user originated',
    1 : 'end user congestion',
    2 : 'end user failure',
    3 : 'SCCP user originated',
    4 : 'destination address unknown',
    5 : 'destination inaccessible',
    6 : 'network resource – QoS not available/non-transient',
    7 : 'network resource – QoS not available/transient',
    8 : 'access failure',
    9 : 'access congestion',
    10 : 'subsystem failure',
    11 : 'subsystem congestion',
    12 : 'expiration of the connection establishment timer',
    13 : 'incompatible user data',
    14 : 'reserved',
    15 : 'unqualified',
    16 : 'hop counter violation',
    17 : 'SCCP failure',
    18 : 'no translation for an address of such nature',
    19 : 'unequipped user'
    }

class RefCause(Uint8):
    _dic = _RefCause_dict


#------------------------------------------------------------------------------#
# Data
# ITU-T Q.713, section 3.16
#------------------------------------------------------------------------------#

class Data(Envelope):
    _GEN = (
        Uint8('Len'),
        Buf('Value', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


#------------------------------------------------------------------------------#
# Segmentation
# ITU-T Q.713, section 3.17
#------------------------------------------------------------------------------#

class Segmentation(Envelope):
    _GEN = (
        Uint('F', val=1, bl=1, dic={1:'first segment'}),
        Uint('C', bl=1, dic={0:'class 0 selected', 1:'class 1 selected'}),
        Uint('spare', bl=2),
        Uint('RemainingSeg', val=0, bl=4, dic={0:'last segment'}),
        Uint24('SegmentLocalRef')
        )


#------------------------------------------------------------------------------#
# Hop counter
# ITU-T Q.713, section 3.18
#------------------------------------------------------------------------------#

class HopCounter(Uint8):
    pass


#------------------------------------------------------------------------------#
# Importance
# ITU-T Q.713, section 3.19
#------------------------------------------------------------------------------#

class Importance(Envelope):
    _GEN = (
        Uint('spare', bl=5),
        Uint('Value', val=0, bl=3, dic={0:'least important', 7:'more important'})
        )


#------------------------------------------------------------------------------#
# Long data
# ITU-T Q.713, section 3.20
#------------------------------------------------------------------------------#

class LongData(Envelope):
    _GEN = (
        # WNG: Q.713 does not say if it is in BE or LE, we guess LE similarly to Ptr16
        Uint16LE('Len'),
        Buf('Value', val=b'', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


#------------------------------------------------------------------------------#
# SCCP messages and codes
# ITU-T Q.713, section 4
#------------------------------------------------------------------------------#

class _Ptr(UintLE):
    """Special SCCP pointer element, which sets its value automatically to the
    given field name
    """
    _field = None
    
    def __init__(self, *args, **kwargs):
        if 'field' in kwargs:
            self._field = kwargs['field']
            del kwargs['field']
        UintLE.__init__(self, *args, **kwargs)
        self._max = (1<<self._bl)-1
    
    def clone(self):
        c = UintLE.clone(self)
        if self._field:
            c._field = self._field
        return c
    
    def _make_val(self):
        if self._env is None or self._env._env is None:
            return 0
        else:
            val = 0
            # in case of pointer to optional part and no options, set to 0
            if self._field == 'Opt' and all([o.get_trans() for o in self._env._env['Opt']._content]):
                return val
            #
            # get the length of the following pointers (including self) within the Pointers envelope
            ind = self._env._content.index(self)
            for ptr in self._env._content[ind:]:
                val += ptr._bl//8
                #print('%s: %s, %i' % (self._name, ptr._name, val))
            if self._bl == 16:
                # see Q.713, section 2.3:
                # pointer value is between the MSB (LE) of the pointer and the parameter
                # hence removing 1 bytes for Ptr16
                val -= 1
            #
            # get the length of the fields after the Pointers field, up to self._field
            ind = 1 + self._env._env._content.index(self._env)
            for field in self._env._env._content[ind:]:
                if field._name == self._field:
                    break
                else:
                    val += field.get_len()
                #print('%s: %s, %i' % (self._name, field._name, val))
            #
            return min(self._max, val)
    
    _valauto = _make_val


class Ptr8(_Ptr):
    _bl = 8


class Ptr16(_Ptr):
    _bl = 16


# constructor for an optional parameter wrapper
def Optional(param, name):
    """prefix the parameter element `param' with an uint8 as name, and eventually
    an uint8 as len, and make it transparent by default
    """
    if param._name == 'EOO':
        w = Envelope(param._name, GEN=(param, ), trans=True)
    elif param.CLASS == 'Envelope' and param[0]._name == 'Len':
        # length prefix already present
        w = Envelope(param._name, GEN=(
                Uint8('Name', val=name, dic=_SCCPParam_dict),
                param), trans=True)
    else:
        # length prefix to be added
        class Option(Envelope):
            _GEN = (
                Uint8('Name', val=name, dic=_SCCPParam_dict),
                Uint8('Len'),
                param
                )
            def __init__(self, *args, **kwargs):
                Envelope.__init__(self, *args, **kwargs)
                self[1].set_valauto(lambda: self[2].get_len())
                if not hasattr(param, '_bl') or param._bl is None:
                    self[2].set_blauto(lambda: self[1].get_val()<<3)
                self.set_trans(True)
        w = Option(param._name)
    return w


# parent class for SCCP messages
class SCCPMessage(Envelope):
    """Parent class for all SCCP message, handling the parsing of variable-length
    fields specifically 
    """
    
    def _from_char(self, char):
        if self.get_trans():
            return
        # parse the fixed content up the the pointers
        start = 0
        for e in self._content:
            e._from_char(char)
            if e._name == 'Pointers':
                # e: envelope containing all Ptr8 or Ptr16 values
                start = 1 + self.index(e)
                break
        if not start:
            return
        # parse the variable-length and optional content according to the pointers
        # this is done non-sequentially
        ccur, numptr = char._cur, len(e._content)
        # ccur: cursor at the end of the Pointers field
        # numptr: number of pointers
        for ind, ptr in enumerate(e._content):
            if ptr._field == 'Opt' and ptr._val == 0:
                break
            # update the charpy cursor
            char._cur = ccur + (8 * ptr.get_val()) - ((numptr-ind) * ptr._bl)
            if ptr._bl == 16:
                # see Q.713, section 2.3:
                # pointer value is between the MSB (LE) of the pointer and the parameter
                # hence removing 1 bytes for Ptr16
                char._cur += 8
            # select the corresponding field
            field = self._content[start+ind]
            #print('%s: %s, %i' % (ptr._name, field._name, char._cur))
            field._from_char(char)
    
    def is_valid(self):
        """Ensures an SCCP message has a valid layout,
        i.e. its mandatory parameters with variable length (those with pointers) 
        do not overlap
        
        Args:
            None
        
        Returns:
            result: bool
        """
        if 'Pointers' in self._by_name:
            ptrs_ind = self._by_name.index('Pointers')
            ptrs  = self._content[ptrs_ind].get_val()
            prms  = self._content[1+ptrs_ind:]
            areas, len_ptrs = [], len(ptrs)
            for i in range(len_ptrs):
                prm = prms[i]
                if prm._name == 'Opt':
                    # Options have no global length prefix, but are always the last parameter
                    # moreover, if their pointer is null, the parameter is not present
                    ptr = ptrs[i]
                    if ptr != 0:
                        areas.append( (ptr-(len_ptrs-i), None) )
                else:
                    areas.append( (ptrs[i]-(len_ptrs-i), 1+prm._content[0].get_val()) )
            areas.sort(key=lambda x: x[0])
            # areas: list of (prm_offset, prm_length), sorted by prm_offset
            #print(areas)
            off = 0
            for prm in areas:
                if prm[0] < off:
                    return False
                else:
                    if prm[1] is not None:
                        off += prm[1]
        return True


# parent class for SCCP messages options
class SCCPOpt(Envelope):
    """Class for handling the set of SCCP optional fields in a given message
    """
    ENV_SEL_TRANS = False
    _opts = {}
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        # build a dict of name : optional field
        self._opts = {e[0]._val: e for e in self._content}
    
    def _from_char(self, char):
        if self.get_trans():
            return
        # parse the different options in the given order
        ind = 0
        while char.len_bit() >= 8:
            name = char.get_uint(8)
            if name not in self._opts:
                #raise(PycrateErr('SCCP option: invalid identifier %i' % name))
                # unknown option
                opt = Optional(Buf('_unk_%i' % name, rep=REPR_HEX), name)
                unk = True
            else:
                opt = self._opts[name]
                unk = False
            opt.set_trans(False)
            opt[0].set_val(name)
            # parse the rest of the option
            for e in opt._content[1:]:
                e._from_char(char)
            if unk:
                # insert unknown optional field
                self.insert(ind, opt)
            elif self.index(opt) != ind:
                # reorder optional field
                self.remove(opt)
                self.insert(ind, opt)
            ind += 1
            if name == 0:
                # end of options
                break


#------------------------------------------------------------------------------#
# Connection Request (CR)
# ITU-T Q.713, section 4.2
#------------------------------------------------------------------------------#

class SCCPConnectionRequest(SCCPMessage):
    _GEN = (
        Uint8('Type', val=1, dic=_SCCPType_dict),
        SrcLocalRef(),
        ProtocolClass(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='CalledPartyAddr'),
            Ptr8('Ptr1', field='Opt')
            )),
        CalledPartyAddr(),
        SCCPOpt('Opt', GEN=(
            Optional(Credit(), 9),
            Optional(CallingPartyAddr(), 4),
            Optional(Data(), 15),
            Optional(HopCounter(), 17),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )


#------------------------------------------------------------------------------#
# Connection Confirm (CC)
# ITU-T Q.713, section 4.3
#------------------------------------------------------------------------------#

class SCCPConnectionConfirm(SCCPMessage):
    _GEN = (
        Uint8('Type', val=2, dic=_SCCPType_dict),
        DstLocalRef(),
        SrcLocalRef(),
        ProtocolClass(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        SCCPOpt('Opt', GEN=(
            Optional(Credit(), 9),
            Optional(CalledPartyAddr(), 4),
            Optional(Data(), 15),
            Optional(HopCounter(), 17),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )


#------------------------------------------------------------------------------#
# Connection Refused (CREF)
# ITU-T Q.713, section 4.4
#------------------------------------------------------------------------------#

class SCCPConnectionRefused(SCCPMessage):
    _GEN = (
        Uint8('Type', val=3, dic=_SCCPType_dict),
        DstLocalRef(),
        RefCause(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        SCCPOpt('Opt', GEN=(
            Optional(CalledPartyAddr(), 4),
            Optional(Data(), 15),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )


#------------------------------------------------------------------------------#
# Released (RLSD)
# ITU-T Q.713, section 4.5
#------------------------------------------------------------------------------#

class SCCPReleased(SCCPMessage):
    _GEN = (
        Uint8('Type', val=4, dic=_SCCPType_dict),
        DstLocalRef(),
        SrcLocalRef(),
        RelCause(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        SCCPOpt('Opt', GEN=(
            Optional(Data(), 15),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )


#------------------------------------------------------------------------------#
# Release complete (RLC)
# ITU-T Q.713, section 4.6
#------------------------------------------------------------------------------#

class SCCPReleaseComplete(SCCPMessage):
    _GEN = (
        Uint8('Type', val=5, dic=_SCCPType_dict),
        DstLocalRef(),
        SrcLocalRef()
        )


#------------------------------------------------------------------------------#
# Data form 1 (DT1)
# ITU-T Q.713, section 4.7
#------------------------------------------------------------------------------#

class SCCPDataForm1(SCCPMessage):
    _GEN = (
        Uint8('Type', val=6, dic=_SCCPType_dict),
        DstLocalRef(),
        SegmentReassemb(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Data'),
            )),
        Data()
        )


#------------------------------------------------------------------------------#
# Data form 2 (DT2)
# ITU-T Q.713, section 4.8
#------------------------------------------------------------------------------#

class SCCPDataForm2(SCCPMessage):
    _GEN = (
        Uint8('Type', val=7, dic=_SCCPType_dict),
        DstLocalRef(),
        SeqSegment(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Data'),
            )),
        Data()
        )


#------------------------------------------------------------------------------#
# Data acknowledgement (AK)
# ITU-T Q.713, section 4.9
#------------------------------------------------------------------------------#

class SCCPDataAck(SCCPMessage):
    _GEN = (
        Uint8('Type', val=8, dic=_SCCPType_dict),
        DstLocalRef(),
        RecvSeqn(),
        Credit()
        )


#------------------------------------------------------------------------------#
# Unit Data (UDT)
# ITU-T Q.713, section 4.10
#------------------------------------------------------------------------------#

class SCCPUnitData(SCCPMessage):
    _GEN = (
        Uint8('Type', val=9, dic=_SCCPType_dict),
        ProtocolClass(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='CalledPartyAddr'),
            Ptr8('Ptr1', field='CallingPartyAddr'),
            Ptr8('Ptr2', field='Data')
            )),
        CalledPartyAddr(),
        CallingPartyAddr(),
        Data()
        )


#------------------------------------------------------------------------------#
# Unit Data Service (UDTS)
# ITU-T Q.713, section 4.11
#------------------------------------------------------------------------------#

class SCCPUnitDataService(SCCPMessage):
    _GEN = (
        Uint8('Type', val=10, dic=_SCCPType_dict),
        RetCause(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='CalledPartyAddr'),
            Ptr8('Ptr1', field='CallingPartyAddr'),
            Ptr8('Ptr2', field='Data')
            )),
        CalledPartyAddr(),
        CallingPartyAddr(),
        Data()
        )


#------------------------------------------------------------------------------#
# Expedited data (ED)
# ITU-T Q.713, section 4.12
#------------------------------------------------------------------------------#

class SCCPExpeditedData(SCCPMessage):
    _GEN = (
        Uint8('Type', val=11, dic=_SCCPType_dict),
        DstLocalRef(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Data'),
            )),
        Data()
        )


#------------------------------------------------------------------------------#
# Expedited data acknowledgement (EA)
# ITU-T Q.713, section 4.13
#------------------------------------------------------------------------------#

class SCCPExpeditedDataAck(SCCPMessage):
    _GEN = (
        Uint8('Type', val=12, dic=_SCCPType_dict),
        DstLocalRef()
        )


#------------------------------------------------------------------------------#
# Reset request (RSR)
# ITU-T Q.713, section 4.14
#------------------------------------------------------------------------------#

class SCCPResetRequest(SCCPMessage):
    _GEN = (
        Uint8('Type', val=13, dic=_SCCPType_dict),
        DstLocalRef(),
        SrcLocalRef(),
        ResCause(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        SCCPOpt('Opt', GEN=(
            Optional(EOO(), 0),
            ))
        )


#------------------------------------------------------------------------------#
# Reset confirmation (RSC)
# ITU-T Q.713, section 4.15
#------------------------------------------------------------------------------#

class SCCPResetConf(SCCPMessage):
    _GEN = (
        Uint8('Type', val=14, dic=_SCCPType_dict),
        DstLocalRef(),
        SrcLocalRef()
        )


#------------------------------------------------------------------------------#
# Protocol data unit error (ERR)
# ITU-T Q.713, section 4.16
#------------------------------------------------------------------------------#

class SCCPError(SCCPMessage):
    _GEN = (
        Uint8('Type', val=15, dic=_SCCPType_dict),
        DstLocalRef(),
        ErrCause,
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='Opt'),
            )),
        SCCPOpt('Opt', GEN=(
            Optional(EOO(), 0),
            ))
        )


#------------------------------------------------------------------------------#
# Inactivity test (IT)
# ITU-T Q.713, section 4.17
#------------------------------------------------------------------------------#

class SCCPInactivityTest(SCCPMessage):
    _GEN = (
        Uint8('Type', val=16, dic=_SCCPType_dict),
        DstLocalRef(),
        SrcLocalRef(),
        ProtocolClass(),
        SeqSegment(),
        Credit()
        )


#------------------------------------------------------------------------------#
# Extended unitdata (XUDT)
# ITU-T Q.713, section 4.18
#------------------------------------------------------------------------------#

class SCCPExtUnitData(SCCPMessage):
    _GEN = (
        Uint8('Type', val=17, dic=_SCCPType_dict),
        ProtocolClass(),
        HopCounter(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='CalledPartyAddr'),
            Ptr8('Ptr1', field='CallingPartyAddr'),
            Ptr8('Ptr2', field='Data'),
            Ptr8('Ptr3', field='Opt')
            )),
        CalledPartyAddr(),
        CallingPartyAddr(),
        Data(),
        SCCPOpt('Opt', GEN=(
            Optional(Segmentation(), 16),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )
        

#------------------------------------------------------------------------------#
# Extended unitdata service (XUDTS)
# ITU-T Q.713, section 4.19
#------------------------------------------------------------------------------#

class SCCPExtUnitDataService(SCCPMessage):
    _GEN = (
        Uint8('Type', val=18, dic=_SCCPType_dict),
        RetCause(),
        HopCounter(),
        Envelope('Pointers', GEN=(
            Ptr8('Ptr0', field='CalledPartyAddr'),
            Ptr8('Ptr1', field='CallingPartyAddr'),
            Ptr8('Ptr2', field='Data'),
            Ptr8('Ptr3', field='Opt')
            )),
        CalledPartyAddr(),
        CallingPartyAddr(),
        Data(),
        SCCPOpt('Opt', GEN=(
            Optional(Segmentation(), 16),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )
        

#------------------------------------------------------------------------------#
# Long unitdata (LUDT)
# ITU-T Q.713, section 4.20
#------------------------------------------------------------------------------#

class SCCPLongUnitData(SCCPMessage):
    _GEN = (
        Uint8('Type', val=19, dic=_SCCPType_dict),
        ProtocolClass(),
        HopCounter(),
        Envelope('Pointers', GEN=(
            Ptr16('Ptr0', field='CalledPartyAddr'),
            Ptr16('Ptr1', field='CallingPartyAddr'),
            Ptr16('Ptr2', field='LongData'),
            Ptr16('Ptr3', field='Opt')
            )),
        CalledPartyAddr(),
        CallingPartyAddr(),
        LongData(),
        SCCPOpt('Opt', GEN=(
            Optional(Segmentation(), 16),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )
    
    def is_valid(self):
        """Ensures an SCCP message has a valid layout,
        i.e. its mandatory parameters with variable length (those with pointers) 
        do not overlap
        
        Args:
            None
        
        Returns:
            result: bool
        """
        # for LUDT / LUDTS, pointer and length prefix are 2 bytes long
        ptrs = self._content[3].get_val()
        prms = self._content[4:]
        areas = []
        for i in range(4):
            prm = prms[i]
            if prm._name == 'Opt':
                # Options have no global length prefix, but are always the last parameter
                # moreover, if their pointer is null, the parameter is not present
                ptr = ptrs[i]
                if ptr != 0:
                    areas.append( (ptr-2*(4-i), None) )
            else:
                areas.append( (ptrs[i]-2*(4-i), 2+prm._content[0].get_val()) )
        areas.sort(key=lambda x: x[0])
        # areas: list of (prm_offset, prm_length), sorted by prm_offset
        #print(areas)
        off = 0
        for prm in areas:
            if prm[0] < off:
                return False
            else:
                if prm[1] is not None:
                    off += prm[1]
        return True


#------------------------------------------------------------------------------#
# Long unitdata service (LUDTS)
# ITU-T Q.713, section 4.21
#------------------------------------------------------------------------------#

class SCCPLongUnitDataService(SCCPMessage):
    _GEN = (
        Uint8('Type', val=20, dic=_SCCPType_dict),
        RetCause(),
        HopCounter(),
        Envelope('Pointers', GEN=(
            Ptr16('Ptr0', field='CalledPartyAddr'),
            Ptr16('Ptr1', field='CallingPartyAddr'),
            Ptr16('Ptr2', field='LongData'),
            Ptr16('Ptr3', field='Opt')
            )),
        CalledPartyAddr(),
        CallingPartyAddr(),
        LongData(),
        SCCPOpt('Opt', GEN=(
            Optional(Segmentation(), 16),
            Optional(Importance(), 18),
            Optional(EOO(), 0)
            ))
        )
    
    def is_valid(self):
        """Ensures an SCCP message has a valid layout,
        i.e. its mandatory parameters with variable length (those with pointers) 
        do not overlap
        
        Args:
            None
        
        Returns:
            result: bool
        """
        # for LUDT / LUDTS, pointer and length prefix are 2 bytes long
        ptrs = self._content[3].get_val()
        prms = self._content[4:]
        areas = []
        for i in range(4):
            prm = prms[i]
            if prm._name == 'Opt':
                # Options have no global length prefix, but are always the last parameter
                # moreover, if their pointer is null, the parameter is not present
                ptr = ptrs[i]
                if ptr != 0:
                    areas.append( (ptr-2*(4-i), None) )
            else:
                areas.append( (ptrs[i]-2*(4-i), 2+prm._content[0].get_val()) )
        areas.sort(key=lambda x: x[0])
        # areas: list of (prm_offset, prm_length), sorted by prm_offset
        #print(areas)
        off = 0
        for prm in areas:
            if prm[0] < off:
                return False
            elif prm[1] is None:
                return False
            else:
                off = prm[1]
        return True


#------------------------------------------------------------------------------#
# SCCP Message dispatcher
#------------------------------------------------------------------------------#

SCCPTypeClasses = {
    1 : SCCPConnectionRequest,
    2 : SCCPConnectionConfirm,
    3 : SCCPConnectionRefused,
    4 : SCCPReleased,
    5 : SCCPReleaseComplete,
    6 : SCCPDataForm1,
    7 : SCCPDataForm2,
    8 : SCCPDataAck,
    9 : SCCPUnitData,
    10 : SCCPUnitDataService,
    11 : SCCPExpeditedData,
    12 : SCCPExpeditedDataAck,
    13 : SCCPResetRequest,
    14 : SCCPResetConf,
    15 : SCCPError,
    16 : SCCPInactivityTest,
    17 : SCCPExtUnitData,
    18 : SCCPExtUnitDataService,
    19 : SCCPLongUnitData,
    20 : SCCPLongUnitDataService,
    }

def get_sccp_msg_instances():
    return {k: SCCPTypeClasses[k]() for k in SCCPTypeClasses}


#------------------------------------------------------------------------------#
# SCCP Management messages and codes
# ITU-T Q.713, section 5
#------------------------------------------------------------------------------#

#------------------------------------------------------------------------------#
# SCMG message parameters
# ITU-T Q.713, section 5.2
#------------------------------------------------------------------------------#

_SCMGType_dict = {
    1 : 'SSA subsystem-allowed',
    2 : 'SSP subsystem-prohibited',
    3 : 'SST subsystem-status-test',
    4 : 'SOR subsystem-out-of-service-request',
    5 : 'SOG subsystem-out-of-service-grant',
    6 : 'SSC SCCP/subsystem-congested'
    }


_SMI_dict = {
    0 : 'affected subsystem multiplicity unknown',
    2 : 'reserved for national use',
    3 : 'reserved for national use'
    }

class SubsysMultInd(Envelope):
    _GEN = (
        Uint('spare', bl=6),
        Uint('Value', val=0, bl=2, dic=_SMI_dict)
        )


class CongestLevel(Envelope):
    _GEN = (
        Uint('spare', bl=4),
        Uint('Value', val=1, bl=4, dic={1:'least congested', 8:'most congested'})
        )


#------------------------------------------------------------------------------#
# SCCP Messages
# ITU-T Q.713, section 5.3
#------------------------------------------------------------------------------#

class SCMGSubsysAllowed(Envelope):
    _GEN = (
        Uint8('Type', val=1, dic=_SCMGType_dict),
        Uint8('AffectedSSN', val=0, dic=_SSN_dict),
        Uint16LE('AffectedPC', val=0),
        SubsysMultInd()
        )


class SCMGSubsysProhibited(Envelope):
    _GEN = (
        Uint8('Type', val=2, dic=_SCMGType_dict),
        Uint8('AffectedSSN', val=0, dic=_SSN_dict),
        Uint16LE('AffectedPC', val=0),
        SubsysMultInd()
        )


class SCMGSubsysStatTest(Envelope):
    _GEN = (
        Uint8('Type', val=3, dic=_SCMGType_dict),
        Uint8('AffectedSSN', val=0, dic=_SSN_dict),
        Uint16LE('AffectedPC', val=0),
        SubsysMultInd()
        )


class SCMGSubsysOutOfServRequest(Envelope):
    _GEN = (
        Uint8('Type', val=4, dic=_SCMGType_dict),
        Uint8('AffectedSSN', val=0, dic=_SSN_dict),
        Uint16LE('AffectedPC', val=0),
        SubsysMultInd()
        )


class SCMGSubsysOutOfServGrant(Envelope):
    _GEN = (
        Uint8('Type', val=5, dic=_SCMGType_dict),
        Uint8('AffectedSSN', val=0, dic=_SSN_dict),
        Uint16LE('AffectedPC', val=0),
        SubsysMultInd()
        )

class SCMGSubsysCongested(Envelope):
    _GEN = (
        Uint8('Type', val=6, dic=_SCMGType_dict),
        Uint8('AffectedSSN', val=0, dic=_SSN_dict),
        Uint16LE('AffectedPC', val=0),
        SubsysMultInd(),
        CongestLevel()
        )

#------------------------------------------------------------------------------#
# SCMG Message dispatcher
#------------------------------------------------------------------------------#

SCMGTypeClasses = {
    1 : SCMGSubsysAllowed,
    2 : SCMGSubsysProhibited,
    3 : SCMGSubsysStatTest,
    4 : SCMGSubsysOutOfServRequest,
    5 : SCMGSubsysOutOfServGrant,
    6 : SCMGSubsysCongested
    }

def get_scmg_msg_instances():
    return {k: SCMGTypeClasses[k]() for k in SCMGTypeClasses}


#------------------------------------------------------------------------------#
# SCPP Message parser
#------------------------------------------------------------------------------#

def parse_SCCP(buf, w_scmg=True):
    """Parses an SCCP message bytes' buffer
    
    Args:
        buf: SCCP message bytes' buffer
    
    Returns:
        element, err: 2-tuple
            element: Element instance, if err is null (no error)
            element: None, if err is not null
            err: 0 no error, 1 invalid message type, 2 message parsing failed
    """
    if not buf:
        return None, 1
    if python_version < 3:
        try:
            Msg = SCCPTypeClasses[ord(buf[0])]()
        except:
            return None, 1
    else:
        try:
            Msg = SCCPTypeClasses[buf[0]]()
        except:
            return None, 1
    try:
        Msg.from_bytes(buf)
    except:
        return None, 2
    #
    # if SCMG, parses it further (UDT/XUDT/LUDT, ProtocolClass 0, both addresses on SSN 1)
    if w_scmg:
        try:
            if Msg[0].get_val() in (9, 17, 19) and Msg[1][1].get_val() == 0 and \
            Msg[3][1][0]['RoutingInd'].get_val() == 1 and  Msg[3][1][0]['SSNInd'].get_val() == 1 and Msg[3][1]['SSN'].get_val() == 1 and \
            Msg[4][1][0]['RoutingInd'].get_val() == 1 and  Msg[4][1][0]['SSNInd'].get_val() == 1 and Msg[4][1]['SSN'].get_val() == 1:
                data = Msg[5]
                dataval = data[1]
                scmg, err = parse_SCMG(dataval.get_val())
                if err == 0:
                    data.replace(dataval, scmg)
        except:
            pass
    #
    return Msg, 0


def parse_SCMG(buf):
    """Parses an SCMG message bytes' buffer
    
    Args:
        buf: SCMG message bytes' buffer
    
    Returns:
        element, err: 2-tuple
            element: Element instance, if err is null (no error)
            element: None, if err is not null
            err: 0 no error, 1 invalid message type, 2 message parsing failed
    """
    if not buf:
        return None, 1
    if python_version < 3:
        try:
            Msg = SCMGTypeClasses[ord(buf[0])]()
        except:
            return None, 1
    else:
        try:
            Msg = SCMGTypeClasses[buf[0]]()
        except:
            return None, 1
    try:
        Msg.from_bytes(buf)
    except:
        return None, 2
    return Msg, 0


