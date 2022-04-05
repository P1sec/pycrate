# -*- coding: UTF-8 -*-
#/**
# * Software Name : pycrate
# * Version : 0.4
# *
# * Copyright 2017. Benoit Michau. ANSSI.
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
# * File Name : pycrate_mobile/TS23040_SMS.py
# * Created : 2017-10-23
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'SMS_TP',
    'TP_OA',
    'TP_DA',
    'TP_PID',
    'TP_DCS',
    'TP_SCTS',
    'TP_VP',
    'TP_VPe',
    'TP_DT',
    'TP_RA',
    'TP_UDH_IE',
    'TP_UDH',
    'TP_UD',
    'TP_PI',
    'SMS_DELIVER',
    'SMS_DELIVER_REPORT_RP_ERROR',
    'SMS_DELIVER_REPORT_RP_ACK',
    'SMS_SUBMIT',
    'SMS_SUBMIT_REPORT_RP_ERROR',
    'SMS_SUBMIT_REPORT_RP_ACK',
    'SMS_STATUS_REPORT',
    'SMS_COMMAND'
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 23.040: Technical realization of the Short Message Service (SMS)
# release 13 (d20)
#------------------------------------------------------------------------------#

from time import struct_time
from math import ceil

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24008_IE import BufBCD, _BCDType_dict, _NumPlan_dict
from .TS24007    import *
from .TS23038    import *


_str_reserved = 'reserved'


class SMS_TP(Envelope):
    """parent class for all SMS TP messages
    """
    pass


#------------------------------------------------------------------------------#
# Address fields
# TS 23.040, section 9.1.2.5	
#------------------------------------------------------------------------------#

class BufTPNum(BufBCD):
    
    _ALNUM_PAD = 0
    
    def get_tpnum_type(self):
        try:
            return self.get_env()['Type'].get_val()
        except Exception:
            # international BCD number
            return 1
    
    def decode(self):
        if self.get_tpnum_type() == 5:
            # alphanumeric
            dec = decode_7b(self._val)
            if self._ALNUM_PAD and dec[-1] == '@':
                return dec[:-1]
            else:
                return dec
        else:
            # BCD
            return BufBCD.decode(self)
    
    def encode(self, val=''):
        if self.get_tpnum_type() == 5:
            # alphanumeric
            self._val, cnt = encode_7b(val)
            if 1 <= (7*cnt) % 8 <= 3:
                self._ALNUM_PAD = 1
            else:
                self._ALNUM_PAD = 0
        else:
            # BCD
            BufBCD.encode(self, val)


class _TPAddress(Envelope):
    _GEN = (
        Uint8('Len'), # WNG: number of nibbles (4-bits) in Num
        Uint('Ext', val=1, bl=1),
        Uint('Type', val=1, bl=3, dic=_BCDType_dict),
        Uint('NumberingPlan', val=1, bl=4, dic=_NumPlan_dict),
        BufTPNum('Num')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self._len_set())
        self[4].set_blauto(lambda: self._len_get())
    
    def _len_set(self):
        if self[2].get_val() == 5:
            # alphanumeric
            l = 2 * self[4].get_len()
            if hasattr(self[4], '_ALNUM_PAD') and self[4]._ALNUM_PAD:
                return l-1
            else:
                return l
        else:
            # BCD
            return len(self[4].decode())
    
    def _len_get(self):
        l = self[0].get_val()
        if l%2:
            if self[2].get_val() == 5 and hasattr(self[4], '_ALNUM_PAD'):
                self[4]._ALNUM_PAD = 1
            return (1+l)<<2
        else:
            return l<<2


#------------------------------------------------------------------------------#
# TP‑Message‑Type‑Indicator (TP‑MTI)
# TS 23.040, section 9.2.3.1
#------------------------------------------------------------------------------#
# coded on 2 bits

_TP_MTI_MT_dict = {
    0 : 'SMS-DELIVER',
    1 : 'SMS-SUBMIT-REPORT',
    2 : 'SMS-STATUS-REPORT',
    3 : 'Reserved',
    }

_TP_MTI_MO_dict = {
    0 : 'SMS-DELIVER-REPORT',
    1 : 'SMS-SUBMIT',
    2 : 'SMS-COMMAND',
    3 : 'Reserved',
    }


#------------------------------------------------------------------------------#
# TP‑More‑Messages‑to‑Send (TP‑MMS)
# TS 23.040, section 9.2.3.2
#------------------------------------------------------------------------------#
# coded on 1 bit

_TP_MMS_dict = {
    0 : 'More messages are waiting for the MS in this SC',
    1 : 'No more messages are waiting for the MS in this SC',
    }


#------------------------------------------------------------------------------#
# TP‑Validity‑Period‑Format (TP‑VPF)
# TS 23.040, section 9.2.3.3
#------------------------------------------------------------------------------#
# coded on 2 bits

_TP_VPF_dict = {
    0 : 'TP VP field not present',
    1 : 'TP-VP field present - enhanced format',
    2 : 'TP VP field present - relative format',
    3 : 'TP VP field present - absolute format',
    }


#------------------------------------------------------------------------------#
# TP‑Status‑Report‑Indication (TP‑SRI)
# TS 23.040, section 9.2.3.4
#------------------------------------------------------------------------------#
# coded on 1 bit

_TP_SRI_dict = {
    0 : 'A status report shall not be returned',
    1 : 'A status report shall be returned',
    }


#------------------------------------------------------------------------------#
# TP‑Status‑Report‑Request (TP‑SRR)
# TS 23.040, section 9.2.3.5
#------------------------------------------------------------------------------#
# coded on 1 bit

_TP_SRR_dict = {
    0 : 'A status report is not requested',
    1 : 'A status report is requested',
    }


#------------------------------------------------------------------------------#
# TP‑Originating‑Address (TP‑OA)
# TS 23.040, section 9.2.3.7
#------------------------------------------------------------------------------#

class TP_OA(_TPAddress):
    pass


#------------------------------------------------------------------------------#
# TP‑Destination‑Address (TP‑DA)
# TS 23.040, section 9.2.3.8
#------------------------------------------------------------------------------#

class TP_DA(_TPAddress):
    pass


#------------------------------------------------------------------------------#
# TP‑Protocol‑Identifier (TP‑PID)
# TS 23.040, section 9.2.3.9
#------------------------------------------------------------------------------#

_TP_PIDFmt_dict = {
    0 : 'telematic indication',
    1 : 'no telematic indication',
    2 : 'Reserved',
    3 : 'protocol for SC specific use',
    }

_TP_PIDTelematic_dict = {
    0 : 'no telematic interworking, but SME-to-SME protocol',
    1 : 'telematic interworking',
    }

_TP_PIDTeleserv_dict = {
    0 : 'implicit - device type is specific to this SC, '\
        'or can be concluded on the basis of the address',
    1 : 'telex (or teletex reduced to telex format)',
    2 : 'group 3 telefax',
    3 : 'group 4 telefax',
    4 : 'voice telephone (i.e. conversion to speech)',
    5 : 'ERMES (European Radio Messaging System)',
    6 : 'National Paging system (known to the SC)',
    7 : 'Videotex (T.100 [20] /T.101 [21])',
    8 : 'teletex, carrier unspecified',
    9 : 'teletex, in PSPDN',
    10 : 'teletex, in CSPDN',
    11 : 'teletex, in analog PSTN',
    12 : 'teletex, in digital ISDN',
    13 : 'UCI (Universal Computer Interface, ETSI DE/PS 3 01 3)',
    14 : '(reserved, 2 combinations)',
    16 : 'a message handling facility (known to the SC)',
    17 : 'any public X.400 based message handling system',
    18 : 'Internet Electronic Mail',
    19 : '(reserved, 5 combinations)',
    24 : 'values specific to each SC, usage based on mutual agreement '\
         'between the SME and the SC (7 combinations available for each SC)',
    31 : 'A GSM/UMTS mobile station. The SC converts the SM from the received '\
         'TP Data Coding Scheme to any data coding scheme supported by that MS',
    }

_TP_PIDServ_dict = {
    0 : 'Short Message Type 0',
    1 : 'Replace Short Message Type 1',
    2 : 'Replace Short Message Type 2',
    3 : 'Replace Short Message Type 3',
    4 : 'Replace Short Message Type 4',
    5 : 'Replace Short Message Type 5',
    6 : 'Replace Short Message Type 6',
    7 : 'Replace Short Message Type 7',
    8 : 'Reserved',
    30 : 'Enhanced Message Service (Obsolete)',
    31 : 'Return Call Message',
    32 : 'Reserved',
    60 : 'ANSI-136 R-DATA',
    61 : 'ME Data download',
    62 : 'ME De personalization Short Message',
    63 : '(U)SIM Data download', # for USAT, TS 51.011
    }

class _TP_PIDTelematic(Envelope):
    _GEN = (
        Uint('Telematic', bl=1, dic=_TP_PIDTelematic_dict),
        Uint('Protocol', bl=5)
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_dicauto(lambda: _TP_PIDTeleserv_dict if self[0]() == 1 else {})


class TP_PID(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('Format', bl=2, dic=_TP_PIDFmt_dict),
        _TP_PIDTelematic('Telematic'), # telematic if Format == 0
        Uint('Protocol', bl=6) # Format != 0
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_transauto(lambda: self[0]() != 0)
        self[2].set_transauto(lambda: self[0]() == 0)
        self[2].set_dicauto(lambda: _TP_PIDServ_dict if self[0]() == 1 else {})


#------------------------------------------------------------------------------#
# TP‑Data‑Coding‑Scheme (TP‑DCS)
# TS 23.040, section 9.2.3.10
#------------------------------------------------------------------------------#
# defined in TS 23.038

class TP_DCS(SMS_DCS):
    pass


#------------------------------------------------------------------------------#
# TP‑Service‑Centre‑Time‑Stamp (TP‑SCTS)
# TS 23.040, section 9.2.3.11
#------------------------------------------------------------------------------#

class _TP_SCTS_Comp(Envelope):
    
    def set_val(self, vals):
        if isinstance(vals, integer_types):
            self.encode(vals)
        else:
            Envelope.set_val(self, vals)
    
    def encode(self, val):
        self.set_val( (val%10, val//10) )
    
    def decode(self):
        return self[0]()+10*self[1]()
    
    def repr(self):
        return '<%s : %i%i>' % (self._name, self[1](), self[0]())
    
    __repr__ = repr


class _TP_SCTS_TZ(Envelope):
    _Sign_dict = {0: '+', 1: '-'}
    _GEN = (
        Uint('TZ1', bl=4),
        Uint('TZS', bl=1, dic=_Sign_dict),
        Uint('TZ0', bl=3)
        )
    
    def set_val(self, vals):
        if isinstance(vals, float):
            self.encode(vals)
        else:
            Envelope.set_val(self, vals)
    
    def encode(self, val):
        if val < 0:
            self[1].set_val(1)
            val = -val
        else:
            self[1].set_val(0)
        if val != 0:
            quart = ceil((val*4) % 128)
            self[0].set_val( quart%16 )
            self[2].set_val( quart>>4 )
        else:
            self[0].set_val(0)
            self[2].set_val(0)
    
    def decode(self):
        if self[1]() == 1:
            return -0.25 * ((self[2]()<<4) + self[0]())
        else:
            return 0.25 * ((self[2]()<<4) + self[0]())
    
    def repr(self):
        return '<TZ: %s%.2f>' % (self._Sign_dict[self[1]()], 0.25 * (self[0]() + (self[2]()<<4)))
        
    __repr__ = repr


class TP_SCTS(Envelope):
    YEAR_BASE = 2000
    _GEN = (
        _TP_SCTS_Comp('Year', GEN=(Uint('Y1', bl=4), Uint('Y0', bl=4))),
        _TP_SCTS_Comp('Mon',  GEN=(Uint('M1', bl=4), Uint('M0', bl=4))),
        _TP_SCTS_Comp('Day',  GEN=(Uint('D1', bl=4), Uint('D0', bl=4))),
        _TP_SCTS_Comp('Hour', GEN=(Uint('H1', bl=4), Uint('H0', bl=4))),
        _TP_SCTS_Comp('Min',  GEN=(Uint('M1', bl=4), Uint('M0', bl=4))),
        _TP_SCTS_Comp('Sec', GEN=(Uint('S1', bl=4), Uint('S0', bl=4))),
        _TP_SCTS_TZ('TZ')
        )
    
    def set_val(self, val):
        if isinstance(val, (tuple, list)) and len(val) == 2:
            self.encode(*val)
        else:
            Envelope.set_val(self, val)
    
    def encode(self, ts, tz=0.0):
        """encode a Python struct_time and potential timezone shift as the value of TP_SCTS
        """
        self['Year'].encode( ts.tm_year-self.YEAR_BASE )
        self['Mon'].encode( ts.tm_mon  )
        self['Day'].encode( ts.tm_mday )
        self['Hour'].encode( ts.tm_hour )
        self['Min'].encode( ts.tm_min  )
        self['Sec'].encode( ts.tm_sec )
        self['TZ'].encode( tz )
    
    def decode(self):
        """decode the current TP_SCTS value into a Python struct_time and timezone shift
        """
        ts = struct_time((self.YEAR_BASE+self['Year'].decode(), self['Mon'].decode(),
                          self['Day'].decode(), self['Hour'].decode(), self['Min'].decode(),
                          self['Sec'].decode(), 0, 0, 0))
        return ts, self['TZ'].decode()


#------------------------------------------------------------------------------#
# TP-VP (Relative format)
# TS 23.040, section 9.2.3.12.1
#------------------------------------------------------------------------------#

_TP_VPRel_dict = {}
for i in range(0, 144):
    _TP_VPRel_dict[i] = '%i min' % (5*(i+1))
for i in range(144, 168):
    _TP_VPRel_dict[i] = '%.1f hr' % (12+(i-143)*0.5)
for i in range(168, 197):
    _TP_VPRel_dict[i] = '%i day' % (i-166)
for i in range(197, 256):
    _TP_VPRel_dict[i] = '%i week' % (i-192)


#------------------------------------------------------------------------------#
# TP-VP (Absolute format)
# TS 23.040, section 9.2.3.12.2
#------------------------------------------------------------------------------#

class TP_VP(TP_SCTS):
    pass


#------------------------------------------------------------------------------#
# TP-VP (Enhanced format)
# TS 23.040, section 9.2.3.12.3
#------------------------------------------------------------------------------#
# not sure it should have been called "enhanced"...

_TP_VPeFmt_dict = {
    0 : 'no VP specified', # 6 spare bytes
    1 : 'relative VP', # 5 spare bytes
    2 : 'relative VP (0 < VP < 256 sec)', # 5 spare bytes
    3 : 'relative VP (HHMMSS)', # 3 spare bytes
    4 : _str_reserved, # 6 spare bytes
    5 : _str_reserved,
    6 : _str_reserved,
    7 : _str_reserved
    }

class _TP_VPe_HHMMSS(Envelope):
    _GEN = (
        _TP_SCTS_Comp('Hour', GEN=(Uint('H1', bl=4), Uint('H0', bl=4))),
        _TP_SCTS_Comp('Min',  GEN=(Uint('M1', bl=4), Uint('M0', bl=4))),
        _TP_SCTS_Comp('Sec', GEN=(Uint('S1', bl=4), Uint('S0', bl=4)))
        )
    
    def set_val(self, val):
        if isinstance(val, struct_time):
            self.encode(val)
        else:
            Envelope.set_val(self, val)
    
    def encode(self, ts):
        """encode a Python struct_time as the value of _TP_VPe_HHMMSS
        """
        self['Hour'].encode( ts.tm_hour )
        self['Min'].encode( ts.tm_min  )
        self['Sec'].encode( ts.tm_sec )
    
    def decode(self):
        """decode the current _TP_VPe_HHMMSS value into a Python struct_time
        """
        return struct_time((0, 0, 0, self['Hour'].decode(), self['Min'].decode(),
                            self['Sec'].decode(), 0, 0, 0))


class TP_VPe(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('Ext', bl=1),
        Uint('SingleShot', bl=1),
        Uint(_str_reserved, bl=3),
        Uint('VPFormat', bl=3, dic=_TP_VPeFmt_dict),
        Uint8('VP'),
        _TP_VPe_HHMMSS('TP'),
        BufAuto('spare')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[4].set_transauto(lambda: self[3]() not in (1, 2))
        self[4].set_dicauto(lambda: _TP_VPRel_dict if self[3]() == 1 else {})
        self[5].set_transauto(lambda: self[3]() != 3)
        self[6].set_blauto(self._set_spare_bl)
    
    def _set_spare_bl(self):
        fmt = self[3]()
        if fmt in (1, 2):
            return 40
        elif fmt == 3:
            return 24
        else:
            return 48


#------------------------------------------------------------------------------#
# TP‑Discharge‑Time (TP‑DT)
# TS 23.040, section 9.2.3.13
#------------------------------------------------------------------------------#

class TP_DT(TP_SCTS):
    pass


#------------------------------------------------------------------------------#
# TP‑Recipient‑Address (TP‑RA)
# TS 23.040, section 9.2.3.14
#------------------------------------------------------------------------------#

class TP_RA(_TPAddress):
    pass


#------------------------------------------------------------------------------#
# TP‑Status (TP‑ST)
# TS 23.040, section 9.2.3.15
#------------------------------------------------------------------------------#

_TP_ST_dict = {
    0 : 'Short message transaction completed - Short message received '\
        'by the SME',
    1 : 'Short message transaction completed - Short message forwarded '\
        'by the SC to the SME but the SC is unable to confirm delivery',
    2 : 'Short message transaction completed - Short message replaced '\
        'by the SC',
    3 : 'Short message transaction completed - reserved',
    16 : 'Short message transaction completed - SC specific',
    32 : 'Temporary error, SC still trying to transfer SM - Congestion',
    33 : 'Temporary error, SC still trying to transfer SM - SME busy',
    34 : 'Temporary error, SC still trying to transfer SM - No response '\
         'from SME',
    35 : 'Temporary error, SC still trying to transfer SM - Service rejected',
    36 : 'Temporary error, SC still trying to transfer SM - '\
         'Quality of service not available',
    37 : 'Temporary error, SC still trying to transfer SM - Error in SME',
    38 : 'Temporary error, SC still trying to transfer SM - reserved',
    48 : 'Temporary error, SC still trying to transfer SM - SC specific',
    64 : 'Permanent error, SC is not making any more transfer attempts - '\
         'Remote procedure error',
    65 : 'Permanent error, SC is not making any more transfer attempts - '\
         'Incompatible destination',
    66 : 'Permanent error, SC is not making any more transfer attempts - '\
         'Connection rejected by SME',
    67 : 'Permanent error, SC is not making any more transfer attempts - '\
         'Not obtainable',
    68 : 'Permanent error, SC is not making any more transfer attempts - '\
         'Quality of service not available',
    69 : 'Permanent error, SC is not making any more transfer attempts - '\
         'No interworking available',
    70 : 'Permanent error, SC is not making any more transfer attempts - '\
         'SM Validity Period Expired',
    71 : 'Permanent error, SC is not making any more transfer attempts - '\
         'SM Deleted by originating SME',
    72 : 'Permanent error, SC is not making any more transfer attempts - '\
         'SM Deleted by SC Administration',
    73 : 'Permanent error, SC is not making any more transfer attempts - '\
         'SM does not exist',
    74 : 'Permanent error, SC is not making any more transfer attempts - '\
         'Reserved',
    80 : 'Permanent error, SC is not making any more transfer attempts - '\
         'SC specific',
    96 : 'Temporary error, SC is not making any more transfer attempts - '\
         'Congestion',
    97 : 'Temporary error, SC is not making any more transfer attempts - '\
         'SME busy',
    98 : 'Temporary error, SC is not making any more transfer attempts - '\
         'No response from SME',
    99 : 'Temporary error, SC is not making any more transfer attempts - '\
         'Service rejected',
    100 : 'Temporary error, SC is not making any more transfer attempts - '\
          'Quality of service not available',
    101 : 'Temporary error, SC is not making any more transfer attempts - '\
          'Error in SME',
    102 : 'Temporary error, SC is not making any more transfer attempts - '\
          'Reserved',
    112 : 'Temporary error, SC is not making any more transfer attempts - '\
          'Values specific to each SC',
    }


#------------------------------------------------------------------------------#
# TP‑User‑Data‑Length (TP‑UDL)
# TS 23.040, section 9.2.3.16
#------------------------------------------------------------------------------#
# number of septets (7-bit groups) in case of GSM 7-bit alphabet used in TP_UD
# number of bytes in case 8-bit or UCS2 alphabet in TP_UD
# in all cases, it includes the TP_UDH part if present


#------------------------------------------------------------------------------#
# TP‑Reply‑Path (TP‑RP)
# TS 23.040, section 9.2.3.17
#------------------------------------------------------------------------------#

_TP_RP_dict = {
    0 : 'TP Reply Path parameter is not set in this SMS SUBMIT/DELIVER',
    1 : 'TP Reply Path parameter is set in this SMS SUBMIT/DELIVER',
    }


#------------------------------------------------------------------------------#
# TP‑Command‑Type (TP‑CT)
# TS 23.040, section 9.2.3.19
#------------------------------------------------------------------------------#

_TP_CT_dict = {
    0 : 'Enquiry relating to previously submitted short message',
    1 : 'Cancel Status Report Request relating to previously '\
        'submitted short message',
    2 : 'Delete previously submitted Short Message', 
    3 : 'Enable Status Report Request relating to previously '\
        'submitted Short Message',
    224 : 'SC specific',
    }


#------------------------------------------------------------------------------#
# TP‑Failure‑Cause (TP‑FCS)
# TS 23.040, section 9.2.3.22
#------------------------------------------------------------------------------#

_TP_FCS_dict = {
	0x80 : 'TP-PID error : telematic interworking not supported',
    0x81 : 'TP-PID error : short message Type 0 not supported',
    0x82 : 'TP-PID error : cannot replace short message',
    0x83 : 'TP-PID error : reserved',
    0x8F : 'Unspecified TP-PID error',
	0x90 : 'TP-DCS error : data coding scheme (alphabet) not supported',
    0x91 : 'TP-DCS error : message class not supported',
    0x92 : 'TP-DCS error : reserved',
    0x9F : 'Unspecified TP-DCS error',
    0xA0 : 'TP-Command Error : command cannot be actioned',
    0xA1 : 'TP-Command Error : Command unsupported',
    0xA2 : 'TP-Command Error : reserved',
    0xAF : 'Unspecified TP-Command error',
    0xB0 : 'TPDU not supported',
    0xB1 : 'TPDU not supported : reserved',
    0xC0 : 'SC busy',
    0xC1 : 'No SC subscription',
    0xC2 : 'SC system failure',
    0xC3 : 'Invalid SME address',
    0xC4 : 'Destination SME barred',
    0xC5 : 'SM Rejected-Duplicate SM',
    0xC6 : 'TP-VPF not supported',
    0xC7 : 'TP-VP not supported',
    0xD0 : '(U)SIM SMS storage full',
    0xD1 : 'No SMS storage capability in (U)SIM',
    0xD2 : 'Error in MS',
    0xD3 : 'Memory Capacity Exceeded',
    0xD4 : '(U)SIM Application Toolkit Busy',
    0xD5 : '(U)SIM data download error',
    0xE0 : 'Values specific to an application',
    0xFF : 'Unspecified error cause',
    }


#------------------------------------------------------------------------------#
# TP‑User Data (TP‑UD)
# TS 23.040, section 9.2.3.24
#------------------------------------------------------------------------------#

_TP_UDHType_dict = {
    0x0 : 'Concatenated short messages, 8-bit reference number',
    0x1 : 'Special SMS Message Indication',
    0x2 : 'Reserved',
    0x3 : 'Value not used to avoid misinterpretation as <LF> character',
    0x4 : 'Application port addressing scheme, 8 bit address',
    0x5 : 'Application port addressing scheme, 16 bit address',
    0x6 : 'SMSC Control Parameters',
    0x7 : 'UDH Source Indicator',
    0x8 : 'Concatenated short message, 16-bit reference number',
    0x9 : 'Wireless Control Message Protocol',
    0x0A : 'Text Formatting',
    0x0B : 'Predefined Sound',
    0x0C : 'User Defined Sound (iMelody max 128 bytes)',
    0x0D : 'Predefined Animation',
    0x0E : 'Large Animation (16*16 times 4 = 32*4 =128 bytes)',
    0x0F : 'Small Animation (8*8 times 4 = 8*4 =32 bytes)',
    0x10 : 'Large Picture (32*32 = 128 bytes)',
    0x11 : 'Small Picture (16*16 = 32 bytes)',
    0x12 : 'Variable Picture',
    0x13 : 'User prompt indicator',
    0x14 : 'Extended Object',
    0x15 : 'Reused Extended Object',
    0x16 : 'Compression Control',
    0x17 : 'Object Distribution Indicator',
    0x18 : 'Standard WVG object',
    0x19 : 'Character Size WVG object',
    0x1A : 'Extended Object Data Request Command',
    0x20 : 'RFC 822 E-Mail Header',
    0x21 : 'Hyperlink format element',
    0x22 : 'Reply Address Element',
    0x23 : 'Enhanced Voice Mail Information',
    0x24 : 'National Language Single Shift',
    0x25 : 'National Language Locking Shift'
    }

for i in range(0x1B, 0x20):
    _TP_UDHType_dict[i] = 'Reserved for future EMS features'
for i in range(0x70, 0x80):
    _TP_UDHType_dict[i] = '(U)SIM Toolkit Security Headers'
for i in range(0x80, 0xA0):
    _TP_UDHType_dict[i] = 'SME to SME specific use'
for i in range(0xC0, 0xE0):
    _TP_UDHType_dict[i] = 'SC specific use'


# 9.2.3.24.1, Concatenated Short Messages

class TP_UDH_IE_0(Envelope):
    _GEN = (
        Uint8('MsgRef'),
        Uint8('MsgParts'),
        Uint8('MsgNum', val=1)
        )


# 9.2.3.24.2, Special SMS Message Indication

IE1MsgType_dict = {
    0 : 'Voice Message Waiting',
    1 : 'Fax Message Waiting',
    2 : 'Electronic Mail Message Waiting',
    3 : 'Extended Message Type Waiting',
    }

class TP_UDH_IE_1(Envelope):
    _GEN = (
        Uint('Store', bl=1),
        Uint('ProfileID', bl=2),
        Uint('ExtMsgType', bl=3, dic={0: 'No Extended Message', 1: 'Video Message Waiting'}),
        Uint('MsgType', bl=2, dic=IE1MsgType_dict),
        Uint8('MsgCnt')
        )


# 9.2.3.24.3, Application Port Addressing 8 bit address

class TP_UDH_IE_4(Envelope):
    _GEN = (
        Uint8('Dest'),
        Uint8('Origin')
        )


# 9.2.3.24.4, Application Port Addressing 16 bit address

class TP_UDH_IE_5(Envelope):
    _GEN = (
        Uint16('Dest'),
        Uint16('Origin')
        )


# 9.2.3.24.8, Concatenated short messages, 16-bit reference number

class TP_UDH_IE_8(Envelope):
    _GEN = (
        Uint16('MsgRef'),
        Uint8('MsgParts'),
        Uint8('MsgNum', val=1)
        )


# 9.2.3.24.10.1.1, Text Formatting

class TP_UDH_IE_A(Envelope):
    _GEN = (
        Uint8('StartPos'),
        Uint8('Len'),
        Uint8('FmtMode'),
        Uint8('Colour')
        )


# 9.2.3.24.10.1.13, Extended Object

IE14Type_dict = {
    0x00 : 'Predefined sound',
    0x01 : 'iMelody',
    0x02 : 'Black and white bitmap',
    0x03 : '2-bit greyscale bitmap',
    0x04 : '6-bit colour bitmap',
    0x05 : 'Predefined animation',
    0x06 : 'Black and white bitmap animation',
    0x07 : '2-bit greyscale bitmap animation',
    0x08 : '6-bit colour bitmap animation',
    0x09 : 'vCard',
    0x0A : 'vCalendar',
    0x0B : 'Standard WVG object',
    0x0C : 'Polyphonic melody',
    0xFF : 'Data Format Delivery Request'
    }

class TP_UDH_IE_14(Envelope):
    _GEN = (
        Uint8('Ref'),
        Uint16('Len'),
        Uint8('Ctrl'),
        Uint8('Type', dict=IE14Type_dict),
        Uint16('Pos'),
        Buf('Data', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(lambda: self[-1].get_len())
        self[-1].set_blauto(lambda: 8*self[1].get_val())


# 9.2.3.24.10.1.15, Compression Control

class TP_UDH_IE_16(Envelope):
    _GEN = (
        Uint('Param', bl=4),
        Uint('Algo', bl=4, dic={0: 'LZSS'}),
        Uint16('Len'),
        Buf('Data', rep=REPR_HEX)
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_valauto(lambda: self[-1].get_len())
        self[-1].set_blauto(lambda: 8*self[2].get_val())


class TP_UDH_IE(Envelope):
    _GEN = (
        Uint8('T', dic=_TP_UDHType_dict),
        Uint8('L'),
        Alt('V', GEN={
            0x00 : TP_UDH_IE_0(),
            0x01 : TP_UDH_IE_1(),
            0x04 : TP_UDH_IE_4(),
            0x05 : TP_UDH_IE_5(),
            0x08 : TP_UDH_IE_8(),
            0x0A : TP_UDH_IE_A(),
            0x14 : TP_UDH_IE_14(),
            0x16 : TP_UDH_IE_16()
            },
            DEFAULT=Buf('raw', rep=REPR_HEX),
            sel=lambda self: self.get_env()[0].get_val()),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[1].set_valauto(self[2].get_len)
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        self[1]._from_char(char)
        char_lb = char._len_bit
        char._len_bit = char._cur + (self[1].get_val()<<3)
        self[2]._from_char(char)
        if char._cur < char._len_bit:
            # length was longer than the expected structure
            self.append( Buf('unk', rep=REPR_HEX) )
            self[3]._from_char(char)
        char._len_bit = char_lb


class TP_UDH(Envelope):
    _GEN = (
        Uint8('UDHL'),
        Sequence('UDH', GEN=TP_UDH_IE('UDHIE')),
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len())
        self[1].set_blauto(lambda: self[0].get_val()<<3)


class BufUD(Buf):
    
    # default encoding, required in SMS REPORT without TP-DCS
    DEFAULT_DCS = DCS_7B  
    # indicator for GSM 7b encoding length
    _ENC_BL = 0
    
    def set_val(self, val):
        if val is None:
            self._val = None
        elif isinstance(val, bytes_types):
            Buf.set_val(self, val)
            if self.get_dcs() == DCS_7B:
                self._ENC_BL = 8*len(val)
            else:
                self._ENC_BL = 0
        else:
            self.encode(val)
    
    def get_dcs(self):
        try:
            dcs = self.get_env().get_env()['TP_DCS']
        except Exception:
            return self.DEFAULT_DCS
        else:
            grp, cs = dcs['Group'](), dcs['Charset']()
            if grp in (0, 1, 4, 5, 15):
                if cs == 0:
                    return DCS_7B
                elif cs == 2:
                    return DCS_UCS
            elif grp in (12, 13) and cs in (0, 2):
                return DCS_7B
            elif grp == 14 and cs in (0, 2):
                return DCS_UCS
            return DCS_8B
    
    def get_dcs7b_off(self):
        try:
            udh = self.get_env()['UDH']
        except Exception:
            return 0
        else:
            if udh.get_trans():
                return 0
            else:
                len_udh = 8 + (udh[0].get_val() << 3)
                return (7 - (len_udh%7)) % 7
    
    def encode(self, val):
        dcs = self.get_dcs()
        if dcs == DCS_7B:
            enc, cnt = encode_7b(val, self.get_dcs7b_off())
            self.set_val(enc)
            self._ENC_BL = 7*cnt
        elif dcs == DCS_UCS:
            self.set_val(val.encode('utf-16-be'))
            self._ENC_BL = 0
        else:
            self.set_val(val)
            self._ENC_BL = 0
    
    def decode(self):
        dcs = self.get_dcs()
        if dcs == DCS_7B:
            try:
                udhbl = self.get_env()['UDH'].get_bl()
            except Exception:
                udhbl = 0
            if (udhbl + self._ENC_BL) % 8 == 1:
                return decode_7b(self.get_val(), self.get_dcs7b_off())[:-1]
            else:
                return decode_7b(self.get_val(), self.get_dcs7b_off())
        elif dcs == DCS_UCS:
            return str(self.get_val(), 'utf-16-be')
        else:
            return self.get_val()
    
    def repr(self):
        dcs = self.get_dcs()
        if dcs == DCS_7B:
            return '<%s : %s>' % (self._name, self.decode())
        elif dcs == DCS_UCS:
            return '<%s : %s>' % (self._name, self.decode())
        else:
            return Buf.repr(self)
    
    __repr__ = repr


class TP_UD(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint8('UDL'),
        TP_UDH('UDH'),
        BufUD('UD')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self._set_udl())
        self[1].set_transauto(lambda: True if self.get_udhi() == 0 else False)
    
    def _set_udl(self):
        if self.get_dcs() == DCS_7B:
            # count number of septets:
            # UDH should be a round number of septet (thanks to the fill bits)
            # UD should have a non-null ENC_BL after encoding the text
            return (self[1].get_bl() + self[2]._ENC_BL) // 7
        else:
            return self[1].get_len() + self[2].get_len()
    
    def _from_char(self, char):
        if not self.get_trans():
            dcs = self.get_dcs()
            self[0]._from_char(char)
            ccur, clen, charnum = char._cur, char._len_bit, self[0]()
            self[1]._from_char(char)
            if dcs == DCS_7B:
                char._len_bit = ccur + 7*charnum
                lastbit, self[2]._ENC_BL = char._len_bit%8, (char._len_bit-char._cur)
                if lastbit:
                    char._len_bit += 8-lastbit
                self[2]._from_char(char)
            else:
                char._len_bit = ccur + 8*charnum
                self[2]._ENC_BL = 0
                self[2]._from_char(char)
            char._len_bit = clen
    
    def get_udhi(self):
        try:
            udhi = self.get_env()['TP_UDHI']
        except Exception:
            return 0
        else:
            return udhi()
    
    def get_dcs(self):
        try:
            dcs = self.get_env()['TP_DCS']
        except Exception:
            return self[2].DEFAULT_DCS
        else:
            grp, cs = dcs['Group'](), dcs['Charset']()
            if grp in (0, 1, 4, 5, 15):
                if cs == 0:
                    return DCS_7B
                elif cs == 2:
                    return DCS_UCS
            elif grp in (12, 13) and cs in (0, 2):
                return DCS_7B
            elif grp == 14 and cs in (0, 2):
                return DCS_UCS
            return DCS_8B


#------------------------------------------------------------------------------#
# TP‑Command‑Data (TP‑CD)
# TS 23.040, section 9.2.3.21
#------------------------------------------------------------------------------#

class TP_CD(Envelope):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint8('CDL'),
        TP_UDH('UDH'),
        Buf('CD')
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[0].set_valauto(lambda: self[1].get_len() + self[2].get_len())
        self[1].set_transauto(lambda: True if self.get_udhi() == 0 else False)
        self[2].set_blauto(lambda: self[0].get_val() - self[1].get_len())

    def get_udhi(self):
        try:
            udhi = self.get_env()['TP_UDHI']
        except Exception:
            return 0
        else:
            return udhi()


#------------------------------------------------------------------------------#
# TP‑Status‑Report‑Qualifier (TP‑SRQ)
# TS 23.040, section 9.2.3.26
#------------------------------------------------------------------------------#

_TP_SRQ_dict = {
    0 : 'The SMS‑STATUS‑REPORT is the result of a SMS‑SUBMIT',
    1 : 'The SMS‑STATUS‑REPORT is the result of an SMS‑COMMAND'
    }


#------------------------------------------------------------------------------#
# TP‑Parameter‑Indicator (TP‑PI)
# TS 23.040, section 9.2.3.27
#------------------------------------------------------------------------------#

class TP_PI(Envelope):
    _GEN = (
        Uint('Ext', bl=1),
        Uint('reserved', bl=4),
        Uint('TP_UDL', bl=1),
        Uint('TP_DCS', bl=1),
        Uint('TP_PID', bl=1)
        )


#------------------------------------------------------------------------------#
# SMS‑DELIVER type
# TS 23.040, section 9.2.2.1
#------------------------------------------------------------------------------#
# Net -> UE

class SMS_DELIVER(SMS_TP):
    _GEN = (
        Uint('TP_RP', bl=1, dic=_TP_RP_dict),
        Uint('TP_UDHI', desc='UDH Indicator', bl=1),
        Uint('TP_SRI', bl=1, dic=_TP_SRI_dict),
        Uint('spare', bl=1),
        Uint('TP_LP', desc='Loop Prevention', bl=1),
        Uint('TP_MMS', desc='no More Message to Send', bl=1),
        Uint('TP_MTI', val=0, bl=2, dic=_TP_MTI_MT_dict),
        TP_OA(desc='Originating Address'),
        TP_PID(),
        TP_DCS(),
        TP_SCTS(),
        TP_UD()
        )


#------------------------------------------------------------------------------#
# SMS‑DELIVER‑REPORT for RP‑ERROR
# TS 23.040, section 9.2.2.1a (i)
#------------------------------------------------------------------------------#
# UE -> Net

class SMS_DELIVER_REPORT_RP_ERROR(SMS_TP):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('spare', bl=1),
        Uint('TP_UDHI', desc='UDH Indicator', bl=1),
        Uint('spare', bl=4),
        Uint('TP_MTI', val=0, bl=2, dic=_TP_MTI_MO_dict),
        Uint8('TP_FCS', dic=_TP_FCS_dict),
        TP_PI(),
        TP_PID(),
        TP_DCS(),
        TP_UD()
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['TP_PID'].set_transauto(lambda: False if self['TP_PI']['TP_PID']() else True)
        self['TP_DCS'].set_transauto(lambda: False if self['TP_PI']['TP_DCS']() else True)
        self['TP_UD'].set_transauto(lambda: False if self['TP_PI']['TP_UDL']() else True)


#------------------------------------------------------------------------------#
# SMS‑DELIVER‑REPORT for RP‑ACK
# TS 23.040, section 9.2.2.1a (ii)
#------------------------------------------------------------------------------#
# UE -> Net

class SMS_DELIVER_REPORT_RP_ACK(SMS_TP):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('spare', bl=1),
        Uint('TP_UDHI', desc='UDH Indicator', bl=1),
        Uint('spare', bl=4),
        Uint('TP_MTI', val=0, bl=2, dic=_TP_MTI_MO_dict),
        TP_PI(),
        TP_PID(),
        TP_DCS(),
        TP_UD()
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['TP_PID'].set_transauto(lambda: False if self['TP_PI']['TP_PID']() else True)
        self['TP_DCS'].set_transauto(lambda: False if self['TP_PI']['TP_DCS']() else True)
        self['TP_UD'].set_transauto(lambda: False if self['TP_PI']['TP_UDL']() else True)


#------------------------------------------------------------------------------#
# SMS‑SUBMIT type
# TS 23.040, section 9.2.2.2
#------------------------------------------------------------------------------#
# UE -> Net

class SMS_SUBMIT(SMS_TP):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('TP_RP', bl=1, dic=_TP_RP_dict),
        Uint('TP_UDHI', desc='UDH Indicator', bl=1),
        Uint('TP_SRR', bl=1, dic=_TP_SRR_dict),
        Uint('TP_VPF', bl=2, dic=_TP_VPF_dict),
        Uint('TP_RD', desc='Reject Duplicates', bl=1),
        Uint('TP_MTI', val=1, bl=2, dic=_TP_MTI_MT_dict),
        Uint8('TP_MR', desc='Message Reference'),
        TP_DA(desc='Destination Address'),
        TP_PID(),
        TP_DCS(),
        # TP_VP: None / Uint8(TP_VPRel) / TP_VP() / TP_VPe(), depends on TP_VPF
        Uint8('TP_VP', dic=_TP_VPRel_dict),
        TP_VP(),
        TP_VPe(),
        TP_UD()
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[10].set_transauto(lambda: False if self[3]() == 2 else True)
        self[11].set_transauto(lambda: False if self[3]() == 3 else True)
        self[12].set_transauto(lambda: False if self[3]() == 1 else True)


#------------------------------------------------------------------------------#
# SMS‑SUBMIT‑REPORT for RP‑ERROR
# TS 23.040, section 9.2.2.2a (i)
#------------------------------------------------------------------------------#
# Net -> UE

class SMS_SUBMIT_REPORT_RP_ERROR(SMS_TP):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('spare', bl=1),
        Uint('TP_UDHI', desc='UDH Indicator', bl=1),
        Uint('spare', bl=4),
        Uint('TP_MTI', val=1, bl=2, dic=_TP_MTI_MT_dict),
        Uint8('TP_FCS', dic=_TP_FCS_dict),
        TP_PI(),
        TP_SCTS(),
        TP_PID(),
        TP_DCS(),
        TP_UD()
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['TP_PID'].set_transauto(lambda: False if self['TP_PI']['TP_PID']() else True)
        self['TP_DCS'].set_transauto(lambda: False if self['TP_PI']['TP_DCS']() else True)
        self['TP_UD'].set_transauto(lambda: False if self['TP_PI']['TP_UDL']() else True)


#------------------------------------------------------------------------------#
# SMS‑SUBMIT‑REPORT for RP‑ACK
# TS 23.040, section 9.2.2.2a (ii)
#------------------------------------------------------------------------------#
# Net -> UE

class SMS_SUBMIT_REPORT_RP_ACK(SMS_TP):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('spare', bl=1),
        Uint('TP_UDHI', desc='UDH Indicator', bl=1),
        Uint('spare', bl=4),
        Uint('TP_MTI', val=1, bl=2, dic=_TP_MTI_MO_dict),
        TP_PI(),
        TP_SCTS(),
        TP_PID(),
        TP_DCS(),
        TP_UD()
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self['TP_PID'].set_transauto(lambda: False if self['TP_PI']['TP_PID']() else True)
        self['TP_DCS'].set_transauto(lambda: False if self['TP_PI']['TP_DCS']() else True)
        self['TP_UD'].set_transauto(lambda: False if self['TP_PI']['TP_UDL']() else True)


#------------------------------------------------------------------------------#
# SMS‑STATUS‑REPORT type
# TS 23.040, section 9.2.2.3
#------------------------------------------------------------------------------#
# Net -> UE

class SMS_STATUS_REPORT(SMS_TP):
    ENV_SEL_TRANS = False
    _GEN = (
        Uint('spare', bl=1),
        Uint('TP_UDHI', desc='UDH Indicator', bl=1),
        Uint('TP_SRQ', bl=1, dic=_TP_SRQ_dict),
        Uint('spare', bl=1),
        Uint('TP_LP', desc='Loop Prevention', bl=1),
        Uint('TP_MMS', desc='no More Message to Send', bl=1),
        Uint('TP_MTI', val=2, bl=2, dic=_TP_MTI_MT_dict),
        Uint8('TP_MR', desc='Message Reference'),
        TP_RA(desc='Recipient Address'),
        TP_SCTS(),
        TP_DT(),
        Uint8('TP_ST', dic=_TP_ST_dict),
        TP_PI(), # may be set to transparent in case none of the following fields are present
        TP_PID(),
        TP_DCS(),
        TP_UD()
        )
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        # warning: TP-PI may be transparent
        self['TP_PID'].set_transauto(lambda: False if not self['TP_PI'].get_trans() and self['TP_PI']['TP_PID']() else True)
        self['TP_DCS'].set_transauto(lambda: False if not self['TP_PI'].get_trans() and self['TP_PI']['TP_DCS']() else True)
        self['TP_UD'].set_transauto(lambda: False if not self['TP_PI'].get_trans() and self['TP_PI']['TP_UDL']() else True)
    
    def _from_char(self, char):
        if not self.get_trans():
            # warning: TP_PI may be transparent
            self[-4].set_trans(True)
            SMS_TP._from_char(self, char)
            if char.len_bit() >= 8:
                self[-4].set_trans(False)
                self[-4]._from_char(char)
                self[-3]._from_char(char)
                self[-2]._from_char(char)
                self[-1]._from_char(char)


#------------------------------------------------------------------------------#
# SMS‑COMMAND type
# TS 23.040, section 9.2.2.4
#------------------------------------------------------------------------------#
# UE -> Net

class SMS_COMMAND(SMS_TP):
    _GEN = (
        Uint('spare', bl=1),
        Uint('TP_UDHI', desc='UDH Indicator', bl=1),
        Uint('TP_SRR', bl=1, dic=_TP_SRR_dict),
        Uint('spare', bl=3),
        Uint('TP_MTI', val=2, bl=2, dic=_TP_MTI_MO_dict),
        Uint8('TP_MR', desc='Message Reference'),
        TP_PID(),
        Uint8('TP_CT', dic=_TP_CT_dict),
        Uint8('TP_MN', desc='Message Number'),
        TP_DA(desc='Destination Address'),
        TP_CD()
        )

