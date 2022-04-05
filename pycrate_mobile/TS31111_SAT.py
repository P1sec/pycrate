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
# * File Name : pycrate_mobile/TS31111_SAT.py
# * Created : 2019-07-19
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/
#
# Implement parts of 3GPP TS 31.111
# Universal Subscriber Identity Module (USIM) Application Toolkit (USAT)
#
# also use parts of ETSI TS 101.220 (numbering) and 102.223 (CAT)

from pycrate_core.base  import *
from pycrate_core.elt   import *
from pycrate_core.repr  import *
from pycrate_core.utils import PycrateErr


# well known TAR (Toolkit Application Reference)

TAR_dict = {
    # ETSI TS 101.220
    0x000000: 'Issuer Security Domain',
    0xB20100: 'Issuer Security Domain',
    0xB00000: 'UICC Shared File System',
    0xB00001: 'ADF Remote File Management',
    0xB20101: 'SCWS (OMA)',
    0xB20102: 'SCWS administrative agent Application (OMA)',
    0xB20200: 'Multiplexing Application (ETSI)',
    0xB20201: 'Controlling Authority Security Domain (GP)',
    0xB20202: 'OMA BCAST Smartcard-Centric Audience Measurement ',
    0xB20203: 'OMA DM LWM2M UICC Application',
    # SIM Alliance SAT browser
    0x534054: 'SAT browser',
    0x505348: 'SAT browser low priority Push' 
    }

# ETSI TS 101.220
for i in range(0xB00002, 0xB00010):
    TAR_dict[i] = 'UICC Shared File System'
for i in range(0xB00010, 0xB00020):
    TAR_dict[i] = 'SIM File System'
for i in range(0xB00020, 0xB00120):
    TAR_dict[i] = 'ADF Remote File Management'
for i in range(0xB00120, 0xB00130):
    TAR_dict[i] = 'UICC Shared File System'
for i in range(0xB00130, 0xB00140):
    TAR_dict[i] = 'SIM File System'
for i in range(0xB00140, 0xB00200):
    TAR_dict[i] = 'ADF Remote File Management'
for i in range(0xB10000, 0xB10005):
    TAR_dict[i] = 'Visa Mobile Payment Toolkit Application'
for i in range(0xB20000, 0xB20100):
    TAR_dict[i] = 'USAT Interpreter Application'
for i in range(0xB20210, 0xB20220):
    TAR_dict[i] = 'Security Domain with Authorized Management privilege (EMVCo)'
for i in range(0xB20220, 0xB20230):
    TAR_dict[i] = 'Security Domain with Delegated Management privilege (EMVCo)'
for i in range(0xBFFF00, 0xC00000):
    TAR_dict[i] = 'Proprietary Toolkit Application'


# section 9, tag values

BERTag_dict = {
    # ETSI 101.220
    0x31 : 'Card Service Data',
    0x73 : 'Card Capabilities',
    0x61 : 'Application Template',
    0x62 : 'FCP Template',
    0x7B : 'Security Environment Template',
    0xCF : 'reserved for proprietary use',
    0xD3 : 'Menu Selection',
    0xD4 : 'Call Control',
    0xD6 : 'Event Download',
    0xD7 : 'Timer Expiration',
    0xD8 : 'reserved for intra-UICC communication',
    0xDA : 'MMS Transfer status',
    0xDB : 'MMS notification download',
    0xDC : 'Terminal application',
    0xDE : 'Envelope Container',
    0xE0 : 'reserved for 3GPP',
    0xE1 : 'reserved for 3GPP',
    0xE2 : 'reserved for 3GPP',
    0xE3 : 'reserved for 3GPP',
    0xE4 : 'reserved for GSMA',
    0x01 : 'reserved for OMA SCWS',
    0x81 : 'reserved for OMA SCWS and GlobalPlatform Card Specification',
    0xA2 : 'reserved for GSMA RSP',
    0xAA : 'Command Scripting Template for definite length coding',
    0xAB : 'Response Scripting Template for definite length coding',
    0xAC : 'Command Scripting Template for indefinite length coding',
    0xAD : 'Response Scripting Template for indefinite length coding',
    # ETSI 102.223
    0xD0 : 'Proactive UICC command',
    # 3GPP 31.111
    0xD1 : 'SMS-PP download',
    0xD2 : 'Cell Broadcast download',
    0xD5 : 'MO Short message control',
    0xD9 : 'USSD download',
    0xDD : 'Geographical Location Reporting',
    0xDF : 'ProSe Report'
    }


CompTag_dict = {
    # ETSI 101.220
    0x01 : 'Command details',
    0x02 : 'Device identity',
    0x03 : 'Result',
    0x04 : 'Duration',
    0x05 : 'Alpha identifier',
    0x06 : 'Address',
    0x07 : 'Capability configuration parameters',
    0x08 : 'Subaddress',
    0x0D : 'Text string',
    0x0E : 'Tone / eCAT client profile',
    0x0F : 'Item / eCAT client identity',
    0x10 : 'Item identifier / Encapsulated envelope type',
    0x11 : 'Response length / Call control result',
    0x12 : 'File List / CAT service list',
    0x13 : 'Location information',
    0x14 : 'IMEI',
    0x15 : 'Help request',
    0x16 : 'Network Measurement Results',
    0x17 : 'Default Text',
    0x18 : 'Items Next Action Indicator',
    0x19 : 'Event list',
    0x1B : 'Location status',
    0x1C : 'Transaction identifier',
    0x1E : 'Icon identifier',
    0x1F : 'Item Icon identifier list',
    0x20 : 'Card reader status',
    0x21 : 'Card ATR / eCAT sequence number',
    0x22 : 'C-APDU / Encrypted TLV',
    0x23 : 'R-APDU / SA template',
    0x24 : 'Timer identifier',
    0x25 : 'Timer value',
    0x26 : 'Date-Time and Time zone',
    0x27 : 'Call control requested action',
    0x28 : 'AT Command',
    0x29 : 'AT Response',
    0x2B : 'Immediate response',
    0x2C : 'DTMF string',
    0x2D : 'Language',
    0x2F : 'AID',
    0x30 : 'Browser Identity',
    0x31 : 'URL / IMS URI',
    0x32 : 'Bearer',
    0x33 : 'Provisioning Reference File',
    0x34 : 'Browser Termination Cause / Supported Radio Access Technologies',
    0x35 : 'Bearer description',
    0x36 : 'Channel data',
    0x37 : 'Channel data length',
    0x38 : 'Channel status',
    0x39 : 'Buffer size',
    0x3A : 'Card reader identifier / REFRESH Enforcement Policy',
    0x3B : 'File Update Information / Application specific refresh data',
    0x3C : 'UICC/terminal interface transport level',
    0x3D : 'Not used',
    0x3E : 'Other address (data destination address)',
    0x3F : 'Access Technology',
    0x40 : 'Display parameters / DNS server address',
    0x41 : 'Service Record',
    0x42 : 'Device Filter',
    0x43 : 'Service Search',
    0x44 : 'Attribute information',
    0x45 : 'Service Availability',
    0x46 : '3GPP2 - tag 1',
    0x47 : 'Network Access Name',
    0x48 : '3GPP2 - tag 2',
    0x49 : 'Remote Entity Address',
    0x4C : 'RFU',
    0x4D : 'RFU',
    0x4E : 'RFU',
    0x4F : 'RFU',
    0x50 : 'Text attribute',
    0x51 : 'Item text attribute list',
    0x53 : 'Contactless state request',
    0x54 : 'Contactless functionality state',
    0x58 : 'RFU',
    0x59 : 'RFU',
    0x5A : 'RFU',
    0x5B : 'RFU',
    0x5C : 'RFU',
    0x5D : 'RFU',
    0x5E : 'RFU',
    0x5F : 'RFU',
    0x60 : 'MAC',
    0x61 : '3GPP2 - Tag 3',
    0x62 : 'IMEISV',
    0x63 : 'Battery state',
    0x64 : 'Browsing status',
    0x65 : 'Network Search Mode',
    0x66 : 'Frame Layout',
    0x67 : 'Frames Information / Profile ID',
    0x68 : 'Frame identifier',
    0x6A : 'Multimedia Message Reference',
    0x6B : 'Multimedia Message Identifier',
    0x6C : 'Multimedia Message Transfer Status',
    0x6D : '3GPP2 - tag 4',
    0x6E : 'Multimedia Message Content Identifier',
    0x6F : 'Multimedia Message Notification',
    0x70 : 'Last Envelope',
    0x71 : 'Registry application data',
    0x7A : 'Broadcast Network Information / Extended registry application data',
    0x7B : 'ACTIVATE descriptor',
    # 3GPP 31.111
    0x09 : '3GPP - SS string / BSSID / PLMN ID',
    0x0A : '3GPP - USSD string / IP Address List / HESSID',
    0x0B : '3GPP - SMS TPDU / Surrounding macrocells',
    0x0C : '3GPP - Cell Broadcast page',
    0x1A : '3GPP - Cause',
    0x1D : '3GPP - BCCH channel list / Data connection status',
    0x2A : '3GPP - BC Repeat Indicator / Data connection type',
    0x2E : '3GPP - Timing Advance / (E)SM cause',
    0x4A : '3GPP - I-WLAN Identifier / SSID',
    0x4B : '3GPP - (I-)WLAN Access Status',
    0x52 : '3GPP - PDP context Activation parameter',
    0x55 : '3GPP - CSG cell selection status / IMS call disconnection cause',
    0x56 : '3GPP - CSG ID',
    0x57 : '3GPP - HNB name / Extended rejection cause code',
    0x69 : '3GPP - UTRAN/E-UTRAN Measurement Qualifier',
    0x72 : '3GPP - PLMNwAcT List',
    0x73 : '3GPP - Routing Area Information / URI truncated',
    0x74 : '3GPP - Update/Attach Type / ProSe Report Data',
    0x75 : '3GPP - Rejection Cause Code',
    0x76 : '3GPP - Geographical Location Parameters / IARI',
    0x77 : '3GPP - GAD Shapes / IMPU list',
    0x78 : '3GPP - NMEA sentence / IMS Status Code',
    0x79 : '3GPP - PLMN List / E-UTRAN Inter-frequency Network Measurement Results',
    0x7C : '3GPP - EPS PDN connection activation parameters',
    0x7D : '3GPP - Tracking Area Identification',
    0x7E : '3GPP - CSG ID list / Media type',
    }


# BER-TLV crappy handler

class BERTag(Envelope):
    # TODO
    pass


class BERLen(Envelope):
    
    DEFAULT_VAL = 0
    
    MAXLEN = 65536
    
    _GEN = (
        Uint('Form', bl=1, dic={0: 'short', 1: 'long'}),
        Uint('Val', bl=7)
        )
    
    def set_val(self, val):
        if val > 127:
            # long format
            self[0].set_val(1)
            bl = val.bit_length()
            if bl % 8:
                l = 1 + (bl>>3)
            else:
                l = bl>>3
            self[1]._name = 'Len'
            self[1].set_val(l)
            self.append(Uint('Val', val=val, bl=l<<3))
        else:
            # short format
            self[0].set_val(0)
            self[1].set_val(val)
    
    def set_valauto(self, valauto=None):
        if valauto is None:
            try:
                del self._valauto
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not callable(valauto):
                raise(EltErr('{0} [set_valauto]: valauto type is {1}, expecting callable'\
                      .format(self._name, type(valauto).__name__)))
            self._valauto = valauto
    
    def get_val(self):
        # follow the value resolution order:
        # 1) raw value
        if self['Val']._val is not None:
            return self['Val']._val
        
        # 2) value automation
        elif self._valauto is not None:
            val = self._valauto()
            self.set_val(val)
            return val
        
        # 3) default value
        else:
            return self.DEFAULT_VAL
    
    __call__ = get_val
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        if self[0]():
            # long format
            self[1]._name = 'Len'
            self[1]._from_char(char)
            self.append(Uint('Val', bl=self[1]()<<3))
            self[2]._from_char(char)
            val = self[2]()
            if val > self.MAXLEN:
                raise(PycrateErr('Length too long, %i' % self[2]()))
            elif val == 0:
                raise(PycrateErr('Undefinite length'))
        else:
            # short format
            self[1]._from_char(char)



# COMPREHENSION-TLV crappy handler

# TS 101.220, section 7.1.1

CR_dict = {
    0: 'Comprehension not required',
    1: 'Comprehension required'
    }


class COMPTagExt(Envelope):
    _GEN = (
        Uint('CR', bl=1, dic=CR_dict),
        Uint('Val', bl=15, dic=CompTag_dict)
        )


class COMPTag(Envelope):
    
    # this is to force the 3 bytes format, even for low tag value
    FORCE_FMT_3B  = False
    
    ENV_SEL_TRANS = False
    
    _GEN = (
        Uint('CR', bl=1, dic=CR_dict),
        Uint('Val', bl=7, dic=CompTag_dict),
        COMPTagExt()
        )
    
    def __init__(self, *args, **kwargs):
        Envelope.__init__(self, *args, **kwargs)
        self[2].set_transauto(lambda: False if self[0].get_val() == 0 and self[1].get_val() == 0x7f else True)
    
    def set_val(self, val):
        if self.FORCE_FMT_3B \
        or (isinstance(val, (tuple, list)) and len(val) > 1 and val[1] > 0x7e) \
        or (isinstance(val, dict) and 'Val' in val and val['Val'] > 0x7e):
            self[0].set_val(0)
            self[1].set_val(0x7f)
            self[2].set_val(val)
        else:
            Envelope.set_val(self, val)
    
    def get_val(self):
        if not self[2].get_trans():
            return self[2].get_val()
        else:
            return Envelope.get_val(self)


# TS 101.220, section 7.1.2

class COMPLen(Envelope):
    
    DEFAULT_VAL = 0
    
    _GEN = (
        Uint8('Val'),
        Uint('ValExt', bl=8)
        )
    
    def __init__(self, *args, **kwargs):
        self[1].set_transauto(lambda: False if self[0].get_val() in (0x81, 0x82, 0x83) else True)
    
    def set_val(self, val):
        if 0 <= val < 0x80:
            self[0].set_val(val)
        elif 0x80 <= val < 0x100:
            self[0].set_val(0x81)
            self[1].set_bl(8)
            self[1].set_val(val)
        elif 0x100 <= val < 0x10000:
            self[0].set_val(0x82)
            self[1].set_bl(16)
            self[1].set_val(val)
        elif 0x10000 <= val < 0x1000000:
            self[0].set_val(0x83)
            self[1].set_bl(24)
            self[1].set_val(val)
        else:
            raise(PycrateErr('invalid length'))
    
    
    def set_valauto(self, valauto=None):
        if valauto is None:
            try:
                del self._valauto
            except Exception:
                pass
        else:
            if self._SAFE_STAT and not callable(valauto):
                raise(EltErr('{0} [set_valauto]: valauto type is {1}, expecting callable'\
                      .format(self._name, type(valauto).__name__)))
            self._valauto = valauto
    
    def get_val(self):
        # follow the value resolution order:
        # 1) raw value
        if self[0]._val is not None:
            if self[0]._val < 0x80:
                return self[0]._val
            elif self[0]._val in (0x81, 0x82, 0x83):
                return self[1]._val
        
        # 2) value automation
        elif self._valauto is not None:
            val = self._valauto()
            self.set_val(val)
            return val
        
        # 3) default value
        else:
            return self.DEFAULT_VAL
    
    def _from_char(self, char):
        if self.get_trans():
            return
        self[0]._from_char(char)
        v = self[0].get_val()
        if v == 0x82:
            self[1].set_bl(8)
            self[1]._from_char(char)
        elif v == 0x83:
            self[1].set_bl(16)
            self[1]._from_char(char)
        elif v == 0x84:
            self[1].set_bl(24)
            self[1]._from_char(char)


