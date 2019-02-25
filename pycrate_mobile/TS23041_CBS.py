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
# * File Name : pycrate_mobile/TS23041_CBS.py
# * Created : 2018-02-22
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'CBSWarningType_dict',
    'CBSWarningType',
    'CBSWarningSecurityInfo',
    'CBS_MessageId_dict',
    'encode_cbs_pages'
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 23.041: Cell Broadcast Service
# release 13 (d30)
#------------------------------------------------------------------------------#

from struct import pack, unpack

from pycrate_core.elt  import *
from pycrate_core.base import *
from .TS23038          import *
from .TS23040_SMS      import TP_SCTS


#------------------------------------------------------------------------------#
# Warning Type
# TS 23.041, section 9.3.24
#------------------------------------------------------------------------------#

CBSWarningType_dict = {
    0 : 'Earthquake',
    1 : 'Tsunami',
    2 : 'Earthquake and Tsunami',
    3 : 'Test',
    4 : 'Other'
    #5-0x7f: future use
    }

class CBSWarningType(Envelope):
    _GEN = (
        Uint('Value', bl=7, dic=CBSWarningType_dict),
        Uint('EmergencyUserAlert', bl=1),
        Uint('Popup', bl=1),
        Uint('pad', bl=7, rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Warning-Security-Information
# TS 23.041, section 9.3.25
#------------------------------------------------------------------------------#

class CBSWarningSecurityInfo(Envelope):
    _GEN = (
        TP_SCTS(),
        Buf('DigitalSignature', bl=344, rep=REPR_HEX)
        )


#------------------------------------------------------------------------------#
# Message Identifier
# TS 23.041, section 9.4.1.2.2
#------------------------------------------------------------------------------#

CBS_MessageId_dict = {
    #0-999: GSMA reserved
    1000 : 'LCS CBS for E-OTD Assistance Data',
    1001 : 'LCS CBS for GPS Ephemeris and Clock Correction Data',
    1002 : 'LCS CBS for GPS Ephemeris and Clock Correction Data',
    1003 : 'LCS CBS for GPS Almanac and Other Data',
    #1004-4095: future use
    #4096-4223: reserved for unsecure SIM download (!)
    #4224-4351: reserved for secured SIM download
    4352: 'ETWS CBS for earthquake warning',
    4353: 'ETWS CBS for tsunami warning',
    4354: 'ETWS CBS for earthquake and tsunami combined warning',
    4355: 'ETWS CBS for test', # silently discarded by the UE
    4356: 'ETWS CBS related to other emergency types',
    #4357-4369: future use
    4370: 'CMAS CBS for CMAS Presidential Level Alerts',
    #     also EU-Alert Level 1 / Korean Public Alert System (KPAS) Class 0, not settable by MMI
    4371: 'CMAS CBS for CMAS Extreme Alerts with Severity of Extreme, Urgency of Immediate, and Certainty of Observed',
    #     also EU-Alert Level 2 / Korean Public Alert System (KPAS) Class 1
    4372: 'CMAS CBS for CMAS Extreme Alerts with Severity of Extreme, Urgency of Immediate, and Certainty of Likely',
    #     also EU-Alert Level 2 / Korean Public Alert System (KPAS) Class 1
    4373: 'CMAS CBS for CMAS Severe Alerts with Severity of Extreme, Urgency of Expected, and Certainty of Observed',
    #     also EU-Alert Level 3 / Korean Public Alert System (KPAS) Class 1
    4374: 'CMAS CBS for CMAS Severe Alerts with Severity of Extreme, Urgency of Expected, and Certainty of Likely',
    #     also EU-Alert Level 3 / Korean Public Alert System (KPAS) Class 1
    4375: 'CMAS CBS for CMAS Severe Alerts with Severity of Severe, Urgency of Immediate, and Certainty of Observed',
    #     also EU-Alert Level 3 / Korean Public Alert System (KPAS) Class 1
    4376: 'CMAS CBS for CMAS Severe Alerts with Severity of Severe, Urgency of Immediate, and Certainty of Likely',
    #     also EU-Alert Level 3 / Korean Public Alert System (KPAS) Class 1
    4377: 'CMAS CBS for CMAS Severe Alerts with Severity of Severe, Urgency of Expected, and Certainty of Observed',
    #     also EU-Alert Level 3 / Korean Public Alert System (KPAS) Class 1
    4378: 'CMAS CBS for CMAS Severe Alerts with Severity of Severe, Urgency of Expected, and Certainty of Likely',
    #     also EU-Alert Level 3 / Korean Public Alert System (KPAS) Class 1
    4379: 'CMAS CBS for Child Abduction Emergency (Amber Alert)',
    #     also EU-Amber / Korean Public Alert System (KPAS) Class 1
    4380: 'CMAS CBS for the Required Monthly Test',
    4381: 'CMAS CBS for CMAS Exercise',
    4382: 'CMAS CBS for operator defined use',
    4383: 'CMAS CBS for CMAS Presidential Level Alerts for additional languages',
    #     also EU-Alert Level 1 / Korean Public Alert System (KPAS) Class 0, not settable by MMI
    4384: 'CMAS CBS for CMAS Extreme Alerts with Severity of Extreme, Urgency of Immediate, and Certainty of Observed for additional languages',
    #     also EU-Alert Level 2 / Korean Public Alert System (KPAS) Class 1
    4385: 'CMAS CBS for CMAS Extreme Alerts with Severity of Extreme, Urgency of Immediate, and Certainty of Likely for additional languages',
    #     also EU-Alert Level 2 / Korean Public Alert System (KPAS) Class 1
    4386: 'CMAS CBS for CMAS Severe Alerts with Severity of Extreme, Urgency of Expected, and Certainty of Observed for additional languages',
    #     also EU-Alert Level 3 / Korean Public Alert System (KPAS) Class 1
    4387: 'CMAS CBS for CMAS Severe Alerts with Severity of Extreme, Urgency of Expected, and Certainty of Likely for additional languages',
    #     also EU-Alert Level 3 / Korean Public Alert System (KPAS) Class 1
    4388: 'CMAS CBS for CMAS Severe Alerts with Severity of Severe, Urgency of Immediate, and Certainty of Observed for additional languages',
    #     also EU-Alert Level 3 / Korean Public Alert System (KPAS) Class 1
    4389: 'CMAS CBS for CMAS Severe Alerts with Severity of Severe, Urgency of Immediate, and Certainty of Likely for additional languages',
    #     also EU-Alert Level 3 / Korean Public Alert System (KPAS) Class 1
    4390: 'CMAS CBS for CMAS Severe Alerts with Severity of Severe, Urgency of Expected, and Certainty of Observed for additional languages',
    #     also EU-Alert Level 3 / Korean Public Alert System (KPAS) Class 1
    4391: 'CMAS CBS for CMAS Severe Alerts with Severity of Severe, Urgency of Expected, and Certainty of Likely for additional languages',
    #     also EU-Alert Level 3 / Korean Public Alert System (KPAS) Class 1
    4392: 'CMAS CBS for Child Abduction Emergency (Amber Alert) for additional languages',
    #     also EU-Amber / Korean Public Alert System (KPAS) Class 1
    4393: 'CMAS CBS for the Required Monthly Test for additional languages',
    4394: 'CMAS CBS for CMAS Exercise for additional languages',
    4395: 'CMAS CBS for operator defined use for additional languages',
    #4396-4399: future CMA / EU-Alert
    #4400-6399: future PWS
    6400: 'EU-Info for the local language',
    #6401-40959: future use
    #40960-45055: operator specific
    #45056-65534: future operator specific
    65535: 'reserved', # used with SIM, not settable by MMI
    }


#------------------------------------------------------------------------------#
# Warning Message Content E-UTRAN
# TS 23.041, section 9.3.35 
#------------------------------------------------------------------------------#

def encode_cbs_pages(msg, dcs7b=True, char_preamb=''):
    """translates the unicode string `msg' into a buffer containing page(s)
    ready for broadcast
    
    dcs7b: True, encode in GSM 7 bit characters
           False, encode in UCS-2
    char_preamb: to add a potential prefix for specifying the language of the 
        message (e.g. "EN", "FR" or "DE")
    """
    if dcs7b:
        # char_preamb should be 2 chars (e.g. EN) followed by a CR
        pages = encode_7b_cbs(char_preamb + '\r' + msg)
    else:
        # char_preamb should be 2 chars, encoded in GSM 7 bits and padded
        txt = encode_7b(char_preamb)[0] + msg.encode('utf-16')
        # check number of pages needed
        num = len(txt) // 82
        if len(txt) % 82:
            num += 1
        pages = [txt[i*82:(i+1)*82] for i in range(0, num)]
    
        
    buf = [pack('>B', len(pages))]
    for page, page_len in pages:
        buf.append(page)
        buf.append(pack('>B', page_len))
    return b''.join(buf)

