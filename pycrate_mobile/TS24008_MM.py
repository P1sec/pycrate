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
# * File Name : pycrate_mobile/TS24008_MM.py
# * Created : 2017-06-22
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'MMIMSIDetachIndication',
    'MMLocationUpdatingAccept',
    'MMLocationUpdatingReject',
    'MMLocationUpdatingRequest',
    'MMAuthenticationReject',
    'MMAuthenticationRequest',
    'MMAuthenticationResponse',
    'MMAuthenticationFailure',
    'MMIdentityRequest',
    'MMIdentityResponse',
    'MMTMSIReallocationCommand',
    'MMTMSIReallocationComplete',
    'MMCMServiceAccept',
    'MMCMServiceReject',
    'MMCMServiceAbort',
    'MMCMServiceRequest',
    'MMCMServicePrompt',
    'MMCMReestablishmentRequest',
    'MMAbort',
    'MMNull',
    'MMStatus',
    'MMInformation',
    #
    'MMTypeClasses',
    'get_mm_msg_instances'
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.008: Mobile radio interface layer 3 specification
# release 13 (d90)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24008_IE import *
from .TS24007    import *

#------------------------------------------------------------------------------#
# CS Mobility Management header
# TS 24.008, section 10.1 to 10.4
#------------------------------------------------------------------------------#

# CS Mobility Management procedures dict
_CS_MM_dict = {
    1 : "Registration - IMSI DETACH INDICATION",
    2 : "Registration - LOCATION UPDATING ACCEPT",
    4 : "Registration - LOCATION UPDATING REJECT",
    8 : "Registration - LOCATION UPDATING REQUEST",
    17: "Security - AUTHENTICATION REJECT",
    18: "Security - AUTHENTICATION REQUEST",
    20: "Security - AUTHENTICATION RESPONSE",
    28: "Security - AUTHENTICATION FAILURE",
    24: "Security - IDENTITY REQUEST",
    25: "Security - IDENTITY RESPONSE",
    26: "Security - TMSI REALLOCATION COMMAND",
    27: "Security - TMSI REALLOCATION COMPLETE",
    33: "Connection Mgt - CM SERVICE ACCEPT",
    34: "Connection Mgt - CM SERVICE REJECT",
    35: "Connection Mgt - CM SERVICE ABORT",
    36: "Connection Mgt - CM SERVICE REQUEST",
    37: "Connection Mgt - CM SERVICE PROMPT",
    38: "Connection Mgt - Reserved",
    40: "Connection Mgt - CM RE-ESTABLISHMENT REQUEST",
    41: "Connection Mgt - ABORT",
    48: "Misc - MM NULL",
    49: "Misc - MM STATUS",
    50: "Misc - MM INFORMATION"
    }

class MMHeader(Envelope):
    _GEN  = (
        Uint('SkipInd', bl=4),
        Uint('ProtDisc', val=5, bl=4, dic=ProtDisc_dict),
        Uint('Seqn', bl=2),
        Uint('Type', val=48, bl=6, dic=_CS_MM_dict),
        )


#------------------------------------------------------------------------------#
# Authentication Reject
# TS 24.008, section 9.2.1
#------------------------------------------------------------------------------#

class MMAuthenticationReject(Layer3):
    _GEN = (
        MMHeader(val={'Type':17}),
        )


#------------------------------------------------------------------------------#
# Authentication Request
# TS 24.008, section 9.2.2
#------------------------------------------------------------------------------#

class MMAuthenticationRequest(Layer3):
    _GEN = (
        MMHeader(val={'Type':18}),
        Uint('spare', bl=4),
        Type1V('CKSN', dic=CKSN_dict),
        Type3V('RAND', val={'V':16*b'\0'}, bl={'V':128}),
        Type4TLV('AUTN', val={'T':0x20, 'V':16*b'\0'}, IE=AUTN())
        )


#------------------------------------------------------------------------------#
# Authentication Response
# TS 24.008, section 9.2.3
#------------------------------------------------------------------------------#

class MMAuthenticationResponse(Layer3):
    _GEN = (
        MMHeader(val={'Type':20}),
        Type3V('RES', val={'V':4*b'\0'}, bl={'V':32}),
        Type4TLV('RESExt', val={'T':0x21, 'V':4*b'\0'})
        )


#------------------------------------------------------------------------------#
# Authentication Failure
# TS 24.008, section 9.2.3a
#------------------------------------------------------------------------------#

class MMAuthenticationFailure(Layer3):
    _GEN = (
        MMHeader(val={'Type':28}),
        Type3V('RejectCause', val={'V':b'\x11'}, bl={'V':8}, IE=RejectCause()),
        Type4TLV('AUTS', val={'T':0x22, 'V':16*b'\0'})
        )


#------------------------------------------------------------------------------#
# CM Reestablishment Request
# TS 24.008, section 9.2.4
#------------------------------------------------------------------------------#

class MMCMReestablishmentRequest(Layer3):
    _GEN = (
        MMHeader(val={'Type':40}),
        Uint('spare', bl=4),
        Type1V('CKSN', dic=CKSN_dict),
        Type4LV('MSCm2', val={'V':b'@\0\0'}, IE=MSCm2()),
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID()),
        Type3TV('LAI', val={'T':0x13, 'V':b'\0\xf1\x10\0\0'}, bl={'V':40}, IE=LAI()),
        Type1TV('DeviceProp', val={'T':0xD, 'V':0}, IE=DeviceProp())
        )


#------------------------------------------------------------------------------#
# CM Service Accept
# TS 24.008, section 9.2.5
#------------------------------------------------------------------------------#

class MMCMServiceAccept(Layer3):
    _GEN = (
        MMHeader(val={'Type':33}),
        )


#------------------------------------------------------------------------------#
# CM Service Prompt $(CCBS)$
# TS 24.008, section 9.2.5a
#------------------------------------------------------------------------------#

class MMCMServicePrompt(Layer3):
    _GEN = (
        MMHeader(val={'Type':37}),
        Type3V('PD_SAPI', val={'V':b'\0'}, bl={'V':8}, IE=PD_SAPI())
        )


#------------------------------------------------------------------------------#
# CM Service Reject
# TS 24.008, section 9.2.6
#------------------------------------------------------------------------------#

class MMCMServiceReject(Layer3):
    _GEN = (
        MMHeader(val={'Type':34}),
        Type3V('RejectCause', val={'V':b'\x11'}, bl={'V':8}, IE=RejectCause()),
        Type4TLV('T3246', val={'T':0x36, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# CM Service Abort
# TS 24.008, section 9.2.7
#------------------------------------------------------------------------------#

class MMCMServiceAbort(Layer3):
    _GEN = (
        MMHeader(val={'Type':35}),
        )


#------------------------------------------------------------------------------#
# Abort
# TS 24.008, section 9.2.8
#------------------------------------------------------------------------------#

class MMAbort(Layer3):
    _GEN = (
        MMHeader(val={'Type':41}),
        Type3V('RejectCause', val={'V':b'\x11'}, bl={'V':8}, IE=RejectCause())
        )


#------------------------------------------------------------------------------#
# CM Service Request
# TS 24.008, section 9.2.9
#------------------------------------------------------------------------------#

class MMCMServiceRequest(Layer3):
    _GEN = (
        MMHeader(val={'Type':36}),
        Type1V('CKSN', dic=CKSN_dict),
        Type1V('Service', val={'V':1}, dic=CMService_dict),
        Type4LV('MSCm2', val={'V':b'@\0\0'}, IE=MSCm2()),
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID()),
        Type1TV('Priority', val={'T':0x8, 'V':0}, IE=PriorityLevel()),
        Type1TV('AddUpdateParams', val={'T':0xC, 'V':0}, IE=AddUpdateParams()),
        Type1TV('DeviceProp', val={'T':0xD, 'V':0}, IE=DeviceProp())
        )


#------------------------------------------------------------------------------#
# Identity Request
# TS 24.008, section 9.2.10
#------------------------------------------------------------------------------#

class MMIdentityRequest(Layer3):
    _GEN = (
        MMHeader(val={'Type':24}),
        Uint('spare', bl=4),
        Type1V('IDType', val={'V':IDTYPE_IMSI}, dic=IDType_dict)
        )


#------------------------------------------------------------------------------#
# Identity Response
# TS 24.008, section 9.2.11
#------------------------------------------------------------------------------#

class MMIdentityResponse(Layer3):
    _GEN = (
        MMHeader(val={'Type':25}),
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID()),
        Type1TV('PTMSIType', val={'T':0xE, 'V':0}, IE=PTMSIType()),
        Type4TLV('RAI', val={'T':0x1B, 'V':b'\0\xf1\x10\0\0\0'}, IE=RAI()),
        Type4TLV('PTMSISign', val={'T':0x19, 'V':3*b'\0'})
        )


#------------------------------------------------------------------------------#
# IMSI Detach Indication
# TS 24.008, section 9.2.12
#------------------------------------------------------------------------------#

class MMIMSIDetachIndication(Layer3):
    _GEN = (
        MMHeader(val={'Type':1}),
        Type3V('MSCm1', val={'V':b'\x40'}, bl={'V':8}, IE=MSCm1()),
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID())
        )


#------------------------------------------------------------------------------#
# Location Updating Accept
# TS 24.008, section 9.2.13
#------------------------------------------------------------------------------#

class MMLocationUpdatingAccept(Layer3):
    _GEN = (
        MMHeader(val={'Type':2}),
        Type3V('LAI', val={'V': b'\0\xf1\x10\0\0'}, bl={'V':40}, IE=LAI()),
        Type4TLV('ID', val={'T':0x17 ,'V':b'\xf4\0\0\0\0'}, IE=ID()),
        Type2('FollowOnProceed', val={'T':0xA1}),
        Type2('CTSPerm', val={'T':0xA2}),
        Type4TLV('EquivPLMNList', val={'T':0x4A, 'V':b'\0\0\0'}, IE=PLMNList()),
        Type4TLV('EmergNumList', val={'T':0x34, 'V':b'\x02\x01\0'}, IE=EmergNumList()),
        Type4TLV('MST3212', val={'T':0x35, 'V':b'\0'}, IE=GPRSTimer3())
        )


#------------------------------------------------------------------------------#
# Location Updating Reject
# TS 24.008, section 9.2.14
#------------------------------------------------------------------------------#

class MMLocationUpdatingReject(Layer3):
    _GEN = (
        MMHeader(val={'Type':4}),
        Type3V('RejectCause', val={'V':b'\x11'}, bl={'V':8}, IE=RejectCause()),
        Type4TLV('T3246', val={'T':0x36, 'V':b'\0'}, IE=MMTimer())
        )


#------------------------------------------------------------------------------#
# Location Updating Request
# TS 24.008, section 9.2.15
#------------------------------------------------------------------------------#

class MMLocationUpdatingRequest(Layer3):
    _GEN = (
        MMHeader(val={'Type':8}),
        Type1V('CKSN', dic=CKSN_dict),
        Type1V('LocUpdateType', IE=LocUpdateType()),
        Type3V('LAI', val={'V': b'\0\xf1\x10\0\0'}, bl={'V':40}, IE=LAI()),
        Type3V('MSCm1', val={'V':b'\x40'}, bl={'V':8}, IE=MSCm1()),
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID()),
        Type4TLV('MSCm2', val={'T':0x33, 'V':b'@\0\0'}, IE=MSCm2()),
        Type1TV('AddUpdateParams', val={'T':0xC, 'V':0}, IE=AddUpdateParams()),
        Type1TV('DeviceProp', val={'T':0xD, 'V':0}, IE=DeviceProp()),
        Type1TV('MSNetFeatSupp', val={'T':0xE, 'V':0}, IE=MSNetFeatSupp())
        )


#------------------------------------------------------------------------------#
# MM Information
# TS 24.008, section 9.2.15a
#------------------------------------------------------------------------------#

class MMInformation(Layer3):
    _GEN = (
        MMHeader(val={'Type':50}),
        Type4TLV('NetFullName', val={'T':0x43, 'V':b'\0'}, IE=NetworkName()),
        Type4TLV('NetShortName', val={'T':0x45, 'V':b'\0'}, IE=NetworkName()),
        Type3TV('LocalTimeZone', val={'T':0x46, 'V':b'\0'}, bl={'V':8}, IE=TimeZone()),
        Type3TV('UnivTimeAndTimeZone', val={'T':0x47, 'V':7*b'\0'}, bl={'V':56},
                IE=TimeZoneTime()),
        Type4TLV('LSAIdentity', val={'T':0x48, 'V':b''}),
        Type4TLV('DLSavingTime', val={'T':0x49, 'V':b'\0'}, IE=DLSavingTime())
        )


#------------------------------------------------------------------------------#
# MM Status
# TS 24.008, section 9.2.16
#------------------------------------------------------------------------------#

class MMStatus(Layer3):
    _GEN = (
        MMHeader(val={'Type':49}),
        Type3V('RejectCause', val={'V':b'\x11'}, bl={'V':8}, IE=RejectCause())
        )


#------------------------------------------------------------------------------#
# TMSI Reallocation Command
# TS 24.008, section 9.2.17
#------------------------------------------------------------------------------#

class MMTMSIReallocationCommand(Layer3):
    _GEN = (
        MMHeader(val={'Type':26}),
        Type3V('LAI', val={'V': b'\0\xf1\x10\0\0'}, bl={'V':40}, IE=LAI()),
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID())
        )


#------------------------------------------------------------------------------#
# TMSI Reallocation Complete
# TS 24.008, section 9.2.18
#------------------------------------------------------------------------------#

class MMTMSIReallocationComplete(Layer3):
    _GEN = (
        MMHeader(val={'Type':27}),
        )


#------------------------------------------------------------------------------#
# MM Null
# TS 24.008, section 9.2.19
#------------------------------------------------------------------------------#

class MMNull(Layer3):
    _GEN = (
        MMHeader(val={'Type':48}),
        )


#------------------------------------------------------------------------------#
# MM dispatcher
#------------------------------------------------------------------------------#

MMTypeClasses = {
    1 : MMIMSIDetachIndication,
    2 : MMLocationUpdatingAccept,
    4 : MMLocationUpdatingReject,
    8 : MMLocationUpdatingRequest,
    17: MMAuthenticationReject,
    18: MMAuthenticationRequest,
    20: MMAuthenticationResponse,
    28: MMAuthenticationFailure,
    24: MMIdentityRequest,
    25: MMIdentityResponse,
    26: MMTMSIReallocationCommand,
    27: MMTMSIReallocationComplete,
    33: MMCMServiceAccept,
    34: MMCMServiceReject,
    35: MMCMServiceAbort,
    36: MMCMServiceRequest,
    37: MMCMServicePrompt,
    40: MMCMReestablishmentRequest,
    41: MMAbort,
    48: MMNull,
    49: MMStatus,
    50: MMInformation,
    }

def get_mm_msg_instances():
    return {k: MMTypeClasses[k]() for k in MMTypeClasses}

