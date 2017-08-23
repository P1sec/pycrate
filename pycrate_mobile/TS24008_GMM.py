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
# * File Name : pycrate_mobile/TS24008_GMM.py
# * Created : 2017-06-22
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

#------------------------------------------------------------------------------#
# 3GPP TS 24.008: Mobile radio interface layer 3 specification
# release 13 (d90)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24008_IE import *
from .TS24301_IE import AddUpdateType, UENetCap
from .TS24007    import *

#------------------------------------------------------------------------------#
# GPRS Mobility Management header
# TS 24.008, section 10.1 to 10.4
#------------------------------------------------------------------------------#

# PS Mobility Management procedures dict
_PS_MM_dict = {
    1 : "GPRS - Attach request",
    2 : "GPRS - Attach accept",
    3 : "GPRS - Attach complete",
    4 : "GPRS - Attach reject",
    5 : "GPRS - Detach request",
    6 : "GPRS - Detach accept",
    8 : "GPRS - Routing area update request",
    9 : "GPRS - Routing area update accept",
    10: "GPRS - Routing area update complete",
    11: "GPRS - Routing area update reject",
    12: "GPRS - Service Request",
    13: "GPRS - Service Accept",
    14: "GPRS - Service Reject",
    16: "GPRS - P-TMSI reallocation command",
    17: "GPRS - P-TMSI reallocation complete",
    18: "GPRS - Authentication and ciphering request",
    19: "GPRS - Authentication and ciphering response",
    20: "GPRS - Authentication and ciphering reject",
    28: "GPRS - Authentication and ciphering failure",
    21: "GPRS - Identity request",
    22: "GPRS - Identity response",
    32: "GPRS - GMM status",
    33: "GPRS - GMM information",
    }

class GMMHeader(Envelope):
    _GEN = (
        Uint('SkipInd', val=0, bl=4),
        Uint('ProtDisc', val=8, bl=4, dic=ProtDisc_dict),
        Uint8('Type', val=32, dic=_PS_MM_dict),
        )

#------------------------------------------------------------------------------#
# Attach Request
# TS 24.008, section 9.4.1
#------------------------------------------------------------------------------#

class GMMAttachRequest(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':1})._content) + (
        Type4LV('MSNetCap', val={'V':b'\0\0'}, IE=MS_network_capability_value_part),
        Uint('CKSN', val=0, bl=4, dic=CKSN_dict),
        AttachType(),
        DRXParam(),
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID()),
        RAI('OldRAI'),
        Type4LV('MSRACap', val={'V':5*b'\0'}, IE=MS_RA_capability_value_part),
        Type3TV('OldPTMSISign', val={'T':0x19, 'V':b'\0\0\0'}, bl={'V':24}, trans=True),
        Type3TV('ReqREADYTimer', val={'T':0x17, 'V':b'\0'}, bl={'V':8}, IE=GPRSTimer(), trans=True),
        Type1TV('TMSIStatus', val={'T':0x9, 'V':0}, IE=TMSIStatus(), trans=True),
        Type4TLV('PSLCSCap', val={'T':0x33, 'V':b'\0'}, IE=PSLCSCap(), trans=True),
        Type4TLV('MSCm2', val={'T':0x11, 'V':b'@\x00\x00'}, IE=MSCm2(), trans=True),
        Type4TLV('MSCm3', val={'T':0x20, 'V':b''}, IE=Classmark_3_Value_part, trans=True),
        Type4TLV('SuppCodecs', val={'T':0x40, 'V':b'\0\x01\0'}, IE=SuppCodecList(), trans=True),
        Type4TLV('UENetCap', val={'T':0x58, 'V':b'\0\0'}, IE=UENetCap(), trans=True),
        Type4TLV('AddID', val={'T':0x1A, 'V':b'\xf4\0\0\0\0'}, IE=ID(), trans=True),
        Type4TLV('AddRAI', val={'T':0x1B, 'V':6*b'\0'}, IE=RAI(), trans=True),
        Type4TLV('VoiceDomPref', val={'T':0x5D, 'V':b'\0'}, IE=VoiceDomPref(), trans=True),
        Type1TV('DeviceProp', val={'T':0xD, 'V':0}, IE=DeviceProp(), trans=True),
        Type1TV('PTMSIType', val={'T':0xE, 'V':0}, IE=PTMSIType(), trans=True),
        Type1TV('MSNetFeatSupp', val={'T':0xC, 'V':0}, IE=MSNetFeatSupp(), trans=True),
        Type4TLV('OldLAI', val={'T':0x14, 'V':5*b'\0'}, IE=LAI(), trans=True),
        Type1TV('AddUpdateType', val={'T':0xF, 'V':0}, IE=AddUpdateType(), trans=True),
        Type4TLV('TMSIBasedNRICont', val={'T':0x10, 'V':b'\0\0'}, IE=NRICont(), trans=True),
        Type4TLV('T3324', val={'T':0x6A, 'V':b'\0'}, IE=GPRSTimer(), trans=True),
        Type4TLV('T3312Ext', val={'T':0x39, 'V':b'\0'}, IE=GPRSTimer3(), trans=True),
        Type4TLV('ExtDRXParam', val={'T':0x6E, 'V':b'\0'}, IE=ExtDRXParam(), trans=True)
        )


#------------------------------------------------------------------------------#
# Attach Accept
# TS 24.008, section 9.4.2
#------------------------------------------------------------------------------#

class GMMAttachAccept(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':2})._content) + (
        ForceStdby(),
        AttachResult(),
        GPRSTimer('PeriodicRAUpdateTimer'),
        RadioPriority('RadioPrioForTOM8'),
        RadioPriority('RadioPrioForSMS'),
        RAI(),
        Type3TV('PTMSISign', val={'T':0x19, 'V':b'\0\0\0'}, bl={'V':24}, trans=True),
        Type3TV('NegoREADYTimer', val={'T':0x17, 'V':b'\0'}, bl={'V':8}, IE=GPRSTimer(), trans=True),
        Type4TLV('AllocPTMSI', val={'T':0x18, 'V':b'\xf4\0\0\0\0'}, IE=ID(), trans=True),
        Type4TLV('MSIdent', val={'T':0x23, 'V':b'\xf4\0\0\0\0'}, IE=ID(), trans=True),
        Type3TV('GMMCause', val={'T':0x25, 'V':b'\x11'}, bl={'V':8},
            IE=Uint8('GMMCause', val=0x11, dic=GMMCause_dict), trans=True),
        Type4TLV('T3302', val={'T':0x2A, 'V':b'\0'}, IE=GPRSTimer(), trans=True),
        Type2('CellNotif', val={'T':0x8C}, trans=True),
        Type4TLV('EquivPLMNList', val={'T':0x4A, 'V':3*b'\0'}, IE=PLMNList(), trans=True),
        Type1TV('NetFeatSupp', val={'T':0xA, 'V':0}, IE=NetFeatSupp(), trans=True),
        Type4TLV('T3319', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer(), trans=True),
        Type4TLV('T3323', val={'T':0x38, 'V':b'\0'}, IE=GPRSTimer(), trans=True),
        Type4TLV('T3312Ext', val={'T':0x39, 'V':b'\0'}, IE=GPRSTimer3(), trans=True),
        Type4TLV('AddNetFeatSupp', val={'T':0x66, 'V':b'\0'}, IE=AddNetFeatSupp(), trans=True),
        Type4TLV('T3324', val={'T':0x6A, 'V':b'\0'}, IE=GPRSTimer(), trans=True),
        Type4TLV('ExtDRXParam', val={'T':0x6E, 'V':b'\0'}, IE=ExtDRXParam(), trans=True),
        Type1TV('UPIntegrityInd', val={'T':0xC, 'V':0}, IE=UPIntegrityInd(), trans=True),
        Type4TLV('ReplayedMSNetCap', val={'T':0x31, 'V':b'\0\0'},
            IE=MS_network_capability_value_part, trans=True),
        Type4TLV('ReplayedMSRACap', val={'T':0x33, 'V':5*b'\0'},
            IE=MS_RA_capability_value_part, trans=True)
        )


#------------------------------------------------------------------------------#
# Attach Complete
# TS 24.008, section 9.4.3
#------------------------------------------------------------------------------#

class GMMAttachComplete(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':3})._content) + (
        Type4TLV('InterRATHOInfo', val={'T':0x27, 'V':b'\0'}, trans=True),
        Type4TLV('EUTRANInterRATHOInfo', val={'T':0x2B, 'V':b'\0'}, trans=True)
        )


#------------------------------------------------------------------------------#
# Attach Reject
# TS 24.008, section 9.4.4
#------------------------------------------------------------------------------#

class GMMAttachReject(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':4})._content) + (
        Uint8('GMMCause', val=0x11, dic=GMMCause_dict),
        Type4TLV('T3302', val={'T':0x2A, 'V':b'\0'}, IE=GPRSTimer(), trans=True),
        Type4TLV('T3346', val={'T':0x3A, 'V':b'\0'}, IE=GPRSTimer(), trans=True)
        )


#------------------------------------------------------------------------------#
# Detach Request (mobile terminated)
# TS 24.008, section 9.4.5.1
#------------------------------------------------------------------------------#

class GMMDetachRequestMT(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':5})._content) + (
        ForceStdby(),
        DetachTypeMT(),
        Type3TV('GMMCause', val={'T':0x25, 'V':b'\x11'}, bl={'V':8},
            IE=Uint8('GMMCause', val=0x11, dic=GMMCause_dict), trans=True)
        )


#------------------------------------------------------------------------------#
# Detach Request (mobile originated)
# TS 24.008, section 9.4.5.2
#------------------------------------------------------------------------------#

class GMMDetachRequestMO(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':5})._content) + (
        Uint('spare', val=0, bl=4),
        DetachTypeMO(),
        Type4TLV('AllocPTMSI', val={'T':0x18, 'V':b'\xf4\0\0\0\0'}, IE=ID(), trans=True),
        Type4TLV('PTMSISign', val={'T':0x19, 'V':b'\0\0\0'}, trans=True)
        )


#------------------------------------------------------------------------------#
# Detach Accept (mobile terminated)
# TS 24.008, section 9.4.6.1
#------------------------------------------------------------------------------#

class GMMDetachAcceptMT(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':6})._content)


#------------------------------------------------------------------------------#
# Detach Accept (mobile originated)
# TS 24.008, section 9.4.6.2
#------------------------------------------------------------------------------#

class GMMDetachAcceptMO(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':6})._content) + (
        Uint('spare', val=0, bl=4),
        ForceStdby()
        )


#------------------------------------------------------------------------------#
# P-TMSI Reallocation Command
# TS 24.008, section 9.4.7
#------------------------------------------------------------------------------#

class GMMPTMSIReallocationCommand(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':16})._content) + (
        Type4LV('AllocPTMSI', val={'V':b'\xf4\0\0\0\0'}, IE=ID(), trans=True),
        RAI(),
        Uint('spare', val=0, bl=4),
        ForceStdby(),
        Type3TV('PTMSISign', val={'T':0x19, 'V':b'\0\0\0'}, bl={'V':24}, trans=True),
        )


#------------------------------------------------------------------------------#
# P-TMSI Reallocation Complete
# TS 24.008, section 9.4.8
#------------------------------------------------------------------------------#

class GMMPTMSIReallocationComplete(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':17})._content)


#------------------------------------------------------------------------------#
# Authentication and ciphering request
# TS 24.008, section 9.4.9
#------------------------------------------------------------------------------#

class GMMAuthenticationCipheringRequest(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':18})._content) + (
        Uint('IMEISVReq', val=0, bl=4),
        Uint('CiphAlgo', val=0, bl=4, dic=CiphAlgo_dict),
        Uint('ACRef', val=0, bl=4),
        ForceStdby(),
        Type3TV('RAND', val={'T':0x21, 'V':16*b'\0'}, trans=True),
        Type1TV('CKSN', val={'T':0x8, 'V':0}, dic=CKSN_dict, trans=True),
        Type4TLV('AUTN', val={'T':0x28, 'V':16*b'\0'}, trans=True),
        Type4TLV('ReplayedMSNetCap', val={'T':0x31, 'V':b'\0\0'},
            IE=MS_network_capability_value_part, trans=True),
        Type1TV('IntegAlgo', val={'T':0x9, 'V':0}, dic=IntegAlgo_dict, trans=True),
        Type4TLV('MAC', val={'T':0x43, 'V':4*b'\0'}, trans=True),
        Type4TLV('ReplayedMSRACap', val={'T':0x33, 'V':5*b'\0'},
            IE=MS_RA_capability_value_part, trans=True)
        )


#------------------------------------------------------------------------------#
# Authentication and ciphering response
# TS 24.008, section 9.4.10
#------------------------------------------------------------------------------#

class GMMAuthenticationCipheringResponse(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':19})._content) + (
        Uint('spare', val=0, bl=4),
        Uint('ACRef', val=0, bl=4),
        Type3TV('RES', val={'T':0x22, 'V':4*b'\0'}, trans=True),
        Type4TLV('IMEISV', val={'T':0x23, 'V':b'\x03\0\0\0\0\0\0\0\xf0'}, IE=ID(), trans=True),
        Type4TLV('RESExt', val={'T':0x29, 'V':4*b'\0'}, trans=True),
        Type4TLV('MAC', val={'T':0x43, 'V':4*b'\0'}, trans=True),
        )


#------------------------------------------------------------------------------#
# Authentication and ciphering failure
# TS 24.008, section 9.4.10a
#------------------------------------------------------------------------------#

class GMMAuthenticationCipheringFailure(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':28})._content) + (
        Uint8('GMMCause', val=0x11, dic=GMMCause_dict),
        Type4TLV('AUTS', val={'T':0x30, 'V':14*b'\0'}, trans=True)
        )


#------------------------------------------------------------------------------#
# Authentication and ciphering reject
# TS 24.008, section 9.4.11
#------------------------------------------------------------------------------#

class GMMAuthenticationCipheringReject(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':20})._content)


#------------------------------------------------------------------------------#
# Identity Request
# TS 24.008, section 9.4.12
#------------------------------------------------------------------------------#

class GMMIdentityRequest(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':21})._content) + (
        ForceStdby(),
        Uint('IDType', val=1, bl=4, dic=IDType_dict)
        )


#------------------------------------------------------------------------------#
# Identity Response
# TS 24.008, section 9.4.13
#------------------------------------------------------------------------------#

class GMMIdentityResponse(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':22})._content) + (
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID()),
        )


#------------------------------------------------------------------------------#
# Routing Area Update Request
# TS 24.008, section 9.4.14
#------------------------------------------------------------------------------#

class GMMRoutingAreaUpdateRequest(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':8})._content) + (
        Uint('CKSN', val=0, bl=4, dic=CKSN_dict),
        UpdateType(),
        RAI('OldRAI'),
        Type4LV('MSRACap', val={'V':5*b'\0'}, IE=MS_RA_capability_value_part),
        Type3TV('OldPTMSISign', val={'T':0x19, 'V':b'\0\0\0'}, bl={'V':24}, trans=True),
        Type3TV('ReqREADYTimer', val={'T':0x17, 'V':b'\0'}, bl={'V':8}, IE=GPRSTimer(), trans=True),
        Type3TV('DRXParam', val={'T':0x27, 'V':b'\0\0'}, bl={'V':8}, IE=DRXParam(), trans=True),
        Type1TV('TMSIStatus', val={'T':0x9, 'V':0}, IE=TMSIStatus(), trans=True),
        Type4TLV('PTMSI', val={'T':0x18, 'V':b'\xf4\0\0\0\0'}, IE=ID(), trans=True),
        Type4TLV('MSNetCap', val={'T':0x31, 'V':b'\0\0'}, IE=MS_network_capability_value_part, trans=True),
        Type4TLV('PDPCtxtStat', val={'T':0x32, 'V':b'\0\0'}, IE=PDPCtxtStat(), trans=True),
        Type4TLV('PSLCSCap', val={'T':0x33, 'V':b'\0'}, IE=PSLCSCap(), trans=True),
        Type4TLV('MBMSCtxtStat', val={'T':0x35, 'V':b''}, IE=MBMSCtxtStat(), trans=True),
        Type4TLV('UENetCap', val={'T':0x58, 'V':b'\0\0'}, IE=UENetCap(), trans=True),
        Type4TLV('AddID', val={'T':0x1A, 'V':b'\xf4\0\0\0\0'}, IE=ID(), trans=True),
        Type4TLV('AddRAI', val={'T':0x1B, 'V':6*b'\0'}, IE=RAI(), trans=True),
        Type4TLV('MSCm2', val={'T':0x11, 'V':b'@\x00\x00'}, IE=MSCm2(), trans=True),
        Type4TLV('MSCm3', val={'T':0x20, 'V':b''}, IE=Classmark_3_Value_part, trans=True),
        Type4TLV('SuppCodecs', val={'T':0x40, 'V':b'\0\x01\0'}, IE=SuppCodecList(), trans=True),
        Type4TLV('VoiceDomPref', val={'T':0x5D, 'V':b'\0'}, IE=VoiceDomPref(), trans=True),
        Type1TV('PTMSIType', val={'T':0xE, 'V':0}, IE=PTMSIType(), trans=True),
        Type1TV('DeviceProp', val={'T':0xD, 'V':0}, IE=DeviceProp(), trans=True),
        Type1TV('MSNetFeatSupp', val={'T':0xC, 'V':0}, IE=MSNetFeatSupp(), trans=True),
        Type4TLV('OldLAI', val={'T':0x14, 'V':5*b'\0'}, IE=LAI(), trans=True),
        Type1TV('AddUpdateType', val={'T':0xF, 'V':0}, IE=AddUpdateType(), trans=True),
        Type4TLV('TMSIBasedNRICont', val={'T':0x10, 'V':b'\0\0'}, IE=NRICont(), trans=True),
        Type4TLV('T3324', val={'T':0x6A, 'V':b'\0'}, IE=GPRSTimer(), trans=True),
        Type4TLV('T3312Ext', val={'T':0x39, 'V':b'\0'}, IE=GPRSTimer3(), trans=True),
        Type4TLV('ExtDRXParam', val={'T':0x6E, 'V':b'\0'}, IE=ExtDRXParam(), trans=True)
        )


#------------------------------------------------------------------------------#
# Routing Area Update Accept
# TS 24.008, section 9.4.15
#------------------------------------------------------------------------------#

class GMMRoutingAreaUpdateAccept(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':9})._content) + (
        ForceStdby(),
        UpdateResult(),
        GPRSTimer('PeriodicRAUpdateTimer'),
        RAI(),
        Type3TV('PTMSISign', val={'T':0x19, 'V':b'\0\0\0'}, bl={'V':24}, trans=True),
        Type4TLV('AllocPTMSI', val={'T':0x18, 'V':b'\xf4\0\0\0\0'}, IE=ID(), trans=True),
        Type4TLV('MSIdent', val={'T':0x23, 'V':b'\xf4\0\0\0\0'}, IE=ID(), trans=True),
        Type4TLV('RcvNPDUNumList', val={'T':0x26, 'V':b'\0\0'},
            IE=Receive_N_PDU_Number_list_value, trans=True),
        Type3TV('NegoREADYTimer', val={'T':0x17, 'V':b'\0'}, bl={'V':8}, IE=GPRSTimer(), trans=True),
        Type3TV('GMMCause', val={'T':0x25, 'V':b'\x11'}, bl={'V':8},
            IE=Uint8('GMMCause', val=0x11, dic=GMMCause_dict), trans=True),
        Type4TLV('T3302', val={'T':0x2A, 'V':b'\0'}, IE=GPRSTimer(), trans=True),
        Type2('CellNotif', val={'T':0x8C}, trans=True),
        Type4TLV('EquivPLMNList', val={'T':0x4A, 'V':3*b'\0'}, IE=PLMNList(), trans=True),
        Type4TLV('PDPCtxtStat', val={'T':0x32, 'V':b'\0\0'}, IE=PDPCtxtStat(), trans=True),
        Type1TV('NetFeatSupp', val={'T':0xA, 'V':0}, IE=NetFeatSupp(), trans=True),
        Type4TLV('EmergNumList', val={'T':0x34, 'V':b'\x02\x01\x00'}, IE=EmergNumList(), trans=True),
        Type4TLV('MBMSCtxtStat', val={'T':0x35, 'V':b''}, IE=MBMSCtxtStat(), trans=True),
        Type1TV('ReqMSInfo', val={'T':0xA, 'V':0}, IE=ReqMSInfo(), trans=True),
        Type4TLV('T3319', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer(), trans=True),
        Type4TLV('T3323', val={'T':0x38, 'V':b'\0'}, IE=GPRSTimer(), trans=True),
        Type4TLV('T3312Ext', val={'T':0x39, 'V':b'\0'}, IE=GPRSTimer3(), trans=True),
        Type4TLV('AddNetFeatSupp', val={'T':0x66, 'V':b'\0'}, IE=AddNetFeatSupp(), trans=True),
        Type4TLV('T3324', val={'T':0x6A, 'V':b'\0'}, IE=GPRSTimer(), trans=True),
        Type4TLV('ExtDRXParam', val={'T':0x6E, 'V':b'\0'}, IE=ExtDRXParam(), trans=True),
        Type1TV('UPIntegrityInd', val={'T':0xC, 'V':0}, IE=UPIntegrityInd(), trans=True),
        Type4TLV('ReplayedMSNetCap', val={'T':0x31, 'V':b'\0\0'},
            IE=MS_network_capability_value_part, trans=True),
        Type4TLV('ReplayedMSRACap', val={'T':0x33, 'V':5*b'\0'},
            IE=MS_RA_capability_value_part, trans=True)
        )


#------------------------------------------------------------------------------#
# Routing Area Update Complete
# TS 24.008, section 9.4.16
#------------------------------------------------------------------------------#

class GMMRoutingAreaUpdateComplete(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':10})._content) + (
        Type4TLV('RcvNPDUNumList', val={'T':0x26, 'V':b'\0\0'},
            IE=Receive_N_PDU_Number_list_value, trans=True),
        Type4TLV('InterRATHOInfo', val={'T':0x27, 'V':b'\0'}, trans=True),
        Type4TLV('EUTRANInterRATHOInfo', val={'T':0x2B, 'V':b'\0'}, trans=True)
        )


#------------------------------------------------------------------------------#
# Routing Area Update Reject
# TS 24.008, section 9.4.17
#------------------------------------------------------------------------------#

class GMMRoutingAreaUpdateReject(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':11})._content) + (
        Uint8('GMMCause', val=0x11, dic=GMMCause_dict),
        Uint('spare', val=0, bl=4),
        ForceStdby(),
        Type4TLV('T3302', val={'T':0x2A, 'V':b'\0'}, IE=GPRSTimer(), trans=True),
        Type4TLV('T3346', val={'T':0x3A, 'V':b'\0'}, IE=GPRSTimer(), trans=True)
        )


#------------------------------------------------------------------------------#
# GMM Status
# TS 24.008, section 9.4.18
#------------------------------------------------------------------------------#

class GMMStatus(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':32})._content) + (
        Uint8('GMMCause', val=0x11, dic=GMMCause_dict),
        )


#------------------------------------------------------------------------------#
# GMM Information
# TS 24.008, section 9.4.19
#------------------------------------------------------------------------------#

class GMMInformation(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':33})._content) + (
        Type4TLV('NetFullName', val={'T':0x43, 'V':b'\0'}, IE=NetworkName(), trans=True),
        Type4TLV('NetShortName', val={'T':0x45, 'V':b'\0'}, IE=NetworkName(), trans=True),
        Type3TV('LocalTimeZone', val={'T':0x46, 'V':b'\0'}, bl={'V':8}, trans=True),
        Type3TV('UnivTimeAndTimeZone', val={'T':0x47, 'V':7*b'\0'}, bl={'V':56},
                IE=TimeZoneTime(), trans=True),
        Type4TLV('LSAIdentity', val={'T':0x48, 'V':b''}, trans=True),
        Type4TLV('NetDLSavingTime', val={'T':0x49, 'V':b'\0'}, trans=True)
        )


#------------------------------------------------------------------------------#
# Service Request
# TS 24.008, section 9.4.20
#------------------------------------------------------------------------------#

class GMMServiceRequest(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':12})._content) + (
        Uint('ServiceType', val=0, bl=4, dic=ServiceType_dict),
        Uint('CKSN', val=0, bl=4, dic=CKSN_dict),
        Type4LV('PTMSI', val={'V':b'\xf4\0\0\0\0'}, IE=ID()),
        Type4TLV('PDPCtxtStat', val={'T':0x32, 'V':b'\0\0'}, IE=PDPCtxtStat(), trans=True),
        Type4TLV('MBMSCtxtStat', val={'T':0x35, 'V':b''}, IE=MBMSCtxtStat(), trans=True),
        Type4TLV('ULDataStat', val={'T':0x36, 'V':b'\0\0'}, IE=ULDataStat(), trans=True),
        Type1TV('DeviceProp', val={'T':0xD, 'V':0}, IE=DeviceProp(), trans=True)
        )


#------------------------------------------------------------------------------#
# Service Accept
# TS 24.008, section 9.4.21
#------------------------------------------------------------------------------#

class GMMServiceAccept(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':13})._content) + (
        Type4TLV('PDPCtxtStat', val={'T':0x32, 'V':b'\0\0'}, IE=PDPCtxtStat(), trans=True),
        Type4TLV('MBMSCtxtStat', val={'T':0x35, 'V':b''}, IE=MBMSCtxtStat(), trans=True),
        )


#------------------------------------------------------------------------------#
# Service Reject
# TS 24.008, section 9.4.22
#------------------------------------------------------------------------------#

class GMMServiceReject(Layer3):
    _GEN = tuple(GMMHeader(val={'Type':14})._content) + (
        Uint8('GMMCause', val=0x11, dic=GMMCause_dict),
        Type4TLV('T3346', val={'T':0x3A, 'V':b'\0'}, IE=GPRSTimer(), trans=True)
        )


#------------------------------------------------------------------------------#
# GMM dispatchers
#------------------------------------------------------------------------------#

GMMTypeMOClasses = {
    1 : GMMAttachRequest,
    2 : GMMAttachAccept,
    3 : GMMAttachComplete,
    4 : GMMAttachReject,
    5 : GMMDetachRequestMO,
    6 : GMMDetachAcceptMO,
    8 : GMMRoutingAreaUpdateRequest,
    9 : GMMRoutingAreaUpdateAccept,
    10: GMMRoutingAreaUpdateComplete,
    11: GMMRoutingAreaUpdateReject,
    12: GMMServiceRequest,
    13: GMMServiceAccept,
    14: GMMServiceReject,
    16: GMMPTMSIReallocationCommand,
    17: GMMPTMSIReallocationComplete,
    18: GMMAuthenticationCipheringRequest,
    19: GMMAuthenticationCipheringResponse,
    20: GMMAuthenticationCipheringReject,
    28: GMMAuthenticationCipheringFailure,
    21: GMMIdentityRequest,
    22: GMMIdentityResponse,
    32: GMMStatus,
    33: GMMInformation
    }

GMMTypeMTClasses = {
    1 : GMMAttachRequest,
    2 : GMMAttachAccept,
    3 : GMMAttachComplete,
    4 : GMMAttachReject,
    5 : GMMDetachRequestMT,
    6 : GMMDetachAcceptMT,
    8 : GMMRoutingAreaUpdateRequest,
    9 : GMMRoutingAreaUpdateAccept,
    10: GMMRoutingAreaUpdateComplete,
    11: GMMRoutingAreaUpdateReject,
    12: GMMServiceRequest,
    13: GMMServiceAccept,
    14: GMMServiceReject,
    16: GMMPTMSIReallocationCommand,
    17: GMMPTMSIReallocationComplete,
    18: GMMAuthenticationCipheringRequest,
    19: GMMAuthenticationCipheringResponse,
    20: GMMAuthenticationCipheringReject,
    28: GMMAuthenticationCipheringFailure,
    21: GMMIdentityRequest,
    22: GMMIdentityResponse,
    32: GMMStatus,
    33: GMMInformation
    }

def get_gmm_msg_mo_instances():
    return {k: GMMTypeMOClasses[k]() for k in GMMTypeMOClasses}

def get_gmm_msg_mt_instances():
    return {k: GMMTypeMTClasses[k]() for k in GMMTypeMTClasses}

