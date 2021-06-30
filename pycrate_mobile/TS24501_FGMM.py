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
# * File Name : pycrate_mobile/TS24501_FGMM.py
# * Created : 2019-11-08
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    "FGMMHeader",
    "FGMMHeaderSec",
    "FGMMAuthenticationRequest",
    "FGMMAuthenticationResponse",
    "FGMMAuthenticationResult",
    "FGMMAuthenticationFailure",
    "FGMMAuthenticationReject",
    "FGMMRegistrationRequest",
    "FGMMRegistrationAccept",
    "FGMMRegistrationComplete",
    "FGMMRegistrationReject",
    "FGMMULNASTransport",
    "FGMMDLNASTransport",
    "FGMMMODeregistrationRequest",
    "FGMMMODeregistrationAccept",
    "FGMMMTDeregistrationRequest",
    "FGMMMTDeregistrationAccept",
    "FGMMServiceRequest",
    "FGMMServiceAccept",
    "FGMMServiceReject",
    "FGMMConfigurationUpdateCommand",
    "FGMMConfigurationUpdateComplete",
    "FGMMIdentityRequest",
    "FGMMIdentityResponse",
    "FGMMNotification",
    "FGMMNotificationResponse",
    "FGMMSecurityModeCommand",
    "FGMMSecurityModeComplete",
    "FGMMSecurityModeReject",
    "FGMMSecProtNASMessage",
    "FGMMSecProtNASMessage",
    "FGMMStatus",
    "FGMMControlPlaneServiceRequest",
    "FGMMNetworkSliceSpecAuthCommand",
    "FGMMNetworkSliceSpecAuthComplete",
    "FGMMNetworkSliceSpecAuthResult",
    "FGMMTypeClasses",
    "get_5gmm_msg_instances"
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.501: NAS protocol for 5G
# release 16 (g51)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007       import *
from .TS24008_IE    import (
    AUTN, MSCm2, SuppCodecList, ExtDRXParam, PLMNList, GPRSTimer, GPRSTimer3,
    EmergNumList, Non3GPPNWProvPol, ExtDRXParam, APN, NetworkName, TimeZone,
    TimeZoneTime, DLSavingTime, IMEISVReq, 
    )
from .TS24301_IE    import (
    NAS_KSI, EPSBearerCtxtStat, UENetCap as EPSUENetCap, ExtEmergNumList, 
    EPSBearerCtxtStat, NASSecAlgo as EPSNASSecAlgo, UESecCap as S1UESecCap, 
    ReleaseAssistInd, 
    )
from .TS24501_IE    import *
#from .TS24501_FGSM  import FGSMTypeClasses

try:
    from CryptoMobile import CM
except:
    _with_cm = False
    log('warning: CryptoMobile Python module not found, unable to handle 5G NAS security')
else:
    _with_cm = True
    if hasattr(CM, 'EEA2'):
        _FGIA = {
            1 : CM.EIA1,
            2 : CM.EIA2,
            3 : CM.EIA3
            }
        _FGEA = {
            1 : CM.EEA1,
            2 : CM.EEA2,
            3 : CM.EEA3
            }
    else:
        _FGIA = {
            1 : CM.EIA1,
            3 : CM.EIA3
            }
        _FGEA = {
            1 : CM.EEA1,
            3 : CM.EEA3
            }


#------------------------------------------------------------------------------#
# 5GS Mobility Management header
# TS 24.501, section 9
#------------------------------------------------------------------------------#

# section 9.7
_FGMM_dict = {
    # registration
    65 : "Registration request",
    66 : "Registration accept",
    67 : "Registration complete",
    68 : "Registration reject",
    69 : "MO Deregistration request",
    70 : "MO Deregistration accept",
    71 : "MT Deregistration request",
    72 : "MT Deregistration accept",
    # service request
    76 : "Service request",
    77 : "Service reject",
    78 : "Service accept",
    79 : "Control plane service request",
    # slice-specific auth
    80 : "Network slice-specific authentication command",
    81 : "Network slice-specific authentication complete",
    82 : "Network slice-specific authentication result",
    # common procedures
    84 : "Configuration update command",
    85 : "Configuration update complete",
    86 : "Authentication request",
    87 : "Authentication response",
    88 : "Authentication reject",
    89 : "Authentiction failure",
    90 : "Authentication result",
    91 : "Identity request",
    92 : "Identity response",
    93 : "Security mode command",
    94 : "Security mode complete",
    95 : "Security Mode reject",
    # misc
    100: "5GMM status",
    101: "Notification",
    102: "Notification response",
    103: "UL NAS transport",
    104: "DL NAS transport"
    }


class FGMMHeader(Envelope):
    _name = '5GMMHeader'
    _GEN = (
        Uint8('EPD', val=126, dic=ProtDisc_dict),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('SecHdr', bl=4, dic=SecHdrType_dict),
        Uint8('Type', val=100, dic=_FGMM_dict)
        )


class FGMMHeaderSec(Envelope):
    _name = '5GMMHeaderSec'
    _GEN = (
        Uint8('EPD', val=126, dic=ProtDisc_dict),
        Uint('spare', bl=4, rep=REPR_HEX),
        Uint('SecHdr', bl=4, dic=SecHdrType_dict)
        )


#------------------------------------------------------------------------------#
# Authentication request
# TS 24.501, section 8.2.1
#------------------------------------------------------------------------------#

class FGMMAuthenticationRequest(Layer3E):
    _name = '5GMMAuthenticationRequest'
    _GEN = (
        FGMMHeader(val={'Type':86}),
        Uint('spare', bl=4, rep=REPR_HEX),
        Type1V('NAS_KSI', val={'V': 7}, IE=NAS_KSI()),
        Type4LV('ABBA', val={'V':b'\0\0'}),
        Type3TV('RAND', val={'T':0x21, 'V':16*b'\0'}, bl={'V':128}),
        Type4TLV('AUTN', val={'T':0x20, 'V':16*b'\0'}, IE=AUTN()),
        Type6TLVE('EAPMsg', val={'T':0x78, 'V':b'\0\0\0\0\0'})
        )


#------------------------------------------------------------------------------#
# Authentication response
# TS 24.501, section 8.2.2
#------------------------------------------------------------------------------#

class FGMMAuthenticationResponse(Layer3E):
    _name = '5GMMAuthenticationResponse'
    _GEN = (
        FGMMHeader(val={'Type':87}),
        Type4TLV('RES', val={'T':0x2D, 'V':16*b'\0'}),
        Type6TLVE('EAPMsg', val={'T':0x78, 'V':b'\0\0\0\0\0'})
        )


#------------------------------------------------------------------------------#
# Authentication result
# TS 24.501, section 8.2.3
#------------------------------------------------------------------------------#

class FGMMAuthenticationResult(Layer3E):
    _name = '5GMMAuthenticationResult'
    _GEN = (
        FGMMHeader(val={'Type':90}),
        Uint('spare', bl=4, rep=REPR_HEX),
        Type1V('NAS_KSI', val={'V':7}, IE=NAS_KSI()),
        Type6LVE('EAPMsg', val={'V':b'\0\0\0\0\0'}),
        Type4TLV('ABBA', val={'T':0x38, 'V':b'\0\0'})
        )


#------------------------------------------------------------------------------#
# Authentication failure
# TS 24.501, section 8.2.4
#------------------------------------------------------------------------------#

class FGMMAuthenticationFailure(Layer3E):
    _name = '5GMMAuthenticationFailure'
    _GEN = (
        FGMMHeader(val={'Type':89}),
        Type3V('5GMMCause', val={'V':b'\x16'}, bl={'V':8}, IE=FGMMCause()),
        Type4TLV('AUTS', val={'T':0x30, 'V':14*b'\0'})
        )


#------------------------------------------------------------------------------#
# Authentication reject
# TS 24.501, section 8.2.5
#------------------------------------------------------------------------------#

class FGMMAuthenticationReject(Layer3E):
    _name = '5GMMAuthenticationReject'
    _GEN = (
        FGMMHeader(val={'Type':88}),
        Type6TLVE('EAPMsg', val={'T':0x78, 'V':b'\0\0\0\0\0'})
        )


#------------------------------------------------------------------------------#
# Registration request
# TS 24.501, section 8.2.6
#------------------------------------------------------------------------------#

class FGMMRegistrationRequest(Layer3E):
    # clear-text IEs, 24.501, section 4.4.6
    _ies_ct = {
        'NAS_KSI',
        '5GSRegType',
        '5GSID',
        'UESecCap',
        'UEStatus',
        'AddGUTI',
        'EPSNASContainer'
        }
    #
    _name = '5GMMRegistrationRequest'
    #
    _GEN = (
        FGMMHeader(val={'Type':65}),
        Type1V('NAS_KSI', val={'V':7}, IE=NAS_KSI()),
        Type1V('5GSRegType', IE=FGSRegType()),
        Type6LVE('5GSID', val={'V':b'\0\0\0\0'}, IE=FGSID()),
        Type1TV('NonCurrentNativeNAS_KSI', val={'T':0xC, 'V':0}, IE=NAS_KSI()),
        Type4TLV('5GMMCap', val={'T':0x10, 'V':b'\0'}, IE=FGMMCap()),
        Type4TLV('UESecCap', val={'T':0x2E, 'V':b'\0\0'}, IE=UESecCap()),
        Type4TLV('NSSAI', val={'T':0x2F, 'V':b'\x01\x01'}, IE=NSSAI()),
        Type3TV('TAI', val={'T':0x52, 'V':6*b'\0'}, bl={'V':48}, IE=FGSTAI()),
        Type4TLV('EPSUENetCap', val={'T':0x17, 'V':b'\0\0'}, IE=EPSUENetCap()),
        Type4TLV('ULDataStat', val={'T':0x40, 'V':b'\0\0'}, IE=ULDataStat()),
        Type4TLV('PDUSessStat', val={'T':0x50, 'V':b'\0\0'}, IE=PDUSessStat()),
        Type1TV('MICOInd', val={'T':0xB, 'V':0}, IE=MICOInd()),
        Type4TLV('UEStatus', val={'T':0x2B, 'V':b'\0'}, IE=UEStatus()),
        Type6TLVE('AddGUTI', val={'T':0x77, 'V':b'\xf2'+10*b'\0'}, IE=FGSID()),
        Type4TLV('AllowedPDUSessStat', val={'T':0x25, 'V':b'\0\0'}, IE=PDUSessStat()),
        Type4TLV('UEUsage', val={'T':0x18, 'V':b'\0'}, IE=UEUsage()),
        Type4TLV('5GSDRXParam', val={'T':0x51, 'V':b'\0'}, IE=FGSDRXParam()),
        Type6TLVE('EPSNASContainer', val={'T':0x70, 'V':b'\x07\0'}),
        Type6TLVE('LADNInd', val={'T':0x74, 'V':b''}, IE=LADNInd()),
        Type1TV('PayloadContainerType', val={'T':0x8, 'V':1}, dic=PayloadContainerType_dict),
        Type6TLVE('PayloadContainer', val={'T':0x7B, 'V':b'\0'}),
        Type1TV('NetSlicingInd', val={'T':0x9, 'V':0}, IE=NetSlicingInd()),
        Type4TLV('5GSUpdateType', val={'T':0x53, 'V':b'\0'}, IE=FGSUpdateType()),
        Type4TLV('MSCm2', val={'T':0x41, 'V':b'@\0\0'}, IE=MSCm2()),
        Type4TLV('SuppCodecs', val={'T':0x42, 'V':b'\0\x01\0'}, IE=SuppCodecList()),
        Type6TLVE('NASContainer', val={'T':0x71, 'V':b'\0\0'}),
        Type4TLV('EPSBearerCtxtStat', val={'T':0x60, 'V':b'\0\0'}, IE=EPSBearerCtxtStat()),
        Type4TLV('ExtDRXParam', val={'T':0x6E, 'V':b'\0'}, IE=ExtDRXParam()),
        Type4TLV('T3324', val={'T':0x6A, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('UERadioCapID', val={'T':0x67, 'V':b'\0'}, IE=UERadioCapID()),
        Type4TLV('MappedNSSAI', val={'T':0x35, 'V':b'\0'}, IE=NSSAI('MappedNSSAI')),
        Type4TLV('AddInfoReq', val={'T':0x48, 'V':b'\0'}, IE=AddInfoReq()),
        Type4TLV('WUSAssistInfo', val={'T':0x1A, 'V':b'\0'}),
        Type2('N5GCInd', val={'T':0xA}),
        Type4TLV('NBN1ModeDRXParam', val={'T':0x30, 'V':b'\0'}, IE=NBN1ModeDRXParam())
        )


#------------------------------------------------------------------------------#
# Registration accept
# TS 24.501, section 8.2.7
#------------------------------------------------------------------------------#

class FGMMRegistrationAccept(Layer3E):
    _name = '5GMMRegistrationAccept'
    _GEN = (
        FGMMHeader(val={'Type':66}),
        Type4LV('5GSRegResult', val={'V':b'\0'}, IE=FGSRegResult()),
        Type6TLVE('GUTI', val={'T': 0x77, 'V':b'\0\0\0\0'}, IE=FGSID()),
        Type4TLV('EquivPLMNList', val={'T':0x4A, 'V':3*b'\0'}, IE=PLMNList()),
        Type4TLV('5GSTAIList', val={'T':0x54, 'V':7*b'\0'}, IE=FGSTAIList()),
        Type4TLV('AllowedNSSAI', val={'T':0x15, 'V':b'\x01\x01'}, IE=NSSAI()),
        Type4TLV('RejectedNSSAI', val={'T':0x11, 'V':b'\x10\x01'}, IE=RejectedNSSAI()),
        Type4TLV('ConfiguredNSSAI', val={'T':0x31, 'V':b'\x01\x01'}, IE=NSSAI()),
        Type4TLV('5GSNetFeat', val={'T':0x21, 'V':b'\0'}, IE=FGSNetFeat()),
        Type4TLV('PDUSessStat', val={'T':0x50, 'V':b'\0\0'}, IE=PDUSessStat()),
        Type4TLV('PDUSessReactResult', val={'T':0x26, 'V':b'\0\0'}, IE=PDUSessStat()),
        Type6TLVE('PDUSessReactResultErr', val={'T':0x72, 'V':b'\0\0'}, IE=PDUSessReactResultErr()),
        Type6TLVE('LADNInfo', val={'T':0x79, 'V':9*b'\0'}, IE=LADNInfo()),
        Type1TV('MICOInd', val={'T':0xB, 'V':0}, IE=MICOInd()),
        Type1TV('NetSlicingInd', val={'T':0x9, 'V':0}, IE=NetSlicingInd()),
        Type4TLV('SAList', val={'T':0x27, 'V':b'\0\0\0'}, IE=SAList()),
        Type4TLV('T3512', val={'T':0x5E, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('Non3GPPDeregTimer', val={'T':0x5D, 'V':b'\0'}, IE=GPRSTimer()),
        Type4TLV('T3502', val={'T':0x16, 'V':b'\0'}, IE=GPRSTimer()),
        Type4TLV('EmergNumList', val={'T':0x34, 'V':b'\x02\x01\0'}, IE=EmergNumList()),
        Type6TLVE('ExtEmergNumList', val={'T':0x7A, 'V':b'\0\0\0\0'}, IE=ExtEmergNumList()),
        Type6TLVE('SORTransContainer', val={'T':0x73, 'V':17*b'\0'}, IE=SORTransContainer()),
        Type6TLVE('EAPMsg', val={'T':0x78, 'V':b'\0\0\0\0\0'}),
        Type1TV('NSSAIInclMode', val={'T':0xA, 'V':0}, IE=NSSAIInclMode()),
        Type6TLVE('OperatorAccessCatDefs', val={'T':0x76, 'V':b''}, IE=OperatorAccessCatDefs()),
        Type4TLV('5GSDRXParam', val={'T':0x51, 'V':b'\0'}, IE=FGSDRXParam()),
        Type1TV('Non3GPPNWProvPol', val={'T':0xD, 'V':0}, IE=Non3GPPNWProvPol()),
        Type4TLV('EPSBearerCtxtStat', val={'T':0x60, 'V':b'\0\0'}, IE=EPSBearerCtxtStat()),
        Type4TLV('ExtDRXParam', val={'T':0x6E, 'V':b'\0'}, IE=ExtDRXParam()),
        Type4TLV('T3447', val={'T':0x6C, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('T3448', val={'T':0x6B, 'V':b'\0'}, IE=GPRSTimer()),
        Type4TLV('T3324', val={'T':0x6A, 'V':b'\0'}, IE=GPRSTimer()),
        Type4TLV('UERadioCapID', val={'T':0x67, 'V':b'\0'}, IE=UERadioCapID()),
        Type4TLV('PendingNSSAI', val={'T':0x39, 'V':b'\x01\x01'}, IE=NSSAI()),
        Type6TLVE('CipheringKeyData', val={'T':0x74, 'V':31*b'\0'}, IE=CipheringKeyData()),
        Type6TLVE('CAGInfoList', val={'T':0x75, 'V':b''}, IE=CAGInfoList()),
        Type4TLV('Trunc5GSTMSIConfig', val={'T':0x1B, 'V':b'\0'}, IE=Trunc5GSTMSIConfig()),
        Type4TLV('WUSAssistInfo', val={'T':0x1A, 'V':b'\0'}),
        Type4TLV('NBN1ModeDRXParam', val={'T':0x29, 'V':b'\0'}, IE=NBN1ModeDRXParam())
        )


#------------------------------------------------------------------------------#
# Registration complete
# TS 24.501, section 8.2.8
#------------------------------------------------------------------------------#

class FGMMRegistrationComplete(Layer3E):
    _name = '5GMMRegistrationComplete'
    _GEN = (
        FGMMHeader(val={'Type':67}),
        Type6TLVE('SORTransContainer', val={'T':0x73, 'V':17*b'\0'}, IE=SORTransContainer())
        )


#------------------------------------------------------------------------------#
# Registration reject
# TS 24.501, section 8.2.9
#------------------------------------------------------------------------------#

class FGMMRegistrationReject(Layer3E):
    _name = '5GMMRegistrationReject'
    _GEN = (
        FGMMHeader(val={'Type':68}),
        Type3V('5GMMCause', val={'V':b'\x16'}, bl={'V':8}, IE=FGMMCause()),
        Type4TLV('T3346', val={'T':0x5F, 'V':b'\0'}, IE=GPRSTimer()),
        Type4TLV('T3502', val={'T':0x16, 'V':b'\0'}, IE=GPRSTimer()),
        Type6TLVE('EAPMsg', val={'T':0x78, 'V':b'\0\0\0\0\0'}),
        Type4TLV('RejectedNSSAI', val={'T':0x69, 'V':b'\x10\x01'}, IE=RejectedNSSAI()),
        Type6TLVE('CAGInfoList', val={'T':0x75, 'V':b''}, IE=CAGInfoList())
        )


#------------------------------------------------------------------------------#
# UL NAS transport
# TS 24.501, section 8.2.10
#------------------------------------------------------------------------------#

class FGMMULNASTransport(Layer3E):
    _name = '5GMMULNASTransport'
    _GEN = (
        FGMMHeader(val={'Type':103}),
        Uint('spare', bl=4, rep=REPR_HEX),
        Type1V('PayloadContainerType', val={'V':1}, dic=PayloadContainerType_dict),
        Type6LVE('PayloadContainer', val={'V':b'\0'}),
        Type3TV('PDUSessID', val={'T':0x12, 'V':b'\0'}, bl={'V':8}, IE=PDUSessID()),
        Type3TV('OldPDUSessID', val={'T':0x59, 'V':b'\0'}, bl={'V':8}, IE=PDUSessID()),
        Type1TV('RequestType', val={'T':0x8, 'V':0}, IE=RequestType()),
        Type4TLV('SNSSAI', val={'T':0x22, 'V':b'\x01'}, IE=SNSSAI()),
        Type4TLV('DNN', val={'T':0x25, 'V':b'\0'}, IE=APN('DNN')),
        Type4TLV('AddInfo', val={'T':0x24, 'V':b'\0'}),
        Type1TV('MAPDUSessInfo', val={'T':0xA, 'V':1}, dic=MAPDUSessInfo_dict),
        Type1TV('ReleaseAssistInd', val={'T':0xF, 'V':0}, IE=ReleaseAssistInd()),
        )


#------------------------------------------------------------------------------#
# DL NAS transport
# TS 24.501, section 8.2.11
#------------------------------------------------------------------------------#

class FGMMDLNASTransport(Layer3E):
    _name = '5GMMDLNASTransport'
    _GEN = (
        FGMMHeader(val={'Type':104}),
        Uint('spare', bl=4, rep=REPR_HEX),
        Type1V('PayloadContainerType', val={'V':1}, dic=PayloadContainerType_dict),
        Type6LVE('PayloadContainer', val={'V':b'\0'}),
        Type3TV('PDUSessID', val={'T':0x12, 'V':b'\0'}, bl={'V':8}, IE=PDUSessID()),
        Type4TLV('AddInfo', val={'T':0x24, 'V':b'\0'}),
        Type3TV('5GMMCause', val={'T':0x58, 'V':b'\x16'}, bl={'V':8}, IE=FGMMCause()),
        Type4TLV('BackOffTimer', val={'T':0x37, 'V':b'\0'}, IE=GPRSTimer3())
        )


#------------------------------------------------------------------------------#
# De-registration request (UE originating de-registration)
# TS 24.501, section 8.2.12
#------------------------------------------------------------------------------#

class FGMMMODeregistrationRequest(Layer3E):
    _name = '5GMMMODeregistrationRequest'
    _GEN = (
        FGMMHeader(val={'Type':69}),
        Type1V('NAS_KSI', val={'V':7}, IE=NAS_KSI()),
        Type1V('DeregistrationType', val={'V':1}, IE=DeregistrationType()),
        Type6LVE('5GSID', val={'V':b'\0\0\0\0'}, IE=FGSID())
        )


#------------------------------------------------------------------------------#
# De-registration accept (UE originating de-registration)
# TS 24.501, section 8.2.13
#------------------------------------------------------------------------------#

class FGMMMODeregistrationAccept(Layer3E):
    _name = '5GMMMODeregistrationAccept'
    _GEN = (
        FGMMHeader(val={'Type':70}),
        )


#------------------------------------------------------------------------------#
# De-registration request (UE terminated de-registration)
# TS 24.501, section 8.2.14
#------------------------------------------------------------------------------#

class FGMMMTDeregistrationRequest(Layer3E):
    _name = '5GMMMTDeregistrationRequest'
    _GEN = (
        FGMMHeader(val={'Type':71}),
        Uint('spare', bl=4, rep=REPR_HEX),
        Type1V('DeregistrationType', val={'V':1}, IE=DeregistrationType()),
        Type3TV('5GMMCause', val={'T':0x58, 'V':b'\x16'}, bl={'V':8}, IE=FGMMCause()),
        Type4TLV('T3346', val={'T':0x5F, 'V':b'\0'}, IE=GPRSTimer()),
        Type4TLV('RejectedNSSAI', val={'T':0x6D, 'V':b'\x10\x01'}, IE=RejectedNSSAI())
        )


#------------------------------------------------------------------------------#
# De-registration accept (UE terminated de-registration)
# TS 24.501, section 8.2.15
#------------------------------------------------------------------------------#

class FGMMMTDeregistrationAccept(Layer3E):
    _name = '5GMMMTDeregistrationAccept'
    _GEN = (
        FGMMHeader(val={'Type':71}),
        )


#------------------------------------------------------------------------------#
# Service request
# TS 24.501, section 8.2.16
#------------------------------------------------------------------------------#

class FGMMServiceRequest(Layer3E):
    # clear-text IEs, 24.501, section 4.4.6
    _ies_ct = {
        'ServiceType',
        'NAS_KSI',
        '5GSID'
        }
    #
    _name = '5GMMServiceRequest'
    #
    _GEN = (
        FGMMHeader(val={'Type':76}),
        Type1V('ServiceType', val={'V':0}, dic=ServiceType_dict),
        Type1V('NAS_KSI', val={'V':7}, IE=NAS_KSI()),
        Type6LVE('5GSID', val={'V':b'\0\0\0\0'}, IE=FGSID()),
        Type4TLV('ULDataStat', val={'T':0x40, 'V':b'\0\0'}, IE=ULDataStat()),
        Type4TLV('PDUSessStat', val={'T':0x50, 'V':b'\0\0'}, IE=PDUSessStat()),
        Type4TLV('AllowedPDUSessStat', val={'T':0x25, 'V':b'\0\0'}, IE=PDUSessStat()),
        Type6TLVE('NASContainer', val={'T':0x71, 'V':b'\0\0'})
        )


#------------------------------------------------------------------------------#
# Service accept
# TS 24.501, section 8.2.17
#------------------------------------------------------------------------------#

class FGMMServiceAccept(Layer3E):
    _name = '5GMMServiceAccept'
    _GEN = (
        FGMMHeader(val={'Type':78}),
        Type4TLV('PDUSessStat', val={'T':0x50, 'V':b'\0\0'}, IE=PDUSessStat()),
        Type4TLV('PDUSessReactResult', val={'T':0x26, 'V':b'\0\0'}, IE=PDUSessStat()),
        Type6TLVE('PDUSessReactResultErr', val={'T':0x72, 'V':b'\0\0'}, IE=PDUSessReactResultErr()),
        Type6TLVE('EAPMsg', val={'T':0x78, 'V':b'\0\0\0\0\0'}),
        Type4TLV('T3448', val={'T':0x6B, 'V':b'\0'}, IE=GPRSTimer())
        )


#------------------------------------------------------------------------------#
# Service reject
# TS 24.501, section 8.2.18
#------------------------------------------------------------------------------#

class FGMMServiceReject(Layer3E):
    _name = '5GMMServiceAccept'
    _GEN = (
        FGMMHeader(val={'Type':77}),
        Type3V('5GMMCause', val={'V':b'\x16'}, bl={'V':8}, IE=FGMMCause()),
        Type4TLV('PDUSessStat', val={'T':0x50, 'V':b'\0\0'}, IE=PDUSessStat()),
        Type4TLV('T3346', val={'T':0x5F, 'V':b'\0'}, IE=GPRSTimer()),
        Type6TLVE('EAPMsg', val={'T':0x78, 'V':b'\0\0\0\0\0'}),
        Type4TLV('T3448', val={'T':0x6B, 'V':b'\0'}, IE=GPRSTimer()),
        Type6TLVE('CAGInfoList', val={'T':0x75, 'V':b''}, IE=CAGInfoList())
        )


#------------------------------------------------------------------------------#
# Configuration update command
# TS 24.501, section 8.2.19
#------------------------------------------------------------------------------#

class FGMMConfigurationUpdateCommand(Layer3E):
    _name = '5GMMConfigurationUpdateCommand'
    _GEN = (
        FGMMHeader(val={'Type':84}),
        Type1TV('ConfigUpdateInd', val={'T':0xD, 'V':0}, IE=ConfigUpdateInd()),
        Type6TLVE('GUTI', val={'T':0x77, 'V':b'\0\0\0\0'}, IE=FGSID()),
        Type4TLV('5GSTAIList', val={'T':0x54, 'V':7*b'\0'}, IE=FGSTAIList()),
        Type4TLV('AllowedNSSAI', val={'T':0x15, 'V':b'\x01\x01'}, IE=NSSAI()),
        Type4TLV('SAList', val={'T':0x27, 'V':b'\0\0\0'}, IE=SAList()),
        Type4TLV('NetFullName', val={'T':0x43, 'V':b'\0'}, IE=NetworkName()),
        Type4TLV('NetShortName', val={'T':0x45, 'V':b'\0'}, IE=NetworkName()),
        Type3TV('LocalTimeZone', val={'T':0x46, 'V':b'\0'}, bl={'V':8}, IE=TimeZone()),
        Type3TV('UnivTimeAndTimeZone', val={'T':0x47, 'V':7*b'\0'}, bl={'V':56}, IE=TimeZoneTime()),
        Type4TLV('DLSavingTime', val={'T':0x49, 'V':b'\0'}, IE=DLSavingTime()),
        Type6TLVE('LADNInfo', val={'T':0x79, 'V':9*b'\0'}, IE=LADNInfo()),
        Type1TV('MICOInd', val={'T':0xB, 'V':0}, IE=MICOInd()),
        Type1TV('NetSlicingInd', val={'T':0x9, 'V':0}, IE=NetSlicingInd()),
        Type4TLV('ConfiguredNSSAI', val={'T':0x31, 'V':b'\x01\x01'}, IE=NSSAI()),
        Type4TLV('RejectedNSSAI', val={'T':0x11, 'V':b'\x10\x01'}, IE=RejectedNSSAI()),
        Type6TLVE('OperatorAccessCatDefs', val={'T':0x76, 'V':b''}, IE=OperatorAccessCatDefs()),
        Type1TV('SMSInd', val={'T':0xF, 'V':0}, IE=SMSInd()),
        Type4TLV('T3447', val={'T':0x6C, 'V':b'\0'}, IE=GPRSTimer3()),
        Type6TLVE('CAGInfoList', val={'T':0x75, 'V':b''}, IE=CAGInfoList()),
        Type4TLV('UERadioCapID', val={'T':0x67, 'V':b'\0'}, IE=UERadioCapID()),
        Type1TV('UERadioCapIDDelInd', val={'T':0xA, 'V':0}, IE=UERadioCapIDDelInd()),
        Type4TLV('5GSRegResult', val={'T':0x44, 'V':b'\0'}, IE=FGSRegResult()),
        Type4TLV('Trunc5GSTMSIConfig', val={'T':0x1B, 'V':b'\0'}, IE=Trunc5GSTMSIConfig()),
        Type1TV('AddConfigInd', val={'T':0xC, 'V':0}, IE=AddConfigInd())
        )


#------------------------------------------------------------------------------#
# Configuration update complete
# TS 24.501, section 8.2.20
#------------------------------------------------------------------------------#

class FGMMConfigurationUpdateComplete(Layer3E):
    _name = '5GMMConfigurationUpdateComplete'
    _GEN = (
        FGMMHeader(val={'Type':85}),
        )


#------------------------------------------------------------------------------#
# Identity request
# TS 24.501, section 8.2.21
#------------------------------------------------------------------------------#

class FGMMIdentityRequest(Layer3E):
    _name = '5GMMIdentityRequest'
    _GEN = (
        FGMMHeader(val={'Type':91}),
        Uint('spare', bl=4, rep=REPR_HEX),
        Type1V('5GSIDType', val={'V':1}, IE=FGSIDType())
        )


#------------------------------------------------------------------------------#
# Identity response
# TS 24.501, section 8.2.22
#------------------------------------------------------------------------------#

class FGMMIdentityResponse(Layer3E):
    _name = '5GMMIdentityResponse'
    _GEN = (
        FGMMHeader(val={'Type':92}),
        Type6LVE('5GSID', val={'V':b'\0'}, IE=FGSID())
        )


#------------------------------------------------------------------------------#
# Notification
# TS 24.501, section 8.2.23
#------------------------------------------------------------------------------#

class FGMMNotification(Layer3E):
    _name = '5GMMNotification'
    _GEN = (
        FGMMHeader(val={'Type':101}),
        Uint('spare', bl=4, rep=REPR_HEX),
        Type1V('AccessType', val={'V':1}, IE=AccessType())
        )


#------------------------------------------------------------------------------#
# Notification response
# TS 24.501, section 8.2.24
#------------------------------------------------------------------------------#

class FGMMNotificationResponse(Layer3E):
    _name = '5GMMNotificationResponse'
    _GEN = (
        FGMMHeader(val={'Type':102}),
        Type4TLV('PDUSessStat', val={'T':0x50, 'V':b'\0\0'}, IE=PDUSessStat())
        )


#------------------------------------------------------------------------------#
# Security mode command
# TS 24.501, section 8.2.25
#------------------------------------------------------------------------------#

class FGMMSecurityModeCommand(Layer3E):
    _name = '5GMMSecurityModeCommand'
    _GEN = (
        FGMMHeader(val={'Type':93}),
        Type3V('NASSecAlgo', val={'V':b'\x11'}, bl={'V':8}, IE=NASSecAlgo()),
        Uint('spare', bl=4, rep=REPR_HEX),
        Type1V('NAS_KSI', val={'V':0}, IE=NAS_KSI()),
        Type4LV('UESecCap', val={'V':b'\0\0'}, IE=UESecCap()),
        Type1TV('IMEISVReq', val={'T':0xE, 'V':0}, IE=IMEISVReq()),
        Type3TV('EPSNASSecAlgo', val={'T':0x57, 'V':b'\x11'}, bl={'V':8}, IE=EPSNASSecAlgo()),
        Type4TLV('Add5GSecInfo', val={'T':0x36, 'V':b'\0'}, IE=Add5GSecInfo()),
        Type6TLVE('EAPMsg', val={'T':0x78, 'V':b'\0\0\0\0\0'}),
        Type4TLV('ABBA', val={'T':0x38, 'V':b'\0\0'}),
        Type4TLV('S1UESecCap', val={'T':0x19, 'V':b'\0\0'}, IE=S1UESecCap())
        )


#------------------------------------------------------------------------------#
# Security mode complete
# TS 24.501, section 8.2.26
#------------------------------------------------------------------------------#

class FGMMSecurityModeComplete(Layer3E):
    _name = '5GMMSecurityModeComplete'
    _GEN = (
        FGMMHeader(val={'Type':94}),
        Type6TLVE('IMEISV', val={'T':0x77, 'V':9*b'\0'}, IE=FGSID()), # IMEISV
        Type6TLVE('NASContainer', val={'T':0x71, 'V':b'\0\0'}),
        Type6TLVE('PEI', val={'T':0x78, 'V':b'\0\0\0\0\0'}, IE=FGSID())
        )


#------------------------------------------------------------------------------#
# Security mode reject
# TS 24.501, section 8.2.27
#------------------------------------------------------------------------------#

class FGMMSecurityModeReject(Layer3E):
    _name = '5GMMSecurityModeReject'
    _GEN = (
        FGMMHeader(val={'Type':95}),
        Type3V('5GMMCause', val={'V':b'\x18'}, bl={'V':8}, IE=FGMMCause())
        )


#------------------------------------------------------------------------------#
# Security protected 5GS NAS message
# TS 24.501, section 8.2.28
#------------------------------------------------------------------------------#

if _with_cm:
    
    class FGMMSecProtNASMessage(Layer3E):
        _name = '5GMMSecProtNASMessage'
        _GEN = (
            FGMMHeaderSec(),
            Buf('MAC', val=b'\0\0\0\0', bl=32, rep=REPR_HEX),
            Uint8('Seqn'),
            Buf('NASMessage', rep=REPR_HEX)
            )
        
        def mac_verify(self, key=16*b'\0', dir=0, fgia=0, seqnoff=0, bearer=1):
            """compute the MAC of the NASMessage using Seqn plus seqnoff, key, 
            direction, bearer and fgia, and verify against the embedded MAC value
            
            Args:
                key: 16 bytes buffer, K_nas_int
                dir: 0 for uplink, 1 for downlink
                fgia: 0 to 3, reference to the 5G-IA algorithm
                seqnoff: uint16, NAS OVERFLOW offset to add to the uint8 Seqn in the header
                bearer: 1 for NAS over 3GPP access, 2 for NAS over non-3GPP access
            
            Returns:
                True if embedded MAC is correct, False otherwise
            """
            if fgia == 0:
                return True
            shdr = self[0][2].get_val()
            if shdr == 0:
                return True
            elif shdr in (1, 2, 3, 4):
                try:
                    FGIA = _FGIA[fgia]
                except KeyError:
                    raise(PycrateErr('5GMMSecProtNASMessage.mac_verify(): invalid 5G-IA identifier, {0}'\
                          .format(fgia)))
                mac = FGIA(key, seqnoff + self[2].get_val(), bearer, dir, self[2].to_bytes() + self[3].get_val())
                return mac == self[1].get_val()
            else:
                raise(PycrateErr('5GMMSecProtNASMessage.mac_verify(): invalid sec hdr value, {0}'\
                      .format(shdr)))
                #return False
        
        def mac_compute(self, key=16*b'\0', dir=0, fgia=0, seqnoff=0, bearer=1):
            """compute the MAC of the NASMessage using Seqn plus seqnoff, key, 
            direction, bearer and fgia, and set the embedded MAC value with it
            
            Args:
                key: 16 bytes buffer, K_nas_int
                dir: 0 for uplink, 1 for downlink
                fgia: 0 to 3, reference to the 5G-IA algorithm
                seqnoff: uint16, NAS OVERFLOW offset to add to the uint8 Seqn in the header
                bearer: 1 for NAS over 3GPP access, 2 for NAS over non-3GPP access
            
            Returns:
                None
            """
            if fgia == 0:
                self[1].set_val(b'\0\0\0\0')
                return
            shdr = self[0][2].get_val()
            if shdr == 0:
                self[1].set_val(b'\0\0\0\0')
            elif shdr in (1, 2, 3, 4):
                try:
                    FGIA = _FGIA[fgia]
                except KeyError:
                    raise(PycrateErr('5GMMSecProtNASMessage.mac_compute(): invalid 5G-IA identifier, {0}'\
                          .format(fgia)))
                mac = FGIA(key, seqnoff + self[2].get_val(), bearer, dir, self[2].to_bytes() + self[3].get_val())
                self[1].set_val(mac)
            else:
                raise(PycrateErr('5GMMSecProtNASMessage.mac_compute(): invalid sec hdr value, {0}'\
                      .format(shdr)))
        
        def encrypt(self, key=16*b'\0', dir=0, fgea=0, seqnoff=0, bearer=1):
            """encrypt the NASMessage in place using Seqn plus seqnoff, key, 
            direction, bearer and fgea
            
            Args:
                key: 16 bytes buffer, K_nas_enc
                dir: 0 for uplink, 1 for downlink
                fgea: 0 to 3, reference to the 5G-EA algorithm
                seqnoff: uint16, NAS OVERFLOW offset to add to the uint8 Seqn in the header
                bearer: 1 for NAS over 3GPP access, 2 for NAS over non-3GPP access
            
            Returns:
                None
            """
            if fgea == 0:
                return
            shdr = self[0][2].get_val()
            if shdr in (0, 1, 3):
                return
            elif shdr in (2, 4):
                try:
                    FGEA = _FGEA[fgea]
                except KeyError:
                    raise(PycrateErr('5GMMSecProtNASMessage.encrypt(): invalid 5G-EA identifier, {0}'\
                          .format(fgea)))
                self._dec_msg = self[3].to_bytes()
                self._enc_msg = FGEA(key, seqnoff + self[2].get_val(), bearer, dir, self._dec_msg)
                self[3].set_val(self._enc_msg)
            else:
                raise(PycrateErr('5GMMSecProtNASMessage.encrypt(): invalid sec hdr value, {0}'\
                      .format(shdr)))
        
        def decrypt(self, key=16*b'\0', dir=0, fgea=0, seqnoff=0, bearer=1):
            """decrypt the NASMessage in place using Seqn plus seqnoff, key, 
            direction, bearer and fgea
            
            Args:
                key: 16 bytes buffer, K_nas_enc
                dir: 0 for uplink, 1 for downlink
                fgea: 0 to 3, reference to the 5G-EA algorithm
                seqnoff: uint16, NAS OVERFLOW offset to add to the uint8 Seqn in the header
                bearer: 1 for NAS over 3GPP access, 2 for NAS over non-3GPP access
            
            Returns:
                None
            """
            if fgea == 0:
                return
            shdr = self[0][2].get_val()
            if shdr in (0, 1, 3):
                return
            elif shdr in (2, 4):
                try:
                    FGEA = _FGEA[fgea]
                except KeyError:
                    raise(PycrateErr('5GMMSecProtNASMessage.decrypt(): invalid 5G-EA identifier, {0}'\
                          .format(fgea)))
                self._enc_msg = self[3].to_bytes()
                self._dec_msg = FGEA(key, seqnoff + self[2].get_val(), bearer, dir, self._enc_msg)
                self[3].set_val(self._dec_msg)
            else:
                raise(PycrateErr('5GMMSecProtNASMessage.decrypt(): invalid sec hdr value, {0}'\
                      .format(shdr)))
    
else:
    
    class FGMMSecProtNASMessage(Layer3E):
        _name = '5GMMSecProtNASMessage'
        _GEN = (
            FGMMHeaderSec(),
            Buf('MAC', val=b'\0\0\0\0', bl=32, rep=REPR_HEX),
            Uint8('Seqn'),
            Buf('NASMessage', rep=REPR_HEX)
            )
            

#------------------------------------------------------------------------------#
# 5GMM status
# TS 24.501, section 8.2.29
#------------------------------------------------------------------------------#

class FGMMStatus(Layer3E):
    _name = '5GMMStatus'
    _GEN = (
        FGMMHeader(val={'Type':100}),
        Type3V('5GMMCause', val={'V':b'\x18'}, bl={'V':8}, IE=FGMMCause())
        )


#------------------------------------------------------------------------------#
# Control Plane Service request
# TS 24.501, section 8.2.30
#------------------------------------------------------------------------------#

class FGMMControlPlaneServiceRequest(Layer3E):
    # clear-text IEs, 24.501, section 4.4.6
    _ies_ct = {
        'NAS_KSI',
        'CtrlPlaneServiceType'
        }
    #
    _name = '5GMMControlPlaneServiceRequest'
    #
    _GEN = (
        FGMMHeader(val={'Type':79}),
        Type1V('NAS_KSI', val={'V':7}, IE=NAS_KSI()),
        Type1V('CtrlPlaneServiceType', val={'V':0}, IE=CtrlPlaneServiceType()),
        Type4TLV('CIoTSmallDataContainer', val={'T':0x6F, 'V':b'\x20\0'}, IE=CIoTSmallDataContainer()),
        Type1TV('PayloadContainerType', val={'T':0x8, 'V':1}, dic=PayloadContainerType_dict),
        Type6TLVE('PayloadContainer', val={'T':0x7B, 'V':b'\0'}),
        Type3TV('PDUSessID', val={'T':0x12, 'V':b'\0'}, bl={'V':8}, IE=PDUSessID()),
        Type4TLV('PDUSessStat', val={'T':0x50, 'V':b'\0\0'}, IE=PDUSessStat()),
        Type1TV('ReleaseAssistInd', val={'T':0xF, 'V':0}, IE=ReleaseAssistInd()),
        Type4TLV('ULDataStat', val={'T':0x40, 'V':b'\0\0'}, IE=ULDataStat()),
        Type6TLVE('NASContainer', val={'T':0x71, 'V':b'\0\0'}),
        Type4TLV('AddInfo', val={'T':0x24, 'V':b'\0'}),
        )


#------------------------------------------------------------------------------#
# Network slice-specific authentication command
# TS 24.501, section 8.2.31
#------------------------------------------------------------------------------#

class FGMMNetworkSliceSpecAuthCommand(Layer3E):
    _name = '5GMMNetworkSliceSpecAuthCommand'
    _GEN = (
        FGMMHeader(val={'Type':80}),
        Type4LV('SNSSAI', val={'V':b'\x01'}, IE=SNSSAI()),
        Type6LVE('EAPMsg', val={'V':b'\0\0\0\0\0'})
        )


#------------------------------------------------------------------------------#
# Network slice-specific authentication complete
# TS 24.501, section 8.2.31
#------------------------------------------------------------------------------#

class FGMMNetworkSliceSpecAuthComplete(Layer3E):
    _name = '5GMMNetworkSliceSpecAuthComplete'
    _GEN = (
        FGMMHeader(val={'Type':81}),
        Type4LV('SNSSAI', val={'V':b'\x01'}, IE=SNSSAI()),
        Type6LVE('EAPMsg', val={'V':b'\0\0\0\0\0'})
        )


#------------------------------------------------------------------------------#
# Network slice-specific authentication result
# TS 24.501, section 8.2.31
#------------------------------------------------------------------------------#

class FGMMNetworkSliceSpecAuthResult(Layer3E):
    _name = '5GMMNetworkSliceSpecAuthResult'
    _GEN = (
        FGMMHeader(val={'Type':82}),
        Type4LV('SNSSAI', val={'V':b'\x01'}, IE=SNSSAI()),
        Type6LVE('EAPMsg', val={'V':b'\0\0\0\0\0'})
        )


#------------------------------------------------------------------------------#
# 5GMM dispatcher
#------------------------------------------------------------------------------#
# special 5GMM message: FGMMSecProtNASMessage

FGMMTypeClasses = {
    65 : FGMMRegistrationRequest,
    66 : FGMMRegistrationAccept,
    67 : FGMMRegistrationComplete,
    68 : FGMMRegistrationReject,
    69 : FGMMMODeregistrationRequest,
    70 : FGMMMODeregistrationAccept,
    71 : FGMMMTDeregistrationRequest,
    72 : FGMMMTDeregistrationAccept,
    76 : FGMMServiceRequest,
    77 : FGMMServiceReject,
    78 : FGMMServiceAccept,
    79 : FGMMControlPlaneServiceRequest,
    80 : FGMMNetworkSliceSpecAuthCommand,
    81 : FGMMNetworkSliceSpecAuthComplete,
    82 : FGMMNetworkSliceSpecAuthResult,
    84 : FGMMConfigurationUpdateCommand,
    85 : FGMMConfigurationUpdateComplete,
    86 : FGMMAuthenticationRequest,
    87 : FGMMAuthenticationResponse,
    88 : FGMMAuthenticationReject,
    89 : FGMMAuthenticationFailure,
    90 : FGMMAuthenticationResult,
    91 : FGMMIdentityRequest,
    92 : FGMMIdentityResponse,
    93 : FGMMSecurityModeCommand,
    94 : FGMMSecurityModeComplete,
    95 : FGMMSecurityModeReject,
    100 : FGMMStatus,
    101 : FGMMNotification,
    102 : FGMMNotificationResponse,
    103 : FGMMULNASTransport,
    104 : FGMMDLNASTransport
    }

def get_5gmm_msg_instances():
    return {k: FGMMTypeClasses[k]() for k in FGMMTypeClasses}

