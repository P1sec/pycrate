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
# * File Name : pycrate_mobile/TS24301_EMM.py
# * Created : 2017-10-27
# * Authors : Benoit Michau 
# *--------------------------------------------------------
#*/

__all__ = [
    'EMMAttachAccept',
    'EMMAttachComplete',
    'EMMAttachReject',
    'EMMAttachRequest',
    'EMMAuthenticationFailure',
    'EMMAuthenticationReject',
    'EMMAuthenticationRequest',
    'EMMAuthenticationResponse',
    'EMMCPServiceRequest',
    'EMMCSServiceNotification',
    'EMMDetachAccept',
    'EMMDetachRequestMO',
    'EMMDetachRequestMT',
    'EMMDLGenericNASTransport',
    'EMMDLNASTransport',
    'EMMExtServiceRequest',
    'EMMGUTIReallocCommand',
    'EMMGUTIReallocComplete',
    'EMMIdentityRequest',
    'EMMIdentityResponse',
    'EMMInformation',
    'EMMSecurityModeCommand',
    'EMMSecurityModeComplete',
    'EMMSecurityModeReject',
    'EMMServiceAccept',
    'EMMServiceReject',
    'EMMStatus',
    'EMMTrackingAreaUpdateAccept',
    'EMMTrackingAreaUpdateComplete',
    'EMMTrackingAreaUpdateReject',
    'EMMTrackingAreaUpdateRequest',
    'EMMULGenericNASTransport',
    'EMMULNASTransport',
    #
    'EMMTypeMOClasses',
    'EMMTypeMTClasses',
    'get_emm_msg_mo_instances',
    'get_emm_msg_mt_instances',
    ]

#------------------------------------------------------------------------------#
# 3GPP TS 24.301: NAS protocol for EPS
# release 13 (g51)
#------------------------------------------------------------------------------#

from pycrate_core.utils import *
from pycrate_core.elt   import *
from pycrate_core.base  import *

from .TS24007     import *
from .TS24008_IE  import *
from .TS24301_IE  import *
from .TS24501_IE  import (
    UERadioCapID, UERadioCapIDDelInd, UEStatus,
    )
from .TS24301_ESM import ESMTypeClasses

try:
    from CryptoMobile import CM
except:
    _with_cm = False
    log('warning: CryptoMobile Python module not found, unable to handle LTE NAS security')
else:
    _with_cm = True
    if hasattr(CM, 'EEA2'):
        _EIA = {
            1 : CM.EIA1,
            2 : CM.EIA2,
            3 : CM.EIA3
            }
        _EEA = {
            1 : CM.EEA1,
            2 : CM.EEA2,
            3 : CM.EEA3
            }
    else:
        _EIA = {
            1 : CM.EIA1,
            3 : CM.EIA3
            }
        _EEA = {
            1 : CM.EEA1,
            3 : CM.EEA3
            }


#------------------------------------------------------------------------------#
# EPS Mobility Management header
# TS 24.301, section 9
#------------------------------------------------------------------------------#

# section 9.8
_EMM_dict = {
    # attach / detach
    65 : "Attach request",
    66 : "Attach accept",
    67 : "Attach complete",
    68 : "Attach reject",
    69 : "Detach request",
    70 : "Detach accept",
    # TAU
    72 : "Tracking area update request",
    73 : "Tracking area update accept",
    74 : "Tracking area update complete",
    75 : "Tracking area update reject",
    # serv request
    76 : "Extended service request",
    77 : "Control plane service request",
    78 : "Service reject",
    79 : "Service accept",
    # identification / authentication
    80 : "GUTI reallocation command",
    81 : "GUTI reallocation complete",
    82 : "Authentication request",
    83 : "Authentication response",
    84 : "Authentication reject",
    92 : "Authentication failure",
    85 : "Identity request",
    86 : "Identity response",
    93 : "Security mode command",
    94 : "Security mode complete",
    95 : "Security mode reject",
    # misc
    96 : "EMM status",
    97 : "EMM information",
    98 : "Downlink NAS transport",
    99 : "Uplink NAS transport",
    100 : "CS Service notification",
    104 : "Downlink generic NAS transport",
    105 : "Uplink generic NAS transport"
    }

class EMMHeader(Envelope):
    _GEN = (
        Uint('SecHdr', bl=4, dic=SecHdrType_dict),
        Uint('ProtDisc', val=7, bl=4, dic=ProtDisc_dict),
        Uint8('Type', val=96, dic=_EMM_dict)
        )


class EMMHeaderSec(Envelope):
    _GEN = (
        Uint('SecHdr', val=1, bl=4, dic=SecHdrType_dict),
        Uint('ProtDisc', val=7, bl=4, dic=ProtDisc_dict),
        )


class EMMHeaderServ(Envelope):
    _GEN = (
        Uint('SecHdr', val=1, bl=4, dic=SecHdrType_dict),
        Uint('ProtDisc', val=7, bl=4, dic=ProtDisc_dict),
        Uint8('Type', val=0, trans=True)
        )


#------------------------------------------------------------------------------#
# Attach accept
# TS 24.301, section 8.2.1
#------------------------------------------------------------------------------#

class EMMAttachAccept(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':66}),
        Uint('spare', bl=4),
        Type1V('EPSAttachResult', dic=EPSAttRes_dict),
        Type3V('T3412', val={'V':b'\0'}, bl={'V':8}, IE=GPRSTimer()),
        Type4LV('TAIList', val={'V':6*b'\0'}, IE=TAIList()),
        Type6LVE('ESMContainer', val={'V':b'\0\0\0'}),
        Type4TLV('GUTI', val={'T':0x50, 'V':b'\xf6'+10*b'\0'}, IE=EPSID()),
        Type3TV('LAI', val={'T':0x13, 'V':5*b'\0'}, bl={'V':40}, IE=LAI()),
        Type4TLV('ID', val={'T':0x23, 'V':b'\xf4\0\0\0\0'}, IE=ID()),
        Type3TV('EMMCause', val={'T':0x53, 'V':b'\0'}, bl={'V':8}, IE=EMMCause()),
        Type3TV('T3402', val={'T':0x17, 'V':b'\0'}, bl={'V':8}, IE=GPRSTimer()),
        Type3TV('T3423', val={'T':0x59, 'V':b'\0'}, bl={'V':8}, IE=GPRSTimer()),
        Type4TLV('EquivPLMNList', val={'T':0x4A, 'V':3*b'\0'}, IE=PLMNList()),
        Type4TLV('EmergNumList', val={'T':0x34, 'V':b'\x02\x01\0'}, IE=EmergNumList()),
        Type4TLV('EPSNetFeat', val={'T':0x64, 'V':b'\0\0'}, IE=EPSNetFeat()),
        Type1TV('AddUpdateRes', val={'T':0xF, 'V':0}, IE=AddUpdateRes()),
        Type4TLV('T3412Ext', val={'T':0x5E, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('T3324', val={'T':0x6A, 'V':b'\0'}, IE=GPRSTimer()),
        Type4TLV('ExtDRXParam', val={'T':0x6E, 'V':b'\0'}, IE=ExtDRXParam()),
        Type1TV('SMSServStat', val={'T':0xE, 'V':0}, IE=SMSServStat()),
        Type1TV('Non3GPPNWProvPol', val={'T':0xD, 'V':0}, IE=Non3GPPNWProvPol()),
        Type4TLV('T3448', val={'T':0x6B, 'V':b'\0'}, IE=GPRSTimer()),
        Type1TV('NetworkPol', val={'T':0xC, 'V':0}, IE=NetworkPol()),
        Type4TLV('T3447', val={'T':0x6C, 'V':b'\0'}, IE=GPRSTimer3()),
        Type6TLVE('ExtEmergNumList', val={'T':0x7A, 'V':b'\0\0\0\0'}, IE=ExtEmergNumList()),
        Type6TLVE('CipherKeyData', val={'T':0x7C, 'V':32*b'\0'}, IE=CipherKeyData()),
        Type4TLV('UERadioCapID', val={'T':0x66, 'V':b'\0'}, IE=UERadioCapID()),
        Type1TV('UERadioCapIDDelInd', val={'T':0xB, 'V':0}, IE=UERadioCapIDDelInd()),
        )


#------------------------------------------------------------------------------#
# Attach complete
# TS 24.301, section 8.2.2
#------------------------------------------------------------------------------#

class EMMAttachComplete(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':67}),
        Type6LVE('ESMContainer', val={'V':b'\0\0\0'}),
        )


#------------------------------------------------------------------------------#
# Attach reject
# TS 24.301, section 8.2.3
#------------------------------------------------------------------------------#

class EMMAttachReject(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':68}),
        Type3V('EMMCause', val={'V':b'\x11'}, bl={'V':8}, IE=EMMCause()),
        Type6TLVE('ESMContainer', val={'T':0x78, 'V':b'\0\0\0'}),
        Type4TLV('T3346', val={'T':0x5F, 'V':b'\0'}, IE=GPRSTimer()),
        Type4TLV('T3402', val={'T':0x16, 'V':b'\0'}, IE=GPRSTimer()),
        Type1TV('ExtEMMCause', val={'T':0xA, 'V':0}, IE=ExtEMMCause())
        )


#------------------------------------------------------------------------------#
# Attach request
# TS 24.301, section 8.2.4
#------------------------------------------------------------------------------#

class EMMAttachRequest(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':65}),
        Type1V('NAS_KSI', val={'V':7}, IE=NAS_KSI()),
        Type1V('EPSAttachType', dic=EPSAttType_dict),
        Type4LV('EPSID', val={'V':b'\xf6'+10*b'\0'}, IE=EPSID()),
        Type4LV('UENetCap', val={'V':b'\0\0'}, IE=UENetCap()),
        Type6LVE('ESMContainer', val={'V':b'\0\0\0'}),
        Type3TV('OldPTMSISign', val={'T':0x19, 'V':b'\0\0\0'}, bl={'V':24}),
        Type4TLV('AddGUTI', val={'T':0x50, 'V':b'\xf6'+10*b'\0'}, IE=EPSID()),
        Type3TV('OldTAI', val={'T':0x52, 'V':5*b'\0'}, bl={'V':40}, IE=TAI()),
        Type3TV('DRXParam', val={'T':0x5C, 'V':b'\0\0'}, bl={'V':16}, IE=DRXParam()),
        Type4TLV('MSNetCap', val={'T':0x31, 'V':b'\0\0'}, IE=ms_network_capability_value_part),
        Type3TV('OldLAI', val={'T':0x13, 'V':5*b'\0'}, bl={'V':40}, IE=LAI()),
        Type1TV('TMSIStatus', val={'T':0x9, 'V':0}, IE=TMSIStatus()),
        Type4TLV('MSCm2', val={'T':0x11, 'V':b'@\0\0'}, IE=MSCm2()),
        Type4TLV('MSCm3', val={'T':0x20, 'V':b''}, IE=classmark_3_value_part),
        Type4TLV('SuppCodecs', val={'T':0x40, 'V':b'\0\x01\0'}, IE=SuppCodecList()),
        Type1TV('AddUpdateType', val={'T':0xF, 'V':0}, IE=AddUpdateType()),
        Type4TLV('VoiceDomPref', val={'T':0x5D, 'V':b'\0'}, IE=VoiceDomPref()),
        Type1TV('DeviceProp', val={'T':0xD, 'V':0}, IE=DeviceProp()),
        Type1TV('OldGUTIType', val={'T':0xE, 'V':0}, IE=GUTIType()),
        Type1TV('MSNetFeatSupp', val={'T':0xC, 'V':0}, IE=MSNetFeatSupp()),
        Type4TLV('TMSIBasedNRICont', val={'T':0x10, 'V':b'\0\0'}, IE=NRICont()),
        Type4TLV('T3324', val={'T':0x6A, 'V':b'\0'}, IE=GPRSTimer()),
        Type4TLV('T3412Ext', val={'T':0x5E, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('ExtDRXParam', val={'T':0x6E, 'V':b'\0'}, IE=ExtDRXParam()),
        Type4TLV('UEAddSecCap', val={'T':0x6F, 'V':b'\0\0\0\0'}, IE=UEAddSecCap()),
        Type4TLV('UEStatus', val={'T':0x6D, 'V':b'\0'}, IE=UEStatus()),
        Type3TV('AddInfoReq', val={'T':0x17, 'V':b'\0'}, IE=AddInfoReq()),
        Type4TLV('N1UENetCap', val={'T':0x32, 'V':b'\0'}, IE=N1UENetCap()),
        Type1TV('UERadioCapIDAvail', val={'T':0xB, 'V':0}, IE=UERadioCapIDAvail()) # WNG: tag is undefined in current TS
        )


#------------------------------------------------------------------------------#
# Authentication failure 
# TS 24.301, section 8.2.5
#------------------------------------------------------------------------------#

class EMMAuthenticationFailure(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':92}),
        Type3V('EMMCause', val={'V':b'\x11'}, bl={'V':8}, IE=EMMCause()),
        Type4TLV('AUTS', val={'T':0x30, 'V':14*b'\0'})
        )


#------------------------------------------------------------------------------#
# Authentication reject
# TS 24.301, section 8.2.6
#------------------------------------------------------------------------------#

class EMMAuthenticationReject(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':84}),
        )


#------------------------------------------------------------------------------#
# Authentication request
# TS 24.301, section 8.2.7
#------------------------------------------------------------------------------#

class EMMAuthenticationRequest(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':82}),
        Uint('spare', bl=4),
        Type1V('NAS_KSI', val={'V':7}, IE=NAS_KSI()),
        Type3V('RAND', val={'V':16*b'\0'}, bl={'V':128}),
        Type4LV('AUTN', val={'V':16*b'\0'}, IE=AUTN())
        )


#------------------------------------------------------------------------------#
# Authentication response
# TS 24.301, section 8.2.8
#------------------------------------------------------------------------------#

class EMMAuthenticationResponse(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':83}),
        Type4LV('RES', val={'V':8*b'\0'})
        )


#------------------------------------------------------------------------------#
# CS service notification
# TS 24.301, section 8.2.9
#------------------------------------------------------------------------------#

class EMMCSServiceNotification(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':100}),
        Type3V('PagingIdentity', val={'V':b'\x01'}, bl={'V':8}, IE=PagingIdentity()),
        Type4TLV('CLI', val={'T':0x60, 'V':b'\x91'}, IE=CallingPartyBCDNumber()),
        Type3TV('SSCode', val={'T':0x61, 'V':b'\0'}, bl={'V':8}, IE=SSCode()),
        Type3TV('LCSInd', val={'T':0x62, 'V':b'\x01'}, bl={'V':8}, IE=LCSInd()),
        Type4TLV('LCSClientId', val={'T':0x63, 'V':b''}, IE=LCSClientId())
        )


#------------------------------------------------------------------------------#
# Detach accept
# TS 24.301, 8.2.10
#------------------------------------------------------------------------------#

class EMMDetachAccept(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':70}),
        )


#------------------------------------------------------------------------------#
# Detach request (UE originating detach)
# TS 24.301, section 8.2.11.1
#------------------------------------------------------------------------------#

class EMMDetachRequestMO(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':69}),
        Type1V('NAS_KSI', val={'V':7}, IE=NAS_KSI()),
        Type1V('EPSDetachType', IE=EPSDetachTypeMO()),
        Type4LV('EPSID', val={'V':b'\xf6'+10*b'\0'}, IE=EPSID())
        )


#------------------------------------------------------------------------------#
# Detach request (UE terminated detach)
# TS 24.301, section 8.2.11.2
#------------------------------------------------------------------------------#

class EMMDetachRequestMT(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':69}),
        Uint('spare', bl=4),
        Type1V('EPSDetachType', IE=EPSDetachTypeMT()),
        Type3TV('EMMCause', val={'T':0x53, 'V':b'\0'}, bl={'V':8}, IE=EMMCause())
        )


#------------------------------------------------------------------------------#
# Downlink NAS Transport
# TS 24.301, section 8.2.12
#------------------------------------------------------------------------------#

class EMMDLNASTransport(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':98}),
        Type4LV('NASContainer', val={'V':b'\0\0'})
        )


#------------------------------------------------------------------------------#
# EMM information
# TS 24.301, section 8.2.13
#------------------------------------------------------------------------------#

class EMMInformation(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':97}),
        Type4TLV('NetFullName', val={'T':0x43, 'V':b'\0'}, IE=NetworkName()),
        Type4TLV('NetShortName', val={'T':0x45, 'V':b'\0'}, IE=NetworkName()),
        Type3TV('LocalTimeZone', val={'T':0x46, 'V':b'\0'}, bl={'V':8}, IE=TimeZone()),
        Type3TV('UnivTimeAndTimeZone', val={'T':0x47, 'V':7*b'\0'}, bl={'V':56},
                IE=TimeZoneTime()),
        Type4TLV('DLSavingTime', val={'T':0x49, 'V':b'\0'}, IE=DLSavingTime())
        )


#------------------------------------------------------------------------------#
# EMM status
# TS 24.301, section 8.2.14
#------------------------------------------------------------------------------#

class EMMStatus(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':96}),
        Type3V('EMMCause', val={'V':b'\x11'}, bl={'V':8}, IE=EMMCause())
        )


#------------------------------------------------------------------------------#
# Extended service request
# TS 24.301, section 8.2.15
#------------------------------------------------------------------------------#

class EMMExtServiceRequest(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':76}),
        Type1V('NAS_KSI', val={'V':7}, IE=NAS_KSI()),
        Type1V('ServiceType', dic=EMMServType_dict),
        Type4LV('MTMSI', val={'V':b'\xf4\0\0\0\0'}, IE=ID()),
        Type1TV('CSFBResponse', val={'T':0xB, 'V':0}, IE=CSFBResponse()),
        Type4TLV('EPSBearerCtxtStat', val={'T':0x57, 'V':b'\0\0'}, IE=EPSBearerCtxtStat()),
        Type1TV('DeviceProp', val={'T':0xD, 'V':0}, IE=DeviceProp())
        )


#------------------------------------------------------------------------------#
# GUTI reallocation command
# TS 24.301, section 8.2.16
#------------------------------------------------------------------------------#

class EMMGUTIReallocCommand(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':80}),
        Type4LV('GUTI', val={'V':b'\xf6'+10*b'\0'}, IE=EPSID()),
        Type4TLV('TAIList', val={'T':0x54, 'V':6*b'\0'}, IE=TAIList()),
        Type4TLV('DCNID', val={'T':0x65, 'V':b'\0\0'}, IE=DCNID()),
        Type4TLV('UERadioCapID', val={'T':0x66, 'V':b'\0'}, IE=UERadioCapID()),
        Type1TV('UERadioCapIDDelInd', val={'T':0xB, 'V':0}, IE=UERadioCapIDDelInd()),
        )


#------------------------------------------------------------------------------#
# GUTI reallocation complete
# TS 24.301, section 8.2.17
#------------------------------------------------------------------------------#

class EMMGUTIReallocComplete(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':81}),
        )


#------------------------------------------------------------------------------#
# Identity request
# TS 24.301, section 8.2.18
#------------------------------------------------------------------------------#

class EMMIdentityRequest(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':85}),
        Uint('spare', bl=4),
        Type1V('IDType', val={'V':IDTYPE_IMSI}, dic=IDType_dict)
        )


#------------------------------------------------------------------------------#
# Identity response
# TS 24.301, section 8.2.19
#------------------------------------------------------------------------------#

class EMMIdentityResponse(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':86}),
        Type4LV('ID', val={'V':b'\xf4\0\0\0\0'}, IE=ID())
        )


#------------------------------------------------------------------------------#
# Security mode command
# TS 24.301, section 8.2.20
#------------------------------------------------------------------------------#

class EMMSecurityModeCommand(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':93}),
        Type3V('NASSecAlgo', val={'V':b'\x11'}, bl={'V':8}, IE=NASSecAlgo()),
        Uint('spare', bl=4),
        Type1V('NAS_KSI', val={'V':0}, IE=NAS_KSI()),
        Type4LV('UESecCap', val={'V':b'\0\0'}, IE=UESecCap()),
        Type1TV('IMEISVReq', val={'T':0xC, 'V':0}, IE=IMEISVReq()),
        Type3TV('NonceUE', val={'T':0x55, 'V':b'\0\0\0\0'}, bl={'V':32}),
        Type3TV('NonceMME', val={'T':0x56, 'V':b'\0\0\0\0'}, bl={'V':32}),
        Type4TLV('HashMME', val={'T':0x4F, 'V':8*b'\0'}),
        Type4TLV('UEAddSecCap', val={'T':0x6F, 'V':b'\0\0\0\0'}, IE=UEAddSecCap()),
        Type1TV('UERadioCapIDReq', val={'T':0xD, 'V':0}, IE=UERadioCapIDReq())
        )


#------------------------------------------------------------------------------#
# Security mode complete
# TS 24.301, section 8.2.21
#------------------------------------------------------------------------------#

class EMMSecurityModeComplete(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':94}),
        Type4TLV('IMEISV', val={'T':0x23, 'V':b'\x03\0\0\0\0\0\0\0\xf0'}, IE=ID()),
        Type6TLVE('NASMessage', val={'T':0x79, 'V':b'\x07\0'}),
        Type4TLV('UERadioCapID', val={'T':0x66, 'V':b'\0'}, IE=UERadioCapID())
        )


#------------------------------------------------------------------------------#
# Security mode reject
# TS 24.301, section 8.2.22
#------------------------------------------------------------------------------#

class EMMSecurityModeReject(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':95}),
        Type3V('EMMCause', val={'V':b'\x11'}, bl={'V':8}, IE=EMMCause())
        )


#------------------------------------------------------------------------------#
# Security protected NAS message
# TS 24.301, section 8.2.23
#------------------------------------------------------------------------------#

if _with_cm:
    
    class EMMSecProtNASMessage(Layer3E):
        _GEN = (
            EMMHeaderSec(),
            Buf('MAC', val=b'\0\0\0\0', bl=32, rep=REPR_HEX),
            Uint8('Seqn'),
            Buf('NASMessage')
            )
        
        def mac_verify(self, key=16*b'\0', dir=0, eia=0, seqnoff=0):
            """compute the MAC of the NASMessage using Seqn plus seqnoff, key, 
            direction and eia, and verify against the embedded MAC value
            
            Args:
                key: 16 bytes buffer, K_nas_int
                dir: 0 for uplink, 1 for downlink
                eia: 0 to 3, reference to EIA algorithm
                seqnoff: 0 to 2^32 - 2^8, NAS count offset to add to Seqn
            
            Returns:
                True if embedded MAC is correct, False otherwise
            """
            if eia == 0:
                return True
            shdr = self[0][0].get_val()
            if shdr == 0:
                return True
            elif shdr in (1, 2, 3, 4):
                try:
                    EIA = _EIA[eia]
                except KeyError:
                    raise(PycrateErr('EMMSecProtNASMessage.mac_verify(): invalid EIA identifier, {0}'\
                          .format(eia)))
                mac = EIA(key, seqnoff + self[2].get_val(), 0, dir, self[2].to_bytes() + self[3].get_val())
                return mac == self[1].get_val()
            else:
                raise(PycrateErr('EMMSecProtNASMessage.mac_verify(): invalid sec hdr value, {0}'\
                      .format(shdr)))
        
        def mac_compute(self, key=16*b'\0', dir=0, eia=0, seqnoff=0):
            """compute the MAC of the NASMessage using Seqn plus seqnoff, key, 
            direction and eia, and set the embedded MAC value with it
            
            Args:
                key: 16 bytes buffer, K_nas_int
                dir: 0 for uplink, 1 for downlink
                eia: 0 to 3, reference to EIA algorithm
                seqnoff: 0 to 2^32 - 2^8, NAS count offset to add to Seqn
            
            Returns:
                None
            """
            if eia == 0:
                self[1].set_val(b'\0\0\0\0')
                return
            shdr = self[0][0].get_val()
            if shdr == 0:
                self[1].set_val(b'\0\0\0\0')
            elif shdr in (1, 2, 3, 4):
                try:
                    EIA = _EIA[eia]
                except KeyError:
                    raise(PycrateErr('EMMSecProtNASMessage.mac_compute(): invalid EIA identifier, {0}'\
                          .format(eia)))
                mac = EIA(key, seqnoff + self[2].get_val(), 0, dir, self[2].to_bytes() + self[3].get_val())
                self[1].set_val(mac)
            else:
                raise(PycrateErr('EMMSecProtNASMessage.mac_compute(): invalid sec hdr value, {0}'\
                      .format(shdr)))
        
        def encrypt(self, key=16*b'\0', dir=0, eea=0, seqnoff=0):
            """encrypt the NASMessage in place using Seqn plus seqnoff, key, 
            direction and eea,
            
            Args:
                key: 16 bytes buffer, K_nas_enc
                dir: 0 for uplink, 1 for downlink
                eea: 0 to 3, reference to EEA algorithm
                seqnoff: 0 to 2^24 by step of 0x100
            
            Returns:
                None
            """
            if eea == 0:
                return
            shdr = self[0][0].get_val()
            if shdr in (0, 1, 3):
                return
            elif shdr in (2, 4):
                try:
                    EEA = _EEA[eea]
                except KeyError:
                    raise(PycrateErr('EMMSecProtNASMessage.encrypt(): invalid EEA identifier, {0}'\
                          .format(eea)))
                self._dec_msg = self[3].to_bytes()
                self._enc_msg = EEA(key, seqnoff + self[2].get_val(), 0, dir, self._dec_msg)
                self[3].set_val(self._enc_msg)
            else:
                raise(PycrateErr('EMMSecProtNASMessage.encrypt(): invalid sec hdr value, {0}'\
                      .format(shdr)))
        
        def decrypt(self, key=16*b'\0', dir=0, eea=0, seqnoff=0):
            """decrypt the NASMessage in place using Seqn plus seqnoff, key, 
            direction and eea, and decode the NASMessage content
            
            Args:
                key: 16 bytes buffer, K_nas_enc
                dir: 0 for uplink, 1 for downlink
                eea: 0 to 3, reference to EEA algorithm
                seqnoff: 0 to 2^24 by step of 0x100
            
            Returns:
                None
            """
            if eea == 0:
                return
            shdr = self[0][0].get_val()
            if shdr in (0, 1, 3):
                return
            elif shdr in (2, 4):
                try:
                    EEA = _EEA[eea]
                except KeyError:
                    raise(PycrateErr('EMMSecProtNASMessage.decrypt(): invalid EEA identifier, {0}'\
                          .format(eea)))
                self._enc_msg = self[3].to_bytes()
                self._dec_msg = EEA(key, seqnoff + self[2].get_val(), 0, dir, self._enc_msg)
                self[3].set_val(self._dec_msg)
            else:
                raise(PycrateErr('EMMSecProtNASMessage.decrypt(): invalid sec hdr value, {0}'\
                      .format(shdr)))

else:
    
    class EMMSecProtNASMessage(Layer3E):
        _GEN = (
            EMMHeaderSec(),
            Buf('MAC', val=b'\0\0\0\0', bl=32, rep=REPR_HEX),
            Uint8('Seqn'),
            Buf('NASMessage')
            )


#------------------------------------------------------------------------------#
# Service reject
# TS 24.301, section 8.2.24
#------------------------------------------------------------------------------#

class EMMServiceReject(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':78}),
        Type3V('EMMCause', val={'V':b'\x11'}, bl={'V':8}, IE=EMMCause()),
        Type3TV('T3442', val={'T':0x5B, 'V':b'\0'}, bl={'V':8}, IE=GPRSTimer()),
        Type4TLV('T3346', val={'T':0x5C, 'V':b'\0'}, IE=GPRSTimer()),
        Type4TLV('T3448', val={'T':0x6B, 'V':b'\0'}, IE=GPRSTimer()),
        )


#------------------------------------------------------------------------------#
# Service request
# TS 24.301, section 8.2.25
#------------------------------------------------------------------------------#

if _with_cm:
    
    class EMMServiceRequest(Layer3E):
        _GEN = (
            EMMHeaderServ(val={'SecHdr': 12}),
            Uint('KSI', bl=3, dic={7:'no key available'}),
            Uint('SeqnShort', bl=5),
            Buf('MACShort', val=b'\0\0', bl=16, rep=REPR_HEX)
            )
    
        def mac_verify(self, key=16*b'\0', dir=0, eia=0, seqnoff=0):
            """compute the MAC of the EMMServiceRequest using SeqnShort plus seqnoff, 
            key, direction and eia, and verify against the embedded MACShort value
            
            Args:
                key: 16 bytes buffer, K_nas_int
                dir: 0 for uplink, 1 for downlink
                eia: 0 to 3, reference to EIA algorithm
                seqnoff: 0 to 2^32 - 2^5, NAS count offset to add to SeqnShort
            
            Returns:
                True if embedded MACShort is correct, False otherwise
            """
            if eia == 0:
                return True
            else:
                try:
                    EIA = _EIA[eia]
                except KeyError:
                    raise(PycrateErr('EMMServiceRequest.mac_verify(): invalid EIA identifier, {0}'\
                          .format(eia)))
                msg = self.to_bytes()
                mac = EIA(key, seqnoff + self[2].get_val(), 0, dir, msg[:2])
                if mac[2:4] != msg[2:4]:
                    return False
                else:
                    return True
        
        def mac_compute(self, key=16*b'\0', dir=0, eia=0, seqnoff=0):
            """compute the MAC of the EMMServiceRequest using SeqnShort plus seqnoff, 
            key, direction and eia, and set the embedded MACShort value with it
            
            Args:
                key: 16 bytes buffer, K_nas_int
                dir: 0 for uplink, 1 for downlink
                eia: 0 to 3, reference to EIA algorithm
                seqnoff: 0 to 2^32 - 2^5, NAS count offset to add to SeqnShort
            
            Returns:
                None
            """
            if eia == 0:
                self[4].set_val(b'\0\0')
            else:
                try:
                    EIA = _EIA[eia]
                except KeyError:
                    raise(PycrateErr('EMMServiceRequest.mac_compute(): invalid EIA identifier, {0}'\
                          .format(eia)))
                msg = self.to_bytes()
                mac = EIA(key, seqnoff + self[2].get_val(), 0, dir, msg[:2])
                self[4].set_val(mac[2:4])

else:
    
    class EMMServiceRequest(Layer3E):
        _GEN = (
            EMMHeaderServ(val={'SecHdr': 12}),
            Uint('KSI', bl=3, dic={7:'no key available'}),
            Uint('SeqnShort', bl=5),
            Buf('MACShort', val=b'\0\0', bl=16, rep=REPR_HEX)
            )


#------------------------------------------------------------------------------#
# Tracking area update accept
# TS 24.301, section 8.2.26
#------------------------------------------------------------------------------#

class EMMTrackingAreaUpdateAccept(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':73}),
        Uint('spare', bl=4),
        Type1V('EPSUpdateResult', dic=EPSUpdRes_dict),
        Type3TV('T3412', val={'T':0x5A, 'V':b'\0'}, bl={'V':8}, IE=GPRSTimer()),
        Type4TLV('GUTI', val={'T':0x50, 'V':b'\xf6'+10*b'\0'}, IE=EPSID()),
        Type4TLV('TAIList', val={'T':0x54, 'V':6*b'\0'}, IE=TAIList()),
        Type4TLV('EPSBearerCtxtStat', val={'T':0x57, 'V':b'\0\0'}, IE=EPSBearerCtxtStat()),
        Type3TV('LAI', val={'T':0x13, 'V':5*b'\0'}, bl={'V':40}, IE=LAI()),
        Type4TLV('ID', val={'T':0x23, 'V':b'\xf4\0\0\0\0'}, IE=ID()),
        Type3TV('EMMCause', val={'T':0x53, 'V':b'\0'}, bl={'V':8}, IE=EMMCause()),
        Type3TV('T3402', val={'T':0x17, 'V':b'\0'}, bl={'V':8}, IE=GPRSTimer()),
        Type3TV('T3423', val={'T':0x59, 'V':b'\0'}, bl={'V':8}, IE=GPRSTimer()),
        Type4TLV('EquivPLMNList', val={'T':0x4A, 'V':3*b'\0'}, IE=PLMNList()),
        Type4TLV('EmergNumList', val={'T':0x34, 'V':b'\x02\x01\0'}, IE=EmergNumList()),
        Type4TLV('EPSNetFeat', val={'T':0x64, 'V':b'\0\0'}, IE=EPSNetFeat()),
        Type1TV('AddUpdateRes', val={'T':0xF, 'V':0}, IE=AddUpdateRes()),
        Type4TLV('T3412Ext', val={'T':0x5E, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('T3324', val={'T':0x6A, 'V':b'\0'}, IE=GPRSTimer()),
        Type4TLV('ExtDRXParam', val={'T':0x6E, 'V':b'\0'}, IE=ExtDRXParam()),
        Type4TLV('HdrCompConfigStat', val={'T':0x68, 'V':b'\0\0'}, IE=HdrCompConfigStat()),
        Type4TLV('DCNID', val={'T':0x65, 'V':b'\0\0'}, IE=DCNID()),
        Type1TV('SMSServStat', val={'T':0xE, 'V':0}, IE=SMSServStat()),
        Type1TV('Non3GPPNWProvPol', val={'T':0xD, 'V':0}, IE=Non3GPPNWProvPol()),
        Type4TLV('T3448', val={'T':0x6B, 'V':b'\0'}, IE=GPRSTimer()),
        Type1TV('NetworkPol', val={'T':0xC, 'V':0}, IE=NetworkPol()),
        Type4TLV('T3447', val={'T':0x6C, 'V':b'\0'}, IE=GPRSTimer3()),
        Type6TLVE('ExtEmergNumList', val={'T':0x7A, 'V':b'\0\0\0\0'}, IE=ExtEmergNumList()),
        Type6TLVE('CipherKeyData', val={'T':0x7C, 'V':32*b'\0'}, IE=CipherKeyData()),
        Type4TLV('UERadioCapID', val={'T':0x66, 'V':b'\0'}, IE=UERadioCapID()),
        Type1TV('UERadioCapIDDelInd', val={'T':0xB, 'V':0}, IE=UERadioCapIDDelInd())
        )


#------------------------------------------------------------------------------#
# Tracking area update complete
# TS 24.301, section 8.2.27
#------------------------------------------------------------------------------#

class EMMTrackingAreaUpdateComplete(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':74}),
        )


#------------------------------------------------------------------------------#
# Tracking area update reject
# TS 24.301, section 8.2.28
#------------------------------------------------------------------------------#

class EMMTrackingAreaUpdateReject(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':75}),
        Type3V('EMMCause', val={'V':b'\x11'}, bl={'V':8}, IE=EMMCause()),
        Type4TLV('T3346', val={'T':0x5F, 'V':b'\0'}, IE=GPRSTimer()),
        Type1TV('ExtEMMCause', val={'T':0xA, 'V':0}, IE=ExtEMMCause())
        )


#------------------------------------------------------------------------------#
# Tracking area update request
# TS 24.301, section 8.2.29
#------------------------------------------------------------------------------#

class EMMTrackingAreaUpdateRequest(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':72}),
        Type1V('NAS_KSI', val={'V':7}, IE=NAS_KSI()),
        Type1V('EPSUpdateType', IE=EPSUpdateType()),
        Type4LV('OldGUTI', val={'V':b'\xf6'+10*b'\0'}, IE=EPSID()),
        Type1TV('Native_NAS_KSI', val={'T':0xB, 'V':0}, IE=NAS_KSI()),
        Type1TV('GPRS_CKSN', val={'T':0x8, 'V':0}, dic=CKSN_dict),
        Type3TV('OldPTMSISign', val={'T':0x19, 'V':b'\0\0\0'}, bl={'V':24}),
        Type4TLV('AddGUTI', val={'T':0x50, 'V':b'\xf6'+10*b'\0'}, IE=EPSID()),
        Type3TV('NonceUE', val={'T':0x55, 'V':4*b'\0'}, bl={'V':32}),
        Type4TLV('UENetCap', val={'T':0x58, 'V':b'\0\0'}, IE=UENetCap()),
        Type3TV('OldTAI', val={'T':0x52, 'V':5*b'\0'}, bl={'V':40}, IE=TAI()),
        Type3TV('DRXParam', val={'T':0x5C, 'V':b'\0\0'}, bl={'V':16}, IE=DRXParam()),
        Type1TV('UERACapUpdateNeed', val={'T':0xA, 'V':0}),
        Type4TLV('EPSBearerCtxtStat', val={'T':0x57, 'V':b'\0\0'}, IE=EPSBearerCtxtStat()),
        Type4TLV('MSNetCap', val={'T':0x31, 'V':b'\0\0'}, IE=ms_network_capability_value_part),
        Type3TV('OldLAI', val={'T':0x13, 'V':5*b'\0'}, bl={'V':40}, IE=LAI()),
        Type1TV('TMSIStatus', val={'T':0x9, 'V':0}, IE=TMSIStatus()),
        Type4TLV('MSCm2', val={'T':0x11, 'V':b'@\0\0'}, IE=MSCm2()),
        Type4TLV('MSCm3', val={'T':0x20, 'V':b''}, IE=classmark_3_value_part),
        Type4TLV('SuppCodecs', val={'T':0x40, 'V':b'\0\x01\0'}, IE=SuppCodecList()),
        Type1TV('AddUpdateType', val={'T':0xF, 'V':0}, IE=AddUpdateType()),
        Type4TLV('VoiceDomPref', val={'T':0x5D, 'V':b'\0'}, IE=VoiceDomPref()),
        Type1TV('OldGUTIType', val={'T':0xE, 'V':0}, IE=GUTIType()),
        Type1TV('DeviceProp', val={'T':0xD, 'V':0}, IE=DeviceProp()),
        Type1TV('MSNetFeatSupp', val={'T':0xC, 'V':0}, IE=MSNetFeatSupp()),
        Type4TLV('TMSIBasedNRICont', val={'T':0x10, 'V':b'\0\0'}, IE=NRICont()),
        Type4TLV('T3324', val={'T':0x6A, 'V':b'\0'}, IE=GPRSTimer()),
        Type4TLV('T3412Ext', val={'T':0x5E, 'V':b'\0'}, IE=GPRSTimer3()),
        Type4TLV('ExtDRXParam', val={'T':0x6E, 'V':b'\0'}, IE=ExtDRXParam()),
        Type4TLV('UEAddSecCap', val={'T':0x6F, 'V':b'\0\0\0\0'}, IE=UEAddSecCap()),
        Type4TLV('UEStatus', val={'T':0x6D, 'V':b'\0'}, IE=UEStatus()),
        Type3TV('AddInfoReq', val={'T':0x17, 'V':b'\0'}, IE=AddInfoReq()),
        Type4TLV('N1UENetCap', val={'T':0x32, 'V':b'\0'}, IE=N1UENetCap()),
        #Type1TV('UERadioCapIDAvail', val={'T':0xB, 'V':0}, IE=UERadioCapIDAvail()) # WNG: tag is undefined in current TS
        )


#------------------------------------------------------------------------------#
# Uplink NAS transport
# TS 24.301, section 8.2.30
#------------------------------------------------------------------------------#

class EMMULNASTransport(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':99}),
        Type4LV('NASContainer', val={'V':b'\0\0'})
        )


#------------------------------------------------------------------------------#
# Downlink generic NAS transport
# TS 24.301, section 8.2.31
#------------------------------------------------------------------------------#

class EMMDLGenericNASTransport(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':104}),
        Type3V('GenericContType', val={'V':b'\0'}, bl={'V':8}, IE=GenericContType()),
        Type6LVE('GenericContainer', val={'V':b'\0\0'}),
        Type4TLV('AddInfo', val={'T':0x65, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Uplink generic NAS transport
# TS 24.301, section 8.2.32
#------------------------------------------------------------------------------#

class EMMULGenericNASTransport(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':105}),
        Type3V('GenericContType', val={'V':b'\0'}, bl={'V':8}, IE=GenericContType()),
        Type6LVE('GenericContainer', val={'V':b'\0\0'}),
        Type4TLV('AddInfo', val={'T':0x65, 'V':b'\0'})
        )


#------------------------------------------------------------------------------#
# Control plane service request
# TS 24.301, section 8.2.33
#------------------------------------------------------------------------------#

class EMMCPServiceRequest(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':77}),
        Type1V('NAS_KSI', val={'V':7}, IE=NAS_KSI()),
        Type1V('CPServiceType', IE=CPServiceType()),
        Type6TLVE('ESMContainer', val={'T':0x78, 'V':b'\0'}),
        Type4TLV('NASContainer', val={'T':0x67, 'V':b'\0\0'}),
        Type4TLV('EPSBearerCtxtStat', val={'T':0x57, 'V':b'\0\0'}, IE=EPSBearerCtxtStat()),
        Type1TV('DeviceProp', val={'T':0xD, 'V':0}, IE=DeviceProp())
        )


#------------------------------------------------------------------------------#
# Service accept
# TS 24.301, section 8.2.34
#------------------------------------------------------------------------------#

class EMMServiceAccept(Layer3E):
    _GEN = (
        EMMHeader(val={'Type':79}),
        Type4TLV('EPSBearerCtxtStat', val={'T':0x57, 'V':b'\0\0'}, IE=EPSBearerCtxtStat()),
        Type4TLV('T3448', val={'T':0x6B, 'V':b'\0'}, IE=GPRSTimer())
        )


#------------------------------------------------------------------------------#
# EMM dispatcher
#------------------------------------------------------------------------------#
# special EMM messages: EMMSecProtNASMessage, EMMServiceRequest

EMMTypeMOClasses = {
    65 : EMMAttachRequest,
    66 : EMMAttachAccept,
    67 : EMMAttachComplete,
    68 : EMMAttachReject,
    69 : EMMDetachRequestMO,
    70 : EMMDetachAccept,
    72 : EMMTrackingAreaUpdateRequest,
    73 : EMMTrackingAreaUpdateAccept,
    74 : EMMTrackingAreaUpdateComplete,
    75 : EMMTrackingAreaUpdateReject,
    76 : EMMExtServiceRequest,
    77 : EMMCPServiceRequest,
    78 : EMMServiceReject,
    79 : EMMServiceAccept,
    80 : EMMGUTIReallocCommand,
    81 : EMMGUTIReallocComplete,
    82 : EMMAuthenticationRequest,
    83 : EMMAuthenticationResponse,
    84 : EMMAuthenticationReject,
    92 : EMMAuthenticationFailure,
    85 : EMMIdentityRequest,
    86 : EMMIdentityResponse,
    93 : EMMSecurityModeCommand,
    94 : EMMSecurityModeComplete,
    95 : EMMSecurityModeReject,
    96 : EMMStatus,
    97 : EMMInformation,
    98 : EMMDLNASTransport,
    99 : EMMULNASTransport,
    100 : EMMCSServiceNotification,
    104 : EMMDLGenericNASTransport,
    105 : EMMULGenericNASTransport
    }

EMMTypeMTClasses = {
    65 : EMMAttachRequest,
    66 : EMMAttachAccept,
    67 : EMMAttachComplete,
    68 : EMMAttachReject,
    69 : EMMDetachRequestMT,
    70 : EMMDetachAccept,
    72 : EMMTrackingAreaUpdateRequest,
    73 : EMMTrackingAreaUpdateAccept,
    74 : EMMTrackingAreaUpdateComplete,
    75 : EMMTrackingAreaUpdateReject,
    76 : EMMExtServiceRequest,
    77 : EMMCPServiceRequest,
    78 : EMMServiceReject,
    79 : EMMServiceAccept,
    80 : EMMGUTIReallocCommand,
    81 : EMMGUTIReallocComplete,
    82 : EMMAuthenticationRequest,
    83 : EMMAuthenticationResponse,
    84 : EMMAuthenticationReject,
    92 : EMMAuthenticationFailure,
    85 : EMMIdentityRequest,
    86 : EMMIdentityResponse,
    93 : EMMSecurityModeCommand,
    94 : EMMSecurityModeComplete,
    95 : EMMSecurityModeReject,
    96 : EMMStatus,
    97 : EMMInformation,
    98 : EMMDLNASTransport,
    99 : EMMULNASTransport,
    100 : EMMCSServiceNotification,
    104 : EMMDLGenericNASTransport,
    105 : EMMULGenericNASTransport
    }

def get_emm_msg_mo_instances():
    return {k: EMMTypeMOClasses[k]() for k in EMMTypeMOClasses}

def get_emm_msg_mt_instances():
    return {k: EMMTypeMTClasses[k]() for k in EMMTypeMTClasses}

